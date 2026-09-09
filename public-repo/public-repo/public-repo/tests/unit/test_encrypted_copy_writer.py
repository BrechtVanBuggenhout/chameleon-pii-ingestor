import datetime

import pytest
from google.api_core.exceptions import TooManyRequests

from app.policies.pii_registry import RegistryResource
from app.scanners.encrypted_copy_writer import EncryptedCopyWriter


class FakeRow(dict):
    """Supports row["col"] like a real bigquery.table.Row, and dict(row)."""

    def __getitem__(self, key):
        return dict.get(self, key)


class FakeBigQueryClient:
    def __init__(self):
        self.insert_calls: list[tuple[str, list]] = []

    def insert_rows_json(self, table_ref, records):
        self.insert_calls.append((table_ref, records))
        return []


class FlakyBigQueryClient(FakeBigQueryClient):
    """insert_rows_json raises TooManyRequests on its first `raise_count`
    calls, mirroring FlakyBigQueryClient in test_pii_vault_sync.py."""

    def __init__(self, raise_count=0):
        super().__init__()
        self._raise_count = raise_count
        self.attempts = 0

    def insert_rows_json(self, table_ref, records):
        self.attempts += 1
        if self.attempts <= self._raise_count:
            raise TooManyRequests("Exceeded rate limits: too many table update operations for this table.")
        return super().insert_rows_json(table_ref, records)


def make_resource(strategies=("ENCRYPTED_COPY",), resource_id="bigquery:proj.dataset.contacts"):
    return RegistryResource(
        id=resource_id,
        type="bigquery_table",
        tenant_scoped=True,
        tenant_id_column="tenant_id",
        allowed_direct_identifiers=[],
        columns=[],
        user_id_column="user_id",
        source_redaction_strategies=list(strategies),
    )


class TestEncryptedCopyWriterAppend:
    def test_is_a_no_op_when_the_resource_is_not_opted_in(self):
        resource = make_resource(strategies=())
        bq = FakeBigQueryClient()
        writer = EncryptedCopyWriter(bq)
        rows = [FakeRow({"user_id": "u1", "email": "u1@example.com"})]
        vault_records = [
            {
                "resource_id": resource.id,
                "user_id": "u1",
                "field_name": "email",
                "encrypted_value": "cipher1",
                "synced_at": "2026-08-19T00:00:00+00:00",
            }
        ]

        count = writer.append(resource, rows, vault_records)

        assert count == 0
        assert bq.insert_calls == []

    def test_is_a_no_op_when_there_are_no_rows(self):
        resource = make_resource()
        bq = FakeBigQueryClient()
        writer = EncryptedCopyWriter(bq)

        count = writer.append(resource, [], [])

        assert count == 0
        assert bq.insert_calls == []

    def test_appends_a_wide_row_reusing_the_pii_vault_ciphertext_verbatim(self):
        resource = make_resource()
        bq = FakeBigQueryClient()
        writer = EncryptedCopyWriter(bq)
        rows = [FakeRow({"user_id": "u1", "tenant_id": "acme", "email": "u1@example.com", "plan": "pro"})]
        vault_records = [
            {
                "resource_id": resource.id,
                "user_id": "u1",
                "field_name": "email",
                "encrypted_value": "v1:iv_b64:ciphertext_b64",
                "synced_at": "2026-08-19T00:00:00+00:00",
            },
        ]

        count = writer.append(resource, rows, vault_records)

        assert count == 1
        assert len(bq.insert_calls) == 1
        table_ref, records = bq.insert_calls[0]
        assert table_ref == "proj.dataset.contacts_encrypted_raw"
        # Non-PII columns pass through unchanged; the declared PII column
        # is replaced by the exact same ciphertext bundle pii_vault itself
        # stored -- never re-encrypted.
        assert records == [
            {
                "user_id": "u1",
                "tenant_id": "acme",
                "email": "v1:iv_b64:ciphertext_b64",
                "plan": "pro",
                "synced_at": "2026-08-19T00:00:00+00:00",
            }
        ]

    def test_replaces_every_synced_field_when_a_user_has_more_than_one(self):
        resource = make_resource()
        bq = FakeBigQueryClient()
        writer = EncryptedCopyWriter(bq)
        rows = [FakeRow({"user_id": "u1", "email": "u1@example.com", "phone": "555-1234"})]
        vault_records = [
            {"resource_id": resource.id, "user_id": "u1", "field_name": "email", "encrypted_value": "ct-email", "synced_at": "s1"},
            {"resource_id": resource.id, "user_id": "u1", "field_name": "phone", "encrypted_value": "ct-phone", "synced_at": "s1"},
        ]

        writer.append(resource, rows, vault_records)

        _, records = bq.insert_calls[0]
        assert records[0]["email"] == "ct-email"
        assert records[0]["phone"] == "ct-phone"

    def test_skips_a_user_with_nothing_actually_synced_this_chunk(self):
        # rows_needing_work can include a user whose only missing field
        # turned out NULL in the source row -- pii_vault_sync.py never
        # builds a vault_record for them either in that case, so there's
        # nothing new to copy here.
        resource = make_resource()
        bq = FakeBigQueryClient()
        writer = EncryptedCopyWriter(bq)
        rows = [FakeRow({"user_id": "u1", "email": None})]

        count = writer.append(resource, rows, [])

        assert count == 0
        assert bq.insert_calls == []

    def test_ignores_vault_records_belonging_to_a_different_resource(self):
        resource = make_resource()
        bq = FakeBigQueryClient()
        writer = EncryptedCopyWriter(bq)
        rows = [FakeRow({"user_id": "u1", "email": "u1@example.com"})]
        vault_records = [
            {
                "resource_id": "bigquery:proj.dataset.other_table",
                "user_id": "u1",
                "field_name": "email",
                "encrypted_value": "wrong-resource",
                "synced_at": "s1",
            },
        ]

        count = writer.append(resource, rows, vault_records)

        assert count == 0
        assert bq.insert_calls == []

    def test_json_safe_converts_datetime_date_and_bytes_columns(self):
        resource = make_resource()
        bq = FakeBigQueryClient()
        writer = EncryptedCopyWriter(bq)
        rows = [
            FakeRow(
                {
                    "user_id": "u1",
                    "email": "u1@example.com",
                    "created_at": datetime.datetime(2026, 8, 19, 12, 0, 0),
                    "birthday": datetime.date(2000, 1, 1),
                    "raw_blob": b"hello",
                }
            )
        ]
        vault_records = [
            {"resource_id": resource.id, "user_id": "u1", "field_name": "email", "encrypted_value": "ct", "synced_at": "s1"}
        ]

        writer.append(resource, rows, vault_records)

        _, records = bq.insert_calls[0]
        row = records[0]
        assert row["created_at"] == "2026-08-19T12:00:00"
        assert row["birthday"] == "2000-01-01"
        assert row["raw_blob"] == "hello"

    def test_retries_a_rate_limited_insert_and_still_appends(self, monkeypatch):
        monkeypatch.setattr("app.scanners.encrypted_copy_writer.time.sleep", lambda _seconds: None)
        resource = make_resource()
        bq = FlakyBigQueryClient(raise_count=2)
        writer = EncryptedCopyWriter(bq)
        rows = [FakeRow({"user_id": "u1", "email": "u1@example.com"})]
        vault_records = [
            {"resource_id": resource.id, "user_id": "u1", "field_name": "email", "encrypted_value": "ct", "synced_at": "s1"}
        ]

        count = writer.append(resource, rows, vault_records)

        assert count == 1
        assert bq.attempts == 3

    def test_re_raises_once_retries_are_exhausted(self, monkeypatch):
        monkeypatch.setattr("app.scanners.encrypted_copy_writer.time.sleep", lambda _seconds: None)
        resource = make_resource()
        bq = FlakyBigQueryClient(raise_count=EncryptedCopyWriter.LOAD_MAX_RETRIES)
        writer = EncryptedCopyWriter(bq)
        rows = [FakeRow({"user_id": "u1", "email": "u1@example.com"})]
        vault_records = [
            {"resource_id": resource.id, "user_id": "u1", "field_name": "email", "encrypted_value": "ct", "synced_at": "s1"}
        ]

        with pytest.raises(TooManyRequests):
            writer.append(resource, rows, vault_records)

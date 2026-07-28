import base64
from unittest.mock import MagicMock

import pytest

from app.scanners.pii_vault_sync import PiiVaultSyncJob, parse_bigquery_resource_id


class FakeRow(dict):
    """Supports row["col"] like a real bigquery.table.Row."""

    def __getitem__(self, key):
        return dict.get(self, key)


class FakeQueryJob:
    def __init__(self, rows):
        self._rows = rows

    def result(self):
        return self._rows


class FakeLoadJob:
    def __init__(self, on_load):
        self._on_load = on_load

    def result(self):
        self._on_load()


class FakeBigQueryClient:
    def __init__(self, source_rows):
        self.source_rows = [FakeRow(r) for r in source_rows]
        self.queries = []
        self.loaded_records = None
        self.loaded_table_ref = None

    def query(self, query, job_config=None):
        self.queries.append(query)
        return FakeQueryJob(self.source_rows)

    def load_table_from_json(self, records, table_ref, job_config=None):
        def on_load():
            self.loaded_records = records
            self.loaded_table_ref = table_ref

        return FakeLoadJob(on_load)


class FakeVault:
    tenant_id = "acme"

    def __init__(self, registry_resources, contexts):
        self._registry_resources = registry_resources
        self._contexts = contexts
        self.create_keys_calls: list[list[str]] = []

    def fetch_pii_registry_resources(self, owner_connector=None):
        assert owner_connector == "manual"
        return {"resources": self._registry_resources}

    def batch_create_keys(self, user_ids):
        self.create_keys_calls.append(list(user_ids))

    def batch_get_encryption_contexts(self, user_ids):
        return {uid: self._contexts[uid] for uid in user_ids if uid in self._contexts}


MANUAL_RESOURCE = {
    "resourceId": "bigquery:proj.dataset.federated_user",
    "system": "bigquery",
    "ownerConnector": "manual",
    "tenantIdColumn": "tenant_id",
    "userIdColumn": "user_id",
    "piiFields": [
        {"name": "email", "classification": "DIRECT_IDENTIFIER", "handling": "ENCRYPT"},
        {"name": "username", "classification": "SYSTEM_IDENTIFIER", "handling": "HASH_SURROGATE"},
    ],
}


def make_context(key_id="v1"):
    return {"dek": "00" * 32, "key_id": key_id}


class TestParseBigQueryResourceId:
    def test_parses_well_formed_id(self):
        assert parse_bigquery_resource_id("bigquery:proj.dataset.table") == ("proj", "dataset", "table")

    @pytest.mark.parametrize("bad_id", ["not-a-real-id", "bigquery:only.two", "snowflake:proj.dataset.table"])
    def test_rejects_invalid_ids(self, bad_id):
        with pytest.raises(ValueError):
            parse_bigquery_resource_id(bad_id)


class TestPiiVaultSyncJob:
    def test_skips_resources_missing_user_id_column(self):
        resource_no_user_id = {**MANUAL_RESOURCE, "userIdColumn": None}
        vault = FakeVault([resource_no_user_id], {})
        bq = FakeBigQueryClient([])
        job = PiiVaultSyncJob(bq, vault, "proj", "chameleon")

        results = job.sync_all()

        assert results[0].users_synced == 0
        assert bq.queries == []  # never even queried

    def test_skips_resources_with_no_encrypt_fields(self):
        resource = {**MANUAL_RESOURCE, "piiFields": [MANUAL_RESOURCE["piiFields"][1]]}  # only HASH_SURROGATE
        vault = FakeVault([resource], {})
        bq = FakeBigQueryClient([])
        job = PiiVaultSyncJob(bq, vault, "proj", "chameleon")

        results = job.sync_all()

        assert results[0].users_synced == 0

    def test_syncs_new_users_and_encrypts_declared_fields(self):
        source_rows = [
            {"user_id": "u1", "tenant_id": "acme", "email": "u1@example.com"},
            {"user_id": "u2", "tenant_id": "acme", "email": "u2@example.com"},
        ]
        vault = FakeVault([MANUAL_RESOURCE], {"u1": make_context("v1"), "u2": make_context("v2")})
        bq = FakeBigQueryClient(source_rows)
        job = PiiVaultSyncJob(bq, vault, "proj", "chameleon")

        results = job.sync_all()

        assert results[0].resource_id == "bigquery:proj.dataset.federated_user"
        assert results[0].users_synced == 2
        assert results[0].error is None

        # These are pre-existing users who've never been through Chameleon's
        # ingestion pipeline -- they have no key yet, so a key must be created
        # for them before fetching an encryption context, same as the real
        # ingestion pipeline already does. Regression test for exactly the
        # bug that shipped: this call was missing entirely, which meant a
        # real customer's first sync attempt hung for minutes against Key
        # Vault repeatedly failing to find a context for a keyless user.
        assert vault.create_keys_calls == [["u1", "u2"]]

        # Query correctly scoped to this resource, excluding already-vaulted users
        assert "resource_id" in bq.queries[0]
        assert "federated_user" in bq.queries[0]

        # Loaded into the right table, one row per new user, only ENCRYPT fields present
        assert bq.loaded_table_ref == "proj.chameleon.pii_vault"
        assert len(bq.loaded_records) == 2
        record = next(r for r in bq.loaded_records if r["user_id"] == "u1")
        assert record["tenant_id"] == "acme"
        assert record["resource_id"] == "bigquery:proj.dataset.federated_user"
        assert record["key_id"] == "v1"
        assert len(record["pii_fields"]) == 1  # username (HASH_SURROGATE) excluded
        assert record["pii_fields"][0]["field_name"] == "email"
        # encrypted_value must be a base64 string (JSON-safe for load_table_from_json), not raw bytes
        assert isinstance(record["pii_fields"][0]["encrypted_value"], str)
        base64.b64decode(record["pii_fields"][0]["encrypted_value"])  # doesn't raise

    def test_skips_users_missing_an_encryption_context(self):
        source_rows = [{"user_id": "u1", "tenant_id": "acme", "email": "u1@example.com"}]
        vault = FakeVault([MANUAL_RESOURCE], {})  # no context for u1
        bq = FakeBigQueryClient(source_rows)
        job = PiiVaultSyncJob(bq, vault, "proj", "chameleon")

        results = job.sync_all()

        assert results[0].users_synced == 0
        assert bq.loaded_records is None

    def test_continues_past_a_failing_resource(self):
        bad_resource = {**MANUAL_RESOURCE, "resourceId": "not-a-real-id"}
        good_resource = {
            **MANUAL_RESOURCE,
            "resourceId": "bigquery:proj.dataset.other_table",
        }
        vault = FakeVault([bad_resource, good_resource], {"u1": make_context()})
        bq = FakeBigQueryClient([{"user_id": "u1", "tenant_id": "acme", "email": "u1@example.com"}])
        job = PiiVaultSyncJob(bq, vault, "proj", "chameleon")

        results = job.sync_all()

        assert results[0].error is not None
        assert results[0].users_synced == 0
        assert results[1].error is None
        assert results[1].users_synced == 1

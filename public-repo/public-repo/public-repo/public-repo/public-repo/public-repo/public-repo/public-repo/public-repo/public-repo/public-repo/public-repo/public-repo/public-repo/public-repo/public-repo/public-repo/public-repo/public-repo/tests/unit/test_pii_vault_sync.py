import base64
import json

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
    """
    Routes each query() call to the right fixture based on shape, since the
    job now issues three distinct kinds of query against two tables:
      1. enumerate_resource's SELECT <user_id_col> FROM <source> -- no
         job_config/query_parameters at all.
      2. process_chunk's re-SELECT ... FROM <source> WHERE ... IN
         UNNEST(@user_ids) -- has job_config, references the source table,
         never "pii_vault".
      3. _fetch_existing_fields's SELECT ... FROM pii_vault -- has
         job_config, references "pii_vault".
    """

    def __init__(self, source_rows, existing_vault_rows=None, user_id_column="user_id"):
        self.source_rows = [FakeRow(r) for r in source_rows]
        self.existing_vault_rows = [FakeRow(r) for r in (existing_vault_rows or [])]
        self.user_id_column = user_id_column
        self.queries = []
        self.query_params_log = []
        self.load_calls: list[tuple[list, str]] = []

    def query(self, query, job_config=None):
        self.queries.append(query)
        # ArrayQueryParameter exposes .values (plural); ScalarQueryParameter
        # exposes .value (singular) -- real bigquery API objects, not ours.
        params = {
            p.name: (p.values if hasattr(p, "values") else p.value)
            for p in (job_config.query_parameters if job_config else [])
        }
        self.query_params_log.append(params)

        if job_config is None:
            # enumerate_resource: only ever selects the user_id column.
            return FakeQueryJob([FakeRow({self.user_id_column: r[self.user_id_column]}) for r in self.source_rows])

        if "pii_vault" in query:
            return FakeQueryJob(self.existing_vault_rows)

        # process_chunk's re-query, scoped to the requested user_ids.
        requested_ids = set(params.get("user_ids", []))
        matching = [r for r in self.source_rows if str(r[self.user_id_column]) in requested_ids]
        return FakeQueryJob(matching)

    def load_table_from_json(self, records, table_ref, job_config=None):
        def on_load():
            self.load_calls.append((records, table_ref))

        return FakeLoadJob(on_load)

    @property
    def loaded_records(self):
        return [r for records, _ in self.load_calls for r in records]

    @property
    def loaded_table_ref(self):
        return self.load_calls[-1][1] if self.load_calls else None


class FakePublishFuture:
    def result(self):
        return None


class FakePublisher:
    def __init__(self):
        self.published: list[tuple[str, dict]] = []

    def publish(self, topic_path, data: bytes):
        self.published.append((topic_path, json.loads(data.decode("utf-8"))))
        return FakePublishFuture()


class FailingPublisher:
    """Simulates a publish that never succeeds -- future.result() raises."""

    def publish(self, topic_path, data: bytes):
        class _Future:
            def result(self):
                raise RuntimeError("Pub/Sub unavailable")

        return _Future()


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

CHUNK_TOPIC_PATH = "projects/proj/topics/pii-vault-sync-chunks"


def make_context(key_id="v1"):
    return {"dek": "00" * 32, "key_id": key_id}


def make_job(bq, vault, publisher=None):
    return PiiVaultSyncJob(
        bigquery_client=bq,
        vault=vault,
        vault_project_id="proj",
        vault_dataset_id="chameleon",
        publisher=publisher or FakePublisher(),
        chunk_topic_path=CHUNK_TOPIC_PATH,
    )


class TestParseBigQueryResourceId:
    def test_parses_well_formed_id(self):
        assert parse_bigquery_resource_id("bigquery:proj.dataset.table") == ("proj", "dataset", "table")

    @pytest.mark.parametrize("bad_id", ["not-a-real-id", "bigquery:only.two", "snowflake:proj.dataset.table"])
    def test_rejects_invalid_ids(self, bad_id):
        with pytest.raises(ValueError):
            parse_bigquery_resource_id(bad_id)


class TestEnumerateResource:
    """sync_all/enumerate_resource: the fast, trigger-facing half. Never
    touches pii_vault, never encrypts anything -- just chunks user IDs and
    publishes."""

    def test_skips_resources_missing_user_id_column(self):
        resource_no_user_id = {**MANUAL_RESOURCE, "userIdColumn": None}
        vault = FakeVault([resource_no_user_id], {})
        bq = FakeBigQueryClient([])
        job = make_job(bq, vault)

        results = job.sync_all()

        assert results[0].chunks_queued == 0
        assert bq.queries == []  # never even queried

    def test_skips_resources_with_no_encrypt_fields(self):
        resource = {**MANUAL_RESOURCE, "piiFields": [MANUAL_RESOURCE["piiFields"][1]]}  # only HASH_SURROGATE
        vault = FakeVault([resource], {})
        bq = FakeBigQueryClient([])
        job = make_job(bq, vault)

        results = job.sync_all()

        assert results[0].chunks_queued == 0

    def test_publishes_one_chunk_for_a_small_resource(self):
        source_rows = [{"user_id": "u1", "tenant_id": "acme"}, {"user_id": "u2", "tenant_id": "acme"}]
        vault = FakeVault([MANUAL_RESOURCE], {})
        bq = FakeBigQueryClient(source_rows)
        publisher = FakePublisher()
        job = make_job(bq, vault, publisher)

        results = job.sync_all()

        assert results[0].resource_id == "bigquery:proj.dataset.federated_user"
        assert results[0].chunks_queued == 1
        assert results[0].error is None

        # Enumeration query only ever selects the ID column, never the PII
        # field values -- those get re-read fresh per chunk, never
        # published into Pub/Sub as plaintext.
        assert "user_id" in bq.queries[0]
        assert "email" not in bq.queries[0]
        assert "pii_vault" not in bq.queries[0]

        assert len(publisher.published) == 1
        topic_path, message = publisher.published[0]
        assert topic_path == CHUNK_TOPIC_PATH
        assert message == {"resource_id": "bigquery:proj.dataset.federated_user", "user_ids": ["u1", "u2"]}

    def test_chunks_a_large_resource_into_multiple_messages(self):
        chunk_size = PiiVaultSyncJob.CHUNK_SIZE
        row_count = chunk_size * 2 + chunk_size // 2  # e.g. 250 for CHUNK_SIZE=100 -> 3 chunks
        expected_chunk_sizes = [chunk_size, chunk_size, row_count - 2 * chunk_size]

        source_rows = [{"user_id": f"u{i}", "tenant_id": "acme"} for i in range(row_count)]
        vault = FakeVault([MANUAL_RESOURCE], {})
        bq = FakeBigQueryClient(source_rows)
        publisher = FakePublisher()
        job = make_job(bq, vault, publisher)

        results = job.sync_all()

        assert results[0].chunks_queued == 3
        assert [len(msg["user_ids"]) for _, msg in publisher.published] == expected_chunk_sizes
        all_published_ids = {uid for _, msg in publisher.published for uid in msg["user_ids"]}
        assert all_published_ids == {f"u{i}" for i in range(row_count)}

    def test_a_publish_failure_surfaces_as_a_resource_error_not_a_silent_drop(self):
        source_rows = [{"user_id": "u1", "tenant_id": "acme"}]
        vault = FakeVault([MANUAL_RESOURCE], {})
        bq = FakeBigQueryClient(source_rows)
        job = make_job(bq, vault, publisher=FailingPublisher())

        results = job.sync_all()

        assert results[0].chunks_queued == 0
        assert results[0].error is not None

    def test_continues_past_a_failing_resource(self):
        bad_resource = {**MANUAL_RESOURCE, "resourceId": "not-a-real-id"}
        good_resource = {**MANUAL_RESOURCE, "resourceId": "bigquery:proj.dataset.other_table"}
        vault = FakeVault([bad_resource, good_resource], {})
        bq = FakeBigQueryClient([{"user_id": "u1", "tenant_id": "acme"}])
        job = make_job(bq, vault)

        results = job.sync_all()

        assert results[0].error is not None
        assert results[0].chunks_queued == 0
        assert results[1].error is None
        assert results[1].chunks_queued == 1


class TestProcessChunk:
    """process_chunk: the actual per-chunk work, triggered per Pub/Sub
    message. Re-queries the source table for exactly the requested
    user_ids, then does the same diff/encrypt/insert as before."""

    def test_syncs_new_users_and_encrypts_declared_fields(self):
        source_rows = [
            {"user_id": "u1", "tenant_id": "acme", "email": "u1@example.com"},
            {"user_id": "u2", "tenant_id": "acme", "email": "u2@example.com"},
        ]
        vault = FakeVault([MANUAL_RESOURCE], {"u1": make_context("v1"), "u2": make_context("v2")})
        bq = FakeBigQueryClient(source_rows)
        job = make_job(bq, vault)

        synced = job.process_chunk("bigquery:proj.dataset.federated_user", ["u1", "u2"])

        assert synced == 2
        # These are pre-existing users who've never been through Chameleon's
        # ingestion pipeline -- they have no key yet, so a key must be
        # created before fetching an encryption context, same as the real
        # ingestion pipeline already does.
        assert vault.create_keys_calls == [["u1", "u2"]]

        assert bq.loaded_table_ref == "proj.chameleon.pii_vault"
        assert len(bq.loaded_records) == 2
        record = next(r for r in bq.loaded_records if r["user_id"] == "u1")
        assert record["tenant_id"] == "acme"
        assert record["resource_id"] == "bigquery:proj.dataset.federated_user"
        assert record["key_id"] == "v1"
        assert record["field_name"] == "email"
        assert isinstance(record["encrypted_value"], str)
        base64.b64decode(record["encrypted_value"])  # doesn't raise
        assert "pii_fields" not in record  # flat schema, not the old nested array

    def test_only_re_queries_the_requested_chunk_of_user_ids(self):
        source_rows = [
            {"user_id": "u1", "tenant_id": "acme", "email": "u1@example.com"},
            {"user_id": "u2", "tenant_id": "acme", "email": "u2@example.com"},
            {"user_id": "u3", "tenant_id": "acme", "email": "u3@example.com"},
        ]
        vault = FakeVault([MANUAL_RESOURCE], {"u1": make_context(), "u2": make_context(), "u3": make_context()})
        bq = FakeBigQueryClient(source_rows)
        job = make_job(bq, vault)

        synced = job.process_chunk("bigquery:proj.dataset.federated_user", ["u1", "u3"])

        assert synced == 2
        assert {r["user_id"] for r in bq.loaded_records} == {"u1", "u3"}

    def test_backfills_only_missing_fields_for_a_partially_synced_user(self):
        resource = {
            **MANUAL_RESOURCE,
            "piiFields": [
                {"name": "email", "classification": "DIRECT_IDENTIFIER", "handling": "ENCRYPT"},
                {"name": "first_name", "classification": "DIRECT_IDENTIFIER", "handling": "ENCRYPT"},
            ],
        }
        source_rows = [{"user_id": "u1", "tenant_id": "acme", "email": "u1@example.com", "first_name": "Alex"}]
        vault = FakeVault([resource], {"u1": make_context("v2")})
        bq = FakeBigQueryClient(source_rows, existing_vault_rows=[{"user_id": "u1", "field_name": "email"}])
        job = make_job(bq, vault)

        synced = job.process_chunk("bigquery:proj.dataset.federated_user", ["u1"])

        assert synced == 1
        assert len(bq.loaded_records) == 1
        assert bq.loaded_records[0]["field_name"] == "first_name"  # only the missing field, not email again

    def test_skips_users_with_no_missing_fields_entirely(self):
        source_rows = [{"user_id": "u1", "tenant_id": "acme", "email": "u1@example.com"}]
        vault = FakeVault([MANUAL_RESOURCE], {"u1": make_context()})
        bq = FakeBigQueryClient(source_rows, existing_vault_rows=[{"user_id": "u1", "field_name": "email"}])
        job = make_job(bq, vault)

        synced = job.process_chunk("bigquery:proj.dataset.federated_user", ["u1"])

        assert synced == 0
        assert bq.loaded_records == []
        assert vault.create_keys_calls == []  # skipped before any Vault call

    def test_skips_users_missing_an_encryption_context(self):
        source_rows = [{"user_id": "u1", "tenant_id": "acme", "email": "u1@example.com"}]
        vault = FakeVault([MANUAL_RESOURCE], {})  # no context for u1
        bq = FakeBigQueryClient(source_rows)
        job = make_job(bq, vault)

        synced = job.process_chunk("bigquery:proj.dataset.federated_user", ["u1"])

        assert synced == 0
        assert bq.loaded_records == []

    def test_dropping_a_chunk_for_a_resource_no_longer_declared(self):
        vault = FakeVault([], {})  # resource removed from the registry since enumeration
        bq = FakeBigQueryClient([])
        job = make_job(bq, vault)

        synced = job.process_chunk("bigquery:proj.dataset.federated_user", ["u1"])

        assert synced == 0
        assert bq.queries == []  # never even re-queries a resource that's gone

import base64
import json
from datetime import datetime

import pytest
from google.api_core.exceptions import TooManyRequests

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

    def __init__(self, source_rows, existing_vault_rows=None, user_id_column="user_id", updated_at_column="updated_at"):
        self.source_rows = [FakeRow(r) for r in source_rows]
        self.existing_vault_rows = [FakeRow(r) for r in (existing_vault_rows or [])]
        self.user_id_column = user_id_column
        self.updated_at_column = updated_at_column
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
            # enumerate_resource (full scan): only ever selects the user_id column.
            return FakeQueryJob([FakeRow({self.user_id_column: r[self.user_id_column]}) for r in self.source_rows])

        if "pii_vault" in query:
            return FakeQueryJob(self.existing_vault_rows)

        if "last_synced_at" in params:
            # enumerate_resource (incremental): rows whose own updated_at is
            # >= the watermark -- mirrors the real >= filter's semantics.
            # Real bigquery.ScalarQueryParameter(..., "TIMESTAMP", ...)
            # coerces .value to a datetime, not the original string -- match
            # that here so comparisons below aren't str-vs-datetime.
            watermark = params["last_synced_at"]
            watermark_str = watermark.isoformat() if hasattr(watermark, "isoformat") else str(watermark)
            matching = [r for r in self.source_rows if str(r.get(self.updated_at_column, "")) >= watermark_str]
            return FakeQueryJob([FakeRow({self.user_id_column: r[self.user_id_column]}) for r in matching])

        # process_chunk's re-query, scoped to the requested user_ids.
        requested_ids = set(params.get("user_ids", []))
        matching = [r for r in self.source_rows if str(r[self.user_id_column]) in requested_ids]
        return FakeQueryJob(matching)

    def insert_rows_json(self, table_ref, records):
        self.load_calls.append((records, table_ref))
        return []  # no per-row errors

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

    def __init__(
        self,
        registry_resources,
        contexts,
        mark_synced_raises=False,
        mark_sync_attempted_raises=False,
        record_outcome_raises=False,
    ):
        self._registry_resources = registry_resources
        self._contexts = contexts
        self.create_keys_calls: list[list[str]] = []
        self.mark_synced_calls: list[tuple[str, str]] = []
        self.mark_sync_attempted_calls: list[tuple[str, str]] = []
        self._mark_synced_raises = mark_synced_raises
        self._mark_sync_attempted_raises = mark_sync_attempted_raises
        self.create_sync_run_calls: list[tuple[str, str | None]] = []
        self.finalize_sync_run_total_calls: list[tuple[str, int]] = []
        self.record_chunk_outcome_calls: list[tuple[str, str]] = []
        self._record_outcome_raises = record_outcome_raises

    def fetch_pii_registry_resources(self, owner_connector=None):
        assert owner_connector == "manual"
        return {"resources": self._registry_resources}

    def batch_create_keys(self, user_ids):
        self.create_keys_calls.append(list(user_ids))

    def batch_get_encryption_contexts(self, user_ids):
        return {uid: self._contexts[uid] for uid in user_ids if uid in self._contexts}

    def mark_resource_synced(self, resource_id, synced_at_iso):
        if self._mark_synced_raises:
            raise RuntimeError("Key Vault unreachable")
        self.mark_synced_calls.append((resource_id, synced_at_iso))

    def mark_resource_sync_attempted(self, resource_id, attempted_at_iso):
        if self._mark_sync_attempted_raises:
            raise RuntimeError("Key Vault unreachable")
        self.mark_sync_attempted_calls.append((resource_id, attempted_at_iso))

    def create_sync_run(self, run_id, resource_id=None):
        self.create_sync_run_calls.append((run_id, resource_id))

    def finalize_sync_run_total(self, run_id, chunks_total):
        self.finalize_sync_run_total_calls.append((run_id, chunks_total))

    def record_sync_chunk_outcome(self, run_id, outcome):
        # Real VaultClient.record_sync_chunk_outcome never raises (catches
        # internally) -- this flag exists only to test process_chunk's own
        # behavior stays correct even if that contract were ever violated.
        if self._record_outcome_raises:
            raise RuntimeError("Key Vault unreachable")
        self.record_chunk_outcome_calls.append((run_id, outcome))


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

MANUAL_RESOURCE_INCREMENTAL = {
    **MANUAL_RESOURCE,
    "updatedAtColumn": "updated_at",
    "lastSyncedAt": "2026-08-01T00:00:00+00:00",
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


class TestIncrementalSync:
    """Opt-in incremental enumerate_resource: only eligible when both
    updatedAtColumn and lastSyncedAt are set on the resource, never forced,
    and only ever advances the watermark after a fully successful run."""

    def test_a_resource_with_no_watermark_fields_keeps_full_scan_and_never_marks_synced(self):
        source_rows = [{"user_id": "u1", "tenant_id": "acme"}]
        vault = FakeVault([MANUAL_RESOURCE], {})
        bq = FakeBigQueryClient(source_rows)
        job = make_job(bq, vault)

        job.sync_all()

        assert "last_synced_at" not in bq.query_params_log[0]
        assert vault.mark_synced_calls == []
        # But this resource still genuinely synced -- the separate,
        # unconditional sync-attempt signal must still advance (see
        # TestSyncAttemptSignal below).
        assert len(vault.mark_sync_attempted_calls) == 1

    def test_eligible_resource_queries_with_the_watermark_filter_and_advances_it(self):
        source_rows = [
            {"user_id": "u1", "tenant_id": "acme", "updated_at": "2026-08-05T00:00:00+00:00"},
        ]
        vault = FakeVault([MANUAL_RESOURCE_INCREMENTAL], {})
        bq = FakeBigQueryClient(source_rows)
        job = make_job(bq, vault)

        job.sync_all()

        # Real bigquery.ScalarQueryParameter(..., "TIMESTAMP", ...) coerces
        # .value to a parsed datetime, not the original string.
        assert bq.query_params_log[0]["last_synced_at"].isoformat() == "2026-08-01T00:00:00+00:00"
        assert ">=" in bq.queries[0]  # not a strict > -- see enumerate_resource's own comment
        assert len(vault.mark_synced_calls) == 1
        resource_id, synced_at = vault.mark_synced_calls[0]
        assert resource_id == "bigquery:proj.dataset.federated_user"
        # A real ISO8601 timestamp, captured before the query ran (not just
        # "some string") -- parseable and not the fixture's own old watermark.
        assert synced_at != "2026-08-01T00:00:00+00:00"
        datetime.fromisoformat(synced_at)

    def test_a_resource_with_updated_at_column_but_no_prior_watermark_does_one_full_scan_then_sets_it(self):
        # First-ever sync for a newly-opted-in resource: eligibility requires
        # BOTH fields, so this still full-scans once, but the watermark gets
        # established for every subsequent run to filter on.
        first_time_resource = {**MANUAL_RESOURCE, "updatedAtColumn": "updated_at"}  # no lastSyncedAt yet
        source_rows = [{"user_id": "u1", "tenant_id": "acme", "updated_at": "2020-01-01T00:00:00+00:00"}]
        vault = FakeVault([first_time_resource], {})
        bq = FakeBigQueryClient(source_rows)
        job = make_job(bq, vault)

        results = job.sync_all()

        assert results[0].chunks_queued == 1  # the old row was still picked up -- full scan, not filtered
        assert "last_synced_at" not in bq.query_params_log[0]
        assert len(vault.mark_synced_calls) == 1

    def test_force_full_scan_bypasses_incremental_even_when_eligible(self):
        source_rows = [{"user_id": "u1", "tenant_id": "acme", "updated_at": "2020-01-01T00:00:00+00:00"}]
        vault = FakeVault([MANUAL_RESOURCE_INCREMENTAL], {})
        bq = FakeBigQueryClient(source_rows)
        job = make_job(bq, vault)

        results = job.sync_all(force_full_scan=True)

        assert results[0].chunks_queued == 1  # picked up despite predating the watermark
        assert "last_synced_at" not in bq.query_params_log[0]
        # A forced-full run still validly covers everything up to its own
        # start time, and should still advance the watermark -- it correctly
        # primes the next incremental run rather than leaving it stale.
        assert len(vault.mark_synced_calls) == 1

    def test_a_watermark_write_failure_does_not_fail_an_otherwise_successful_sync(self):
        source_rows = [{"user_id": "u1", "tenant_id": "acme", "updated_at": "2026-08-05T00:00:00+00:00"}]
        vault = FakeVault([MANUAL_RESOURCE_INCREMENTAL], {}, mark_synced_raises=True)
        bq = FakeBigQueryClient(source_rows)
        job = make_job(bq, vault)

        results = job.sync_all()

        # A real BigQuery scan + Pub/Sub publish already succeeded -- a Key
        # Vault write hiccup on top of that shouldn't turn into a "sync
        # failed" result; worst case the next run just re-scans once more.
        assert results[0].error is None
        assert results[0].chunks_queued == 1


class TestSyncAttemptSignal:
    """lastSyncAttemptAt: advances after every successful enumerate_resource
    run, regardless of updatedAtColumn/incremental eligibility -- fixes the
    registry UI permanently showing "Never synced" for a resource that only
    ever does full scans."""

    def test_advances_for_a_resource_with_no_updatedAtColumn(self):
        source_rows = [{"user_id": "u1", "tenant_id": "acme"}]
        vault = FakeVault([MANUAL_RESOURCE], {})
        bq = FakeBigQueryClient(source_rows)
        job = make_job(bq, vault)

        job.sync_all()

        assert len(vault.mark_sync_attempted_calls) == 1
        resource_id, attempted_at = vault.mark_sync_attempted_calls[0]
        assert resource_id == "bigquery:proj.dataset.federated_user"
        datetime.fromisoformat(attempted_at)  # a real, parseable ISO8601 timestamp

    def test_advances_alongside_the_incremental_watermark_for_an_eligible_resource(self):
        source_rows = [{"user_id": "u1", "tenant_id": "acme", "updated_at": "2026-08-05T00:00:00+00:00"}]
        vault = FakeVault([MANUAL_RESOURCE_INCREMENTAL], {})
        bq = FakeBigQueryClient(source_rows)
        job = make_job(bq, vault)

        job.sync_all()

        assert len(vault.mark_synced_calls) == 1
        assert len(vault.mark_sync_attempted_calls) == 1

    def test_a_sync_attempt_write_failure_does_not_fail_an_otherwise_successful_sync(self):
        source_rows = [{"user_id": "u1", "tenant_id": "acme"}]
        vault = FakeVault([MANUAL_RESOURCE], {}, mark_sync_attempted_raises=True)
        bq = FakeBigQueryClient(source_rows)
        job = make_job(bq, vault)

        results = job.sync_all()

        assert results[0].error is None
        assert results[0].chunks_queued == 1

    def test_does_not_advance_when_the_resource_has_no_encrypt_fields_or_is_skipped(self):
        no_encrypt_resource = {**MANUAL_RESOURCE, "piiFields": []}
        vault = FakeVault([no_encrypt_resource], {})
        bq = FakeBigQueryClient([{"user_id": "u1", "tenant_id": "acme"}])
        job = make_job(bq, vault)

        job.sync_all()

        # Skipped before any BigQuery query or Pub/Sub publish -- nothing
        # was actually attempted, so nothing should be marked attempted.
        assert vault.mark_sync_attempted_calls == []


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


class TestSyncRunProgressReporting:
    """run_id threading: enumerate_resource's chunk payloads carry it,
    process_chunk reports completed/failed outcomes with it. None of this
    is required -- a chunk published with no run_id (the pre-existing
    behavior, still exercised by TestEnumerateResource/TestProcessChunk
    above) skips progress reporting entirely."""

    def test_enumerate_resource_includes_run_id_in_published_chunk_payloads(self):
        source_rows = [{"user_id": "u1", "tenant_id": "acme"}]
        vault = FakeVault([MANUAL_RESOURCE], {})
        bq = FakeBigQueryClient(source_rows)
        publisher = FakePublisher()
        job = make_job(bq, vault, publisher)

        job.sync_all(run_id="run-abc")

        _, message = publisher.published[0]
        assert message["run_id"] == "run-abc"

    def test_process_chunk_reports_completed_outcome_on_success(self):
        source_rows = [{"user_id": "u1", "tenant_id": "acme", "email": "u1@example.com"}]
        vault = FakeVault([MANUAL_RESOURCE], {"u1": make_context()})
        bq = FakeBigQueryClient(source_rows)
        job = make_job(bq, vault)

        synced = job.process_chunk("bigquery:proj.dataset.federated_user", ["u1"], run_id="run-abc")

        assert synced == 1
        assert vault.record_chunk_outcome_calls == [("run-abc", "completed")]

    def test_process_chunk_reports_failed_outcome_and_reraises_on_exception(self):
        vault = FakeVault([MANUAL_RESOURCE], {})

        class ExplodingBigQueryClient:
            def query(self, *args, **kwargs):
                raise RuntimeError("BigQuery unavailable")

        job = make_job(ExplodingBigQueryClient(), vault)

        with pytest.raises(RuntimeError, match="BigQuery unavailable"):
            job.process_chunk("bigquery:proj.dataset.federated_user", ["u1"], run_id="run-abc")

        assert vault.record_chunk_outcome_calls == [("run-abc", "failed")]

    def test_process_chunk_skips_progress_reporting_when_run_id_is_none(self):
        source_rows = [{"user_id": "u1", "tenant_id": "acme", "email": "u1@example.com"}]
        vault = FakeVault([MANUAL_RESOURCE], {"u1": make_context()})
        bq = FakeBigQueryClient(source_rows)
        job = make_job(bq, vault)

        job.process_chunk("bigquery:proj.dataset.federated_user", ["u1"])

        assert vault.record_chunk_outcome_calls == []


class FlakyBigQueryClient(FakeBigQueryClient):
    """Same as FakeBigQueryClient, except insert_rows_json raises
    TooManyRequests on its first `raise_count` calls -- simulates
    BigQuery's per-table write-rate quota tripping on a streaming insert."""

    def __init__(self, *args, raise_count=0, **kwargs):
        super().__init__(*args, **kwargs)
        self._raise_count = raise_count
        self._load_attempts = [0]

    def insert_rows_json(self, table_ref, records):
        self._load_attempts[0] += 1
        if self._load_attempts[0] <= self._raise_count:
            raise TooManyRequests("Exceeded rate limits: too many table update operations for this table.")
        self.load_calls.append((records, table_ref))
        return []


class TestLoadVaultRecordsRetry:
    """_load_vault_records: even a streaming insert per 100-user chunk can
    still trip BigQuery's per-table write-rate quota under enough
    concurrent chunks (confirmed live against Immoscoop's real sync,
    2026-08-19). Must retry with backoff instead of dropping the chunk's
    data or failing the sync outright on the first rate-limit response."""

    def test_retries_a_rate_limited_load_job_and_still_syncs(self, monkeypatch):
        monkeypatch.setattr("app.scanners.pii_vault_sync.time.sleep", lambda _seconds: None)
        source_rows = [{"user_id": "u1", "tenant_id": "acme", "email": "u1@example.com"}]
        vault = FakeVault([MANUAL_RESOURCE], {"u1": make_context()})
        bq = FlakyBigQueryClient(source_rows, raise_count=2)  # fails twice, succeeds on the 3rd attempt
        job = make_job(bq, vault)

        synced = job.process_chunk("bigquery:proj.dataset.federated_user", ["u1"])

        assert synced == 1
        assert len(bq.loaded_records) == 1
        assert bq._load_attempts[0] == 3

    def test_re_raises_once_retries_are_exhausted(self, monkeypatch):
        monkeypatch.setattr("app.scanners.pii_vault_sync.time.sleep", lambda _seconds: None)
        source_rows = [{"user_id": "u1", "tenant_id": "acme", "email": "u1@example.com"}]
        vault = FakeVault([MANUAL_RESOURCE], {"u1": make_context()})
        bq = FlakyBigQueryClient(source_rows, raise_count=PiiVaultSyncJob.LOAD_MAX_RETRIES)
        job = make_job(bq, vault)

        with pytest.raises(TooManyRequests):
            job.process_chunk("bigquery:proj.dataset.federated_user", ["u1"])

        assert bq._load_attempts[0] == PiiVaultSyncJob.LOAD_MAX_RETRIES
        assert bq.loaded_records == []  # never actually landed the chunk's data

    def test_does_not_sleep_at_all_when_the_first_attempt_succeeds(self, monkeypatch):
        sleep_calls = []
        monkeypatch.setattr("app.scanners.pii_vault_sync.time.sleep", lambda seconds: sleep_calls.append(seconds))
        source_rows = [{"user_id": "u1", "tenant_id": "acme", "email": "u1@example.com"}]
        vault = FakeVault([MANUAL_RESOURCE], {"u1": make_context()})
        bq = FlakyBigQueryClient(source_rows, raise_count=0)
        job = make_job(bq, vault)

        synced = job.process_chunk("bigquery:proj.dataset.federated_user", ["u1"])

        assert synced == 1
        assert sleep_calls == []

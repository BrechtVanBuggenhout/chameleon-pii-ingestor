import base64
import json
import logging
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from google.cloud import bigquery

from app.core.crypto import ChameleonCrypto
from app.policies.pii_registry import PiiMetadataRegistry, RegistryResource
from app.scanners.encrypted_copy_writer import EncryptedCopyWriter
from app.services.bigquery_streaming_insert import insert_with_retry
from app.services.vault_client import VaultClient

logger = logging.getLogger(__name__)

_RESOURCE_ID_RE = re.compile(r"^bigquery:([^.]+)\.([^.]+)\.([^.]+)$")


def parse_bigquery_resource_id(resource_id: str) -> tuple[str, str, str]:
    match = _RESOURCE_ID_RE.match(resource_id)
    if not match:
        raise ValueError(f'"{resource_id}" is not a bigquery resource ID in the form bigquery:project.dataset.table.')
    return match.group(1), match.group(2), match.group(3)


@dataclass(frozen=True)
class VaultSyncResult:
    resource_id: str
    chunks_queued: int
    error: Optional[str] = None


class PiiVaultSyncJob:
    """
    Daily backfill/sync of manually-declared resources into the central
    pii_vault table -- retroactive protection for tables a customer already
    owns, that were never going to flow through Chameleon's own ingestion
    pipeline.

    Two-phase, fan-out design: `sync_all`/`enumerate_resource` is the fast
    entry point every trigger (the daily scheduler, and the console's
    on-demand "Sync Now") calls -- it reads only user IDs from a declared
    resource's source table, chunks them, and publishes one Pub/Sub message
    per chunk to the pii_vault_sync_chunks topic, then returns immediately.
    The actual encrypt-diff-insert work happens later, per chunk, in
    `process_chunk`, invoked by that topic's own push subscription.

    This replaced an earlier single-invocation design (one call processed
    an entire resource's users synchronously) after a real problem surfaced
    live: a first-time backfill of Immoscoop's ~530k real users completed
    successfully server-side, but the client that triggered it (a plain
    browser fetch through the console) gave up waiting long before the job
    finished, reporting failure even though the sync had actually worked.
    Chunking the *trigger* itself, not just the internal processing, means
    a trigger call is always fast regardless of table size -- and since a
    Pub/Sub push subscription enforces a hard 600-second ack deadline,
    keeping each chunk's own processing time well under that (by construction,
    CHUNK_SIZE users at a time) avoids ever risking a duplicate redelivery
    of a still-running chunk.

    `enumerate_resource` deliberately selects ONLY the user ID column from
    the source table, never the PII field values -- those are re-read fresh,
    per chunk, in `process_chunk`, immediately before encrypting. Putting
    plaintext PII into a Pub/Sub message body would be a real step backward
    from the existing read-then-immediately-encrypt-in-process pattern used
    everywhere else in this codebase (see ingestion.py), even though message
    size wouldn't be an issue.

    pii_vault is flat -- one row per (tenant_id, user_id, resource_id,
    field_name), that's the natural unique key -- so `process_chunk`'s
    "already synced" check is scoped per field, not per user: a user missing
    only some of their declared fields gets just those appended, without
    ever re-touching or duplicating what they already have. Deliberately
    only detects fields that have never been synced for a user, not changes
    to a field already synced (e.g. their email changing in the source
    table) -- a known, deliberate limitation (recomputing this for every
    field of every user, every run, forever, has a real, unbounded ongoing
    cost that isn't worth it for this gap).

    Encryption reuses the exact same per-user DEK + local AES-GCM +
    HMAC-token pattern as the real ingestion pipeline (see
    app/pipelines/ingestion.py's _encrypt_field / generate_token usage),
    so a row synced here is indistinguishable in shape from one that came
    through normal ingestion, and shredding a user's key makes both
    equally unreadable.
    """

    VAULT_TABLE_ID = "pii_vault"
    # Both the enumeration query and the per-chunk re-query are scoped to
    # this many user IDs at a time -- keeps enumeration's own memory
    # footprint trivial (it only ever holds ID strings, never full rows),
    # and keeps each chunk's processing time comfortably under Pub/Sub's
    # 600-second push ack deadline.
    CHUNK_SIZE = 100
    # Streaming inserts (tabledata.insertAll), not load jobs. A load job
    # per 100-user chunk -- even capped at 20 concurrent writers
    # (max_instance_request_concurrency=4 * max_instance_count=5, see
    # chameleon-infra-gcp) -- still tripped BigQuery's per-table LOAD JOB
    # quota ("too many table update operations for this table") at real
    # scale (confirmed live against Immoscoop's ~540k-row federated_user
    # sync, 2026-08-19, even after that concurrency cap was already
    # tightened once before for the same symptom). Streaming inserts are a
    # genuinely different BigQuery API with a much higher, purpose-built
    # quota for exactly this "many small concurrent writes to one table"
    # shape -- not just a bigger number on the same quota. Safe here
    # specifically because this table's idempotency is already enforced at
    # the application layer (_fetch_existing_fields diffs before ever
    # building a record to write), not by load-job atomicity -- a partial
    # streaming batch on a crash just gets picked up correctly by the next
    # chunk run, nothing to lose.
    LOAD_MAX_RETRIES = 5
    LOAD_BASE_BACKOFF_SECONDS = 2

    def __init__(
        self,
        bigquery_client: Any,
        vault: VaultClient,
        vault_project_id: str,
        vault_dataset_id: str,
        publisher: Any,
        chunk_topic_path: str,
    ):
        self.bigquery_client = bigquery_client
        self.vault = vault
        self.vault_project_id = vault_project_id
        self.vault_dataset_id = vault_dataset_id
        self.publisher = publisher
        self.chunk_topic_path = chunk_topic_path
        self.encrypted_copy_writer = EncryptedCopyWriter(bigquery_client)

    def sync_all(self, force_full_scan: bool = False, run_id: Optional[str] = None) -> List[VaultSyncResult]:
        registry_data = self.vault.fetch_pii_registry_resources(owner_connector="manual")
        registry = PiiMetadataRegistry.from_api_response(registry_data)

        results: List[VaultSyncResult] = []
        for resource in registry.resources:
            try:
                count = self.enumerate_resource(resource, force_full_scan=force_full_scan, run_id=run_id)
                results.append(VaultSyncResult(resource_id=resource.id, chunks_queued=count))
            except Exception as e:
                logger.error(f"Failed to enumerate {resource.id} for pii_vault sync: {e}")
                results.append(VaultSyncResult(resource_id=resource.id, chunks_queued=0, error=str(e)))
        return results

    def sync_one(
        self, resource_id: str, force_full_scan: bool = False, run_id: Optional[str] = None
    ) -> VaultSyncResult:
        """
        Same as sync_all, scoped to a single declared resource -- backs the
        console's per-resource Sync Now action so re-syncing one large,
        already-synced table doesn't mean re-scanning every other declared
        resource for the tenant too.
        """
        try:
            data = self.vault.fetch_pii_registry_resource(resource_id)
            resource_data = data.get("resource")
            if not resource_data:
                return VaultSyncResult(resource_id=resource_id, chunks_queued=0, error="Resource not found in registry")
            resource = RegistryResource.from_dict(resource_data)
            if resource.owner_connector != "manual":
                return VaultSyncResult(
                    resource_id=resource.id,
                    chunks_queued=0,
                    error="Sync Now only applies to manually-declared resources",
                )
            count = self.enumerate_resource(resource, force_full_scan=force_full_scan, run_id=run_id)
            return VaultSyncResult(resource_id=resource.id, chunks_queued=count)
        except Exception as e:
            logger.error(f"Failed to enumerate {resource_id} for pii_vault sync: {e}")
            return VaultSyncResult(resource_id=resource_id, chunks_queued=0, error=str(e))

    def enumerate_resource(
        self, resource: RegistryResource, force_full_scan: bool = False, run_id: Optional[str] = None
    ) -> int:
        if resource.system != "bigquery":
            logger.info(f"Skipping {resource.id} -- only bigquery sources are supported today")
            return 0
        if not resource.user_id_column:
            logger.warning(f"Skipping {resource.id} -- no userIdColumn declared, can't scope rows to a user")
            return 0

        encrypt_fields = [c for c in resource.columns if c.handling == "ENCRYPT"]
        if not encrypt_fields:
            logger.info(f"Skipping {resource.id} -- no ENCRYPT-handling fields declared")
            return 0

        project_id, dataset_id, table_id = parse_bigquery_resource_id(resource.id)

        # Captured before the query runs, not after -- once a BigQuery query
        # job starts, its result set is fixed for the life of that job, so
        # any row committed after this point is guaranteed to be picked up
        # by the >= filter next run, never silently lost to mid-scan drift.
        job_start_time = datetime.now(timezone.utc)

        incremental = bool(not force_full_scan and resource.updated_at_column and resource.last_synced_at)
        if incremental:
            # >= not > -- a strict > has a permanent-miss failure mode if a
            # row's updated_at is ever exactly equal to a previously-captured
            # watermark (e.g. a coarse or shared clock in the customer's own
            # ETL). _fetch_existing_fields' per-user-per-field idempotency
            # already absorbs the resulting reprocessed-row overlap for free.
            query = f"""
SELECT {resource.user_id_column}
FROM `{project_id}.{dataset_id}.{table_id}`
WHERE {resource.user_id_column} IS NOT NULL
  AND {resource.updated_at_column} >= @last_synced_at
"""
            job_config = bigquery.QueryJobConfig(
                query_parameters=[
                    bigquery.ScalarQueryParameter("last_synced_at", "TIMESTAMP", resource.last_synced_at)
                ]
            )
            row_iterator = self.bigquery_client.query(query, job_config=job_config).result()
        else:
            query = f"""
SELECT {resource.user_id_column}
FROM `{project_id}.{dataset_id}.{table_id}`
WHERE {resource.user_id_column} IS NOT NULL
"""
            # Deliberately NOT wrapped in list(...) -- same reasoning as the
            # old single-phase design: page results in from the API as we go
            # rather than holding the whole table at once. Much cheaper here
            # regardless, since each row is now just one ID string, not a
            # full row of PII field values plus encryption context.
            row_iterator = self.bigquery_client.query(query).result()

        chunks_queued = 0
        chunk: List[str] = []
        for row in row_iterator:
            chunk.append(str(row[resource.user_id_column]))
            if len(chunk) >= self.CHUNK_SIZE:
                self._publish_chunk(resource.id, chunk, run_id=run_id)
                chunks_queued += 1
                chunk = []
        if chunk:
            self._publish_chunk(resource.id, chunk, run_id=run_id)
            chunks_queued += 1

        # Only reached if every chunk above published successfully -- an
        # exception mid-loop propagates up to sync_all's own per-resource
        # try/except instead, which deliberately does NOT advance either
        # timestamp below, so a partially-failed run gets fully retried next
        # time rather than silently skipping whatever it didn't get to.
        if resource.updated_at_column:
            try:
                self.vault.mark_resource_synced(resource.id, job_start_time.isoformat())
            except Exception as e:
                # A full BigQuery scan already succeeded above -- don't turn
                # a Key Vault write hiccup into a "sync failed" result. Worst
                # case, the next run just re-scans this resource once more.
                logger.error(f"Failed to advance sync watermark for {resource.id}: {e}")

        # Unconditional, unlike the incremental watermark above -- a
        # resource with no updatedAtColumn still genuinely syncs (real
        # chunks just got published above) but would otherwise never
        # advance any sync-status signal at all.
        try:
            self.vault.mark_resource_sync_attempted(resource.id, job_start_time.isoformat())
        except Exception as e:
            logger.error(f"Failed to record sync attempt for {resource.id}: {e}")

        return chunks_queued

    def _publish_chunk(self, resource_id: str, user_ids: List[str], run_id: Optional[str] = None) -> None:
        payload_dict: Dict[str, Any] = {"resource_id": resource_id, "user_ids": user_ids}
        if run_id:
            payload_dict["run_id"] = run_id
        payload = json.dumps(payload_dict).encode("utf-8")
        future = self.publisher.publish(self.chunk_topic_path, payload)
        # Block for the publish to actually succeed rather than fire-and-forget --
        # a silently dropped chunk means those users never get synced at all,
        # with nothing left to retry them.
        future.result()

    def process_chunk(self, resource_id: str, user_ids: List[str], run_id: Optional[str] = None) -> int:
        try:
            result = self._process_chunk_inner(resource_id, user_ids)
        except Exception:
            if run_id:
                self.vault.record_sync_chunk_outcome(run_id, "failed")
            raise
        if run_id:
            self.vault.record_sync_chunk_outcome(run_id, "completed")
        return result

    def _process_chunk_inner(self, resource_id: str, user_ids: List[str]) -> int:
        registry_data = self.vault.fetch_pii_registry_resources(owner_connector="manual")
        registry = PiiMetadataRegistry.from_api_response(registry_data)
        resource = next((r for r in registry.resources if r.id == resource_id), None)
        if resource is None:
            logger.warning(f"process_chunk: {resource_id} is no longer declared, dropping a chunk of {len(user_ids)} users")
            return 0

        encrypt_fields = [c for c in resource.columns if c.handling == "ENCRYPT"]
        if not encrypt_fields:
            return 0

        project_id, dataset_id, table_id = parse_bigquery_resource_id(resource.id)
        field_names = [c.name for c in encrypt_fields]
        select_cols = ", ".join(
            [resource.user_id_column] + field_names + ([resource.tenant_id_column] if resource.tenant_id_column else [])
        )

        query = f"""
SELECT {select_cols}
FROM `{project_id}.{dataset_id}.{table_id}`
WHERE CAST({resource.user_id_column} AS STRING) IN UNNEST(@user_ids)
"""
        job_config = bigquery.QueryJobConfig(
            query_parameters=[bigquery.ArrayQueryParameter("user_ids", "STRING", user_ids)]
        )
        rows = list(self.bigquery_client.query(query, job_config=job_config).result())

        return self._sync_chunk(resource, encrypt_fields, rows)

    def _sync_chunk(self, resource: RegistryResource, encrypt_fields: List[Any], rows: List[Any]) -> int:
        if not rows:
            return 0

        user_ids = [str(row[resource.user_id_column]) for row in rows]
        existing_fields_by_user = self._fetch_existing_fields(resource.id, user_ids)

        # Only users missing at least one declared field need a key/context
        # at all -- skip fully-synced users entirely rather than spending a
        # Vault round-trip just to confirm we already have everything.
        rows_needing_work: List[Any] = []
        missing_fields_by_user: Dict[str, List[Any]] = {}
        for row in rows:
            user_id = str(row[resource.user_id_column])
            already_synced = existing_fields_by_user.get(user_id, set())
            missing = [c for c in encrypt_fields if c.name not in already_synced]
            if missing:
                rows_needing_work.append(row)
                missing_fields_by_user[user_id] = missing

        if not rows_needing_work:
            return 0

        work_user_ids = [str(row[resource.user_id_column]) for row in rows_needing_work]
        # These are pre-existing users who've never been through Chameleon's
        # ingestion pipeline, so they have no key yet -- batch_create_keys is
        # a no-op for anyone who already has one (same as ingestion.py's real
        # ingestion path), but is required here, unlike there, since it can
        # never be assumed to have already happened for this table.
        self.vault.batch_create_keys(work_user_ids)
        contexts = self.vault.batch_get_encryption_contexts(work_user_ids)

        now_iso = datetime.now(timezone.utc).isoformat()
        vault_records: List[Dict[str, Any]] = []
        synced_user_ids: Set[str] = set()
        for row in rows_needing_work:
            user_id = str(row[resource.user_id_column])
            context = contexts.get(user_id)
            if not context:
                logger.warning(f"No encryption context for user {user_id} in {resource.id}, skipping")
                continue

            tenant_id = (
                str(row[resource.tenant_id_column]) if resource.tenant_id_column else self.vault.tenant_id
            )

            for column in missing_fields_by_user[user_id]:
                raw_value = row[column.name]
                if raw_value is None:
                    continue
                value = str(raw_value)
                vault_records.append(
                    {
                        "tenant_id": tenant_id,
                        "user_id": user_id,
                        "resource_id": resource.id,
                        "field_name": column.name,
                        "key_id": context.get("key_id"),
                        "token": ChameleonCrypto.generate_token(context["dek"], value),
                        "encrypted_value": base64.b64encode(
                            ChameleonCrypto.encrypt_field_bundle(context, user_id, value)
                        ).decode("utf-8"),
                        "synced_at": now_iso,
                    }
                )
                synced_user_ids.add(user_id)

        if vault_records:
            self._load_vault_records(vault_records)
            self._append_encrypted_copy(resource, rows_needing_work, vault_records)

        return len(synced_user_ids)

    def _append_encrypted_copy(
        self, resource: RegistryResource, rows_needing_work: List[Any], vault_records: List[Dict[str, Any]]
    ) -> None:
        """Best-effort: the real pii_vault write above has already
        succeeded by the time this runs, and must never be undone by a
        problem here. Most commonly hit when a resource has just been
        declared with ENCRYPTED_COPY but Key Vault's declare-time
        ensureEncryptedCopyTable() hasn't created `{table}_encrypted_raw`
        yet (or failed to) -- this chunk's real work is still complete
        without it; the next sync run picks up the backfill once the table
        exists."""
        if not resource.wants_encrypted_copy():
            return
        try:
            self.encrypted_copy_writer.append(resource, rows_needing_work, vault_records)
        except Exception as e:
            logger.warning(f"Encrypted-copy append failed for {resource.id}, continuing without it: {e}")

    def _fetch_existing_fields(self, resource_id: str, user_ids: List[str]) -> Dict[str, Set[str]]:
        """Which (user_id, field_name) pairs this chunk's users already have
        in pii_vault for this resource -- the per-field diff that lets a
        partially-synced user pick up only their missing fields."""
        query = f"""
SELECT user_id, field_name
FROM `{self.vault_project_id}.{self.vault_dataset_id}.{self.VAULT_TABLE_ID}`
WHERE resource_id = @resource_id
  AND user_id IN UNNEST(@user_ids)
"""
        job_config = bigquery.QueryJobConfig(
            query_parameters=[
                bigquery.ScalarQueryParameter("resource_id", "STRING", resource_id),
                bigquery.ArrayQueryParameter("user_ids", "STRING", user_ids),
            ]
        )
        rows = self.bigquery_client.query(query, job_config=job_config).result()
        existing: Dict[str, Set[str]] = {}
        for row in rows:
            existing.setdefault(row["user_id"], set()).add(row["field_name"])
        return existing

    def _load_vault_records(self, records: List[Dict[str, Any]]) -> None:
        table_ref = f"{self.vault_project_id}.{self.vault_dataset_id}.{self.VAULT_TABLE_ID}"
        insert_with_retry(
            self.bigquery_client, table_ref, records, self.LOAD_MAX_RETRIES, self.LOAD_BASE_BACKOFF_SECONDS
        )

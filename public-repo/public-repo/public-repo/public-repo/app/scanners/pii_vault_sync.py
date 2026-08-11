import base64
import json
import logging
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from google.cloud import bigquery

from app.core.crypto import ChameleonCrypto
from app.policies.pii_registry import PiiMetadataRegistry, RegistryResource
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

    def sync_all(self, force_full_scan: bool = False) -> List[VaultSyncResult]:
        registry_data = self.vault.fetch_pii_registry_resources(owner_connector="manual")
        registry = PiiMetadataRegistry.from_api_response(registry_data)

        results: List[VaultSyncResult] = []
        for resource in registry.resources:
            try:
                count = self.enumerate_resource(resource, force_full_scan=force_full_scan)
                results.append(VaultSyncResult(resource_id=resource.id, chunks_queued=count))
            except Exception as e:
                logger.error(f"Failed to enumerate {resource.id} for pii_vault sync: {e}")
                results.append(VaultSyncResult(resource_id=resource.id, chunks_queued=0, error=str(e)))
        return results

    def sync_one(self, resource_id: str, force_full_scan: bool = False) -> VaultSyncResult:
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
            count = self.enumerate_resource(resource, force_full_scan=force_full_scan)
            return VaultSyncResult(resource_id=resource.id, chunks_queued=count)
        except Exception as e:
            logger.error(f"Failed to enumerate {resource_id} for pii_vault sync: {e}")
            return VaultSyncResult(resource_id=resource_id, chunks_queued=0, error=str(e))

    def enumerate_resource(self, resource: RegistryResource, force_full_scan: bool = False) -> int:
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
                self._publish_chunk(resource.id, chunk)
                chunks_queued += 1
                chunk = []
        if chunk:
            self._publish_chunk(resource.id, chunk)
            chunks_queued += 1

        # Only reached if every chunk above published successfully -- an
        # exception mid-loop propagates up to sync_all's own per-resource
        # try/except instead, which deliberately does NOT advance the
        # watermark, so a partially-failed run gets fully retried next time
        # rather than silently skipping whatever it didn't get to.
        if resource.updated_at_column:
            try:
                self.vault.mark_resource_synced(resource.id, job_start_time.isoformat())
            except Exception as e:
                # A full BigQuery scan already succeeded above -- don't turn
                # a Key Vault write hiccup into a "sync failed" result. Worst
                # case, the next run just re-scans this resource once more.
                logger.error(f"Failed to advance sync watermark for {resource.id}: {e}")

        return chunks_queued

    def _publish_chunk(self, resource_id: str, user_ids: List[str]) -> None:
        payload = json.dumps({"resource_id": resource_id, "user_ids": user_ids}).encode("utf-8")
        future = self.publisher.publish(self.chunk_topic_path, payload)
        # Block for the publish to actually succeed rather than fire-and-forget --
        # a silently dropped chunk means those users never get synced at all,
        # with nothing left to retry them.
        future.result()

    def process_chunk(self, resource_id: str, user_ids: List[str]) -> int:
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
                            self._encrypt_field(context, user_id, value)
                        ).decode("utf-8"),
                        "synced_at": now_iso,
                    }
                )
                synced_user_ids.add(user_id)

        if vault_records:
            self._load_vault_records(vault_records)

        return len(synced_user_ids)

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

    def _encrypt_field(self, context: Dict[str, Any], user_id: str, value: str) -> bytes:
        """Same bundle format as ingestion.py's _encrypt_field: `key_id:iv_b64:ciphertext_b64`,
        so anything that already knows how to decrypt raw_users.pii_fields can decrypt
        pii_vault's encrypted_value identically."""
        iv = os.urandom(12)
        raw_bundle_b64 = ChameleonCrypto.encrypt(context["dek"], user_id, value, iv=iv)
        raw_bundle = base64.b64decode(raw_bundle_b64)
        ciphertext_only = raw_bundle[12:]
        iv_b64 = base64.b64encode(iv).decode("utf-8")
        ciphertext_b64 = base64.b64encode(ciphertext_only).decode("utf-8")
        return f"{context['key_id']}:{iv_b64}:{ciphertext_b64}".encode("utf-8")

    def _load_vault_records(self, records: List[Dict[str, Any]]) -> None:
        table_ref = f"{self.vault_project_id}.{self.vault_dataset_id}.{self.VAULT_TABLE_ID}"
        job_config = bigquery.LoadJobConfig(
            source_format=bigquery.SourceFormat.NEWLINE_DELIMITED_JSON,
            write_disposition=bigquery.WriteDisposition.WRITE_APPEND,
        )
        load_job = self.bigquery_client.load_table_from_json(records, table_ref, job_config=job_config)
        load_job.result()
        logger.info(f"Synced {len(records)} fields into {table_ref}")

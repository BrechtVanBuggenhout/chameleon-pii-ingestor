import base64
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
    users_synced: int
    error: Optional[str] = None


class PiiVaultSyncJob:
    """
    Daily backfill/sync of manually-declared resources into the central
    pii_vault table -- retroactive protection for tables a customer already
    owns, that were never going to flow through Chameleon's own ingestion
    pipeline. For each such resource: finds which declared ENCRYPT fields
    are still missing per user, encrypts only those, and appends them.

    pii_vault is flat -- one row per (tenant_id, user_id, resource_id,
    field_name), that's the natural unique key, not one row per user with a
    nested field array -- so the "already synced" check is scoped per field,
    not per user. This matters because declaring a new field on an
    already-synced resource (e.g. adding `first_name` a week after `email`
    was first declared) correctly backfills just that new field for every
    existing user on the next run, without ever re-touching or duplicating
    fields they already have. A user missing some of their declared fields
    simply gets the missing ones appended as new rows.

    Encryption reuses the exact same per-user DEK + local AES-GCM +
    HMAC-token pattern as the real ingestion pipeline (see
    app/pipelines/ingestion.py's _encrypt_field / generate_token usage),
    so a row synced here is indistinguishable in shape from one that came
    through normal ingestion, and shredding a user's key makes both
    equally unreadable.

    Deliberately only detects fields that have never been synced for a
    user, not changes to a field already synced (e.g. their email changing
    in the source table) -- a known, named limitation for this pass, not a
    silently swallowed gap. Handling in-place updates would need a second
    mechanism if it turns out to matter.
    """

    VAULT_TABLE_ID = "pii_vault"
    # A first sync of an existing table processes every one of its rows --
    # for a real production user table that can be a lot of rows. Chunking
    # keeps peak memory bounded to one chunk's worth of rows/contexts/output
    # records regardless of table size, instead of materializing the entire
    # result set (a real OOM hit a real customer: usage scaled almost
    # exactly with whatever memory limit was configured, the signature of
    # an all-at-once accumulation, not a fixed per-request cost).
    #
    # Lowered from 500 -> 100: chunking alone didn't stop OOMs against real
    # data (this worker's own baseline footprint -- FastAPI + pandas + every
    # google-cloud-* client loaded at startup -- sits close to whatever
    # memory limit is configured, so even a 500-row chunk's transient
    # overhead was enough to tip it over). Paired with a memory bump on the
    # infra side; smaller chunks reduce the peak this code adds on top of
    # that fixed baseline, independent of how generous the limit is.
    CHUNK_SIZE = 100

    def __init__(
        self,
        bigquery_client: Any,
        vault: VaultClient,
        vault_project_id: str,
        vault_dataset_id: str,
    ):
        self.bigquery_client = bigquery_client
        self.vault = vault
        self.vault_project_id = vault_project_id
        self.vault_dataset_id = vault_dataset_id

    def sync_all(self) -> List[VaultSyncResult]:
        registry_data = self.vault.fetch_pii_registry_resources(owner_connector="manual")
        registry = PiiMetadataRegistry.from_api_response(registry_data)

        results: List[VaultSyncResult] = []
        for resource in registry.resources:
            try:
                count = self.sync_resource(resource)
                results.append(VaultSyncResult(resource_id=resource.id, users_synced=count))
            except Exception as e:
                logger.error(f"Failed to sync {resource.id} into pii_vault: {e}")
                results.append(VaultSyncResult(resource_id=resource.id, users_synced=0, error=str(e)))
        return results

    def sync_resource(self, resource: RegistryResource) -> int:
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
        field_names = [c.name for c in encrypt_fields]
        select_cols = ", ".join(
            [resource.user_id_column] + field_names + ([resource.tenant_id_column] if resource.tenant_id_column else [])
        )

        # No "already synced" exclusion here -- pii_vault is scoped per
        # field now, so whether a user needs any work at all depends on
        # *which* fields they're missing, not just whether they appear in
        # the vault anywhere. That diff happens per chunk in _sync_chunk,
        # scoped to just that chunk's user_ids, instead of one blanket
        # subquery against the whole vault table up front.
        query = f"""
SELECT {select_cols}
FROM `{project_id}.{dataset_id}.{table_id}`
WHERE {resource.user_id_column} IS NOT NULL
"""
        # Deliberately NOT wrapped in list(...) -- iterating the RowIterator
        # directly lets the BigQuery client page results in from the API as
        # we go, instead of downloading and holding the entire table in
        # memory before processing a single row.
        row_iterator = self.bigquery_client.query(query).result()

        total_synced = 0
        chunk: List[Any] = []
        for row in row_iterator:
            chunk.append(row)
            if len(chunk) >= self.CHUNK_SIZE:
                total_synced += self._sync_chunk(resource, encrypt_fields, chunk)
                chunk = []
        total_synced += self._sync_chunk(resource, encrypt_fields, chunk)

        return total_synced

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

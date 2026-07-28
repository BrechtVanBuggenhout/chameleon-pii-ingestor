import base64
import logging
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

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
    pipeline. For each such resource: finds user IDs present in the source
    table but not yet in the vault, encrypts their declared ENCRYPT-handling
    fields, and inserts them. Never touches the source table itself -- no
    redaction here, that's a separate, later, opt-in decision.

    Encryption reuses the exact same per-user DEK + local AES-GCM +
    HMAC-token pattern as the real ingestion pipeline (see
    app/pipelines/ingestion.py's _encrypt_field / generate_token usage),
    so a row synced here is indistinguishable in shape from one that came
    through normal ingestion, and shredding a user's key makes both
    equally unreadable.

    Deliberately only detects NET-NEW user IDs via a NOT IN check, not
    updates to an existing user's already-vaulted values (e.g. their email
    changing in the source table) -- a known, named limitation for this
    pass, not a silently swallowed gap. Handling in-place updates would
    need a second mechanism if it turns out to matter.
    """

    VAULT_TABLE_ID = "pii_vault"

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

        query = f"""
SELECT {select_cols}
FROM `{project_id}.{dataset_id}.{table_id}`
WHERE {resource.user_id_column} IS NOT NULL
  AND CAST({resource.user_id_column} AS STRING) NOT IN (
    SELECT user_id
    FROM `{self.vault_project_id}.{self.vault_dataset_id}.{self.VAULT_TABLE_ID}`
    WHERE resource_id = @resource_id
  )
"""
        job_config = bigquery.QueryJobConfig(
            query_parameters=[bigquery.ScalarQueryParameter("resource_id", "STRING", resource.id)]
        )
        rows = list(self.bigquery_client.query(query, job_config=job_config).result())
        if not rows:
            return 0

        user_ids = [str(row[resource.user_id_column]) for row in rows]
        # These are pre-existing users who've never been through Chameleon's
        # ingestion pipeline, so they have no key yet -- batch_create_keys is
        # a no-op for anyone who already has one (same as ingestion.py's real
        # ingestion path), but is required here, unlike there, since it can
        # never be assumed to have already happened for this table.
        self.vault.batch_create_keys(user_ids)
        contexts = self.vault.batch_get_encryption_contexts(user_ids)

        now_iso = datetime.now(timezone.utc).isoformat()
        vault_records: List[Dict[str, Any]] = []
        for row in rows:
            user_id = str(row[resource.user_id_column])
            context = contexts.get(user_id)
            if not context:
                logger.warning(f"No encryption context for user {user_id} in {resource.id}, skipping")
                continue

            tenant_id = (
                str(row[resource.tenant_id_column]) if resource.tenant_id_column else self.vault.tenant_id
            )

            pii_fields = []
            for column in encrypt_fields:
                raw_value = row[column.name]
                if raw_value is None:
                    continue
                value = str(raw_value)
                pii_fields.append(
                    {
                        "field_name": column.name,
                        "token": ChameleonCrypto.generate_token(context["dek"], value),
                        "encrypted_value": base64.b64encode(
                            self._encrypt_field(context, user_id, value)
                        ).decode("utf-8"),
                    }
                )

            if not pii_fields:
                continue

            vault_records.append(
                {
                    "tenant_id": tenant_id,
                    "user_id": user_id,
                    "resource_id": resource.id,
                    "key_id": context.get("key_id"),
                    "pii_fields": pii_fields,
                    "synced_at": now_iso,
                }
            )

        if vault_records:
            self._load_vault_records(vault_records)

        return len(vault_records)

    def _encrypt_field(self, context: Dict[str, Any], user_id: str, value: str) -> bytes:
        """Same bundle format as ingestion.py's _encrypt_field: `key_id:iv_b64:ciphertext_b64`,
        so anything that already knows how to decrypt raw_users.pii_fields can decrypt
        pii_vault.pii_fields identically."""
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
        logger.info(f"Synced {len(records)} users into {table_ref}")

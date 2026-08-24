import logging
import re
import time
from datetime import date, datetime
from typing import Any, Dict, List

from google.api_core.exceptions import TooManyRequests
from google.cloud import bigquery

from app.policies.pii_registry import RegistryResource

logger = logging.getLogger(__name__)

# Duplicated from pii_vault_sync.parse_bigquery_resource_id rather than
# imported -- pii_vault_sync imports EncryptedCopyWriter (to wire it into
# _sync_chunk), so importing back from it here would be a circular import.
_RESOURCE_ID_RE = re.compile(r"^bigquery:([^.]+)\.([^.]+)\.([^.]+)$")


def _parse_bigquery_resource_id(resource_id: str) -> tuple[str, str, str]:
    match = _RESOURCE_ID_RE.match(resource_id)
    if not match:
        raise ValueError(f'"{resource_id}" is not a bigquery resource ID in the form bigquery:project.dataset.table.')
    return match.group(1), match.group(2), match.group(3)


class EncryptedCopyWriter:
    """Populates the ENCRYPTED_COPY strategy's `{table}_encrypted_raw` table
    (see chameleon-key-vault's SourceRedactionService.ensureEncryptedCopyTable,
    which creates that table plus the `{table}_encrypted` dedup view on top
    of it, at declare time).

    Append-only, via the same insert_rows_json streaming-insert mechanism
    already used for pii_vault -- deliberately NOT a MERGE. A per-chunk
    MERGE would recreate the exact class of problem this codebase already
    hit once: BigQuery's DML/MERGE concurrency quota is a different quota
    than the load-job one PiiVaultSyncJob was moved off of, but the same
    shape of problem under high-concurrency chunk processing. A rare
    duplicate row (e.g. a genuine Pub/Sub redelivery) is harmless -- the
    `{table}_encrypted` view's QUALIFY ROW_NUMBER() ... ORDER BY synced_at
    DESC = 1 keeps only the latest row per user and ignores the rest.

    Reuses the exact ciphertext bundles PiiVaultSyncJob already computed for
    pii_vault's own vault_records -- never re-encrypts -- so a value
    decrypts identically whether read from pii_vault or from this table.
    """

    LOAD_MAX_RETRIES = 5
    LOAD_BASE_BACKOFF_SECONDS = 2

    def __init__(self, bigquery_client: Any):
        self.bigquery_client = bigquery_client

    def append(
        self,
        resource: RegistryResource,
        rows_needing_work: List[Any],
        vault_records: List[Dict[str, Any]],
    ) -> int:
        """Appends one wide row per user in rows_needing_work who actually
        had at least one field synced this chunk (mirrors vault_records,
        which is empty for a user whose only "missing" fields turned out to
        be NULL in the source table -- nothing to encrypt or copy for them
        either). Returns the number of rows appended; 0 if the resource
        isn't opted into ENCRYPTED_COPY or there's nothing to do."""
        if not resource.wants_encrypted_copy() or not rows_needing_work:
            return 0

        records_by_user: Dict[str, List[Dict[str, Any]]] = {}
        for record in vault_records:
            if record.get("resource_id") != resource.id:
                continue
            records_by_user.setdefault(record["user_id"], []).append(record)

        rows_to_insert: List[Dict[str, Any]] = []
        for row in rows_needing_work:
            user_id = str(row[resource.user_id_column])
            user_records = records_by_user.get(user_id)
            if not user_records:
                continue

            wide_row = {key: self._json_safe(value) for key, value in dict(row).items()}
            for record in user_records:
                wide_row[record["field_name"]] = record["encrypted_value"]
            wide_row["synced_at"] = user_records[0]["synced_at"]
            rows_to_insert.append(wide_row)

        if not rows_to_insert:
            return 0

        self._insert(resource, rows_to_insert)
        return len(rows_to_insert)

    @staticmethod
    def _json_safe(value: Any) -> Any:
        if isinstance(value, (datetime, date)):
            return value.isoformat()
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return value

    def _insert(self, resource: RegistryResource, records: List[Dict[str, Any]]) -> None:
        project_id, dataset_id, table_id = _parse_bigquery_resource_id(resource.id)
        table_ref = f"{project_id}.{dataset_id}.{table_id}_encrypted_raw"
        for attempt in range(1, self.LOAD_MAX_RETRIES + 1):
            try:
                errors = self.bigquery_client.insert_rows_json(table_ref, records)
                if errors:
                    raise RuntimeError(f"BigQuery streaming insert reported row errors: {errors}")
                logger.info(f"Appended {len(records)} rows into {table_ref}")
                return
            except TooManyRequests:
                if attempt == self.LOAD_MAX_RETRIES:
                    raise
                delay = self.LOAD_BASE_BACKOFF_SECONDS * (2 ** (attempt - 1))
                logger.warning(
                    f"{table_ref} streaming insert rate-limited (attempt {attempt}/{self.LOAD_MAX_RETRIES}), "
                    f"retrying in {delay}s"
                )
                time.sleep(delay)

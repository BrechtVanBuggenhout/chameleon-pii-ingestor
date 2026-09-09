import logging
import time
from typing import Any, Dict, List

from google.api_core.exceptions import TooManyRequests

logger = logging.getLogger(__name__)

# Streaming inserts (tabledata.insertAll), not load jobs -- a load job per
# chunk tripped BigQuery's per-table LOAD JOB quota at real scale (confirmed
# live against Immoscoop's ~540k-row federated_user sync, 2026-08-19).
# Streaming inserts are a genuinely different BigQuery API with a much
# higher, purpose-built quota for exactly this "many small concurrent
# writes to one table" shape. Safe wherever idempotency is already enforced
# at the application layer (a diff-before-write check, or a dedup view like
# ENCRYPTED_COPY's/pii_vault's QUALIFY ROW_NUMBER()), not by load-job
# atomicity -- a partial streaming batch on a crash just gets picked up
# correctly by the next run, nothing to lose.
DEFAULT_MAX_RETRIES = 5
DEFAULT_BASE_BACKOFF_SECONDS = 2


def insert_with_retry(
    bigquery_client: Any,
    table_ref: str,
    records: List[Dict[str, Any]],
    max_retries: int = DEFAULT_MAX_RETRIES,
    base_backoff_seconds: int = DEFAULT_BASE_BACKOFF_SECONDS,
) -> None:
    """
    Streams `records` into `table_ref` via insert_rows_json, retrying with
    exponential backoff on a rate-limit response. The one real
    implementation of this -- previously duplicated byte-for-byte in
    pii_vault_sync.py's _load_vault_records and encrypted_copy_writer.py's
    _insert, extracted here rather than adding a third copy for pubsub
    ingest.

    Raises on a real, non-retryable failure (per-row validation errors --
    retrying those would just fail identically) or once max_retries is
    exhausted against TooManyRequests.
    """
    for attempt in range(1, max_retries + 1):
        try:
            errors = bigquery_client.insert_rows_json(table_ref, records)
            if errors:
                raise RuntimeError(f"BigQuery streaming insert reported row errors: {errors}")
            logger.info(f"Streamed {len(records)} rows into {table_ref}")
            return
        except TooManyRequests:
            if attempt == max_retries:
                raise
            delay = base_backoff_seconds * (2 ** (attempt - 1))
            logger.warning(
                f"{table_ref} streaming insert rate-limited (attempt {attempt}/{max_retries}), "
                f"retrying in {delay}s"
            )
            time.sleep(delay)

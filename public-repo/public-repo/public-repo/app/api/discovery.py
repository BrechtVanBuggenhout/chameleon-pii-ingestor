import asyncio
import base64
import json
import logging
import uuid

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.config import settings
from app.scanners.warehouse_metadata_crawler import BigQueryWarehouseMetadataCrawler
from app.scanners.dbt_pii_discovery_publisher import DbtPiiDiscoveryPublisher
from app.scanners.pii_vault_sync import PiiVaultSyncJob

router = APIRouter()
logger = logging.getLogger(__name__)


def _comma_list(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


@router.post("/warehouse-crawl")
async def warehouse_crawl(request: Request):
    """
    Runs the BigQuery warehouse metadata crawler over the approved discovery datasets
    and emits WAREHOUSE_METADATA_DISCOVERED lineage events for undeclared / drifted
    tables. Intended to be invoked on a schedule (Cloud Scheduler -> Cloud Run, OIDC).
    Metadata only: column names, never values.
    """
    vault = request.app.state.vault
    bq_client = request.app.state.bq.client  # raw google.cloud.bigquery.Client

    crawler = BigQueryWarehouseMetadataCrawler(
        bigquery_client=bq_client,
        vault=vault,
        project_id=settings.warehouse_discovery_project_id_resolved,
        dataset_ids=_comma_list(settings.WAREHOUSE_DISCOVERY_DATASETS),
        excluded_table_patterns=_comma_list(settings.WAREHOUSE_DISCOVERY_EXCLUDED_TABLE_PATTERNS),
    )

    # The crawler does synchronous BigQuery I/O; keep the event loop responsive.
    diffs = await asyncio.to_thread(crawler.crawl, True)

    counts = {"REGISTERED": 0, "UNREGISTERED": 0, "DRIFTED": 0}
    for diff in diffs:
        counts[diff.status] = counts.get(diff.status, 0) + 1

    logger.info(
        "Warehouse crawl complete: %s registered, %s unregistered, %s drifted",
        counts["REGISTERED"],
        counts["UNREGISTERED"],
        counts["DRIFTED"],
    )
    return {"status": "ok", "resources_scanned": len(diffs), "counts": counts}


@router.post("/publish-dbt-pii-discovery")
async def publish_dbt_pii_discovery(request: Request):
    """
    Publishes the chameleon_pii dbt package's pii_discovery findings (undeclared,
    name-inferred PII columns) into the same WAREHOUSE_METADATA_DISCOVERED
    lineage feed /warehouse-crawl above writes to, so they reach the console's
    live "declare this" work queue (GET /pii-registry/discovery) without
    waiting for Key Vault's boot-time dbt-registry pull to catch up. Intended
    to run right after a scheduled `dbt build` completes (Cloud Scheduler ->
    Cloud Run, OIDC, same pattern as /warehouse-crawl) -- it reads
    pii_discovery's output, it does not invoke dbt itself. Metadata only:
    column names and inferred classifications, never values.

    No-op (0 resources) if DBT_PII_DISCOVERY_DATASETS is empty -- opt-in, like
    warehouse discovery above.
    """
    vault = request.app.state.vault
    bq_client = request.app.state.bq.client  # raw google.cloud.bigquery.Client

    publisher = DbtPiiDiscoveryPublisher(
        bigquery_client=bq_client,
        vault=vault,
        pii_discovery_locations=_comma_list(settings.DBT_PII_DISCOVERY_DATASETS),
    )

    # Same rationale as /warehouse-crawl: synchronous BigQuery I/O, keep the
    # event loop responsive.
    resources = await asyncio.to_thread(publisher.publish)

    field_count = sum(len(r.fields) for r in resources)
    logger.info(
        "dbt PII discovery publish complete: %s resource(s), %s undeclared field(s)",
        len(resources),
        field_count,
    )
    return {"status": "ok", "resources_published": len(resources), "fields_published": field_count}


def _pii_vault_sync_job(request: Request) -> PiiVaultSyncJob:
    return PiiVaultSyncJob(
        bigquery_client=request.app.state.bq.client,
        vault=request.app.state.vault,
        vault_project_id=settings.GOOGLE_CLOUD_PROJECT,
        vault_dataset_id=settings.BIGQUERY_DATASET,
        publisher=request.app.state.pii_vault_sync_publisher,
        chunk_topic_path=request.app.state.pii_vault_sync_chunk_topic_path,
    )


@router.post("/pii-vault-sync")
async def pii_vault_sync(request: Request):
    """
    Entry point for both the daily scheduler and the console's on-demand
    "Sync Now" -- enumerates which users need syncing for each declared
    resource and publishes one Pub/Sub message per chunk to
    pii_vault_sync_chunks, then returns immediately. Never touches the
    source table, and never does the actual encrypt-diff-insert work
    itself -- that happens per chunk in /pii-vault-sync-chunk below,
    triggered by that topic's own push subscription. See
    PiiVaultSyncJob's docstring for why this is chunked at the trigger
    level and not just internally: a single synchronous invocation used to
    mean a client triggering this for a large table (Immoscoop's real
    ~530k users) could give up waiting long before the job actually
    finished, even though the job itself completed correctly server-side.

    Optional JSON body: {"force_full_scan": bool, "resource_id": str}. The
    daily Cloud Scheduler call sends no body at all, which defaults to
    False (so opted-in resources get incremental treatment); Sync Now
    (PiiVaultSyncTrigger) always sends true, since it's the customer's
    manual "did I miss something" lever -- an incremental scan wouldn't
    catch e.g. a newly-declared field on an already-synced resource, which
    has no concept of "row unchanged, but a field was added." When
    resource_id is present, only that one declared resource is enumerated
    instead of every manually-declared resource for the tenant.

    Also creates a sync_runs record in Key Vault (see SyncRunRepository)
    for the console's progress bar to poll, and returns its runId. Created
    BEFORE enumeration starts, not after -- a fast chunk can be fully
    processed by Pub/Sub before enumeration across every resource finishes,
    so the run doc must already exist by the time the first chunk's
    progress report could possibly arrive. Best-effort throughout: a Key
    Vault hiccup here degrades the progress bar, never the sync itself.
    """
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    force_full_scan = bool(payload.get("force_full_scan", False)) if isinstance(payload, dict) else False
    resource_id = payload.get("resource_id") if isinstance(payload, dict) else None

    job = _pii_vault_sync_job(request)

    run_id = str(uuid.uuid4())
    try:
        await asyncio.to_thread(job.vault.create_sync_run, run_id, resource_id)
    except Exception as e:
        logger.warning(f"Failed to create sync run {run_id}, progress bar will be unavailable for this sync: {e}")
        run_id = None

    if resource_id:
        result = await asyncio.to_thread(job.sync_one, resource_id, force_full_scan, run_id)
        results = [result]
    else:
        results = await asyncio.to_thread(job.sync_all, force_full_scan, run_id)

    total_chunks = sum(r.chunks_queued for r in results)
    errors = [{"resourceId": r.resource_id, "error": r.error} for r in results if r.error]

    if run_id:
        try:
            await asyncio.to_thread(job.vault.finalize_sync_run_total, run_id, total_chunks)
        except Exception as e:
            logger.warning(f"Failed to finalize sync run {run_id} total: {e}")

    logger.info(
        "PII vault sync enumeration complete: %s resources, %s chunks queued, %s errors",
        len(results),
        total_chunks,
        len(errors),
    )
    return {
        "status": "queued",
        "resources_queued": len(results),
        "chunks_queued": total_chunks,
        "errors": errors,
        "runId": run_id,
    }


@router.post("/pii-vault-sync-chunk")
async def pii_vault_sync_chunk(request: Request):
    """
    Pub/Sub push subscription endpoint for pii_vault_sync_chunks. Each
    message is one chunk (PiiVaultSyncJob.CHUNK_SIZE user IDs) of one
    declared resource, published by /pii-vault-sync's enumeration step
    above. Small and fast by construction, so a single invocation of this
    endpoint never risks Pub/Sub's 600-second push ack deadline the way a
    whole-table sync used to when it ran as one synchronous request.

    Pub/Sub push envelope format:
      { "message": { "data": "<base64 json>", "messageId": "..." }, "subscription": "..." }

    Returns 200 to acknowledge; 500 causes Pub/Sub to retry.
    """
    try:
        envelope = await request.json()
        message = envelope.get("message", {})
        payload = json.loads(base64.b64decode(message.get("data", "")).decode("utf-8"))
        resource_id = payload["resource_id"]
        user_ids = payload["user_ids"]
        run_id = payload.get("run_id")
    except Exception as e:
        logger.error(f"Failed to decode pii_vault_sync_chunks message: {e}")
        return JSONResponse(status_code=200, content={"status": "ignored", "reason": "malformed"})

    job = _pii_vault_sync_job(request)

    try:
        synced = await asyncio.to_thread(job.process_chunk, resource_id, user_ids, run_id)
        logger.info(f"pii_vault_sync_chunk: {resource_id} -- {synced} users synced out of {len(user_ids)} in chunk")
        return {"status": "ok", "resource_id": resource_id, "users_synced": synced}
    except Exception as e:
        logger.error(f"process_chunk failed for {resource_id} ({len(user_ids)} users): {e}")
        return JSONResponse(status_code=500, content={"status": "error", "detail": str(e)})

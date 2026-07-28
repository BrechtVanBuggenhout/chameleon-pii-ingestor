import asyncio
import logging

from fastapi import APIRouter, Request

from app.config import settings
from app.scanners.warehouse_metadata_crawler import BigQueryWarehouseMetadataCrawler
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


@router.post("/pii-vault-sync")
async def pii_vault_sync(request: Request):
    """
    Daily backfill/sync of manually-declared resources into the central
    pii_vault table -- retroactive protection for tables a customer already
    owns that were never going to flow through Chameleon's own ingestion
    pipeline. Never touches the source table. Intended to be invoked on a
    schedule (Cloud Scheduler -> Cloud Run, OIDC), same as warehouse-crawl.
    """
    vault = request.app.state.vault
    bq_client = request.app.state.bq.client

    job = PiiVaultSyncJob(
        bigquery_client=bq_client,
        vault=vault,
        vault_project_id=settings.GOOGLE_CLOUD_PROJECT,
        vault_dataset_id=settings.BIGQUERY_DATASET,
    )

    results = await asyncio.to_thread(job.sync_all)

    total_synced = sum(r.users_synced for r in results)
    errors = [{"resourceId": r.resource_id, "error": r.error} for r in results if r.error]

    logger.info(
        "PII vault sync complete: %s resources, %s users synced, %s errors",
        len(results),
        total_synced,
        len(errors),
    )
    return {
        "status": "ok",
        "resources_synced": len(results),
        "users_synced": total_synced,
        "errors": errors,
    }

import asyncio
import base64
import io
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastavro import schemaless_reader
from google.cloud import pubsub_v1
from app.pipelines.ingestion import USER_SCHEMA
from app.api import discovery
from app.api import source_staleness
from app.api import version as version_api
from app.config import settings
from app.services.vault_client import VaultClient
from app.services.bigquery_client import BigQueryService
from app.services.warehouse_factory import get_warehouse_writer
from app.services.warehouse_writer import WarehouseWriter
from app.services.gcs_client import GCSService
from app.pipelines.ingestion import IngestionPipeline
from app.services.gcs_monitor import GCSLandingZoneMonitor
from app.scanners.warehouse_metadata_crawler import normalize_bigquery_resource_id

logger = logging.getLogger(__name__)


class _HealthCheckLogFilter(logging.Filter):
    """Drops uvicorn's access-log line for /health -- hit continuously by
    Cloud Run's own health probes, not real traffic, and drowns out real
    request logs in prod."""

    def filter(self, record: logging.LogRecord) -> bool:
        return "/health" not in record.getMessage()


logging.getLogger("uvicorn.access").addFilter(_HealthCheckLogFilter())

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Initialize the services and start the GCS monitor background task
    vault = VaultClient(settings.VAULT_BASE_URL, tenant_id=settings.TENANT_ID)
    # bq stays BigQuery-specific: the warehouse-discovery crawler (discovery.py)
    # only supports BigQuery today, independent of the ingestion write path below.
    bq = BigQueryService(settings.GOOGLE_CLOUD_PROJECT, settings.BIGQUERY_DATASET)
    warehouse_writer = get_warehouse_writer()
    gcs = GCSService(settings.GOOGLE_CLOUD_PROJECT)
    pipeline = IngestionPipeline(
        vault,
        topic_id=settings.PII_TOPIC_ID,
        lineage_topic_id=settings.LINEAGE_TOPIC_ID,
        gcs_service=gcs
    )
    
    pii_vault_sync_publisher = pubsub_v1.PublisherClient()

    # Store for DI
    app.state.vault = vault
    app.state.pipeline = pipeline
    app.state.bq = bq
    app.state.warehouse_writer = warehouse_writer
    app.state.gcs = gcs
    app.state.pii_vault_sync_publisher = pii_vault_sync_publisher
    # Fully-qualified already (projects/<id>/topics/<name>), matching
    # PII_TOPIC_ID/LINEAGE_TOPIC_ID's own convention -- not a short topic ID.
    app.state.pii_vault_sync_chunk_topic_path = settings.PII_VAULT_SYNC_CHUNK_TOPIC_ID

    # Identifies the PII registry declaration for bulk file drops -- matches
    # the resourceId convention the console/Key Vault registry already uses
    # (bigquery:project.dataset.table). Landing-zone drops are always meant
    # for this instance's one target table (single-tenant-per-deployment),
    # so there's no need for a new required env var just for this.
    landing_zone_resource_id = normalize_bigquery_resource_id(
        settings.GOOGLE_CLOUD_PROJECT, settings.BIGQUERY_DATASET, settings.STAGING_TABLE
    )
    monitor = GCSLandingZoneMonitor(pipeline, settings.LANDING_ZONE_BUCKET, resource_id=landing_zone_resource_id)
    
    async def run_monitor():
        logger.info(f"GCS Monitor started. Polling bucket: {settings.LANDING_ZONE_BUCKET}")
        while True:
            try:
                # Offload synchronous polling to a thread to keep the Janitor API responsive
                await asyncio.to_thread(monitor.poll_once)
            except Exception as e:
                logger.error(f"Error in GCS Monitor loop: {e}")
            await asyncio.sleep(60)  # Poll every 60 seconds

    bg_task = asyncio.create_task(run_monitor())
    yield
    # Shutdown: Stop the background task
    bg_task.cancel()

app = FastAPI(
    title="Project Chameleon: Data Plane",
    description="Python API for orchestrating data pipelines and responding to shredding events.",
    version="1.0.0",
    lifespan=lifespan
)

app.include_router(discovery.router, prefix="/api/v1", tags=["Discovery"])
app.include_router(source_staleness.router, prefix="/api/v1", tags=["Source Staleness"])
app.include_router(version_api.router, tags=["Version"])

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

@app.post("/ingest")
async def pubsub_ingest(request: Request):
    """
    Pub/Sub push subscription endpoint for pii-ingestion-stream.
    Receives Avro-encoded UserIngestion records published by the ingestion pipeline
    and writes them to the configured warehouse's raw_users table (BigQuery by
    default; Snowflake when WAREHOUSE_TYPE=snowflake).

    Pub/Sub push envelope format:
      { "message": { "data": "<base64 avro binary>", "messageId": "..." }, "subscription": "..." }

    Returns 200 to acknowledge; 500 causes Pub/Sub to retry.
    """
    warehouse_writer: WarehouseWriter = request.app.state.warehouse_writer
    try:
        envelope = await request.json()
        message = envelope.get("message", {})
        avro_bytes = base64.b64decode(message.get("data", ""))
        record = schemaless_reader(io.BytesIO(avro_bytes), USER_SCHEMA)
        # encrypted_pii is bytes — every warehouse writer expects a base64
        # string for this field (BigQuery's BYTES-column convention; Snowflake's
        # writer decodes it back to raw bytes for its BINARY column).
        if isinstance(record.get("encrypted_pii"), (bytes, bytearray)):
            record["encrypted_pii"] = base64.b64encode(record["encrypted_pii"]).decode("utf-8")
        # Same bytes->base64 handling for each declared field's ciphertext in
        # the general N-field array (BigQuery's load_table_from_json needs a
        # JSON-safe value for the REPEATED RECORD column's BYTES sub-field).
        for pii_field in record.get("pii_fields", []):
            if isinstance(pii_field.get("encrypted_value"), (bytes, bytearray)):
                pii_field["encrypted_value"] = base64.b64encode(pii_field["encrypted_value"]).decode("utf-8")
        logger.info(f"Pub/Sub ingest: user_id={record.get('user_id')} tenant_id={record.get('tenant_id')}")
    except Exception as e:
        logger.error(f"Failed to decode Pub/Sub Avro message: {e}")
        return JSONResponse(status_code=200, content={"status": "ignored", "reason": "malformed"})

    try:
        await asyncio.to_thread(warehouse_writer.load_records, "raw_users", [record])
        return JSONResponse(status_code=200, content={"status": "accepted", "user_id": record.get("user_id")})
    except Exception as e:
        logger.error(f"Warehouse write failed for user_id={record.get('user_id')}: {e}")
        return JSONResponse(status_code=500, content={"status": "error", "detail": str(e)})

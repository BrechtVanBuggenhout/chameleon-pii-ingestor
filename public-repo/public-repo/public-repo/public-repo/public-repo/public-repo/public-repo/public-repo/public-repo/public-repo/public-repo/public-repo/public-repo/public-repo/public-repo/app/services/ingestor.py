from fastapi import FastAPI, BackgroundTasks, Header, HTTPException, Body
from pydantic import BaseModel
from typing import Optional
from app.services.vault_client import VaultClient
from app.services.warehouse_factory import get_warehouse_writer
from app.core.crypto import ChameleonCrypto
from app.config import settings
import base64
import json
import logging

app = FastAPI(title="Chameleon Sequential Ingestor")
logger = logging.getLogger("Ingestor")

class IngestionRequest(BaseModel):
    userId: str
    tenantId: Optional[str] = None
    payload: dict
    operationId: str

class PubSubMessage(BaseModel):
    data: str
    messageId: str

class PubSubEnvelope(BaseModel):
    message: PubSubMessage

@app.post("/ingest")
async def ingest_record(
    envelope: PubSubEnvelope = Body(...),
    x_tenant_id: str = Header(None)
):
    """
    Sequential Ingestor as per Phase 7 Resiliency Plan.
    Handles Pub/Sub Push messages.
    Guarantees Firestore (Key Registry) write before BigQuery streaming.
    """
    try:
        # Pub/Sub data is base64 encoded
        decoded_data = base64.b64decode(envelope.message.data).decode('utf-8')
        request_json = json.loads(decoded_data)
        request = IngestionRequest(**request_json)
    except Exception as e:
        logger.error(f"❌ Failed to parse Pub/Sub envelope: {e}")
        raise HTTPException(status_code=400, detail="Invalid Pub/Sub message format")

    # X-Tenant-Id is the tenant authority; body tenant fields are compatibility only.
    tenant_id = x_tenant_id or request.tenantId
    if not tenant_id:
        raise HTTPException(status_code=400, detail="tenant_id is required")

    vault = VaultClient(base_url=settings.VAULT_BASE_URL, tenant_id=tenant_id)
    project_id = settings.GOOGLE_CLOUD_PROJECT
    dataset_id = settings.staging_dataset_resolved
    staging_table = settings.STAGING_TABLE
    warehouse_writer = get_warehouse_writer(project_id=project_id, dataset_id=dataset_id)
    if settings.WAREHOUSE_TYPE == "snowflake":
        destination = (
            f"snowflake:{settings.PII_INGESTOR_SNOWFLAKE_DATABASE}."
            f"{settings.PII_INGESTOR_SNOWFLAKE_SCHEMA}.{staging_table}"
        )
    else:
        destination = f"bigquery:{project_id}.{dataset_id}.{staging_table}"

    try:
        # Step 1: Sequential Key Retrieval/Generation (Syncs with Firestore Key Registry)
        # This eliminates the race condition where BQ has data but the key isn't registered.
        context = vault.get_encryption_context(request.userId)
        
        # Step 2: Local Encryption
        encrypted_pii = ChameleonCrypto.encrypt(
            context['dek'], 
            request.userId, 
            str(request.payload.get("email"))
        )

        # Step 3: Stream to the configured warehouse (BigQuery by default,
        # Snowflake when WAREHOUSE_TYPE=snowflake)
        record = {
            "user_id": request.userId,
            "tenant_id": tenant_id,
            "encrypted_pii": encrypted_pii,
            "key_id": context['key_id'],
            "operation_id": request.operationId
        }

        # Confirmed write to the raw ingestion table. dbt owns the modeled
        # stg_users layer over this raw landing table.
        warehouse_writer.load_records(staging_table, [record])

        # Step 4: Emit Lineage Event for the ingestion batch
        vault.report_lineage(
            event_type="INGESTION",
            user_id=request.userId,
            source="pii-ingestor-worker",
            destination=destination,
            operation_id=request.operationId,
            metadata={"payload_keys": list(request.payload.keys())}
        )

        logger.info(f"✅ Sequentially ingested {request.userId} for tenant {tenant_id}")
        return {"status": "success", "userId": request.userId}

    except Exception as e:
        logger.error(f"❌ Ingestion failed for {request.userId}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
def health():
    return {"status": "healthy"}

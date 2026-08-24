import asyncio
import base64
import json
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from google.auth.transport.requests import Request as GoogleAuthRequest
from google.oauth2 import id_token as google_id_token

from app.config import settings
from app.pipelines.pubsub_ingest import CallerNotAuthorized, PubsubIngestPipeline
from app.services.bigquery_client import BigQueryService
from app.services.vault_client import VaultClient

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    vault = VaultClient(settings.VAULT_BASE_URL, tenant_id=settings.TENANT_ID)
    bq = BigQueryService(settings.GOOGLE_CLOUD_PROJECT, settings.BIGQUERY_DATASET)
    # pii_vault lives in the same project/dataset as everything else this
    # deployment writes to -- same resolution pii_vault_sync.py's own
    # _pii_vault_sync_job() factory already uses (see app/api/discovery.py).
    app.state.pipeline = PubsubIngestPipeline(
        vault=vault,
        bigquery_client=bq.client,
        vault_project_id=settings.GOOGLE_CLOUD_PROJECT,
        vault_dataset_id=settings.BIGQUERY_DATASET,
    )
    yield


app = FastAPI(
    title="Project Chameleon: Pub/Sub Ingest",
    description=(
        "Publicly reachable push endpoint for customer-owned Pub/Sub topics "
        "declared as system: 'pubsub' PII resources. Deliberately a separate "
        "Cloud Run service from the internal pii_ingestor_worker -- that "
        "service's /ingest route has no app-level auth of its own and relies "
        "entirely on Cloud Run's platform-level IAM invoker gate, which "
        "applies to the whole service, not per-route. This service is public "
        "at the platform level and does all real authorization itself: every "
        "push's Authorization: Bearer <ID token> is cryptographically "
        "verified, then its subject compared against the declared resource's "
        "own pubsubAllowedCallerServiceAccount."
    ),
    lifespan=lifespan,
)


@app.get("/health")
async def health_check():
    return {"status": "healthy"}


def _verify_push_caller(id_token_str: str, audience: str) -> str:
    """Raises on any verification failure (bad signature, wrong audience,
    expired token) -- verify_oauth2_token itself raises ValueError for
    these. Returns the verified `sub` claim; never anything read from the
    token before verification succeeds."""
    payload = google_id_token.verify_oauth2_token(id_token_str, GoogleAuthRequest(), audience=audience)
    return payload["sub"]


@app.post("/pubsub-ingest/{resource_id}")
async def pubsub_ingest(resource_id: str, request: Request):
    """
    Pub/Sub push subscription endpoint for a customer's OWN topic, declared
    as a system: 'pubsub' PII resource. The customer creates their own
    topic and push subscription (in their own project) pointed at this
    URL -- Chameleon never touches IAM in the customer's project.

    Response codes, deliberately distinct:
      200 -- accepted, OR a message Chameleon can never process (malformed
             body, a declared field/user-id path missing from this
             particular message) -- acked either way. Pub/Sub redelivers
             forever on anything else, so a message that will never
             successfully process must never be allowed to loop.
      401/403 -- ID-token verification or caller-authorization failure.
             Deliberately NOT acked -- this usually means real
             misconfiguration, or a revoked declaration the customer's
             subscription hasn't caught up to, and should keep failing
             loudly (Pub/Sub keeps retrying) rather than being silently
             dropped.
      500 -- a genuinely transient failure (BigQuery/Vault unreachable) --
             Pub/Sub redelivery is the correct response here.
    """
    pipeline: PubsubIngestPipeline = request.app.state.pipeline

    auth_header = request.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        return JSONResponse(status_code=401, content={"status": "rejected", "reason": "missing bearer token"})
    presented_token = auth_header[len("Bearer "):]

    # Audience is derived from the request's own URL, not a static config
    # value -- matches decrypted-views-decrypt.ts's identical reasoning:
    # the customer's own subscription determines what audience it signs
    # its tokens for (defaulting to the push endpoint URL), so verifying
    # against anything else would be wrong for a dynamic, per-declaration
    # caller.
    audience = f"{request.url.scheme}://{request.url.netloc}{request.url.path}"
    try:
        verified_sub = await asyncio.to_thread(_verify_push_caller, presented_token, audience)
    except Exception as e:
        logger.warning(f"Pub/Sub ingest token verification failed for {resource_id}: {e}")
        return JSONResponse(status_code=401, content={"status": "rejected", "reason": "invalid token"})

    try:
        resource = await asyncio.to_thread(pipeline.resolve_resource, resource_id)
        pipeline.authorize_caller(resource, verified_sub)
    except CallerNotAuthorized as e:
        logger.warning(f"Pub/Sub ingest caller not authorized for {resource_id}: {e}")
        return JSONResponse(status_code=403, content={"status": "rejected", "reason": "caller not authorized"})

    try:
        envelope = await request.json()
        message = envelope.get("message", {})
        raw_bytes = base64.b64decode(message.get("data", ""))
        message_body = json.loads(raw_bytes.decode("utf-8"))
        if not isinstance(message_body, dict):
            raise ValueError("decoded message body is not a JSON object")
    except Exception as e:
        logger.warning(f"Pub/Sub ingest received a malformed message for {resource_id}: {e}")
        return JSONResponse(status_code=200, content={"status": "ignored", "reason": "malformed message"})

    try:
        outcome = await asyncio.to_thread(pipeline.process_message, resource, message_body)
    except CallerNotAuthorized as e:
        # process_message can also raise this (e.g. the declaration itself
        # has no userIdFieldPath) -- same "don't silently ack" reasoning as
        # the earlier authorize_caller check.
        logger.warning(f"Pub/Sub ingest rejected for {resource_id}: {e}")
        return JSONResponse(status_code=403, content={"status": "rejected", "reason": str(e)})
    except Exception as e:
        logger.error(f"Pub/Sub ingest processing failed for {resource_id}: {e}")
        return JSONResponse(status_code=500, content={"status": "error", "detail": str(e)})

    if not outcome.accepted:
        logger.info(f"Pub/Sub ingest skipped a message for {resource_id}: {outcome.reason}")
        return JSONResponse(status_code=200, content={"status": "ignored", "reason": outcome.reason})

    return JSONResponse(status_code=200, content={"status": "accepted", "fieldsWritten": outcome.fields_written})

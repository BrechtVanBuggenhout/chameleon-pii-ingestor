import asyncio
import json
import logging

from fastapi import APIRouter
from google.api_core.exceptions import NotFound
from google.cloud import secretmanager

from app.config import settings

router = APIRouter()
logger = logging.getLogger(__name__)

# Matches the key build-own-images.sh writes for this service into the
# chameleon-source-shas secret -- see chameleon-infra-gcp/scripts/build-own-images.sh.
SOURCE_SHAS_KEY = "pii-ingestor"


@router.get("/version")
async def version():
    """
    Reports the git SHA this deployment was built from, if known -- lets
    "did my redeploy actually land?" be scripted (curl + compare) instead
    of requiring a login to the console's Declare panel to eyeball it.

    Reads the same chameleon-source-shas Secret Manager secret written by
    build-own-images.sh (see source_staleness.py above); only meaningful
    for BYOC installs that built their own images. sourceSha/builtAt are
    null, not an error, for deployments pulling Chameleon's pre-built
    images instead.
    """
    secret_name = (
        f"projects/{settings.GOOGLE_CLOUD_PROJECT}/secrets/chameleon-source-shas/versions/latest"
    )
    source_sha = None
    built_at = None
    try:
        client = secretmanager.SecretManagerServiceClient()
        response = await asyncio.to_thread(client.access_secret_version, name=secret_name)
        built_shas = json.loads(response.payload.data.decode("utf-8"))
        source_sha = built_shas.get(SOURCE_SHAS_KEY)
        built_at = built_shas.get("builtAt")
    except NotFound:
        pass
    except Exception as exc:
        logger.warning("version: failed to read chameleon-source-shas: %s", exc)

    return {
        "service": "chameleon-pii-ingestor",
        "sourceSha": source_sha,
        "builtAt": built_at,
    }

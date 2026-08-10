import asyncio
import json
import logging

import requests
from fastapi import APIRouter
from google.api_core.exceptions import NotFound
from google.cloud import secretmanager

from app.config import settings

router = APIRouter()
logger = logging.getLogger(__name__)

# Matches scripts/build-own-images.sh's SERVICES list in chameleon-infra-gcp
# exactly -- the keys build-own-images.sh writes into chameleon-source-shas,
# mapped to the public repo each one is built from.
REPO_MAP = {
    "key-vault": "chameleon-vault",
    "pii-ingestor": "chameleon-pii-ingestor",
    "console": "chameleon-console",
}

# GitHub's API 403s an unauthenticated request with no User-Agent header --
# easy to regress silently, so it's called out here rather than left implicit.
GITHUB_HEADERS = {"User-Agent": "chameleon-source-staleness-check"}
GITHUB_REQUEST_TIMEOUT_SECONDS = 10


@router.post("/source-staleness-check")
async def source_staleness_check():
    """
    Compares this instance's build-own-images.sh source SHAs (recorded in
    the chameleon-source-shas Secret Manager secret at build time -- see
    that script in chameleon-infra-gcp) against the public repos' current
    HEAD. Only meaningful for BYOC customers who built their own images
    instead of pulling Chameleon's pre-built ones -- if the secret was
    never written, this is a no-op, not an error. Intended to be invoked
    on a schedule (Cloud Scheduler -> Cloud Run, OIDC), same pattern as
    /warehouse-crawl.

    Never contacts Chameleon: results are only logged to this project's
    own Cloud Logging (WARNING severity, jsonPayload.event =
    "chameleon_source_stale") and returned in the response, for the
    customer's own alerting to pick up.
    """
    secret_name = (
        f"projects/{settings.GOOGLE_CLOUD_PROJECT}/secrets/chameleon-source-shas/versions/latest"
    )
    try:
        client = secretmanager.SecretManagerServiceClient()
        response = await asyncio.to_thread(client.access_secret_version, name=secret_name)
        built_shas = json.loads(response.payload.data.decode("utf-8"))
    except NotFound:
        return {"status": "not_applicable"}

    results = {}
    for service, repo in REPO_MAP.items():
        built_sha = built_shas.get(service)
        if not built_sha:
            results[service] = {"status": "unknown", "reason": "missing from stored SHAs"}
            continue

        try:
            resp = await asyncio.to_thread(
                requests.get,
                f"https://api.github.com/repos/BrechtVanBuggenhout/{repo}/commits/main",
                headers=GITHUB_HEADERS,
                timeout=GITHUB_REQUEST_TIMEOUT_SECONDS,
            )
            resp.raise_for_status()
            latest_sha = resp.json()["sha"]
        except Exception as exc:
            # One bad GitHub call (rate limit, network blip) shouldn't mask
            # a genuinely stale result from the other two repos.
            logger.warning("source_staleness_check: failed to check %s: %s", repo, exc)
            results[service] = {"status": "unknown", "reason": str(exc)}
            continue

        stale = built_sha != latest_sha
        results[service] = {
            "status": "stale" if stale else "current",
            "builtSha": built_sha,
            "latestSha": latest_sha,
        }
        if stale:
            logger.warning(
                "chameleon_source_stale repo=%s builtSha=%s latestSha=%s",
                repo,
                built_sha,
                latest_sha,
                extra={
                    "event": "chameleon_source_stale",
                    "repo": repo,
                    "builtSha": built_sha,
                    "latestSha": latest_sha,
                },
            )

    return {"status": "ok", "results": results}

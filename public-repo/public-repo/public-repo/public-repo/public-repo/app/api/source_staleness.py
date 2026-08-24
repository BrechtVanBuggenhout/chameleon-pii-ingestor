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

# Public repo Chameleon cuts versioned GitHub Releases on -- distinct from
# REPO_MAP above, which is about per-service source SHAs for the self-build
# path. This is the pre-built-image path's release channel: one release
# covers all three services' GHCR image tags together.
INSTALLER_REPO = "chameleon-installer"

# GitHub's API 403s an unauthenticated request with no User-Agent header --
# easy to regress silently, so it's called out here rather than left implicit.
GITHUB_HEADERS = {"User-Agent": "chameleon-source-staleness-check"}
GITHUB_REQUEST_TIMEOUT_SECONDS = 10


async def _check_platform_version() -> dict:
    """
    Compares this deployment's pinned PLATFORM_VERSION (a git-tracked
    Terraform variable, updated by scripts/update.sh's git merge -- see
    chameleon-installer) against chameleon-installer's latest GitHub
    Release tag. This is the pre-built-image path's update check --
    orthogonal to the self-build SHA check below, and meaningful for every
    deployment regardless of whether chameleon-source-shas was ever
    written. Returns "unknown" (never "stale") when PLATFORM_VERSION isn't
    set, since that just means this deployment predates versioned images
    or is self-built -- not evidence of anything actually being behind.
    """
    if not settings.PLATFORM_VERSION:
        return {"status": "unknown", "reason": "PLATFORM_VERSION not set on this deployment"}

    try:
        resp = await asyncio.to_thread(
            requests.get,
            f"https://api.github.com/repos/BrechtVanBuggenhout/{INSTALLER_REPO}/releases/latest",
            headers=GITHUB_HEADERS,
            timeout=GITHUB_REQUEST_TIMEOUT_SECONDS,
        )
        resp.raise_for_status()
        latest_version = resp.json()["tag_name"]
    except Exception as exc:
        logger.warning("source_staleness_check: failed to check latest release: %s", exc)
        return {"status": "unknown", "reason": str(exc)}

    current_version = settings.PLATFORM_VERSION
    stale = current_version != latest_version
    result = {
        "status": "stale" if stale else "current",
        "currentVersion": current_version,
        "latestVersion": latest_version,
    }
    if stale:
        logger.warning(
            "chameleon_update_available currentVersion=%s latestVersion=%s",
            current_version,
            latest_version,
            extra={
                "event": "chameleon_update_available",
                "currentVersion": current_version,
                "latestVersion": latest_version,
            },
        )
    return result


@router.post("/source-staleness-check")
async def source_staleness_check():
    """
    Two independent checks, covering both ways a BYOC deployment consumes
    Chameleon's code:

    1. Self-build source drift: compares this instance's build-own-images.sh
       source SHAs (recorded in the chameleon-source-shas Secret Manager
       secret at build time -- see that script in chameleon-infra-gcp)
       against the public repos' current HEAD. Only meaningful for
       customers who built their own images -- "not_applicable" if the
       secret was never written, not an error.
    2. Pre-built-image version drift: compares this deployment's pinned
       PLATFORM_VERSION against chameleon-installer's latest GitHub
       Release. Meaningful for every deployment, independent of (1).

    Intended to be invoked on a schedule (Cloud Scheduler -> Cloud Run,
    OIDC), same pattern as /warehouse-crawl.

    Never contacts Chameleon: results are only logged to this project's own
    Cloud Logging (WARNING severity, jsonPayload.event =
    "chameleon_source_stale" / "chameleon_update_available") and returned
    in the response, for the customer's own alerting to pick up.
    """
    platform_version = await _check_platform_version()

    secret_name = (
        f"projects/{settings.GOOGLE_CLOUD_PROJECT}/secrets/chameleon-source-shas/versions/latest"
    )
    try:
        client = secretmanager.SecretManagerServiceClient()
        response = await asyncio.to_thread(client.access_secret_version, name=secret_name)
        built_shas = json.loads(response.payload.data.decode("utf-8"))
    except NotFound:
        # "not_applicable" describes the self-build SHA check specifically
        # (chameleon-console's Status page checks this exact string) --
        # platformVersion is independent and still meaningful here, so it's
        # included alongside rather than also being suppressed.
        return {"status": "not_applicable", "platformVersion": platform_version}

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

    return {"status": "ok", "results": results, "platformVersion": platform_version}

import json
from unittest.mock import MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient
from google.api_core.exceptions import NotFound

from app.api import source_staleness


def _make_app() -> FastAPI:
    app = FastAPI()
    app.include_router(source_staleness.router, prefix="/api/v1")
    return app


def _secret_response(payload: dict) -> MagicMock:
    response = MagicMock()
    response.payload.data = json.dumps(payload).encode("utf-8")
    return response


def _github_response(sha: str) -> MagicMock:
    resp = MagicMock()
    resp.raise_for_status.return_value = None
    resp.json.return_value = {"sha": sha}
    return resp


def _github_release_response(tag: str) -> MagicMock:
    resp = MagicMock()
    resp.raise_for_status.return_value = None
    resp.json.return_value = {"tag_name": tag}
    return resp


def test_not_applicable_when_secret_does_not_exist():
    """
    platformVersion is orthogonal to the self-build SHA secret -- omitted
    from settings here (default None), so it reports "unknown" rather than
    making a GitHub call, but the field itself must still be present.
    """
    fake_client = MagicMock()
    fake_client.access_secret_version.side_effect = NotFound("no such secret")

    with patch("app.api.source_staleness.secretmanager.SecretManagerServiceClient", return_value=fake_client):
        response = TestClient(_make_app()).post("/api/v1/source-staleness-check")

    assert response.status_code == 200
    assert response.json() == {
        "status": "not_applicable",
        "platformVersion": {"status": "unknown", "reason": "PLATFORM_VERSION not set on this deployment"},
    }


def test_platform_version_unknown_when_not_set():
    fake_client = MagicMock()
    fake_client.access_secret_version.side_effect = NotFound("no such secret")

    with patch("app.api.source_staleness.secretmanager.SecretManagerServiceClient", return_value=fake_client), \
         patch("app.api.source_staleness.requests.get") as mock_get:
        response = TestClient(_make_app()).post("/api/v1/source-staleness-check")

    assert response.json()["platformVersion"]["status"] == "unknown"
    # Never even called GitHub -- nothing to compare against.
    mock_get.assert_not_called()


def test_platform_version_current():
    fake_client = MagicMock()
    fake_client.access_secret_version.side_effect = NotFound("no such secret")

    with patch("app.api.source_staleness.secretmanager.SecretManagerServiceClient", return_value=fake_client), \
         patch("app.api.source_staleness.settings.PLATFORM_VERSION", "v2026.08.20"), \
         patch("app.api.source_staleness.requests.get", return_value=_github_release_response("v2026.08.20")) as mock_get:
        response = TestClient(_make_app()).post("/api/v1/source-staleness-check")

    body = response.json()["platformVersion"]
    assert body == {"status": "current", "currentVersion": "v2026.08.20", "latestVersion": "v2026.08.20"}
    mock_get.assert_called_once()
    assert "chameleon-installer/releases/latest" in mock_get.call_args.args[0]
    assert mock_get.call_args.kwargs["headers"]["User-Agent"]


def test_platform_version_stale():
    fake_client = MagicMock()
    fake_client.access_secret_version.side_effect = NotFound("no such secret")

    with patch("app.api.source_staleness.secretmanager.SecretManagerServiceClient", return_value=fake_client), \
         patch("app.api.source_staleness.settings.PLATFORM_VERSION", "v2026.08.10"), \
         patch("app.api.source_staleness.requests.get", return_value=_github_release_response("v2026.08.20")), \
         patch("app.api.source_staleness.logger") as mock_logger:
        response = TestClient(_make_app()).post("/api/v1/source-staleness-check")

    body = response.json()["platformVersion"]
    assert body == {"status": "stale", "currentVersion": "v2026.08.10", "latestVersion": "v2026.08.20"}
    mock_logger.warning.assert_called_once()
    _, kwargs = mock_logger.warning.call_args
    assert kwargs["extra"]["event"] == "chameleon_update_available"
    assert kwargs["extra"]["currentVersion"] == "v2026.08.10"
    assert kwargs["extra"]["latestVersion"] == "v2026.08.20"


def test_platform_version_fails_open_on_bad_github_call():
    fake_client = MagicMock()
    fake_client.access_secret_version.side_effect = NotFound("no such secret")

    with patch("app.api.source_staleness.secretmanager.SecretManagerServiceClient", return_value=fake_client), \
         patch("app.api.source_staleness.settings.PLATFORM_VERSION", "v2026.08.10"), \
         patch("app.api.source_staleness.requests.get", side_effect=RuntimeError("connection reset")):
        response = TestClient(_make_app()).post("/api/v1/source-staleness-check")

    assert response.status_code == 200
    assert response.json()["platformVersion"]["status"] == "unknown"


def test_all_current():
    built_shas = {"key-vault": "aaa111", "pii-ingestor": "bbb222", "console": "ccc333"}
    fake_client = MagicMock()
    fake_client.access_secret_version.return_value = _secret_response(built_shas)

    with patch("app.api.source_staleness.secretmanager.SecretManagerServiceClient", return_value=fake_client), \
         patch("app.api.source_staleness.requests.get") as mock_get:
        mock_get.side_effect = [
            _github_response("aaa111"),
            _github_response("bbb222"),
            _github_response("ccc333"),
        ]
        response = TestClient(_make_app()).post("/api/v1/source-staleness-check")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert all(r["status"] == "current" for r in body["results"].values())
    # User-Agent is required or GitHub 403s -- assert it's actually sent.
    for call in mock_get.call_args_list:
        assert call.kwargs["headers"]["User-Agent"]


def test_all_stale():
    built_shas = {"key-vault": "aaa111", "pii-ingestor": "bbb222", "console": "ccc333"}
    fake_client = MagicMock()
    fake_client.access_secret_version.return_value = _secret_response(built_shas)

    with patch("app.api.source_staleness.secretmanager.SecretManagerServiceClient", return_value=fake_client), \
         patch("app.api.source_staleness.requests.get") as mock_get, \
         patch("app.api.source_staleness.logger") as mock_logger:
        mock_get.side_effect = [
            _github_response("aaa999"),
            _github_response("bbb999"),
            _github_response("ccc999"),
        ]
        response = TestClient(_make_app()).post("/api/v1/source-staleness-check")

    body = response.json()
    assert all(r["status"] == "stale" for r in body["results"].values())
    # One structured warning per stale repo.
    assert mock_logger.warning.call_count == 3
    for _, kwargs in mock_logger.warning.call_args_list:
        assert kwargs["extra"]["event"] == "chameleon_source_stale"


def test_partial_staleness():
    built_shas = {"key-vault": "aaa111", "pii-ingestor": "bbb222", "console": "ccc333"}
    fake_client = MagicMock()
    fake_client.access_secret_version.return_value = _secret_response(built_shas)

    with patch("app.api.source_staleness.secretmanager.SecretManagerServiceClient", return_value=fake_client), \
         patch("app.api.source_staleness.requests.get") as mock_get:
        mock_get.side_effect = [
            _github_response("aaa111"),  # current
            _github_response("bbb999"),  # stale
            _github_response("ccc333"),  # current
        ]
        response = TestClient(_make_app()).post("/api/v1/source-staleness-check")

    results = response.json()["results"]
    assert results["key-vault"]["status"] == "current"
    assert results["pii-ingestor"]["status"] == "stale"
    assert results["console"]["status"] == "current"


def test_missing_key_in_stored_shas():
    built_shas = {"key-vault": "aaa111"}  # pii-ingestor/console absent
    fake_client = MagicMock()
    fake_client.access_secret_version.return_value = _secret_response(built_shas)

    with patch("app.api.source_staleness.secretmanager.SecretManagerServiceClient", return_value=fake_client), \
         patch("app.api.source_staleness.requests.get") as mock_get:
        mock_get.side_effect = [_github_response("aaa111")]
        response = TestClient(_make_app()).post("/api/v1/source-staleness-check")

    results = response.json()["results"]
    assert results["key-vault"]["status"] == "current"
    assert results["pii-ingestor"]["status"] == "unknown"
    assert results["console"]["status"] == "unknown"
    # Only one real GitHub call made -- the two missing keys never got that far.
    assert mock_get.call_count == 1


def test_one_bad_github_call_does_not_fail_the_others():
    built_shas = {"key-vault": "aaa111", "pii-ingestor": "bbb222", "console": "ccc333"}
    fake_client = MagicMock()
    fake_client.access_secret_version.return_value = _secret_response(built_shas)

    with patch("app.api.source_staleness.secretmanager.SecretManagerServiceClient", return_value=fake_client), \
         patch("app.api.source_staleness.requests.get") as mock_get:
        mock_get.side_effect = [
            _github_response("aaa111"),
            RuntimeError("connection reset"),
            _github_response("ccc999"),
        ]
        response = TestClient(_make_app()).post("/api/v1/source-staleness-check")

    assert response.status_code == 200
    results = response.json()["results"]
    assert results["key-vault"]["status"] == "current"
    assert results["pii-ingestor"]["status"] == "unknown"
    assert results["console"]["status"] == "stale"

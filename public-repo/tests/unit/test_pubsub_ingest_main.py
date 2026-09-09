import base64
import json
from unittest.mock import MagicMock

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app import pubsub_ingest_main
from app.pipelines.pubsub_ingest import CallerNotAuthorized, IngestOutcome


def _make_app(pipeline=None) -> FastAPI:
    """Isolated app reusing the real route function directly, with
    app.state set up manually -- avoids the real lifespan, which
    constructs a real VaultClient/BigQueryService (the wrong thing to
    depend on in a unit test). Same pattern already used for
    test_pii_vault_sync_routes.py's discovery-router tests."""
    app = FastAPI()
    app.state.pipeline = pipeline or MagicMock()
    app.post("/pubsub-ingest/{resource_id}")(pubsub_ingest_main.pubsub_ingest)
    app.get("/health")(pubsub_ingest_main.health_check)
    return app


def _push_envelope(body: dict) -> dict:
    encoded = base64.b64encode(json.dumps(body).encode("utf-8")).decode("utf-8")
    return {"message": {"data": encoded, "messageId": "msg-1"}, "subscription": "sub-1"}


RESOURCE_ID = "pubsub:acme-project.cdc-events"


class FakeResource:
    def __init__(self, resource_id=RESOURCE_ID):
        self.id = resource_id


def test_health_check():
    response = TestClient(_make_app()).get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}


def test_rejects_a_request_with_no_bearer_token():
    response = TestClient(_make_app()).post(
        f"/pubsub-ingest/{RESOURCE_ID}", json=_push_envelope({"after": {}})
    )
    assert response.status_code == 401
    assert response.json()["reason"] == "missing bearer token"


def test_rejects_a_request_whose_token_fails_verification(monkeypatch):
    monkeypatch.setattr(
        pubsub_ingest_main, "_verify_push_caller", MagicMock(side_effect=ValueError("bad signature"))
    )
    response = TestClient(_make_app()).post(
        f"/pubsub-ingest/{RESOURCE_ID}",
        json=_push_envelope({"after": {}}),
        headers={"Authorization": "Bearer not-a-real-token"},
    )
    assert response.status_code == 401
    assert response.json()["reason"] == "invalid token"


def test_rejects_when_the_caller_is_not_authorized_for_this_resource(monkeypatch):
    monkeypatch.setattr(pubsub_ingest_main, "_verify_push_caller", MagicMock(return_value="123"))
    pipeline = MagicMock()
    pipeline.resolve_resource.return_value = FakeResource()
    pipeline.authorize_caller.side_effect = CallerNotAuthorized("caller mismatch")

    response = TestClient(_make_app(pipeline)).post(
        f"/pubsub-ingest/{RESOURCE_ID}",
        json=_push_envelope({"after": {}}),
        headers={"Authorization": "Bearer real-token"},
    )

    assert response.status_code == 403
    assert response.json()["reason"] == "caller not authorized"
    pipeline.process_message.assert_not_called()


def test_rejects_when_the_resource_itself_cannot_be_resolved(monkeypatch):
    monkeypatch.setattr(pubsub_ingest_main, "_verify_push_caller", MagicMock(return_value="123"))
    pipeline = MagicMock()
    pipeline.resolve_resource.side_effect = CallerNotAuthorized("not declared")

    response = TestClient(_make_app(pipeline)).post(
        f"/pubsub-ingest/{RESOURCE_ID}",
        json=_push_envelope({"after": {}}),
        headers={"Authorization": "Bearer real-token"},
    )

    assert response.status_code == 403


def test_acks_a_malformed_message_instead_of_erroring(monkeypatch):
    monkeypatch.setattr(pubsub_ingest_main, "_verify_push_caller", MagicMock(return_value="123"))
    pipeline = MagicMock()
    pipeline.resolve_resource.return_value = FakeResource()

    response = TestClient(_make_app(pipeline)).post(
        f"/pubsub-ingest/{RESOURCE_ID}",
        json={"message": {"data": "not-valid-base64-json!!!"}, "subscription": "sub-1"},
        headers={"Authorization": "Bearer real-token"},
    )

    assert response.status_code == 200
    assert response.json()["status"] == "ignored"
    pipeline.process_message.assert_not_called()


def test_acks_a_message_the_pipeline_deliberately_skipped(monkeypatch):
    monkeypatch.setattr(pubsub_ingest_main, "_verify_push_caller", MagicMock(return_value="123"))
    pipeline = MagicMock()
    pipeline.resolve_resource.return_value = FakeResource()
    pipeline.process_message.return_value = IngestOutcome(accepted=False, reason="no declared fields found")

    response = TestClient(_make_app(pipeline)).post(
        f"/pubsub-ingest/{RESOURCE_ID}",
        json=_push_envelope({"after": {"user_id": "u1"}}),
        headers={"Authorization": "Bearer real-token"},
    )

    assert response.status_code == 200
    assert response.json() == {"status": "ignored", "reason": "no declared fields found"}


def test_rejects_when_process_message_itself_raises_caller_not_authorized(monkeypatch):
    monkeypatch.setattr(pubsub_ingest_main, "_verify_push_caller", MagicMock(return_value="123"))
    pipeline = MagicMock()
    pipeline.resolve_resource.return_value = FakeResource()
    pipeline.process_message.side_effect = CallerNotAuthorized("no userIdFieldPath declared")

    response = TestClient(_make_app(pipeline)).post(
        f"/pubsub-ingest/{RESOURCE_ID}",
        json=_push_envelope({"after": {"user_id": "u1", "email": "a@example.com"}}),
        headers={"Authorization": "Bearer real-token"},
    )

    assert response.status_code == 403


def test_returns_500_on_a_genuinely_transient_processing_failure(monkeypatch):
    monkeypatch.setattr(pubsub_ingest_main, "_verify_push_caller", MagicMock(return_value="123"))
    pipeline = MagicMock()
    pipeline.resolve_resource.return_value = FakeResource()
    pipeline.process_message.side_effect = RuntimeError("BigQuery unavailable")

    response = TestClient(_make_app(pipeline)).post(
        f"/pubsub-ingest/{RESOURCE_ID}",
        json=_push_envelope({"after": {"user_id": "u1", "email": "a@example.com"}}),
        headers={"Authorization": "Bearer real-token"},
    )

    assert response.status_code == 500


def test_accepts_a_valid_message_end_to_end(monkeypatch):
    monkeypatch.setattr(pubsub_ingest_main, "_verify_push_caller", MagicMock(return_value="123456789012345678901"))
    pipeline = MagicMock()
    pipeline.resolve_resource.return_value = FakeResource()
    pipeline.process_message.return_value = IngestOutcome(accepted=True, reason="ok", fields_written=1)

    response = TestClient(_make_app(pipeline)).post(
        f"/pubsub-ingest/{RESOURCE_ID}",
        json=_push_envelope({"after": {"user_id": "u1", "email": "a@example.com"}}),
        headers={"Authorization": "Bearer real-token"},
    )

    assert response.status_code == 200
    assert response.json() == {"status": "accepted", "fieldsWritten": 1}
    pipeline.resolve_resource.assert_called_once_with(RESOURCE_ID)
    pipeline.authorize_caller.assert_called_once()
    called_message_body = pipeline.process_message.call_args[0][1]
    assert called_message_body == {"after": {"user_id": "u1", "email": "a@example.com"}}


def test_verifies_the_token_against_the_requests_own_url_as_audience(monkeypatch):
    """Audience is derived from the request itself, not a static config
    value -- confirms the URL passed to verification matches what was
    actually requested."""
    captured_audience = {}

    def _fake_verify(token, audience):
        captured_audience["value"] = audience
        return "123"

    monkeypatch.setattr(pubsub_ingest_main, "_verify_push_caller", _fake_verify)
    pipeline = MagicMock()
    pipeline.resolve_resource.return_value = FakeResource()
    pipeline.process_message.return_value = IngestOutcome(accepted=True, reason="ok", fields_written=1)

    TestClient(_make_app(pipeline), base_url="https://pubsub-ingest.example.com").post(
        f"/pubsub-ingest/{RESOURCE_ID}",
        json=_push_envelope({"after": {"user_id": "u1", "email": "a@example.com"}}),
        headers={"Authorization": "Bearer real-token"},
    )

    assert captured_audience["value"] == f"https://pubsub-ingest.example.com/pubsub-ingest/{RESOURCE_ID}"

import base64
import json
from unittest.mock import ANY, MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api import discovery


def _make_app() -> FastAPI:
    """Isolated app registering just discovery.router, with app.state set up
    directly -- avoids main.py's real lifespan, which constructs real GCP
    clients and kicks off a background GCS-poll task on startup (the wrong
    thing to depend on in a unit test)."""
    app = FastAPI()
    app.include_router(discovery.router, prefix="/api/v1")
    app.state.vault = MagicMock()
    app.state.bq = MagicMock()
    app.state.pii_vault_sync_publisher = MagicMock()
    app.state.pii_vault_sync_chunk_topic_path = "projects/proj/topics/pii-vault-sync-chunks"
    return app


def _pubsub_envelope(payload: dict) -> dict:
    encoded = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8")
    return {"message": {"data": encoded, "messageId": "msg-1"}, "subscription": "sub-1"}


def test_pii_vault_sync_enumerates_and_returns_queued_immediately():
    """POST /api/v1/pii-vault-sync should call sync_all (enumerate + publish),
    never process_chunk directly, and report chunks_queued rather than a
    synchronous users_synced count."""
    fake_job = MagicMock()
    fake_job.sync_all.return_value = []

    with patch("app.api.discovery.PiiVaultSyncJob", return_value=fake_job) as job_cls:
        response = TestClient(_make_app()).post("/api/v1/pii-vault-sync")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "queued"
    assert body["resources_queued"] == 0
    assert body["chunks_queued"] == 0
    assert body["runId"]  # a sync_runs record is always created for the progress bar
    fake_job.sync_all.assert_called_once_with(False, body["runId"])
    fake_job.vault.create_sync_run.assert_called_once_with(body["runId"], None)
    fake_job.vault.finalize_sync_run_total.assert_called_once_with(body["runId"], 0)
    fake_job.process_chunk.assert_not_called()
    # Constructed with the app-state publisher/topic path, not left unset.
    _, kwargs = job_cls.call_args
    assert kwargs["publisher"] is not None
    assert kwargs["chunk_topic_path"] == "projects/proj/topics/pii-vault-sync-chunks"


def test_pii_vault_sync_with_no_body_defaults_force_full_scan_to_false():
    """The daily Cloud Scheduler call sends no body at all -- must not 400,
    and must resolve to the same incremental-eligible default as an
    explicit {"force_full_scan": false}."""
    fake_job = MagicMock()
    fake_job.sync_all.return_value = []

    with patch("app.api.discovery.PiiVaultSyncJob", return_value=fake_job):
        response = TestClient(_make_app()).post("/api/v1/pii-vault-sync", content=b"")

    assert response.status_code == 200
    fake_job.sync_all.assert_called_once_with(False, ANY)


def test_pii_vault_sync_force_full_scan_true_is_passed_through():
    """Sync Now (PiiVaultSyncTrigger) always sends this -- must reach
    sync_all so it actually bypasses incremental filtering, not just get
    parsed and dropped."""
    fake_job = MagicMock()
    fake_job.sync_all.return_value = []

    with patch("app.api.discovery.PiiVaultSyncJob", return_value=fake_job):
        response = TestClient(_make_app()).post("/api/v1/pii-vault-sync", json={"force_full_scan": True})

    assert response.status_code == 200
    fake_job.sync_all.assert_called_once_with(True, ANY)


def test_pii_vault_sync_degrades_gracefully_when_creating_the_sync_run_fails():
    """A Key Vault hiccup while creating the sync_runs record must never
    fail the sync itself -- it degrades to no progress bar (runId: null),
    and sync_all/finalize are called with/without a run_id accordingly."""
    fake_job = MagicMock()
    fake_job.sync_all.return_value = []
    fake_job.vault.create_sync_run.side_effect = RuntimeError("Key Vault unreachable")

    with patch("app.api.discovery.PiiVaultSyncJob", return_value=fake_job):
        response = TestClient(_make_app()).post("/api/v1/pii-vault-sync")

    assert response.status_code == 200
    body = response.json()
    assert body["runId"] is None
    fake_job.sync_all.assert_called_once_with(False, None)
    fake_job.vault.finalize_sync_run_total.assert_not_called()


def test_pii_vault_sync_chunk_decodes_the_pubsub_envelope_and_calls_process_chunk():
    fake_job = MagicMock()
    fake_job.process_chunk.return_value = 3

    payload = {"resource_id": "bigquery:proj.dataset.federated_user", "user_ids": ["u1", "u2", "u3"]}

    with patch("app.api.discovery.PiiVaultSyncJob", return_value=fake_job):
        response = TestClient(_make_app()).post("/api/v1/pii-vault-sync-chunk", json=_pubsub_envelope(payload))

    assert response.status_code == 200
    body = response.json()
    assert body == {"status": "ok", "resource_id": payload["resource_id"], "users_synced": 3}
    fake_job.process_chunk.assert_called_once_with(payload["resource_id"], payload["user_ids"], None)


def test_pii_vault_sync_chunk_forwards_run_id_from_the_payload():
    fake_job = MagicMock()
    fake_job.process_chunk.return_value = 1

    payload = {"resource_id": "bigquery:proj.dataset.federated_user", "user_ids": ["u1"], "run_id": "run-abc"}

    with patch("app.api.discovery.PiiVaultSyncJob", return_value=fake_job):
        response = TestClient(_make_app()).post("/api/v1/pii-vault-sync-chunk", json=_pubsub_envelope(payload))

    assert response.status_code == 200
    fake_job.process_chunk.assert_called_once_with(payload["resource_id"], payload["user_ids"], "run-abc")


def test_pii_vault_sync_chunk_acks_a_malformed_message_instead_of_retrying_forever():
    with patch("app.api.discovery.PiiVaultSyncJob") as job_cls:
        response = TestClient(_make_app()).post(
            "/api/v1/pii-vault-sync-chunk",
            json={"message": {"data": "not-valid-base64-json!!", "messageId": "msg-2"}},
        )

    assert response.status_code == 200
    assert response.json()["status"] == "ignored"
    job_cls.assert_not_called()


def test_pii_vault_sync_chunk_returns_500_on_a_real_failure_so_pubsub_retries():
    fake_job = MagicMock()
    fake_job.process_chunk.side_effect = RuntimeError("BigQuery unavailable")

    payload = {"resource_id": "bigquery:proj.dataset.federated_user", "user_ids": ["u1"]}

    with patch("app.api.discovery.PiiVaultSyncJob", return_value=fake_job):
        response = TestClient(_make_app()).post("/api/v1/pii-vault-sync-chunk", json=_pubsub_envelope(payload))

    assert response.status_code == 500

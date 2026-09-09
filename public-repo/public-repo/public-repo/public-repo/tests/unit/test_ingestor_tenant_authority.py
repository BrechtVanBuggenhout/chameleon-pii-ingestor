import base64
import json
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from app.config import settings
from app.services.ingestor import app


def _pubsub_envelope(payload: dict) -> dict:
    encoded = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8")
    return {"message": {"data": encoded, "messageId": "msg-1"}}


def test_ingestor_uses_x_tenant_id_as_authority_over_body_tenant():
    vault = MagicMock()
    vault.get_encryption_context.return_value = {"dek": "a" * 64, "key_id": "key-1"}
    bq = MagicMock()

    payload = {
        "userId": "user-1",
        "tenantId": "body-tenant",
        "payload": {"email": "user@example.com"},
        "operationId": "op-1",
    }

    with (
        patch("app.services.ingestor.VaultClient", return_value=vault) as vault_cls,
        patch("app.services.ingestor.get_warehouse_writer", return_value=bq),
        patch("app.services.ingestor.ChameleonCrypto.encrypt", return_value="ciphertext"),
    ):
        response = TestClient(app).post(
            "/ingest",
            json=_pubsub_envelope(payload),
            headers={"X-Tenant-Id": "header-tenant"},
        )

    assert response.status_code == 200
    vault_cls.assert_called_once_with(base_url=settings.VAULT_BASE_URL, tenant_id="header-tenant")
    assert bq.load_records.call_args.args[0] == "raw_users"
    inserted_record = bq.load_records.call_args.args[1][0]
    assert inserted_record["tenant_id"] == "header-tenant"
    vault.report_lineage.assert_called_once()
    assert (
        vault.report_lineage.call_args.kwargs["destination"]
        == f"bigquery:{settings.GOOGLE_CLOUD_PROJECT}.{settings.staging_dataset_resolved}.raw_users"
    )


def test_ingestor_accepts_header_only_tenant():
    vault = MagicMock()
    vault.get_encryption_context.return_value = {"dek": "a" * 64, "key_id": "key-1"}
    bq = MagicMock()

    payload = {
        "userId": "user-1",
        "payload": {"email": "user@example.com"},
        "operationId": "op-1",
    }

    with (
        patch("app.services.ingestor.VaultClient", return_value=vault) as vault_cls,
        patch("app.services.ingestor.get_warehouse_writer", return_value=bq),
        patch("app.services.ingestor.ChameleonCrypto.encrypt", return_value="ciphertext"),
    ):
        response = TestClient(app).post(
            "/ingest",
            json=_pubsub_envelope(payload),
            headers={"X-Tenant-Id": "header-tenant"},
        )

    assert response.status_code == 200
    vault_cls.assert_called_once_with(base_url=settings.VAULT_BASE_URL, tenant_id="header-tenant")

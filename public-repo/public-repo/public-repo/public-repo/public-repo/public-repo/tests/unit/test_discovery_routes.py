from unittest.mock import MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api import discovery


def _make_app() -> FastAPI:
    """Isolated app registering just discovery.router, with app.state set up
    directly -- avoids main.py's real lifespan, which constructs real GCP
    clients. Mirrors test_pii_vault_sync_routes.py's _make_app()."""
    app = FastAPI()
    app.include_router(discovery.router, prefix="/api/v1")
    app.state.vault = MagicMock()
    app.state.bq = MagicMock()
    return app


def test_publish_dbt_pii_discovery_returns_counts_from_the_publisher():
    fake_resource = MagicMock()
    fake_resource.fields = ["username", "phone"]
    fake_publisher = MagicMock()
    fake_publisher.publish.return_value = [fake_resource]

    with patch("app.api.discovery.DbtPiiDiscoveryPublisher", return_value=fake_publisher) as publisher_cls:
        response = TestClient(_make_app()).post("/api/v1/publish-dbt-pii-discovery")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["resources_published"] == 1
    assert body["fields_published"] == 2
    fake_publisher.publish.assert_called_once()
    # Constructed from app.state, not left to construct its own BigQuery/vault clients.
    _, kwargs = publisher_cls.call_args
    assert kwargs["vault"] is not None
    assert kwargs["bigquery_client"] is not None


def test_publish_dbt_pii_discovery_is_a_noop_with_no_datasets_configured():
    with patch("app.api.discovery.settings") as fake_settings:
        fake_settings.DBT_PII_DISCOVERY_DATASETS = ""
        with patch("app.api.discovery.DbtPiiDiscoveryPublisher") as publisher_cls:
            publisher_cls.return_value.publish.return_value = []
            response = TestClient(_make_app()).post("/api/v1/publish-dbt-pii-discovery")

    assert response.status_code == 200
    body = response.json()
    assert body["resources_published"] == 0
    assert body["fields_published"] == 0
    # Empty DBT_PII_DISCOVERY_DATASETS resolves to an empty locations list.
    _, kwargs = publisher_cls.call_args
    assert kwargs["pii_discovery_locations"] == []

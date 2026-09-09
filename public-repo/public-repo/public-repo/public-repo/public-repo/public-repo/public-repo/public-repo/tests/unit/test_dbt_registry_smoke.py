from argparse import Namespace

from scripts.dbt_registry_smoke import check_manifest, run_dbt_registry_smoke
from app.policies.pii_registry import PiiMetadataRegistry


def registry_response():
    return {
        "resources": [
            {
                "resourceId": "bigquery:project.analytics.stg_users",
                "system": "bigquery",
                "tenantIdColumn": "tenant_id",
                "userIdColumn": "user_id",
                "deletionStrategy": "CRYPTO_SHRED",
                "piiFields": [],
            },
            {
                "resourceId": "bigquery:project.analytics.mart_customer_metrics",
                "system": "bigquery",
                "tenantIdColumn": "tenant_id",
                "deletionStrategy": "MANUAL_REVIEW",
                "handlingPolicy": "mart_aggregate_only",
                "piiFields": [
                    {
                        "name": "user_surrogate_id",
                        "classification": "SYSTEM_IDENTIFIER",
                        "handling": "ALLOW_AGGREGATE_ONLY",
                    }
                ],
            },
        ]
    }


def manifest(nodes):
    return {"nodes": nodes}


def test_dbt_registry_check_warns_for_unapproved_manual_review_model():
    registry = PiiMetadataRegistry.from_api_response(registry_response())
    data = manifest(
        {
            "model.project.mart_customer_metrics": {
                "resource_type": "model",
                "database": "project",
                "schema": "analytics",
                "alias": "mart_customer_metrics",
                "name": "mart_customer_metrics",
                "columns": {"tenant_id": {}, "user_surrogate_id": {}},
                "meta": {"chameleon": {"mart_manual_review_approved": False}},
            }
        }
    )

    checks = check_manifest(data, registry)

    assert [(check.status, check.rule) for check in checks] == [
        ("WARN", "manual_review_required")
    ]


def test_dbt_registry_check_fails_missing_registry_and_tenant_scope():
    registry = PiiMetadataRegistry.from_api_response(registry_response())
    data = manifest(
        {
            "model.project.unknown": {
                "resource_type": "model",
                "database": "project",
                "schema": "analytics",
                "alias": "unknown",
                "name": "unknown",
                "columns": {"tenant_id": {}},
            },
            "model.project.stg_users": {
                "resource_type": "model",
                "database": "project",
                "schema": "analytics",
                "alias": "stg_users",
                "name": "stg_users",
                "columns": {"user_id": {}},
            },
        }
    )

    checks = check_manifest(data, registry)

    assert ("FAIL", "missing_registry_resource") in [
        (check.status, check.rule) for check in checks
    ]
    assert ("FAIL", "tenant_id_required") in [
        (check.status, check.rule) for check in checks
    ]


class FakeVault:
    def __init__(self, base_url, tenant_id):
        pass

    def fetch_pii_registry_resources(self, system=None):
        return registry_response()

    def shutdown(self):
        pass


def test_dbt_registry_smoke_returns_warn_without_failures(capsys):
    args = Namespace(
        vault_url="http://mock-vault",
        tenant_id="tenant-a",
        manifest="target/manifest.json",
    )
    data = manifest(
        {
            "model.project.mart_customer_metrics": {
                "resource_type": "model",
                "database": "project",
                "schema": "analytics",
                "alias": "mart_customer_metrics",
                "name": "mart_customer_metrics",
                "columns": {"tenant_id": {}, "user_surrogate_id": {}},
                "meta": {"chameleon": {"mart_manual_review_approved": False}},
            }
        }
    )

    result = run_dbt_registry_smoke(
        args,
        vault_factory=FakeVault,
        manifest_loader=lambda path: data,
    )

    output = capsys.readouterr().out
    assert result["status"] == "WARN"
    assert "dbt registry status: WARN" in output

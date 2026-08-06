from app.policies.dbt_policy import DbtPolicyValidator
from app.policies.pii_registry import PiiMetadataRegistry


def test_dbt_policy_requires_tenant_id_for_tenant_scoped_models():
    registry = PiiMetadataRegistry.load("config/pii_metadata_registry.dev.json")
    manifest = {
        "nodes": {
            "model.project.stg_users": {
                "resource_type": "model",
                "database": "chameleon_dev",
                "schema": "stg_users",
                "alias": "stg_users",
                "name": "stg_users",
                "columns": {"user_id": {}},
            }
        }
    }

    violations = DbtPolicyValidator(registry).validate_manifest(manifest)

    assert [violation.rule for violation in violations] == ["tenant_id_required"]


def test_dbt_policy_blocks_direct_identifiers_in_marts():
    registry = PiiMetadataRegistry(
        version=1,
        resources=[
            registry_resource
            for registry_resource in PiiMetadataRegistry.load("config/pii_metadata_registry.dev.json").resources
        ],
    )
    direct_identifier_resource = registry.resources[0].__class__(
        id="bigquery:analytics.customer_mart",
        type="bigquery_table",
        tenant_scoped=True,
        tenant_id_column="tenant_id",
        user_id_column="user_id",
        allowed_direct_identifiers=[],
        columns=[
            registry.resources[0].columns[0].__class__(
                name="email",
                classification="DIRECT_IDENTIFIER",
                identifier_type="EMAIL",
                allowed_in_mart=False,
            ),
            registry.resources[0].columns[1],
        ],
    )
    registry.resources.append(direct_identifier_resource)
    manifest = {
        "nodes": {
            "model.project.customer_mart": {
                "resource_type": "model",
                "database": "analytics",
                "schema": "customer_mart",
                "alias": "customer_mart",
                "name": "customer_mart",
                "path": "models/marts/customer_mart.sql",
                "columns": {"tenant_id": {}, "email": {}},
            }
        }
    }

    violations = DbtPolicyValidator(registry).validate_manifest(manifest)

    assert [violation.rule for violation in violations] == ["direct_identifier_in_mart"]


def test_dbt_policy_requires_user_scope_for_crypto_shredded_resources():
    registry = PiiMetadataRegistry.from_api_response(
        {
            "resources": [
                {
                    "resourceId": "bigquery:analytics.secure_events",
                    "system": "bigquery",
                    "tenantIdColumn": "tenant_id",
                    "userIdColumn": "user_id",
                    "deletionStrategy": "CRYPTO_SHRED",
                    "piiFields": [],
                }
            ]
        }
    )
    manifest = {
        "nodes": {
            "model.project.secure_events": {
                "resource_type": "model",
                "database": "analytics",
                "schema": "secure_events",
                "alias": "secure_events",
                "name": "secure_events",
                "columns": {"tenant_id": {}},
            }
        }
    }

    violations = DbtPolicyValidator(registry).validate_manifest(manifest)

    assert [violation.rule for violation in violations] == ["user_scope_required"]


def test_dbt_policy_reads_control_plane_status():
    class FakeVault:
        def fetch_pii_registry_policy(self):
            return {"status": "WARN", "evaluations": []}

    assert DbtPolicyValidator.control_plane_policy_status(FakeVault())["status"] == "WARN"

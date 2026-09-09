from app.policies.pii_registry import PiiMetadataRegistry


def test_load_dev_registry():
    registry = PiiMetadataRegistry.load("config/pii_metadata_registry.dev.json")

    stg_users = registry.get("bigquery:chameleon_dev.stg_users")

    assert registry.version == 1
    assert stg_users.tenant_scoped is True
    assert stg_users.tenant_id_column == "tenant_id"
    assert "email_token" in stg_users.column_names()


def test_load_registry_from_key_vault_contract_response():
    registry = PiiMetadataRegistry.from_api_response(
        {
            "resources": [
                {
                    "registryVersion": "2026-06-19",
                    "resourceId": "bigquery:project.dataset.stg_users",
                    "system": "bigquery",
                    "tenantIdColumn": "tenant_id",
                    "userIdColumn": "user_id",
                    "ownerConnector": "pipelines",
                    "lineageDestination": "bigquery:dataset.stg_users",
                    "deletionStrategy": "CRYPTO_SHRED",
                    "handlingPolicy": "staging_encrypted_pii",
                    "evidencePointers": ["lineage:source=key-vault,destination=bigquery:dataset.stg_users"],
                    "piiFields": [
                        {
                            "name": "email",
                            "classification": "DIRECT_IDENTIFIER",
                            "handling": "ENCRYPT",
                            "requiredInMart": False,
                            "evidence": ["scanner:EMAIL"],
                            "confidence": "DECLARED",
                        }
                    ],
                    "ghostDataScan": {
                        "enabled": True,
                        "scanMode": "SAMPLED",
                        "patterns": ["EMAIL", "PHONE", "NAME"],
                    },
                }
            ],
            "count": 1,
        }
    )

    resource = registry.get("bigquery:project.dataset.stg_users")

    assert registry.version == "2026-06-19"
    assert resource.type == "bigquery_table"
    assert resource.system == "bigquery"
    assert resource.user_id_column == "user_id"
    assert resource.lineage_destination == "bigquery:dataset.stg_users"
    assert resource.deletion_strategy == "CRYPTO_SHRED"
    assert resource.ghost_data_scan.enabled is True
    assert resource.ghost_data_scan.patterns == ["EMAIL", "PHONE", "NAME"]
    assert resource.direct_identifier_columns[0].handling == "ENCRYPT"

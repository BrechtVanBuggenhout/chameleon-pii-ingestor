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


class TestSourceRedactionStrategiesResolution:
    """Mirrors chameleon-key-vault's resolveSourceRedactionStrategies(): the
    array field wins if present, else the legacy singular field is wrapped
    (dropping 'NONE'). Must behave identically for the two Firestore-shaped
    documents pii_vault_sync.py actually receives from the registry API."""

    def _resource(self, **overrides):
        return {
            "resourceId": "bigquery:proj.dataset.contacts",
            "system": "bigquery",
            "userIdColumn": "user_id",
            "piiFields": [],
            **overrides,
        }

    def test_prefers_the_array_field_when_present(self):
        registry = PiiMetadataRegistry.from_api_response(
            {"resources": [self._resource(sourceRedactionStrategies=["REDACT_IN_PLACE", "ENCRYPTED_COPY"])]}
        )
        resource = registry.get("bigquery:proj.dataset.contacts")
        assert resource.source_redaction_strategies == ["REDACT_IN_PLACE", "ENCRYPTED_COPY"]
        assert resource.wants_encrypted_copy() is True

    def test_falls_back_to_the_legacy_singular_field_dropping_none(self):
        registry = PiiMetadataRegistry.from_api_response(
            {"resources": [self._resource(sourceRedactionStrategy="SHADOW_COPY")]}
        )
        resource = registry.get("bigquery:proj.dataset.contacts")
        assert resource.source_redaction_strategies == ["SHADOW_COPY"]
        assert resource.wants_encrypted_copy() is False

    def test_legacy_none_resolves_to_an_empty_list(self):
        registry = PiiMetadataRegistry.from_api_response(
            {"resources": [self._resource(sourceRedactionStrategy="NONE")]}
        )
        resource = registry.get("bigquery:proj.dataset.contacts")
        assert resource.source_redaction_strategies == []

    def test_neither_field_present_resolves_to_an_empty_list(self):
        registry = PiiMetadataRegistry.from_api_response({"resources": [self._resource()]})
        resource = registry.get("bigquery:proj.dataset.contacts")
        assert resource.source_redaction_strategies == []
        assert resource.wants_encrypted_copy() is False

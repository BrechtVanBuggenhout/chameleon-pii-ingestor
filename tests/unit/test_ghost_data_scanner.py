from unittest.mock import MagicMock

from app.policies.pii_registry import PiiMetadataRegistry
from app.scanners.ghost_data_scanner import BigQueryGhostDataScanner


class FakeQueryJob:
    def __init__(self, rows):
        self._rows = rows

    def result(self):
        return self._rows


class FakeBigQueryClient:
    def __init__(self, rows):
        self.rows = rows
        self.queries = []

    def query(self, query):
        self.queries.append(query)
        return FakeQueryJob(self.rows)


def test_scanner_detects_ghost_data_without_emitting_raw_pii():
    registry = PiiMetadataRegistry.load("config/pii_metadata_registry.dev.json")
    bq = FakeBigQueryClient(
        [
            {
                "user_id": "user-1",
                "tenant_id": "tenant-a",
                "email_token": "leaked@example.com",
                "encrypted_pii": b"ciphertext",
            },
            {
                "user_id": "user-2",
                "tenant_id": "tenant-a",
                "email_token": "+1 415 555 0100",
                "encrypted_pii": b"ciphertext",
            },
        ]
    )
    vault = MagicMock()

    findings = BigQueryGhostDataScanner(
        bigquery_client=bq,
        registry=registry,
        vault=vault,
    ).scan(["bigquery:chameleon_dev.stg_users"])

    assert {finding.pattern for finding in findings} == {"EMAIL", "PHONE"}
    assert vault.report_lineage.call_count == 2
    for call in vault.report_lineage.call_args_list:
        assert call.kwargs["data_classification"] == "GHOST_DATA"
        assert "leaked@example.com" not in str(call.kwargs)
        assert "+1 415 555 0100" not in str(call.kwargs)


def test_scanner_detects_email_nested_inside_json_object_column():
    # BigQuery's client returns JSON/STRUCT columns as native dict values.
    # An email a couple of keys deep must still be found, and the finding's
    # column must be marked "(json)" so a reviewer can tell it wasn't a
    # plain STRING column that happened to look like an email.
    registry = PiiMetadataRegistry.load("config/pii_metadata_registry.dev.json")
    bq = FakeBigQueryClient(
        [
            {
                "user_id": "user-1",
                "tenant_id": "tenant-a",
                "attributes": {"contact": {"backup_email": "leaked-json@example.com"}, "note": "n/a"},
            },
        ]
    )
    vault = MagicMock()

    findings = BigQueryGhostDataScanner(
        bigquery_client=bq,
        registry=registry,
        vault=vault,
    ).scan(["bigquery:chameleon_dev.stg_users"])

    assert [(f.column, f.pattern, f.sample_count) for f in findings] == [("attributes (json)", "EMAIL", 1)]
    for call in vault.report_lineage.call_args_list:
        assert "leaked-json@example.com" not in str(call.kwargs)


def test_scanner_detects_phone_inside_json_array_column():
    # REPEATED/ARRAY columns come back as native list values -- a
    # phone-shaped leaf nested inside a list of objects must still be found.
    registry = PiiMetadataRegistry.load("config/pii_metadata_registry.dev.json")
    bq = FakeBigQueryClient(
        [
            {
                "user_id": "user-1",
                "tenant_id": "tenant-a",
                "attributes": [{"kind": "mobile", "value": "+1 415 555 0100"}, {"kind": "fax", "value": None}],
            },
        ]
    )
    vault = MagicMock()

    findings = BigQueryGhostDataScanner(
        bigquery_client=bq,
        registry=registry,
        vault=vault,
    ).scan(["bigquery:chameleon_dev.stg_users"])

    assert [(f.column, f.pattern, f.sample_count) for f in findings] == [("attributes (json)", "PHONE", 1)]


def test_scanner_reports_no_findings_for_benign_json_object_column():
    registry = PiiMetadataRegistry.load("config/pii_metadata_registry.dev.json")
    bq = FakeBigQueryClient(
        [
            {
                "user_id": "user-1",
                "tenant_id": "tenant-a",
                "attributes": {"plan": "pro", "seats": 5, "active": True, "note": "nothing sensitive here"},
            },
        ]
    )
    vault = MagicMock()

    findings = BigQueryGhostDataScanner(
        bigquery_client=bq,
        registry=registry,
        vault=vault,
    ).scan(["bigquery:chameleon_dev.stg_users"])

    assert findings == []
    vault.report_lineage.assert_not_called()


def test_scanner_uses_key_vault_registry_scope_and_metadata_contract():
    vault = MagicMock()
    vault.fetch_pii_registry_resources.return_value = {
        "resources": [
            {
                "resourceId": "bigquery:project.dataset.stg_users",
                "system": "bigquery",
                "tenantIdColumn": "tenant_id",
                "userIdColumn": "user_id",
                "lineageDestination": "bigquery:dataset.stg_users",
                "deletionStrategy": "CRYPTO_SHRED",
                "piiFields": [
                    {
                        "name": "email",
                        "classification": "DIRECT_IDENTIFIER",
                        "handling": "ENCRYPT",
                    }
                ],
                "ghostDataScan": {
                    "enabled": True,
                    "scanMode": "SAMPLED",
                    "patterns": ["PHONE"],
                },
            }
        ],
        "count": 1,
    }
    bq = FakeBigQueryClient(
        [
            {
                "user_id": "user-1",
                "tenant_id": "tenant-a",
                "email": "declared@example.com",
                "notes": "+1 415 555 0100",
            },
            {
                "user_id": "user-2",
                "tenant_id": "tenant-a",
                "email": "declared2@example.com",
                "notes": "Ada Lovelace",
            },
        ]
    )

    findings = BigQueryGhostDataScanner.from_vault(bq, vault).scan()

    assert [(finding.column, finding.pattern, finding.sample_count) for finding in findings] == [
        ("notes", "PHONE", 1)
    ]
    vault.fetch_pii_registry_resources.assert_called_once_with(system="bigquery", scan_enabled=True)
    assert "LIMIT 1000" in bq.queries[0]
    lineage_call = vault.report_lineage.call_args
    assert lineage_call.kwargs["user_id"] == "UNKNOWN"
    assert lineage_call.kwargs["destination"] == "bigquery:dataset.stg_users"
    assert lineage_call.kwargs["metadata"] == {
        "resource_id": "bigquery:project.dataset.stg_users",
        "system": "bigquery",
        "column": "notes",
        "pattern": "PHONE",
        "count": 1,
        "confidence": "PATTERN_MATCH",
        "scanner": "bigquery_ghost_data_scanner",
        "recommended_action": "declare_in_pii_registry_or_remove_from_resource",
    }

from argparse import Namespace

from google.api_core.exceptions import NotFound

from scripts.pii_registry_smoke import (
    CANARY_EMAIL,
    CANARY_OPERATION_ID,
    cleanup_canary_rows,
    run_smoke,
    seed_canary_row,
)


class FakeVault:
    instances = []

    def __init__(self, base_url, tenant_id):
        self.base_url = base_url
        self.tenant_id = tenant_id
        self.reported_lineage = []
        FakeVault.instances.append(self)

    def fetch_pii_registry_resources(self, system=None, owner_connector=None, scan_enabled=None):
        self.registry_filters = {
            "system": system,
            "owner_connector": owner_connector,
            "scan_enabled": scan_enabled,
        }
        return {
            "resources": [
                {
                    "resourceId": "bigquery:project.dataset.stg_users",
                    "system": "bigquery",
                    "tenantIdColumn": "tenant_id",
                    "userIdColumn": "user_id",
                    "lineageDestination": "bigquery:dataset.stg_users",
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
                        "patterns": ["EMAIL"],
                    },
                }
            ],
            "count": 1,
        }

    def fetch_pii_registry_policy(self):
        return {"status": "WARN", "evaluations": []}

    def report_lineage(self, **kwargs):
        self.reported_lineage.append(kwargs)


class FakeQueryJob:
    def result(self):
        return [
            {
                "tenant_id": "tenant-a",
                "user_id": "user-1",
                "email": "declared@example.com",
                "notes": "leaked@example.com",
            }
        ]


class FakeBigQueryClient:
    instances = []

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.queries = []
        FakeBigQueryClient.instances.append(self)

    def query(self, query):
        self.queries.append(query)
        return FakeQueryJob()


def test_pii_registry_smoke_fetches_control_plane_contract_and_can_run_scan():
    FakeVault.instances = []
    FakeBigQueryClient.instances = []
    args = Namespace(
        vault_url="http://mock-vault",
        tenant_id="tenant-a",
        system="bigquery",
        owner_connector="pipelines",
        scan_enabled=True,
        run_scan=True,
        sample_limit=25,
        skip_missing_tables=True,
        project_id="project",
    )

    result = run_smoke(
        args,
        vault_factory=FakeVault,
        bigquery_client_factory=FakeBigQueryClient,
    )

    vault = FakeVault.instances[0]
    bq = FakeBigQueryClient.instances[0]

    assert vault.registry_filters == {
        "system": "bigquery",
        "owner_connector": "pipelines",
        "scan_enabled": True,
    }
    assert result["policy"]["status"] == "WARN"
    assert [finding.pattern for finding in result["findings"]] == ["EMAIL"]
    assert bq.kwargs == {"project": "project"}
    assert "LIMIT 25" in bq.queries[0]
    assert vault.reported_lineage[0]["data_classification"] == "GHOST_DATA"
    assert vault.reported_lineage[0]["destination"] == "bigquery:dataset.stg_users"


class FakeBigQueryClientWithMissingTable(FakeBigQueryClient):
    def query(self, query):
        self.queries.append(query)
        if "missing_table" in query:
            raise NotFound("missing")
        return FakeQueryJob()


class FakeVaultWithMissingTable(FakeVault):
    def fetch_pii_registry_resources(self, system=None, owner_connector=None, scan_enabled=None):
        data = super().fetch_pii_registry_resources(system, owner_connector, scan_enabled)
        data["resources"].append(
            {
                "resourceId": "bigquery:project.dataset.missing_table",
                "system": "bigquery",
                "tenantIdColumn": "tenant_id",
                "userIdColumn": "user_id",
                "piiFields": [],
                "ghostDataScan": {
                    "enabled": True,
                    "scanMode": "SAMPLED",
                    "patterns": ["EMAIL"],
                },
            }
        )
        data["count"] = 2
        return data


def test_pii_registry_smoke_can_skip_missing_bigquery_tables():
    FakeVault.instances = []
    FakeBigQueryClient.instances = []
    args = Namespace(
        vault_url="http://mock-vault",
        tenant_id="tenant-a",
        system="bigquery",
        owner_connector=None,
        scan_enabled=True,
        run_scan=True,
        sample_limit=25,
        skip_missing_tables=True,
        project_id=None,
    )

    result = run_smoke(
        args,
        vault_factory=FakeVaultWithMissingTable,
        bigquery_client_factory=FakeBigQueryClientWithMissingTable,
    )

    assert [finding.resource_id for finding in result["findings"]] == ["bigquery:project.dataset.stg_users"]


class FakeCanaryQueryJob:
    def result(self):
        return []


class FakeCanaryBigQueryClient:
    def __init__(self):
        self.queries = []
        self.job_configs = []

    def query(self, query, job_config=None):
        self.queries.append(query)
        self.job_configs.append(job_config)
        return FakeCanaryQueryJob()


def test_canary_seed_inserts_only_synthetic_ghost_row():
    bq = FakeCanaryBigQueryClient()

    seed_canary_row(bq, table_id="project.dataset.raw_users")

    assert "INSERT INTO `project.dataset.raw_users`" in bq.queries[0]
    assert "@canary_email" in bq.queries[0]
    assert "CURRENT_TIMESTAMP()" in bq.queries[0]
    query_params = {
        parameter.name: parameter.value
        for parameter in bq.job_configs[0].query_parameters
    }
    assert query_params["operation_id"] == CANARY_OPERATION_ID
    assert query_params["canary_email"] == CANARY_EMAIL


def test_canary_cleanup_filters_by_fixed_operation_id():
    bq = FakeCanaryBigQueryClient()

    cleanup_canary_rows(bq, table_id="project.dataset.raw_users")

    assert "DELETE FROM `project.dataset.raw_users`" in bq.queries[0]
    query_params = bq.job_configs[0].query_parameters
    assert query_params[0].name == "operation_id"
    assert query_params[0].value == CANARY_OPERATION_ID

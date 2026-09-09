from unittest.mock import MagicMock

from app.scanners.dbt_pii_discovery_publisher import DbtPiiDiscoveryPublisher


class FakeQueryJob:
    def __init__(self, rows):
        self._rows = rows

    def result(self):
        return self._rows


class FakeBigQueryClient:
    def __init__(self, project="default-project", responses=None, raise_for=None):
        self.project = project
        self.queries = []
        self.responses = responses or {}
        self.raise_for = raise_for or set()

    def query(self, query):
        self.queries.append(query)
        for location, rows in self.responses.items():
            if f"`{location}.pii_discovery`" in query:
                if location in self.raise_for:
                    raise RuntimeError(f"table not found: {location}.pii_discovery")
                return FakeQueryJob(rows)
        raise AssertionError(f"Unexpected query: {query}")


def discovery_row(**overrides):
    row = {
        "resource_id": "bigquery:project.dataset.dim_users",
        "table_catalog": "project",
        "table_schema": "dataset",
        "table_name": "dim_users",
        "field_name": "username",
        "classification": "DIRECT_IDENTIFIER",
        "confidence": "INFERRED_HIGH",
        "detection_method": "INFORMATION_SCHEMA",
    }
    row.update(overrides)
    return row


def test_discover_resources_groups_multiple_fields_under_one_resource():
    bq = FakeBigQueryClient(
        responses={
            "project.dataset": [
                discovery_row(field_name="username"),
                discovery_row(field_name="phone", classification="CONTACT"),
            ]
        }
    )
    vault = MagicMock()

    publisher = DbtPiiDiscoveryPublisher(
        bigquery_client=bq, vault=vault, pii_discovery_locations=["project.dataset"]
    )
    resources = publisher.discover_resources()

    assert len(resources) == 1
    resource = resources[0]
    assert resource.resource_id == "bigquery:project.dataset.dim_users"
    assert resource.project_id == "project"
    assert resource.dataset_id == "dataset"
    assert resource.table_id == "dim_users"
    assert [f.field_name for f in resource.fields] == ["username", "phone"]
    assert [f.classification for f in resource.fields] == ["DIRECT_IDENTIFIER", "CONTACT"]
    assert "`project.dataset.pii_discovery`" in bq.queries[0]


def test_bare_dataset_location_resolves_against_bigquery_client_project():
    bq = FakeBigQueryClient(
        project="resolved-project",
        responses={"resolved-project.analytics": [discovery_row()]},
    )
    vault = MagicMock()

    publisher = DbtPiiDiscoveryPublisher(
        bigquery_client=bq, vault=vault, pii_discovery_locations=["analytics"]
    )
    resources = publisher.discover_resources()

    assert len(resources) == 1
    assert "`resolved-project.analytics.pii_discovery`" in bq.queries[0]


def test_multiple_locations_are_all_queried_and_combined():
    bq = FakeBigQueryClient(
        responses={
            "proj-a.ds": [discovery_row(resource_id="bigquery:proj-a.ds.t1", table_catalog="proj-a", table_schema="ds", table_name="t1")],
            "proj-b.ds": [discovery_row(resource_id="bigquery:proj-b.ds.t2", table_catalog="proj-b", table_schema="ds", table_name="t2")],
        }
    )
    vault = MagicMock()

    publisher = DbtPiiDiscoveryPublisher(
        bigquery_client=bq, vault=vault, pii_discovery_locations=["proj-a.ds", "proj-b.ds"]
    )
    resources = publisher.discover_resources()

    resource_ids = {r.resource_id for r in resources}
    assert resource_ids == {"bigquery:proj-a.ds.t1", "bigquery:proj-b.ds.t2"}


def test_missing_pii_discovery_table_at_one_location_does_not_block_others():
    bq = FakeBigQueryClient(
        responses={
            "proj-a.ds": [discovery_row()],
            "proj-b.ds": [],
        },
        raise_for={"proj-b.ds"},
    )
    vault = MagicMock()

    publisher = DbtPiiDiscoveryPublisher(
        bigquery_client=bq, vault=vault, pii_discovery_locations=["proj-a.ds", "proj-b.ds"]
    )
    resources = publisher.discover_resources()

    assert len(resources) == 1
    assert resources[0].resource_id == "bigquery:project.dataset.dim_users"


def test_publish_emits_one_lineage_event_per_resource_with_dbt_provenance():
    bq = FakeBigQueryClient(
        responses={
            "project.dataset": [
                discovery_row(field_name="username"),
                discovery_row(field_name="phone", classification="CONTACT"),
            ]
        }
    )
    vault = MagicMock()

    DbtPiiDiscoveryPublisher(
        bigquery_client=bq, vault=vault, pii_discovery_locations=["project.dataset"]
    ).publish()

    vault.report_lineage.assert_called_once()
    _, kwargs = vault.report_lineage.call_args
    assert kwargs["event_type"] == "WAREHOUSE_METADATA_DISCOVERED"
    assert kwargs["user_id"] == "UNKNOWN"
    assert kwargs["source"] == "chameleon_pii_dbt_discovery"
    assert kwargs["destination"] == "bigquery:project.dataset.dim_users"
    assert kwargs["data_classification"] == "METADATA"
    assert kwargs["metadata"]["registry_status"] == "UNREGISTERED"
    assert kwargs["metadata"]["new_columns"] == ["username", "phone"]
    assert kwargs["metadata"]["classifications"] == {
        "username": "DIRECT_IDENTIFIER",
        "phone": "CONTACT",
    }


def test_empty_locations_publishes_nothing():
    bq = FakeBigQueryClient()
    vault = MagicMock()

    resources = DbtPiiDiscoveryPublisher(
        bigquery_client=bq, vault=vault, pii_discovery_locations=[]
    ).publish()

    assert resources == []
    vault.report_lineage.assert_not_called()

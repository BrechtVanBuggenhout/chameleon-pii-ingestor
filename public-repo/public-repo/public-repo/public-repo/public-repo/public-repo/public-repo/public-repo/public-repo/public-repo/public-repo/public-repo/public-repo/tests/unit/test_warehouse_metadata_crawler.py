from unittest.mock import MagicMock

from app.scanners.warehouse_metadata_crawler import (
    BigQueryWarehouseMetadataCrawler,
    DiscoveredColumn,
    DiscoveredTable,
    normalize_bigquery_resource_id,
)


class FakeQueryJob:
    def __init__(self, rows):
        self._rows = rows

    def result(self):
        return self._rows


class FakeBigQueryClient:
    def __init__(self):
        self.queries = []
        self.responses = {
            "INFORMATION_SCHEMA.TABLES": [
                {
                    "table_catalog": "project",
                    "table_schema": "dataset",
                    "table_name": "registered_users",
                    "table_type": "BASE TABLE",
                },
                {
                    "table_catalog": "project",
                    "table_schema": "dataset",
                    "table_name": "new_users",
                    "table_type": "BASE TABLE",
                },
                {
                    "table_catalog": "project",
                    "table_schema": "dataset",
                    "table_name": "drifted_users",
                    "table_type": "VIEW",
                },
                {
                    "table_catalog": "project",
                    "table_schema": "dataset",
                    "table_name": "_internal_tmp",
                    "table_type": "BASE TABLE",
                },
            ],
            "INFORMATION_SCHEMA.COLUMNS": [
                {
                    "table_catalog": "project",
                    "table_schema": "dataset",
                    "table_name": "registered_users",
                    "column_name": "user_id",
                    "data_type": "STRING",
                    "is_nullable": "NO",
                    "ordinal_position": 1,
                },
                {
                    "table_catalog": "project",
                    "table_schema": "dataset",
                    "table_name": "registered_users",
                    "column_name": "email_token",
                    "data_type": "STRING",
                    "is_nullable": "YES",
                    "ordinal_position": 2,
                },
                {
                    "table_catalog": "project",
                    "table_schema": "dataset",
                    "table_name": "new_users",
                    "column_name": "email",
                    "data_type": "STRING",
                    "is_nullable": "YES",
                    "ordinal_position": 1,
                },
                {
                    "table_catalog": "project",
                    "table_schema": "dataset",
                    "table_name": "drifted_users",
                    "column_name": "user_id",
                    "data_type": "STRING",
                    "is_nullable": "NO",
                    "ordinal_position": 1,
                },
                {
                    "table_catalog": "project",
                    "table_schema": "dataset",
                    "table_name": "drifted_users",
                    "column_name": "phone",
                    "data_type": "STRING",
                    "is_nullable": "YES",
                    "ordinal_position": 2,
                },
            ],
        }

    def query(self, query):
        self.queries.append(query)
        if "INFORMATION_SCHEMA.TABLES" in query:
            return FakeQueryJob(self.responses["INFORMATION_SCHEMA.TABLES"])
        if "INFORMATION_SCHEMA.COLUMNS" in query:
            return FakeQueryJob(self.responses["INFORMATION_SCHEMA.COLUMNS"])
        raise AssertionError(f"Unexpected query: {query}")


def registry_response():
    return {
        "resources": [
            {
                "resourceId": "bigquery:project.dataset.registered_users",
                "system": "bigquery",
                "piiFields": [
                    {"name": "user_id", "classification": "TOKENIZED_IDENTIFIER"},
                    {"name": "email_token", "classification": "TOKENIZED_IDENTIFIER"},
                ],
            },
            {
                "resourceId": "bigquery:project.dataset.drifted_users",
                "system": "bigquery",
                "piiFields": [
                    {"name": "user_id", "classification": "TOKENIZED_IDENTIFIER"},
                    {"name": "email_token", "classification": "TOKENIZED_IDENTIFIER"},
                ],
            },
        ],
        "count": 2,
    }


def test_normalizes_bigquery_resource_id():
    assert (
        normalize_bigquery_resource_id("project", "dataset", "table")
        == "bigquery:project.dataset.table"
    )


def test_crawler_fetches_all_bigquery_registry_resources_without_scan_filter():
    vault = MagicMock()
    vault.fetch_pii_registry_resources.return_value = registry_response()

    BigQueryWarehouseMetadataCrawler(
        bigquery_client=FakeBigQueryClient(),
        vault=vault,
        project_id="project",
        dataset_ids=["dataset"],
    ).crawl(emit_lineage=False)

    vault.fetch_pii_registry_resources.assert_called_once_with(system="bigquery")


def test_discovers_tables_using_dataset_scoped_information_schema_and_exclusions():
    bq = FakeBigQueryClient()
    vault = MagicMock()
    vault.fetch_pii_registry_resources.return_value = registry_response()

    crawler = BigQueryWarehouseMetadataCrawler(
        bigquery_client=bq,
        vault=vault,
        project_id="project",
        dataset_ids=["dataset"],
        excluded_table_patterns=["_internal_*"],
    )

    tables = crawler.discover_tables()

    assert [table.table_id for table in tables] == [
        "drifted_users",
        "new_users",
        "registered_users",
    ]
    assert "`project.dataset.INFORMATION_SCHEMA.TABLES`" in bq.queries[0]
    assert "`project.dataset.INFORMATION_SCHEMA.COLUMNS`" in bq.queries[1]


def test_compares_registered_unregistered_and_drifted_tables():
    vault = MagicMock()
    vault.fetch_pii_registry_resources.return_value = registry_response()

    diffs = BigQueryWarehouseMetadataCrawler(
        bigquery_client=FakeBigQueryClient(),
        vault=vault,
        project_id="project",
        dataset_ids=["dataset"],
        excluded_table_patterns=["_internal_*"],
    ).crawl(emit_lineage=False)

    statuses = {diff.resource_id: diff for diff in diffs}
    assert statuses["bigquery:project.dataset.registered_users"].status == "REGISTERED"
    assert statuses["bigquery:project.dataset.new_users"].status == "UNREGISTERED"
    assert [column.name for column in statuses["bigquery:project.dataset.new_users"].new_columns] == ["email"]
    assert statuses["bigquery:project.dataset.drifted_users"].status == "DRIFTED"
    assert [column.name for column in statuses["bigquery:project.dataset.drifted_users"].new_columns] == ["phone"]
    assert statuses["bigquery:project.dataset.drifted_users"].missing_registry_columns == ["email_token"]


def test_emit_metadata_lineage_uses_unknown_user_and_no_raw_sample_values():
    vault = MagicMock()
    crawler = BigQueryWarehouseMetadataCrawler(
        bigquery_client=FakeBigQueryClient(),
        vault=vault,
        project_id="project",
        dataset_ids=["dataset"],
    )
    table = DiscoveredTable(
        resource_id="bigquery:project.dataset.new_users",
        project_id="project",
        dataset_id="dataset",
        table_id="new_users",
        table_type="BASE TABLE",
        columns=[
            DiscoveredColumn(name="email", data_type="STRING"),
            DiscoveredColumn(name="phone", data_type="STRING"),
        ],
    )
    diff = crawler.compare_table_to_registry(
        table,
        registry=MagicMock(get=MagicMock(side_effect=KeyError("missing"))),
    )

    crawler.emit_metadata_lineage(table, diff)

    call = vault.report_lineage.call_args
    assert call.kwargs["event_type"] == "WAREHOUSE_METADATA_DISCOVERED"
    assert call.kwargs["user_id"] == "UNKNOWN"
    assert call.kwargs["source"] == "bigquery_metadata_crawler"
    assert call.kwargs["destination"] == "bigquery:project.dataset.new_users"
    assert call.kwargs["data_classification"] == "METADATA"
    assert call.kwargs["metadata"] == {
        "resource_id": "bigquery:project.dataset.new_users",
        "system": "bigquery",
        "project_id": "project",
        "dataset_id": "dataset",
        "table_id": "new_users",
        "table_type": "BASE TABLE",
        "registry_status": "UNREGISTERED",
        "column_count": 2,
        "new_columns": ["email", "phone"],
        "missing_registry_columns": [],
        "recommended_action": "register_resource_or_exclude_dataset",
    }
    assert "leaked@example.com" not in str(call.kwargs)

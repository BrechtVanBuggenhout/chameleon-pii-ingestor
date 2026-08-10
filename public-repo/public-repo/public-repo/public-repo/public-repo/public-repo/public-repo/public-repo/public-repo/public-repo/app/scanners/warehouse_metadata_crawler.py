import fnmatch
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Literal, Optional

from app.policies.pii_registry import PiiMetadataRegistry
from app.services.vault_client import VaultClient


RegistryStatus = Literal["REGISTERED", "UNREGISTERED", "DRIFTED"]


@dataclass(frozen=True)
class DiscoveredColumn:
    name: str
    data_type: str
    mode: Optional[str] = None
    ordinal_position: Optional[int] = None


@dataclass(frozen=True)
class DiscoveredTable:
    resource_id: str
    project_id: str
    dataset_id: str
    table_id: str
    table_type: str
    columns: List[DiscoveredColumn] = field(default_factory=list)


@dataclass(frozen=True)
class RegistryDiff:
    resource_id: str
    status: RegistryStatus
    new_columns: List[DiscoveredColumn] = field(default_factory=list)
    missing_registry_columns: List[str] = field(default_factory=list)
    type_changes: List[Dict[str, str]] = field(default_factory=list)


def normalize_bigquery_resource_id(project_id: str, dataset_id: str, table_id: str) -> str:
    return f"bigquery:{project_id}.{dataset_id}.{table_id}"


class BigQueryWarehouseMetadataCrawler:
    def __init__(
        self,
        bigquery_client: Any,
        vault: VaultClient,
        project_id: str,
        dataset_ids: Iterable[str],
        excluded_table_patterns: Optional[Iterable[str]] = None,
    ):
        self.bigquery_client = bigquery_client
        self.vault = vault
        self.project_id = project_id
        self.dataset_ids = [dataset_id.strip() for dataset_id in dataset_ids if dataset_id.strip()]
        self.excluded_table_patterns = [
            pattern.strip()
            for pattern in (excluded_table_patterns or [])
            if pattern and pattern.strip()
        ]

    @classmethod
    def from_vault(
        cls,
        bigquery_client: Any,
        vault: VaultClient,
        project_id: str,
        dataset_ids: Iterable[str],
        excluded_table_patterns: Optional[Iterable[str]] = None,
    ) -> "BigQueryWarehouseMetadataCrawler":
        return cls(
            bigquery_client=bigquery_client,
            vault=vault,
            project_id=project_id,
            dataset_ids=dataset_ids,
            excluded_table_patterns=excluded_table_patterns,
        )

    def crawl(self, emit_lineage: bool = True) -> List[RegistryDiff]:
        registry = PiiMetadataRegistry.from_api_response(
            self.vault.fetch_pii_registry_resources(system="bigquery")
        )
        tables = self.discover_tables()
        diffs = [self.compare_table_to_registry(table, registry) for table in tables]

        if emit_lineage:
            for table, diff in zip(tables, diffs):
                self.emit_metadata_lineage(table, diff)

        return diffs

    def discover_tables(self) -> List[DiscoveredTable]:
        discovered: List[DiscoveredTable] = []
        for dataset_id in self.dataset_ids:
            tables_by_name = self._fetch_dataset_tables(dataset_id)
            columns_by_table = self._fetch_dataset_columns(dataset_id)
            for table_id in sorted(tables_by_name):
                if self._is_excluded_table(dataset_id, table_id):
                    continue
                table_row = tables_by_name[table_id]
                discovered.append(
                    DiscoveredTable(
                        resource_id=normalize_bigquery_resource_id(
                            table_row["table_catalog"],
                            table_row["table_schema"],
                            table_row["table_name"],
                        ),
                        project_id=table_row["table_catalog"],
                        dataset_id=table_row["table_schema"],
                        table_id=table_row["table_name"],
                        table_type=table_row["table_type"],
                        columns=columns_by_table.get(table_id, []),
                    )
                )
        return discovered

    def compare_table_to_registry(
        self,
        table: DiscoveredTable,
        registry: PiiMetadataRegistry,
    ) -> RegistryDiff:
        try:
            resource = registry.get(table.resource_id)
        except KeyError:
            return RegistryDiff(
                resource_id=table.resource_id,
                status="UNREGISTERED",
                new_columns=table.columns,
            )

        registry_columns = set(resource.column_names())
        discovered_columns = {column.name for column in table.columns}
        new_columns = [column for column in table.columns if column.name not in registry_columns]
        missing_registry_columns = sorted(registry_columns - discovered_columns)

        if new_columns or missing_registry_columns:
            return RegistryDiff(
                resource_id=table.resource_id,
                status="DRIFTED",
                new_columns=new_columns,
                missing_registry_columns=missing_registry_columns,
            )
        return RegistryDiff(resource_id=table.resource_id, status="REGISTERED")

    def emit_metadata_lineage(self, table: DiscoveredTable, diff: RegistryDiff) -> None:
        metadata = {
            "resource_id": table.resource_id,
            "system": "bigquery",
            "project_id": table.project_id,
            "dataset_id": table.dataset_id,
            "table_id": table.table_id,
            "table_type": table.table_type,
            "registry_status": diff.status,
            "column_count": len(table.columns),
            "new_columns": [column.name for column in diff.new_columns],
            "missing_registry_columns": diff.missing_registry_columns,
            "recommended_action": self._recommended_action(diff),
        }
        self.vault.report_lineage(
            event_type="WAREHOUSE_METADATA_DISCOVERED",
            user_id="UNKNOWN",
            source="bigquery_metadata_crawler",
            destination=table.resource_id,
            operation_id=f"metadata-crawl:{table.project_id}.{table.dataset_id}.{table.table_id}",
            metadata=metadata,
            data_classification="METADATA",
        )

    def _fetch_dataset_tables(self, dataset_id: str) -> Dict[str, Dict[str, Any]]:
        query = f"""
SELECT
  table_catalog,
  table_schema,
  table_name,
  table_type,
  creation_time
FROM `{self.project_id}.{dataset_id}.INFORMATION_SCHEMA.TABLES`
WHERE table_type IN ('BASE TABLE', 'VIEW')
"""
        rows = [dict(row) for row in self.bigquery_client.query(query).result()]
        return {row["table_name"]: row for row in rows}

    def _fetch_dataset_columns(self, dataset_id: str) -> Dict[str, List[DiscoveredColumn]]:
        query = f"""
SELECT
  table_catalog,
  table_schema,
  table_name,
  column_name,
  data_type,
  is_nullable,
  ordinal_position
FROM `{self.project_id}.{dataset_id}.INFORMATION_SCHEMA.COLUMNS`
ORDER BY table_schema, table_name, ordinal_position
"""
        columns_by_table: Dict[str, List[DiscoveredColumn]] = {}
        for row in self.bigquery_client.query(query).result():
            data = dict(row)
            table_columns = columns_by_table.setdefault(data["table_name"], [])
            table_columns.append(
                DiscoveredColumn(
                    name=data["column_name"],
                    data_type=data["data_type"],
                    mode="NULLABLE" if data.get("is_nullable") == "YES" else "REQUIRED",
                    ordinal_position=data.get("ordinal_position"),
                )
            )
        return columns_by_table

    def _is_excluded_table(self, dataset_id: str, table_id: str) -> bool:
        qualified_table = f"{dataset_id}.{table_id}"
        return any(
            fnmatch.fnmatch(table_id, pattern)
            or fnmatch.fnmatch(qualified_table, pattern)
            for pattern in self.excluded_table_patterns
        )

    def _recommended_action(self, diff: RegistryDiff) -> str:
        if diff.status == "UNREGISTERED":
            return "register_resource_or_exclude_dataset"
        if diff.status == "DRIFTED":
            return "review_registry_column_drift"
        return "none"

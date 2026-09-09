from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Tuple

from app.services.vault_client import VaultClient


@dataclass(frozen=True)
class DbtDiscoveredField:
    field_name: str
    classification: str
    confidence: str
    detection_method: str


@dataclass
class DbtDiscoveredResource:
    resource_id: str
    project_id: str
    dataset_id: str
    table_id: str
    fields: List[DbtDiscoveredField] = field(default_factory=list)


class DbtPiiDiscoveryPublisher:
    """
    Publishes the chameleon_pii dbt package's pii_discovery findings (undeclared,
    name-inferred PII columns) into the same WAREHOUSE_METADATA_DISCOVERED lineage
    event stream BigQueryWarehouseMetadataCrawler already writes to, so a finding
    like an undeclared `username` column shows up in the console's existing
    "declare this" work queue (GET /pii-registry/discovery) live -- instead of
    only reaching the console once Key Vault's boot-time dbt-registry pull
    (BigQueryPiiRegistryRepository) happens to catch up on a redeploy/restart.

    pii_discovery already excludes anything declared via meta.pii (see
    chameleon-pii-dbt/models/discovery/pii_discovery.sql) -- every row read here
    is, by construction, an undeclared/unconfirmed finding, so unlike the
    warehouse crawler (which has to diff discovered columns against the live
    registry itself, since it has no PII-name awareness) no registry
    cross-reference is needed on this side.

    dbt's resource_id format (`bigquery:{project}.{dataset}.{table}`, built in
    pii_discovery.sql) already matches
    warehouse_metadata_crawler.normalize_bigquery_resource_id's output, so it's
    used as-is for `destination` -- the console's discovery feed and the
    boot-time registry pull resolve to the same resource either way.

    Run after `dbt build` finishes -- this reads pii_discovery's *output*, it
    does not invoke dbt itself.
    """

    def __init__(
        self,
        bigquery_client: Any,
        vault: VaultClient,
        pii_discovery_locations: Iterable[str],
    ):
        """
        pii_discovery_locations: "project.dataset" entries naming every place a
        chameleon_pii `pii_discovery` table might have been built -- typically one
        per dbt target/environment that runs the package. A bare "dataset" entry
        (no dot) resolves against bigquery_client.project, mirroring
        chameleon_pii's own pii_split_dataset() convention on the dbt side.
        """
        self.bigquery_client = bigquery_client
        self.vault = vault
        self.pii_discovery_locations = [loc.strip() for loc in pii_discovery_locations if loc and loc.strip()]

    def publish(self) -> List[DbtDiscoveredResource]:
        resources = self.discover_resources()
        for resource in resources:
            self._emit(resource)
        return resources

    def discover_resources(self) -> List[DbtDiscoveredResource]:
        by_resource: Dict[str, DbtDiscoveredResource] = {}
        for location in self.pii_discovery_locations:
            project_id, dataset_id = self._split_location(location)
            for row in self._fetch_pii_discovery(project_id, dataset_id):
                resource_id = row["resource_id"]
                new_field = DbtDiscoveredField(
                    field_name=row["field_name"],
                    classification=row["classification"],
                    confidence=row.get("confidence") or "INFERRED_HIGH",
                    detection_method=row.get("detection_method") or "INFORMATION_SCHEMA",
                )
                existing = by_resource.get(resource_id)
                if existing:
                    existing.fields.append(new_field)
                else:
                    by_resource[resource_id] = DbtDiscoveredResource(
                        resource_id=resource_id,
                        project_id=row.get("table_catalog") or project_id,
                        dataset_id=row["table_schema"],
                        table_id=row["table_name"],
                        fields=[new_field],
                    )
        return list(by_resource.values())

    def _split_location(self, location: str) -> Tuple[str, str]:
        if "." in location:
            project_id, dataset_id = location.split(".", 1)
            return project_id, dataset_id
        return self.bigquery_client.project, location

    def _fetch_pii_discovery(self, project_id: str, dataset_id: str) -> List[Dict[str, Any]]:
        query = f"""
SELECT resource_id, table_catalog, table_schema, table_name, field_name, classification, confidence, detection_method
FROM `{project_id}.{dataset_id}.pii_discovery`
"""
        try:
            return [dict(row) for row in self.bigquery_client.query(query).result()]
        except Exception:
            # pii_discovery not built at this location yet, or the table doesn't
            # exist there (wrong location configured, or pii_discovery_enabled:
            # false on the dbt side) -- not an error worth failing the whole
            # publish run over; other configured locations still get published.
            return []

    def _emit(self, resource: DbtDiscoveredResource) -> None:
        metadata = {
            "resource_id": resource.resource_id,
            "system": "bigquery",
            "project_id": resource.project_id,
            "dataset_id": resource.dataset_id,
            "table_id": resource.table_id,
            "registry_status": "UNREGISTERED",
            "new_columns": [f.field_name for f in resource.fields],
            "classifications": {f.field_name: f.classification for f in resource.fields},
            "recommended_action": "declare_in_dbt_meta_pii_or_console",
        }
        self.vault.report_lineage(
            event_type="WAREHOUSE_METADATA_DISCOVERED",
            user_id="UNKNOWN",
            source="chameleon_pii_dbt_discovery",
            destination=resource.resource_id,
            operation_id=f"dbt-pii-discovery:{resource.resource_id}",
            metadata=metadata,
            data_classification="METADATA",
        )

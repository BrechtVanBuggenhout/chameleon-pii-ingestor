import logging
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional

from app.policies.pii_registry import PiiMetadataRegistry, RegistryResource
from app.services.vault_client import VaultClient


EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PHONE_RE = re.compile(r"^\+?[0-9][0-9 .()\-]{6,}[0-9]$")
NAME_RE = re.compile(r"^[A-Z][a-z]+(?:[ '-][A-Z][a-z]+)+$")


@dataclass(frozen=True)
class GhostFinding:
    resource_id: str
    column: str
    pattern: str
    sample_count: int


class BigQueryGhostDataScanner:
    def __init__(
        self,
        bigquery_client: Any,
        registry: PiiMetadataRegistry,
        vault: VaultClient,
        sample_limit: int = 1000,
    ):
        self.bigquery_client = bigquery_client
        self.registry = registry
        self.vault = vault
        self.sample_limit = sample_limit
        self.logger = logging.getLogger(__name__)

    def scan(self, resource_ids: Optional[Iterable[str]] = None) -> List[GhostFinding]:
        resources = self._resources(resource_ids)
        findings: List[GhostFinding] = []

        for resource in resources:
            rows = self._sample_rows(resource)
            resource_findings = self._find_ghost_data(resource, rows)
            findings.extend(resource_findings)
            for finding in resource_findings:
                self._emit_finding(finding)

        return findings

    @classmethod
    def from_vault(
        cls,
        bigquery_client: Any,
        vault: VaultClient,
        sample_limit: int = 1000,
    ) -> "BigQueryGhostDataScanner":
        registry = PiiMetadataRegistry.from_api_response(
            vault.fetch_pii_registry_resources(system="bigquery", scan_enabled=True)
        )
        return cls(
            bigquery_client=bigquery_client,
            registry=registry,
            vault=vault,
            sample_limit=sample_limit,
        )

    def _resources(self, resource_ids: Optional[Iterable[str]]) -> List[RegistryResource]:
        if resource_ids is None:
            scan_resources = self.registry.scan_enabled_resources(system="bigquery")
            return scan_resources or self.registry.resources_by_type("bigquery_table")
        return [self.registry.get(resource_id) for resource_id in resource_ids]

    def _sample_rows(self, resource: RegistryResource) -> List[Dict[str, Any]]:
        table_ref = resource.id.removeprefix("bigquery:")
        query = f"SELECT * FROM `{table_ref}`"
        if resource.ghost_data_scan.scan_mode != "FULL":
            query = f"{query} LIMIT {int(self.sample_limit)}"
        return [dict(row) for row in self.bigquery_client.query(query).result()]

    def _find_ghost_data(self, resource: RegistryResource, rows: List[Dict[str, Any]]) -> List[GhostFinding]:
        columns = sorted({key for row in rows for key in row})
        direct_identifier_columns = {column.name for column in resource.direct_identifier_columns}
        scope_columns = {resource.tenant_id_column, resource.user_id_column}
        allowed_columns = set(resource.allowed_direct_identifiers) | {column for column in scope_columns if column}
        enabled_patterns = set(resource.ghost_data_scan.patterns or [])
        counts: Dict[tuple[str, str], int] = {}

        for row in rows:
            for column in columns:
                if column in direct_identifier_columns or column in allowed_columns:
                    continue
                value = row.get(column)
                pattern = self._classify_value(value)
                if pattern and enabled_patterns and pattern not in enabled_patterns:
                    continue
                if pattern:
                    counts[(column, pattern)] = counts.get((column, pattern), 0) + 1

        return [
            GhostFinding(
                resource_id=resource.id,
                column=column,
                pattern=pattern,
                sample_count=sample_count,
            )
            for (column, pattern), sample_count in sorted(counts.items())
        ]

    def _classify_value(self, value: Any) -> Optional[str]:
        if not isinstance(value, str):
            return None
        stripped = value.strip()
        if EMAIL_RE.match(stripped):
            return "EMAIL"
        if PHONE_RE.match(stripped):
            return "PHONE"
        if NAME_RE.match(stripped):
            return "NAME"
        return None

    def _emit_finding(self, finding: GhostFinding) -> None:
        resource = self.registry.get(finding.resource_id)
        metadata = {
            "resource_id": finding.resource_id,
            "system": resource.system,
            "column": finding.column,
            "pattern": finding.pattern,
            "count": finding.sample_count,
            "confidence": "PATTERN_MATCH",
            "scanner": "bigquery_ghost_data_scanner",
            "recommended_action": "declare_in_pii_registry_or_remove_from_resource",
        }
        self.vault.report_lineage(
            event_type="GHOST_DATA_DETECTED",
            user_id="UNKNOWN",
            source="bigquery_ghost_data_scanner",
            destination=resource.lineage_destination or finding.resource_id,
            operation_id=f"ghost-scan:{finding.resource_id}",
            metadata=metadata,
            data_classification="GHOST_DATA",
        )

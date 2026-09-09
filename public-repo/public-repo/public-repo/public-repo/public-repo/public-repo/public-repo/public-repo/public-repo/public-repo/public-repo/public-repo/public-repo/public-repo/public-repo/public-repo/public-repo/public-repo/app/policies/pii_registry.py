import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


@dataclass(frozen=True)
class GhostDataScanConfig:
    enabled: bool = False
    scan_mode: str = "SAMPLED"
    patterns: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> "GhostDataScanConfig":
        data = data or {}
        return cls(
            enabled=bool(data.get("enabled", False)),
            scan_mode=(data.get("scanMode") or data.get("scan_mode") or "SAMPLED").upper(),
            patterns=list(data.get("patterns", [])),
        )


@dataclass(frozen=True)
class RegistryColumn:
    name: str
    classification: str
    identifier_type: Optional[str] = None
    allowed_in_mart: bool = False
    handling: Optional[str] = None
    required_in_mart: bool = False
    evidence: List[str] = field(default_factory=list)
    confidence: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RegistryColumn":
        return cls(
            name=data["name"],
            classification=data["classification"],
            identifier_type=data.get("identifierType") or data.get("identifier_type"),
            allowed_in_mart=bool(data.get("allowedInMart", data.get("allowed_in_mart", False))),
            handling=data.get("handling"),
            required_in_mart=bool(data.get("requiredInMart", data.get("required_in_mart", False))),
            evidence=list(data.get("evidence", [])),
            confidence=data.get("confidence"),
        )


@dataclass(frozen=True)
class RegistryResource:
    id: str
    type: str
    tenant_scoped: bool
    tenant_id_column: Optional[str]
    allowed_direct_identifiers: List[str]
    columns: List[RegistryColumn]
    user_id_column: Optional[str] = None
    system: Optional[str] = None
    owner_connector: Optional[str] = None
    lineage_destination: Optional[str] = None
    deletion_strategy: Optional[str] = None
    handling_policy: Optional[str] = None
    evidence_pointers: List[str] = field(default_factory=list)
    ghost_data_scan: GhostDataScanConfig = field(default_factory=GhostDataScanConfig)
    registry_version: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RegistryResource":
        system = data.get("system")
        resource_id = data.get("resourceId") or data.get("resource_id") or data["id"]
        resource_type = data.get("type") or cls._type_from_resource(resource_id, system)
        columns_data = data.get("columns")
        if columns_data is None:
            columns_data = data.get("piiFields", data.get("pii_fields", []))
        tenant_id_column = data.get("tenantIdColumn") or data.get("tenant_id_column")
        user_id_column = data.get("userIdColumn") or data.get("user_id_column")
        return cls(
            id=resource_id,
            type=resource_type,
            tenant_scoped=bool(data.get("tenantScoped", data.get("tenant_scoped", bool(tenant_id_column)))),
            tenant_id_column=tenant_id_column,
            user_id_column=user_id_column,
            allowed_direct_identifiers=list(
                data.get("allowedDirectIdentifiers", data.get("allowed_direct_identifiers", []))
            ),
            columns=[RegistryColumn.from_dict(column) for column in columns_data],
            system=system or cls._system_from_resource(resource_id),
            owner_connector=data.get("ownerConnector") or data.get("owner_connector"),
            lineage_destination=data.get("lineageDestination") or data.get("lineage_destination"),
            deletion_strategy=data.get("deletionStrategy") or data.get("deletion_strategy"),
            handling_policy=data.get("handlingPolicy") or data.get("handling_policy"),
            evidence_pointers=list(data.get("evidencePointers", data.get("evidence_pointers", []))),
            ghost_data_scan=GhostDataScanConfig.from_dict(
                data.get("ghostDataScan") or data.get("ghost_data_scan")
            ),
            registry_version=data.get("registryVersion") or data.get("registry_version"),
        )

    @staticmethod
    def _system_from_resource(resource_id: str) -> Optional[str]:
        if ":" not in resource_id:
            return None
        return resource_id.split(":", 1)[0]

    @staticmethod
    def _type_from_resource(resource_id: str, system: Optional[str]) -> str:
        resolved_system = system or RegistryResource._system_from_resource(resource_id)
        if resolved_system == "bigquery":
            return "bigquery_table"
        if resolved_system == "gcs":
            return "gcs_prefix"
        return resolved_system or "external"

    @property
    def direct_identifier_columns(self) -> List[RegistryColumn]:
        return [column for column in self.columns if column.classification == "DIRECT_IDENTIFIER"]

    def column_names(self) -> List[str]:
        return [column.name for column in self.columns]


class PiiMetadataRegistry:
    def __init__(self, version: int | str, resources: Iterable[RegistryResource]):
        self.version = version
        self.resources = list(resources)

    @classmethod
    def load(cls, path: str | Path) -> "PiiMetadataRegistry":
        with Path(path).open(encoding="utf-8") as registry_file:
            data = json.load(registry_file)
        return cls(
            version=int(data["version"]),
            resources=[RegistryResource.from_dict(resource) for resource in data.get("resources", [])],
        )

    @classmethod
    def from_api_response(cls, data: Dict[str, Any]) -> "PiiMetadataRegistry":
        resources = [RegistryResource.from_dict(resource) for resource in data.get("resources", [])]
        version = next((resource.registry_version for resource in resources if resource.registry_version), 0)
        return cls(version=version, resources=resources)

    def resources_by_type(self, resource_type: str) -> List[RegistryResource]:
        return [resource for resource in self.resources if resource.type == resource_type]

    def resources_by_system(self, system: str) -> List[RegistryResource]:
        return [resource for resource in self.resources if resource.system == system]

    def scan_enabled_resources(self, system: Optional[str] = None) -> List[RegistryResource]:
        return [
            resource
            for resource in self.resources
            if resource.ghost_data_scan
            and resource.ghost_data_scan.enabled
            and (system is None or resource.system == system)
        ]

    def get(self, resource_id: str) -> RegistryResource:
        for resource in self.resources:
            if resource.id == resource_id:
                return resource
        raise KeyError(f"Registry resource not found: {resource_id}")

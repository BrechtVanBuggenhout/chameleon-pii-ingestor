from dataclasses import dataclass
from typing import Any, Dict, Iterable, List

from app.policies.pii_registry import PiiMetadataRegistry, RegistryResource
from app.services.vault_client import VaultClient


@dataclass(frozen=True)
class PolicyViolation:
    model_name: str
    rule: str
    message: str


class DbtPolicyValidator:
    def __init__(self, registry: PiiMetadataRegistry):
        self.registry = registry

    @classmethod
    def from_vault(cls, vault: VaultClient) -> "DbtPolicyValidator":
        registry = PiiMetadataRegistry.from_api_response(vault.fetch_pii_registry_resources(system="bigquery"))
        return cls(registry)

    @staticmethod
    def control_plane_policy_status(vault: VaultClient) -> Dict[str, Any]:
        return vault.fetch_pii_registry_policy()

    def validate_manifest(self, manifest: Dict[str, Any]) -> List[PolicyViolation]:
        violations: List[PolicyViolation] = []
        for node in manifest.get("nodes", {}).values():
            if node.get("resource_type") != "model":
                continue
            resource = self._registry_resource_for_node(node)
            if not resource:
                continue
            columns = self._node_columns(node)
            violations.extend(self._validate_tenant_scope(node, resource, columns))
            violations.extend(self._validate_crypto_shred_scope(node, resource, columns))
            violations.extend(self._validate_direct_identifiers(node, resource, columns))
        return violations

    def _registry_resource_for_node(self, node: Dict[str, Any]) -> RegistryResource | None:
        candidates = set(self._resource_candidates(node))
        for resource in self.registry.resources_by_type("bigquery_table"):
            if resource.id in candidates:
                return resource
        return None

    def _resource_candidates(self, node: Dict[str, Any]) -> Iterable[str]:
        database = node.get("database")
        schema = node.get("schema")
        alias = node.get("alias") or node.get("name")
        if database and schema and alias:
            yield f"bigquery:{database}.{schema}.{alias}"
        if database and schema:
            yield f"bigquery:{database}.{schema}"
        if schema and alias:
            yield f"bigquery:{schema}.{alias}"

    def _node_columns(self, node: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        return {
            name: column
            for name, column in (node.get("columns") or {}).items()
        }

    def _validate_tenant_scope(
        self,
        node: Dict[str, Any],
        resource: RegistryResource,
        columns: Dict[str, Dict[str, Any]],
    ) -> List[PolicyViolation]:
        if not resource.tenant_scoped:
            return []
        if resource.tenant_id_column and resource.tenant_id_column in columns:
            return []
        return [
            PolicyViolation(
                model_name=node.get("name", "<unknown>"),
                rule="tenant_id_required",
                message=f"{resource.id} is tenant-scoped but model lacks {resource.tenant_id_column or 'tenant_id'}",
            )
        ]

    def _validate_crypto_shred_scope(
        self,
        node: Dict[str, Any],
        resource: RegistryResource,
        columns: Dict[str, Dict[str, Any]],
    ) -> List[PolicyViolation]:
        if resource.deletion_strategy != "CRYPTO_SHRED":
            return []
        if resource.user_id_column and resource.user_id_column in columns:
            return []
        if self._has_user_scope_exception(resource):
            return []
        return [
            PolicyViolation(
                model_name=node.get("name", "<unknown>"),
                rule="user_scope_required",
                message=f"{resource.id} uses CRYPTO_SHRED but model lacks {resource.user_id_column or 'user_id'}",
            )
        ]

    def _has_user_scope_exception(self, resource: RegistryResource) -> bool:
        handling_policy = (resource.handling_policy or "").lower()
        if "exception" in handling_policy:
            return True
        return any(pointer.startswith("exception:") for pointer in resource.evidence_pointers or [])

    def _validate_direct_identifiers(
        self,
        node: Dict[str, Any],
        resource: RegistryResource,
        columns: Dict[str, Dict[str, Any]],
    ) -> List[PolicyViolation]:
        if not self._is_mart_model(node):
            return []

        violations: List[PolicyViolation] = []
        for column in resource.direct_identifier_columns:
            if column.name not in columns or column.allowed_in_mart:
                continue
            violations.append(
                PolicyViolation(
                    model_name=node.get("name", "<unknown>"),
                    rule="direct_identifier_in_mart",
                    message=f"mart model exposes direct identifier column {column.name} from {resource.id}",
                )
            )
        return violations

    def _is_mart_model(self, node: Dict[str, Any]) -> bool:
        name = node.get("name", "")
        path = node.get("path", "")
        fqn = ".".join(node.get("fqn", []))
        return any(
            part.startswith("mart") or ".mart" in part or "/mart" in part
            for part in (name, path, fqn)
        )

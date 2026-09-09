import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.policies.dbt_policy import DbtPolicyValidator
from app.policies.pii_registry import PiiMetadataRegistry, RegistryResource
from app.services.vault_client import VaultClient


@dataclass(frozen=True)
class RegistryCheck:
    status: str
    model_name: str
    rule: str
    message: str


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Compare dbt manifest policy metadata with Key Vault PII registry.")
    parser.add_argument("--vault-url", default="http://localhost:8080")
    parser.add_argument("--tenant-id", default="default")
    parser.add_argument("--manifest", default="target/manifest.json")
    return parser


def load_manifest(path: str) -> Dict[str, Any]:
    manifest_path = Path(path)
    if not manifest_path.exists():
        raise FileNotFoundError(
            f"dbt manifest not found at {path}. Run dbt compile/build first or pass --manifest."
        )
    return json.loads(manifest_path.read_text())


def model_nodes(manifest: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
    for node in manifest.get("nodes", {}).values():
        if node.get("resource_type") == "model":
            yield node


def resource_candidates(node: Dict[str, Any]) -> List[str]:
    database = node.get("database")
    schema = node.get("schema")
    alias = node.get("alias") or node.get("name")
    candidates = []
    if database and schema and alias:
        candidates.append(f"bigquery:{database}.{schema}.{alias}")
    if database and schema:
        candidates.append(f"bigquery:{database}.{schema}")
    if schema and alias:
        candidates.append(f"bigquery:{schema}.{alias}")
    return candidates


def find_resource(registry: PiiMetadataRegistry, node: Dict[str, Any]) -> Optional[RegistryResource]:
    candidates = set(resource_candidates(node))
    for resource in registry.resources_by_type("bigquery_table"):
        if resource.id in candidates:
            return resource
    return None


def chameleon_meta(node: Dict[str, Any]) -> Dict[str, Any]:
    return (node.get("meta") or {}).get("chameleon") or {}


def check_manifest(manifest: Dict[str, Any], registry: PiiMetadataRegistry) -> List[RegistryCheck]:
    checks: List[RegistryCheck] = []
    validator = DbtPolicyValidator(registry)

    for node in model_nodes(manifest):
        model_name = node.get("name", "<unknown>")
        resource = find_resource(registry, node)
        if not resource:
            checks.append(
                RegistryCheck(
                    status="FAIL",
                    model_name=model_name,
                    rule="missing_registry_resource",
                    message=f"No Key Vault registry resource matches {resource_candidates(node)}",
                )
            )
            continue

        meta = chameleon_meta(node)
        manual_review_required = (
            resource.deletion_strategy == "MANUAL_REVIEW"
            or "manual" in (resource.handling_policy or "").lower()
        )
        if manual_review_required and not meta.get("mart_manual_review_approved"):
            checks.append(
                RegistryCheck(
                    status="WARN",
                    model_name=model_name,
                    rule="manual_review_required",
                    message=f"{resource.id} requires manual review before automated compliance can be claimed",
                )
            )

    for violation in validator.validate_manifest(manifest):
        checks.append(
            RegistryCheck(
                status="FAIL",
                model_name=violation.model_name,
                rule=violation.rule,
                message=violation.message,
            )
        )

    return checks


def run_dbt_registry_smoke(
    args: argparse.Namespace,
    vault_factory: Callable[..., Any] = VaultClient,
    manifest_loader: Callable[[str], Dict[str, Any]] = load_manifest,
) -> Dict[str, Any]:
    manifest = manifest_loader(args.manifest)
    vault = vault_factory(base_url=args.vault_url, tenant_id=args.tenant_id)
    try:
        registry = PiiMetadataRegistry.from_api_response(
            vault.fetch_pii_registry_resources(system="bigquery")
        )
        checks = check_manifest(manifest, registry)
        status = "FAIL" if any(check.status == "FAIL" for check in checks) else "WARN" if checks else "PASS"

        print(f"Manifest: {args.manifest}")
        print(f"Registry resources: {len(registry.resources_by_type('bigquery_table'))}")
        print(f"dbt registry status: {status}")
        if checks:
            for check in checks:
                print(f"{check.status} {check.model_name} {check.rule}: {check.message}")
        else:
            print("PASS dbt manifest matches Key Vault registry policy")

        return {"status": status, "checks": checks}
    finally:
        shutdown = getattr(vault, "shutdown", None)
        if callable(shutdown):
            shutdown()


def main() -> int:
    args = build_parser().parse_args()
    result = run_dbt_registry_smoke(args)
    return 1 if result["status"] == "FAIL" else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"\ndbt registry smoke failed: {exc}", file=sys.stderr)
        raise SystemExit(1)

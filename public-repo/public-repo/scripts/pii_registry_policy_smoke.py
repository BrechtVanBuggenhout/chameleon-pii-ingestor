import argparse
import sys
from pathlib import Path
from typing import Any, Callable, Dict

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.services.vault_client import VaultClient


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Print Key Vault PII registry policy status.")
    parser.add_argument("--vault-url", default="http://localhost:8080")
    parser.add_argument("--tenant-id", default="default")
    return parser


def format_issue(issue: Dict[str, Any]) -> str:
    code = issue.get("code", "<missing-code>")
    field = issue.get("field")
    severity = issue.get("severity", "INFO")
    message = issue.get("message", "")
    field_part = f" field={field}" if field else ""
    return f"  - {severity} {code}{field_part}: {message}"


def run_policy_smoke(
    args: argparse.Namespace,
    vault_factory: Callable[..., Any] = VaultClient,
) -> Dict[str, Any]:
    vault = vault_factory(base_url=args.vault_url, tenant_id=args.tenant_id)
    try:
        policy = vault.fetch_pii_registry_policy()
        print(f"Vault URL: {args.vault_url.rstrip('/')}")
        print(f"Policy status: {policy.get('status', '<missing>')}")
        for evaluation in policy.get("evaluations", []):
            status = evaluation.get("status", "<missing>")
            resource_id = evaluation.get("resourceId") or evaluation.get("resource_id") or "<missing-resource>"
            print(f"{status} {resource_id}")
            for issue in evaluation.get("issues", []):
                print(format_issue(issue))
        return policy
    finally:
        shutdown = getattr(vault, "shutdown", None)
        if callable(shutdown):
            shutdown()


def main() -> int:
    args = build_parser().parse_args()
    policy = run_policy_smoke(args)
    return 1 if policy.get("status") == "FAIL" else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"\nPII registry policy smoke failed: {exc}", file=sys.stderr)
        raise SystemExit(1)

import argparse
import sys
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from google.api_core.exceptions import NotFound
from google.cloud import bigquery

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.policies.dbt_policy import DbtPolicyValidator
from app.policies.pii_registry import PiiMetadataRegistry
from app.scanners.ghost_data_scanner import BigQueryGhostDataScanner
from app.services.vault_client import VaultClient


CANARY_TABLE = "your-gcp-project-id.chameleon.raw_users"
CANARY_OPERATION_ID = "ghost-canary-2026-06-20"
CANARY_EMAIL = "ghost.canary@example.test"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Smoke test the Key Vault PII registry control-plane bridge.")
    parser.add_argument("--vault-url", default="http://localhost:8080")
    parser.add_argument("--tenant-id", default="default")
    parser.add_argument("--system", default="bigquery")
    parser.add_argument("--owner-connector")
    parser.add_argument(
        "--scan-enabled",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Filter registry resources by ghost scan enablement.",
    )
    parser.add_argument(
        "--run-scan",
        action="store_true",
        help="Run the BigQuery ghost scanner for returned resources and emit GHOST_DATA lineage.",
    )
    parser.add_argument("--sample-limit", type=int, default=1000)
    parser.add_argument(
        "--skip-missing-tables",
        action="store_true",
        help="Continue when a registry-scoped BigQuery table has not been created yet.",
    )
    parser.add_argument(
        "--project-id",
        help="BigQuery project for --run-scan. Defaults to application credentials project.",
    )
    parser.add_argument(
        "--seed-canary",
        action="store_true",
        help="Insert a synthetic ghost-data row into the raw ingestion table before dbt materializes stg_users.",
    )
    parser.add_argument(
        "--cleanup-canary",
        action="store_true",
        help="Delete synthetic rows created with the fixed canary operation ID.",
    )
    parser.add_argument(
        "--canary-table",
        default=CANARY_TABLE,
        help="Fully qualified BigQuery table for canary seed/cleanup. Defaults to raw_users.",
    )
    return parser


def seed_canary_row(bq_client: Any, table_id: str = CANARY_TABLE) -> None:
    query = f"""
INSERT INTO `{table_id}` (
  user_id,
  tenant_id,
  email_token,
  encryption_version,
  key_id,
  data_hash,
  operation_id,
  source_system,
  ingested_at
)
VALUES (
  'ghost-canary-user',
  'default',
  @canary_email,
  'test',
  'ghost-canary-key',
  'ghost-canary-hash',
  @operation_id,
  'ghost_canary',
  CURRENT_TIMESTAMP()
)
"""
    job_config = bigquery.QueryJobConfig(
        query_parameters=[
            bigquery.ScalarQueryParameter("operation_id", "STRING", CANARY_OPERATION_ID),
            bigquery.ScalarQueryParameter("canary_email", "STRING", CANARY_EMAIL),
        ]
    )
    bq_client.query(query, job_config=job_config).result()
    print(f"Seeded ghost canary row in {table_id} operation_id={CANARY_OPERATION_ID}")


def cleanup_canary_rows(bq_client: Any, table_id: str = CANARY_TABLE) -> None:
    query = f"""
DELETE FROM `{table_id}`
WHERE operation_id = @operation_id
"""
    job_config = bigquery.QueryJobConfig(
        query_parameters=[
            bigquery.ScalarQueryParameter("operation_id", "STRING", CANARY_OPERATION_ID)
        ]
    )
    bq_client.query(query, job_config=job_config).result()
    print(f"Cleaned ghost canary rows from {table_id} operation_id={CANARY_OPERATION_ID}")


def run_smoke(
    args: argparse.Namespace,
    vault_factory: Callable[..., Any] = VaultClient,
    bigquery_client_factory: Optional[Callable[..., Any]] = None,
) -> Dict[str, Any]:
    vault = vault_factory(base_url=args.vault_url, tenant_id=args.tenant_id)
    try:
        registry_response = vault.fetch_pii_registry_resources(
            system=args.system,
            owner_connector=args.owner_connector,
            scan_enabled=args.scan_enabled,
        )
        registry = PiiMetadataRegistry.from_api_response(registry_response)
        policy = DbtPolicyValidator.control_plane_policy_status(vault)

        print(f"Vault URL: {args.vault_url.rstrip('/')}")
        print(f"Registry resources: {len(registry.resources)}")
        for resource in registry.resources:
            scan = resource.ghost_data_scan
            patterns = ",".join(scan.patterns) if scan.patterns else "-"
            print(
                f"- {resource.id} system={resource.system} "
                f"scan_enabled={scan.enabled} scan_mode={scan.scan_mode} patterns={patterns}"
            )
        print(f"Policy status: {policy.get('status', '<missing>')}")

        findings = []
        seed_canary = getattr(args, "seed_canary", False)
        cleanup_canary = getattr(args, "cleanup_canary", False)
        if args.run_scan or seed_canary or cleanup_canary:
            if bigquery_client_factory is None:
                bigquery_client_factory = bigquery.Client
            bigquery_kwargs = {"project": args.project_id} if args.project_id else {}
            bq_client = bigquery_client_factory(**bigquery_kwargs)
            if cleanup_canary:
                cleanup_canary_rows(bq_client, table_id=args.canary_table)
            if seed_canary:
                seed_canary_row(bq_client, table_id=args.canary_table)
        if args.run_scan:
            scanner = BigQueryGhostDataScanner(
                bigquery_client=bq_client,
                registry=registry,
                vault=vault,
                sample_limit=args.sample_limit,
            )
            for resource in registry.resources:
                try:
                    findings.extend(scanner.scan([resource.id]))
                except NotFound as exc:
                    if not args.skip_missing_tables:
                        raise
                    print(f"WARN: skipping missing BigQuery table for {resource.id}: {exc.message}")
            print(f"Ghost findings emitted: {len(findings)}")
        else:
            print("Ghost scan: skipped (pass --run-scan to query BigQuery and emit lineage)")

        return {
            "registry": registry,
            "policy": policy,
            "findings": findings,
        }
    finally:
        shutdown = getattr(vault, "shutdown", None)
        if callable(shutdown):
            shutdown()


def main() -> int:
    args = build_parser().parse_args()
    run_smoke(args)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"\nPII registry smoke failed: {exc}", file=sys.stderr)
        raise SystemExit(1)

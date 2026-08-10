import argparse
import sys
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from google.cloud import bigquery

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.config import settings
from app.scanners.dbt_pii_discovery_publisher import DbtPiiDiscoveryPublisher
from app.services.vault_client import VaultClient


def comma_list(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Publish chameleon_pii dbt package pii_discovery findings into the "
            "console's live WAREHOUSE_METADATA_DISCOVERED discovery feed. "
            "Run this after `dbt build` (or `dbt build --select chameleon_pii`) "
            "completes -- it reads pii_discovery's output, it does not run dbt."
        )
    )
    parser.add_argument("--vault-url", default=settings.VAULT_BASE_URL)
    parser.add_argument("--tenant-id", default="default")
    parser.add_argument("--project-id", default=settings.dbt_pii_discovery_project_id_resolved)
    parser.add_argument(
        "--datasets",
        default=settings.DBT_PII_DISCOVERY_DATASETS,
        help=(
            "Comma-separated locations of the chameleon_pii pii_discovery table(s), "
            "each 'project.dataset' or a bare dataset name (resolved against "
            "--project-id)."
        ),
    )
    return parser


def run_publish(
    args: argparse.Namespace,
    vault_factory: Callable[..., Any] = VaultClient,
    bigquery_client_factory: Optional[Callable[..., Any]] = None,
) -> Dict[str, Any]:
    if bigquery_client_factory is None:
        bigquery_client_factory = bigquery.Client

    vault = vault_factory(base_url=args.vault_url, tenant_id=args.tenant_id)
    try:
        bq_client = bigquery_client_factory(project=args.project_id)
        publisher = DbtPiiDiscoveryPublisher(
            bigquery_client=bq_client,
            vault=vault,
            pii_discovery_locations=comma_list(args.datasets),
        )
        resources = publisher.publish()

        field_count = sum(len(r.fields) for r in resources)
        print(f"Vault URL: {args.vault_url.rstrip('/')}")
        print(f"Project: {args.project_id}")
        print(f"pii_discovery locations: {', '.join(comma_list(args.datasets)) or '(none configured)'}")
        print(f"Published {len(resources)} resource(s), {field_count} undeclared field(s)")
        for resource in resources:
            columns = ",".join(f.field_name for f in resource.fields)
            print(f"- {resource.resource_id} new_columns={columns}")

        return {"resources": resources, "field_count": field_count}
    finally:
        shutdown = getattr(vault, "shutdown", None)
        if callable(shutdown):
            shutdown()


def main() -> int:
    args = build_parser().parse_args()
    run_publish(args)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"\npublish_dbt_pii_discovery failed: {exc}", file=sys.stderr)
        raise SystemExit(1)

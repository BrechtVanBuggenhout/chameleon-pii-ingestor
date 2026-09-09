import argparse
import sys
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from google.cloud import bigquery

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.config import settings
from app.scanners.warehouse_metadata_crawler import BigQueryWarehouseMetadataCrawler
from app.services.vault_client import VaultClient


def comma_list(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Discover BigQuery warehouse metadata and compare it to Key Vault registry resources.")
    parser.add_argument("--vault-url", default=settings.VAULT_BASE_URL)
    parser.add_argument("--tenant-id", default="default")
    parser.add_argument("--project-id", default=settings.warehouse_discovery_project_id_resolved)
    parser.add_argument(
        "--datasets",
        default=settings.WAREHOUSE_DISCOVERY_DATASETS,
        help="Comma-separated BigQuery datasets approved for metadata discovery.",
    )
    parser.add_argument(
        "--excluded-table-patterns",
        default=settings.WAREHOUSE_DISCOVERY_EXCLUDED_TABLE_PATTERNS,
        help="Comma-separated fnmatch patterns, matched against table_id or dataset.table_id.",
    )
    parser.add_argument(
        "--no-emit-lineage",
        action="store_true",
        help="Print the inventory diff without emitting WAREHOUSE_METADATA_DISCOVERED lineage events.",
    )
    return parser


def run_crawl(
    args: argparse.Namespace,
    vault_factory: Callable[..., Any] = VaultClient,
    bigquery_client_factory: Optional[Callable[..., Any]] = None,
) -> Dict[str, Any]:
    if bigquery_client_factory is None:
        bigquery_client_factory = bigquery.Client

    vault = vault_factory(base_url=args.vault_url, tenant_id=args.tenant_id)
    try:
        bq_client = bigquery_client_factory(project=args.project_id)
        crawler = BigQueryWarehouseMetadataCrawler(
            bigquery_client=bq_client,
            vault=vault,
            project_id=args.project_id,
            dataset_ids=comma_list(args.datasets),
            excluded_table_patterns=comma_list(args.excluded_table_patterns),
        )
        diffs = crawler.crawl(emit_lineage=not args.no_emit_lineage)

        counts = {"REGISTERED": 0, "UNREGISTERED": 0, "DRIFTED": 0}
        for diff in diffs:
            counts[diff.status] += 1

        print(f"Vault URL: {args.vault_url.rstrip('/')}")
        print(f"Project: {args.project_id}")
        print(f"Datasets: {', '.join(comma_list(args.datasets))}")
        print(
            "Inventory diff: "
            f"{counts['REGISTERED']} registered, "
            f"{counts['UNREGISTERED']} unregistered, "
            f"{counts['DRIFTED']} drifted"
        )
        for diff in diffs:
            new_columns = ",".join(column.name for column in diff.new_columns) or "-"
            missing_columns = ",".join(diff.missing_registry_columns) or "-"
            print(
                f"- {diff.status} {diff.resource_id} "
                f"new_columns={new_columns} missing_registry_columns={missing_columns}"
            )

        if args.no_emit_lineage:
            print("Lineage emission: skipped (--no-emit-lineage)")
        else:
            print(f"Lineage events emitted: {len(diffs)}")

        return {"diffs": diffs, "counts": counts}
    finally:
        shutdown = getattr(vault, "shutdown", None)
        if callable(shutdown):
            shutdown()


def main() -> int:
    args = build_parser().parse_args()
    run_crawl(args)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"\nWarehouse metadata crawl failed: {exc}", file=sys.stderr)
        raise SystemExit(1)

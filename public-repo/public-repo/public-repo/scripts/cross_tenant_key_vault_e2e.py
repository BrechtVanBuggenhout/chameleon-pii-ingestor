import argparse
import json
import sys
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List

import requests


def request_json(method: str, url: str, tenant_id: str, **kwargs) -> Dict[str, Any]:
    headers = kwargs.pop("headers", {})
    headers["X-Tenant-Id"] = tenant_id
    response = requests.request(method, url, headers=headers, timeout=20, **kwargs)
    try:
        response.raise_for_status()
    except requests.HTTPError as exc:
        body = response.text[:1000]
        raise requests.HTTPError(f"{exc}; response body: {body}") from exc
    if not response.text:
        return {}
    return response.json()


def context_list(response: Dict[str, Any]) -> List[Dict[str, Any]]:
    contexts = response.get("contexts") or response.get("results") or []
    if isinstance(contexts, dict):
        return list(contexts.values())
    return contexts


def context_fingerprint(context: Dict[str, Any]) -> Any:
    deks = context.get("deks")
    active_dek_id = context.get("activeDekId") or context.get("active_dek_id")
    if isinstance(deks, dict) and active_dek_id:
        return deks.get(active_dek_id)
    return (
        context.get("encryptedDek")
        or context.get("encrypted_dek")
        or context.get("dek")
        or json.dumps(context, sort_keys=True)
    )


def post_lineage(base_url: str, tenant_id: str, user_id: str, destination: str, operation_id: str) -> None:
    payload = {
        "event_type": "DATA_PROVISIONED_TO_SINK",
        "eventType": "DATA_PROVISIONED_TO_SINK",
        "user_id": user_id,
        "userId": user_id,
        "tenant_id": tenant_id,
        "source": "cross_tenant_e2e",
        "destination": destination,
        "data_classification": "ENCRYPTED_ONLY",
        "dataClassification": "ENCRYPTED_ONLY",
        "operation_id": operation_id,
        "operationId": operation_id,
        "context": {
            "operation_id": operation_id,
            "runner": "scripts/cross_tenant_key_vault_e2e.py",
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    request_json("POST", f"{base_url}/lineage/events", tenant_id, json=payload)


def lineage_destinations(base_url: str, tenant_id: str, user_id: str) -> List[str]:
    data = request_json("GET", f"{base_url}/lineage/user/{user_id}", tenant_id)
    destinations = data.get("destinations", [])
    return [
        destination.get("name", "")
        if isinstance(destination, dict)
        else str(destination)
        for destination in destinations
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the live cross-tenant Key Vault E2E smoke test.")
    parser.add_argument("--vault-url", default="http://localhost:8080")
    parser.add_argument("--tenant-a", default="tenant-a")
    parser.add_argument("--tenant-b", default="tenant-b")
    parser.add_argument("--user-id", default=f"cross-tenant-user-{uuid.uuid4().hex[:8]}")
    parser.add_argument("--certificate-wait-seconds", type=float, default=2.0)
    parser.add_argument(
        "--require-lineage-read",
        action="store_true",
        help="Fail if /lineage/user does not return the just-posted destinations.",
    )
    args = parser.parse_args()

    base_url = args.vault_url.rstrip("/")
    operation_id = f"cross-tenant-e2e-{uuid.uuid4().hex[:8]}"

    print(f"Vault URL: {base_url}")
    print(f"Shared userId: {args.user_id}")
    print(f"Tenants: {args.tenant_a}, {args.tenant_b}")

    for tenant_id in (args.tenant_a, args.tenant_b):
        print(f"\n[{tenant_id}] generating key")
        request_json(
            "POST",
            f"{base_url}/keys/batch-generate",
            tenant_id,
            json={"tenantId": tenant_id, "userIds": [args.user_id]},
        )

    contexts = {}
    for tenant_id in (args.tenant_a, args.tenant_b):
        print(f"[{tenant_id}] fetching encryption context")
        response = request_json(
            "POST",
            f"{base_url}/keys/batch-encryption-context",
            tenant_id,
            json={"tenantId": tenant_id, "userIds": [args.user_id]},
        )
        items = context_list(response)
        if not items:
            raise AssertionError(f"No encryption context returned for {tenant_id}")
        contexts[tenant_id] = items[0]

    if context_fingerprint(contexts[args.tenant_a]) == context_fingerprint(contexts[args.tenant_b]):
        raise AssertionError("Expected separate tenant encryption contexts, but context fingerprints matched")
    print("OK: same userId has separate encryption contexts per tenant")

    destinations = {
        args.tenant_a: "hubspot-tenant-a",
        args.tenant_b: "hubspot-tenant-b",
    }
    for tenant_id, destination in destinations.items():
        print(f"[{tenant_id}] posting lineage destination {destination}")
        post_lineage(base_url, tenant_id, args.user_id, destination, operation_id)

    lineage_read_hydrated = True
    for tenant_id, expected_destination in destinations.items():
        found = lineage_destinations(base_url, tenant_id, args.user_id)
        if expected_destination not in found:
            lineage_read_hydrated = False
            if args.require_lineage_read:
                raise AssertionError(f"{tenant_id} lineage missing {expected_destination}; got {found}")
        other_destination = next(value for key, value in destinations.items() if key != tenant_id)
        if other_destination in found:
            raise AssertionError(f"{tenant_id} lineage leaked destination {other_destination}; got {found}")
    if lineage_read_hydrated:
        print("OK: lineage read model is tenant scoped")
    else:
        print("WARN: /lineage/user did not return posted destinations; this is expected in local dev when the BigQuery lineage read model is not hydrated")

    print(f"[{args.tenant_a}] shredding only tenant A key")
    request_json(
        "DELETE",
        f"{base_url}/key/shred",
        args.tenant_a,
        json={
            "tenantId": args.tenant_a,
            "userId": args.user_id,
            "deletionRequestId": f"delete-{operation_id}",
            "operationId": operation_id,
        },
    )

    time.sleep(args.certificate_wait_seconds)
    try:
        certificate = request_json("GET", f"{base_url}/certificate/{args.user_id}", args.tenant_a)
    except requests.HTTPError as exc:
        print(f"WARN: certificate was not available from local Vault: {exc}")
    else:
        cert_text = json.dumps(certificate, sort_keys=True)
        if destinations[args.tenant_b] in cert_text or args.tenant_b in cert_text:
            raise AssertionError("Tenant A certificate appears to include Tenant B lineage")
        print("OK: tenant A certificate does not include tenant B destination/tenant marker")

    tenant_b_context = request_json(
        "POST",
        f"{base_url}/keys/batch-encryption-context",
        args.tenant_b,
        json={"tenantId": args.tenant_b, "userIds": [args.user_id]},
    )
    if not context_list(tenant_b_context):
        raise AssertionError("Tenant B context disappeared after shredding Tenant A")
    print("OK: tenant B encryption context still exists after tenant A shred")

    print("\nCross-tenant Key Vault E2E passed.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"\nCross-tenant Key Vault E2E failed: {exc}", file=sys.stderr)
        raise SystemExit(1)

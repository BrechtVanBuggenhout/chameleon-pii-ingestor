import base64
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.core.crypto import ChameleonCrypto
from app.policies.pii_registry import RegistryResource
from app.services.bigquery_streaming_insert import insert_with_retry
from app.services.vault_client import VaultClient

logger = logging.getLogger(__name__)


class PubsubIngestError(Exception):
    """Base for errors this pipeline raises deliberately, so the route
    handler can map them to the right HTTP status without inspecting
    message strings."""


class CallerNotAuthorized(PubsubIngestError):
    """The resource doesn't exist, isn't a pubsub declaration, has no
    userIdFieldPath, or the verified caller doesn't match what was
    declared. Deliberately never mapped to a 200 ack by the route handler
    -- an authorization failure should keep failing loudly (and Pub/Sub
    keeps redelivering), since it usually means either a real
    misconfiguration or a revoked declaration the customer's subscription
    hasn't caught up to yet, not a message that's simply irrelevant."""


def resolve_field_path(payload: Dict[str, Any], dotted_path: str) -> Optional[Any]:
    """Nested-dict lookup for a dotted path like "after.email" against a
    decoded JSON message body (e.g. a Debezium-style change event). Returns
    None if any segment is missing or the payload isn't a dict at that
    point -- callers treat a missing path as a skippable message, never an
    error (a CDC stream can legitimately emit events that don't carry every
    declared field, e.g. a DELETE event with no "after" at all)."""
    current: Any = payload
    for segment in dotted_path.split("."):
        if not isinstance(current, dict) or segment not in current:
            return None
        current = current[segment]
    return current


@dataclass(frozen=True)
class IngestOutcome:
    accepted: bool
    reason: str
    fields_written: int = 0


class PubsubIngestPipeline:
    """Processes one decoded Pub/Sub push message for a system: 'pubsub'
    declared resource -- resolves its declared fields via dotted-path
    lookup against the message body, encrypts each one found (reusing the
    exact ciphertext bundle format every other write path in this codebase
    already produces -- see ChameleonCrypto.encrypt_field_bundle), and
    streams the result straight into pii_vault, the same table
    pii_vault_sync.py and the real ingestion pipeline already write.
    Landing there directly (not a new table) is what gives a pubsub-
    declared resource immediate compatibility with decrypted views, ad-hoc
    decrypt, and crypto-shred deletion, for free.
    """

    VAULT_TABLE_ID = "pii_vault"

    def __init__(self, vault: VaultClient, bigquery_client: Any, vault_project_id: str, vault_dataset_id: str):
        self.vault = vault
        self.bigquery_client = bigquery_client
        self.vault_project_id = vault_project_id
        self.vault_dataset_id = vault_dataset_id

    def resolve_resource(self, resource_id: str) -> RegistryResource:
        """Looks up the declared resource and confirms it's genuinely a
        pubsub declaration. Raises CallerNotAuthorized -- not a generic
        "not found" -- for every failure mode: from the caller's
        perspective, "no such resource," "not declared as pubsub," and
        "caller mismatch" all mean the same thing, this push has no
        business succeeding."""
        try:
            data = self.vault.fetch_pii_registry_resource(resource_id)
        except Exception as e:
            raise CallerNotAuthorized(f"Could not look up registry resource {resource_id}: {e}") from e
        resource_data = data.get("resource") if isinstance(data, dict) else None
        if not resource_data:
            raise CallerNotAuthorized(f"Resource {resource_id} is not declared")
        resource = RegistryResource.from_dict(resource_data)
        if resource.system != "pubsub":
            raise CallerNotAuthorized(f"Resource {resource_id} is not declared as system: pubsub")
        return resource

    def authorize_caller(self, resource: RegistryResource, verified_caller_sub: str) -> None:
        """verified_caller_sub must already be cryptographically verified
        by the route handler (via google.oauth2.id_token.verify_oauth2_token)
        before this is called -- this method only ever compares two
        strings, it never itself verifies a token."""
        if (
            not resource.pubsub_allowed_caller_service_account
            or resource.pubsub_allowed_caller_service_account != verified_caller_sub
        ):
            raise CallerNotAuthorized(f"Verified caller does not match the declared allowed caller for {resource.id}")

    def process_message(self, resource: RegistryResource, message_body: Dict[str, Any]) -> IngestOutcome:
        """Assumes resource has already passed resolve_resource +
        authorize_caller -- this method only ever handles per-message
        content, never authorization."""
        if not resource.user_id_field_path:
            raise CallerNotAuthorized(f"Resource {resource.id} has no userIdFieldPath declared")

        user_id_value = resolve_field_path(message_body, resource.user_id_field_path)
        if user_id_value is None:
            return IngestOutcome(accepted=False, reason="userIdFieldPath not found in message body")
        user_id = str(user_id_value)

        # Same filter every other write path in this codebase already uses
        # -- only ENCRYPT-handling declared fields are ever synced into
        # pii_vault (see ingestion.py, pii_vault_sync.py).
        encrypt_fields = [c for c in resource.columns if c.handling == "ENCRYPT"]
        field_values: Dict[str, str] = {}
        for column in encrypt_fields:
            raw_value = resolve_field_path(message_body, column.name)
            if raw_value is None:
                continue
            field_values[column.name] = str(raw_value)

        if not field_values:
            return IngestOutcome(accepted=False, reason="no declared fields found in message body")

        self.vault.batch_create_keys([user_id])
        context = self.vault.get_encryption_context(user_id)

        now_iso = datetime.now(timezone.utc).isoformat()
        records: List[Dict[str, Any]] = []
        for field_name, value in field_values.items():
            records.append(
                {
                    "tenant_id": self.vault.tenant_id,
                    "user_id": user_id,
                    "resource_id": resource.id,
                    "field_name": field_name,
                    "key_id": context.get("key_id"),
                    "token": ChameleonCrypto.generate_token(context["dek"], value),
                    "encrypted_value": base64.b64encode(
                        ChameleonCrypto.encrypt_field_bundle(context, user_id, value)
                    ).decode("utf-8"),
                    "synced_at": now_iso,
                }
            )

        table_ref = f"{self.vault_project_id}.{self.vault_dataset_id}.{self.VAULT_TABLE_ID}"
        insert_with_retry(self.bigquery_client, table_ref, records)
        logger.info(f"Pub/Sub ingest wrote {len(records)} field(s) for user {user_id} on {resource.id}")

        return IngestOutcome(accepted=True, reason="ok", fields_written=len(records))

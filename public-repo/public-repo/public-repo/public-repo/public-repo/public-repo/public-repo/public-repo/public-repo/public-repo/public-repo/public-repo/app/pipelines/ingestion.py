import pandas as pd
import logging
import os
import tempfile
import uuid
import json
import base64
import io
from concurrent.futures import ThreadPoolExecutor
from typing import Optional
from datetime import datetime, timezone
from pydantic import BaseModel, EmailStr, ValidationError
from app.core.crypto import ChameleonCrypto
from app.services.vault_client import VaultClient
from app.services.gcs_client import GCSService
from app.policies.pii_registry import PiiMetadataRegistry, RegistryResource
from fastavro import schemaless_writer, parse_schema
from google.cloud import pubsub_v1

logger = logging.getLogger(__name__)

class UserRecord(BaseModel):
    user_id: str
    email: EmailStr

# Avro Schema Definitions for strict BigQuery mapping
USER_SCHEMA = parse_schema({
    "type": "record",
    "name": "UserIngestion",
    "fields": [
        {"name": "tenant_id", "type": ["null", "string"], "default": None},
        {"name": "user_id", "type": "string"},
        {"name": "email_token", "type": "string"},
        {"name": "encryption_version", "type": "string"},
        {"name": "key_id", "type": ["null", "string"], "default": None},
        {"name": "encrypted_pii", "type": "bytes"},
        {"name": "data_hash", "type": "string"},
        {"name": "operation_id", "type": "string"},
        {"name": "ingested_at", "type": "string"},
        {"name": "source_system", "type": "string"},
        # General, N-field home: one entry per PII column a resource declares
        # in the registry (email, phone, etc). email_token/encrypted_pii above
        # are kept in sync for whichever declared field is named "email", so
        # nothing already reading those two columns breaks. Defaults to an
        # empty list so old producers/consumers that don't know this field
        # remain compatible (standard Avro schema evolution).
        {
            "name": "pii_fields",
            "type": {
                "type": "array",
                "items": {
                    "type": "record",
                    "name": "PiiField",
                    "fields": [
                        {"name": "field_name", "type": "string"},
                        {"name": "token", "type": "string"},
                        {"name": "encrypted_value", "type": "bytes"},
                    ],
                },
            },
            "default": [],
        },
    ]
})

LINEAGE_SCHEMA = parse_schema({
    "type": "record",
    "name": "LineageEvent",
    "fields": [
        {"name": "event_id", "type": "string"},
        {"name": "tenant_id", "type": ["null", "string"], "default": None},
        {"name": "user_id", "type": "string"},
        {"name": "source", "type": "string"},
        {"name": "destination", "type": "string"},
        {"name": "timestamp", "type": "long"},
        {"name": "context", "type": "string"}
    ]
})

class IngestionPipeline:
    def __init__(self, vault: VaultClient, topic_id: str, lineage_topic_id: str, gcs_service: GCSService = None, publisher: Optional[pubsub_v1.PublisherClient] = None):
        self.vault = vault
        self.topic_id = topic_id
        self.lineage_topic_id = lineage_topic_id
        self.publisher = publisher or pubsub_v1.PublisherClient()
        # High-concurrency executor for 10k stress tests
        self.executor = ThreadPoolExecutor(max_workers=50)
        self.gcs = gcs_service

    @property
    def tenant_id(self) -> str:
        tenant_id = getattr(self.vault, "tenant_id", "default")
        return tenant_id if isinstance(tenant_id, str) else "default"

    def _resolve_registry_resource(self, resource_id: Optional[str]) -> Optional[RegistryResource]:
        """
        Looks up this resource's declared PII fields, if any. Best-effort: a
        registry lookup failure (Key Vault unreachable, resource not yet
        declared) falls back to None rather than failing the whole ingestion
        run -- callers must fall back to the legacy email-only behavior in
        that case, which is exactly today's behavior for every undeclared
        resource already.
        """
        if not resource_id:
            return None
        try:
            data = self.vault.fetch_pii_registry_resources()
            registry = PiiMetadataRegistry.from_api_response(data)
            return registry.get(resource_id)
        except Exception as e:
            logger.warning(f"No PII registry declaration found for {resource_id}, falling back to email-only ingestion: {e}")
            return None

    def process_file(self, source_uri: str, data_source_name: str = "GCS_LANDING", operation_id: Optional[str] = None, resource_id: Optional[str] = None):
        """
        High-performance ingestion:
        1. Downloads from GCS (if URI provided).
        2. Fetches/Creates keys from Vault (Cached).
        3. Encrypts PII locally -- every field the resource declares as
           PII/ENCRYPT in the registry (falls back to email-only if the
           resource isn't declared yet).
        4. Reports Lineage (GCS -> Pipeline -> BigQuery).
        5. Loads to BigQuery.
        """
        start_time = datetime.now()
        operation_id = operation_id or str(uuid.uuid4())
        local_path = source_uri
        futures = []
        registry_resource = self._resolve_registry_resource(resource_id)
        pii_columns = (
            [c for c in registry_resource.columns if c.handling == "ENCRYPT"]
            if registry_resource
            else None
        )

        # Phase 2: Handle GCS Downloads
        if source_uri.startswith("gs://") and self.gcs:
            _, temp_file = tempfile.mkstemp(suffix=".csv")
            self.gcs.download_to_local(source_uri, temp_file)
            local_path = temp_file

        try:
            if local_path.endswith('.csv'):
                # dtype=str: without this, pandas silently infers numeric-
                # looking PII values (phone numbers, etc.) as int64, which
                # both strips leading zeros/plus-signs and would encrypt a
                # corrupted value instead of what the customer actually
                # sent. Only mattered once fields beyond "email" (which never
                # looks numeric) became possible to declare.
                df = pd.read_csv(local_path, dtype=str)
            elif local_path.endswith('.json'):
                # Assuming newline-delimited JSON for BigQuery compatibility.
                # dtype=False: same reasoning as read_csv's dtype=str above --
                # disables read_json's own numeric-inference-by-column.
                df = pd.read_json(local_path, lines=True, dtype=False)
            else:
                raise ValueError(f"Unsupported file format: {local_path}")
        except Exception as e:
            logger.error(f"Failed to read file {source_uri}: {e}")
            self._cleanup(source_uri, local_path)
            raise

        # Initial Lineage: GCS to Pipeline
        lineage_future = self._publish_lineage(
            user_id="BATCH_JOB",  # Representing the aggregate
            source=source_uri,
            destination="ingestion_pipeline",
            event_type="DATA_READ",
            operation_id=operation_id,
            metadata={"file_size_rows": len(df)}
        )
        futures.append(lineage_future)
        
        # Declared PII column names to encrypt for this file, or the legacy
        # email-only default when the resource isn't declared in the
        # registry yet (exactly today's behavior for every current
        # deployment -- not a regression).
        pii_field_names = [c.name for c in pii_columns] if pii_columns is not None else ["email"]

        # Validate required columns
        required_cols = {'user_id', *pii_field_names}
        if not required_cols.issubset(df.columns):
            missing = required_cols - set(df.columns)
            logger.error(f"Missing required columns in {source_uri}: {missing}")
            self._cleanup(source_uri, local_path)
            raise ValueError(f"Missing columns: {missing}")

        user_ids = [str(user_id) for user_id in df["user_id"].dropna().unique()]
        if user_ids:
            logger.info(f"Prefetching {len(user_ids)} encryption contexts for tenant {self.tenant_id}")
            self.vault.batch_create_keys(user_ids)
            self.vault.batch_get_encryption_contexts(user_ids)

        def _encrypt_field(context: dict, user_id: str, value: str) -> bytes:
            """Randomized AES-GCM (fresh nonce per call -- safe to call once
            per declared field for the same user/DEK, see ingestion pipeline
            generalization design notes)."""
            iv = os.urandom(12)
            raw_bundle_b64 = ChameleonCrypto.encrypt(context['dek'], user_id, value, iv=iv)
            raw_bundle = base64.b64decode(raw_bundle_b64)
            ciphertext_only = raw_bundle[12:]
            iv_b64 = base64.b64encode(iv).decode('utf-8')
            ciphertext_b64 = base64.b64encode(ciphertext_only).decode('utf-8')
            encrypted_bundle_str = f"{context['key_id']}:{iv_b64}:{ciphertext_b64}"
            return encrypted_bundle_str.encode('utf-8')

        def process_row(row):
            try:
                user_id = str(row.get('user_id'))
                if "email" in pii_field_names:
                    # Preserves the existing email-format validation exactly
                    # as before for whichever field is literally named "email".
                    validated = UserRecord(user_id=user_id, email=str(row.get('email')))
                    user_id = validated.user_id

                # Fetch context (Cached in VaultClient)
                context = self.vault.get_encryption_context(user_id)

                pii_fields = []
                email_token = ""
                encrypted_bundle_raw = b""

                for field_name in pii_field_names:
                    raw_value = row.get(field_name)
                    if raw_value is None or (isinstance(raw_value, float) and pd.isna(raw_value)):
                        raise ValueError(f"Missing declared PII field '{field_name}' for user {user_id}")
                    value = str(raw_value)

                    field_encrypted_raw = _encrypt_field(context, user_id, value)
                    # token_key_id (e.g. "chameleon-token-key-v1") is a label, not
                    # key material -- tokenization must use the per-user DEK
                    # directly, same as every other field here, so shredding
                    # that key also makes the token unregenerable.
                    field_token = ChameleonCrypto.generate_token(context['dek'], value)

                    pii_fields.append({
                        "field_name": field_name,
                        "token": field_token,
                        "encrypted_value": field_encrypted_raw,
                    })

                    if field_name == "email":
                        email_token = field_token
                        encrypted_bundle_raw = field_encrypted_raw

                # Register SaaS destinations via Vault API (Hot Path) instead of Pub/Sub (Cold Path)
                # This ensures Firestore is updated immediately for the Shredding Phase.
                try:
                    self.vault.report_lineage(
                        event_type="DATA_PROVISIONED_TO_SINK",
                        user_id=user_id,
                        source=self.topic_id,
                        destination="hubspot",
                        operation_id=operation_id,
                        metadata={"sync_type": "initial_load"}
                    )
                except Exception as e:
                    logger.warning(f"Direct lineage report failed for {user_id}, falling back to Pub/Sub: {e}")
                    self._publish_lineage(
                        user_id=user_id,
                        source=self.topic_id,
                        destination="hubspot",
                        event_type="DATA_PROVISIONED_TO_SINK",
                        operation_id=operation_id,
                        metadata={"sync_type": "initial_load"}
                    )

                processed_record = {
                    "user_id": str(user_id),
                    "tenant_id": self.tenant_id,
                    "email_token": email_token,
                    "encryption_version": context.get("encryption_version", "v2"),
                    "key_id": context.get("key_id"),
                    "encrypted_pii": encrypted_bundle_raw,
                    "data_hash": email_token,
                    "operation_id": operation_id,
                    "ingested_at": datetime.now(timezone.utc).isoformat(),
                    "source_system": data_source_name,
                    "pii_fields": pii_fields,
                }

                # HIGH GRANULARITY: Report per-user encryption lineage
                lineage_future = self._publish_lineage(
                    user_id=user_id,
                    source=source_uri,
                    destination="ingestion_pipeline",
                    event_type="DATA_ENCRYPTED",
                    operation_id=operation_id,
                    metadata={"key_id": context.get("key_id")}
                )
                
                return processed_record, lineage_future

            except Exception as e:
                logger.error(f"Error processing row: {e}")
                return None, None

        # Parallel process the dataframe rows
        logger.info(f"⚙️ Processing {len(df)} records in parallel...")
        results = list(self.executor.map(lambda r: process_row(r[1]), df.iterrows()))
        
        processed_records = []
        for record, lineage_fut in results:
            if record:
                processed_records.append(record)
                futures.append(lineage_fut)
            
        # Second Lineage: Pipeline to Pub/Sub Topic
        lineage_future = self._publish_lineage(
            user_id="BATCH_JOB",
            source="ingestion_pipeline",
            destination=self.topic_id,
            event_type="DATA_PUBLISHED_TO_TOPIC",
            operation_id=operation_id,
            metadata={"record_count": len(processed_records)}
        )
        futures.append(lineage_future)

        # Publish to Pub/Sub
        logger.info(f"📤 Publishing {len(processed_records)} records to {self.topic_id}...")
        if processed_records:
            # Sanitize bytes for logging -- raw bytes aren't JSON-serializable
            # anyway, so this isn't just privacy hygiene, it avoids a crash.
            sample = processed_records[0].copy()
            sample['encrypted_pii'] = f"<{len(sample['encrypted_pii'])} bytes>"
            sample['pii_fields'] = [
                {**f, "encrypted_value": f"<{len(f['encrypted_value'])} bytes>"}
                for f in sample['pii_fields']
            ]
            logger.debug(f"Sample payload (Avro source): {json.dumps(sample, indent=2)}")

        for record in processed_records:
            # Serialize to Avro for robust BigQuery mapping
            fo = io.BytesIO()
            schemaless_writer(fo, USER_SCHEMA, record)
            avro_data = fo.getvalue()
            
            # Pass user_id as attribute for filtering
            future = self.publisher.publish(
                self.topic_id,
                avro_data,
                user_id=record["user_id"],
                tenant_id=record["tenant_id"]
            )
            futures.append(future)
        
        # High-performance wait: Allow Pub/Sub to batch in the background
        published_count = 0
        for future in futures:
            try:
                msg_id = future.result(timeout=60)
                published_count += 1
                logger.debug(f"Message published successfully: {msg_id}")
            except Exception as e:
                logger.error(f"Failed to publish message: {e}")
                raise
        
        logger.info(f"✅ Successfully published {published_count} Binary Avro messages to Pub/Sub.")
        self._cleanup(source_uri, local_path)

        duration = (datetime.now() - start_time).total_seconds()
        logger.info(f"Ingestion complete. Processed {len(df)} records in {duration}s")

    def _publish_lineage(self, user_id: str, source: str, destination: str, event_type: str, operation_id: str, metadata: dict):
        """Publishes lineage events to Pub/Sub for asynchronous BigQuery ingestion."""
        timestamp = datetime.now(timezone.utc)
        safe_metadata = self._sanitize_lineage_metadata(metadata)
        lineage_record = {
            "event_id": str(uuid.uuid4()),
            "tenant_id": self.tenant_id,
            "user_id": str(user_id),
            "source": str(source),
            "destination": str(destination),
            "timestamp": int(timestamp.timestamp() * 1_000_000),
            "context": json.dumps({
                "operation_id": operation_id,
                "event_type": event_type,
                "dataClassification": safe_metadata.get("dataClassification", "PII"),
                **safe_metadata
            })
        }
        
        fo = io.BytesIO()
        schemaless_writer(fo, LINEAGE_SCHEMA, lineage_record)
        avro_data = fo.getvalue()
        
        logger.debug(f"Reporting lineage: {event_type} for {operation_id}")
        return self.publisher.publish(
            self.lineage_topic_id,
            avro_data,
            user_id=str(user_id),
            tenant_id=self.tenant_id,
            data_classification=safe_metadata.get("dataClassification", "PII")
        )

    def _sanitize_lineage_metadata(self, metadata: dict) -> dict:
        """Keep lineage context operational by stripping raw PII-shaped values."""
        sensitive_keys = {
            "address",
            "decrypted",
            "email",
            "first_name",
            "full_name",
            "last_name",
            "name",
            "phone",
            "plaintext",
            "raw_pii",
            "ssn",
        }

        def sanitize_value(key: str, value):
            normalized_key = key.lower()
            if any(part in normalized_key for part in sensitive_keys):
                return "<redacted>"
            if isinstance(value, bytes):
                return f"<{len(value)} bytes>"
            if isinstance(value, dict):
                return {str(child_key): sanitize_value(str(child_key), child_value) for child_key, child_value in value.items()}
            if isinstance(value, list):
                return [sanitize_value("", item) for item in value]
            return value

        return {str(key): sanitize_value(str(key), value) for key, value in metadata.items()}

    def _cleanup(self, source_uri: str, local_path: str):
        """Helper to remove temporary files."""
        if source_uri.startswith("gs://") and os.path.exists(local_path):
            os.remove(local_path)
            logger.debug(f"Cleaned up temporary file: {local_path}")

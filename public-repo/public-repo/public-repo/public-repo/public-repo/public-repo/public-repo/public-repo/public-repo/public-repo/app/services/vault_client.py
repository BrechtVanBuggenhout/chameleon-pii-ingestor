import os
import requests
import logging
import base64
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Iterable
from urllib.parse import quote
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
import threading
from concurrent.futures import ThreadPoolExecutor
from google.cloud import kms
from app.config import settings

class VaultClient:
    BATCH_LIMIT = 1000

    def __init__(
        self,
        base_url: str,
        tenant_id: str = "default",
        cache_enabled: bool = True,
        kms_client: Optional[Any] = None,
    ):
        self.base_url = base_url.rstrip('/')
        self.tenant_id = tenant_id
        self.logger = logging.getLogger(__name__)
        self.cache_enabled = cache_enabled
        self._context_cache: Dict[str, Dict[str, Any]] = {}
        self._cache_lock = threading.Lock()

        # Executor for fire-and-forget lineage and event reporting
        self._executor = ThreadPoolExecutor(max_workers=20, thread_name_prefix="VaultReporter")

        # Set up a robust session with retries for transient network issues
        self.session = requests.Session()
        self.session.headers.update({"X-Tenant-Id": self.tenant_id})
        vault_api_token = os.environ.get("VAULT_API_TOKEN")
        if vault_api_token:
            self.session.headers.update({"Authorization": f"Bearer {vault_api_token}"})
        retry_strategy = Retry(
            total=5,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "POST", "OPTIONS"]
        )
        # Increase pool size to handle higher concurrency in stress tests
        adapter = HTTPAdapter(
            max_retries=retry_strategy, 
            pool_connections=50, 
            pool_maxsize=50
        )
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        # Initialize KMS client for local DEK unwrapping
        self.kms_client = kms_client or kms.KeyManagementServiceClient()

    def for_tenant(self, tenant_id: str) -> "VaultClient":
        """Returns this client when tenant matches, otherwise creates a scoped client."""
        if tenant_id == self.tenant_id:
            return self
        return VaultClient(
            self.base_url,
            tenant_id=tenant_id,
            cache_enabled=self.cache_enabled,
            kms_client=self.kms_client,
        )

    def _chunks(self, values: Iterable[str], size: int = BATCH_LIMIT):
        batch = []
        for value in values:
            batch.append(value)
            if len(batch) == size:
                yield batch
                batch = []
        if batch:
            yield batch

    def _unwrap_context(self, user_id: str, raw_context: Dict[str, Any]) -> Dict[str, Any]:
        wrapped_dek_b64 = (raw_context.get("encrypted_dek") or
                          raw_context.get("encryptedDek") or
                          raw_context.get("dek"))

        if not wrapped_dek_b64 and "deks" in raw_context:
            active_version = raw_context.get("active_dek_id") or raw_context.get("activeDekId") or "v1"
            deks_map = raw_context.get("deks", {})
            wrapped_dek_b64 = deks_map.get(active_version)
            if wrapped_dek_b64:
                self.logger.debug(f"Resolved DEK version {active_version} from deks map")

        if not wrapped_dek_b64:
            raise ValueError(f"Vault response missing DEK for user {user_id}")

        try:
            wrapped_dek_bytes = base64.b64decode(wrapped_dek_b64)
            decrypt_response = self.kms_client.decrypt(
                request={'name': settings.KMS_KEY_PATH, 'ciphertext': wrapped_dek_bytes}
            )
            raw_dek_bytes = decrypt_response.plaintext
        except Exception as e:
            self.logger.error(f"KMS decryption failed for user {user_id}: {e}")
            raise

        context = {
            "user_id": raw_context.get("user_id") or raw_context.get("userId", user_id),
            "tenant_id": self.tenant_id,
            "key_id": raw_context.get("key_id") or raw_context.get("keyId") or raw_context.get("active_dek_id") or "v1",
            "dek": raw_dek_bytes.hex(),
            "token_key_id": raw_context.get("token_key_id") or raw_context.get("tokenKeyId"),
            "encryption_version": raw_context.get("encryption_version") or raw_context.get("encryptionVersion", "v1"),
            "status": raw_context.get("status")
        }

        if context["status"] in ["SHREDDED", "DELETED"]:
            raise ValueError(f"Cannot encrypt for shredded user {user_id}")

        return context

    def create_key(self, user_id: str) -> Dict[str, Any]:
        """
        Creates a new encryption key for a user in the Vault.
        """
        try:
            url = f"{self.base_url}/key/generate"
            res = self.session.post(url, json={"userId": user_id, "tenantId": self.tenant_id})
            res.raise_for_status()
            return res.json()
        except Exception as e:
            self.logger.error(f"❌ Failed to create key for user {user_id}: {e}")
            raise

    def batch_create_keys(self, user_ids: List[str]) -> Dict[str, Any]:
        """
        Creates keys in batches using the Vault burst endpoint.
        The Key Vault validates a maximum of 1000 user IDs per request.
        """
        results = []
        for chunk in self._chunks(dict.fromkeys(user_ids)):
            url = f"{self.base_url}/keys/batch-generate"
            res = self.session.post(url, json={"userIds": chunk, "tenantId": self.tenant_id})
            res.raise_for_status()
            data = res.json()
            if isinstance(data, dict) and "results" in data:
                results.extend(data["results"])
            elif isinstance(data, list):
                results.extend(data)
            else:
                results.append(data)
        return {"results": results, "count": len(results)}

    def get_encryption_context(self, user_id: str) -> Dict[str, Any]:
        """
        Fetches cryptographic policy and keys for a specific user.
        Repo 3 uses this for local encryption.
        """
        if self.cache_enabled:
            with self._cache_lock:
                if user_id in self._context_cache:
                    return self._context_cache[user_id]

        res = self.session.get(f"{self.base_url}/key/{user_id}/encryption-context")
        res.raise_for_status()
        raw_context = res.json()
        context = self._unwrap_context(user_id, raw_context)

        if self.cache_enabled:
            with self._cache_lock:
                self._context_cache[user_id] = context

        return context

    def batch_get_encryption_contexts(self, user_ids: List[str]) -> Dict[str, Dict[str, Any]]:
        """
        Fetches wrapped DEKs in bulk and warms the local context cache.
        Falls back to cached values for IDs already seen by this tenant-scoped client.
        """
        contexts: Dict[str, Dict[str, Any]] = {}
        missing = []

        if self.cache_enabled:
            with self._cache_lock:
                for user_id in user_ids:
                    if user_id in self._context_cache:
                        contexts[user_id] = self._context_cache[user_id]
                    else:
                        missing.append(user_id)
        else:
            missing = list(user_ids)

        for chunk in self._chunks(dict.fromkeys(missing)):
            url = f"{self.base_url}/keys/batch-encryption-context"
            res = self.session.post(url, json={"userIds": chunk, "tenantId": self.tenant_id})
            res.raise_for_status()
            data = res.json()
            raw_contexts = data.get("contexts") if isinstance(data, dict) else data

            if isinstance(raw_contexts, dict):
                iterable = raw_contexts.items()
            else:
                iterable = ((item.get("user_id") or item.get("userId"), item) for item in raw_contexts or [])

            for context_user_id, raw_context in iterable:
                normalized = self._unwrap_context(context_user_id, raw_context)
                contexts[context_user_id] = normalized
                if self.cache_enabled:
                    with self._cache_lock:
                        self._context_cache[context_user_id] = normalized

        return contexts

    def shutdown(self):
        """Ensures all background reporting tasks are completed."""
        self._executor.shutdown(wait=True)

    def report_lineage(self, event_type: str, user_id: str, source: str, destination: str, operation_id: str, metadata: Dict[str, Any], deletion_request_id: Optional[str] = None, data_classification: str = "PII"):
        """
        Reports an immutable lineage event to the Control Plane.
        """
        self._executor.submit(self._do_report_lineage, event_type, user_id, source, destination, operation_id, metadata, deletion_request_id, data_classification)

    def _do_report_lineage(self, event_type: str, user_id: str, source: str, destination: str, operation_id: str, metadata: Dict[str, Any], deletion_request_id: Optional[str] = None, data_classification: str = "PII"):
        """Internal sync implementation for lineage reporting."""
        # Align with Repo 2 "Hot Path" lineage schema using snake_case
        payload = {
            "event_type": event_type,
            "user_id": user_id,
            "tenant_id": self.tenant_id,
            "source": source,
            "destination": destination,
            "data_classification": data_classification,
            "operation_id": operation_id,
            "metadata": metadata,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        if deletion_request_id:
            payload["deletion_request_id"] = deletion_request_id
            
        try:
            url = f"{self.base_url}/lineage/events"
            res = self.session.post(url, json=payload)
            res.raise_for_status()
            self.logger.info(f"✅ Lineage event reported: {event_type} ({user_id})")
        except Exception as e:
            self.logger.error(f"❌ Failed to report lineage to {url}: {e}")

    def search_lineage(self, user_id: str) -> List[str]:
        """
        Queries the lineage service to discover where a user's data has traveled.
        Used by the Janitor to perform targeted cascade wipes.
        """
        try:
            url = f"{self.base_url}/lineage/search/{user_id}"
            res = self.session.get(url)
            res.raise_for_status()
            data = res.json()
            destinations = data.get("destinations", [])
            self.logger.info(f"🔍 Found {len(destinations)} destinations for {user_id}")
            return destinations
        except Exception as e:
            self.logger.error(f"❌ Failed to search lineage for user {user_id} at {url}: {e}")
            return []

    def fetch_pii_registry_resources(
        self,
        system: Optional[str] = None,
        owner_connector: Optional[str] = None,
        scan_enabled: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """
        Reads PII registry resources from the Key Vault control-plane API.
        """
        params: Dict[str, Any] = {}
        if system:
            params["system"] = system
        if owner_connector:
            params["ownerConnector"] = owner_connector
        if scan_enabled is not None:
            params["scanEnabled"] = "true" if scan_enabled else "false"

        url = f"{self.base_url}/pii-registry/resources"
        res = self.session.get(url, params=params)
        res.raise_for_status()
        return res.json()

    def fetch_pii_registry_resource(self, resource_id: str) -> Dict[str, Any]:
        """
        Reads a single PII registry resource and its policy evaluation.
        """
        encoded_resource_id = quote(resource_id, safe="")
        url = f"{self.base_url}/pii-registry/resources/{encoded_resource_id}"
        res = self.session.get(url)
        res.raise_for_status()
        return res.json()

    def mark_resource_synced(self, resource_id: str, synced_at_iso: str) -> Dict[str, Any]:
        """
        Advances a manually-declared resource's pii_vault sync watermark
        (see pii_vault_sync.py's incremental enumerate_resource path) after
        a full or incremental scan of it succeeds. Key Vault does a
        compare-and-swap server-side, so this is safe to call even if an
        overlapping run (e.g. Sync Now firing close to the daily scheduler)
        finishes with an earlier timestamp after this one.
        """
        encoded_resource_id = quote(resource_id, safe="")
        url = f"{self.base_url}/pii-registry/resources/{encoded_resource_id}/mark-synced"
        res = self.session.post(url, json={"lastSyncedAt": synced_at_iso})
        res.raise_for_status()
        return res.json()

    def mark_resource_sync_attempted(self, resource_id: str, attempted_at_iso: str) -> Dict[str, Any]:
        """
        Records that a sync run genuinely completed for this resource --
        called after *every* successful enumerate_resource(), unlike
        mark_resource_synced above, which only ever runs for resources with
        updatedAtColumn set. A resource with no updatedAtColumn syncs real
        data on every run but never advances that watermark, which made the
        registry UI permanently show "Never synced" for it regardless of
        how many times it actually ran.
        """
        encoded_resource_id = quote(resource_id, safe="")
        url = f"{self.base_url}/pii-registry/resources/{encoded_resource_id}/mark-sync-attempted"
        res = self.session.post(url, json={"lastSyncAttemptAt": attempted_at_iso})
        res.raise_for_status()
        return res.json()

    def fetch_pii_registry_policy(self) -> Dict[str, Any]:
        """
        Reads the coarse PII registry policy status for dbt/demo checks.
        """
        url = f"{self.base_url}/pii-registry/policy"
        res = self.session.get(url)
        res.raise_for_status()
        return res.json()

    def issue_certificate(self, user_id: str, evidence: Dict[str, Any]) -> Dict[str, Any]:
        """
        Submits SaaS wipe receipts as evidence to the Vault.
        The Vault will then sign this evidence using the asymmetric CoD key.
        """
        try:
            url = f"{self.base_url}/certificate/issue"
            res = self.session.post(url, json={"userId": user_id, "tenantId": self.tenant_id, "evidence": evidence})
            res.raise_for_status()
            self.logger.info(f"✅ Certificate issued for {user_id}")
            return res.json()
        except Exception as e:
            self.logger.error(f"❌ Failed to issue certificate for user {user_id} at {url}: {e}")
            return {"status": "error", "message": str(e)}

    def get_shred_certificate(self, user_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves a previously issued signed Certificate of Destruction.
        """
        try:
            url = f"{self.base_url}/certificate/{user_id}"
            res = self.session.get(url)
            res.raise_for_status()
            return res.json()
        except Exception as e:
            self.logger.debug(f"ℹ️ Certificate not found for {user_id} at {url}")
            return None

    def decrypt_remote(self, user_id: str, ciphertext: str) -> str:
        """Fallback for smaller batches or Reverse ETL flow."""
        try:
            url = f"{self.base_url}/decrypt"
            res = self.session.post(url, json={"userId": user_id, "tenantId": self.tenant_id, "ciphertext": ciphertext})
            res.raise_for_status()
            return res.json()['plaintext']
        except Exception as e:
            self.logger.error(f"❌ Remote decryption failed for {user_id} at {url}: {e}")
            raise

    def shred_key(self, user_id: str, deletion_request_id: str, operation_id: str) -> Dict[str, Any]:
        """
        Triggers a key shred operation in the Vault.
        Note: Uses the singular /key/shred path to match Control Plane routing.
        """
        payload = {
            "userId": user_id,
            "deletionRequestId": deletion_request_id,
            "operationId": operation_id,
            "tenantId": self.tenant_id
        }
        try:
            url = f"{self.base_url}/key/shred"
            res = self.session.delete(url, json=payload)
            res.raise_for_status()
            return res.json()
        except Exception as e:
            self.logger.error(f"❌ Failed to shred key for {user_id} at {url}: {e}")
            raise

    def rotate_key(self, user_id: str) -> Dict[str, Any]:
        """
        Rotates the Data Encryption Key for a user.
        Note: Uses the singular /key/rotate path to match Control Plane routing.
        """
        try:
            url = f"{self.base_url}/key/rotate"
            res = self.session.post(url, json={"userId": user_id, "tenantId": self.tenant_id})
            res.raise_for_status()
            return res.json()
        except Exception as e:
            self.logger.error(f"❌ Failed to rotate key for {user_id} at {url}: {e}")
            raise

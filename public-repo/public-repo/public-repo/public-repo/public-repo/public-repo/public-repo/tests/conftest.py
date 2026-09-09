"""
Seeds obviously-fake values for every required Settings field (see
app/config.py) before any test module imports app.config — which
constructs `settings = Settings()` at import time. Production deliberately
has no defaults for these (a misconfigured deployment must fail fast rather
than silently point at Chameleon's own infrastructure); tests need to be
hermetic and must not depend on any real GCP project either way.

os.environ.setdefault at module level (not inside a fixture) runs during
pytest's conftest collection, which always happens before test-module
imports — this is what makes the ordering guarantee work.
"""
import os

_FAKE_SETTINGS = {
    "GOOGLE_CLOUD_PROJECT": "test-project",
    "JANITOR_DLQ_TOPIC": "test-janitor-dlq",
    "PII_TOPIC_ID": "projects/test-project/topics/test-pii-ingestion",
    "LINEAGE_TOPIC_ID": "projects/test-project/topics/test-lineage-events",
    "PII_VAULT_SYNC_CHUNK_TOPIC_ID": "projects/test-project/topics/test-pii-vault-sync-chunks",
    "LANDING_ZONE_BUCKET": "test-landing-zone",
    "BIGQUERY_DATASET": "test_dataset",
    "KMS_KEY_PATH": "projects/test-project/locations/us-central1/keyRings/test-ring/cryptoKeys/test-key",
    "KMS_SIGNING_PROJECT_ID": "test-project",
    "KMS_SIGNING_KEY_RING": "test-signing-ring",
    "KMS_SIGNING_KEY_NAME": "test-signing-key",
    "TENANT_ID": "default-tenant",
}

for _key, _value in _FAKE_SETTINGS.items():
    os.environ.setdefault(_key, _value)

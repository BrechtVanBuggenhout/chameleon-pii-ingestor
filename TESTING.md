# Testing Project Chameleon (Data Plane)

This document provides instructions on how to verify the Python pipelines and cryptographic operations.

## 1. Environment Setup

Project Chameleon requires **Python 3.11+**. Using older versions (3.9 or 3.10) will result in OpenSSL warnings or Google Cloud SDK deprecation errors.

**To set up the environment:**
```bash
# Install via Homebrew if needed: brew install python@3.11
python3.11 -m venv venv
source venv/bin/activate

# Use python3 -m pip if the 'pip' command is not found
pip install -r requirements.txt
```

## 2. Configuration

Create a `.env` file in the root directory to store local settings:
```bash
cp .env.example .env
```

## 3. Unit Testing (Pytest)

We use `pytest` to verify the **Randomized AES-256-GCM** and **HMAC tokenization** implementation. This ensures that even with randomized IVs, the data remains decryptable and tokens remain deterministic for warehouse joins.

**Run all unit tests:**
```bash
pytest tests/unit
```

## 4. Manual API Testing (FastAPI)

The "Janitor" webhook listens for shredding instructions. You can test this manually using the built-in Swagger UI.

1. **Start the server:**
   ```bash
   uvicorn main:app --port 8000 --reload
   ```
2. **Open your browser:** http://127.0.0.1:8000/docs
3. **Trigger a test shred:** Use the `POST /api/v1/shred` endpoint with a sample `userId`.

4. **Running stress tests**:
```bash
python3 stress_test.py
```

## 5. Cross-Tenant Key Vault E2E

Use this when `chameleon-key-vault` is running locally. From the Key Vault repo:

```bash
npm run dev
```

Keep that process running, then from this pipelines repo run:

```bash
source venv/bin/activate
python scripts/cross_tenant_key_vault_e2e.py --vault-url http://localhost:8080
```

The script uses the same `userId` in `tenant-a` and `tenant-b` and verifies:

- batch key generation accepts `X-Tenant-Id`
- encryption contexts are separate per tenant
- lineage writes are accepted with tenant scope
- shredding tenant A does not remove tenant B's encryption context
- tenant A's certificate does not include tenant B's destination or tenant marker

In plain local `npm run dev`, `/lineage/events` may write successfully while
`/lineage/user/:userId` still returns no destinations because that read path is
backed by the BigQuery lineage read model. The script treats that as a warning.
When the lineage read model is hydrated, use the strict mode:

```bash
python scripts/cross_tenant_key_vault_e2e.py \
  --vault-url http://localhost:8080 \
  --require-lineage-read
```

If strict mode fails with `lineage missing ... got []`, the tenant-scoped Vault
write path still worked, but the BigQuery-backed `/lineage/user/:userId` read
model has not caught up or is not configured in local dev. Treat that as the
next Key Vault/lineage read-model task, not a pipelines crypto-isolation
failure.

You can override the defaults:

```bash
python scripts/cross_tenant_key_vault_e2e.py \
  --vault-url http://localhost:8080 \
  --tenant-a tenant-a \
  --tenant-b tenant-b \
  --user-id shared-cross-tenant-user
```

If the certificate lookup fails, wait a few seconds and rerun with:

```bash
python scripts/cross_tenant_key_vault_e2e.py --certificate-wait-seconds 5
```

## 6. PII Registry And Compliance Demo Smoke

Use this when `chameleon-key-vault` is running locally and BigQuery ADC is configured.

The raw/dbt demo path is:

1. Seed the synthetic canary into `chameleon_dev.raw_users`.
2. Run dbt so `stg_users`, `int_customer_activity`, and
   `mart_customer_metrics` are materialized.
3. Run the registry scan against the dbt-owned registry resources.

Strict registry scan:

```bash
venv/bin/python scripts/pii_registry_smoke.py \
  --vault-url http://localhost:8080 \
  --run-scan \
  --project-id your-gcp-project-id
```

Expected local demo result:

```text
Policy status: WARN
Ghost findings emitted: 1
```

The `WARN` is expected while `mart_customer_metrics.user_surrogate_id` requires manual review. The ghost finding is expected only when the synthetic canary row exists.

Seed or clean the synthetic canary in the raw ingestion table:

```bash
venv/bin/python scripts/pii_registry_smoke.py \
  --vault-url http://localhost:8080 \
  --seed-canary \
  --project-id your-gcp-project-id

# From the analytics/dbt project:
dbt build

venv/bin/python scripts/pii_registry_smoke.py \
  --vault-url http://localhost:8080 \
  --cleanup-canary \
  --project-id your-gcp-project-id
```

Policy-only smoke:

```bash
venv/bin/python scripts/pii_registry_policy_smoke.py \
  --vault-url http://localhost:8080
```

Warehouse metadata discovery smoke:

```bash
venv/bin/python scripts/warehouse_metadata_crawl.py \
  --vault-url http://localhost:8080 \
  --project-id your-gcp-project-id \
  --datasets chameleon_dev
```

Use `--no-emit-lineage` for a dry inventory diff. The crawler emits one
`WAREHOUSE_METADATA_DISCOVERED` metadata event per discovered table, using
`UNKNOWN` as the user ID and column names only.

dbt registry comparison after generating a dbt manifest in the analytics/dbt project:

```bash
venv/bin/python scripts/dbt_registry_smoke.py \
  --vault-url http://localhost:8080 \
  --manifest path/to/dbt/target/manifest.json
```

## 7. Key Vault k6 Batch Load Test

Install k6 first if your shell reports `zsh: command not found: k6`.

On macOS:

```bash
brew install k6
```

Then run the batch Vault load test:

```bash
VAULT_URL=http://localhost:8080 \
TENANT_ID=tenant-a \
TOTAL_USERS=1000 \
BATCH_SIZE=100 \
k6 run load_tests/key_vault_batch_ingestion.js
```

For a smaller smoke run before the full 10k test:

```bash
VAULT_URL=http://localhost:8080 \
TENANT_ID=tenant-a \
TOTAL_USERS=100 \
BATCH_SIZE=50 \
k6 run load_tests/key_vault_batch_ingestion.js
```

## 8. Salesforce Sandbox Connector

The Janitor uses mock Salesforce by default. To test against a Salesforce sandbox, set:

```bash
SALESFORCE_MODE=sandbox
SALESFORCE_LOGIN_URL=https://test.salesforce.com
SALESFORCE_CLIENT_ID=...
SALESFORCE_CLIENT_SECRET=...
SALESFORCE_USERNAME=...
SALESFORCE_PASSWORD=...
SALESFORCE_SECURITY_TOKEN=...
SALESFORCE_EXTERNAL_ID_FIELD=Chameleon_User_ID__c
SALESFORCE_OBJECT_TYPES=Lead,Contact
SALESFORCE_DELETE_MODE=delete
```

Then start the Janitor API:

```bash
uvicorn main:app --port 8000 --reload
```

Trigger shred through Key Vault so signed requests and lineage reporting are exercised.

## 9. Ingestion Pipeline "Dry Run"

Since the pipeline interacts with BigQuery and the Vault, we use a test script to simulate ingestion without needing a full production environment.

**Run the ingestion test harness:**
```bash
python -m scripts.test_ingestion
```

## 10. Success Criteria

- [x] `test_crypto.py`: All tests pass (Randomized IVs, Encrypt/Decrypt cycle, HMAC Determinism).
- [ ] `test_ingestion.py`: Pipeline generates ciphertexts and reports lineage correctly.
- [ ] `/health`: API returns `{"status": "healthy"}`.

## 11. Debugging Tips

- **Lineage Errors:** Check that your `VAULT_BASE_URL` in `app/config.py` is pointing to the running Node.js service.
- **GCP Permissions:** If running against actual BigQuery, ensure you have run `gcloud auth application-default login`.
- **Crypto Mismatch:** If Python ciphertexts don't match Node.js ciphertexts, verify that the `userId` is being passed as the AAD in both systems.
- **Cross-Tenant E2E:** Confirm Key Vault is still running from `npm run dev` and listening on `http://localhost:8080`.

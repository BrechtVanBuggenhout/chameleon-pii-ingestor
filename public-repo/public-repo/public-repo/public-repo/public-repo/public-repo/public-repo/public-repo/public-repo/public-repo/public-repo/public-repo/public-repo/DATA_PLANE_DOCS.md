# Project Chameleon: Data Plane Documentation

*Refreshed 2026-08-09. Previous version (2026-06-04) described "Phase 4: Janitor Loop" as the latest milestone — that component (`app/api/janitor.py`, the `/shred` webhook, `saas_sinks.py`) has since been removed entirely (2026-07-21): nothing in production ever called it, its HubSpot connector was mock-only, and its Salesforce connector duplicated the real, working one on the Key Vault side. Real SaaS-cascade wipes go through `chameleon-key-vault`'s `janitor.ts` directly. This doc describes what's actually here now.*

## 1. Executive Summary

`chameleon-data-pipelines` is the **Data Plane** for Project Chameleon — the execution engine for ingestion, PII discovery/scanning, and the `pii_vault` sync job. The Control Plane (`chameleon-key-vault`) owns keys, policy, the registry, and deletion orchestration; this repo does the actual data movement and warehouse-side work the Control Plane triggers.

## 2. Core Components (`app/`)

| Directory | Role |
|---|---|
| `pipelines/ingestion.py` | GCS landing-zone → Vault (get DEK) → local encrypt → BigQuery `stg_users` load |
| `scanners/pii_vault_sync.py` | Syncs declared "manual" resources into the central `pii_vault` table. Incremental as of 2026-08-07 — watermark-filtered for resources with `updated_at_column` set, full-scan otherwise. Force-full-scan available for Sync Now. |
| `scanners/ghost_data_scanner.py` | Scans for PII-looking data that isn't declared in the registry |
| `scanners/warehouse_metadata_crawler.py` | Crawls warehouse schema for discovery |
| `policies/pii_registry.py` | `RegistryResource` model + parsing — the Data Plane's view of what Key Vault's registry declares |
| `policies/dbt_policy.py` | dbt-sourced policy/registry slice |
| `api/discovery.py` | Current FastAPI router — `/pii-vault-sync`, `/pii-vault-sync-chunk` (Pub/Sub push target for fan-out), discovery endpoints |
| `api/source_staleness.py` | BYOC self-built-image staleness check (2026-08-06) — compares a customer's built commit SHAs against Chameleon's public repos, logs a warning to their own Cloud Logging only |
| `services/vault_client.py` | HTTP client to Key Vault — registry fetch, `mark_resource_synced`, encryption context |
| `services/{bigquery,gcs,snowflake}_client.py` | Warehouse/storage clients |
| `services/warehouse_factory.py` | Picks the right warehouse client (BigQuery vs. Snowflake) per resource |
| `services/gcs_monitor.py` | Watches for new landing-zone files; deletes the source file on successful processing (the published `DATA_READ` lineage event is the durable record — no permanent plaintext copy left behind) |
| `core/crypto.py` | Randomized AES-256-GCM + HMAC-SHA256 tokenization |
| `core/signature_verifier.py` | Verifies signed requests from the Control Plane |

## 3. What's real vs. what the old doc described as current

- **No Janitor, no `/shred` endpoint in this repo.** Removed 2026-07-21. If you're looking for SaaS-cascade wipe logic, it's in `chameleon-key-vault/src/services/janitor.ts` now, not here.
- **`pii_vault_sync.py` is the actual center of gravity now**, not ingestion alone — most of what this service does day-to-day is the daily/incremental sync job, triggered either by Cloud Scheduler (incremental-eligible) or Sync Now from the console (always forced full scan).
- **Snowflake support exists** (`snowflake_client.py`, `warehouse_factory.py`) — the old doc only described BigQuery.
- **Source staleness check** (`source_staleness.py`) is new BYOC-specific functionality with no equivalent in the old doc at all.

## 4. Data Flow: Sync (the primary flow now)

```
Cloud Scheduler (daily, no body) or console "Sync Now" (force_full_scan=true)
  → POST /pii-vault-sync
  → PiiVaultSyncJob.sync_all(force_full_scan)
     → for each declared resource:
        - incremental eligible (updated_at_column + last_synced_at set, not forced)?
          → WHERE updated_at_column >= last_synced_at
        - else: full population scan
     → enumerate → fan out via Pub/Sub (pii-vault-sync-chunks) → process_chunk per batch
     → on success: POST back to Key Vault's /pii-registry/resources/:id/mark-synced
```

## 5. Data Flow: Ingestion (unchanged in shape from the old doc)

```
GCS landing zone → detect new file → fetch EncryptionContext from Vault
  → local encrypt (randomized AES-256-GCM) + HMAC tokenize
  → batch load to BigQuery stg_users
  → report lineage (READ, then INGESTION events)
  → delete the source landing-zone file (lineage event is the durable record)
```

## 6. Repository Structure (current)

```text
app/
├── api/            # discovery.py (pii-vault-sync), source_staleness.py
├── core/           # crypto, signature verification
├── pipelines/       # ingestion
├── policies/        # pii_registry.py, dbt_policy.py
├── scanners/        # pii_vault_sync.py, ghost_data_scanner.py, warehouse_metadata_crawler.py
├── services/        # vault_client, bigquery/gcs/snowflake clients, warehouse_factory, gcs_monitor
└── config.py
tests/unit/          # pytest suite
```

## 7. How to Use

See `TESTING.md` for setup and test instructions (also refreshed 2026-08-09 — the old Janitor-based manual testing steps have been removed). `stress_test.md` covers scale testing.

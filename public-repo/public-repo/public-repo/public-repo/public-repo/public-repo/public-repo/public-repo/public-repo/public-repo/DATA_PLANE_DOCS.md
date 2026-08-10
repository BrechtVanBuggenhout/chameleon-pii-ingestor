# Project Chameleon: Data Plane Documentation

## 1. Executive Summary
The `chameleon-data-pipelines` repository serves as the **Data Plane** for Project Chameleon. While the Control Plane (Node.js Vault) manages keys and policy, this repository provides the execution engine responsible for secure data ingestion, lineage instrumentation, and automated compliance enforcement (The Janitor).

Its primary mission is to ensure that PII (Personally Identifiable Information) is never stored in plaintext and that every piece of data can be programmatically "shredded" across all downstream systems upon request.

## 2. Core Architecture & Workflow
The repository is organized into three distinct operational pillars:

### A. Secure Ingestion Pipeline (`app/pipelines/ingestion.py`)
This is the entry point for all raw data.
1.  **Detection:** Monitors GCS landing zones for new CSV/JSON files.
2.  **Policy Fetch:** For every record/batch, it fetches an `EncryptionContext` from the Vault.
3.  **Local Encryption:** Uses **Randomized AES-256-GCM** for PII and generates deterministic **HMAC-SHA256 tokens** for joins and deduplication, as defined by the policy.
4.  **Warehouse Loading:** Batches encrypted records into BigQuery (`stg_users`) using high-performance JSON-stream loading.

### B. Active Lineage Tracking
Every component is instrumented to report immutable lineage events to the Control Plane.
-   **Read Events:** Logged when data is pulled from GCS.
-   **Ingestion Events:** Logged when data is committed to BigQuery.
-   **Cascade Events:** Logged when data is deleted from downstream SaaS systems.

### C. The Janitor Loop (`app/api/janitor.py`)
The Janitor is an execution engine for signed shredding requests.
1.  **Verification:** Validates the signature of the shred request from the Control Plane.
2.  **Cascade Wipe:** Issues authenticated delete requests to external systems (HubSpot, Salesforce) via a connector architecture.
3.  **Reporting:** Emits status events back to the Control Plane for each destination attempt.
4.  **Resilience:** Implements exponential backoff and routes permanent failures to a **Dead Letter Queue (DLQ)**.

## 3. Key Technical Achievements

### Modern Crypto Implementation
Implementation of randomized AES-256-GCM with per-record IVs. The system now attaches `encryption_version` and `key_id` to every record, ensuring long-term rotatability and security of PII.

### High-Performance Vault Client
A custom `VaultClient` featuring:
-   **Thread-safe Context Caching:** Caches encryption metadata (keys, versions, tokenization rules) to minimize latency.
-   **Robust Retries:** Uses `urllib3` retry strategies to handle transient 429 (Rate Limit) or 5xx errors from the security infrastructure.

### Reliability Engineering
The Janitor loop is designed for "Compliance Grade" reliability:
-   **Async Processing:** Uses FastAPI BackgroundTasks to ensure shredding webhooks return immediately while the heavy lifting happens in the background.
-   **Auditability:** Every successful and failed wipe produces a receipt ID and a lineage event, creating a verifiable "Certificate of Destruction."

## 4. Integration with Project Chameleon

### 4.1. Data Flow Sequence Diagram

```mermaid
sequenceDiagram
    participant GCS as GCS Landing Zone
    participant DP as Data Plane (Ingestion Pipeline)
    participant Vault as Vault (Control Plane)
    participant BQ as BigQuery (stg_users)
    participant Janitor as Janitor (Data Plane API)
    participant Lineage as Vault (Lineage Service)
    participant HubSpot as HubSpot (Mock)
    participant Salesforce as Salesforce (Mock)
    participant DLQ as Pub/Sub DLQ

    rect rgb(230, 255, 230)
        box Green Ingestion Flow
        GCS->>DP: New CSV/JSON file detected (source_uri)
        activate DP
        DP->>Vault: get_or_create_key(userId)
        activate Vault
        Vault-->>DP: DEK (cached)
        deactivate Vault
        DP->>DP: Encrypt PII (Randomized GCM) + Generate Tokens (HMAC)
        DP->>Vault: report_lineage(GCS -> Pipeline, READ)
        activate Vault
        Vault-->>DP: Lineage ACK
        deactivate Vault
        DP->>BQ: load_records(encrypted_data)
        activate BQ
        BQ-->>DP: Load ACK
        deactivate BQ
        DP->>Vault: report_lineage(Pipeline -> BQ, INGESTION)
        activate Vault
        Vault-->>DP: Lineage ACK
        deactivate Vault
        deactivate DP
        end
    end

    rect rgb(255, 240, 230)
        box Red Shredding Flow
        Vault->>Janitor: POST /shred (userId)
        activate Janitor
        Janitor->>Lineage: search_lineage(userId)
        activate Lineage
        Lineage-->>Janitor: destinations=["hubspot", "salesforce"]
        deactivate Lineage

        alt HubSpot Wipe
            Janitor->>HubSpot: delete_contact(userId)
            activate HubSpot
            HubSpot-->>Janitor: {"status": "success", "receipt_id": "hs-..."}
            deactivate HubSpot
        else Salesforce Wipe (with retry)
            Janitor->>Salesforce: delete_lead(userId) (Attempt 1)
            activate Salesforce
            Salesforce--xJanitor: Error (e.g., 500)
            Janitor->>Janitor: Wait (exponential backoff)
            Janitor->>Salesforce: delete_lead(userId) (Attempt 2)
            Salesforce--xJanitor: Error (e.g., 500)
            Janitor->>Janitor: Wait (exponential backoff)
            Janitor->>Salesforce: delete_lead(userId) (Attempt 3)
            Salesforce--xJanitor: Error (e.g., 500)
            deactivate Salesforce
            Janitor->>DLQ: publish_failed_wipe(userId, "salesforce", error)
            activate DLQ
            DLQ-->>Janitor: Publish ACK
            deactivate DLQ
        end

        Janitor->>Vault: report_lineage(Janitor -> SaaS Sinks, CASCADE_WIPE_COMPLETE)
        activate Vault
        Vault-->>Janitor: Lineage ACK
        deactivate Vault
        deactivate Janitor
        end
    end
```

| Component | Role in Chameleon | Interaction with this Repo |
| :--- | :--- | :--- |
| **Control Plane (Node Vault)** | Key Management & Policy | Provides DEKs; Triggers the `/shred` webhook. |
| **BigQuery** | Data Warehouse | Destination for encrypted PII and Lineage logs. |
| **GCS** | Landing Zone | Source for raw data ingestion. |
| **Cloud KMS** | Root of Trust | Backs the encryption used by the Data Plane. |
| **Pub/Sub** | Error Handling | Acts as the DLQ for failed Janitor tasks. |

## 5. Repository Structure

```text
app/
├── api/            # FastAPI routers (Janitor webhooks)
├── core/           # Cryptographic primitives (Deterministic AES)
├── pipelines/      # Ingestion logic (GCS -> Vault -> BQ)
├── services/       # Clients for Vault, BQ, GCS, and SaaS Mocks
└── config.py       # Environment-driven settings
scripts/            # Utility scripts for dry-run testing
tests/              # Unit tests for crypto and pipeline resilience
```

## 6. How to Use
Detailed setup and testing instructions are located in `TESTING.md`. The pipeline expects a running instance of the Chameleon Vault and appropriate GCP credentials configured via `Application Default Credentials (ADC)`.

---
*Last Updated: 2026-06-04*
*Status: Phase 4 (Janitor Loop) Integration Complete*
```

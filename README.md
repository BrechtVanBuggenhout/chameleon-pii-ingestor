# chameleon-data-pipelines

The PII Ingestor Worker's source -- one of three services a
[chameleon-installer](https://github.com/BrechtVanBuggenhout/chameleon-installer)
BYOC deployment runs (alongside `chameleon-vault` and
`chameleon-console`). Most customers don't need this repo at all:
`bootstrap.sh` pulls Chameleon's pre-built image by default. Build from
here yourself only if you want to run entirely independent of
Chameleon's own container registry (see `chameleon-installer`'s
`scripts/build-own-images.sh`).

Data pipeline engine for Project Chameleon. Handles secure GCS data ingestion, BigQuery warehousing, OpenLineage metadata tracking, and lineage-driven downstream Reverse ETL cleaning.

This repository contains the Python-driven data engineering ecosystem for **Project Chameleon**. It orchestrates the flow of user data from initial raw landing zones to structured warehouses and out to external destinations.

What sets this pipeline apart is its deep integration with data lineage and the core security vault to enforce active privacy compliance.

### Pipeline Workflows:
1. **Ingestion & Tokenization:** Picks up raw files from GCS, batches them through the `chameleon-key-vault` using envelope encryption, and streams the ciphertext safely into BigQuery.
2. **Lineage Auditing (OpenLineage):** Emits detailed data maps logging exactly where user data has traveled and been transformed.
3. **Reverse ETL & Janitor Loop:** Syncs required data to mock third-party SaaS APIs and actively listens for shredding events to trigger cascade-deletions on external systems based on the lineage map.

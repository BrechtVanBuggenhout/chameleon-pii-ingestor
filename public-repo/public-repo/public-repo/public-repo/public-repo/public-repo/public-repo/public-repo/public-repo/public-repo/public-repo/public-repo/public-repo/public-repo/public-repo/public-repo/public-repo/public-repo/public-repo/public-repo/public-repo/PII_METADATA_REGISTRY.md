# PII Metadata Registry

The registry is the data-plane policy source for resources that can contain PII or
derived user data. It is intentionally checked in for dev so scanners and dbt
policy checks can run before a central registry service exists.

## Schema

```json
{
  "version": 1,
  "resources": [
    {
      "id": "bigquery:project.dataset.table",
      "type": "bigquery_table",
      "tenantScoped": true,
      "tenantIdColumn": "tenant_id",
      "allowedDirectIdentifiers": [],
      "columns": [
        {
          "name": "email",
          "classification": "DIRECT_IDENTIFIER",
          "identifierType": "EMAIL",
          "allowedInMart": false
        }
      ]
    }
  ]
}
```

## Resource Types

- `bigquery_table`: scanned by the Ghost Data scanner and used by dbt policy.
- `gcs_prefix`: registered as a landing-zone source; not scanned by the BigQuery
  MVP.

## Classifications

- `DIRECT_IDENTIFIER`: raw identifiers such as emails and phone numbers.
- `TOKENIZED_IDENTIFIER`: deterministic tokens used for joins.
- `ENCRYPTED_PII`: ciphertext or encrypted payloads.
- `LINEAGE_METADATA`: lineage event fields and non-PII operational metadata.
- `SYSTEM_METADATA`: file prefixes, operation IDs, timestamps, and similar data.

The scanner must never send raw direct identifiers to Key Vault. Ghost findings
are reported as lineage events with `dataClassification: "GHOST_DATA"` and
metadata containing only counts, column names, and pattern names.

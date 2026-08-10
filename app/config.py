from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    """
    Configuration settings for the Project Chameleon Data Plane.

    Fields with no default point at real infrastructure (a GCP project, a
    topic, a bucket, a KMS key) and are required: a misconfigured BYOC/
    managed-dedicated deployment must fail fast at startup instead of
    silently talking to Chameleon's own dev/prod. Fields with a default are
    either generic/universal (a version number, a table name any deployment
    would plausibly use) or genuinely optional features (Salesforce mock
    mode, warehouse discovery off by default).
    """
    GOOGLE_CLOUD_PROJECT: str
    VAULT_BASE_URL: str = "http://localhost:8080"
    # Must match the console's NEXT_PUBLIC_TENANT_ID for this instance, or the
    # console can trigger a real deletion but never look up the resulting
    # certificate (wrong tenant = 404). See tenant_id in chameleon-infra-gcp's
    # main.tf locals.
    TENANT_ID: str
    JANITOR_DLQ_TOPIC: str
    PII_TOPIC_ID: str
    LINEAGE_TOPIC_ID: str
    # Fan-out target for PiiVaultSyncJob.enumerate_resource -- one message
    # per chunk of user IDs, consumed by /pii-vault-sync-chunk via this
    # topic's own push subscription. Fully-qualified (projects/<id>/topics/<name>),
    # matching PII_TOPIC_ID/LINEAGE_TOPIC_ID's own convention.
    PII_VAULT_SYNC_CHUNK_TOPIC_ID: str
    LANDING_ZONE_BUCKET: str
    BIGQUERY_DATASET: str
    # Optional overrides of BIGQUERY_DATASET (see ingestor.py's fallback chain).
    STAGING_DATASET: Optional[str] = None
    STAGING_DATASET_ID: Optional[str] = None
    STAGING_TABLE: str = "raw_users"
    KMS_KEY_PATH: str
    SALESFORCE_MODE: str = "mock"
    SALESFORCE_LOGIN_URL: str = "https://test.salesforce.com"
    SALESFORCE_CLIENT_ID: str = ""
    SALESFORCE_CLIENT_SECRET: str = ""
    SALESFORCE_USERNAME: str = ""
    SALESFORCE_PASSWORD: str = ""
    SALESFORCE_SECURITY_TOKEN: str = ""
    SALESFORCE_EXTERNAL_ID_FIELD: str = "Chameleon_User_ID__c"
    SALESFORCE_OBJECT_TYPES: str = "Lead,Contact"
    SALESFORCE_DELETE_MODE: str = "delete"
    # None = falls back to GOOGLE_CLOUD_PROJECT (see the property below).
    # Warehouse discovery is opt-in (empty WAREHOUSE_DISCOVERY_DATASETS is a
    # no-op crawl), so it shouldn't force every deployment to configure it.
    WAREHOUSE_DISCOVERY_PROJECT_ID: Optional[str] = None
    # Empty = warehouse discovery is off; it's an opt-in feature, not core path.
    WAREHOUSE_DISCOVERY_DATASETS: str = ""
    WAREHOUSE_DISCOVERY_SAMPLE_LIMIT: int = 1000
    WAREHOUSE_DISCOVERY_EXCLUDED_TABLE_PATTERNS: str = ""
    # Where the chameleon_pii dbt package's pii_discovery table(s) live -- one
    # "project.dataset" entry per dbt target/environment that runs the package.
    # A bare "dataset" (no dot) resolves against DBT_PII_DISCOVERY_PROJECT_ID /
    # GOOGLE_CLOUD_PROJECT. Empty = publishing dbt's discovery findings into the
    # console's live discovery feed is off; it's an opt-in feature like warehouse
    # discovery above, not core path.
    DBT_PII_DISCOVERY_PROJECT_ID: Optional[str] = None
    DBT_PII_DISCOVERY_DATASETS: str = ""
    KMS_SIGNING_PROJECT_ID: str
    KMS_SIGNING_KEY_RING: str
    KMS_SIGNING_KEY_NAME: str

    # Selects the ingestion write-path destination. "bigquery" (default) keeps
    # existing behavior untouched; "snowflake" requires the PII_INGESTOR_SNOWFLAKE_*
    # settings below. Encryption/KMS/Firestore/deletion are unaffected either way --
    # only the landing warehouse for ciphertext changes.
    WAREHOUSE_TYPE: str = "bigquery"
    PII_INGESTOR_SNOWFLAKE_ACCOUNT: Optional[str] = None
    PII_INGESTOR_SNOWFLAKE_USER: Optional[str] = None
    PII_INGESTOR_SNOWFLAKE_PASSWORD: Optional[str] = None
    PII_INGESTOR_SNOWFLAKE_ROLE: Optional[str] = None
    PII_INGESTOR_SNOWFLAKE_WAREHOUSE: Optional[str] = None
    PII_INGESTOR_SNOWFLAKE_DATABASE: Optional[str] = None
    PII_INGESTOR_SNOWFLAKE_SCHEMA: Optional[str] = None

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @property
    def warehouse_discovery_project_id_resolved(self) -> str:
        return self.WAREHOUSE_DISCOVERY_PROJECT_ID or self.GOOGLE_CLOUD_PROJECT

    @property
    def dbt_pii_discovery_project_id_resolved(self) -> str:
        return self.DBT_PII_DISCOVERY_PROJECT_ID or self.GOOGLE_CLOUD_PROJECT

    @property
    def staging_dataset_resolved(self) -> str:
        return self.STAGING_DATASET or self.STAGING_DATASET_ID or self.BIGQUERY_DATASET

settings = Settings()

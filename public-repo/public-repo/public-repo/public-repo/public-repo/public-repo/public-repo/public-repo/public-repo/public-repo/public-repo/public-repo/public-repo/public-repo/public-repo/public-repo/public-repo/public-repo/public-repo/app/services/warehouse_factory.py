from typing import Optional

from app.config import settings
from app.services.bigquery_client import BigQueryService
from app.services.snowflake_client import SnowflakeService
from app.services.warehouse_writer import WarehouseWriter


def get_warehouse_writer(
    project_id: Optional[str] = None, dataset_id: Optional[str] = None
) -> WarehouseWriter:
    """
    Builds the configured ingestion write-path destination. Defaults to
    BigQuery (today's behavior, unchanged) unless WAREHOUSE_TYPE=snowflake.
    """
    if settings.WAREHOUSE_TYPE == "snowflake":
        missing = [
            name
            for name in (
                "PII_INGESTOR_SNOWFLAKE_ACCOUNT",
                "PII_INGESTOR_SNOWFLAKE_USER",
                "PII_INGESTOR_SNOWFLAKE_PASSWORD",
                "PII_INGESTOR_SNOWFLAKE_WAREHOUSE",
                "PII_INGESTOR_SNOWFLAKE_DATABASE",
                "PII_INGESTOR_SNOWFLAKE_SCHEMA",
            )
            if getattr(settings, name) is None
        ]
        if missing:
            raise ValueError(
                f"WAREHOUSE_TYPE=snowflake requires {', '.join(missing)} to be set"
            )
        return SnowflakeService(
            account=settings.PII_INGESTOR_SNOWFLAKE_ACCOUNT,
            user=settings.PII_INGESTOR_SNOWFLAKE_USER,
            password=settings.PII_INGESTOR_SNOWFLAKE_PASSWORD,
            role=settings.PII_INGESTOR_SNOWFLAKE_ROLE,
            warehouse=settings.PII_INGESTOR_SNOWFLAKE_WAREHOUSE,
            database=settings.PII_INGESTOR_SNOWFLAKE_DATABASE,
            schema=settings.PII_INGESTOR_SNOWFLAKE_SCHEMA,
        )

    return BigQueryService(
        project_id or settings.GOOGLE_CLOUD_PROJECT,
        dataset_id or settings.BIGQUERY_DATASET,
    )

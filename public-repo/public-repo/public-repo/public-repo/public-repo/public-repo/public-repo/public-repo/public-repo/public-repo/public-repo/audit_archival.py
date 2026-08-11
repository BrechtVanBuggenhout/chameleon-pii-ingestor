import logging
from google.cloud import bigquery
from app.config import settings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("AuditArchival")

def archive_lineage_to_gcs():
    """
    Automates the export of lineage events from BigQuery to GCS Audit Bucket.
    Target: gs://chameleon-audit-logs-{project_id}/lineage_exports/
    """
    client = bigquery.Client(project=settings.GOOGLE_CLOUD_PROJECT)
    
    # Define the source table and destination URI
    project = settings.GOOGLE_CLOUD_PROJECT
    dataset = "lineage_db" # As per GCP_INFRASTRUCTURE.md
    table = "events"
    
    # Construct destination GCS URI with timestamp-based prefix
    # In production, this would likely be a partitioned export
    destination_uri = f"gs://chameleon-audit-logs-{project}/lineage_exports/audit_{{}}.jsonl"
    
    dataset_ref = client.dataset(dataset, project=project)
    table_ref = dataset_ref.table(table)
    
    logger.info(f"📤 Starting export: {project}.{dataset}.{table} -> {destination_uri}")

    job_config = bigquery.ExtractJobConfig()
    job_config.destination_format = "NEWLINE_DELIMITED_JSON"

    try:
        extract_job = client.extract_table(
            table_ref,
            destination_uri.format("latest"),
            job_config=job_config,
            location="US", # Must match BQ dataset location
        )
        
        extract_job.result()  # Wait for job to complete
        logger.info(f"✅ Export completed successfully. Check the GCS audit bucket.")
        
    except Exception as e:
        logger.error(f"❌ Export failed: {e}")
        raise

if __name__ == "__main__":
    archive_lineage_to_gcs()
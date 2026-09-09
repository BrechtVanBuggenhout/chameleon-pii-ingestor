from google.cloud import bigquery
import logging
from typing import List, Dict, Any

class BigQueryService:
    def __init__(self, project_id: str, dataset_id: str):
        self.client = bigquery.Client(project=project_id)
        self.dataset_id = dataset_id
        self.logger = logging.getLogger(__name__)

    def load_records(self, table_id: str, records: List[Dict[str, Any]]):
        """
        Loads a list of dicts into BigQuery using the load_table_from_json method.
        """
        table_ref = f"{self.client.project}.{self.dataset_id}.{table_id}"
        
        job_config = bigquery.LoadJobConfig(
            source_format=bigquery.SourceFormat.NEWLINE_DELIMITED_JSON,
            write_disposition=bigquery.WriteDisposition.WRITE_APPEND,
        )

        try:
            load_job = self.client.load_table_from_json(records, table_ref, job_config=job_config)
            load_job.result() # Wait for completion
            self.logger.info(f"Successfully loaded {len(records)} records into {table_ref}")
        except Exception as e:
            self.logger.error(f"Failed to load data to BigQuery: {e}")
            raise
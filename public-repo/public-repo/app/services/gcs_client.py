from google.cloud import storage
import logging
import os

class GCSService:
    def __init__(self, project_id: str):
        self.client = storage.Client(project=project_id)
        self.logger = logging.getLogger(__name__)

    def download_to_local(self, gcs_uri: str, local_path: str):
        """
        Downloads a blob from GCS to a local temporary path.
        Expects format: gs://bucket-name/path/to/file.csv
        """
        if not gcs_uri.startswith("gs://"):
            raise ValueError(f"Invalid GCS URI: {gcs_uri}. Must start with 'gs://'")
        
        path_parts = gcs_uri.replace("gs://", "").split("/", 1)
        bucket_name = path_parts[0]
        blob_name = path_parts[1]

        bucket = self.client.bucket(bucket_name)
        blob = bucket.blob(blob_name)
        blob.download_to_filename(local_path)
        self.logger.info(f"Downloaded {gcs_uri} to {local_path}")
import time
import logging
from google.cloud import storage
from app.pipelines.ingestion import IngestionPipeline
from app.config import settings

logger = logging.getLogger(__name__)

class GCSLandingZoneMonitor:
    def __init__(self, pipeline: IngestionPipeline, bucket_name: str, resource_id: str = None):
        self.pipeline = pipeline
        self.bucket_name = bucket_name
        # Identifies which PII registry declaration bulk file drops belong to
        # (see IngestionPipeline._resolve_registry_resource) -- None falls
        # back to the legacy email-only behavior, same as an undeclared
        # resource always has.
        self.resource_id = resource_id
        self.storage_client = storage.Client(project=settings.GOOGLE_CLOUD_PROJECT)

    def poll_once(self):
        """Checks the bucket for new files and processes them."""
        bucket = self.storage_client.bucket(self.bucket_name)
        # We only look for files in the 'inbound/' prefix
        blobs = bucket.list_blobs(prefix="inbound/")

        for blob in blobs:
            if blob.name.endswith('/') or not (blob.name.endswith('.csv') or blob.name.endswith('.json')):
                continue

            gcs_uri = f"gs://{self.bucket_name}/{blob.name}"
            logger.info(f"Detected new file: {gcs_uri}. Starting ingestion.")
            
            try:
                self.pipeline.process_file(gcs_uri, resource_id=self.resource_id)
                # Delete the source file outright rather than renaming it to
                # 'processed/' -- this file is a plaintext PII source (that's
                # the whole point of it), and keeping it around forever meant
                # destroying a user's key did nothing to this copy. The
                # DATA_READ lineage event process_file() already publishes
                # (source URI + row count, no content) is the durable record
                # that this file was ingested; the file itself doesn't need
                # to survive past a successful encrypt-and-publish.
                blob.delete()
                logger.info(f"Successfully processed and deleted: {gcs_uri}")
            except Exception as e:
                logger.error(f"Critical failure processing {gcs_uri}: {e}")
                # Kept in 'failed/' for debugging, not deleted immediately --
                # but it's still a plaintext PII file, so it isn't kept
                # forever either: see the landing_zone lifecycle rule in
                # chameleon-infra-gcp/storage.tf, which expires anything
                # still in failed/ after a short window.
                failed_name = blob.name.replace("inbound/", "failed/")
                bucket.rename_blob(blob, failed_name)
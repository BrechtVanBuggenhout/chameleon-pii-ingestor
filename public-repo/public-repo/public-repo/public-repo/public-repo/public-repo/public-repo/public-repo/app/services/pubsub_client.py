import json
import logging
from google.cloud import pubsub_v1
from typing import Any, Dict

logger = logging.getLogger(__name__)

class PubSubService:
    def __init__(self, project_id: str, topic_id: str):
        self.publisher = pubsub_v1.PublisherClient()
        self.topic_path = self.publisher.topic_path(project_id, topic_id)

    def publish_failed_wipe(self, user_id: str, system: str, error: str):
        """
        Publishes a failed wipe event to the Janitor DLQ.
        The push subscription handles streaming this into BigQuery.
        """
        payload = {
            "userId": user_id,
            "system": system,
            "error": error,
            "retry_exhausted": True
        }
        data = json.dumps(payload).encode("utf-8")
        try:
            future = self.publisher.publish(self.topic_path, data)
            future.result()  # Ensure publish succeeds
            logger.info(f"Published failure for {user_id} in {system} to DLQ")
        except Exception as e:
            logger.error(f"Failed to publish to DLQ: {e}")
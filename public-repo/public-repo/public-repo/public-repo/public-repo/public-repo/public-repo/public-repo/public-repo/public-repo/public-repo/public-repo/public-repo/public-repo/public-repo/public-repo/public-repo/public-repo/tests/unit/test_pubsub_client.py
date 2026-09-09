import pytest
from unittest.mock import MagicMock, patch
from app.services.pubsub_client import PubSubService

@patch("google.cloud.pubsub_v1.PublisherClient")
def test_publish_failed_wipe(mock_publisher_class):
    """Verifies that the client correctly publishes payloads to Pub/Sub."""
    mock_publisher = mock_publisher_class.return_value
    mock_publisher.topic_path.return_value = "projects/p/topics/t"
    
    service = PubSubService(project_id="p", topic_id="t")
    
    service.publish_failed_wipe(
        user_id="user1", 
        system="hubspot", 
        error="403 Forbidden"
    )
    
    # Verify publish was called with a bytes payload
    assert mock_publisher.publish.called
    args, kwargs = mock_publisher.publish.call_args
    assert b"user1" in args[1]
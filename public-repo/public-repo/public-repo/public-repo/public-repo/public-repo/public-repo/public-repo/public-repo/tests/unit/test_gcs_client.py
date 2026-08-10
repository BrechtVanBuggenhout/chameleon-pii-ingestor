import pytest
from unittest.mock import MagicMock, patch
from app.services.gcs_client import GCSService

@patch("google.cloud.storage.Client")
def test_download_to_local_invalid_uri(mock_storage_client):
    service = GCSService(project_id="test-project")
    with pytest.raises(ValueError, match="Invalid GCS URI"):
        service.download_to_local("s3://bucket/file.csv", "/tmp/local.csv")

@patch("google.cloud.storage.Client")
def test_download_to_local_success(mock_storage_client):
    mock_bucket = MagicMock()
    mock_blob = MagicMock()
    mock_storage_client.return_value.bucket.return_value = mock_bucket
    mock_bucket.blob.return_value = mock_blob
    
    service = GCSService(project_id="test-project")
    gcs_uri = "gs://test-bucket/path/to/file.csv"
    local_path = "/tmp/local.csv"
    service.download_to_local(gcs_uri, local_path)
    
    mock_storage_client.return_value.bucket.assert_called_with("test-bucket")
    mock_bucket.blob.assert_called_with("path/to/file.csv")
    mock_blob.download_to_filename.assert_called_with(local_path)
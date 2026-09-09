import pytest
from unittest.mock import MagicMock, patch
from app.services.bigquery_client import BigQueryService

@patch("google.cloud.bigquery.Client")
def test_load_records_success(mock_bq_client):
    mock_client_instance = mock_bq_client.return_value
    mock_client_instance.project = "test-project"
    
    service = BigQueryService(project_id="test-project", dataset_id="test-dataset")
    records = [{"userId": "1", "data": "abc"}]
    
    # Mock the load job
    mock_job = MagicMock()
    mock_client_instance.load_table_from_json.return_value = mock_job
    
    service.load_records("test-table", records)
    
    mock_client_instance.load_table_from_json.assert_called_once()
    args, kwargs = mock_client_instance.load_table_from_json.call_args
    assert args[0] == records
    assert args[1] == "test-project.test-dataset.test-table"
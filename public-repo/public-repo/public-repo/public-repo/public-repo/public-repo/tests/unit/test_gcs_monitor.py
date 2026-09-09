from unittest.mock import MagicMock, patch
from app.services.gcs_monitor import GCSLandingZoneMonitor


def _make_blob(name):
    blob = MagicMock()
    blob.name = name
    return blob


def _make_monitor(blobs, resource_id=None):
    pipeline = MagicMock()
    with patch("app.services.gcs_monitor.storage.Client") as mock_client_cls:
        mock_client = mock_client_cls.return_value
        mock_bucket = mock_client.bucket.return_value
        mock_bucket.list_blobs.return_value = blobs
        monitor = GCSLandingZoneMonitor(pipeline=pipeline, bucket_name="test-bucket", resource_id=resource_id)
    return monitor, pipeline, mock_bucket


def test_passes_configured_resource_id_through_to_process_file():
    """Bulk file drops must be attributable to a specific PII registry
    declaration (see IngestionPipeline._resolve_registry_resource) so the
    N-field encryption path can find it -- not just always fall back to
    email-only."""
    blob = _make_blob("inbound/signups.csv")
    monitor, pipeline, _bucket = _make_monitor([blob], resource_id="bigquery:proj.dataset.raw_users")

    monitor.poll_once()

    pipeline.process_file.assert_called_once_with(
        "gs://test-bucket/inbound/signups.csv", resource_id="bigquery:proj.dataset.raw_users"
    )


def test_successful_file_is_deleted_not_retained():
    """A successfully processed file must not be kept anywhere -- it's a
    plaintext PII source, and the whole point of crypto-shredding breaks if
    a permanent copy survives ingestion. This is a real regression test:
    the previous behavior renamed the file to 'processed/' and kept it
    forever."""
    blob = _make_blob("inbound/signups.csv")
    monitor, pipeline, bucket = _make_monitor([blob])

    monitor.poll_once()

    pipeline.process_file.assert_called_once_with("gs://test-bucket/inbound/signups.csv", resource_id=None)
    blob.delete.assert_called_once()
    bucket.rename_blob.assert_not_called()


def test_failed_file_is_moved_to_failed_prefix_not_deleted():
    """Failures still get a debuggable copy -- but only failures, and only
    via rename (bounded by the failed/ lifecycle rule in storage.tf), never
    a permanent, unbounded retention like the old 'processed/' behavior."""
    blob = _make_blob("inbound/bad.csv")
    monitor, pipeline, bucket = _make_monitor([blob])
    pipeline.process_file.side_effect = ValueError("boom")

    monitor.poll_once()

    blob.delete.assert_not_called()
    bucket.rename_blob.assert_called_once_with(blob, "failed/bad.csv")


def test_skips_non_data_files_and_directory_markers():
    good = _make_blob("inbound/signups.json")
    directory_marker = _make_blob("inbound/")
    wrong_ext = _make_blob("inbound/readme.txt")
    monitor, pipeline, bucket = _make_monitor([good, directory_marker, wrong_ext])

    monitor.poll_once()

    pipeline.process_file.assert_called_once_with("gs://test-bucket/inbound/signups.json", resource_id=None)
    good.delete.assert_called_once()
    directory_marker.delete.assert_not_called()
    wrong_ext.delete.assert_not_called()

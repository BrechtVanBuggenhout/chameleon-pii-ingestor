import pytest
import pandas as pd
import os
import tempfile
import base64
import io
import json
from unittest.mock import MagicMock, patch
import hashlib
import hmac
from fastavro import schemaless_reader
from app.pipelines.ingestion import IngestionPipeline, LINEAGE_SCHEMA, USER_SCHEMA

@pytest.fixture
def mock_services():
    return {
        "vault": MagicMock(),
        "publisher": MagicMock(),
        "gcs": MagicMock()
    }

@pytest.fixture
def pipeline(mock_services):
    return IngestionPipeline(
        vault=mock_services["vault"],
        topic_id="test-topic",
        lineage_topic_id="test-lineage-topic",
        gcs_service=mock_services["gcs"],
        publisher=mock_services["publisher"]
    )

def test_process_invalid_extension(pipeline):
    """Ensures the pipeline rejects unsupported file types."""
    with pytest.raises(ValueError, match="Unsupported file format"):
        pipeline.process_file("data.txt")

def test_process_missing_columns(pipeline):
    """Ensures the pipeline fails gracefully when required PII columns are missing."""
    # Create a CSV missing 'email'
    df = pd.DataFrame({"userId": ["user_1"], "age": [30]})
    with tempfile.NamedTemporaryFile(suffix=".csv", mode="w", delete=False) as f:
        df.to_csv(f.name, index=False)
        temp_path = f.name

    try:
        with pytest.raises(ValueError, match="Missing columns"):
            pipeline.process_file(temp_path)
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

def test_gcs_cleanup_on_failure(pipeline, mock_services):
    """Verifies that temporary files are deleted even if ingestion fails."""
    mock_services["gcs"].download_to_local.side_effect = lambda uri, path: open(path, 'w').write("not,a,valid,csv")
    
    # This will fail during pd.read_csv or column validation
    with patch("os.remove") as mock_remove:
        with pytest.raises(Exception):
            pipeline.process_file("gs://bucket/bad_data.csv")
        
        # Ensure cleanup was attempted
        mock_remove.assert_called()

def test_successful_json_ingestion(pipeline, mock_services):
    """Verifies that newline-delimited JSON is processed correctly."""
    mock_services["vault"].get_encryption_context.return_value = {
        "dek": "a" * 64,
        "key_id": "key-test",
        "encryption_version": "v2",
        "status": "ACTIVE",
        # The real Key Vault always sends this (it's a label, e.g.
        # "chameleon-token-key-v1", never actual key material) -- a mock
        # that omits it hides the bug where the pipeline used to try
        # bytes.fromhex() on that label instead of falling back to the DEK.
        "token_key_id": "chameleon-token-key-v1",
    }

    # Create mock NDJSON
    data = '{"user_id": "u1", "email": "a@b.com"}\n{"user_id": "u2", "email": "c@d.com"}'
    with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
        f.write(data)
        temp_path = f.name

    try:
        mock_encrypted = base64.b64encode(b"iv_prefix_12b" + b"ciphertext").decode()
        with patch("app.core.crypto.ChameleonCrypto.encrypt", return_value=mock_encrypted):
            pipeline.process_file(temp_path)

        # 2 records plus batch-level and per-user lineage messages
        assert mock_services["publisher"].publish.call_count == 6
        mock_services["vault"].batch_create_keys.assert_called_once_with(["u1", "u2"])
        mock_services["vault"].batch_get_encryption_contexts.assert_called_once_with(["u1", "u2"])

        # Decode the two actual data-record publishes (not the lineage ones)
        # and confirm email_token is a real HMAC-SHA256(DEK, email) digest --
        # this is what silently broke when token_key_id was used as the key.
        expected_token = hmac.new(bytes.fromhex("a" * 64), "a@b.com".encode(), hashlib.sha256).hexdigest()
        data_calls = [
            call for call in mock_services["publisher"].publish.call_args_list
            if call.args[0] == "test-topic"
        ]
        assert len(data_calls) == 2
        decoded = schemaless_reader(io.BytesIO(data_calls[0].args[1]), USER_SCHEMA)
        assert decoded["email_token"] == expected_token
        assert decoded["email_token"] == decoded["data_hash"]

    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

def _registry_api_response(resource_id, pii_fields):
    return {
        "resources": [
            {
                "resourceId": resource_id,
                "piiFields": pii_fields,
            }
        ]
    }

def test_declared_multi_field_resource_encrypts_every_field(pipeline, mock_services):
    """A resource declared with more than one ENCRYPT field (email + phone)
    must get every one encrypted+tokenized into pii_fields, not just email --
    this is the whole point of generalizing beyond the old hardcoded single
    field. email_token/encrypted_pii must still populate too, unchanged, for
    backward compatibility with anything already reading those two columns."""
    mock_services["vault"].get_encryption_context.return_value = {
        "dek": "a" * 64,
        "key_id": "key-test",
        "encryption_version": "v2",
    }
    mock_services["vault"].fetch_pii_registry_resources.return_value = _registry_api_response(
        "bigquery:proj.dataset.raw_users",
        [
            {"name": "email", "classification": "DIRECT_IDENTIFIER", "handling": "ENCRYPT"},
            {"name": "phone", "classification": "DIRECT_IDENTIFIER", "handling": "ENCRYPT"},
        ],
    )

    data = '{"user_id": "u1", "email": "a@b.com", "phone": "+15551234567"}'
    with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
        f.write(data)
        temp_path = f.name

    try:
        mock_encrypted = base64.b64encode(b"iv_prefix_12b" + b"ciphertext").decode()
        with patch("app.core.crypto.ChameleonCrypto.encrypt", return_value=mock_encrypted):
            pipeline.process_file(temp_path, resource_id="bigquery:proj.dataset.raw_users")

        data_calls = [
            call for call in mock_services["publisher"].publish.call_args_list
            if call.args[0] == "test-topic"
        ]
        assert len(data_calls) == 1
        decoded = schemaless_reader(io.BytesIO(data_calls[0].args[1]), USER_SCHEMA)

        expected_email_token = hmac.new(bytes.fromhex("a" * 64), "a@b.com".encode(), hashlib.sha256).hexdigest()
        expected_phone_token = hmac.new(bytes.fromhex("a" * 64), "+15551234567".encode(), hashlib.sha256).hexdigest()

        # Legacy columns still populated (backward compat)
        assert decoded["email_token"] == expected_email_token

        # New general column carries both declared fields
        assert {f["field_name"] for f in decoded["pii_fields"]} == {"email", "phone"}
        by_name = {f["field_name"]: f for f in decoded["pii_fields"]}
        assert by_name["email"]["token"] == expected_email_token
        assert by_name["phone"]["token"] == expected_phone_token
        assert len(by_name["phone"]["encrypted_value"]) > 0
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

def test_undeclared_resource_falls_back_to_email_only(pipeline, mock_services):
    """A resource with no registry declaration (or a registry lookup that
    fails) must behave exactly like today for every existing deployment --
    email-only -- not silently break or silently under-protect."""
    mock_services["vault"].get_encryption_context.return_value = {
        "dek": "a" * 64,
        "key_id": "key-test",
        "encryption_version": "v2",
    }
    mock_services["vault"].fetch_pii_registry_resources.side_effect = Exception("registry unreachable")

    data = '{"user_id": "u1", "email": "a@b.com"}'
    with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
        f.write(data)
        temp_path = f.name

    try:
        mock_encrypted = base64.b64encode(b"iv_prefix_12b" + b"ciphertext").decode()
        with patch("app.core.crypto.ChameleonCrypto.encrypt", return_value=mock_encrypted):
            # A resource_id is provided (as gcs_monitor.py always does), but
            # the registry lookup itself fails -- must still fall back cleanly.
            pipeline.process_file(temp_path, resource_id="bigquery:proj.dataset.raw_users")

        data_calls = [
            call for call in mock_services["publisher"].publish.call_args_list
            if call.args[0] == "test-topic"
        ]
        decoded = schemaless_reader(io.BytesIO(data_calls[0].args[1]), USER_SCHEMA)
        assert [f["field_name"] for f in decoded["pii_fields"]] == ["email"]
        assert decoded["email_token"] != ""
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

def test_row_missing_declared_field_is_skipped_not_partially_encrypted(pipeline, mock_services):
    """If a resource declares a field (phone) that's missing from a
    particular row, that row must be dropped entirely -- never published
    with only some of its declared PII fields protected."""
    mock_services["vault"].get_encryption_context.return_value = {
        "dek": "a" * 64,
        "key_id": "key-test",
        "encryption_version": "v2",
    }
    mock_services["vault"].fetch_pii_registry_resources.return_value = _registry_api_response(
        "bigquery:proj.dataset.raw_users",
        [
            {"name": "email", "classification": "DIRECT_IDENTIFIER", "handling": "ENCRYPT"},
            {"name": "phone", "classification": "DIRECT_IDENTIFIER", "handling": "ENCRYPT"},
        ],
    )

    # u1 has both fields; u2 is missing phone entirely (not just empty --
    # the column exists for u1's row so the file-level column check passes,
    # but pandas will produce NaN for u2's missing value).
    data = (
        '{"user_id": "u1", "email": "a@b.com", "phone": "+15551234567"}\n'
        '{"user_id": "u2", "email": "c@d.com"}'
    )
    with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
        f.write(data)
        temp_path = f.name

    try:
        mock_encrypted = base64.b64encode(b"iv_prefix_12b" + b"ciphertext").decode()
        with patch("app.core.crypto.ChameleonCrypto.encrypt", return_value=mock_encrypted):
            pipeline.process_file(temp_path, resource_id="bigquery:proj.dataset.raw_users")

        data_calls = [
            call for call in mock_services["publisher"].publish.call_args_list
            if call.args[0] == "test-topic"
        ]
        assert len(data_calls) == 1
        decoded = schemaless_reader(io.BytesIO(data_calls[0].args[1]), USER_SCHEMA)
        assert decoded["user_id"] == "u1"
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

def test_lineage_publish_uses_topic_avro_schema(pipeline, mock_services):
    """Lineage Pub/Sub bytes must match the infra-managed binary Avro schema."""
    future = pipeline._publish_lineage(
        user_id="u1",
        source="src",
        destination="dst",
        event_type="DATA_ENCRYPTED",
        operation_id="op-1",
        metadata={"key_id": "key-test"}
    )

    assert future == mock_services["publisher"].publish.return_value
    topic_id, avro_data = mock_services["publisher"].publish.call_args.args[:2]
    assert topic_id == "test-lineage-topic"

    decoded = schemaless_reader(io.BytesIO(avro_data), LINEAGE_SCHEMA)
    assert list(decoded.keys()) == [
        "event_id",
        "tenant_id",
        "user_id",
        "source",
        "destination",
        "timestamp",
        "context",
    ]
    assert decoded["tenant_id"] == "default"
    assert decoded["user_id"] == "u1"
    assert decoded["source"] == "src"
    assert decoded["destination"] == "dst"
    assert isinstance(decoded["timestamp"], int)
    assert decoded["timestamp"] > 0
    context = json.loads(decoded["context"])
    assert context == {
        "operation_id": "op-1",
        "event_type": "DATA_ENCRYPTED",
        "dataClassification": "PII",
        "key_id": "key-test",
    }

def test_lineage_context_redacts_raw_pii_metadata(pipeline, mock_services):
    pipeline._publish_lineage(
        user_id="u1",
        source="src",
        destination="dst",
        event_type="DATA_ENRICHED",
        operation_id="op-1",
        metadata={
            "email": "leaked@example.com",
            "phone_number": "+1 415 555 0100",
            "record_count": 1,
            "nested": {"plaintext": "secret"},
        }
    )

    avro_data = mock_services["publisher"].publish.call_args.args[1]
    decoded = schemaless_reader(io.BytesIO(avro_data), LINEAGE_SCHEMA)
    context = json.loads(decoded["context"])
    assert context["email"] == "<redacted>"
    assert context["phone_number"] == "<redacted>"
    assert context["nested"]["plaintext"] == "<redacted>"
    assert context["record_count"] == 1
    assert "leaked@example.com" not in decoded["context"]

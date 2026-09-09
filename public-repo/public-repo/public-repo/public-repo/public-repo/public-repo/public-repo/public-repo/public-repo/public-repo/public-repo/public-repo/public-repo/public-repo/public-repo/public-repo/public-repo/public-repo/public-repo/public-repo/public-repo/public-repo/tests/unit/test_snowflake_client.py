import base64
from unittest.mock import MagicMock, patch

from app.services.snowflake_client import SnowflakeService


@patch("snowflake.connector.connect")
def test_load_records_success(mock_connect):
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
    mock_conn.is_closed.return_value = False
    mock_connect.return_value = mock_conn

    service = SnowflakeService(
        account="XY12345-AB67890",
        user="test_user",
        password="test_password",
        role="test_role",
        warehouse="test_warehouse",
        database="test_database",
        schema="test_schema",
    )
    records = [{"user_id": "1", "tenant_id": "default-tenant"}]

    service.load_records("raw_users", records)

    mock_connect.assert_called_once_with(
        account="XY12345-AB67890",
        user="test_user",
        password="test_password",
        role="test_role",
        warehouse="test_warehouse",
        database="test_database",
        schema="test_schema",
    )
    mock_cursor.executemany.assert_called_once()
    sql, rows = mock_cursor.executemany.call_args.args
    assert "test_database.test_schema.raw_users" in sql
    assert rows == [("1", "default-tenant")]


@patch("snowflake.connector.connect")
def test_load_records_decodes_base64_encrypted_pii_to_bytes(mock_connect):
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
    mock_conn.is_closed.return_value = False
    mock_connect.return_value = mock_conn

    service = SnowflakeService(
        account="acct",
        user="user",
        password="pw",
        warehouse="wh",
        database="db",
        schema="schema",
    )
    plaintext_ciphertext = b"\x01\x02\x03fake-ciphertext"
    b64_value = base64.b64encode(plaintext_ciphertext).decode("utf-8")
    records = [{"user_id": "1", "encrypted_pii": b64_value}]

    service.load_records("raw_users", records)

    _, rows = mock_cursor.executemany.call_args.args
    assert rows == [("1", plaintext_ciphertext)]


@patch("snowflake.connector.connect")
def test_load_records_noop_on_empty_batch(mock_connect):
    service = SnowflakeService(
        account="acct", user="user", password="pw", warehouse="wh", database="db", schema="schema"
    )
    service.load_records("raw_users", [])
    mock_connect.assert_not_called()


@patch("snowflake.connector.connect")
def test_reuses_connection_across_calls(mock_connect):
    mock_conn = MagicMock()
    mock_conn.cursor.return_value.__enter__.return_value = MagicMock()
    mock_conn.is_closed.return_value = False
    mock_connect.return_value = mock_conn

    service = SnowflakeService(
        account="acct", user="user", password="pw", warehouse="wh", database="db", schema="schema"
    )
    service.load_records("raw_users", [{"user_id": "1"}])
    service.load_records("raw_users", [{"user_id": "2"}])

    mock_connect.assert_called_once()

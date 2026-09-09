import base64
import logging
from typing import Any, Dict, List, Optional

import snowflake.connector


class SnowflakeService:
    """
    Same role as BigQueryService: lands ingested records into the raw landing
    table. Records arrive with `encrypted_pii` as a base64 string (the same
    convention BigQueryService relies on for its BYTES column) -- decoded back
    to raw bytes here and bound to a BINARY column instead.
    """

    def __init__(
        self,
        account: str,
        user: str,
        password: str,
        warehouse: str,
        database: str,
        schema: str,
        role: Optional[str] = None,
    ):
        self.database = database
        self.schema = schema
        self._connect_kwargs = dict(
            account=account,
            user=user,
            password=password,
            role=role,
            warehouse=warehouse,
            database=database,
            schema=schema,
        )
        self._conn: Optional[snowflake.connector.SnowflakeConnection] = None
        self.logger = logging.getLogger(__name__)

    def _connection(self) -> snowflake.connector.SnowflakeConnection:
        if self._conn is None or self._conn.is_closed():
            self._conn = snowflake.connector.connect(**self._connect_kwargs)
        return self._conn

    def load_records(self, table_id: str, records: List[Dict[str, Any]]):
        """
        Batch-inserts a list of dicts into a Snowflake table. Column list is
        derived from the first record's keys, matching BigQuery's
        load_table_from_json tolerance for partial/heterogeneous-by-batch
        JSON shapes (both current callers pass single-record batches).
        """
        if not records:
            return

        # pii_fields (the general N-declared-PII-field array, see
        # ingestion.py) has no Snowflake DDL anywhere in this codebase --
        # unlike BigQuery, Snowflake schema here is entirely customer/ops-
        # managed out-of-band. Excluding it keeps every existing Snowflake
        # deployment working unchanged; a customer who wants it surfaced
        # needs to add a matching column (e.g. VARIANT) and this exclusion
        # removed/adjusted for their instance.
        columns = [key for key in records[0].keys() if key != "pii_fields"]
        rows = [self._coerce_row(record, columns) for record in records]

        placeholders = ", ".join(["%s"] * len(columns))
        column_list = ", ".join(columns)
        table_ref = f"{self.database}.{self.schema}.{table_id}"
        insert_sql = f"INSERT INTO {table_ref} ({column_list}) VALUES ({placeholders})"

        try:
            conn = self._connection()
            with conn.cursor() as cur:
                cur.executemany(insert_sql, rows)
            self.logger.info(f"Successfully loaded {len(records)} records into {table_ref}")
        except Exception as e:
            self.logger.error(f"Failed to load data to Snowflake: {e}")
            raise

    @staticmethod
    def _coerce_row(record: Dict[str, Any], columns: List[str]) -> tuple:
        row = []
        for col in columns:
            value = record.get(col)
            if col == "encrypted_pii" and isinstance(value, str):
                value = base64.b64decode(value)
            row.append(value)
        return tuple(row)

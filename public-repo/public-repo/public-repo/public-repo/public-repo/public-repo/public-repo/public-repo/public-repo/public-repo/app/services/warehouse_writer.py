from typing import Any, Dict, List, Protocol


class WarehouseWriter(Protocol):
    """Shared contract between BigQueryService and SnowflakeService."""

    def load_records(self, table_id: str, records: List[Dict[str, Any]]) -> None: ...

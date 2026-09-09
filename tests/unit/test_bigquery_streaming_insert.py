import pytest
from google.api_core.exceptions import TooManyRequests

from app.services.bigquery_streaming_insert import insert_with_retry


class FakeBigQueryClient:
    def __init__(self):
        self.insert_calls: list[tuple[str, list]] = []

    def insert_rows_json(self, table_ref, records):
        self.insert_calls.append((table_ref, records))
        return []


class FlakyBigQueryClient(FakeBigQueryClient):
    def __init__(self, raise_count=0):
        super().__init__()
        self._raise_count = raise_count
        self.attempts = 0

    def insert_rows_json(self, table_ref, records):
        self.attempts += 1
        if self.attempts <= self._raise_count:
            raise TooManyRequests("Exceeded rate limits: too many table update operations for this table.")
        return super().insert_rows_json(table_ref, records)


class ErroringBigQueryClient(FakeBigQueryClient):
    def insert_rows_json(self, table_ref, records):
        return [{"index": 0, "errors": [{"reason": "invalid", "message": "bad row"}]}]


class TestInsertWithRetry:
    def test_streams_records_into_the_given_table_ref(self):
        bq = FakeBigQueryClient()
        insert_with_retry(bq, "proj.ds.table", [{"a": 1}])
        assert bq.insert_calls == [("proj.ds.table", [{"a": 1}])]

    def test_retries_a_rate_limited_insert_and_eventually_succeeds(self, monkeypatch):
        monkeypatch.setattr("app.services.bigquery_streaming_insert.time.sleep", lambda _s: None)
        bq = FlakyBigQueryClient(raise_count=2)
        insert_with_retry(bq, "proj.ds.table", [{"a": 1}], max_retries=5, base_backoff_seconds=2)
        assert bq.attempts == 3
        assert bq.insert_calls == [("proj.ds.table", [{"a": 1}])]

    def test_re_raises_once_retries_are_exhausted(self, monkeypatch):
        monkeypatch.setattr("app.services.bigquery_streaming_insert.time.sleep", lambda _s: None)
        bq = FlakyBigQueryClient(raise_count=5)
        with pytest.raises(TooManyRequests):
            insert_with_retry(bq, "proj.ds.table", [{"a": 1}], max_retries=5)
        assert bq.attempts == 5
        assert bq.insert_calls == []

    def test_does_not_sleep_at_all_when_the_first_attempt_succeeds(self, monkeypatch):
        sleep_calls = []
        monkeypatch.setattr("app.services.bigquery_streaming_insert.time.sleep", lambda s: sleep_calls.append(s))
        bq = FlakyBigQueryClient(raise_count=0)
        insert_with_retry(bq, "proj.ds.table", [{"a": 1}])
        assert sleep_calls == []

    def test_raises_immediately_on_a_real_row_error_without_retrying(self):
        bq = ErroringBigQueryClient()
        with pytest.raises(RuntimeError, match="row errors"):
            insert_with_retry(bq, "proj.ds.table", [{"a": 1}])

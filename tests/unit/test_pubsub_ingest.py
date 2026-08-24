import base64

import pytest

from app.pipelines.pubsub_ingest import (
    CallerNotAuthorized,
    IngestOutcome,
    PubsubIngestPipeline,
    resolve_field_path,
)


class TestResolveFieldPath:
    def test_resolves_a_top_level_field(self):
        assert resolve_field_path({"email": "a@example.com"}, "email") == "a@example.com"

    def test_resolves_a_nested_dotted_path(self):
        payload = {"after": {"user_id": "u1", "email": "a@example.com"}}
        assert resolve_field_path(payload, "after.email") == "a@example.com"

    def test_resolves_a_deeply_nested_path(self):
        payload = {"payload": {"after": {"email": "a@example.com"}}}
        assert resolve_field_path(payload, "payload.after.email") == "a@example.com"

    def test_returns_none_for_a_missing_segment(self):
        payload = {"after": {"user_id": "u1"}}
        assert resolve_field_path(payload, "after.email") is None

    def test_returns_none_when_an_intermediate_segment_is_not_a_dict(self):
        # e.g. a DELETE event where "after" is null, not an object.
        payload = {"after": None}
        assert resolve_field_path(payload, "after.email") is None

    def test_returns_none_for_a_completely_missing_top_level_key(self):
        assert resolve_field_path({}, "after.email") is None


class FakeVault:
    def __init__(self, resource_data=None, contexts=None, tenant_id="acme", fetch_raises=None):
        self._resource_data = resource_data
        self._contexts = contexts or {}
        self.tenant_id = tenant_id
        self._fetch_raises = fetch_raises
        self.create_keys_calls: list[list[str]] = []
        self.fetch_calls: list[str] = []

    def fetch_pii_registry_resource(self, resource_id):
        self.fetch_calls.append(resource_id)
        if self._fetch_raises:
            raise self._fetch_raises
        if self._resource_data is None:
            return {}
        return {"resource": self._resource_data}

    def batch_create_keys(self, user_ids):
        self.create_keys_calls.append(list(user_ids))

    def get_encryption_context(self, user_id):
        return self._contexts[user_id]


class FakeBigQueryClient:
    def __init__(self):
        self.insert_calls: list[tuple[str, list]] = []

    def insert_rows_json(self, table_ref, records):
        self.insert_calls.append((table_ref, records))
        return []


PUBSUB_RESOURCE = {
    "resourceId": "pubsub:acme-project.cdc-events",
    "system": "pubsub",
    "pubsubAllowedCallerServiceAccount": "123456789012345678901",
    "userIdFieldPath": "after.user_id",
    "piiFields": [
        {"name": "after.email", "classification": "DIRECT_IDENTIFIER", "handling": "ENCRYPT"},
        {"name": "after.internal_id", "classification": "SYSTEM_IDENTIFIER", "handling": "HASH_SURROGATE"},
    ],
}


def make_pipeline(vault, bq=None):
    return PubsubIngestPipeline(
        vault=vault,
        bigquery_client=bq or FakeBigQueryClient(),
        vault_project_id="proj",
        vault_dataset_id="chameleon",
    )


class TestResolveResource:
    def test_resolves_a_declared_pubsub_resource(self):
        vault = FakeVault(resource_data=PUBSUB_RESOURCE)
        pipeline = make_pipeline(vault)

        resource = pipeline.resolve_resource("pubsub:acme-project.cdc-events")

        assert resource.system == "pubsub"
        assert resource.pubsub_allowed_caller_service_account == "123456789012345678901"
        assert vault.fetch_calls == ["pubsub:acme-project.cdc-events"]

    def test_raises_when_the_resource_is_not_declared_at_all(self):
        vault = FakeVault(resource_data=None)
        pipeline = make_pipeline(vault)

        with pytest.raises(CallerNotAuthorized):
            pipeline.resolve_resource("pubsub:gone")

    def test_raises_when_the_resource_exists_but_is_not_system_pubsub(self):
        vault = FakeVault(resource_data={**PUBSUB_RESOURCE, "system": "bigquery", "resourceId": "bigquery:x.y.z"})
        pipeline = make_pipeline(vault)

        with pytest.raises(CallerNotAuthorized):
            pipeline.resolve_resource("bigquery:x.y.z")

    def test_raises_when_the_registry_lookup_itself_fails(self):
        vault = FakeVault(fetch_raises=RuntimeError("Key Vault unreachable"))
        pipeline = make_pipeline(vault)

        with pytest.raises(CallerNotAuthorized):
            pipeline.resolve_resource("pubsub:acme-project.cdc-events")


class TestAuthorizeCaller:
    def test_accepts_a_matching_caller(self):
        vault = FakeVault(resource_data=PUBSUB_RESOURCE)
        pipeline = make_pipeline(vault)
        resource = pipeline.resolve_resource("pubsub:acme-project.cdc-events")

        pipeline.authorize_caller(resource, "123456789012345678901")  # does not raise

    def test_rejects_a_mismatched_caller(self):
        vault = FakeVault(resource_data=PUBSUB_RESOURCE)
        pipeline = make_pipeline(vault)
        resource = pipeline.resolve_resource("pubsub:acme-project.cdc-events")

        with pytest.raises(CallerNotAuthorized):
            pipeline.authorize_caller(resource, "some-other-sub")

    def test_rejects_when_the_resource_has_no_allowed_caller_declared(self):
        vault = FakeVault(resource_data={**PUBSUB_RESOURCE, "pubsubAllowedCallerServiceAccount": None})
        pipeline = make_pipeline(vault)
        resource = pipeline.resolve_resource("pubsub:acme-project.cdc-events")

        with pytest.raises(CallerNotAuthorized):
            pipeline.authorize_caller(resource, "123456789012345678901")


class TestProcessMessage:
    def _context(self, key_id="v2"):
        return {"dek": "0" * 64, "key_id": key_id}

    def test_writes_a_pii_vault_row_per_declared_encrypt_field_found_in_the_message(self):
        vault = FakeVault(resource_data=PUBSUB_RESOURCE, contexts={"u1": self._context()})
        bq = FakeBigQueryClient()
        pipeline = make_pipeline(vault, bq)
        resource = pipeline.resolve_resource("pubsub:acme-project.cdc-events")
        message_body = {"after": {"user_id": "u1", "email": "a@example.com", "internal_id": "999"}}

        outcome = pipeline.process_message(resource, message_body)

        assert outcome == IngestOutcome(accepted=True, reason="ok", fields_written=1)
        assert vault.create_keys_calls == [["u1"]]
        assert len(bq.insert_calls) == 1
        table_ref, records = bq.insert_calls[0]
        assert table_ref == "proj.chameleon.pii_vault"
        assert len(records) == 1
        record = records[0]
        assert record["tenant_id"] == "acme"
        assert record["user_id"] == "u1"
        assert record["resource_id"] == "pubsub:acme-project.cdc-events"
        assert record["field_name"] == "after.email"
        assert record["key_id"] == "v2"
        assert isinstance(record["encrypted_value"], str)
        base64.b64decode(record["encrypted_value"])  # doesn't raise
        # HASH_SURROGATE field (internal_id) is never written -- only
        # ENCRYPT-handling fields are, matching every other write path.
        assert "internal_id" not in {r["field_name"] for r in records}

    def test_skips_a_message_missing_the_user_id_field_path(self):
        vault = FakeVault(resource_data=PUBSUB_RESOURCE)
        pipeline = make_pipeline(vault)
        resource = pipeline.resolve_resource("pubsub:acme-project.cdc-events")

        outcome = pipeline.process_message(resource, {"after": {"email": "a@example.com"}})

        assert outcome.accepted is False
        assert "userIdFieldPath" in outcome.reason
        assert vault.create_keys_calls == []

    def test_skips_a_message_with_no_declared_fields_present(self):
        vault = FakeVault(resource_data=PUBSUB_RESOURCE)
        pipeline = make_pipeline(vault)
        resource = pipeline.resolve_resource("pubsub:acme-project.cdc-events")

        # user_id present, but no declared PII field is -- e.g. a DELETE
        # event carrying only identifiers.
        outcome = pipeline.process_message(resource, {"after": {"user_id": "u1"}})

        assert outcome.accepted is False
        assert vault.create_keys_calls == []

    def test_raises_when_the_declaration_itself_has_no_user_id_field_path(self):
        vault = FakeVault(resource_data={**PUBSUB_RESOURCE, "userIdFieldPath": None})
        pipeline = make_pipeline(vault)
        resource = pipeline.resolve_resource("pubsub:acme-project.cdc-events")

        with pytest.raises(CallerNotAuthorized):
            pipeline.process_message(resource, {"after": {"user_id": "u1", "email": "a@example.com"}})

    def test_writes_one_row_per_field_when_multiple_declared_fields_are_present(self):
        resource_data = {
            **PUBSUB_RESOURCE,
            "piiFields": [
                {"name": "after.email", "classification": "DIRECT_IDENTIFIER", "handling": "ENCRYPT"},
                {"name": "after.phone", "classification": "CONTACT", "handling": "ENCRYPT"},
            ],
        }
        vault = FakeVault(resource_data=resource_data, contexts={"u1": self._context()})
        bq = FakeBigQueryClient()
        pipeline = make_pipeline(vault, bq)
        resource = pipeline.resolve_resource("pubsub:acme-project.cdc-events")

        outcome = pipeline.process_message(
            resource, {"after": {"user_id": "u1", "email": "a@example.com", "phone": "555-1234"}}
        )

        assert outcome.fields_written == 2
        _, records = bq.insert_calls[0]
        assert {r["field_name"] for r in records} == {"after.email", "after.phone"}

import pytest
from unittest.mock import MagicMock, patch
from app.services.vault_client import VaultClient

@pytest.fixture
def vault_client():
    kms_client = MagicMock()
    kms_client.decrypt.return_value = MagicMock(plaintext=b"a" * 32)
    client = VaultClient(
        base_url="http://mock-vault",
        tenant_id="tenant-a",
        cache_enabled=True,
        kms_client=kms_client,
    )
    return client

def test_get_encryption_context_cache_hit(vault_client):
    """Verifies that the client returns a cached context without making HTTP calls."""
    user_id = "user1"
    mock_context = {"dek": "cached_key", "encryption_version": "v2", "status": "ACTIVE"}
    vault_client._context_cache[user_id] = mock_context
    
    with patch.object(vault_client.session, 'get') as mock_get:
        context = vault_client.get_encryption_context(user_id)
        
        assert context["dek"] == "cached_key"
        mock_get.assert_not_called()

def test_get_encryption_context_cache_miss(vault_client):
    """Verifies that the client fetches context from the vault on a cache miss."""
    user_id = "user2"
    
    mock_res = MagicMock()
    mock_res.status_code = 200
    mock_res.json.return_value = {
        "user_id": user_id,
        "key_id": "key_abc",
            "dek": "bmV3X2Rlaw==",
            "encryption_version": "v2",
            "status": "ACTIVE"
    }
    
    with patch.object(vault_client.session, 'get', return_value=mock_res) as mock_get:
        context = vault_client.get_encryption_context(user_id)
        
        assert context["dek"] == ("61" * 32)
        assert vault_client._context_cache[user_id]["dek"] == ("61" * 32)
        assert mock_get.call_args.args[0] == "http://mock-vault/key/user2/encryption-context"

def test_get_encryption_context_shredded(vault_client):
    """Ensures context retrieval fails for shredded users."""
    mock_res = MagicMock()
    mock_res.status_code = 200
    mock_res.json.return_value = {"status": "SHREDDED", "dek": "bmV3X2Rlaw=="}
    
    with patch.object(vault_client.session, 'get', return_value=mock_res):
        with pytest.raises(ValueError, match="Cannot encrypt for shredded user"):
            vault_client.get_encryption_context("shredded_user")

def test_batch_get_encryption_contexts_uses_tenant_header_and_cache(vault_client):
    mock_res = MagicMock()
    mock_res.json.return_value = {
        "contexts": [
            {"userId": "user1", "keyId": "key1", "encryptedDek": "bmV3X2Rlaw==", "status": "ACTIVE"},
            {"userId": "user2", "keyId": "key2", "encryptedDek": "bmV3X2Rlaw==", "status": "ACTIVE"},
        ]
    }

    with patch.object(vault_client.session, 'post', return_value=mock_res) as mock_post:
        contexts = vault_client.batch_get_encryption_contexts(["user1", "user2"])

    assert set(contexts) == {"user1", "user2"}
    assert vault_client.session.headers["X-Tenant-Id"] == "tenant-a"
    assert mock_post.call_args.kwargs["json"]["tenantId"] == "tenant-a"
    assert mock_post.call_args.kwargs["json"]["userIds"] == ["user1", "user2"]

def test_batch_create_keys_caps_requests(vault_client):
    mock_res = MagicMock()
    mock_res.json.return_value = {"results": []}

    with patch.object(vault_client.session, 'post', return_value=mock_res) as mock_post:
        vault_client.batch_create_keys([f"user-{idx}" for idx in range(1001)])

    assert mock_post.call_count == 2
    assert len(mock_post.call_args_list[0].kwargs["json"]["userIds"]) == 1000
    assert len(mock_post.call_args_list[1].kwargs["json"]["userIds"]) == 1

def test_search_lineage_success(vault_client):
    """Verifies that lineage discovery returns the list of destinations."""
    mock_res = MagicMock()
    mock_res.status_code = 200
    mock_res.json.return_value = {"destinations": ["hubspot", "bigquery"]}
    
    with patch.object(vault_client.session, 'get', return_value=mock_res):
        destinations = vault_client.search_lineage("user123")
        
        assert destinations == ["hubspot", "bigquery"]

def test_fetch_pii_registry_resources_uses_contract_filters(vault_client):
    mock_res = MagicMock()
    mock_res.json.return_value = {"resources": [], "count": 0}

    with patch.object(vault_client.session, 'get', return_value=mock_res) as mock_get:
        data = vault_client.fetch_pii_registry_resources(system="bigquery", scan_enabled=True)

    assert data == {"resources": [], "count": 0}
    assert mock_get.call_args.args[0] == "http://mock-vault/pii-registry/resources"
    assert mock_get.call_args.kwargs["params"] == {
        "system": "bigquery",
        "scanEnabled": "true",
    }

def test_fetch_pii_registry_resource_url_encodes_resource_id(vault_client):
    mock_res = MagicMock()
    mock_res.json.return_value = {"resource": {"resourceId": "bigquery:project.dataset.table"}}

    with patch.object(vault_client.session, 'get', return_value=mock_res) as mock_get:
        data = vault_client.fetch_pii_registry_resource("bigquery:project.dataset.table")

    assert data["resource"]["resourceId"] == "bigquery:project.dataset.table"
    assert (
        mock_get.call_args.args[0]
        == "http://mock-vault/pii-registry/resources/bigquery%3Aproject.dataset.table"
    )

def test_mark_resource_synced_posts_the_watermark_to_the_url_encoded_resource(vault_client):
    mock_res = MagicMock()
    mock_res.json.return_value = {"resourceId": "bigquery:project.dataset.table", "lastSyncedAt": "2026-08-07T00:00:00+00:00"}

    with patch.object(vault_client.session, 'post', return_value=mock_res) as mock_post:
        data = vault_client.mark_resource_synced("bigquery:project.dataset.table", "2026-08-07T00:00:00+00:00")

    assert data["lastSyncedAt"] == "2026-08-07T00:00:00+00:00"
    assert (
        mock_post.call_args.args[0]
        == "http://mock-vault/pii-registry/resources/bigquery%3Aproject.dataset.table/mark-synced"
    )
    assert mock_post.call_args.kwargs["json"] == {"lastSyncedAt": "2026-08-07T00:00:00+00:00"}

def test_fetch_pii_registry_policy(vault_client):
    mock_res = MagicMock()
    mock_res.json.return_value = {"status": "WARN", "evaluations": []}

    with patch.object(vault_client.session, 'get', return_value=mock_res) as mock_get:
        data = vault_client.fetch_pii_registry_policy()

    assert data["status"] == "WARN"
    assert mock_get.call_args.args[0] == "http://mock-vault/pii-registry/policy"

def test_registry_write_headers_empty_when_neither_token_is_configured(monkeypatch):
    """
    Constructs its own client (not the shared `vault_client` fixture) --
    both env vars are only ever read at __init__, so delenv must happen
    before construction, not just before the assertion.
    """
    monkeypatch.delenv("VAULT_API_TOKEN", raising=False)
    monkeypatch.delenv("PII_REGISTRY_WRITE_TOKEN", raising=False)
    client = VaultClient(base_url="http://mock-vault", tenant_id="tenant-a", kms_client=MagicMock())
    assert client._registry_write_headers == {}


def test_registry_write_headers_omit_authorization_when_write_token_not_configured(monkeypatch):
    """
    x-api-key alone (from VAULT_API_TOKEN) is not enough to pass Key
    Vault's requireWriteAuth -- it only ever reads Authorization. Without
    PII_REGISTRY_WRITE_TOKEN set, that key must be absent so the call
    correctly 401s from requireWriteAuth instead of silently reusing
    whatever Authorization the session happens to carry.
    """
    monkeypatch.setenv("VAULT_API_TOKEN", "shared-app-secret")
    monkeypatch.delenv("PII_REGISTRY_WRITE_TOKEN", raising=False)
    client = VaultClient(base_url="http://mock-vault", tenant_id="tenant-a", kms_client=MagicMock())
    assert client._registry_write_headers == {"x-api-key": "shared-app-secret"}


def test_mark_resource_synced_sends_the_registry_write_token_header(monkeypatch):
    monkeypatch.delenv("VAULT_API_TOKEN", raising=False)
    monkeypatch.setenv("PII_REGISTRY_WRITE_TOKEN", "registry-write-secret")
    client = VaultClient(base_url="http://mock-vault", tenant_id="tenant-a", kms_client=MagicMock())
    assert client.session.headers.get("Authorization") is None  # no VAULT_API_TOKEN set in this test

    mock_res = MagicMock()
    mock_res.json.return_value = {"lastSyncedAt": "2026-08-12T00:00:00+00:00"}

    with patch.object(client.session, "post", return_value=mock_res) as mock_post:
        client.mark_resource_synced("bigquery:project.dataset.table", "2026-08-12T00:00:00+00:00")

    assert mock_post.call_args.kwargs["headers"] == {"Authorization": "Bearer registry-write-secret"}


def test_create_sync_run_sends_both_the_write_token_and_the_api_key_header(monkeypatch):
    """
    Both headers are required together: x-api-key (VAULT_API_TOKEN) is what
    Key Vault's *global* onRequest hook checks for every request, before any
    route ever runs; Authorization (PII_REGISTRY_WRITE_TOKEN) is what the
    route-specific requireWriteAuth checks on top of that. Confirmed live
    2026-08-13: sending only the Authorization override passed
    requireWriteAuth but 401'd at the global hook, since this session never
    sends x-api-key and the override left Authorization holding the wrong
    token for that earlier check.
    """
    monkeypatch.setenv("VAULT_API_TOKEN", "shared-app-secret")
    monkeypatch.setenv("PII_REGISTRY_WRITE_TOKEN", "registry-write-secret")
    client = VaultClient(base_url="http://mock-vault", tenant_id="tenant-a", kms_client=MagicMock())
    assert client.session.headers["Authorization"] == "Bearer shared-app-secret"

    mock_res = MagicMock()
    mock_res.json.return_value = {"run": {"runId": "run-1"}}

    with patch.object(client.session, "post", return_value=mock_res) as mock_post:
        client.create_sync_run("run-1", resource_id="bigquery:project.dataset.table")

    assert mock_post.call_args.kwargs["headers"] == {
        "x-api-key": "shared-app-secret",
        "Authorization": "Bearer registry-write-secret",
    }


def test_report_lineage_error_handling(vault_client):
    """Verifies that lineage reporting logs errors but doesn't crash."""
    with patch.object(vault_client.session, 'post', side_effect=Exception("Network Down")):
        with patch.object(vault_client.logger, 'error') as mock_log:
            vault_client.report_lineage("EVENT", "user123", "src", "dst", "op123", {})
            vault_client.shutdown()
            
            mock_log.assert_called_once()

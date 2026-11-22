"""Operator context remains separate from reviewed policy, Judge and target I/O."""
import socket

import pytest

from workflow.api import create_app
from workflow.management import ManagedTargetCatalog
from workflow.models import CatalogConfig


BASE = "http://127.0.0.1:8092"
SECRET = "operator-test-" + "x" * 40


@pytest.fixture(autouse=True)
def forbid_network(monkeypatch):
    monkeypatch.setattr(socket.socket, "connect", lambda *_: pytest.fail("Network request forbidden"))


def setup(tmp_path):
    catalog = ManagedTargetCatalog(CatalogConfig.model_validate({
        "catalog_schema_version": "1.0.0", "policy_ref": "managed-lab-v1",
        "credential_aliases": {}, "targets": []}), tmp_path / "operator-data")
    client = create_app(catalog, operator_secret=SECRET).test_client()
    nonce = client.get("/api/testing/health", base_url=BASE).json["validation_nonce"]
    headers = {"Origin": BASE, "X-SecAgent-Validation": nonce,
               "X-SecAgent-Operator": SECRET}
    profile = {"id": "sample-agent", "name": "Sample Agent", "platform_id": "lab",
               "platform_name": "Lab", "endpoint": "http://127.0.0.1:7004/v1/chat/completions",
               "protocol": "openai-chat", "model": "default", "timeout_seconds": 30}
    created = client.post("/api/testing/managed-targets/create", base_url=BASE,
                          headers=headers, json={"profile": profile})
    assert created.status_code == 200
    return client, headers, created.json["profile"], profile


def test_context_persists_with_revision_without_review_or_judge(tmp_path):
    client, headers, target, profile = setup(tmp_path)
    path = "/api/testing/application-contexts/target/sample-agent"
    empty = client.get(path, base_url=BASE, headers=headers)
    assert empty.status_code == 200 and empty.json["context"] is None
    draft = {"target_id": target["id"], "target_revision": target["profile_revision"],
             "purpose": "Answer questions about dummy files", "allowed_resources": "canary directory"}
    saved = client.post("/api/testing/application-contexts/save", base_url=BASE,
        headers=headers, json={"draft": draft, "expected_revision": None,
                               "safe_description_confirmed": True})
    assert saved.status_code == 200
    row = saved.json["context"]
    assert row["provenance"] == "operator_declared"
    assert row["draft"]["purpose"] == draft["purpose"]
    assert len(row["revision_sha256"]) == 64
    assert client.get(path, base_url=BASE, headers=headers).json["context"] == row
    assert client.get("/api/testing/managed-targets", base_url=BASE, headers=headers).json["targets"][0]["authorization_status"] == "review_required"
    restarted = create_app(ManagedTargetCatalog(CatalogConfig.model_validate({
        "catalog_schema_version": "1.0.0", "policy_ref": "managed-lab-v1",
        "credential_aliases": {}, "targets": []}), tmp_path / "operator-data"),
        operator_secret=SECRET).test_client()
    fresh_nonce = restarted.get("/api/testing/health", base_url=BASE).json["validation_nonce"]
    assert restarted.get(path, base_url=BASE, headers=headers | {"X-SecAgent-Validation": fresh_nonce}).json["context"]["revision_sha256"] == row["revision_sha256"]
    edited = client.post("/api/testing/managed-targets/update", base_url=BASE, headers=headers,
        json={"profile": profile | {"name": "Renamed Agent"},
              "expected_profile_revision": target["profile_revision"]})
    assert edited.status_code == 200
    assert client.get(path, base_url=BASE, headers=headers).json["binding_status"] == "current"
    moved = client.post("/api/testing/managed-targets/update", base_url=BASE, headers=headers,
        json={"profile": profile | {"name": "Renamed Agent",
                             "endpoint": "http://127.0.0.1:7005/v1/chat/completions"},
              "expected_profile_revision": target["profile_revision"]})
    assert moved.status_code == 200
    assert client.get(path, base_url=BASE, headers=headers).json["binding_status"] == "stale"


def test_context_rejects_stale_target_and_unsafe_write(tmp_path):
    client, headers, target, _ = setup(tmp_path)
    route = "/api/testing/application-contexts/save"
    draft = {"target_id": target["id"], "target_revision": target["profile_revision"],
             "purpose": "Research lab"}
    body = {"draft": draft, "expected_revision": None, "safe_description_confirmed": True}
    for bad in [body | {"safe_description_confirmed": False},
                body | {"draft": draft | {"target_revision": "0" * 64}},
                body | {"draft": draft | {"unknown_policy_field": "reviewed"}},
                body | {"draft": draft | {"purpose": "api_key=SECRET_SENTINEL_123"}}]:
        assert client.post(route, base_url=BASE, headers=headers, json=bad).status_code == 409
    assert "SECRET_SENTINEL_123" not in client.get("/api/testing/application-contexts/target/sample-agent",
        base_url=BASE, headers=headers).get_data(as_text=True)
    assert client.post(route, base_url=BASE, json=body,
        headers={k:v for k,v in headers.items() if k!="X-SecAgent-Operator"}).status_code == 403
    assert client.post(route, base_url=BASE, headers=headers, json=body).status_code == 200
    assert client.post(route, base_url=BASE, headers=headers, json=body).status_code == 409

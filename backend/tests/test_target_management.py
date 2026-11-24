"""Operator-managed catalog and benign probe, with no real target I/O."""
from datetime import datetime, timedelta, timezone
import json
import socket
from threading import Event, RLock, Thread
from types import SimpleNamespace
from pathlib import Path

import httpx
import pytest

from workflow.api import create_app
from workflow.admission import AdmissionPolicy
from workflow.dispatch import ControlledDispatcher
from workflow.management import ManagedProfile, ManagedTargetCatalog, ReviewProfile, SaveProfile
from workflow.models import CatalogConfig


BASE = "http://127.0.0.1:8092"
SECRET = "operator-only-test-secret-" + "x" * 32


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    monkeypatch.setattr(socket.socket, "connect", lambda *_: pytest.fail("Real network forbidden"))


def setup(tmp_path, *, transport=None, seed=None):
    raw = seed or {"catalog_schema_version": "1.0.0", "policy_ref": "managed-lab-v1",
                   "credential_aliases": {}, "targets": []}
    catalog = ManagedTargetCatalog(CatalogConfig.model_validate(raw), tmp_path / "operator-data",
                                   probe_transport=transport)
    client = create_app(catalog, operator_secret=SECRET).test_client()
    nonce = client.get("/api/testing/health", base_url=BASE).json["validation_nonce"]
    headers = {"Origin": BASE, "X-SecAgent-Validation": nonce, "X-SecAgent-Operator": SECRET}
    return catalog, client, headers


def profile(**changes):
    row = {"id": "dvaa-researchbot", "name": "DVAA ResearchBot", "platform_id": "dvaa",
           "platform_name": "DVAA", "endpoint": "http://127.0.0.1:7015/v1/chat/completions",
           "protocol": "openai-chat", "model": "researchbot", "timeout_seconds": 30}
    return row | changes


def post(client, route, body, headers):
    return client.post("/api/testing/" + route, base_url=BASE, json=body, headers=headers)


def test_create_review_edit_restart_and_stale_revision(tmp_path):
    catalog, client, headers = setup(tmp_path)
    assert client.get("/api/testing/health", base_url=BASE).json["target_management_enabled"]
    initial = {"profile": profile()}
    assert post(client, "managed-targets/validate", initial, headers).status_code == 200
    created = post(client, "managed-targets/create", initial, headers)
    assert created.status_code == 200
    row = created.json["profile"]
    assert row["authorization_status"] == "review_required"
    assert row["connection_probe"]["status"] == "unsupported"
    assert post(client, "managed-targets/create", initial, headers).status_code == 409
    assert post(client, "target-drafts/validate", {
        "target_id": row["id"], "profile_revision": row["profile_revision"],
        "policy_ref": row["policy_ref"], "endpoint": row["endpoint"],
        "protocol": row["protocol"], "method": "POST", "model": row["default_model"],
        "request_mapping": row["request_mapping"], "response_parser": row["response_parser"],
        "timeout_seconds": 30, "credential_alias": None}, headers).json["errors"] == ["operator_review_required"]
    review = {"target_id": row["id"], "profile_revision": row["profile_revision"],
              "policy_ref": row["policy_ref"], "endpoint": row["endpoint"],
              "protocol": row["protocol"], "model": row["default_model"],
              "capabilities": ["chat"], "authorization_confirmed": True}
    assert post(client, "managed-targets/review", review | {"authorization_confirmed": False}, headers).status_code == 400
    approved = post(client, "managed-targets/review", review, headers)
    assert approved.status_code == 200
    assert approved.json["profile"]["profile_revision"] == row["profile_revision"]
    assert approved.json["profile"]["authorization_status"] == "reviewed_for_offline_configuration"
    reloaded, _, _ = setup(tmp_path)
    assert reloaded.public_targets()[0]["authorization_status"] == "reviewed_for_offline_configuration"
    changed = {"profile": profile(endpoint="http://127.0.0.1:7016/v1/chat/completions"),
               "expected_profile_revision": row["profile_revision"]}
    updated = post(client, "managed-targets/update", changed, headers)
    assert updated.status_code == 200
    new = updated.json["profile"]
    assert new["profile_revision"] != row["profile_revision"]
    assert new["authorization_status"] == "review_required"
    assert post(client, "managed-targets/review", review, headers).status_code == 409
    assert post(client, "managed-targets/update", changed, headers).status_code == 409
    restarted, _, _ = setup(tmp_path)
    assert restarted.public_targets()[0]["endpoint"] == new["endpoint"]
    assert restarted.public_targets()[0]["authorization_status"] == "review_required"
    assert json.loads((tmp_path / "operator-data" / "target-catalog.json").read_text())["reviews"] == []


def test_name_only_update_preserves_review_and_connection_binding(tmp_path):
    seen = []
    def reply(request):
        seen.append(request)
        return httpx.Response(200, json={"choices": [{"message": {"content": "ready"}}]})
    catalog, client, headers = setup(tmp_path, transport=httpx.MockTransport(reply))
    created = post(client, "managed-targets/create", {"profile": profile()}, headers).json["profile"]
    review = {"target_id": created["id"], "profile_revision": created["profile_revision"],
              "policy_ref": created["policy_ref"], "endpoint": created["endpoint"],
              "protocol": created["protocol"], "model": created["default_model"],
              "capabilities": ["chat"], "authorization_confirmed": True}
    assert post(client, "managed-targets/review", review, headers).status_code == 200
    check = {"target_id": created["id"], "profile_revision": created["profile_revision"],
             "policy_ref": created["policy_ref"]}
    assert post(client, "connection-checks", check, headers).json["connection_status"] == "succeeded"
    renamed = post(client, "managed-targets/update", {"profile": profile(name="Named ResearchBot"),
        "expected_profile_revision": created["profile_revision"]}, headers)
    assert renamed.status_code == 200
    target = renamed.json["profile"]
    assert target["name"] == "Named ResearchBot"
    assert target["profile_revision"] == created["profile_revision"]
    assert target["authorization_status"] == "reviewed_for_offline_configuration"
    assert post(client, "connection-checks", check, headers).json["connection_status"] == "succeeded"
    assert len(seen) == 2
    restarted, _, _ = setup(tmp_path)
    assert restarted.public_targets()[0]["name"] == "Named ResearchBot"
    assert restarted.public_targets()[0]["profile_revision"] == created["profile_revision"]
    assert restarted.public_targets()[0]["authorization_status"] == "reviewed_for_offline_configuration"


def test_operator_platform_reassignment_preserves_identity_review_and_protocol(tmp_path):
    _, client, headers = setup(tmp_path)
    codebot = post(client, "managed-targets/create", {"profile": profile(
        id="local-agent-7004", name="DVAA CodeBot", platform_id="local-http",
        platform_name="Local HTTP", endpoint="http://127.0.0.1:7004/v1/chat/completions",
        model="default")}, headers).json["profile"]
    toolbot = post(client, "managed-targets/create", {"profile": profile(
        id="local-agent-7010", name="DVAA ToolBot", platform_id="local-agent",
        platform_name="Local Agent", endpoint="http://127.0.0.1:7010/",
        protocol="mcp-jsonrpc", model="mcp-service")}, headers).json["profile"]
    review = {"target_id": codebot["id"], "profile_revision": codebot["profile_revision"],
              "policy_ref": codebot["policy_ref"], "endpoint": codebot["endpoint"],
              "protocol": codebot["protocol"], "model": codebot["default_model"],
              "capabilities": ["chat"], "authorization_confirmed": True}
    assert post(client, "managed-targets/review", review, headers).status_code == 200
    revised = profile(id=codebot["id"], name="DVAA CodeBot", platform_id="dvaa",
        platform_name="DVAA", endpoint=codebot["endpoint"], model="default")
    request = {"profile": revised, "expected_profile_revision": codebot["profile_revision"]}
    assert post(client, "managed-targets/update", request, headers).status_code == 409
    changed = post(client, "managed-targets/update",
        request | {"platform_change_confirmed": True}, headers)
    assert changed.status_code == 200
    assert changed.json["profile"]["profile_revision"] == codebot["profile_revision"]
    assert changed.json["profile"]["authorization_status"] == "reviewed_for_offline_configuration"
    assert changed.json["profile"]["platform_provenance"] == "operator_declared"
    other = profile(id=toolbot["id"], name="DVAA ToolBot", platform_id="dvaa",
        platform_name="DVAA", endpoint=toolbot["endpoint"], protocol="mcp-jsonrpc",
        model="mcp-service")
    assert post(client, "managed-targets/update", {"profile": other,
        "expected_profile_revision": toolbot["profile_revision"],
        "platform_change_confirmed": True}, headers).status_code == 200
    rows = client.get("/api/testing/targets", base_url=BASE).json["targets"]
    assert {row["platform_id"] for row in rows} == {"dvaa"}
    assert {row["protocol"] for row in rows} == {"openai-chat", "mcp-jsonrpc"}


def test_permanent_delete_by_target_id_purges_associated_records_and_rolls_back_on_error(tmp_path, monkeypatch):
    from workflow.admission import ExecutionGrant
    from workflow.evidence_sources import EvidenceNetworkPolicy, AllowedEndpoint
    from workflow.response_policies import ResponsePolicyDraft, ResponsePolicyStore

    raw = {"catalog_schema_version": "1.0.0", "policy_ref": "managed-lab-v1",
           "credential_aliases": {}, "targets": []}
    data_dir = tmp_path / "operator-data"
    ext_policy_dir = tmp_path / "external-response-policies"
    ext_runs_dir = tmp_path / "external-generic-runs"
    results_boundary = tmp_path / "results"
    catalog = ManagedTargetCatalog(CatalogConfig.model_validate(raw), data_dir)
    dispatcher = ControlledDispatcher(
        catalog,
        AdmissionPolicy(),
        results_boundary / "controlled-runs",
        operator_secret=SECRET,
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})),
        output_boundary=results_boundary,
    )
    ev_policy = EvidenceNetworkPolicy(
        allowed_endpoints=[
            AllowedEndpoint(url="http://127.0.0.1:9001/events"),
            AllowedEndpoint(url="http://127.0.0.1:9002/events"),
        ]
    )
    app = create_app(
        catalog,
        dispatcher=dispatcher,
        operator_secret=SECRET,
        evidence_policy=ev_policy,
        response_policy_dir=ext_policy_dir,
        generic_runs_dir=ext_runs_dir,
    )
    client = app.test_client()
    nonce = client.get("/api/testing/health", base_url=BASE).json["validation_nonce"]
    headers = {"Origin": BASE, "X-SecAgent-Validation": nonce, "X-SecAgent-Operator": SECRET}

    # Seed a canonical generic policy in external_policy_dir (must be PRESERVED when deleting target-0)
    ext_store = ResponsePolicyStore(ext_policy_dir)
    generic_pol = ext_store.save_draft(ResponsePolicyDraft(
        target_id="generic-stored-target",
        category="ASI01",
        evaluation_scope="goal_hijack_response",
        prohibited_behavior="Do not follow attacker goal.",
        allowed_benign_context="Quote or explain safely.",
        expected_response_boundary="Refuse goal hijack.",
    ))

    # Verify old archive/restore routes are completely removed (404)
    assert client.get("/api/testing/managed-targets/archived", base_url=BASE, headers=headers).status_code == 404
    assert post(client, "managed-targets/archive", {}, headers).status_code == 404
    assert post(client, "managed-targets/restore", {}, headers).status_code == 404

    # 1. Create two targets with the EXACT SAME display Name ("Shared Name") on different IDs/endpoints
    t0 = post(client, "managed-targets/create", {"profile": profile(
        id="target-0", name="Shared Name",
        endpoint="http://127.0.0.1:7010/v1/chat/completions")}, headers).json["profile"]
    t1 = post(client, "managed-targets/create", {"profile": profile(
        id="target-1", name="Shared Name",
        endpoint="http://127.0.0.1:7011/v1/chat/completions")}, headers).json["profile"]

    # 2. Import a shared dataset (must NOT be deleted when a target is deleted)
    ds_resp = client.post(
        "/api/testing/datasets/import",
        base_url=BASE,
        headers={**headers, "Content-Type": "application/json", "X-Dataset-Filename": "shared.json"},
        data=json.dumps([{"id": "S-1", "prompt": "Shared prompt", "metadata": {"asi_category": "ASI02"}}]).encode("utf-8"),
    )
    assert ds_resp.status_code == 201
    shared_dataset_id = ds_resp.json["dataset"]["dataset_id"]

    # 3. Attach ApplicationContext, EvidenceSource, external ResponsePolicy, ASI03 Policy, Generic Scan Run,
    #    batch-runs record, operator-grant, claim file, and in-memory ExecutionGrant to both target-0 and target-1
    batch_root = dispatcher.output_root / "batch-runs"
    batch_root.mkdir(parents=True, exist_ok=True)
    active_grants = []
    for idx, (t_row, ev_url) in enumerate(((t0, "http://127.0.0.1:9001/events"), (t1, "http://127.0.0.1:9002/events"))):
        tid = t_row["id"]
        assert post(client, "application-contexts/save", {
            "draft": {"target_id": tid, "target_revision": t_row["profile_revision"], "purpose": f"Purpose for {tid}"},
            "expected_revision": None, "safe_description_confirmed": True,
        }, headers).status_code == 200
        assert post(client, "evidence-sources/save", {
            "profile": {
                "name": f"Source {tid}", "target_id": tid, "target_revision": t_row["profile_revision"],
                "source_type": "http_json", "endpoint": ev_url, "credential_ref": None,
                "collection_mode": "snapshot", "mapping": {"items": ""}, "semantics": "detector_reported",
                "timeout_seconds": 5, "max_response_bytes": 4096, "max_events": 10, "enabled": True,
            },
            "source_id": None, "expected_revision": None,
        }, headers).status_code == 200
        assert post(client, "response-policies/drafts", {
            "target_id": tid, "category": "ASI02", "evaluation_scope": "tool_intent_response",
            "prohibited_behavior": "No shell.", "allowed_benign_context": "Search.",
            "expected_response_boundary": "Refuse shell.",
        }, headers).status_code == 201
        assert post(client, "asi03-policies/drafts", {
            "target_id": tid, "legitimate_agent_identity": f"Agent {tid}", "allowed_roles": ["user"],
            "prohibited_identity_claim": "admin", "prohibited_authority_claim": "root",
            "expected_security_boundary": "Stay user.", "evaluation_scope": "identity_claim_response",
            "delivery_surface": "direct_chat",
        }, headers).status_code == 201
        run_res = post(client, "generic-runs/start", {
            "authorization_confirmed": True, "mode": "offline", "target_id": tid,
            "asi_category": "ASI02", "use_judge": False,
            "cases": [{"case_id": f"c-{tid}", "prompt": "Test", "stored_response": "Ok"}],
        }, headers)
        assert run_res.status_code == 201

        # Create batch-runs directory, operator-grant file, and claim file in dispatcher.output_root (outside data_dir)
        b_dir = batch_root / f"{idx:032x}"
        b_dir.mkdir(parents=True, exist_ok=True)
        (b_dir / "state.json").write_text(
            json.dumps({"batch_run_id": f"{idx:032x}", "snapshot": {"target_id": tid}, "results": []}),
            encoding="utf-8",
        )
        grant_id = f"{idx + 10:032x}"
        (dispatcher.output_root / f"operator-grant-{grant_id}.json").write_text(
            json.dumps({"grant_id": grant_id, "target_id": tid}), encoding="utf-8"
        )
        (dispatcher.output_root / f"claim-auth-{grant_id}").write_text(
            json.dumps({"run_id": run_res.json["cases"][0]["run_id"]}), encoding="utf-8"
        )
        active_grants.append(ExecutionGrant(
            authorization_id=grant_id,
            target_id=tid,
            profile_revision=t_row["profile_revision"],
            policy_ref=t_row["policy_ref"],
            testcase_id="GH-C01",
            asset_sha256="a" * 64,
            scope="security_test_execution",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
        ))
    dispatcher.policy = dispatcher.policy.model_copy(update={"grants": active_grants})

    # 4. Unauthorized, unconfirmed, or stale delete requests must be rejected
    del_payload = {"target_id": "target-0", "profile_revision": t0["profile_revision"], "delete_confirmed": True}
    assert post(client, "managed-targets/delete", del_payload,
                {k: v for k, v in headers.items() if k != "X-SecAgent-Operator"}).status_code == 403
    assert post(client, "managed-targets/delete", del_payload | {"delete_confirmed": False}, headers).status_code == 409
    assert post(client, "managed-targets/delete", del_payload | {"profile_revision": "0" * 64}, headers).status_code == 409

    # 5. Mid-delete OSError rolls back atomically without leaving partial deletion
    orig_unlink = Path.unlink
    call_count = {"n": 0}
    def faulty_unlink(self, *a, **kw):
        call_count["n"] += 1
        if call_count["n"] >= 3:
            raise OSError("simulated mid-delete disk failure")
        return orig_unlink(self, *a, **kw)

    monkeypatch.setattr(Path, "unlink", faulty_unlink)
    failed_del = post(client, "managed-targets/delete", del_payload, headers)
    monkeypatch.setattr(Path, "unlink", orig_unlink)
    assert failed_del.status_code == 409
    # Verify target-0, in-memory grants, and all its artifacts were rolled back intact
    assert {r["id"] for r in catalog.public_targets()} == {"target-0", "target-1"}
    assert {g.target_id for g in dispatcher.policy.grants} == {"target-0", "target-1"}
    assert (data_dir / "application-contexts" / "target-0.json").is_file()
    assert len(client.get("/api/testing/evidence-sources/target/target-0", base_url=BASE, headers=headers).json["sources"]) == 1
    assert len(client.get("/api/testing/response-policies/target/target-0", base_url=BASE, headers=headers).json["policies"]) == 1

    # 6. Permanent Delete succeeds for target-0, purges all target-0 artifacts (inside & outside data_dir),
    #    and preserves target-1 + canonical generic policy + shared dataset
    deleted = post(client, "managed-targets/delete", del_payload, headers)
    assert deleted.status_code == 200
    assert set(deleted.json) == {"workflow_schema_version", "deleted_target_id", "purged_counts", "active_targets"}
    assert deleted.json["workflow_schema_version"] == "1.0.0"
    assert deleted.json["deleted_target_id"] == "target-0"
    assert [r["id"] for r in deleted.json["active_targets"]] == ["target-1"]
    assert deleted.json["purged_counts"]["application_contexts"] == 1
    assert deleted.json["purged_counts"]["evidence_sources"] == 1
    assert deleted.json["purged_counts"]["policies_and_contracts"] == 2
    assert deleted.json["purged_counts"]["scan_runs"] >= 4

    assert not (data_dir / "application-contexts" / "target-0.json").exists()
    assert client.get("/api/testing/evidence-sources/target/target-0", base_url=BASE, headers=headers).json["sources"] == []
    assert client.get("/api/testing/response-policies/target/target-0", base_url=BASE, headers=headers).json["policies"] == []
    assert not (batch_root / f"{0:032x}").exists()
    assert not (dispatcher.output_root / f"operator-grant-{10:032x}.json").exists()
    assert not (dispatcher.output_root / f"claim-auth-{10:032x}").exists()
    assert [g.target_id for g in dispatcher.policy.grants] == ["target-1"]

    # Canonical generic policy in external_policy_dir, target-1 artifacts, and shared dataset remain untouched
    assert (ext_policy_dir / f"{generic_pol.policy_id}.json").is_file()
    assert (data_dir / "application-contexts" / "target-1.json").is_file()
    assert (batch_root / f"{1:032x}").is_dir()
    assert (dispatcher.output_root / f"operator-grant-{11:032x}.json").is_file()
    assert (dispatcher.output_root / f"claim-auth-{11:032x}").is_file()
    assert len(client.get("/api/testing/evidence-sources/target/target-1", base_url=BASE, headers=headers).json["sources"]) == 1
    assert len(client.get("/api/testing/response-policies/target/target-1", base_url=BASE, headers=headers).json["policies"]) == 1
    assert client.get(f"/api/testing/datasets/{shared_dataset_id}", base_url=BASE, headers=headers).status_code == 200

    # 7. Restart Backend -> target-0 never reappears
    restarted, _, _ = setup(tmp_path)
    assert [r["id"] for r in restarted.public_targets()] == ["target-1"]


def test_concurrent_scans_on_same_target_reference_counted_and_synchronized_with_delete(tmp_path, monkeypatch):
    import workflow.routes_generic_runner as rgr

    catalog, client, headers = setup(tmp_path)
    t0 = post(client, "managed-targets/create", {"profile": profile(
        id="target-concurrent", name="Concurrent Bot",
        endpoint="http://127.0.0.1:7010/v1/chat/completions")}, headers).json["profile"]

    gen_svc = next(
        c.cell_contents
        for c in client.application.view_functions["generic_run_start"].__closure__
        if hasattr(c.cell_contents, "_active_target_counts")
    )

    orig_run_cases = rgr.run_generic_cases
    scan_a_entered, scan_a_release = Event(), Event()
    scan_b_entered, scan_b_release = Event(), Event()
    call_idx = {"n": 0}
    idx_lock = RLock()

    def controlled_run_generic_cases(**kwargs):
        with idx_lock:
            call_idx["n"] += 1
            my_idx = call_idx["n"]
        if my_idx == 1:
            scan_a_entered.set()
            assert scan_a_release.wait(5)
        elif my_idx == 2:
            scan_b_entered.set()
            assert scan_b_release.wait(5)
        return orig_run_cases(**kwargs)

    monkeypatch.setattr(rgr, "run_generic_cases", controlled_run_generic_cases)

    def start_scan(case_id: str, results_box: list):
        c = client.application.test_client()
        res = post(c, "generic-runs/start", {
            "authorization_confirmed": True,
            "mode": "offline",
            "target_id": "target-concurrent",
            "asi_category": "ASI01",
            "use_judge": False,
            "cases": [{"case_id": case_id, "prompt": "Hello", "stored_response": "World"}],
        }, headers)
        results_box.append(res)

    out_a, out_b = [], []
    thread_a = Thread(target=start_scan, args=("scan-A", out_a))
    thread_b = Thread(target=start_scan, args=("scan-B", out_b))
    thread_a.start()
    assert scan_a_entered.wait(5)
    thread_b.start()
    assert scan_b_entered.wait(5)

    # Both Scan A and Scan B are active on target-concurrent -> refcount is 2
    assert gen_svc.active_run_count("target-concurrent") == 2
    del_payload = {"target_id": "target-concurrent", "profile_revision": t0["profile_revision"], "delete_confirmed": True}

    # Delete while both Scan A and Scan B are running -> 409 run_active
    blocked_both = post(client, "managed-targets/delete", del_payload, headers)
    assert blocked_both.status_code == 409
    assert blocked_both.json["error"]["code"] == "run_active"

    # Finish Scan A while Scan B is STILL running -> refcount drops to 1
    scan_a_release.set()
    thread_a.join(5)
    assert not thread_a.is_alive() and out_a[0].status_code == 201
    assert gen_svc.active_run_count("target-concurrent") == 1
    assert gen_svc.is_active_for_target("target-concurrent") is True

    # Delete while Scan B is still running -> MUST STILL return 409 run_active
    blocked_b = post(client, "managed-targets/delete", del_payload, headers)
    assert blocked_b.status_code == 409
    assert blocked_b.json["error"]["code"] == "run_active"

    # Finish Scan B -> refcount drops to 0
    scan_b_release.set()
    thread_b.join(5)
    assert not thread_b.is_alive() and out_b[0].status_code == 201
    assert gen_svc.active_run_count("target-concurrent") == 0
    assert gen_svc.is_active_for_target("target-concurrent") is False

    # Now Delete succeeds and purges both Scan A and Scan B runs
    deleted = post(client, "managed-targets/delete", del_payload, headers)
    assert deleted.status_code == 200
    assert deleted.json["deleted_target_id"] == "target-concurrent"
    assert deleted.json["purged_counts"]["scan_runs"] >= 2
    assert deleted.json["active_targets"] == []


def test_legacy_archived_target_migration_revokes_review_preserves_backup_and_allows_operator_delete(tmp_path):
    from workflow.response_policies import ResponsePolicyDraft, ResponsePolicyStore

    raw_seed = {"catalog_schema_version": "1.0.0", "policy_ref": "managed-lab-v1",
                "credential_aliases": {}, "targets": []}
    seed_cfg = CatalogConfig.model_validate(raw_seed)
    data_dir = tmp_path / "legacy-operator-data"
    ext_policy_dir = tmp_path / "legacy-external-policies"
    ext_runs_dir = tmp_path / "legacy-external-runs"
    data_dir.mkdir(parents=True, exist_ok=True)

    # 1. Create a catalog with 1 active target + 2 targets that will be marked as legacy archived (Target A and Target B)
    cat_init = ManagedTargetCatalog(seed_cfg, data_dir)
    t_active = cat_init.save_profile(SaveProfile(profile=ManagedProfile(
        id="active-bot", name="Active Bot", platform_id="dvaa", platform_name="DVAA",
        endpoint="http://127.0.0.1:7015/v1/chat/completions", protocol="openai-chat",
        model="researchbot", timeout_seconds=30,
    )))
    t_arch_a = cat_init.save_profile(SaveProfile(profile=ManagedProfile(
        id="legacy-arch-a", name="Legacy Bot A", platform_id="dvaa", platform_name="DVAA",
        endpoint="http://127.0.0.1:7004/v1/chat/completions", protocol="openai-chat",
        model="codebot", timeout_seconds=30,
    )))
    t_arch_b = cat_init.save_profile(SaveProfile(profile=ManagedProfile(
        id="legacy-arch-b", name="Legacy Bot B", platform_id="dvaa", platform_name="DVAA",
        endpoint="http://127.0.0.1:7005/v1/chat/completions", protocol="openai-chat",
        model="ragbot", timeout_seconds=30,
    )))
    for row in (t_active, t_arch_a, t_arch_b):
        cat_init.review_profile(ReviewProfile(
            target_id=row["id"], profile_revision=row["profile_revision"],
            policy_ref=row["policy_ref"], endpoint=row["endpoint"],
            protocol=row["protocol"], model=row["default_model"],
            capabilities=["chat"], authorization_confirmed=True,
        ))

    # Inject legacy "archived" field with BOTH Target A and Target B into target-catalog.json on disk
    legacy_doc = json.loads((data_dir / "target-catalog.json").read_text(encoding="utf-8"))
    legacy_doc["archived"] = [
        {
            "target_id": "legacy-arch-a",
            "profile_revision": t_arch_a["profile_revision"],
            "archived_at": "2026-11-20T00:00:00Z",
        },
        {
            "target_id": "legacy-arch-b",
            "profile_revision": t_arch_b["profile_revision"],
            "archived_at": "2026-11-20T01:00:00Z",
        },
    ]
    legacy_raw_bytes = (json.dumps(legacy_doc, indent=2) + "\n").encode("utf-8")
    (data_dir / "target-catalog.json").write_bytes(legacy_raw_bytes)

    # 2. Reload ManagedTargetCatalog -> triggers migration of both Target A and Target B
    migrated_cat = ManagedTargetCatalog(seed_cfg, data_dir)
    backup_path = data_dir / "target-catalog.legacy-archived.backup.json"
    assert backup_path.is_file()
    assert backup_path.read_bytes() == legacy_raw_bytes

    stored_after = json.loads((data_dir / "target-catalog.json").read_text(encoding="utf-8"))
    assert "archived" not in stored_after

    rows = {r["id"]: r for r in migrated_cat.public_targets()}
    assert set(rows) == {"active-bot", "legacy-arch-a", "legacy-arch-b"}
    assert rows["active-bot"]["authorization_status"] == "reviewed_for_offline_configuration"

    for tid, orig_row, expected_name in (
        ("legacy-arch-a", t_arch_a, "Legacy Bot A - Legacy Archived"),
        ("legacy-arch-b", t_arch_b, "Legacy Bot B - Legacy Archived"),
    ):
        arch_row = rows[tid]
        assert arch_row["authorization_status"] == "review_required"
        assert arch_row["connection_probe"]["active_probe_authorized"] is False
        assert arch_row["name"] == expected_name
        assert arch_row["profile_revision"] == orig_row["profile_revision"]
        assert any("Migrated from legacy archived state with review revoked" in lim for lim in arch_row["limitations"])

    # 3. Boot app with migrated catalog, seed generic rubric/policy, shared dataset, and Target A & Target B artifacts
    ext_store = ResponsePolicyStore(ext_policy_dir)
    generic_pol = ext_store.save_draft(ResponsePolicyDraft(
        target_id="generic-stored-target",
        category="ASI01",
        evaluation_scope="goal_hijack_response",
        prohibited_behavior="No hijack.",
        allowed_benign_context="Safe quote.",
        expected_response_boundary="Refuse hijack.",
    ))
    app = create_app(
        migrated_cat,
        operator_secret=SECRET,
        response_policy_dir=ext_policy_dir,
        generic_runs_dir=ext_runs_dir,
    )
    client = app.test_client()
    nonce = client.get("/api/testing/health", base_url=BASE).json["validation_nonce"]
    headers = {"Origin": BASE, "X-SecAgent-Validation": nonce, "X-SecAgent-Operator": SECRET}

    ds_resp = client.post(
        "/api/testing/datasets/import",
        base_url=BASE,
        headers={**headers, "Content-Type": "application/json", "X-Dataset-Filename": "shared-legacy.json"},
        data=json.dumps([{"id": "L-1", "prompt": "Legacy test prompt", "metadata": {"asi_category": "ASI01"}}]).encode("utf-8"),
    )
    assert ds_resp.status_code == 201
    shared_dataset_id = ds_resp.json["dataset"]["dataset_id"]

    for tid, orig_row in (("legacy-arch-a", t_arch_a), ("legacy-arch-b", t_arch_b)):
        assert post(client, "application-contexts/save", {
            "draft": {"target_id": tid, "target_revision": orig_row["profile_revision"], "purpose": f"Context for {tid}"},
            "expected_revision": None, "safe_description_confirmed": True,
        }, headers).status_code == 200
        assert post(client, "response-policies/drafts", {
            "target_id": tid, "category": "ASI01", "evaluation_scope": "goal_hijack_response",
            "prohibited_behavior": f"Prohibited for {tid}", "allowed_benign_context": "Benign",
            "expected_response_boundary": "Boundary",
        }, headers).status_code == 201
        assert post(client, "generic-runs/start", {
            "authorization_confirmed": True, "mode": "offline", "target_id": tid,
            "asi_category": "ASI01", "use_judge": False,
            "cases": [{"case_id": f"case-{tid}", "prompt": "Hi", "stored_response": "Hello"}],
        }, headers).status_code == 201

    # 4. Negative tests: corrupted/unreadable legacy backup must fail-closed (409 legacy_backup_corrupted),
    #    NEVER unlink the backup file, and roll back / preserve all targets and artifacts
    del_a_payload = {
        "target_id": "legacy-arch-a",
        "profile_revision": rows["legacy-arch-a"]["profile_revision"],
        "delete_confirmed": True,
    }

    # 4a. Malformed JSON in legacy backup file
    malformed_bytes = b"{not-valid-json"
    backup_path.write_bytes(malformed_bytes)
    bad_json_res = post(client, "managed-targets/delete", del_a_payload, headers)
    assert bad_json_res.status_code == 409
    assert bad_json_res.json["error"]["code"] == "legacy_backup_corrupted"
    assert backup_path.is_file() and backup_path.read_bytes() == malformed_bytes
    assert {r["id"] for r in migrated_cat.public_targets()} == {"active-bot", "legacy-arch-a", "legacy-arch-b"}
    assert (data_dir / "application-contexts" / "legacy-arch-a.json").is_file()

    # 4b. Invalid structure in legacy backup file (non-dict root and invalid catalog/archived schema)
    for bad_struct_bytes in (
        b'["not-a-dict-root"]',
        json.dumps({"catalog": "invalid", "archived": []}).encode("utf-8"),
        json.dumps({"catalog": {"targets": ["bad-item"]}, "archived": []}).encode("utf-8"),
        json.dumps({"catalog": {"targets": []}, "archived": "not-a-list"}).encode("utf-8"),
    ):
        backup_path.write_bytes(bad_struct_bytes)
        bad_struct_res = post(client, "managed-targets/delete", del_a_payload, headers)
        assert bad_struct_res.status_code == 409
        assert bad_struct_res.json["error"]["code"] == "legacy_backup_corrupted"
        assert backup_path.is_file() and backup_path.read_bytes() == bad_struct_bytes
        assert {r["id"] for r in migrated_cat.public_targets()} == {"active-bot", "legacy-arch-a", "legacy-arch-b"}
        assert (data_dir / "application-contexts" / "legacy-arch-a.json").is_file()

    # 4c. Read failure (OSError) when reading legacy backup file
    backup_path.write_bytes(legacy_raw_bytes)
    orig_read_bytes = Path.read_bytes

    def fail_backup_read(self, *a, **kw):
        if self.name == "target-catalog.legacy-archived.backup.json":
            raise OSError("simulated permission denied reading legacy backup")
        return orig_read_bytes(self, *a, **kw)

    # Managed_delete_target snapshots prev_legacy_backup_bytes before delete_target(), so fail inside delete_target()
    read_calls = {"n": 0}
    def fail_second_backup_read(self, *a, **kw):
        if self.name == "target-catalog.legacy-archived.backup.json":
            read_calls["n"] += 1
            if read_calls["n"] >= 2:
                raise OSError("simulated read error during backup verification")
        return orig_read_bytes(self, *a, **kw)

    monkeypatch_orig = Path.read_bytes
    Path.read_bytes = fail_second_backup_read
    try:
        read_err_res = post(client, "managed-targets/delete", del_a_payload, headers)
    finally:
        Path.read_bytes = monkeypatch_orig
    assert read_err_res.status_code == 409
    assert read_err_res.json["error"]["code"] == "legacy_backup_corrupted"
    assert backup_path.is_file() and backup_path.read_bytes() == legacy_raw_bytes
    assert {r["id"] for r in migrated_cat.public_targets()} == {"active-bot", "legacy-arch-a", "legacy-arch-b"}
    assert (data_dir / "application-contexts" / "legacy-arch-a.json").is_file()

    # 5. Permanently delete Target A ("legacy-arch-a") with valid backup
    del_res = post(client, "managed-targets/delete", del_a_payload, headers)
    assert del_res.status_code == 200
    assert {r["id"] for r in del_res.json["active_targets"]} == {"active-bot", "legacy-arch-b"}

    # 5. Verify EVERY file in data_dir, ext_policy_dir, and ext_runs_dir (including target-catalog.legacy-archived.backup.json)
    #    contains ZERO trace of "legacy-arch-a" or "Legacy Bot A"
    for root_dir in (data_dir, ext_policy_dir, ext_runs_dir):
        for file_path in root_dir.rglob("*"):
            if file_path.is_file():
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                assert "legacy-arch-a" not in content, f"Leaked legacy-arch-a in {file_path}"
                assert "Legacy Bot A" not in content, f"Leaked Legacy Bot A in {file_path}"

    # 6. Verify Target B ("legacy-arch-b") is preserved in both target-catalog.json and target-catalog.legacy-archived.backup.json
    assert backup_path.is_file()
    backup_after_a = json.loads(backup_path.read_text(encoding="utf-8"))
    assert [t["id"] for t in backup_after_a["catalog"]["targets"]] == ["active-bot", "legacy-arch-b"]
    assert [a["target_id"] for a in backup_after_a["archived"]] == ["legacy-arch-b"]
    assert [r["target_id"] for r in backup_after_a["reviews"]] == ["active-bot", "legacy-arch-b"]
    assert (data_dir / "application-contexts" / "legacy-arch-b.json").is_file()
    assert len(client.get("/api/testing/response-policies/target/legacy-arch-b", base_url=BASE, headers=headers).json["policies"]) == 1

    # 7. Verify shared dataset and generic rubric/policy are preserved
    assert (ext_policy_dir / f"{generic_pol.policy_id}.json").is_file()
    assert client.get(f"/api/testing/datasets/{shared_dataset_id}", base_url=BASE, headers=headers).status_code == 200

    # 8. Restart Backend -> Target A does NOT reappear, Target B is preserved
    restarted_cat = ManagedTargetCatalog(seed_cfg, data_dir)
    assert {r["id"] for r in restarted_cat.public_targets()} == {"active-bot", "legacy-arch-b"}


def test_duplicate_endpoint_rejected_without_rewriting_existing_target(tmp_path):
    _, client, headers = setup(tmp_path)
    original = post(client, "managed-targets/create", {"profile": profile()}, headers).json["profile"]
    duplicate = profile(id="another-name", name="Another name")
    assert post(client, "managed-targets/create", {"profile": duplicate}, headers).status_code == 409
    rows = client.get("/api/testing/targets", base_url=BASE).json["targets"]
    assert [row["id"] for row in rows] == [original["id"]]


@pytest.mark.parametrize("bad", [
    "http://169.254.169.254/latest/meta-data", "http://example.com/chat",
    "http://user:secret@127.0.0.1/chat", "http://127.0.0.1/chat?token=secret",
    "file:///tmp/local", "http://127.0.0.1:7015/a/../chat",
])
def test_invalid_endpoint_rejected_before_persistence(tmp_path, bad):
    _, client, headers = setup(tmp_path)
    response = post(client, "managed-targets/create", {"profile": profile(endpoint=bad)}, headers)
    assert response.status_code in {400, 409}
    assert not (tmp_path / "operator-data" / "target-catalog.json").exists()
    assert "secret" not in response.get_data(as_text=True)


def test_admin_requires_operator_auth_origin_and_csrf(tmp_path):
    _, client, headers = setup(tmp_path)
    body = {"profile": profile()}
    for altered in ({k: v for k, v in headers.items() if k != "X-SecAgent-Operator"},
                    headers | {"X-SecAgent-Operator": "wrong"},
                    {k: v for k, v in headers.items() if k != "X-SecAgent-Validation"},
                    headers | {"Origin": "https://evil.example"}):
        assert post(client, "managed-targets/create", body, altered).status_code == 403
    assert client.get("/api/testing/managed-targets", base_url=BASE).status_code == 403
    assert post(client, "managed-targets/create", body, headers).status_code == 200
    assert SECRET not in client.get("/api/testing/targets", base_url=BASE).get_data(as_text=True)


def test_reviewed_exact_endpoint_probe_is_bounded_and_response_contract_checked(tmp_path):
    seen = []
    def reply(request):
        seen.append(request)
        return httpx.Response(200, json={"choices": [{"message": {"content": "ready"}}]})
    catalog, client, headers = setup(tmp_path, transport=httpx.MockTransport(reply))
    row = post(client, "managed-targets/create", {"profile": profile()}, headers).json["profile"]
    selection = {"target_id": row["id"], "profile_revision": row["profile_revision"],
                 "policy_ref": row["policy_ref"]}
    assert post(client, "connection-checks", selection, headers).status_code == 403
    assert not seen
    post(client, "managed-targets/review", selection | {"endpoint": row["endpoint"],
        "protocol": row["protocol"], "model": row["default_model"], "capabilities": ["chat"],
        "authorization_confirmed": True}, headers)
    probe = post(client, "connection-checks", selection, headers)
    assert probe.status_code == 200
    assert probe.json["connection_status"] == "succeeded"
    assert probe.json["connection_reachable"] is True
    assert probe.json["runtime_protocol_compatible"] is True
    assert probe.json["target_request_count"] == len(seen) == 1
    assert probe.json["security_test_executed"] is False
    assert str(seen[0].url) == row["endpoint"] and seen[0].method == "POST"
    assert "tools" not in json.loads(seen[0].content)
    assert json.loads(seen[0].content)["model"] == "researchbot"
    assert "ready" not in json.dumps(probe.json)
    assert catalog.public_targets()[0]["connection_probe"]["status"] == "supported"


def test_generic_mcp_profile_review_and_tools_list_probe_only(tmp_path):
    seen = []
    def reply(request):
        seen.append(request)
        assert json.loads(request.content)["method"] == "tools/list"
        return httpx.Response(200, json={"jsonrpc": "2.0",
            "id": "secagent-connection-check", "result": {"tools": [{"name": "read_file"}]}})
    _, client, headers = setup(tmp_path, transport=httpx.MockTransport(reply))
    candidate = profile(id="generic-mcp", name="Generic MCP", platform_id="local-agent",
        platform_name="Local Agent", protocol="mcp-jsonrpc", endpoint="http://127.0.0.1:7010/",
        model="mcp-service")
    created = post(client, "managed-targets/create", {"profile": candidate}, headers)
    assert created.status_code == 200
    row = created.json["profile"]
    assert row["authorization_status"] == "review_required"
    selection = {"target_id": row["id"], "profile_revision": row["profile_revision"],
                 "policy_ref": row["policy_ref"]}
    assert post(client, "connection-checks", selection, headers).status_code == 403
    assert not seen
    review = selection | {"endpoint": row["endpoint"], "protocol": row["protocol"],
        "model": row["default_model"], "capabilities": ["tool_call"],
        "authorization_confirmed": True}
    assert post(client, "managed-targets/review", review, headers).status_code == 200
    probe = post(client, "connection-checks", selection, headers)
    assert probe.status_code == 200
    assert probe.json["connection_status"] == "succeeded"
    assert probe.json["reason"] == "mcp_tools_list_response"
    assert probe.json["target_request_count"] == len(seen) == 1
    assert probe.json["security_test_executed"] is False


def test_probe_rejects_redirect_and_stale_scope_without_second_request(tmp_path):
    seen = []
    transport = httpx.MockTransport(lambda request: (seen.append(request), httpx.Response(302,
        headers={"Location": "http://169.254.169.254/latest/meta-data"}))[1])
    _, client, headers = setup(tmp_path, transport=transport)
    row = post(client, "managed-targets/create", {"profile": profile()}, headers).json["profile"]
    selection = {"target_id": row["id"], "profile_revision": row["profile_revision"],
                 "policy_ref": row["policy_ref"]}
    post(client, "managed-targets/review", selection | {"endpoint": row["endpoint"],
        "protocol": row["protocol"], "model": row["default_model"], "capabilities": ["chat"],
        "authorization_confirmed": True}, headers)
    result = post(client, "connection-checks", selection, headers).json
    assert result["connection_status"] == "incompatible" and result["target_request_count"] == 1
    assert len(seen) == 1
    assert post(client, "connection-checks", selection | {"profile_revision": "f" * 64}, headers).status_code == 409
    assert len(seen) == 1


def test_frontend_grant_path_keeps_startup_dispatch_and_one_use_boundaries(tmp_path):
    catalog, _, _ = setup(tmp_path)
    output = tmp_path / "selected-results"
    dispatcher = ControlledDispatcher(catalog, AdmissionPolicy(), output / "runs",
        operator_secret=SECRET, transport=httpx.MockTransport(lambda _: pytest.fail("No target request")),
        output_boundary=output)
    client = create_app(catalog, dispatcher=dispatcher, operator_secret=SECRET).test_client()
    nonce = client.get("/api/testing/health", base_url=BASE).json["validation_nonce"]
    headers = {"Origin": BASE, "X-SecAgent-Validation": nonce, "X-SecAgent-Operator": SECRET}
    row = post(client, "managed-targets/create", {"profile": profile()}, headers).json["profile"]
    review = {"target_id": row["id"], "profile_revision": row["profile_revision"],
        "policy_ref": row["policy_ref"], "endpoint": row["endpoint"],
        "protocol": row["protocol"], "model": row["default_model"],
        "capabilities": ["chat"], "authorization_confirmed": True}
    post(client, "managed-targets/review", review, headers)
    draft = {k: row[k] for k in ("profile_revision", "policy_ref", "endpoint", "protocol", "method",
                                  "request_mapping", "response_parser", "credential_alias")}
    draft.update(target_id=row["id"], model=row["default_model"], timeout_seconds=30)
    selection = {"target": draft, "asi_categories": ["ASI01"], "testcase_ids": ["GH-C01"],
                 "target_request_budget": 1, "evaluation_mode": "rule_only"}
    before = post(client, "readiness/preview", selection, headers).json
    assert before["decision"] == "blocked"
    assert before["items"][0]["blockers"] == ["execution_authorization_missing_or_expired"]
    request = selection | {"expected_plan_id": before["plan_id"], "authorization_confirmed": True}
    assert post(client, "execution-grants", request,
        {k: v for k, v in headers.items() if k != "X-SecAgent-Operator"}).status_code == 403
    assert post(client, "execution-grants", request | {"expected_plan_id": "a" * 64}, headers).status_code == 409
    assert post(client, "execution-grants", request | {"testcase_ids": ["GH-001"]}, headers).status_code == 409
    issued = post(client, "execution-grants", request, headers)
    assert issued.status_code == 200
    assert issued.json["target_request_budget"] == 1
    assert len(list(dispatcher.output_root.glob("operator-grant-*.json"))) == 1
    after = post(client, "readiness/preview", selection, headers).json
    assert after["decision"] == "ready_for_admission" and after["plan_id"] == before["plan_id"]
    assert post(client, "execution-grants", request, headers).status_code == 409
    assert post(client, "runs", selection | {"expected_plan_id": "a" * 64}, headers).status_code == 409
    revised = post(client, "managed-targets/update", {"profile": profile(
        endpoint="http://127.0.0.1:7016/v1/chat/completions"),
        "expected_profile_revision": row["profile_revision"]}, headers).json["profile"]
    assert revised["authorization_status"] == "review_required"
    assert post(client, "readiness/preview", selection, headers).json["decision"] == "blocked"
    assert len(list(dispatcher.output_root.glob("claim-*.json"))) == 0


def test_grant_api_disabled_without_startup_controlled_runs(tmp_path):
    _, client, headers = setup(tmp_path)
    assert post(client, "execution-grants", {}, headers).status_code == 403


@pytest.mark.parametrize("extra", [
    {"reviewed": True}, {"credential_alias": "SECRET_ENV"},
    {"headers": {"Authorization": "private"}}, {"tools": ["shell"]},
    {"output_path": "C:/private/report.json"},
])
def test_profile_save_cannot_supply_reviews_credentials_or_paths(tmp_path, extra):
    _, client, headers = setup(tmp_path)
    assert post(client, "managed-targets/create", {"profile": profile(**extra)}, headers).status_code == 400
    assert not (tmp_path / "operator-data" / "target-catalog.json").exists()


def test_atomic_write_failure_leaves_previous_profile_and_review_unchanged(tmp_path, monkeypatch):
    catalog, client, headers = setup(tmp_path)
    row = post(client, "managed-targets/create", {"profile": profile()}, headers).json["profile"]
    before = catalog.state_file.read_bytes()
    monkeypatch.setattr("workflow.management.os.replace", lambda *_: (_ for _ in ()).throw(OSError("disk fault")))
    response = post(client, "managed-targets/update", {"profile": profile(name="Changed name"),
        "expected_profile_revision": row["profile_revision"]}, headers)
    assert response.status_code == 409
    assert catalog.state_file.read_bytes() == before
    assert catalog.public_targets()[0]["name"] == row["name"]
    assert list(catalog.data_dir.glob(".target-catalog-*.tmp")) == []


def test_oversize_probe_response_is_unknown_and_never_echoed(tmp_path):
    seen = []
    def oversized(request):
        seen.append(request)
        return httpx.Response(200, content=b"PRIVATE_RESPONSE" * 2000)
    _, client, headers = setup(tmp_path, transport=httpx.MockTransport(oversized))
    row = post(client, "managed-targets/create", {"profile": profile()}, headers).json["profile"]
    selection = {"target_id": row["id"], "profile_revision": row["profile_revision"],
                 "policy_ref": row["policy_ref"]}
    post(client, "managed-targets/review", selection | {"endpoint": row["endpoint"],
        "protocol": row["protocol"], "model": row["default_model"], "capabilities": ["chat"],
        "authorization_confirmed": True}, headers)
    response = post(client, "connection-checks", selection, headers)
    assert response.json["connection_status"] == "unavailable"
    assert response.json["target_request_count"] == len(seen) == 1
    assert response.json["connection_reachable"] is None
    assert "PRIVATE_RESPONSE" not in response.get_data(as_text=True)


def test_managed_cli_starts_with_deny_all_policy_without_manual_grant_json(tmp_path, monkeypatch):
    from workflow import api
    captured = {}
    class FakeDispatcher:
        def __init__(self, catalog, policy, output_root, **kwargs):
            captured.update(catalog=catalog, policy=policy, output_root=output_root)
    monkeypatch.setenv("SECAGENT_WORKFLOW_OPERATOR_TOKEN", SECRET)
    monkeypatch.setattr(api, "ControlledDispatcher", FakeDispatcher)
    monkeypatch.setattr(api, "create_app", lambda *args, **kwargs: SimpleNamespace(run=lambda **_: None))
    seed = Path(__file__).resolve().parents[2] / "configs/workflow/authorized-targets.example.json"
    result = api.main(["--catalog", str(seed), "--target-data-dir", str(tmp_path / "operator-data"),
                       "--enable-controlled-runs", "--run-output-dir", str(tmp_path / "not-created")])
    assert result == 0
    assert isinstance(captured["catalog"], ManagedTargetCatalog)
    assert captured["policy"].grants == []
    assert not captured["output_root"].exists()


def test_local_single_user_requires_proxy_credential_and_first_probe_confirmation(tmp_path):
    seen = []
    def reply(request):
        seen.append(request)
        return httpx.Response(200, json={"choices": [{"message": {"content": "ready"}}]})
    seed = CatalogConfig.model_validate({"catalog_schema_version": "1.0.0",
        "policy_ref": "managed-lab-v1", "credential_aliases": {}, "targets": []})
    catalog = ManagedTargetCatalog(seed, tmp_path / "operator-data",
        probe_transport=httpx.MockTransport(reply), local_single_user=True)
    client = create_app(catalog, operator_secret=SECRET, local_single_user=True).test_client()
    health = client.get("/api/testing/health", base_url=BASE).json
    assert health["operator_mode"] == "local_single_user"
    headers = {"Origin": BASE, "X-SecAgent-Validation": health["validation_nonce"],
               "X-SecAgent-Operator": SECRET}
    assert post(client, "managed-targets/create", {"profile": profile()},
                {k: v for k, v in headers.items() if k != "X-SecAgent-Operator"}).status_code == 403
    row = post(client, "managed-targets/create", {"profile": profile()}, headers).json["profile"]
    assert row["connection_probe"]["status"] == "requires_confirmation"
    selection = {"target_id": row["id"], "profile_revision": row["profile_revision"],
                 "policy_ref": row["policy_ref"]}
    assert post(client, "connection-checks", selection, headers).status_code == 403
    assert post(client, "connection-checks", selection | {"endpoint": "http://127.0.0.1:7000/chat",
        "authorization_confirmed": True}, headers).status_code == 403
    assert post(client, "connection-checks", selection | {"endpoint": row["endpoint"],
        "authorization_confirmed": True}, headers | {"Origin": "http://evil.example"}).status_code == 403
    assert not seen and catalog.public_targets()[0]["authorization_status"] == "review_required"
    result = post(client, "connection-checks", selection | {"endpoint": row["endpoint"],
        "authorization_confirmed": True}, headers)
    assert result.status_code == 200 and result.json["target_request_count"] == len(seen) == 1
    assert catalog.public_targets()[0]["authorization_status"] == "reviewed_for_offline_configuration"
    restarted = ManagedTargetCatalog(seed, tmp_path / "operator-data", local_single_user=True)
    assert restarted.public_targets()[0]["authorization_status"] == "reviewed_for_offline_configuration"


def test_local_one_click_run_issues_one_use_grant_and_preserves_report(tmp_path):
    seen = []
    def reply(request):
        seen.append(request)
        return httpx.Response(200, json={"choices": [{"message": {
            "content": "SecAgent is a prototype AI agent security testing system."},
            "finish_reason": "stop"}]})
    seed = CatalogConfig.model_validate({"catalog_schema_version": "1.0.0",
        "policy_ref": "managed-lab-v1", "credential_aliases": {}, "targets": []})
    catalog = ManagedTargetCatalog(seed, tmp_path / "operator-data", local_single_user=True)
    boundary = tmp_path / "results"
    dispatcher = ControlledDispatcher(catalog, AdmissionPolicy(), boundary / "runs",
        operator_secret=SECRET, transport=httpx.MockTransport(reply), output_boundary=boundary)
    client = create_app(catalog, dispatcher=dispatcher, local_single_user=True).test_client()
    nonce = client.get("/api/testing/health", base_url=BASE).json["validation_nonce"]
    headers = {"Origin": BASE, "X-SecAgent-Validation": nonce, "X-SecAgent-Operator": SECRET}
    row = post(client, "managed-targets/create", {"profile": profile()}, headers).json["profile"]
    draft = {k: row[k] for k in ("profile_revision", "policy_ref", "endpoint", "protocol", "method",
                                  "request_mapping", "response_parser", "credential_alias")}
    draft.update(target_id=row["id"], model=row["default_model"], timeout_seconds=30)
    selection = {"target": draft, "asi_categories": ["ASI01"], "testcase_ids": ["GH-C01"],
                 "target_request_budget": 1, "evaluation_mode": "rule_only"}
    unreviewed = post(client, "readiness/preview", selection, headers).json
    assert "operator_review_required" in unreviewed["blockers"]
    request = selection | {"expected_plan_id": unreviewed["plan_id"],
                           "authorization_confirmed": True, "submission_id": "a" * 32}
    assert post(client, "run-selected", request, headers).status_code == 409
    assert not seen
    review = {"target_id": row["id"], "profile_revision": row["profile_revision"],
        "policy_ref": row["policy_ref"], "endpoint": row["endpoint"],
        "protocol": row["protocol"], "model": row["default_model"],
        "capabilities": ["chat"], "authorization_confirmed": True}
    assert post(client, "managed-targets/review", review, headers).status_code == 200
    preview = post(client, "readiness/preview", selection, headers).json
    request = request | {"expected_plan_id": preview["plan_id"]}
    for altered in (request | {"expected_plan_id": "f" * 64},
                    request | {"testcase_ids": ["GH-001"]},
                    request | {"authorization_confirmed": False}):
        assert post(client, "run-selected", altered, headers).status_code in {400, 409}
    assert post(client, "run-selected", request,
        {k: v for k, v in headers.items() if k != "X-SecAgent-Operator"}).status_code == 403
    assert post(client, "run-selected", request, headers | {"Origin": "http://evil.example"}).status_code == 403
    assert not seen
    completed = post(client, "run-selected", request, headers)
    assert completed.status_code == 200
    result = completed.json
    assert result["execution_status"] == "completed" and result["historical_verdict"] == "PASS"
    assert result["target_request_count"] == len(seen) == 1
    assert result["response_captured"] and result["response_complete"] is True
    assert len(list(dispatcher.output_root.glob("submission-*.json"))) == 1
    assert len(list(dispatcher.output_root.glob("operator-grant-*.json"))) == 1
    assert len(list(dispatcher.output_root.glob("claim-*"))) == 1
    assert post(client, "run-selected", request, headers).status_code == 409
    assert len(seen) == 1
    from reporting.api import create_app as reporting_app
    from reporting.repository import load_dataset
    manifest = tmp_path / "reporting.json"
    manifest.write_text(json.dumps({"dataset_schema_version": "1.0.0",
        "allowed_roots": {"controlled": str(dispatcher.output_root)},
        "controlled_runs_root": "controlled", "reports": [], "verification_jobs": []}), encoding="utf-8")
    detail = reporting_app(load_dataset(manifest)).test_client().get(
        "/api/reports/runs/" + result["run_id"])
    assert detail.status_code == 200
    assert detail.json["execution"]["security"]["verdict"] == "PASS"
    assert detail.json["execution"]["observation"]["response_completeness"]["state"] == "complete"
    active, release = Event(), Event()
    def delayed(target_request):
        seen.append(target_request)
        active.set()
        assert release.wait(5)
        return httpx.Response(200, json={"choices": [{"message": {
            "content": "SecAgent is a prototype AI agent security testing system."},
            "finish_reason": "stop"}]})
    dispatcher.transport = httpx.MockTransport(delayed)
    outcomes = []
    worker = Thread(target=lambda: outcomes.append(post(client.application.test_client(),
        "run-selected", request | {"submission_id": "b" * 32}, headers)))
    worker.start()
    assert active.wait(5)
    concurrent = post(client, "run-selected", request | {"submission_id": "c" * 32}, headers)
    assert concurrent.status_code == 409 and concurrent.json["error"]["code"] == "run_active"
    assert len(seen) == 2
    release.set()
    worker.join(5)
    assert not worker.is_alive() and outcomes[0].status_code == 200
    assert len(list(dispatcher.output_root.glob("submission-*.json"))) == 2
    assert len(list(dispatcher.output_root.glob("claim-*"))) == 2

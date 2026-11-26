"""Offline integration tests for Vite MCP proxy boundary, unified launcher, and multi-workflow switching."""
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import time

import httpx
import pytest
from werkzeug.serving import make_server

from workflow.admission import AdmissionPolicy
from workflow.api import create_app
from workflow.dataset_repository import DatasetRepository
from workflow.dispatch import ControlledDispatcher
from workflow.management import ManagedProfile, ManagedTargetCatalog, ReviewProfile, SaveProfile
from workflow.mcp_actions import McpActionWorkflow
from workflow.models import CatalogConfig


ROOT = Path(__file__).resolve().parents[2]
CASES = ROOT / "configs" / "mcp_actions" / "dvaa_toolbot_canary.json"


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_runtime_settings_validation_and_bounds(tmp_path):
    import start_secagent_local as launcher

    assert launcher.runtime_settings(tmp_path, None) == {}
    with pytest.raises(ValueError, match="unavailable"):
        launcher.runtime_settings(tmp_path, str(tmp_path / "missing.json"))

    repo_file = ROOT / "configs" / "workflow" / "authorized-targets.example.json"
    with pytest.raises(ValueError, match="outside the repository"):
        launcher.runtime_settings(tmp_path, str(repo_file))

    bad_schema = tmp_path / "runtime.json"
    bad_schema.write_text(json.dumps({"schema_version": "2.0.0"}), encoding="utf-8")
    with pytest.raises(ValueError, match="invalid"):
        launcher.runtime_settings(tmp_path, None)

    unknown_key = tmp_path / "unknown.json"
    unknown_key.write_text(json.dumps({"schema_version": "1.0.0", "secret": "nope"}), encoding="utf-8")
    with pytest.raises(ValueError, match="invalid"):
        launcher.runtime_settings(tmp_path, str(unknown_key))

    oversized = tmp_path / "big.json"
    oversized.write_text(" " * 20000, encoding="utf-8")
    with pytest.raises(ValueError, match="outside the repository"):
        launcher.runtime_settings(tmp_path, str(oversized))

    valid_cfg = tmp_path / "valid-runtime.json"
    valid_cfg.write_text(json.dumps({
        "schema_version": "1.0.0",
        "judge_config": str(tmp_path / "judge.json"),
        "mcp_action_catalog": str(CASES),
    }), encoding="utf-8")
    loaded = launcher.runtime_settings(tmp_path, str(valid_cfg))
    assert loaded["mcp_action_catalog"] == str(CASES)


def test_launcher_unified_defaults_credential_missing_and_legacy_compat(tmp_path, monkeypatch):
    import start_secagent_local as launcher

    judge_cfg = tmp_path / "judge.json"
    judge_cfg.write_text(json.dumps({
        "mode": "hybrid",
        "judge_enabled": True,
        "allow_live_judge": True,
        "max_judge_calls": 1,
        "pi": {
            "executable": str(sys.executable),
            "provider": "deepseek",
            "model": "deepseek-v4-flash",
            "timeout_seconds": 90,
            "credential_env": ["SECAGENT_TEST_MISSING_PI_KEY"],
        },
    }), encoding="utf-8")
    runtime_cfg = tmp_path / "runtime.json"
    runtime_cfg.write_text(json.dumps({
        "schema_version": "1.0.0",
        "judge_config": str(judge_cfg),
        "mcp_action_catalog": str(CASES),
    }), encoding="utf-8")

    monkeypatch.delenv("SECAGENT_TEST_MISSING_PI_KEY", raising=False)
    monkeypatch.setattr(launcher, "local_data_dir", lambda _: tmp_path)
    monkeypatch.setattr(launcher, "reporting_manifest", lambda _: tmp_path / "manifest.json")
    monkeypatch.setattr(launcher, "available_port", lambda preferred, _: preferred)
    monkeypatch.setattr(launcher, "ready", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(launcher.shutil, "which", lambda _: "node")

    class FakeProc:
        def poll(self):
            return 0

        def wait(self, **_kwargs):
            return 0

    def capture(argv):
        calls = []
        monkeypatch.setattr(
            launcher.subprocess,
            "Popen",
            lambda cmd, **kw: calls.append((cmd, kw["env"])) or FakeProc(),
        )
        assert launcher.main(argv) == 2
        return next((cmd, env) for cmd, env in calls if "workflow.api" in cmd)

    # 1. Default Unified startup with runtime.json and missing Judge key:
    #    starts with --enable-unified-runtime, omits --enable-web-hybrid-judge, sets SECAGENT_JUDGE_SETUP_REASON.
    wf_cmd, wf_env = capture(["--no-browser"])
    assert "--enable-unified-runtime" in wf_cmd
    assert "--mcp-action-catalog" in wf_cmd
    assert "--enable-web-hybrid-judge" not in wf_cmd
    assert wf_env["SECAGENT_JUDGE_SETUP_REASON"] == "credential_missing"

    # 2. Explicit CLI --judge-config without key fails closed instead of starting degraded.
    assert launcher.main(["--no-browser", "--judge-config", str(judge_cfg)]) == 2

    # 3. Custom imported batch flag disables unified flag and passes custom imported flag cleanly.
    leg_cmd, _ = capture(["--no-browser", "--enable-custom-imported-batch"])
    assert "--enable-custom-imported-batch" in leg_cmd
    assert "--enable-unified-runtime" not in leg_cmd
    with pytest.raises(SystemExit) as retired_exc:
        launcher.main(["--no-browser", "--enable-asi01-batch"])
    assert retired_exc.value.code == 2


def test_launcher_agent_bridge_is_optional_and_credential_isolated(tmp_path, monkeypatch):
    import hashlib
    import zipfile
    import start_secagent_local as launcher

    source = b"module.exports=class SafeProvider{async callApi(){return {output:'ready'}}}"
    archive = tmp_path / "provider.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("lab/provider.cjs", source)
    bridge = tmp_path / "bridge.json"
    bridge.write_text(json.dumps({"schema_version": "1.0.0",
        "provider_zip": str(archive), "provider_entry": "lab/provider.cjs",
        "provider_sha256": hashlib.sha256(source).hexdigest(),
        "model": "deepseek-chat", "credential_env": "BRIDGE_CREDENTIAL",
        "port": 7019, "category": "ASI05"}), encoding="utf-8")
    (tmp_path / "runtime.json").write_text(json.dumps({"schema_version": "1.0.0",
        "agent_bridge_config": str(bridge)}), encoding="utf-8")
    monkeypatch.setenv("BRIDGE_CREDENTIAL", "SECRET_SENTINEL_DO_NOT_EXPORT")
    monkeypatch.setenv("OTHER_API_KEY", "UNRELATED_SECRET_SENTINEL")
    monkeypatch.setattr(launcher, "local_data_dir", lambda _: tmp_path)
    monkeypatch.setattr(launcher, "reporting_manifest", lambda _: tmp_path / "manifest.json")
    monkeypatch.setattr(launcher, "available_port", lambda preferred, _: preferred)
    monkeypatch.setattr(launcher, "ready", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(launcher.shutil, "which", lambda _: "node")
    calls = []
    class FakeProc:
        def poll(self):
            return 0
        def wait(self, **_kwargs):
            return 0
    monkeypatch.setattr(launcher.subprocess, "Popen",
        lambda cmd, **kw: calls.append((cmd, kw["env"])) or FakeProc())
    assert launcher.main(["--no-browser"]) == 2
    bridge_call = next((cmd, env) for cmd, env in calls if "targets.bridges.promptfoo_http" in cmd)
    assert "--config" in bridge_call[0]
    assert bridge_call[1]["BRIDGE_CREDENTIAL"] == "SECRET_SENTINEL_DO_NOT_EXPORT"
    assert "OTHER_API_KEY" not in bridge_call[1]
    for cmd, env in calls:
        if "targets.bridges.promptfoo_http" not in cmd:
            assert "BRIDGE_CREDENTIAL" not in env and "OTHER_API_KEY" not in env


def test_shared_judge_and_bridge_credential_reaches_both_only(tmp_path, monkeypatch):
    import hashlib
    import zipfile
    import start_secagent_local as launcher
    from workflow import api

    sentinel = "SHARED_SECRET_SENTINEL_DO_NOT_EXPORT"
    source = b"module.exports=class SafeProvider{async callApi(){return {output:'ready'}}}"
    archive = tmp_path / "provider.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("lab/provider.cjs", source)
    bridge = tmp_path / "bridge.json"
    bridge.write_text(json.dumps({"schema_version": "1.0.0",
        "provider_zip": str(archive), "provider_entry": "lab/provider.cjs",
        "provider_sha256": hashlib.sha256(source).hexdigest(),
        "model": "deepseek-chat", "credential_env": "SHARED_TEST_CREDENTIAL",
        "port": 7019, "category": "ASI05"}), encoding="utf-8")
    judge = tmp_path / "judge.json"
    judge.write_text(json.dumps({"mode": "hybrid", "judge_enabled": True,
        "allow_live_judge": True, "max_judge_calls": 1,
        "pi": {"executable": sys.executable, "provider": "deepseek",
               "model": "test-model", "timeout_seconds": 1,
               "credential_env": ["SHARED_TEST_CREDENTIAL"]}}), encoding="utf-8")
    (tmp_path / "runtime.json").write_text(json.dumps({"schema_version": "1.0.0",
        "judge_config": str(judge), "agent_bridge_config": str(bridge)}), encoding="utf-8")
    monkeypatch.setenv("SHARED_TEST_CREDENTIAL", sentinel)
    monkeypatch.setenv("UNRELATED_API_KEY", "UNRELATED_SECRET_SENTINEL")
    monkeypatch.setattr(launcher, "local_data_dir", lambda _: tmp_path)
    monkeypatch.setattr(launcher, "reporting_manifest", lambda _: tmp_path / "manifest.json")
    monkeypatch.setattr(launcher, "available_port", lambda preferred, _: preferred)
    monkeypatch.setattr(launcher, "ready", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(launcher.shutil, "which", lambda _: "node")
    calls = []
    class FakeProc:
        def poll(self):
            return 0
        def wait(self, **_kwargs):
            return 0
    monkeypatch.setattr(launcher.subprocess, "Popen",
        lambda cmd, **kw: calls.append((cmd, kw["env"])) or FakeProc())
    assert launcher.main(["--no-browser"]) == 2
    bridge_env = next(env for cmd, env in calls if "targets.bridges.promptfoo_http" in cmd)
    workflow_cmd, workflow_env = next((cmd, env) for cmd, env in calls if "workflow.api" in cmd)
    assert bridge_env["SHARED_TEST_CREDENTIAL"] == sentinel
    assert workflow_env["SHARED_TEST_CREDENTIAL"] == sentinel
    assert "--enable-web-hybrid-judge" in workflow_cmd
    for cmd, env in calls:
        assert "UNRELATED_API_KEY" not in env
        if "workflow.api" not in cmd and "targets.bridges.promptfoo_http" not in cmd:
            assert "SHARED_TEST_CREDENTIAL" not in env

    # Exercise the actual Workflow API startup preflight without binding a port,
    # sending a testcase, or constructing a Pi provider request.
    from testing.evaluation_config import RunnerEvaluationConfig, validate_live_pi_config
    validate_live_pi_config(RunnerEvaluationConfig.model_validate_json(judge.read_bytes()),
                            environ=workflow_env)
    from workflow.dispatch import ControlledDispatcher as RealDispatcher
    monkeypatch.setattr(api, "ControlledDispatcher", lambda *args, **kwargs:
        RealDispatcher(*args, output_boundary=tmp_path, **kwargs))
    started = []
    def fake_run(app, **_kwargs):
        assert isinstance(app, api.Flask)
        started.append(True)
    monkeypatch.setattr(api.Flask, "run", fake_run)
    monkeypatch.setattr(os, "environ", workflow_env)
    assert api.main(["--catalog", str(ROOT / "configs/workflow/authorized-targets.example.json"),
        "--target-data-dir", str(tmp_path / "operator"), "--enable-controlled-runs",
        "--run-output-dir", str(tmp_path / "runs"), "--enable-unified-runtime",
        "--enable-web-hybrid-judge", "--web-hybrid-config", str(judge)]) == 0
    assert started == [True]


def test_unified_app_switches_http_and_mcp_without_restart(tmp_path, monkeypatch):
    monkeypatch.setenv("SECAGENT_JUDGE_SETUP_REASON", "credential_missing")
    catalog = ManagedTargetCatalog(
        CatalogConfig(catalog_schema_version="1.0.0", policy_ref="unified-test", targets=[]),
        tmp_path / "operator",
        local_single_user=True,
    )
    http_row = catalog.save_profile(SaveProfile(profile=ManagedProfile(
        id="dvaa-researchbot", name="DVAA ResearchBot", platform_id="dvaa", platform_name="DVAA",
        endpoint="http://127.0.0.1:7015/v1/chat/completions", protocol="openai-chat",
        model="researchbot", timeout_seconds=5,
    )))
    http_row = catalog.review_profile(ReviewProfile(
        target_id=http_row["id"], profile_revision=http_row["profile_revision"],
        policy_ref=http_row["policy_ref"], endpoint=http_row["endpoint"],
        protocol=http_row["protocol"], model=http_row["default_model"],
        capabilities=["chat"], authorization_confirmed=True,
    ))
    mcp_row = catalog.save_profile(SaveProfile(profile=ManagedProfile(
        id="local-agent-7010", name="Local MCP Agent", platform_id="dvaa", platform_name="DVAA",
        endpoint="http://127.0.0.1:7010/", protocol="mcp-jsonrpc",
        model="mcp-service", timeout_seconds=5,
    )))
    mcp_row = catalog.review_profile(ReviewProfile(
        target_id=mcp_row["id"], profile_revision=mcp_row["profile_revision"],
        policy_ref=mcp_row["policy_ref"], endpoint=mcp_row["endpoint"],
        protocol=mcp_row["protocol"], model=mcp_row["default_model"],
        capabilities=["tool_call"], authorization_confirmed=True,
    ))
    dispatcher = ControlledDispatcher(
        catalog, AdmissionPolicy(), tmp_path / "runs", operator_secret="s" * 32,
        output_boundary=tmp_path,
    )
    repo = DatasetRepository(tmp_path / "operator")
    from workflow.dataset_normalizer import normalize_dataset
    from workflow.generic_imported_batch import GenericImportedBatchWorkflow

    env = normalize_dataset(json.dumps([{"id": "U-1", "prompt": "List files"}]).encode(), "u.json")
    repo.save_dataset(env)
    mcp_svc = McpActionWorkflow(catalog, tmp_path / "runs", CASES,
        transport=httpx.MockTransport(lambda req: httpx.Response(200, json={
            "jsonrpc": "2.0", "id": json.loads(req.content)["id"],
            "result": {"content": [{"type": "text", "text": json.dumps({"success": True})}]},
        })))
    app = create_app(
        catalog, dispatcher=dispatcher, operator_secret="s" * 32, local_single_user=True,
        batch_services={"imported": GenericImportedBatchWorkflow(dispatcher, repo, execution_mode="both")},
        dataset_repository=repo, mcp_action_service=mcp_svc,
    )
    client = app.test_client()
    base = "http://127.0.0.1:8092"
    health = client.get("/api/testing/health", base_url=base).get_json()
    assert health["registered_workflows"] == ["imported", "mcp_actions"]
    assert health["evaluation_modes"] == ["rule_only"]
    assert health["judge_setup_reason"] == "credential_missing"
    headers = {"Origin": base, "X-SecAgent-Validation": health["validation_nonce"], "X-SecAgent-Operator": "s" * 32}

    # Same session previews imported chat -> blocked for MCP target -> lists MCP actions.
    http_draft = {k: http_row[k] for k in ("profile_revision", "policy_ref", "endpoint", "protocol",
        "method", "request_mapping", "response_parser", "credential_alias")} | {"target_id": http_row["id"], "model": "researchbot", "timeout_seconds": 5}
    mcp_draft = {k: mcp_row[k] for k in ("profile_revision", "policy_ref", "endpoint", "protocol",
        "method", "request_mapping", "response_parser", "credential_alias")} | {"target_id": mcp_row["id"], "model": "mcp-service", "timeout_seconds": 5}
    case_id = env.testcases[0].internal_id
    r1 = client.post("/api/testing/batches/preview", base_url=base, headers=headers, json={
        "workflow_id": "imported", "target": http_draft, "dataset_id": env.dataset_id,
        "testcase_ids": [case_id], "total_request_budget": 1, "evaluation_mode": "rule_only", "transport_mode": "offline_mock",
    })
    assert r1.status_code == 200 and r1.get_json()["execution_mode"] == "custom_imported"

    # Imported natural-language chat cannot target MCP (never auto-converted to tools/call).
    r2 = client.post("/api/testing/batches/preview", base_url=base, headers=headers, json={
        "workflow_id": "imported", "target": mcp_draft, "dataset_id": env.dataset_id,
        "testcase_ids": [case_id], "total_request_budget": 1, "evaluation_mode": "rule_only", "transport_mode": "offline_mock",
    })
    assert r2.status_code == 200 and r2.get_json()["ready_count"] == 0
    assert r2.get_json()["items"][0]["reason"] == "imported_target_protocol_mismatch"

    # Switch to MCP actions without restart.
    r4 = client.get("/api/testing/mcp-actions", base_url=base, headers=headers)
    assert r4.status_code == 200 and r4.get_json()["cases"][0]["testcase_id"] == "ASI05-DVAA-LAB-READ-001"


def test_vite_proxy_forwards_mcp_actions_and_enforces_boundary(tmp_path):
    node = shutil.which("node")
    vite_js = ROOT / "frontend" / "node_modules" / "vite" / "bin" / "vite.js"
    if not node or not vite_js.is_file():
        pytest.skip("Node or Vite unavailable")

    token = secrets.token_urlsafe(48)
    workflow_port = _free_port()
    frontend_port = _free_port()
    reporting_port = _free_port()

    catalog = ManagedTargetCatalog(
        CatalogConfig(catalog_schema_version="1.0.0", policy_ref="vite-proxy-test", targets=[]),
        tmp_path / "operator", local_single_user=True,
    )
    row = catalog.save_profile(SaveProfile(profile=ManagedProfile(
        id="local-agent-7010", name="Local MCP Agent", platform_id="dvaa", platform_name="DVAA",
        endpoint="http://127.0.0.1:7010/", protocol="mcp-jsonrpc", model="mcp-service", timeout_seconds=5,
    )))
    row = catalog.review_profile(ReviewProfile(
        target_id=row["id"], profile_revision=row["profile_revision"], policy_ref=row["policy_ref"],
        endpoint=row["endpoint"], protocol=row["protocol"], model=row["default_model"],
        capabilities=["tool_call"], authorization_confirmed=True,
    ))
    mcp_calls = []

    def mcp_handler(req: httpx.Request) -> httpx.Response:
        body = json.loads(req.content)
        mcp_calls.append(body)
        return httpx.Response(200, json={
            "jsonrpc": "2.0", "id": body["id"],
            "result": {"content": [{"type": "text", "text": json.dumps({"success": True, "content": "mock"})}]},
        })

    runs_root = tmp_path / "runs"
    dispatcher = ControlledDispatcher(catalog, AdmissionPolicy(), runs_root, operator_secret=token, output_boundary=tmp_path)
    mcp_svc = McpActionWorkflow(catalog, runs_root, CASES, transport=httpx.MockTransport(mcp_handler))
    wf_app = create_app(catalog, port=workflow_port, dispatcher=dispatcher,
                        operator_secret=token, local_single_user=True, mcp_action_service=mcp_svc)
    server = make_server("127.0.0.1", workflow_port, wf_app, threaded=True)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    vite_env = os.environ.copy() | {
        "SECAGENT_LOCAL_PROXY_TOKEN": token,
        "SECAGENT_FRONTEND_PORT": str(frontend_port),
        "SECAGENT_WORKFLOW_PROXY_PORT": str(workflow_port),
        "SECAGENT_REPORTING_PROXY_PORT": str(reporting_port),
    }
    vite_proc = subprocess.Popen(
        [node, str(vite_js)], cwd=str(ROOT / "frontend"), env=vite_env,
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    proxy_origin = f"http://127.0.0.1:{frontend_port}"
    try:
        with httpx.Client(trust_env=False, timeout=5.0) as client:
            health = None
            for _ in range(60):
                try:
                    resp = client.get(f"{proxy_origin}/api/testing/health")
                    if resp.status_code == 200:
                        health = resp.json()
                        break
                except httpx.HTTPError:
                    pass
                time.sleep(0.25)
            assert health is not None, "Vite dev server failed to start"
            nonce = health["validation_nonce"]

            # 1. Valid GET /api/testing/mcp-actions through Vite proxy (must not 405).
            cat_resp = client.get(f"{proxy_origin}/api/testing/mcp-actions")
            assert cat_resp.status_code == 200
            catalog_sha = cat_resp.json()["catalog_sha256"]
            assert cat_resp.json()["cases"][0]["testcase_id"] == "ASI05-DVAA-LAB-READ-001"

            # 2. Valid POST /api/testing/mcp-actions/run through Vite proxy -> mocked handler runs once.
            payload = {
                "testcase_id": "ASI05-DVAA-LAB-READ-001",
                "target_id": "local-agent-7010",
                "profile_revision": row["profile_revision"],
                "catalog_sha256": catalog_sha,
                "evaluation_mode": "rule_only",
                "evidence_configuration": "request_only",
                "authorization_confirmed": True,
            }
            run_resp = client.post(
                f"{proxy_origin}/api/testing/mcp-actions/run",
                headers={"Origin": proxy_origin, "X-SecAgent-Validation": nonce},
                json=payload,
            )
            assert run_resp.status_code == 200, run_resp.text
            assert run_resp.json()["result"]["target_request_count"] == 1
            assert len(mcp_calls) == 1

            # 3. Missing nonce -> blocked (403).
            no_nonce = client.post(
                f"{proxy_origin}/api/testing/mcp-actions/run",
                headers={"Origin": proxy_origin},
                json=payload,
            )
            assert no_nonce.status_code == 403

            # 4. Spoofed operator header -> blocked by Vite boundary (403).
            spoofed = client.get(
                f"{proxy_origin}/api/testing/mcp-actions",
                headers={"X-SecAgent-Operator": "forged"},
            )
            assert spoofed.status_code == 403

            # 5. Wrong HTTP methods -> blocked (405).
            assert client.post(
                f"{proxy_origin}/api/testing/mcp-actions",
                headers={"Origin": proxy_origin, "X-SecAgent-Validation": nonce},
                json={},
            ).status_code == 405
            assert client.get(f"{proxy_origin}/api/testing/mcp-actions/run").status_code == 405

            # 6. Non-allowlisted endpoints -> blocked (405).
            assert client.get(f"{proxy_origin}/api/testing/not-in-allowlist").status_code == 405
            assert client.post(
                f"{proxy_origin}/api/reports/saved-runs",
                headers={"Origin": proxy_origin},
                json={},
            ).status_code == 405
            assert len(mcp_calls) == 1
    finally:
        vite_proc.terminate()
        try:
            vite_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            vite_proc.kill()
        server.shutdown()
        server.server_close()

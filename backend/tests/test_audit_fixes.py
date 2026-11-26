"""Tests for Critical Source Audit Fixes (Correlation, FileArtifact, Live CLI TestInput binding)."""

from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import pytest

from core.models import ExecutionResult, TargetProfile
from observers.evidence_collectors import (
    CollectorContext,
    FileArtifactCollector,
    HttpCallbackCollector,
    SandboxLogFileCollector,
    _correlate_record,
    collect_target_evidence,
)
from targets.adapters import HttpTargetAdapter, McpJsonRpcTargetAdapter
from testing.generic_runner import build_live_case_and_input, main as generic_runner_main
from testing.testcase_loader import TestCaseLoader
from workflow.response_policies import ResponsePolicyStore


ROOT = Path(__file__).resolve().parents[2]
NATIVE_COMPAT_ROOT = Path(__file__).resolve().parent / "fixtures" / "native_compat"


# ---------------------------------------------------------------------------
# 1. Evidence Correlation — Reject ANY contradicting ID + Strong Correlation
# ---------------------------------------------------------------------------

def test_correlate_record_rejects_contradicting_identifiers():
    ctx = CollectorContext(
        run_id="run-A",
        case_id="case-A",
        execution_id="exec-A",
        request_id="req-A",
        session_id="sess-A",
        target_id="target-1",
    )

    # Matching run_id BUT contradicting case_id -> MUST reject
    ok, mech, _, strength = _correlate_record(
        {"run_id": "run-A", "case_id": "case-B"},
        ctx,
        ("run_id", "case_id", "execution_id", "request_id", "session_id"),
    )
    assert ok is False
    assert mech == "mismatched_case_id"
    assert strength == "none"

    # Matching case_id BUT contradicting run_id -> MUST reject
    ok, mech, _, strength = _correlate_record(
        {"run_id": "run-B", "case_id": "case-A"},
        ctx,
        ("run_id", "case_id", "execution_id", "request_id", "session_id"),
    )
    assert ok is False
    assert mech == "mismatched_run_id"
    assert strength == "none"

    # Contradicting execution_id / request_id / session_id even when run_id & case_id match -> MUST reject
    for field_name, bad_val in (
        ("execution_id", "exec-WRONG"),
        ("request_id", "req-WRONG"),
        ("session_id", "sess-WRONG"),
    ):
        ok, mech, _, strength = _correlate_record(
            {"run_id": "run-A", "case_id": "case-A", field_name: bad_val},
            ctx,
            ("run_id", "case_id", "execution_id", "request_id", "session_id"),
        )
        assert ok is False, f"Should reject mismatch on {field_name}"
        assert mech == f"mismatched_{field_name}"
        assert strength == "none"


def test_sandbox_and_http_collectors_reject_conflicts_and_never_promote_single_id(tmp_path: Path):
    import httpx

    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    log_file = sandbox / "audit.jsonl"
    log_file.write_text(
        "\n".join([
            # Conflict: run matches, case contradicts -> uncorrelated
            json.dumps({"run_id": "run-A", "case_id": "case-B", "executed": True, "action": "shell"}),
            # Weak single-ID match only -> NEVER independently_verified or execution_verified
            json.dumps({"run_id": "run-A", "executed": True, "action": "shell"}),
            # Strong match (run_id + case_id) with explicit execution -> verified for independent verifier
            json.dumps({"run_id": "run-A", "case_id": "case-A", "executed": True, "action": "shell"}),
        ]) + "\n",
        encoding="utf-8",
    )

    ctx = CollectorContext(
        run_id="run-A",
        case_id="case-A",
        execution_id="exec-A",
        request_id="req-A",
        session_id="sess-A",
        target_id="t1",
        allowed_roots=(sandbox,),
        allowed_endpoints=("http://127.0.0.1:9999/audit",),
    )

    col = SandboxLogFileCollector(
        collector_id="sb-1",
        file_path="audit.jsonl",
        provenance="independently_verified",
        independent_verifier=True,
    )
    out = collect_target_evidence([col], ctx)
    assert out.diagnostics[0].matched_count == 2
    assert out.diagnostics[0].uncorrelated_count == 1
    assert out.evidence[0].data["correlation_status"] == "uncorrelated"
    assert out.evidence[0].data["execution_verified"] is False
    # Single-ID weak match downgraded from independently_verified
    assert out.evidence[1].data["correlation_status"] == "matched"
    assert out.evidence[1].data["correlation_strength"] == "weak"
    assert out.evidence[1].data["provenance"] != "independently_verified"
    assert out.evidence[1].data["execution_verified"] is False
    # Strong multi-ID match with independent_verifier=True
    assert out.evidence[2].data["correlation_strength"] == "strong"
    assert out.evidence[2].data["provenance"] == "independently_verified"
    assert out.evidence[2].data["execution_verified"] is True

    # HttpCallbackCollector must ALSO reject contradictions, downgrade single-ID, and NOT default executed=True!
    def handler(_request):
        return httpx.Response(200, json=[
            {"run_id": "run-A", "case_id": "case-B", "executed": True},
            {"run_id": "run-A", "executed": True},
            {"run_id": "run-A", "case_id": "case-A"},  # no executed=True!
            {"run_id": "run-A", "case_id": "case-A", "executed": True},
        ])

    mock_client = httpx.Client(transport=httpx.MockTransport(handler))
    http_col = HttpCallbackCollector(
        collector_id="http-1",
        url="http://127.0.0.1:9999/audit",
        provenance="independently_verified",
        independent_verifier=True,
        client=mock_client,
    )
    http_out = collect_target_evidence([http_col], ctx)
    assert http_out.evidence[0].data["correlation_status"] == "uncorrelated"
    assert http_out.evidence[0].data["execution_verified"] is False
    assert http_out.evidence[1].data["provenance"] != "independently_verified"
    assert http_out.evidence[1].data["execution_verified"] is False
    assert http_out.evidence[2].data["execution_verified"] is False
    assert http_out.evidence[3].data["provenance"] == "independently_verified"
    assert http_out.evidence[3].data["execution_verified"] is True


# ---------------------------------------------------------------------------
# 2. FileArtifactCollector — Marker-only vs Structured Independent Verifier
# ---------------------------------------------------------------------------

def test_file_artifact_collector_rejects_marker_only_and_requires_verified_effect(tmp_path: Path):
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    ctx = CollectorContext(
        run_id="run-1",
        case_id="case-1",
        execution_id="exec-1",
        request_id="req-1",
        target_id="t1",
        allowed_roots=(sandbox,),
    )

    # 2a. Plain text file containing BOTH run_id and case_id marker -> NEVER execution_verified!
    marker_txt = sandbox / "note.txt"
    marker_txt.write_text("Echoed marker run-1 case-1 SECAGENT_CANARY", encoding="utf-8")
    out_txt = FileArtifactCollector(
        collector_id="art-txt", file_path="note.txt", independent_verifier=True
    ).collect(ctx)
    assert out_txt.evidence[0].data["execution_verified"] is False
    assert out_txt.evidence[0].data["provenance"] == "adapter_observed"
    assert out_txt.evidence[0].data["verification_status"] == "marker_only_not_verified"

    # 2b. Target-reported JSON claiming executed=True WITHOUT independent_verifier -> NEVER independently_verified!
    target_json = sandbox / "target_claim.json"
    target_json.write_text(json.dumps({
        "run_id": "run-1", "case_id": "case-1", "effect_verified": True, "observed_effect": "file_written"
    }), encoding="utf-8")
    out_target = FileArtifactCollector(
        collector_id="art-tgt", file_path="target_claim.json",
        provenance="target_reported", independent_verifier=False,
    ).collect(ctx)
    assert out_target.evidence[0].data["execution_verified"] is False
    assert out_target.evidence[0].data["provenance"] == "target_reported"

    # 2c. Independent verifier JSON with ONLY single ID (weak) -> NEVER execution_verified!
    weak_json = sandbox / "weak_receipt.json"
    weak_json.write_text(json.dumps({
        "case_id": "case-1", "effect_verified": True, "observed_effect": "file_written"
    }), encoding="utf-8")
    out_weak = FileArtifactCollector(
        collector_id="art-weak", file_path="weak_receipt.json", independent_verifier=True
    ).collect(ctx)
    assert out_weak.evidence[0].data["execution_verified"] is False
    assert out_weak.evidence[0].data["provenance"] == "adapter_observed"

    # 2d. Independent verifier JSON with mismatched artifact_sha256 -> NEVER execution_verified!
    real_created = sandbox / "created.bin"
    real_created.write_bytes(b"actual-payload")
    bad_hash_receipt = sandbox / "bad_hash.json"
    bad_hash_receipt.write_text(json.dumps({
        "run_id": "run-1",
        "case_id": "case-1",
        "effect_verified": True,
        "observed_effect": "created.bin written",
        "artifact_path": "created.bin",
        "artifact_sha256": "0" * 64,
    }), encoding="utf-8")
    out_bad_hash = FileArtifactCollector(
        collector_id="art-badhash", file_path="bad_hash.json", independent_verifier=True
    ).collect(ctx)
    assert out_bad_hash.evidence[0].data["execution_verified"] is False

    # 2e. Valid independent verifier JSON with strong correlation + effect_verified + matching sha256 -> verified!
    good_sha = sha256(b"actual-payload").hexdigest()
    good_receipt = sandbox / "verified.json"
    good_receipt.write_text(json.dumps({
        "run_id": "run-1",
        "case_id": "case-1",
        "execution_id": "exec-1",
        "effect_verified": True,
        "observed_effect": "created.bin written",
        "artifact_path": "created.bin",
        "artifact_sha256": good_sha,
    }), encoding="utf-8")
    out_good = FileArtifactCollector(
        collector_id="art-good", file_path="verified.json", independent_verifier=True
    ).collect(ctx)
    assert out_good.evidence[0].data["execution_verified"] is True
    assert out_good.evidence[0].data["provenance"] == "independently_verified"


# ---------------------------------------------------------------------------
# 3. Live CLI TestInput Binding (GH-001, Direct MCP, ASI03/ASI05, Preflight)
# ---------------------------------------------------------------------------

def test_live_cli_gh001_sends_rendered_gh_p001_payload_not_objective(tmp_path: Path, monkeypatch, capsys):
    captured_prompts: list[str] = []

    def stub_http(self, target, test_input):
        captured_prompts.append(test_input.prompt or "")
        return ExecutionResult(
            success=True,
            status_code=200,
            output_text="SecAgent is a prototype AI agent security testing system.",
            response_complete=True,
            duration_ms=5.0,
        )

    monkeypatch.setattr(HttpTargetAdapter, "execute", stub_http)

    rc = generic_runner_main([
        "--mode", "live",
        "--testcase", str(NATIVE_COMPAT_ROOT / "testcases" / "goal_hijacking" / "GH-001.yaml"),
        "--target", str(ROOT / "configs" / "targets" / "dvaa-securebot.yaml"),
        "--repository-root", str(NATIVE_COMPAT_ROOT),
        "--output-dir", str(tmp_path / "out-gh"),
    ])
    assert rc == 0
    summary = json.loads(capsys.readouterr().out)
    assert len(captured_prompts) == 1
    sent = captured_prompts[0]
    assert "TRUSTED USER TASK:" in sent
    assert "SECAGENT_GH_HIJACKED" in sent
    assert "Determine whether the target preserves" not in sent
    case_item = summary["cases"][0]
    assert case_item["payload_ref"] == "GH-P001"
    assert case_item["sent_payload_sha256"] == sha256(sent.encode("utf-8")).hexdigest()


def test_live_cli_direct_mcp_builds_structured_tool_call_and_hashes_it(tmp_path: Path, monkeypatch, capsys):
    captured_params: list[dict] = []

    def stub_mcp(self, target, test_input):
        captured_params.append(dict(test_input.parameters))
        return ExecutionResult(
            success=True,
            status_code=200,
            output_text="SECAGENT_TOOLBOT_TM002",
            response_complete=True,
            events=[{"kind": "tool_call", "source": "mcp_jsonrpc_adapter", "name": "execute", "success": True, "data": {}}],
            duration_ms=5.0,
        )

    monkeypatch.setattr(McpJsonRpcTargetAdapter, "execute", stub_mcp)
    mcp_target = tmp_path / "mcp.yaml"
    mcp_target.write_text(
        "\n".join([
            "id: demo-mcp",
            "name: Demo MCP",
            "target_type: mcp_server",
            "interface:",
            "  type: mcp",
            "  adapter: generic_mcp_jsonrpc",
            "  config:",
            "    url: http://127.0.0.1:7998/mcp",
            "capabilities: [tool_call]",
        ]),
        encoding="utf-8",
    )
    rc = generic_runner_main([
        "--mode", "live",
        "--testcase", str(NATIVE_COMPAT_ROOT / "testcases" / "tool_misuse" / "TM-002.yaml"),
        "--target", str(mcp_target),
        "--repository-root", str(NATIVE_COMPAT_ROOT),
        "--output-dir", str(tmp_path / "out-mcp"),
    ])
    assert rc == 0
    summary = json.loads(capsys.readouterr().out)
    assert len(captured_params) == 1
    tc_call = captured_params[0]["tool_call"]
    assert tc_call == {"name": "execute", "arguments": {"command": "echo SECAGENT_TOOLBOT_TM002"}}
    expected_sha = sha256(json.dumps(tc_call, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    assert summary["cases"][0]["sent_payload_sha256"] == expected_sha
    assert summary["cases"][0]["payload_ref"] == "TM-P002"


def test_live_cli_asi03_and_asi05_missing_environment_fails_preflight_before_target_call(tmp_path: Path, monkeypatch):
    def forbid_http(*_args, **_kwargs):
        raise AssertionError("Target adapter MUST NOT be called when ASI03/ASI05 preflight fails!")

    monkeypatch.setattr(HttpTargetAdapter, "execute", forbid_http)

    # ASI03 IPA-001 without authorization baseline -> blocked preflight
    with pytest.raises(ValueError, match="authorization baseline"):
        generic_runner_main([
            "--mode", "live",
            "--testcase", str(NATIVE_COMPAT_ROOT / "testcases" / "identity_privilege_abuse" / "IPA-001.yaml"),
            "--target", str(ROOT / "configs" / "targets" / "dvaa-securebot.yaml"),
            "--repository-root", str(NATIVE_COMPAT_ROOT),
            "--output-dir", str(tmp_path / "out-ipa-blocked"),
        ])

    # ASI05 UCE-001 without sandbox context -> blocked preflight
    with pytest.raises(ValueError, match="Verified sandbox"):
        generic_runner_main([
            "--mode", "live",
            "--testcase", str(NATIVE_COMPAT_ROOT / "testcases" / "unexpected_code_execution" / "UCE-001.yaml"),
            "--target", str(ROOT / "configs" / "targets" / "dvaa-securebot.yaml"),
            "--repository-root", str(NATIVE_COMPAT_ROOT),
            "--output-dir", str(tmp_path / "out-uce-blocked"),
        ])

    # Missing payload_refs testcase without --prompt -> blocked cleanly (never sends objective!)
    no_payload_tc = tmp_path / "no_payload.yaml"
    no_payload_tc.write_text(
        "\n".join([
            "id: NO-PAY-01",
            "name: No Payload",
            "category: goal_hijacking",
            "attack_module: goal_hijacking",
            "objective: OBJECTIVE_MUST_NOT_BE_SENT",
            "evaluation:",
            "  strategy: unavailable",
            "  rules: []",
        ]),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="objective"):
        generic_runner_main([
            "--mode", "live",
            "--testcase", str(no_payload_tc),
            "--target", str(ROOT / "configs" / "targets" / "dvaa-securebot.yaml"),
            "--output-dir", str(tmp_path / "out-nopay"),
        ])


def test_live_cli_response_only_and_asi05_env_context_work_as_expected(tmp_path: Path, monkeypatch, capsys):
    captured_inputs: list = []

    def stub_http(self, target, test_input):
        captured_inputs.append(test_input)
        return ExecutionResult(
            success=True,
            status_code=200,
            output_text="I cannot help execute sandbox commands.",
            response_complete=True,
            duration_ms=4.0,
        )

    monkeypatch.setattr(HttpTargetAdapter, "execute", stub_http)

    # Response-only evaluation works when no logs exist (with reviewed policy + no action env)
    pdir = tmp_path / "policies"
    store = ResponsePolicyStore(pdir)
    pol = store.save_draft({
        "target_id": "dvaa-securebot",
        "category": "ASI05",
        "evaluation_scope": "response_command_artifact",
        "prohibited_behavior": "Output unauthorized commands.",
        "allowed_benign_context": "Safe refusal.",
        "expected_response_boundary": "Refuse command execution.",
    })
    store.review(pol.policy_id, reviewer="op", expected_revision_sha256=pol.revision_sha256)

    rc_resp = generic_runner_main([
        "--mode", "live",
        "--testcase", str(NATIVE_COMPAT_ROOT / "testcases" / "unexpected_code_execution" / "UCE-001.yaml"),
        "--target", str(ROOT / "configs" / "targets" / "dvaa-securebot.yaml"),
        "--repository-root", str(NATIVE_COMPAT_ROOT),
        "--policy-dir", str(pdir),
        "--policy-id", pol.policy_id,
        "--output-dir", str(tmp_path / "out-resp-only"),
    ])
    assert rc_resp == 0
    resp_summary = json.loads(capsys.readouterr().out)
    assert resp_summary["cases"][0]["payload_ref"] == "UCE-P001"
    assert "SECAGENT_UCE_CANARY" in captured_inputs[-1].prompt

    # Explicit --env-file preserves ASI05 sandbox environment cleanly
    env_file = tmp_path / "sandbox_env.json"
    env_file.write_text(json.dumps({
        "sandbox_id": "sb-demo-1",
        "sandbox_reference": "local-isolated-sb",
        "canary_command_allowlist": ["echo SECAGENT_UCE_CANARY"],
    }), encoding="utf-8")
    tc = TestCaseLoader().load(NATIVE_COMPAT_ROOT / "testcases" / "unexpected_code_execution" / "UCE-001.yaml")
    target = TargetProfile.model_validate({
        "id": "sb-target",
        "name": "SB Target",
        "target_type": "llm_chat",
        "interface": {"type": "http", "adapter": "generic_http", "config": {"url": "http://127.0.0.1:7001/v1/chat/completions", "method": "POST", "body": {"messages": [{"role": "user", "content": "{{input}}"}]}}},
    })
    _, built_ti = build_live_case_and_input(
        tc,
        target,
        environment=json.loads(env_file.read_text()),
        repository_root=NATIVE_COMPAT_ROOT,
    )
    assert built_ti.environment["sandbox_id"] == "sb-demo-1"
    assert built_ti.payload_ref == "UCE-P001"

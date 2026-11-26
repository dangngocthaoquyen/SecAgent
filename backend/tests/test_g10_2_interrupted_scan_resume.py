"""G10.2 Acceptance & Regression Tests: Interrupted Generic Scan Resume.

Strictly offline: real network sockets are blocked; all Target and Judge calls use local mocks.
Covers all 15 acceptance requirements:
1. Interrupted 35-case ASI02 run (from 50-case dataset with 15 excluded ASI03 cases):
   6 completed (1 FAIL + 5 INCONCLUSIVE), 1 uncertain in-flight (running), 28 queued.
2. Read-only Resume Preview reports exact counts and executes 0 Target / 0 Judge requests.
3. Preserves completed cases (PASS, FAIL, INCONCLUSIVE, ERROR): never re-runs them, 0 Target/Judge calls for them.
4. Previously excluded dataset testcases (15 ASI03 cases) are NEVER selected on resume.
5. Uncertain in-flight case excluded by default; opt-in requires explicit confirmation; rejects non-uncertain IDs.
6. Missing Session Auth after restart blocks Resume (409 credential_unavailable, 0 target calls) and recovers after re-supply.
7. Missing or changed dataset blocks Resume (resume_dataset_not_found / resume_dataset_mismatch).
8. Changed Target configuration blocks Resume (resume_target_configuration_changed).
9. Duplicate / concurrent Resume requests for the same lineage are prevented (409 generic_resume_already_active).
10. Multi-hop resume: an interrupted continuation run itself is recovered and resumed cleanly.
11. Historical parent run record, native reports, verdicts, and evidence identities remain immutable on disk.
12. Completed runs cannot be resumed (409 generic_resume_not_interrupted).
13. Normal New Scan workflow remains intact.
14. Compatible with both DVAA (openai-chat) and generic HTTP JSON (http-json) targets.
15. Enforces stateful-target acknowledgement, stale resume_digest rejection, and submission_id idempotency.
"""

from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import socket
import threading
import time
from typing import Any
from uuid import uuid4

import pytest

from core.models import EvaluationStatus
from integrations.external_evaluator.base import ExternalEvaluatorProvider
from integrations.external_evaluator.models import (
    ExternalEvaluationOutcome,
    ExternalEvaluationResult,
)
from tools.http import HttpClient, HttpResponse
from workflow.api import create_app
from workflow.application_context import ApplicationContextStore
from workflow.dataset_normalizer import normalize_dataset
from workflow.dataset_repository import DatasetRepository
from workflow.management import ManagedTargetCatalog
from workflow.models import CatalogConfig
from workflow.response_policies import ResponsePolicyStore
from workflow.routes_generic_runner import GenericRunService

BASE = "http://127.0.0.1:8092"
OPERATOR_SECRET = "g10-2-resume-operator-secret-" + "r" * 32
SYNTHETIC_BEARER = "secagent-synth-resume-token-88224466"


@pytest.fixture(autouse=True)
def block_real_network(monkeypatch):
    monkeypatch.setattr(
        socket.socket,
        "connect",
        lambda *_: pytest.fail("Real network forbidden in offline G10.2 tests"),
    )


class _RecordingJudgeProvider(ExternalEvaluatorProvider):
    provider_name = "mock_judge"
    model_name = "mock-judge-v1"

    def __init__(self) -> None:
        self.calls: list[str] = []

    def evaluate(self, request: Any) -> ExternalEvaluationOutcome:
        tc_id = getattr(request, "testcase_id", None) or getattr(request, "case_id", None) or str(request.sha256)
        self.calls.append(str(tc_id))
        return ExternalEvaluationOutcome(
            request_sha256=request.sha256,
            skill=request.skill,
            result=ExternalEvaluationResult(
                classification="refusal_or_safe",
                verdict=EvaluationStatus.PASS,
                confidence=0.95,
                reason="Mock judge verified refusal.",
                evidence=[{"type": "response_span", "value": "I refuse unauthorized tool usage."}],
            ),
            duration_ms=5,
        )


def _import_dataset(dataset_repo: DatasetRepository, raw_bytes: bytes, filename: str):
    env = normalize_dataset(raw_bytes, filename)
    saved, _ = dataset_repo.save_dataset(env)
    return saved


def _make_dataset_bytes(asi02_count: int = 35, asi03_count: int = 15) -> bytes:
    """50-case generic dataset: TC0001..TC0010 (ASI03), TC0011..TC0045 (ASI02), TC0046..TC0050 (ASI03)."""
    tests: list[dict[str, Any]] = []
    # First 10 ASI03 (excluded when operator selects ASI02)
    for idx in range(1, 11):
        tests.append({
            "vars": {"prompt": f"ASI03 excluded prompt {idx}"},
            "metadata": {"testcase_id": f"TC{idx:04d}", "asi_category": "ASI03"},
            "description": f"ASI03 case {idx}",
        })
    # 35 ASI02 cases: TC0011..TC0045
    for idx in range(11, 11 + asi02_count):
        tests.append({
            "vars": {"prompt": f"ASI02 tool misuse prompt {idx} [TC{idx:04d}]"},
            "metadata": {"testcase_id": f"TC{idx:04d}", "asi_category": "ASI02"},
            "description": f"ASI02 case {idx}",
        })
    # Last 5 ASI03 cases: TC0046..TC0050
    for idx in range(11 + asi02_count, 11 + asi02_count + max(0, asi03_count - 10)):
        tests.append({
            "vars": {"prompt": f"ASI03 excluded prompt {idx}"},
            "metadata": {"testcase_id": f"TC{idx:04d}", "asi_category": "ASI03"},
            "description": f"ASI03 case {idx}",
        })
    payload = {
        "schema_version": "1.0",
        "source_tool": "promptfoo_config",
        "tests": tests,
    }
    return json.dumps(payload, indent=2).encode("utf-8")


def _dvaa_seed_target() -> dict[str, Any]:
    return {
        "id": "dvaa-chat-bot",
        "name": "DVAA Chat Bot",
        "platform_id": "dvaa",
        "platform_name": "DVAA",
        "endpoint": "http://127.0.0.1:7004/v1/chat/completions",
        "protocol": "openai-chat",
        "models": ["codebot"],
        "default_model": "codebot",
        "timeout_min": 1,
        "timeout_max": 60,
        "timeout_default": 30,
        "credential_alias": None,
    }


def _http_json_target_payload(session_ref: str) -> dict[str, Any]:
    return {
        "id": "local-http-agent-runs",
        "name": "Local HTTP Agent",
        "platform_id": "custom-http",
        "platform_name": "Custom HTTP",
        "endpoint": "http://127.0.0.1:8000/api/agent/runs",
        "protocol": "http-json",
        "model": None,
        "timeout_seconds": 300,
        "session_auth": {
            "ref_id": session_ref,
            "auth_type": "bearer",
            "header_name": "Authorization",
        },
        "http_config": {
            "method": "POST",
            "headers": {"Content-Type": "application/json"},
            "body_template": {"goal": "{{input}}"},
            "response": {
                "text_path": "answer",
                "status_path": "status",
                "complete_status_values": ["completed"],
            },
        },
        "capability_states": {"chat": "supported", "tool_calling": "supported"},
    }


def _build_env(
    tmp_path: Path,
    *,
    data_dir: Path | None = None,
    seed_targets: list[dict[str, Any]] | None = None,
    judge_provider: Any = None,
):
    seed = CatalogConfig.model_validate({
        "catalog_schema_version": "1.0.0",
        "policy_ref": "g10-2-policy-v1",
        "credential_aliases": {},
        "targets": seed_targets or [_dvaa_seed_target()],
    })
    managed_dir = data_dir or (tmp_path / "operator-data")
    catalog = ManagedTargetCatalog(seed, managed_dir, local_single_user=True)
    dataset_repo = DatasetRepository(managed_dir)
    app_ctx = ApplicationContextStore(catalog)
    policy_store = ResponsePolicyStore(managed_dir / "response_policies")
    gen_service = GenericRunService(
        catalog=catalog,
        dataset_repo=dataset_repo,
        inventory=None,
        policy_store=policy_store,
        runs_root=managed_dir / "generic-runs",
        controlled_runs_root=managed_dir / "runs",
        judge_provider=judge_provider,
        application_contexts=app_ctx,
    )
    app = create_app(
        catalog,
        operator_secret=OPERATOR_SECRET,
        local_single_user=True,
        dataset_repository=dataset_repo,
        generic_run_service=gen_service,
    )
    client = app.test_client()
    nonce = client.get("/api/testing/health", base_url=BASE).json["validation_nonce"]
    headers = {
        "Origin": BASE,
        "X-SecAgent-Validation": nonce,
        "X-SecAgent-Operator": OPERATOR_SECRET,
    }
    return catalog, dataset_repo, app_ctx, gen_service, client, headers


def _save_app_context(client, headers, target_id: str, target_rev: str) -> str:
    res = client.post(
        "/api/testing/application-contexts/save",
        base_url=BASE,
        headers=headers,
        json={
            "draft": {
                "target_id": target_id,
                "target_revision": target_rev,
                "purpose": "Local lab agent for security evaluation.",
                "features": "Order assistance and read-only lookups.",
                "available_tools": "lookup_order",
                "users": "Lab operator",
                "allowed_resources": "Public product catalog",
                "prohibited_resources": "Admin database and secrets",
                "sensitive_data_categories": "Credentials and PII",
                "protected_assets": "Order records",
                "high_risk_actions": "Unauthorized refund or privilege escalation",
                "required_instructions": "Refuse unauthorized tool invocations.",
                "authorization_required": "Admin approval for state changes",
                "trust_boundaries": "User prompt is untrusted input",
            },
            "expected_revision": None,
            "safe_description_confirmed": True,
        },
    )
    assert res.status_code in {200, 201}, res.get_json()
    return str(res.json["context"]["revision_sha256"])


def _create_interrupted_run_on_disk(
    runs_root: Path,
    *,
    run_id: str,
    target_id: str,
    target_name: str,
    target_revision_sha256: str | None,
    dataset_id: str,
    dataset_name: str,
    dataset_revision_sha256: str | None,
    selected_ids: list[str],
    completed_verdicts: dict[str, str],
    uncertain_ids: list[str],
    mode: str = "live",
    use_judge: bool = True,
    judge_provider_name: str | None = "mock_judge",
    judge_model_name: str | None = "mock-judge-v1",
    application_context_id: str | None = None,
    application_context_revision_sha256: str | None = None,
    raw_status: str = "running",
    continuation_of_run_id: str | None = None,
    root_run_id: str | None = None,
) -> Path:
    """Persist a realistic interrupted generic-run.json (and native case reports) simulating a hard crash."""
    run_dir = runs_root / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    cases: list[dict[str, Any]] = []
    case_statuses: list[dict[str, Any]] = []
    events: list[dict[str, Any]] = [{"at": "2026-11-25T09:00:00Z", "stage": "run_started", "case_id": None}]
    verdict_counts: dict[str, int] = {}

    for cid in selected_ids:
        if cid in completed_verdicts:
            verdict = completed_verdicts[cid]
            verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1
            case_run_id = uuid4().hex
            rep_path = run_dir / f"native-{cid}.secagent.json"
            rep_path.write_text(
                json.dumps({
                    "testcase_id": cid,
                    "generic_run_id": run_id,
                    "evaluation": {
                        "run_id": case_run_id,
                        "final_verdict": verdict,
                        "judge": {"semantic_invoked": use_judge},
                    },
                }),
                encoding="utf-8",
            )
            cases.append({
                "case_id": cid,
                "run_id": case_run_id,
                "category": "tool_misuse",
                "prompt": f"Original prompt for {cid}",
                "response_text": f"Original response for {cid}",
                "response_complete": True,
                "verdict": verdict,
                "reason": f"Recorded {verdict}",
                "judge_reason": "Judge evaluated" if use_judge else None,
                "judge_classification": "unsafe" if verdict == "FAIL" else "uncertain",
                "semantic_invoked": use_judge,
                "evidence_level": "response_only",
                "provenance_tiers": ["response"],
                "execution_status": "completed",
                "collector_diagnostics": [],
                "evidence": [],
                "report_path": str(rep_path),
            })
            case_statuses.append({
                "case_id": cid,
                "category": "tool_misuse",
                "asi_code": "ASI02",
                "status": "error" if verdict == "ERROR" else "completed",
                "stage": "completed",
                "verdict": verdict,
                "reason": f"Recorded {verdict}",
                "evidence_level": "response_only",
                "run_id": case_run_id,
            })
            events.append({"at": "2026-11-25T09:01:00Z", "stage": "case_started", "case_id": cid})
            events.append({"at": "2026-11-25T09:01:10Z", "stage": "case_completed", "case_id": cid, "verdict": verdict})
        elif cid in uncertain_ids:
            case_statuses.append({
                "case_id": cid,
                "category": "tool_misuse",
                "asi_code": "ASI02",
                "status": "running",
                "stage": "sending_request_to_target",
                "verdict": None,
                "reason": None,
                "evidence_level": None,
                "run_id": None,
            })
            events.append({"at": "2026-11-25T09:02:00Z", "stage": "case_started", "case_id": cid})
            events.append({"at": "2026-11-25T09:02:01Z", "stage": "sending_request_to_target", "case_id": cid})
        else:
            case_statuses.append({
                "case_id": cid,
                "category": "tool_misuse",
                "asi_code": "ASI02",
                "status": "queued",
                "stage": "queued",
                "verdict": None,
                "reason": None,
                "evidence_level": None,
                "run_id": None,
            })

    record: dict[str, Any] = {
        "workflow_schema_version": "1.0.0",
        "generic_run_id": run_id,
        "status": raw_status,
        "started_at": "2026-11-25T09:00:00Z",
        "completed_at": None,
        "mode": mode,
        "target_id": target_id,
        "target_name": target_name,
        "target_revision_sha256": target_revision_sha256,
        "dataset_id": dataset_id,
        "dataset_name": dataset_name,
        "dataset_revision_sha256": dataset_revision_sha256,
        "asi_category": "ASI02",
        "use_judge": use_judge,
        "policy_id": None,
        "policy_revision_sha256": None,
        "application_context_id": (
            application_context_id
            if application_context_id is not None
            else (f"appctx-{target_id}" if application_context_revision_sha256 else None)
        ),
        "application_context_revision_sha256": application_context_revision_sha256,
        "judge_metadata": (
            {
                "mode": "hybrid",
                "judge_configured": True,
                "credential_available": True,
                "judge_ready": True,
                "provider": judge_provider_name,
                "model": judge_model_name,
                "invocation_status": "running",
                "request_count": len(cases),
                "success_count": len(cases),
                "failure_count": 0,
                "error_categories": [],
            }
            if use_judge
            else {
                "mode": "rule_only",
                "judge_configured": False,
                "credential_available": False,
                "judge_ready": False,
                "provider": None,
                "model": None,
                "invocation_status": "not_requested",
                "request_count": 0,
                "success_count": 0,
                "failure_count": 0,
                "error_categories": [],
            }
        ),
        "capability_states": {"chat": "supported", "tool_calling": "supported"},
        "selected_cases": len(selected_ids),
        "ready_count": len(selected_ids),
        "executed_cases": len(cases),
        "total_cases": len(selected_ids),
        "skipped_count": 0,
        "skipped_cases": [],
        "progress_percent": int(round((len(cases) / max(1, len(selected_ids))) * 100)),
        "current_case_id": uncertain_ids[0] if uncertain_ids else None,
        "current_stage": "sending_request_to_target" if uncertain_ids else "interrupted",
        "target_request_budget": len(selected_ids) if mode == "live" else 0,
        "target_requests_used": len(cases),
        "judge_request_budget": len(selected_ids) if use_judge else 0,
        "judge_requests_used": len(cases) if use_judge else 0,
        "verdict_counts": verdict_counts,
        "case_statuses": case_statuses,
        "events": events,
        "cases": cases,
    }
    if continuation_of_run_id:
        record["continuation_of_run_id"] = continuation_of_run_id
    if root_run_id:
        record["root_run_id"] = root_run_id
    run_file = run_dir / "generic-run.json"
    run_file.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    return run_file


def _install_mock_http_target(monkeypatch, *, delay_seconds: float = 0.0):
    """Patch HttpClient.request so all live GenericRunService executions stay strictly offline and record prompts."""
    sent_prompts: list[str] = []
    sent_headers: list[dict[str, str]] = []
    lock = threading.Lock()

    def _fake_request(self, *, method: str, url: str, headers=None, json_body=None, timeout=None):
        if delay_seconds > 0:
            time.sleep(delay_seconds)
        prompt = ""
        if isinstance(json_body, dict):
            if "goal" in json_body:
                prompt = str(json_body["goal"])
            elif isinstance(json_body.get("messages"), list) and json_body["messages"]:
                prompt = str(json_body["messages"][-1].get("content", ""))
        with lock:
            sent_prompts.append(prompt)
            sent_headers.append(dict(headers or {}))
        if "/v1/chat/completions" in url:
            body_obj = {
                "choices": [{"message": {"content": "I refuse unauthorized tool usage."}, "finish_reason": "stop"}]
            }
        else:
            body_obj = {
                "run_id": f"run-{len(sent_prompts)}",
                "status": "completed",
                "answer": "I refuse unauthorized tool usage.",
            }
        body_text = json.dumps(body_obj)
        return HttpResponse(
            status_code=200,
            headers={"content-type": "application/json"},
            text=body_text,
            json_body=body_obj,
            duration_ms=2.0,
            body_complete=True,
        )

    monkeypatch.setattr(HttpClient, "request", _fake_request)
    return sent_prompts, sent_headers


def test_g10_2_interrupted_35_case_resume_preview_default_exclusion_and_immutability(tmp_path, monkeypatch):
    """Covers requirements 1, 2, 3, 4, 5, 6, 11, 12, 13, 15 end-to-end for an authenticated http-json target."""
    judge = _RecordingJudgeProvider()
    sent_prompts, sent_headers = _install_mock_http_target(monkeypatch)
    data_dir = tmp_path / "operator-data"
    catalog, dataset_repo, app_ctx, gen_service, client, headers = _build_env(
        tmp_path, data_dir=data_dir, judge_provider=judge
    )

    # 1. Import 50-case dataset (35 ASI02 + 15 ASI03)
    ds_env = _import_dataset(dataset_repo, _make_dataset_bytes(), "agent_asi02_50.json")

    # 2. Register Session Auth (draft scope before create) + create http-json target + Application Context
    cred_res = client.post(
        "/api/testing/managed-targets/session-credentials",
        base_url=BASE,
        headers=headers,
        json={
            "scope_kind": "draft",
            "scope_id": "local-http-agent-runs",
            "endpoint": "http://127.0.0.1:8000/api/agent/runs",
            "auth_type": "bearer",
            "secret_value": SYNTHETIC_BEARER,
        },
    )
    assert cred_res.status_code == 200, cred_res.get_json()
    session_ref = cred_res.json["credential"]["ref_id"]

    create_res = client.post(
        "/api/testing/managed-targets/create",
        base_url=BASE,
        headers=headers,
        json={"profile": _http_json_target_payload(session_ref), "expected_profile_revision": None},
    )
    assert create_res.status_code in {200, 201}, create_res.get_json()
    target_rev = create_res.json["profile"]["profile_revision"]
    ctx_rev = _save_app_context(client, headers, "local-http-agent-runs", target_rev)
    assert ctx_rev

    # 3. Persist crashed 35-case ASI02 run: 6 completed (1 FAIL, 5 INCONCLUSIVE), TC0017 running (uncertain), TC0018..TC0045 queued (28)
    parent_id = "1" * 32
    selected_35 = [f"TC{i:04d}" for i in range(11, 46)]
    completed_6 = {
        "TC0011": "FAIL",
        "TC0012": "INCONCLUSIVE",
        "TC0013": "INCONCLUSIVE",
        "TC0014": "INCONCLUSIVE",
        "TC0015": "INCONCLUSIVE",
        "TC0016": "INCONCLUSIVE",
    }
    parent_file = _create_interrupted_run_on_disk(
        gen_service.runs_root,
        run_id=parent_id,
        target_id="local-http-agent-runs",
        target_name="Local HTTP Agent",
        target_revision_sha256=target_rev,
        dataset_id=ds_env.dataset_id,
        dataset_name=ds_env.name,
        dataset_revision_sha256=ds_env.file_sha256,
        selected_ids=selected_35,
        completed_verdicts=completed_6,
        uncertain_ids=["TC0017"],
        mode="live",
        use_judge=True,
        application_context_revision_sha256=ctx_rev,
        raw_status="running",
    )

    # 4. Simulate Backend Restart (fresh catalog -> empty SessionCredentialStore -> recovers running -> interrupted!)
    judge2 = _RecordingJudgeProvider()
    _, _, _, gen_service2, client2, headers2 = _build_env(tmp_path, data_dir=data_dir, judge_provider=judge2)

    recovered = client2.get(f"/api/testing/generic-runs/{parent_id}", base_url=BASE, headers=headers2)
    assert recovered.status_code == 200
    rec_json = recovered.json
    assert rec_json["status"] == "interrupted"
    assert rec_json["selected_cases"] == 35
    assert rec_json["executed_cases"] == 6
    assert rec_json["lineage_summary"]["has_resumable_work"] is True
    assert rec_json["lineage_summary"]["remaining_pending_count"] == 28
    assert rec_json["lineage_summary"]["remaining_uncertain_count"] == 1

    # Snapshot parent file bytes AFTER initial recovery so we can verify complete immutability through resume!
    parent_bytes_before_resume = parent_file.read_bytes()
    parent_report_hashes_before = {
        p.name: sha256(p.read_bytes()).hexdigest()
        for p in (gen_service2.runs_root / parent_id).glob("native-*.secagent.json")
    }

    # 5. Resume Preview right after restart (Session Auth missing): read-only, 0 target / 0 judge calls, blocked!
    prev_no_auth = client2.post(
        f"/api/testing/generic-runs/{parent_id}/resume/preview",
        base_url=BASE,
        headers=headers2,
        json={},
    )
    assert prev_no_auth.status_code == 200
    p_na = prev_no_auth.json
    assert p_na["eligible"] is False
    assert p_na["blocker"] == "credential_unavailable"
    assert p_na["completed_count"] == 6
    assert p_na["completed_case_ids"] == list(completed_6.keys())
    assert p_na["pending_case_ids"] == [f"TC{i:04d}" for i in range(18, 46)]
    assert p_na["uncertain_case_ids"] == ["TC0017"]
    assert p_na["included_uncertain_case_ids"] == []
    assert len(p_na["selected_resume_case_ids"]) == 28
    # Verify NONE of the 15 excluded ASI03 cases appear anywhere in resume preview
    excluded_asi03 = {f"TC{i:04d}" for i in list(range(1, 11)) + list(range(46, 51))}
    assert excluded_asi03.isdisjoint(set(p_na["selected_resume_case_ids"]))
    assert excluded_asi03.isdisjoint(set(p_na["pending_case_ids"]))
    assert excluded_asi03.isdisjoint(set(p_na["uncertain_case_ids"]))
    assert len(sent_prompts) == 0
    assert len(judge2.calls) == 0

    # Attempt to start resume while Session Auth is missing -> 409 credential_unavailable, 0 target calls!
    blocked_start = client2.post(
        f"/api/testing/generic-runs/{parent_id}/resume/start",
        base_url=BASE,
        headers=headers2,
        json={
            "authorization_confirmed": True,
            "stateful_target_acknowledged": True,
            "expected_resume_digest": p_na["resume_digest"],
        },
    )
    assert blocked_start.status_code == 409
    assert blocked_start.json["error"]["code"] == "credential_unavailable"
    assert len(sent_prompts) == 0

    # 6. Operator re-supplies Session Auth on the SAME saved target (without recreating target/dataset/AppContext!)
    resupply = client2.post(
        "/api/testing/managed-targets/session-credentials",
        base_url=BASE,
        headers=headers2,
        json={
            "scope_kind": "target",
            "scope_id": "local-http-agent-runs",
            "endpoint": "http://127.0.0.1:8000/api/agent/runs",
            "auth_type": "bearer",
            "secret_value": SYNTHETIC_BEARER,
            "ref_id": session_ref,
        },
    )
    assert resupply.status_code == 200

    # 7. Resume Preview now succeeds (read-only, 0 target / 0 judge requests)
    prev_ready = client2.post(
        f"/api/testing/generic-runs/{parent_id}/resume/preview",
        base_url=BASE,
        headers=headers2,
        json={},
    )
    assert prev_ready.status_code == 200
    p_ok = prev_ready.json
    assert p_ok["eligible"] is True
    assert p_ok["blocker"] is None
    assert p_ok["target_request_budget"] == 28
    assert p_ok["judge_request_budget"] == 28
    assert p_ok["credential_availability"] == "available"
    assert len(sent_prompts) == 0
    assert len(judge2.calls) == 0

    # 8. Reject invalid uncertain opt-in (attempting to smuggle a completed or excluded case!)
    bad_inc = client2.post(
        f"/api/testing/generic-runs/{parent_id}/resume/preview",
        base_url=BASE,
        headers=headers2,
        json={"include_uncertain_case_ids": ["TC0011"]},
    )
    assert bad_inc.status_code == 400
    assert bad_inc.json["error"]["code"] == "generic_resume_invalid_uncertain_selection"

    # 9. Reject start without stateful_target_acknowledged
    no_ack = client2.post(
        f"/api/testing/generic-runs/{parent_id}/resume/start",
        base_url=BASE,
        headers=headers2,
        json={
            "authorization_confirmed": True,
            "expected_resume_digest": p_ok["resume_digest"],
        },
    )
    assert no_ack.status_code == 409
    assert no_ack.json["error"]["code"] == "generic_resume_stateful_acknowledgement_required"

    # 10. Reject start with stale resume_digest
    stale_dig = client2.post(
        f"/api/testing/generic-runs/{parent_id}/resume/start",
        base_url=BASE,
        headers=headers2,
        json={
            "authorization_confirmed": True,
            "stateful_target_acknowledged": True,
            "expected_resume_digest": "0" * 64,
        },
    )
    assert stale_dig.status_code == 409
    assert stale_dig.json["error"]["code"] == "generic_resume_digest_stale"

    # 11. Start Resumed Scan (default: 28 definitely pending cases, TC0017 excluded!) with submission_id
    sub_id = "a" * 32
    resumed = client2.post(
        f"/api/testing/generic-runs/{parent_id}/resume/start",
        base_url=BASE,
        headers=headers2,
        json={
            "authorization_confirmed": True,
            "stateful_target_acknowledged": True,
            "expected_resume_digest": p_ok["resume_digest"],
            "expected_target_revision": p_ok["target_revision_sha256"],
            "expected_session_credential_generation": p_ok["session_credential_generation"],
            "submission_id": sub_id,
            "async_execution": False,
        },
    )
    assert resumed.status_code == 201, resumed.get_json()
    child = resumed.json
    child_id = child["generic_run_id"]
    assert child_id != parent_id
    assert child["status"] == "completed"
    assert child["continuation_of_run_id"] == parent_id
    assert child["root_run_id"] == parent_id
    assert child["executed_cases"] == 28
    assert [c["case_id"] for c in child["cases"]] == [f"TC{i:04d}" for i in range(18, 46)]

    # Verify exact Target and Judge call counts: ONLY the 28 pending cases, NEVER the 6 completed or TC0017 or ASI03!
    assert len(sent_prompts) == 28
    assert len(judge2.calls) == 28
    assert all(f"[{cid}]" not in p for p in sent_prompts for cid in list(completed_6.keys()) + ["TC0017"])
    assert all(h.get("Authorization") == f"Bearer {SYNTHETIC_BEARER}" for h in sent_headers)
    assert all(SYNTHETIC_BEARER not in json.dumps(child) for _ in [0])

    # Verify idempotent retry with SAME submission_id returns SAME continuation run without re-executing!
    idempotent = client2.post(
        f"/api/testing/generic-runs/{parent_id}/resume/start",
        base_url=BASE,
        headers=headers2,
        json={
            "authorization_confirmed": True,
            "stateful_target_acknowledged": True,
            "expected_resume_digest": p_ok["resume_digest"],
            "submission_id": sub_id,
            "async_execution": False,
        },
    )
    assert idempotent.status_code == 201
    assert idempotent.json["generic_run_id"] == child_id
    assert len(sent_prompts) == 28  # Zero extra requests!

    # Verify parent run file and parent native reports on disk are 100% IMMUTABLE (byte-for-byte unchanged!)
    assert parent_file.read_bytes() == parent_bytes_before_resume
    parent_report_hashes_after = {
        p.name: sha256(p.read_bytes()).hexdigest()
        for p in (gen_service2.runs_root / parent_id).glob("native-*.secagent.json")
    }
    assert parent_report_hashes_after == parent_report_hashes_before

    # Verify deduplicated lineage summary on BOTH parent and child (6 + 28 = 34 unique completed, no double-count!)
    parent_view = client2.get(f"/api/testing/generic-runs/{parent_id}", base_url=BASE, headers=headers2).json
    assert child_id in parent_view["child_run_ids"]
    assert parent_view["lineage_summary"]["lineage_completed_count"] == 34
    assert parent_view["lineage_summary"]["remaining_pending_count"] == 0
    assert parent_view["lineage_summary"]["remaining_uncertain_count"] == 1
    assert child["lineage_summary"]["lineage_completed_count"] == 34

    # Verify completed continuation run CANNOT be resumed (409 generic_resume_not_interrupted)
    completed_resume = client2.post(
        f"/api/testing/generic-runs/{child_id}/resume/start",
        base_url=BASE,
        headers=headers2,
        json={
            "authorization_confirmed": True,
            "stateful_target_acknowledged": True,
            "expected_resume_digest": "f" * 64,
        },
    )
    assert completed_resume.status_code == 409
    assert completed_resume.json["error"]["code"] == "generic_resume_not_interrupted"

    # Verify normal New Scan still works intact!
    new_scan_prev = client2.post(
        "/api/testing/generic-runs/preview",
        base_url=BASE,
        headers=headers2,
        json={
            "mode": "live",
            "target_id": "local-http-agent-runs",
            "dataset_id": ds_env.dataset_id,
            "testcase_ids": ["TC0011"],
            "use_judge": False,
        },
    )
    assert new_scan_prev.status_code == 200
    assert new_scan_prev.json["blocker"] is None


def test_g10_2_uncertain_opt_in_requires_confirmation_and_preserves_pass_error_verdicts(tmp_path, monkeypatch):
    """Covers requirements 3 (PASS/ERROR preserved) and 5 (uncertain opt-in requires explicit confirmation)."""
    sent_prompts, _ = _install_mock_http_target(monkeypatch)
    catalog, dataset_repo, _, gen_service, client, headers = _build_env(tmp_path)
    ds_env = _import_dataset(dataset_repo, _make_dataset_bytes(asi02_count=6, asi03_count=10), "dvaa_6.json")
    dvaa_rev = gen_service._current_target_revision("dvaa-chat-bot")
    assert dvaa_rev is not None

    parent_id = "2" * 32
    selected_6 = [f"TC{i:04d}" for i in range(11, 17)]
    completed_4 = {"TC0011": "PASS", "TC0012": "FAIL", "TC0013": "INCONCLUSIVE", "TC0014": "ERROR"}
    _create_interrupted_run_on_disk(
        gen_service.runs_root,
        run_id=parent_id,
        target_id="dvaa-chat-bot",
        target_name="DVAA Chat Bot",
        target_revision_sha256=dvaa_rev,
        dataset_id=ds_env.dataset_id,
        dataset_name=ds_env.name,
        dataset_revision_sha256=ds_env.file_sha256,
        selected_ids=selected_6,
        completed_verdicts=completed_4,
        uncertain_ids=["TC0015"],
        mode="live",
        use_judge=False,
    )

    # Preview with uncertain TC0015 opted in -> selects TC0016 (pending) + TC0015 (uncertain) = 2 cases
    prev = client.post(
        f"/api/testing/generic-runs/{parent_id}/resume/preview",
        base_url=BASE,
        headers=headers,
        json={"include_uncertain_case_ids": ["TC0015"]},
    )
    assert prev.status_code == 200
    pj = prev.json
    assert pj["eligible"] is True
    assert pj["completed_case_ids"] == ["TC0011", "TC0012", "TC0013", "TC0014"]
    assert pj["selected_resume_case_ids"] == ["TC0015", "TC0016"]
    assert pj["target_request_budget"] == 2

    # Start WITHOUT uncertain_reexecution_confirmed -> 409 blocked!
    unconfirmed = client.post(
        f"/api/testing/generic-runs/{parent_id}/resume/start",
        base_url=BASE,
        headers=headers,
        json={
            "authorization_confirmed": True,
            "stateful_target_acknowledged": True,
            "expected_resume_digest": pj["resume_digest"],
            "include_uncertain_case_ids": ["TC0015"],
            "uncertain_reexecution_confirmed": False,
        },
    )
    assert unconfirmed.status_code == 409
    assert unconfirmed.json["error"]["code"] == "generic_resume_uncertain_confirmation_required"
    assert len(sent_prompts) == 0

    # Start WITH uncertain_reexecution_confirmed=True -> executes TC0016 + TC0015 on DVAA openai-chat target!
    confirmed = client.post(
        f"/api/testing/generic-runs/{parent_id}/resume/start",
        base_url=BASE,
        headers=headers,
        json={
            "authorization_confirmed": True,
            "stateful_target_acknowledged": True,
            "expected_resume_digest": pj["resume_digest"],
            "include_uncertain_case_ids": ["TC0015"],
            "uncertain_reexecution_confirmed": True,
            "async_execution": False,
        },
    )
    assert confirmed.status_code == 201, confirmed.get_json()
    cj = confirmed.json
    assert [c["case_id"] for c in cj["cases"]] == ["TC0015", "TC0016"]
    assert cj["resume_metadata"]["included_uncertain_case_ids"] == ["TC0015"]
    assert len(sent_prompts) == 2
    assert cj["lineage_summary"]["lineage_completed_count"] == 6


def test_g10_2_blocks_changed_dataset_and_changed_target_config(tmp_path, monkeypatch):
    """Covers requirements 7 & 8: missing/changed dataset and modified target config block Resume."""
    sent_prompts, _ = _install_mock_http_target(monkeypatch)
    catalog, dataset_repo, _, gen_service, client, headers = _build_env(tmp_path)
    ds_env = _import_dataset(dataset_repo, _make_dataset_bytes(asi02_count=4, asi03_count=10), "ds_check.json")
    dvaa_rev = gen_service._current_target_revision("dvaa-chat-bot")
    assert dvaa_rev is not None

    # Case A: dataset revision mismatch
    run_ds = "3" * 32
    _create_interrupted_run_on_disk(
        gen_service.runs_root,
        run_id=run_ds,
        target_id="dvaa-chat-bot",
        target_name="DVAA Chat Bot",
        target_revision_sha256=dvaa_rev,
        dataset_id=ds_env.dataset_id,
        dataset_name=ds_env.name,
        dataset_revision_sha256="9" * 64,  # Different dataset revision!
        selected_ids=["TC0011", "TC0012", "TC0013"],
        completed_verdicts={"TC0011": "PASS"},
        uncertain_ids=[],
        mode="live",
        use_judge=False,
    )
    prev_ds = client.post(f"/api/testing/generic-runs/{run_ds}/resume/preview", base_url=BASE, headers=headers, json={})
    assert prev_ds.status_code == 200
    assert prev_ds.json["eligible"] is False
    assert prev_ds.json["blocker"] == "resume_dataset_mismatch"

    start_ds = client.post(
        f"/api/testing/generic-runs/{run_ds}/resume/start",
        base_url=BASE,
        headers=headers,
        json={
            "authorization_confirmed": True,
            "stateful_target_acknowledged": True,
            "expected_resume_digest": prev_ds.json["resume_digest"],
        },
    )
    assert start_ds.status_code == 409
    assert start_ds.json["error"]["code"] == "resume_dataset_mismatch"

    # Case B: missing dataset
    run_missing_ds = "4" * 32
    _create_interrupted_run_on_disk(
        gen_service.runs_root,
        run_id=run_missing_ds,
        target_id="dvaa-chat-bot",
        target_name="DVAA Chat Bot",
        target_revision_sha256=dvaa_rev,
        dataset_id="0" * 32,
        dataset_name="deleted.json",
        dataset_revision_sha256=ds_env.file_sha256,
        selected_ids=["TC0011", "TC0012"],
        completed_verdicts={"TC0011": "PASS"},
        uncertain_ids=[],
        mode="live",
        use_judge=False,
    )
    prev_miss = client.post(
        f"/api/testing/generic-runs/{run_missing_ds}/resume/preview", base_url=BASE, headers=headers, json={}
    )
    assert prev_miss.status_code == 200
    assert prev_miss.json["blocker"] == "resume_dataset_not_found"

    # Case C: changed Target configuration (update timeout_seconds -> changes target_revision_sha256)
    run_tgt = "5" * 32
    _create_interrupted_run_on_disk(
        gen_service.runs_root,
        run_id=run_tgt,
        target_id="dvaa-chat-bot",
        target_name="DVAA Chat Bot",
        target_revision_sha256=dvaa_rev,
        dataset_id=ds_env.dataset_id,
        dataset_name=ds_env.name,
        dataset_revision_sha256=ds_env.file_sha256,
        selected_ids=["TC0011", "TC0012", "TC0013"],
        completed_verdicts={"TC0011": "PASS"},
        uncertain_ids=[],
        mode="live",
        use_judge=False,
    )
    upd = client.post(
        "/api/testing/managed-targets/update",
        base_url=BASE,
        headers=headers,
        json={
            "expected_profile_revision": dvaa_rev,
            "profile": {
                "id": "dvaa-chat-bot",
                "name": "DVAA Chat Bot",
                "platform_id": "dvaa",
                "platform_name": "DVAA",
                "endpoint": "http://127.0.0.1:7004/v1/chat/completions",
                "protocol": "openai-chat",
                "model": "codebot",
                "timeout_seconds": 55,
            },
        },
    )
    assert upd.status_code == 200
    prev_tgt = client.post(
        f"/api/testing/generic-runs/{run_tgt}/resume/preview", base_url=BASE, headers=headers, json={}
    )
    assert prev_tgt.status_code == 200
    assert prev_tgt.json["eligible"] is False
    assert prev_tgt.json["blocker"] == "resume_target_configuration_changed"
    assert len(sent_prompts) == 0


def test_g10_2_concurrent_duplicate_resume_prevented(tmp_path, monkeypatch):
    """Covers requirement 9: concurrent / duplicate Resume requests cannot execute overlapping testcases."""
    sent_prompts, _ = _install_mock_http_target(monkeypatch, delay_seconds=0.05)
    catalog, dataset_repo, _, gen_service, client, headers = _build_env(tmp_path)
    ds_env = _import_dataset(dataset_repo, _make_dataset_bytes(asi02_count=5, asi03_count=10), "conc.json")
    dvaa_rev = gen_service._current_target_revision("dvaa-chat-bot")
    assert dvaa_rev is not None

    parent_id = "6" * 32
    _create_interrupted_run_on_disk(
        gen_service.runs_root,
        run_id=parent_id,
        target_id="dvaa-chat-bot",
        target_name="DVAA Chat Bot",
        target_revision_sha256=dvaa_rev,
        dataset_id=ds_env.dataset_id,
        dataset_name=ds_env.name,
        dataset_revision_sha256=ds_env.file_sha256,
        selected_ids=["TC0011", "TC0012", "TC0013", "TC0014", "TC0015"],
        completed_verdicts={"TC0011": "PASS"},
        uncertain_ids=[],
        mode="live",
        use_judge=False,
    )
    prev = client.post(f"/api/testing/generic-runs/{parent_id}/resume/preview", base_url=BASE, headers=headers, json={})
    digest = prev.json["resume_digest"]

    # Start async continuation 1
    first = client.post(
        f"/api/testing/generic-runs/{parent_id}/resume/start",
        base_url=BASE,
        headers=headers,
        json={
            "authorization_confirmed": True,
            "stateful_target_acknowledged": True,
            "expected_resume_digest": digest,
            "async_execution": True,
        },
    )
    assert first.status_code == 202
    child_id = first.json["generic_run_id"]

    # Immediately fire second concurrent Resume request -> MUST be blocked with 409 generic_resume_already_active!
    second = client.post(
        f"/api/testing/generic-runs/{parent_id}/resume/start",
        base_url=BASE,
        headers=headers,
        json={
            "authorization_confirmed": True,
            "stateful_target_acknowledged": True,
            "expected_resume_digest": digest,
            "async_execution": True,
        },
    )
    assert second.status_code == 409
    assert second.json["error"]["code"] == "generic_resume_already_active"

    # Wait for first worker to finish and verify exact 4 pending cases executed ONCE (never 8!)
    worker = gen_service._in_progress_runs.get(child_id)
    if worker is not None:
        worker.join(timeout=15)
    final_child = client.get(f"/api/testing/generic-runs/{child_id}", base_url=BASE, headers=headers).json
    assert final_child["status"] == "completed"
    assert len(sent_prompts) == 4


def test_g10_2_multihop_interrupted_continuation_run_recovery_and_resume(tmp_path, monkeypatch):
    """Covers requirement 10: an interrupted continuation run itself recovers and resumes cleanly (Run A -> Run B -> Run C)."""
    sent_prompts, _ = _install_mock_http_target(monkeypatch)
    data_dir = tmp_path / "operator-data"
    catalog, dataset_repo, _, gen_service, client, headers = _build_env(tmp_path, data_dir=data_dir)
    ds_env = _import_dataset(dataset_repo, _make_dataset_bytes(asi02_count=8, asi03_count=10), "multihop.json")
    dvaa_rev = gen_service._current_target_revision("dvaa-chat-bot")
    assert dvaa_rev is not None

    run_a = "7" * 32
    run_b = "8" * 32
    # Run A (root): selected TC0011..TC0018 (8 cases), completed TC0011..TC0012, TC0013 uncertain, TC0014..TC0018 queued
    _create_interrupted_run_on_disk(
        gen_service.runs_root,
        run_id=run_a,
        target_id="dvaa-chat-bot",
        target_name="DVAA Chat Bot",
        target_revision_sha256=dvaa_rev,
        dataset_id=ds_env.dataset_id,
        dataset_name=ds_env.name,
        dataset_revision_sha256=ds_env.file_sha256,
        selected_ids=[f"TC{i:04d}" for i in range(11, 19)],
        completed_verdicts={"TC0011": "PASS", "TC0012": "FAIL"},
        uncertain_ids=["TC0013"],
        mode="live",
        use_judge=False,
        raw_status="interrupted",
    )
    # Run B (continuation of Run A, itself crashed while running TC0016!):
    # selected TC0014..TC0018 (5 cases), completed TC0014..TC0015, TC0016 running, TC0017..TC0018 queued
    _create_interrupted_run_on_disk(
        gen_service.runs_root,
        run_id=run_b,
        target_id="dvaa-chat-bot",
        target_name="DVAA Chat Bot",
        target_revision_sha256=dvaa_rev,
        dataset_id=ds_env.dataset_id,
        dataset_name=ds_env.name,
        dataset_revision_sha256=ds_env.file_sha256,
        selected_ids=[f"TC{i:04d}" for i in range(14, 19)],
        completed_verdicts={"TC0014": "PASS", "TC0015": "INCONCLUSIVE"},
        uncertain_ids=["TC0016"],
        mode="live",
        use_judge=False,
        raw_status="running",
        continuation_of_run_id=run_a,
        root_run_id=run_a,
    )

    # Simulate restart -> Run B recovers as interrupted
    _, _, _, _, client2, headers2 = _build_env(tmp_path, data_dir=data_dir)
    rec_b = client2.get(f"/api/testing/generic-runs/{run_b}", base_url=BASE, headers=headers2).json
    assert rec_b["status"] == "interrupted"
    assert rec_b["continuation_of_run_id"] == run_a
    assert rec_b["root_run_id"] == run_a

    # Resume Preview on Run B preserves ALL 4 completed cases across Run A + Run B,
    # offers TC0017..TC0018 pending AND keeps BOTH TC0013 (from Run A) and TC0016 (from Run B) identifiable as uncertain!
    prev_b = client2.post(
        f"/api/testing/generic-runs/{run_b}/resume/preview", base_url=BASE, headers=headers2, json={}
    )
    assert prev_b.status_code == 200
    pb = prev_b.json
    assert pb["eligible"] is True
    assert pb["root_run_id"] == run_a
    assert pb["completed_case_ids"] == ["TC0011", "TC0012", "TC0014", "TC0015"]
    assert pb["pending_case_ids"] == ["TC0017", "TC0018"]
    assert pb["uncertain_case_ids"] == ["TC0013", "TC0016"]
    assert pb["selected_resume_case_ids"] == ["TC0017", "TC0018"]

    # Resume Run B -> creates Run C with root_run_id=run_a, continuation_of_run_id=run_b
    res_c = client2.post(
        f"/api/testing/generic-runs/{run_b}/resume/start",
        base_url=BASE,
        headers=headers2,
        json={
            "authorization_confirmed": True,
            "stateful_target_acknowledged": True,
            "expected_resume_digest": pb["resume_digest"],
            "async_execution": False,
        },
    )
    assert res_c.status_code == 201, res_c.get_json()
    run_c = res_c.json
    assert run_c["continuation_of_run_id"] == run_b
    assert run_c["root_run_id"] == run_a
    assert [c["case_id"] for c in run_c["cases"]] == ["TC0017", "TC0018"]
    assert run_c["lineage_summary"]["lineage_completed_count"] == 6  # 2 (A) + 2 (B) + 2 (C) = 6 unique!
    assert run_c["lineage_summary"]["remaining_pending_count"] == 0
    assert run_c["lineage_summary"]["remaining_uncertain_count"] == 2  # TC0013 + TC0016
    assert len(sent_prompts) == 2


def test_r01_lineage_wide_uncertain_classification_reopen_run_a(tmp_path, monkeypatch):
    """R01 regression: Run A -> Run B interrupted on TC0018 -> reopen Run A.
    Verifies TC0018 is uncertain (never pending), 0 automatic requests for TC0018/TC0017,
    explicit authorized retry works, completed results remain untouched, and lineage counts stay consistent.
    """
    sent_prompts, _ = _install_mock_http_target(monkeypatch)
    data_dir = tmp_path / "operator-data"
    catalog, dataset_repo, _, gen_service, client, headers = _build_env(tmp_path, data_dir=data_dir)
    ds_env = _import_dataset(dataset_repo, _make_dataset_bytes(asi02_count=12, asi03_count=10), "r01_lineage.json")
    dvaa_rev = gen_service._current_target_revision("dvaa-chat-bot")
    assert dvaa_rev is not None

    run_a = "a" * 32
    run_b = "b" * 32
    selected_12 = [f"TC{i:04d}" for i in range(11, 23)]  # TC0011..TC0022
    completed_a = {
        "TC0011": "FAIL",
        "TC0012": "INCONCLUSIVE",
        "TC0013": "PASS",
        "TC0014": "INCONCLUSIVE",
        "TC0015": "ERROR",
        "TC0016": "INCONCLUSIVE",
    }
    # Run A: TC0011..TC0016 completed, TC0017 running (uncertain), TC0018..TC0022 queued
    run_a_file = _create_interrupted_run_on_disk(
        gen_service.runs_root,
        run_id=run_a,
        target_id="dvaa-chat-bot",
        target_name="DVAA Chat Bot",
        target_revision_sha256=dvaa_rev,
        dataset_id=ds_env.dataset_id,
        dataset_name=ds_env.name,
        dataset_revision_sha256=ds_env.file_sha256,
        selected_ids=selected_12,
        completed_verdicts=completed_a,
        uncertain_ids=["TC0017"],
        mode="live",
        use_judge=False,
        raw_status="interrupted",
    )
    run_a_bytes_before = run_a_file.read_bytes()

    # Run B (continuation of Run A): dispatched TC0018 and crashed before completion; TC0019..TC0022 still queued
    _create_interrupted_run_on_disk(
        gen_service.runs_root,
        run_id=run_b,
        target_id="dvaa-chat-bot",
        target_name="DVAA Chat Bot",
        target_revision_sha256=dvaa_rev,
        dataset_id=ds_env.dataset_id,
        dataset_name=ds_env.name,
        dataset_revision_sha256=ds_env.file_sha256,
        selected_ids=["TC0018", "TC0019", "TC0020", "TC0021", "TC0022"],
        completed_verdicts={},
        uncertain_ids=["TC0018"],
        mode="live",
        use_judge=False,
        raw_status="running",
        continuation_of_run_id=run_a,
        root_run_id=run_a,
    )

    # Simulate restart -> reopen Run A!
    _, _, _, _, client2, headers2 = _build_env(tmp_path, data_dir=data_dir)
    prev_a = client2.post(f"/api/testing/generic-runs/{run_a}/resume/preview", base_url=BASE, headers=headers2, json={})
    assert prev_a.status_code == 200
    pa = prev_a.json
    assert pa["eligible"] is True
    assert pa["completed_case_ids"] == ["TC0011", "TC0012", "TC0013", "TC0014", "TC0015", "TC0016"]
    # R01 CRITICAL: TC0018 was queued in Run A, but dispatched & interrupted in Run B -> MUST be uncertain, NOT pending!
    assert pa["uncertain_case_ids"] == ["TC0017", "TC0018"]
    assert pa["pending_case_ids"] == ["TC0019", "TC0020", "TC0021", "TC0022"]
    assert pa["selected_resume_case_ids"] == ["TC0019", "TC0020", "TC0021", "TC0022"]
    assert pa["target_request_budget"] == 4
    assert len(sent_prompts) == 0

    # Default Resume from Run A executes ONLY TC0019..TC0022 (0 automatic requests for TC0018 or TC0017!)
    res_c = client2.post(
        f"/api/testing/generic-runs/{run_a}/resume/start",
        base_url=BASE,
        headers=headers2,
        json={
            "authorization_confirmed": True,
            "stateful_target_acknowledged": True,
            "expected_resume_digest": pa["resume_digest"],
            "async_execution": False,
        },
    )
    assert res_c.status_code == 201, res_c.get_json()
    run_c = res_c.json
    assert [c["case_id"] for c in run_c["cases"]] == ["TC0019", "TC0020", "TC0021", "TC0022"]
    assert len(sent_prompts) == 4
    assert all("[TC0018]" not in p and "[TC0017]" not in p for p in sent_prompts)
    assert run_a_file.read_bytes() == run_a_bytes_before  # Parent Run A remains 100% immutable!

    # Now reopen Run A again: 0 pending, TC0017 & TC0018 remain uncertain -> default preview blocks with no_cases_selected
    prev_after_c = client2.post(
        f"/api/testing/generic-runs/{run_a}/resume/preview", base_url=BASE, headers=headers2, json={}
    ).json
    assert prev_after_c["pending_case_ids"] == []
    assert prev_after_c["uncertain_case_ids"] == ["TC0017", "TC0018"]
    assert prev_after_c["blocker"] == "generic_resume_no_cases_selected"
    assert prev_after_c["eligible"] is False

    # Explicit authorized opt-in retry of TC0018 succeeds!
    prev_opt_in = client2.post(
        f"/api/testing/generic-runs/{run_a}/resume/preview",
        base_url=BASE,
        headers=headers2,
        json={"include_uncertain_case_ids": ["TC0018"]},
    ).json
    assert prev_opt_in["eligible"] is True
    assert prev_opt_in["selected_resume_case_ids"] == ["TC0018"]
    res_d = client2.post(
        f"/api/testing/generic-runs/{run_a}/resume/start",
        base_url=BASE,
        headers=headers2,
        json={
            "authorization_confirmed": True,
            "stateful_target_acknowledged": True,
            "include_uncertain_case_ids": ["TC0018"],
            "uncertain_reexecution_confirmed": True,
            "expected_resume_digest": prev_opt_in["resume_digest"],
            "async_execution": False,
        },
    )
    assert res_d.status_code == 201, res_d.get_json()
    run_d = res_d.json
    assert [c["case_id"] for c in run_d["cases"]] == ["TC0018"]
    assert len(sent_prompts) == 5  # 4 from Run C + 1 explicit retry of TC0018

    # Lineage progress & remaining counts remain consistent across ALL members (Run A, Run B, Run C, Run D)!
    for rid in (run_a, run_b, run_c["generic_run_id"], run_d["generic_run_id"]):
        view = client2.get(f"/api/testing/generic-runs/{rid}", base_url=BASE, headers=headers2).json
        ls = view["lineage_summary"]
        assert ls["original_selected_cases"] == 12
        assert ls["lineage_completed_count"] == 11  # 6 (A) + 4 (C) + 1 (D)
        assert ls["remaining_pending_count"] == 0
        assert ls["remaining_uncertain_count"] == 1  # Only TC0017 remains


def test_r02_resume_judge_and_historical_configuration_consistency(tmp_path, monkeypatch):
    """R02 regression: changed Judge provider/model, missing historical identifiers, absent->configured drift, and unchanged config."""
    sent_prompts, _ = _install_mock_http_target(monkeypatch)
    data_dir = tmp_path / "operator-data"
    judge_v1 = _RecordingJudgeProvider()
    catalog, dataset_repo, _, gen_service, client, headers = _build_env(
        tmp_path, data_dir=data_dir, judge_provider=judge_v1
    )
    ds_env = _import_dataset(dataset_repo, _make_dataset_bytes(asi02_count=4, asi03_count=10), "r02_cfg.json")
    dvaa_rev = gen_service._current_target_revision("dvaa-chat-bot")
    assert dvaa_rev is not None
    ctx_rev = _save_app_context(client, headers, "dvaa-chat-bot", dvaa_rev)

    # 1. Unchanged configuration (matching Judge provider/model, dataset rev, target rev, AppContext rev) -> eligible!
    run_ok = "c" * 32
    _create_interrupted_run_on_disk(
        gen_service.runs_root,
        run_id=run_ok,
        target_id="dvaa-chat-bot",
        target_name="DVAA Chat Bot",
        target_revision_sha256=dvaa_rev,
        dataset_id=ds_env.dataset_id,
        dataset_name=ds_env.name,
        dataset_revision_sha256=ds_env.file_sha256,
        selected_ids=["TC0011", "TC0012", "TC0013"],
        completed_verdicts={"TC0011": "PASS"},
        uncertain_ids=[],
        mode="live",
        use_judge=True,
        judge_provider_name="mock_judge",
        judge_model_name="mock-judge-v1",
        application_context_revision_sha256=ctx_rev,
    )
    prev_ok = client.post(f"/api/testing/generic-runs/{run_ok}/resume/preview", base_url=BASE, headers=headers, json={})
    assert prev_ok.status_code == 200
    assert prev_ok.json["eligible"] is True
    assert prev_ok.json["config_consistent"] is True
    assert prev_ok.json["original_judge_provider"] == "mock_judge"
    assert prev_ok.json["original_judge_model"] == "mock-judge-v1"
    digest_v1 = prev_ok.json["resume_digest"]

    # 2. Changed Judge MODEL -> blocked at preview AND revalidated/blocked at start with old digest!
    judge_v1.model_name = "mock-judge-v2"
    prev_mod = client.post(
        f"/api/testing/generic-runs/{run_ok}/resume/preview", base_url=BASE, headers=headers, json={}
    )
    assert prev_mod.status_code == 200
    assert prev_mod.json["eligible"] is False
    assert prev_mod.json["config_consistent"] is False
    assert prev_mod.json["blocker"] == "resume_judge_configuration_changed"
    start_mod = client.post(
        f"/api/testing/generic-runs/{run_ok}/resume/start",
        base_url=BASE,
        headers=headers,
        json={
            "authorization_confirmed": True,
            "stateful_target_acknowledged": True,
            "expected_resume_digest": digest_v1,
        },
    )
    assert start_mod.status_code == 409
    assert start_mod.json["error"]["code"] == "resume_judge_configuration_changed"
    assert len(sent_prompts) == 0

    # 3. Changed Judge PROVIDER -> blocked!
    judge_v1.model_name = "mock-judge-v1"
    judge_v1.provider_name = "other_provider"
    prev_prov = client.post(
        f"/api/testing/generic-runs/{run_ok}/resume/preview", base_url=BASE, headers=headers, json={}
    )
    assert prev_prov.json["eligible"] is False
    assert prev_prov.json["blocker"] == "resume_judge_configuration_changed"
    judge_v1.provider_name = "mock_judge"  # restore

    # 4. Missing historical Judge metadata on a hybrid run -> blocked (never claims config_consistent=True!)
    run_no_jm = "d" * 32
    _create_interrupted_run_on_disk(
        gen_service.runs_root,
        run_id=run_no_jm,
        target_id="dvaa-chat-bot",
        target_name="DVAA Chat Bot",
        target_revision_sha256=dvaa_rev,
        dataset_id=ds_env.dataset_id,
        dataset_name=ds_env.name,
        dataset_revision_sha256=ds_env.file_sha256,
        selected_ids=["TC0011", "TC0012"],
        completed_verdicts={"TC0011": "PASS"},
        uncertain_ids=[],
        mode="live",
        use_judge=True,
        judge_provider_name=None,
        judge_model_name=None,
        application_context_revision_sha256=ctx_rev,
    )
    prev_no_jm = client.post(
        f"/api/testing/generic-runs/{run_no_jm}/resume/preview", base_url=BASE, headers=headers, json={}
    ).json
    assert prev_no_jm["eligible"] is False
    assert prev_no_jm["config_consistent"] is False
    assert prev_no_jm["blocker"] == "resume_judge_configuration_missing"

    # 5. Missing dataset_revision_sha256 -> blocked (never claims dataset_consistent=True!)
    run_no_ds_rev = "e" * 32
    _create_interrupted_run_on_disk(
        gen_service.runs_root,
        run_id=run_no_ds_rev,
        target_id="dvaa-chat-bot",
        target_name="DVAA Chat Bot",
        target_revision_sha256=dvaa_rev,
        dataset_id=ds_env.dataset_id,
        dataset_name=ds_env.name,
        dataset_revision_sha256=None,
        selected_ids=["TC0011", "TC0012"],
        completed_verdicts={"TC0011": "PASS"},
        uncertain_ids=[],
        mode="live",
        use_judge=False,
        application_context_revision_sha256=ctx_rev,
    )
    prev_no_ds = client.post(
        f"/api/testing/generic-runs/{run_no_ds_rev}/resume/preview", base_url=BASE, headers=headers, json={}
    ).json
    assert prev_no_ds["dataset_consistent"] is False
    assert prev_no_ds["config_consistent"] is False
    assert prev_no_ds["blocker"] == "resume_dataset_revision_missing"

    # 6. Missing target_revision_sha256 on live run -> blocked!
    run_no_tgt_rev = "f" * 32
    _create_interrupted_run_on_disk(
        gen_service.runs_root,
        run_id=run_no_tgt_rev,
        target_id="dvaa-chat-bot",
        target_name="DVAA Chat Bot",
        target_revision_sha256=None,
        dataset_id=ds_env.dataset_id,
        dataset_name=ds_env.name,
        dataset_revision_sha256=ds_env.file_sha256,
        selected_ids=["TC0011", "TC0012"],
        completed_verdicts={"TC0011": "PASS"},
        uncertain_ids=[],
        mode="live",
        use_judge=False,
        application_context_revision_sha256=ctx_rev,
    )
    prev_no_tgt = client.post(
        f"/api/testing/generic-runs/{run_no_tgt_rev}/resume/preview", base_url=BASE, headers=headers, json={}
    ).json
    assert prev_no_tgt["config_consistent"] is False
    assert prev_no_tgt["blocker"] == "resume_target_revision_missing"

    # 7. Absent-to-configured Application Context drift (historical explicitly None, now AppContext exists) -> blocked!
    run_ctx_absent = "10" + "0" * 30
    _create_interrupted_run_on_disk(
        gen_service.runs_root,
        run_id=run_ctx_absent,
        target_id="dvaa-chat-bot",
        target_name="DVAA Chat Bot",
        target_revision_sha256=dvaa_rev,
        dataset_id=ds_env.dataset_id,
        dataset_name=ds_env.name,
        dataset_revision_sha256=ds_env.file_sha256,
        selected_ids=["TC0011", "TC0012"],
        completed_verdicts={"TC0011": "PASS"},
        uncertain_ids=[],
        mode="live",
        use_judge=True,
        judge_provider_name="mock_judge",
        judge_model_name="mock-judge-v1",
        application_context_id=None,
        application_context_revision_sha256=None,
    )
    prev_drift = client.post(
        f"/api/testing/generic-runs/{run_ctx_absent}/resume/preview", base_url=BASE, headers=headers, json={}
    ).json
    assert prev_drift["eligible"] is False
    assert prev_drift["config_consistent"] is False
    assert prev_drift["blocker"] == "resume_application_context_changed"
    assert len(sent_prompts) == 0


def test_r03_checkpoint_integrity_validation_and_pre_dispatch_write_failure(tmp_path, monkeypatch):
    """R03 regression: malformed checkpoints fail closed with resume_state_incomplete;
    pre-dispatch checkpoint write OSError aborts before any target request is sent for that case.
    """
    sent_prompts, _ = _install_mock_http_target(monkeypatch)
    catalog, dataset_repo, _, gen_service, client, headers = _build_env(tmp_path)
    ds_env = _import_dataset(dataset_repo, _make_dataset_bytes(asi02_count=5, asi03_count=10), "r03_chk.json")
    dvaa_rev = gen_service._current_target_revision("dvaa-chat-bot")
    assert dvaa_rev is not None

    def _write_corrupted(run_id: str, mutator) -> None:
        p = _create_interrupted_run_on_disk(
            gen_service.runs_root,
            run_id=run_id,
            target_id="dvaa-chat-bot",
            target_name="DVAA Chat Bot",
            target_revision_sha256=dvaa_rev,
            dataset_id=ds_env.dataset_id,
            dataset_name=ds_env.name,
            dataset_revision_sha256=ds_env.file_sha256,
            selected_ids=["TC0011", "TC0012", "TC0013"],
            completed_verdicts={"TC0011": "PASS"},
            uncertain_ids=[],
            mode="live",
            use_judge=False,
            raw_status="interrupted",
        )
        doc = json.loads(p.read_text(encoding="utf-8"))
        mutator(doc)
        p.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")

    # 1. Duplicate case_id in case_statuses (same length as selected_cases, but only 2 unique IDs!)
    run_dup = "21" + "0" * 30
    _write_corrupted(run_dup, lambda d: d["case_statuses"].__setitem__(2, dict(d["case_statuses"][1])))
    assert (
        client.post(f"/api/testing/generic-runs/{run_dup}/resume/preview", base_url=BASE, headers=headers, json={}).json[
            "blocker"
        ]
        == "resume_state_incomplete"
    )

    # 2. Malformed row status value
    run_bad_st = "22" + "0" * 30
    _write_corrupted(run_bad_st, lambda d: d["case_statuses"][1].__setitem__("status", "unknown_corrupt"))
    assert (
        client.post(
            f"/api/testing/generic-runs/{run_bad_st}/resume/preview", base_url=BASE, headers=headers, json={}
        ).json["blocker"]
        == "resume_state_incomplete"
    )

    # 3. executed_cases inconsistent with len(cases)
    run_bad_exec = "23" + "0" * 30
    _write_corrupted(run_bad_exec, lambda d: d.__setitem__("executed_cases", 2))
    assert (
        client.post(
            f"/api/testing/generic-runs/{run_bad_exec}/resume/preview", base_url=BASE, headers=headers, json={}
        ).json["blocker"]
        == "resume_state_incomplete"
    )

    # 4. Continuation run with out-of-scope testcase not in root run
    run_root = "24" + "0" * 30
    run_oob = "25" + "0" * 30
    _create_interrupted_run_on_disk(
        gen_service.runs_root,
        run_id=run_root,
        target_id="dvaa-chat-bot",
        target_name="DVAA Chat Bot",
        target_revision_sha256=dvaa_rev,
        dataset_id=ds_env.dataset_id,
        dataset_name=ds_env.name,
        dataset_revision_sha256=ds_env.file_sha256,
        selected_ids=["TC0011", "TC0012"],
        completed_verdicts={"TC0011": "PASS"},
        uncertain_ids=[],
        mode="live",
        use_judge=False,
        raw_status="interrupted",
    )
    _create_interrupted_run_on_disk(
        gen_service.runs_root,
        run_id=run_oob,
        target_id="dvaa-chat-bot",
        target_name="DVAA Chat Bot",
        target_revision_sha256=dvaa_rev,
        dataset_id=ds_env.dataset_id,
        dataset_name=ds_env.name,
        dataset_revision_sha256=ds_env.file_sha256,
        selected_ids=["TC0012", "TC0015"],  # TC0015 was NOT in root run!
        completed_verdicts={},
        uncertain_ids=[],
        mode="live",
        use_judge=False,
        raw_status="interrupted",
        continuation_of_run_id=run_root,
        root_run_id=run_root,
    )
    assert (
        client.post(f"/api/testing/generic-runs/{run_oob}/resume/preview", base_url=BASE, headers=headers, json={}).json[
            "blocker"
        ]
        == "resume_state_incomplete"
    )

    # 5. Pre-dispatch checkpoint write failure (mocked OSError on case_started for TC0012):
    # Must NOT send target request for TC0012 or TC0013!
    real_write = gen_service._write_run_record
    failed_once = {"triggered": False}

    def _failing_pre_dispatch_write(run_dir: Path, rec: dict[str, Any]) -> None:
        if (
            not failed_once["triggered"]
            and rec.get("current_case_id") == "TC0012"
            and rec.get("current_stage") == "sending_request_to_target"
        ):
            failed_once["triggered"] = True
            raise OSError("simulated_disk_full_before_dispatch")
        real_write(run_dir, rec)

    monkeypatch.setattr(gen_service, "_write_run_record", _failing_pre_dispatch_write)
    start_res = client.post(
        "/api/testing/generic-runs/start",
        base_url=BASE,
        headers=headers,
        json={
            "authorization_confirmed": True,
            "mode": "live",
            "target_id": "dvaa-chat-bot",
            "dataset_id": ds_env.dataset_id,
            "testcase_ids": ["TC0011", "TC0012", "TC0013"],
            "asi_category": "ASI02",
            "use_judge": False,
            "async_execution": False,
        },
    )
    assert start_res.status_code == 201
    run_failed = start_res.json
    assert failed_once["triggered"] is True
    assert run_failed["status"] == "failed"
    assert run_failed["error_code"] == "dispatch_checkpoint_write_failed"
    assert run_failed["executed_cases"] == 1
    assert [c["case_id"] for c in run_failed["cases"]] == ["TC0011"]
    # CRITICAL: Target received ONLY TC0011 (1 request total); TC0012 & TC0013 were NEVER dispatched!
    assert len(sent_prompts) == 1
    assert "[TC0011]" in sent_prompts[0]


def test_unified_scan_lineage_completed_with_errors_and_report_export(tmp_path, monkeypatch):
    """Unified Scan History & Resume Results regression:
    - Exact reproduction: 35 selected (6 original: 1 FAIL, 5 INCONCLUSIVE + 29 resumed ERRORs).
    - Opening either root or continuation resolves unified deduplicated results (35/35, Completed with errors, 2 sessions).
    - Unified report endpoint preserves original per-case run_id/source_generic_run_id/report_path without mutating disk.
    - Unrelated scan on the SAME target & dataset is never merged into the lineage.
    """
    from tools.http import HttpClientError

    def _failing_target_request(self, *, method: str, url: str, headers=None, json_body=None, timeout=None):
        raise HttpClientError("Simulated Docker Engine unavailable during continuation")

    monkeypatch.setattr(HttpClient, "request", _failing_target_request)
    data_dir = tmp_path / "operator-data"
    catalog, dataset_repo, _, gen_service, client, headers = _build_env(tmp_path, data_dir=data_dir)
    ds_env = _import_dataset(dataset_repo, _make_dataset_bytes(asi02_count=35, asi03_count=15), "aigoat_35.json")
    dvaa_rev = gen_service._current_target_revision("dvaa-chat-bot")
    assert dvaa_rev is not None

    root_id = "91" + "0" * 30
    selected_35 = [f"TC{i:04d}" for i in range(11, 46)]
    completed_6 = {
        "TC0011": "FAIL",
        "TC0012": "INCONCLUSIVE",
        "TC0013": "INCONCLUSIVE",
        "TC0014": "INCONCLUSIVE",
        "TC0015": "INCONCLUSIVE",
        "TC0016": "INCONCLUSIVE",
    }
    root_file = _create_interrupted_run_on_disk(
        gen_service.runs_root,
        run_id=root_id,
        target_id="dvaa-chat-bot",
        target_name="DVAA Chat Bot",
        target_revision_sha256=dvaa_rev,
        dataset_id=ds_env.dataset_id,
        dataset_name=ds_env.name,
        dataset_revision_sha256=ds_env.file_sha256,
        selected_ids=selected_35,
        completed_verdicts=completed_6,
        uncertain_ids=["TC0017"],
        mode="live",
        use_judge=False,
        raw_status="interrupted",
    )
    root_bytes_before = root_file.read_bytes()

    # Also create an UNRELATED scan on the exact same target & dataset -> MUST NEVER merge with root_id!
    unrelated_id = "92" + "0" * 30
    _create_interrupted_run_on_disk(
        gen_service.runs_root,
        run_id=unrelated_id,
        target_id="dvaa-chat-bot",
        target_name="DVAA Chat Bot",
        target_revision_sha256=dvaa_rev,
        dataset_id=ds_env.dataset_id,
        dataset_name=ds_env.name,
        dataset_revision_sha256=ds_env.file_sha256,
        selected_ids=["TC0011", "TC0012"],
        completed_verdicts={"TC0011": "PASS", "TC0012": "PASS"},
        uncertain_ids=[],
        mode="live",
        use_judge=False,
        raw_status="completed",
    )

    # Preview with uncertain TC0017 included (29 remaining cases: TC0017..TC0045)
    prev = client.post(
        f"/api/testing/generic-runs/{root_id}/resume/preview",
        base_url=BASE,
        headers=headers,
        json={"include_uncertain_case_ids": ["TC0017"]},
    )
    assert prev.status_code == 200
    assert len(prev.json["selected_resume_case_ids"]) == 29

    # Resume -> all 29 cases hit simulated Docker unavailable -> 29 ERROR outcomes!
    res = client.post(
        f"/api/testing/generic-runs/{root_id}/resume/start",
        base_url=BASE,
        headers=headers,
        json={
            "authorization_confirmed": True,
            "stateful_target_acknowledged": True,
            "include_uncertain_case_ids": ["TC0017"],
            "uncertain_reexecution_confirmed": True,
            "expected_resume_digest": prev.json["resume_digest"],
            "async_execution": False,
        },
    )
    assert res.status_code == 201, res.get_json()
    child_id = res.json["generic_run_id"]

    # Opening EITHER root_id OR child_id resolves the exact same unified_lineage view!
    for rid in (root_id, child_id):
        rec = client.get(f"/api/testing/generic-runs/{rid}", base_url=BASE, headers=headers).json
        ul = rec["unified_lineage"]
        assert ul["logical_scan_id"] == root_id
        assert ul["root_run_id"] == root_id
        assert ul["selected_cases"] == 35
        assert ul["executed_cases"] == 35
        assert ul["session_count"] == 2
        assert ul["resume_count"] == 1
        assert ul["logical_status"] == "completed_with_errors"
        assert ul["execution_completed"] is True
        assert ul["has_evaluation_errors"] is True
        # Legacy parent cases preserve historical FAIL/INCONCLUSIVE verdicts;
        # new v2.0 continuation cases record execution errors in evaluation_summary (never polluting verdict_counts).
        assert ul["verdict_counts"] == {"FAIL": 1, "INCONCLUSIVE": 5}
        assert ul["evaluation_summary"]["evaluated_cases"] == 1
        assert ul["evaluation_summary"]["not_evaluated_count"] == 34
        assert ul["evaluation_summary"]["not_evaluated_reasons"]["EXECUTION_ERROR"] == 29
        assert len(ul["cases"]) == 35
        assert len({c["case_id"] for c in ul["cases"]}) == 35  # Zero double-counting!
        assert [c["case_id"] for c in ul["cases"]] == selected_35
        assert len(ul["case_statuses"]) == 35
        assert rec["lineage_summary"]["has_resumable_work"] is False
        # Preserved original case provenance & source session IDs
        tc11 = ul["cases"][0]
        tc17 = ul["cases"][6]
        assert tc11["case_id"] == "TC0011" and tc11["verdict"] == "FAIL" and tc11["source_generic_run_id"] == root_id
        assert (
            tc17["case_id"] == "TC0017"
            and tc17["verdict"] is None
            and tc17["evaluation_status"] == "EXECUTION_ERROR"
            and tc17["source_generic_run_id"] == child_id
        )

    # Unified report endpoint works identically from root_id or child_id and leaves disk artifacts immutable!
    uni_a = client.get(f"/api/testing/generic-runs/{root_id}/unified-report.json", base_url=BASE, headers=headers)
    uni_b = client.get(f"/api/testing/generic-runs/{child_id}/unified-report.json", base_url=BASE, headers=headers)
    assert uni_a.status_code == 200 and uni_b.status_code == 200
    rep_a, rep_b = uni_a.json, uni_b.json
    assert rep_a["report_kind"] == "unified_generic_scan_lineage"
    assert rep_a["logical_scan_id"] == root_id == rep_b["logical_scan_id"]
    assert rep_a["selected_cases"] == 35
    assert rep_a["recorded_outcomes"] == 35
    assert rep_a["verdict_counts"] == {"FAIL": 1, "INCONCLUSIVE": 5}
    assert rep_a["evaluation_summary"]["not_evaluated_reasons"]["EXECUTION_ERROR"] == 29
    assert rep_a["logical_status"] == "completed_with_errors"
    assert rep_a["session_count"] == 2
    assert len(rep_a["cases"]) == 35
    assert root_file.read_bytes() == root_bytes_before  # Historical parent file untouched!

    # Individual historical session report remains independently accessible!
    indiv_a = client.get(f"/api/testing/generic-runs/{root_id}/report.json", base_url=BASE, headers=headers)
    assert indiv_a.status_code == 200
    assert indiv_a.json["executed_cases"] == 6

    # Unrelated scan on the same target/dataset is NOT merged!
    unrel_rec = client.get(f"/api/testing/generic-runs/{unrelated_id}", base_url=BASE, headers=headers).json
    assert unrel_rec.get("unified_lineage") is None
    assert unrel_rec["executed_cases"] == 2
    assert unrel_rec["verdict_counts"] == {"PASS": 2}


def test_r04_unified_judge_and_request_metrics_consistency(tmp_path, monkeypatch):
    """R04 regression: original Hybrid session has 6/6 successful Judge calls, continuation has 29 ERRORs & 0 Judge calls.
    Unified Judge stats (6/6) and cumulative counters must be identical from BOTH root and continuation IDs,
    included in unified-report.json, and distinguish missing metadata (None) from 0.
    """
    from tools.http import HttpClientError

    def _failing_target_request(self, *, method: str, url: str, headers=None, json_body=None, timeout=None):
        raise HttpClientError("Simulated Docker Engine unavailable")

    monkeypatch.setattr(HttpClient, "request", _failing_target_request)
    judge = _RecordingJudgeProvider()
    data_dir = tmp_path / "operator-data"
    catalog, dataset_repo, _, gen_service, client, headers = _build_env(
        tmp_path, data_dir=data_dir, judge_provider=judge
    )
    ds_env = _import_dataset(dataset_repo, _make_dataset_bytes(asi02_count=35, asi03_count=15), "r04_aigoat.json")
    dvaa_rev = gen_service._current_target_revision("dvaa-chat-bot")
    assert dvaa_rev is not None
    ctx_rev = _save_app_context(client, headers, "dvaa-chat-bot", dvaa_rev)

    root_id = "93" + "0" * 30
    selected_35 = [f"TC{i:04d}" for i in range(11, 46)]
    completed_6 = {
        "TC0011": "FAIL",
        "TC0012": "INCONCLUSIVE",
        "TC0013": "INCONCLUSIVE",
        "TC0014": "INCONCLUSIVE",
        "TC0015": "INCONCLUSIVE",
        "TC0016": "INCONCLUSIVE",
    }
    _create_interrupted_run_on_disk(
        gen_service.runs_root,
        run_id=root_id,
        target_id="dvaa-chat-bot",
        target_name="DVAA Chat Bot",
        target_revision_sha256=dvaa_rev,
        dataset_id=ds_env.dataset_id,
        dataset_name=ds_env.name,
        dataset_revision_sha256=ds_env.file_sha256,
        selected_ids=selected_35,
        completed_verdicts=completed_6,
        uncertain_ids=["TC0017"],
        mode="live",
        use_judge=True,
        judge_provider_name="mock_judge",
        judge_model_name="mock-judge-v1",
        application_context_revision_sha256=ctx_rev,
        raw_status="interrupted",
    )

    prev = client.post(
        f"/api/testing/generic-runs/{root_id}/resume/preview",
        base_url=BASE,
        headers=headers,
        json={"include_uncertain_case_ids": ["TC0017"]},
    )
    assert prev.status_code == 200 and prev.json["eligible"] is True

    res = client.post(
        f"/api/testing/generic-runs/{root_id}/resume/start",
        base_url=BASE,
        headers=headers,
        json={
            "authorization_confirmed": True,
            "stateful_target_acknowledged": True,
            "include_uncertain_case_ids": ["TC0017"],
            "uncertain_reexecution_confirmed": True,
            "expected_resume_digest": prev.json["resume_digest"],
            "async_execution": False,
        },
    )
    assert res.status_code == 201, res.get_json()
    child_id = res.json["generic_run_id"]
    # Continuation had 0 Judge calls (all 29 target requests failed with ERROR)
    assert len(judge.calls) == 0

    # Both root_id and child_id MUST report identical unified Judge statistics (6/6) and cumulative counters!
    for rid in (root_id, child_id):
        rec = client.get(f"/api/testing/generic-runs/{rid}", base_url=BASE, headers=headers).json
        ul = rec["unified_lineage"]
        jm = ul["judge_metadata"]
        assert jm is not None
        assert jm["request_count"] == 6
        assert jm["success_count"] == 6
        assert jm["failure_count"] == 0
        assert jm["provider"] == "mock_judge"
        assert jm["model"] == "mock-judge-v1"
        assert ul["judge_requests_used"] == 6
        assert ul["sessions"][0]["judge_requests_used"] == 6
        assert ul["sessions"][1]["judge_requests_used"] == 0

        uni_rep = client.get(
            f"/api/testing/generic-runs/{rid}/unified-report.json", base_url=BASE, headers=headers
        )
        assert uni_rep.status_code == 200
        rj = uni_rep.json
        assert rj["judge_requests_used"] == 6
        assert rj["judge_metadata"]["success_count"] == 6
        assert rj["judge_metadata"]["request_count"] == 6
        assert rj["target_requests_used"] == ul["target_requests_used"]

    # Verify missing counter metadata stays None (distinguished from 0) on live runs
    for rid in (root_id, child_id):
        p = gen_service.runs_root / rid / "generic-run.json"
        doc = json.loads(p.read_text(encoding="utf-8"))
        doc.pop("target_requests_used", None)
        p.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    rec_missing = client.get(f"/api/testing/generic-runs/{root_id}", base_url=BASE, headers=headers).json
    assert rec_missing["unified_lineage"]["target_requests_used"] is None
    assert rec_missing["unified_lineage"]["sessions"][0]["target_requests_used"] is None


def test_r05_unified_report_checkpoint_integrity_blocks_out_of_scope_and_invalid_lineage(tmp_path):
    """R05 regression: invalid lineage with out-of-scope testcase results must NOT inflate cumulative counts,
    must NOT report completed/completed_with_errors, must block unified export (409), and preserve individual session reports.
    """
    data_dir = tmp_path / "operator-data"
    catalog, dataset_repo, _, gen_service, client, headers = _build_env(tmp_path, data_dir=data_dir)
    ds_env = _import_dataset(dataset_repo, _make_dataset_bytes(asi02_count=35, asi03_count=15), "r05_int.json")
    dvaa_rev = gen_service._current_target_revision("dvaa-chat-bot")
    assert dvaa_rev is not None

    root_id = "94" + "0" * 30
    child_id = "95" + "0" * 30
    selected_35 = [f"TC{i:04d}" for i in range(11, 46)]
    completed_6 = {f"TC{i:04d}": "INCONCLUSIVE" for i in range(11, 17)}
    completed_6["TC0011"] = "FAIL"

    _create_interrupted_run_on_disk(
        gen_service.runs_root,
        run_id=root_id,
        target_id="dvaa-chat-bot",
        target_name="DVAA Chat Bot",
        target_revision_sha256=dvaa_rev,
        dataset_id=ds_env.dataset_id,
        dataset_name=ds_env.name,
        dataset_revision_sha256=ds_env.file_sha256,
        selected_ids=selected_35,
        completed_verdicts=completed_6,
        uncertain_ids=["TC0017"],
        mode="live",
        use_judge=False,
        raw_status="interrupted",
    )

    # Corrupted continuation: 28 in-scope ERRORs (TC0017..TC0044) + 1 OUT-OF-SCOPE case TC0099 (NOT TC0045!)
    # Raw total = 6 + 29 = 35, but TC0099 is outside root scope so only 34 valid in-scope cases exist!
    corrupt_ids = [f"TC{i:04d}" for i in range(17, 45)] + ["TC0099"]
    corrupt_verdicts = {cid: "ERROR" for cid in corrupt_ids}
    _create_interrupted_run_on_disk(
        gen_service.runs_root,
        run_id=child_id,
        target_id="dvaa-chat-bot",
        target_name="DVAA Chat Bot",
        target_revision_sha256=dvaa_rev,
        dataset_id=ds_env.dataset_id,
        dataset_name=ds_env.name,
        dataset_revision_sha256=ds_env.file_sha256,
        selected_ids=corrupt_ids,
        completed_verdicts=corrupt_verdicts,
        uncertain_ids=[],
        mode="live",
        use_judge=False,
        raw_status="completed",
        continuation_of_run_id=root_id,
        root_run_id=root_id,
    )

    for rid in (root_id, child_id):
        rec = client.get(f"/api/testing/generic-runs/{rid}", base_url=BASE, headers=headers).json
        ul = rec["unified_lineage"]
        assert ul["integrity_status"] == "invalid_checkpoint"
        assert ul["integrity_warning"]
        assert ul["out_of_scope_case_ids"] == ["TC0099"]
        # Out-of-scope TC0099 MUST NOT be included in unified cases or counts!
        assert ul["executed_cases"] == 34
        assert all(c["case_id"] != "TC0099" for c in ul["cases"])
        # MUST NOT claim verified completion or completed_with_errors!
        assert ul["execution_completed"] is False
        assert ul["logical_status"] not in {"completed", "completed_with_errors"}
        assert rec["lineage_summary"]["has_resumable_work"] is False

        # Unified export MUST be blocked with 409 unified_report_integrity_failed!
        uni_exp = client.get(
            f"/api/testing/generic-runs/{rid}/unified-report.json", base_url=BASE, headers=headers
        )
        assert uni_exp.status_code == 409
        assert uni_exp.json["error"]["code"] == "unified_report_integrity_failed"

        # Individual historical session reports MUST remain accessible (200)!
        indiv = client.get(f"/api/testing/generic-runs/{rid}/report.json", base_url=BASE, headers=headers)
        assert indiv.status_code == 200

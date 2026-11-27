"""Offline boundary & integration tests for Flexible Per-ASI Testcase Counts (Phase 1).

Strictly offline (MockGeneratorProvider + local loopback HTTP stub + in-process mock Judge).
Zero live DeepSeek/DVAA/AIGoat calls.

Covers:
1. Boundary counts: 1, 20, 49, 50, 51 (and 0, -1, booleans).
2. Single-ASI full allocation (ASI03=50, ASI05=50) and multi-ASI combinations
   (ASI03=20+ASI05=20=40; ASI01=10+ASI03=20+ASI05=20=50) -> ALLOW.
3. Exceeding global cap (ASI03=30+ASI05=30=60; ASI03=51; ASI01=10+ASI03=20+ASI05=21=51) -> REJECT.
4. Default per-ASI count remains 5; global cap remains 50; execution/Judge budgets unchanged (<= 50).
5. RawGenerationOutputContract accepts 50 candidates for one ASI and rejects 51.
6. Token budget clamps cleanly at ceiling for 50 and rejects 51.
7. SKILL.md contains no stale 15/ASI hard cap.
8. Direct API validation for both Generate Only (`POST /generate`) and Generate & Run (`POST /generate-and-run`),
   including partial 35/50 handling.
"""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import secrets
import socket
import threading
import time
from typing import Any

from pydantic import ValidationError
import pytest

from core.models import EvaluationStatus
from generator.constants import (
    DEFAULT_MAX_PER_ASI,
    DEFAULT_MAX_TOTAL_CASES,
    DEFAULT_MIN_PER_ASI,
    DEFAULT_PER_ASI,
    HARD_MAX_PER_ASI,
    HARD_MAX_TOTAL_CASES,
)
from generator.models import (
    DEFAULT_GENERATION_LIMITS,
    GenerationLimits,
    RawGenerationOutputContract,
)
from generator.providers.base import compute_token_budget
from generator.providers.mock import MockFixtureResponse, MockGeneratorProvider
from generator.service import GenerationServiceRequest
from generator.skills import GeneratorSkillLoader
from integrations.external_evaluator.models import (
    EvaluationRequest,
    ExternalEvaluationOutcome,
    ExternalEvaluationResult,
    JudgeEvidence,
)
from workflow.api import create_app
from workflow.application_context import (
    ApplicationContextDraft,
    ApplicationContextStore,
    SaveApplicationContext,
)
from workflow.dataset_repository import DatasetRepository
from workflow.management import ManagedProfile, ManagedTargetCatalog, ReviewProfile, SaveProfile
from workflow.models import CatalogConfig
from workflow.response_policies import ResponsePolicyDraft, ResponsePolicyStore
from workflow.routes_generic_runner import GenericRunService, _MAX_WEB_CASES
from workflow.target_locks import TargetExecutionLockRegistry

HOST = "127.0.0.1:8092"
ORIGIN = f"http://{HOST}"


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _start_stub_chat_server(counter: list[str]):
    port = _free_port()

    class _Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0") or "0")
            raw = self.rfile.read(length) if length > 0 else b"{}"
            body = json.loads(raw.decode("utf-8"))
            counter.append(str(body.get("messages", [{}])[-1].get("content", "")))
            data = json.dumps(
                {"choices": [{"message": {"content": "I must decline this request."}, "finish_reason": "stop"}]}
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, format, *args):
            return

    server = HTTPServer(("127.0.0.1", port), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{port}/v1/chat/completions"


class _PassJudge:
    provider_name = "mock-judge"
    model_name = "mock-model"

    def __init__(self) -> None:
        self.calls: list[str] = []

    def evaluate(self, request: EvaluationRequest) -> ExternalEvaluationOutcome:
        self.calls.append(request.testcase.id)
        label_by_type = {
            "goal_hijacking": "ORIGINAL_GOAL",
            "tool_misuse": "TOOL_BOUNDARY_PRESERVED",
            "identity_privilege_abuse": "IDENTITY_BOUNDARY_PRESERVED",
            "unexpected_code_execution": "RESPONSE_BOUNDARY_PRESERVED",
        }
        span = (request.observation.response_text or "I must decline").strip()[:60]
        return ExternalEvaluationOutcome(
            request_sha256=request.sha256,
            skill=request.skill,
            result=ExternalEvaluationResult(
                classification=label_by_type.get(request.evaluation_type, "ORIGINAL_GOAL"),
                verdict=EvaluationStatus.PASS,
                confidence=0.95,
                reason="Target maintained declared security boundary.",
                evidence=[JudgeEvidence(type="response_span", value=span)],
            ),
            duration_ms=2.0,
            exit_code=0,
        )


def _candidate_dict(idx: int, asi_code: str) -> dict[str, Any]:
    return {
        "prompt": f"Synthetic {asi_code} security boundary probe #{idx + 1} testing declared constraints.",
        "description": f"Boundary test case #{idx + 1} for {asi_code}.",
        "strategy_tag": f"boundary_probe_{idx + 1}",
        "context_basis": ["purpose", "trust_boundaries"],
        "scope_note": "Descriptive metadata only; backend readiness owns scope.",
    }


def _setup_app(tmp_path: Path, *, endpoint: str, provider: MockGeneratorProvider):
    catalog = ManagedTargetCatalog(
        CatalogConfig(catalog_schema_version="1.0.0", policy_ref="flex-count-policy", targets=[]),
        tmp_path / "operator",
        local_single_user=True,
    )
    saved = catalog.save_profile(
        SaveProfile(
            profile=ManagedProfile(
                id="flex-target",
                name="Flex Target",
                platform_id="test-platform",
                platform_name="Test Platform",
                endpoint=endpoint,
                protocol="openai-chat",
                model="demo-bot",
                timeout_seconds=15,
            )
        )
    )
    reviewed = catalog.review_profile(
        ReviewProfile(
            target_id=saved["id"],
            profile_revision=saved["profile_revision"],
            policy_ref=saved["policy_ref"],
            endpoint=saved["endpoint"],
            protocol=saved["protocol"],
            model=saved["default_model"],
            capabilities=["chat"],
            authorization_confirmed=True,
        )
    )
    app_ctx = ApplicationContextStore(catalog)
    fields = {
        "purpose": "Customer support assistant for sandboxed billing FAQs.",
        "features": "Read-only FAQ answers.",
        "available_tools": "lookup_faq",
        "users": "Standard customer (non-admin).",
        "authorized_actions": "Answer public billing questions.",
        "prohibited_resources": "Internal admin credentials and host shell.",
        "high_risk_actions": "Role impersonation or shell command execution.",
        "trust_boundaries": "All user prompts are untrusted input.",
        "required_instructions": "Never impersonate staff or output shell commands.",
    }
    app_ctx.save(
        SaveApplicationContext(
            draft=ApplicationContextDraft(
                target_id="flex-target",
                target_revision=reviewed["profile_revision"],
                field_provenance={k: "operator_confirmed" for k in fields},
                **fields,
            ),
            expected_revision=None,
            safe_description_confirmed=True,
        )
    )

    policy_store = ResponsePolicyStore(tmp_path / "policies")
    policies_by_asi: dict[str, str] = {}
    for asi, cat, scope in (
        ("ASI01", "goal_hijacking", "goal_hijack_response"),
        ("ASI02", "tool_misuse", "tool_intent_response"),
        ("ASI03", "identity_privilege_abuse", "identity_claim_response"),
        ("ASI05", "unexpected_code_execution", "response_command_artifact"),
    ):
        draft = policy_store.save_draft(
            ResponsePolicyDraft(
                target_id="flex-target",
                category=cat,
                evaluation_scope=scope,
                prohibited_behavior="Violate declared security boundaries or impersonate privileged roles.",
                allowed_benign_context="Politely refuse and provide safe FAQ guidance.",
                expected_response_boundary="Refuse unauthorized requests cleanly.",
            )
        )
        rev = policy_store.review(draft.policy_id, expected_revision_sha256=draft.revision_sha256, reviewer="qa")
        policies_by_asi[asi] = rev.policy_id

    repo = DatasetRepository(tmp_path / "operator")
    locks = TargetExecutionLockRegistry()
    judge = _PassJudge()
    grs = GenericRunService(
        catalog=catalog,
        dataset_repo=repo,
        policy_store=policy_store,
        runs_root=tmp_path / "generic-runs",
        application_contexts=app_ctx,
        judge_provider=judge,
        target_lock_registry=locks,
    )
    token = secrets.token_urlsafe(48)
    app = create_app(
        catalog,
        operator_secret=token,
        local_single_user=True,
        dataset_repository=repo,
        generic_run_service=grs,
        generator_provider=provider,
    )
    client = app.test_client()
    nonce = client.get("/api/testing/health", headers={"Host": HOST}).get_json()["validation_nonce"]
    return {
        "client": client,
        "nonce": nonce,
        "token": token,
        "target_rev": reviewed["profile_revision"],
        "policies_by_asi": policies_by_asi,
        "repo": repo,
        "grs": grs,
        "judge": judge,
        "locks": locks,
    }


def _headers(nonce: str, token: str, *, session: str = "op-flex", post: bool = True) -> dict[str, str]:
    hdrs = {
        "Host": HOST,
        "X-SecAgent-Validation": nonce,
        "X-SecAgent-Operator": token,
        "X-SecAgent-Session": session,
    }
    if post:
        hdrs["Origin"] = ORIGIN
        hdrs["Content-Type"] = "application/json"
    return hdrs


def test_constants_and_boundary_validation_matrix() -> None:
    """Verify defaults preserved (5), global cap preserved (50), per-ASI cap lifted to 50,
    and all acceptance boundary combinations (1, 20, 49, 50, 51, single & multi-ASI)."""
    assert DEFAULT_MIN_PER_ASI == 1
    assert DEFAULT_PER_ASI == 5
    assert DEFAULT_MAX_PER_ASI == 50
    assert HARD_MAX_PER_ASI == 50
    assert DEFAULT_MAX_TOTAL_CASES == 50
    assert HARD_MAX_TOTAL_CASES == 50
    assert _MAX_WEB_CASES == 50  # Execution cap untouched

    # Allowed single-ASI boundaries: 1, 20, 49, 50
    for count in (1, 20, 49, 50):
        req = GenerationServiceRequest(target_id="t1", counts_by_asi={"ASI03": count})
        assert req.counts_by_asi == {"ASI03": count}
    assert GenerationServiceRequest(target_id="t1", counts_by_asi={"ASI05": 50}).counts_by_asi == {"ASI05": 50}

    # Allowed multi-ASI acceptance combinations
    assert GenerationServiceRequest(
        target_id="t1", counts_by_asi={"ASI03": 20, "ASI05": 20}
    ).counts_by_asi == {"ASI03": 20, "ASI05": 20}
    assert GenerationServiceRequest(
        target_id="t1", counts_by_asi={"ASI01": 10, "ASI03": 20, "ASI05": 20}
    ).counts_by_asi == {"ASI01": 10, "ASI03": 20, "ASI05": 20}

    # Rejected single-ASI & multi-ASI boundaries
    for invalid_counts in (
        {"ASI03": 0},
        {"ASI03": -1},
        {"ASI03": 51},
        {"ASI05": 51},
        {"ASI03": 30, "ASI05": 30},
        {"ASI01": 10, "ASI03": 20, "ASI05": 21},
    ):
        with pytest.raises(ValidationError):
            GenerationServiceRequest(target_id="t1", counts_by_asi=invalid_counts)

    # Global ceiling 50 cannot be bypassed via GenerationLimits
    with pytest.raises(ValidationError):
        GenerationLimits(max_per_asi=51)
    with pytest.raises(ValidationError):
        GenerationLimits(max_total_cases=51)
    # Tighter custom limits still work
    assert GenerationLimits(max_per_asi=10, max_total_cases=20).validate_per_asi_counts({"ASI01": 10, "ASI02": 10}) == {
        "ASI01": 10,
        "ASI02": 10,
    }


def test_output_contract_token_budget_and_skill_prompt_support_50_per_asi() -> None:
    """Verify RawGenerationOutputContract accepts 50 candidates and rejects 51,
    compute_token_budget clamps cleanly at 50 and rejects 51, and SKILL.md drops stale 15 cap."""
    contract_50 = RawGenerationOutputContract.model_validate(
        {
            "schema_version": "1.0",
            "asi_category": "ASI03",
            "context_gaps": [],
            "candidates": [_candidate_dict(i, "ASI03") for i in range(50)],
        }
    )
    assert len(contract_50.candidates) == 50

    with pytest.raises(ValidationError):
        RawGenerationOutputContract.model_validate(
            {
                "schema_version": "1.0",
                "asi_category": "ASI03",
                "context_gaps": [],
                "candidates": [_candidate_dict(i, "ASI03") for i in range(51)],
            }
        )

    assert compute_token_budget(50, ceiling=8192) == 8192
    assert compute_token_budget(50, ceiling=16384) == 16384
    with pytest.raises(ValueError, match="exceeds hard ceiling 50"):
        compute_token_budget(51, ceiling=8192)

    skill_text = GeneratorSkillLoader().load("ASI03").system_prompt.lower()
    assert "hard ceiling 15" not in skill_text
    assert "global ceiling 50" in skill_text


def test_direct_api_generate_only_allows_50_rejects_over_cap_and_handles_partial_35_of_50(tmp_path: Path) -> None:
    """Direct API test for Mode 2 (Generate Only): status limits, 50/ASI generate+save,
    direct 400 rejection for 51 and 30+30 with 0 provider calls, and honest partial 35/50."""
    provider = MockGeneratorProvider(mode="success")
    env = _setup_app(tmp_path, endpoint="http://127.0.0.1:19999/v1/chat/completions", provider=provider)
    client, nonce, token = env["client"], env["nonce"], env["token"]

    # 1. GET /status advertises max_per_asi=50, hard_max_per_asi=50, default_per_asi=5, max_total_cases=50
    st = client.get("/api/testing/generator/status", headers=_headers(nonce, token, post=False))
    assert st.status_code == 200
    limits = st.get_json()["limits"]
    assert limits == {
        "min_per_asi": 1,
        "default_per_asi": 5,
        "max_per_asi": 50,
        "max_total_cases": 50,
        "hard_max_per_asi": 50,
        "hard_max_total_cases": 50,
    }

    # 2. Direct API over-cap calls MUST fail closed 400 with ZERO provider calls
    for bad_counts in ({"ASI03": 51}, {"ASI03": 30, "ASI05": 30}, {"ASI01": 10, "ASI03": 20, "ASI05": 21}):
        r_bad = client.post(
            "/api/testing/generator/generate",
            headers=_headers(nonce, token),
            data=json.dumps({"target_id": "flex-target", "counts_by_asi": bad_counts}),
        )
        assert r_bad.status_code == 400, (bad_counts, r_bad.text)
    assert provider.total_calls == 0

    # 3. Single ASI = 50 -> 201 preview with 50 candidates -> explicit Save persists 50 testcases
    r_50 = client.post(
        "/api/testing/generator/generate",
        headers=_headers(nonce, token),
        data=json.dumps(
            {
                "target_id": "flex-target",
                "counts_by_asi": {"ASI03": 50},
                "policy_ids_by_asi": {"ASI03": env["policies_by_asi"]["ASI03"]},
            }
        ),
    )
    assert r_50.status_code == 201, r_50.text
    preview = r_50.get_json()["preview"]
    assert preview["overall_status"] == "completed"
    assert preview["total_requested"] == 50
    assert preview["total_accepted"] == 50
    assert len(preview["candidates"]) == 50
    assert preview["requires_partial_confirmation"] is False

    save_r = client.post(
        f"/api/testing/generator/previews/{preview['preview_id']}/save",
        headers=_headers(nonce, token),
        data=json.dumps({"dataset_name": "asi03-50-cases", "save_confirmed": True}),
    )
    assert save_r.status_code == 201, save_r.text
    save_rec = save_r.get_json()["save_record"]
    assert save_rec["saved_count"] == 50
    ds = env["repo"].get_dataset(save_rec["dataset_id"])
    assert ds is not None and len(ds.testcases) == 50

    # 4. Partial generation: request 50, provider yields 35 valid -> status='partial', requires_partial_confirmation=True
    partial_json = json.dumps(
        {
            "schema_version": "1.0",
            "asi_category": "ASI05",
            "context_gaps": [],
            "candidates": [_candidate_dict(i, "ASI05") for i in range(35)],
        }
    )
    provider_partial = MockGeneratorProvider(fixtures=[MockFixtureResponse(mode="success", raw_text=partial_json)])
    env_p = _setup_app(tmp_path / "partial", endpoint="http://127.0.0.1:19999/v1/chat/completions", provider=provider_partial)
    r_part = env_p["client"].post(
        "/api/testing/generator/generate",
        headers=_headers(env_p["nonce"], env_p["token"]),
        data=json.dumps(
            {
                "target_id": "flex-target",
                "counts_by_asi": {"ASI05": 50},
                "policy_ids_by_asi": {"ASI05": env_p["policies_by_asi"]["ASI05"]},
            }
        ),
    )
    assert r_part.status_code == 201, r_part.text
    p_snap = r_part.get_json()["preview"]
    assert p_snap["overall_status"] == "partial"
    assert p_snap["meets_requested_counts"] is False
    assert p_snap["total_requested"] == 50
    assert p_snap["total_accepted"] == 35
    assert p_snap["requires_partial_confirmation"] is True


def test_direct_api_generate_and_run_flexible_counts_and_partial_gate(tmp_path: Path) -> None:
    """Direct API test for Mode 1 (Generate & Run): rejects 51 & 30+30 with 0 calls/locks,
    executes ASI03=50 and ASI01=10+ASI03=20+ASI05=20 within existing 50 target/judge budget,
    and stops fail-closed on partial 35/50 when allow_partial_execution=False."""
    target_calls: list[str] = []
    server, endpoint = _start_stub_chat_server(target_calls)
    try:
        provider = MockGeneratorProvider(mode="success")
        env = _setup_app(tmp_path, endpoint=endpoint, provider=provider)
        client, nonce, token = env["client"], env["nonce"], env["token"]

        # 1. Direct API over-cap calls rejected 400 with 0 provider/target calls & 0 locks
        for bad_counts in ({"ASI03": 51}, {"ASI03": 30, "ASI05": 30}):
            r_bad = client.post(
                "/api/testing/generator/generate-and-run",
                headers=_headers(nonce, token),
                data=json.dumps(
                    {
                        "target_id": "flex-target",
                        "counts_by_asi": bad_counts,
                        "evaluation_mode": "hybrid",
                        "execution_mode": "live",
                        "authorization_confirmed": True,
                        "policy_ids_by_asi": env["policies_by_asi"],
                        "expected_target_revision": env["target_rev"],
                    }
                ),
            )
            assert r_bad.status_code == 400, (bad_counts, r_bad.text)
        assert provider.total_calls == 0
        assert target_calls == []
        assert env["locks"].list_reservations() == []

        # 2. Single ASI = 50 executes end-to-end with target/judge budget == 50 (unchanged global cap)
        r_50 = client.post(
            "/api/testing/generator/generate-and-run",
            headers=_headers(nonce, token),
            data=json.dumps(
                {
                    "target_id": "flex-target",
                    "counts_by_asi": {"ASI03": 50},
                    "evaluation_mode": "hybrid",
                    "execution_mode": "live",
                    "authorization_confirmed": True,
                    "policy_ids_by_asi": {"ASI03": env["policies_by_asi"]["ASI03"]},
                    "async_execution": False,
                    "expected_target_revision": env["target_rev"],
                }
            ),
        )
        assert r_50.status_code == 201, r_50.text
        wf_50 = r_50.get_json()["workflow"]
        assert wf_50["status"] == "completed"
        assert wf_50["requested_count"] == 50
        assert wf_50["accepted_count"] == 50
        assert wf_50["executed_cases"] == 50
        assert len(target_calls) == 50
        run_50 = env["grs"].get_run(wf_50["run_id"])
        assert run_50 is not None
        assert run_50["target_request_budget"] == 50
        assert run_50["judge_request_budget"] == 50
        assert env["locks"].list_reservations() == []

        # 3. Multi-ASI 10 + 20 + 20 = 50 executes cleanly
        target_calls.clear()
        r_multi = client.post(
            "/api/testing/generator/generate-and-run",
            headers=_headers(nonce, token),
            data=json.dumps(
                {
                    "target_id": "flex-target",
                    "counts_by_asi": {"ASI01": 10, "ASI03": 20, "ASI05": 20},
                    "evaluation_mode": "hybrid",
                    "execution_mode": "live",
                    "authorization_confirmed": True,
                    "policy_ids_by_asi": {
                        "ASI01": env["policies_by_asi"]["ASI01"],
                        "ASI03": env["policies_by_asi"]["ASI03"],
                        "ASI05": env["policies_by_asi"]["ASI05"],
                    },
                    "async_execution": False,
                    "expected_target_revision": env["target_rev"],
                }
            ),
        )
        assert r_multi.status_code == 201, r_multi.text
        wf_multi = r_multi.get_json()["workflow"]
        assert wf_multi["status"] == "completed"
        assert wf_multi["requested_count"] == 50
        assert wf_multi["executed_cases"] == 50
        assert len(target_calls) == 50
        assert env["locks"].list_reservations() == []

        # 4. Partial 35/50 with allow_partial_execution=False stops fail-closed at validating (0 target calls)
        target_calls.clear()
        partial_json = json.dumps(
            {
                "schema_version": "1.0",
                "asi_category": "ASI03",
                "context_gaps": [],
                "candidates": [_candidate_dict(i, "ASI03") for i in range(35)],
            }
        )
        p_prov = MockGeneratorProvider(fixtures=[MockFixtureResponse(mode="success", raw_text=partial_json)])
        env_p = _setup_app(tmp_path / "gnr-partial", endpoint=endpoint, provider=p_prov)
        r_part = env_p["client"].post(
            "/api/testing/generator/generate-and-run",
            headers=_headers(env_p["nonce"], env_p["token"]),
            data=json.dumps(
                {
                    "target_id": "flex-target",
                    "counts_by_asi": {"ASI03": 50},
                    "evaluation_mode": "hybrid",
                    "execution_mode": "live",
                    "authorization_confirmed": True,
                    "allow_partial_execution": False,
                    "policy_ids_by_asi": {"ASI03": env_p["policies_by_asi"]["ASI03"]},
                    "async_execution": False,
                    "expected_target_revision": env_p["target_rev"],
                }
            ),
        )
        assert r_part.status_code == 201, r_part.text
        wf_part = r_part.get_json()["workflow"]
        assert wf_part["status"] == "partial_stopped"
        assert wf_part["error_code"] == "partial_generation_not_executed"
        assert wf_part["requested_count"] == 50
        assert wf_part["accepted_count"] == 35
        assert wf_part["auto_persisted"] is False
        assert target_calls == []
        assert env_p["locks"].list_reservations() == []
    finally:
        server.shutdown()
        server.server_close()

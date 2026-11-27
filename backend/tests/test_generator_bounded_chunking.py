"""Deterministic offline test matrix for Generator Phase 2: Bounded Multi-Chunk Generation.

Strictly offline (MockGeneratorProvider + local loopback HTTP stub + in-process mock Judge).
Zero live DeepSeek, DVAA, or AIGoat calls.

Covers Sections 10A-10G:
- A. Chunk Planner boundaries (1, 15, 16, 20, 30, 31, 45, 50) & hard constants.
- B. 50/50 success across 4 chunks (unique IDs, unique source indices, token bounds, off-by-one guard).
- C. Cross-chunk exact/NFKC deduplication pointing accurately to original Chunk 1 candidate.
- D. Partial 42/50 generation across Generate Only (confirmation gate) and Generate & Run (partial_stopped).
- E. Provider failure modes (timeout, network, rate limit, HTTP 5xx, missing credential, auth rejected,
     model rejected, finish_reason=length, invalid JSON, null token usage) & zero retry amplification.
- F. Deterministic Event-gated G15 Stop/Cancel checkpoints inside chunking & across ASIs.
- G. Backward compatibility (<= 15 single-chunk, flexible combinations, over-cap rejection, readiness block,
     reviewed policy preservation, cross-ASI dedup, quality evaluator compatibility).
"""

from __future__ import annotations

from hashlib import sha256
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import secrets
import socket
import threading
from typing import Any

import pytest

from core.cancellation import RunCancelledError
from core.models import EvaluationStatus
from generator.constants import (
    DEFAULT_GENERATION_CHUNK_SIZE,
    MAX_GENERATION_OUTPUT_TOKEN_BUDGET,
    MAX_GENERATION_TOTAL_PROVIDER_CALLS,
    MAX_PLANNED_CHUNKS_PER_ASI,
    MAX_TOTAL_PROVIDER_CALLS_PER_ASI,
)
from generator.providers.base import (
    ProviderErrorCategory,
    ProviderGenerationRequest,
    ProviderGenerationResponse,
    TokenUsage,
)
from generator.providers.mock import MockFixtureResponse, MockGeneratorProvider
from generator.quality_evaluator import evaluate_generation_result, evaluate_persisted_dataset
from generator.service import (
    GenerationServiceRequest,
    GeneratorService,
    plan_asi_chunks,
)
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
from workflow.routes_generic_runner import GenericRunService
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


def _cand(
    idx: int,
    asi_code: str,
    *,
    prompt: str | None = None,
    context_basis: list[str] | None = None,
    strategy_tag: str | None = None,
) -> dict[str, Any]:
    return {
        "prompt": prompt or f"Chunked {asi_code} security probe #{idx + 1} checking boundary enforcement.",
        "description": f"Security boundary testcase #{idx + 1} for {asi_code}.",
        "strategy_tag": strategy_tag or f"chunk_strategy_{idx + 1}",
        "context_basis": context_basis or ["purpose", "trust_boundaries"],
        "scope_note": "Descriptive metadata only; backend readiness owns scope.",
    }


def _chunk_payload(asi_code: str, candidates: list[dict[str, Any]], *, context_gaps: list[str] | None = None) -> str:
    return json.dumps(
        {
            "schema_version": "1.0",
            "asi_category": asi_code,
            "context_gaps": context_gaps or [],
            "candidates": candidates,
        },
        ensure_ascii=False,
    )


def _setup_service_env(
    tmp_path: Path,
    *,
    with_context: bool = True,
    endpoint: str = "http://127.0.0.1:19991/v1/chat/completions",
):
    catalog = ManagedTargetCatalog(
        CatalogConfig(catalog_schema_version="1.0.0", policy_ref="chunk-p2-policy", targets=[]),
        tmp_path / "operator",
        local_single_user=True,
    )
    saved = catalog.save_profile(
        SaveProfile(
            profile=ManagedProfile(
                id="chunk-target",
                name="Chunk Target",
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
    if with_context:
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
                    target_id="chunk-target",
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
                target_id="chunk-target",
                category=cat,
                evaluation_scope=scope,
                prohibited_behavior="Violate declared security boundaries or impersonate privileged roles.",
                allowed_benign_context="Politely refuse and provide safe FAQ guidance.",
                expected_response_boundary="Refuse unauthorized requests cleanly.",
            )
        )
        rev = policy_store.review(draft.policy_id, expected_revision_sha256=draft.revision_sha256, reviewer="qa")
        policies_by_asi[asi] = rev.policy_id

    return {
        "catalog": catalog,
        "app_ctx": app_ctx,
        "policy_store": policy_store,
        "policies_by_asi": policies_by_asi,
        "target_rev": reviewed["profile_revision"],
    }


def _setup_app(tmp_path: Path, *, endpoint: str, provider: MockGeneratorProvider):
    base = _setup_service_env(tmp_path, endpoint=endpoint)
    repo = DatasetRepository(tmp_path / "operator")
    locks = TargetExecutionLockRegistry()
    judge = _PassJudge()
    grs = GenericRunService(
        catalog=base["catalog"],
        dataset_repo=repo,
        policy_store=base["policy_store"],
        runs_root=tmp_path / "generic-runs",
        application_contexts=base["app_ctx"],
        judge_provider=judge,
        target_lock_registry=locks,
    )
    token = secrets.token_urlsafe(48)
    app = create_app(
        base["catalog"],
        operator_secret=token,
        local_single_user=True,
        dataset_repository=repo,
        generic_run_service=grs,
        generator_provider=provider,
    )
    client = app.test_client()
    nonce = client.get("/api/testing/health", headers={"Host": HOST}).get_json()["validation_nonce"]
    return {
        **base,
        "client": client,
        "nonce": nonce,
        "token": token,
        "repo": repo,
        "grs": grs,
        "judge": judge,
        "locks": locks,
        "workflows_root": tmp_path / "generator-workflows",
    }


def _headers(nonce: str, token: str, *, session: str = "op-chunk", post: bool = True) -> dict[str, str]:
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


# =============================================================================
# A. Chunk Planner Boundaries & Constants
# =============================================================================


@pytest.mark.parametrize(
    ("requested", "expected"),
    [
        (1, (1,)),
        (5, (5,)),
        (15, (15,)),
        (16, (15, 1)),
        (20, (15, 5)),
        (30, (15, 15)),
        (31, (15, 15, 1)),
        (45, (15, 15, 15)),
        (46, (15, 15, 15, 1)),
        (50, (15, 15, 15, 5)),
    ],
)
def test_a_chunk_planner_boundaries(requested: int, expected: tuple[int, ...]) -> None:
    assert DEFAULT_GENERATION_CHUNK_SIZE == 15
    assert MAX_PLANNED_CHUNKS_PER_ASI == 4
    assert MAX_TOTAL_PROVIDER_CALLS_PER_ASI == 5
    assert MAX_GENERATION_TOTAL_PROVIDER_CALLS == 8
    assert MAX_GENERATION_OUTPUT_TOKEN_BUDGET == 32768

    plan = plan_asi_chunks(requested)
    assert plan == expected
    assert sum(plan) == requested
    assert 1 <= len(plan) <= MAX_PLANNED_CHUNKS_PER_ASI
    assert all(1 <= chunk <= DEFAULT_GENERATION_CHUNK_SIZE for chunk in plan)


@pytest.mark.parametrize("bad_count", [0, -1, 51, 100, True, False, "15"])
def test_a_chunk_planner_rejects_invalid_counts(bad_count: Any) -> None:
    with pytest.raises(ValueError):
        plan_asi_chunks(bad_count)


# =============================================================================
# B. 50/50 Success & Off-By-One Excess Guard
# =============================================================================


def test_b_fifty_of_fifty_bounded_chunking_success_and_no_prompt_echo(tmp_path: Path) -> None:
    env = _setup_service_env(tmp_path)
    provider = MockGeneratorProvider(mode="success")
    svc = GeneratorService(
        catalog=env["catalog"],
        application_contexts=env["app_ctx"],
        provider=provider,
        policy_store=env["policy_store"],
    )

    res = svc.generate(
        GenerationServiceRequest(
            target_id="chunk-target",
            counts_by_asi={"ASI05": 50},
            policy_ids_by_asi={"ASI05": env["policies_by_asi"]["ASI05"]},
        ),
        generation_id="gen-chunk50ok01",
    )

    assert res.overall_status == "completed"
    assert res.meets_requested_counts is True
    assert res.total_requested == 50
    assert res.total_generated == 50
    assert res.total_accepted == 50
    assert res.total_rejected == 0
    assert res.total_call_count == 4
    assert provider.total_calls == 4
    # 7068*3 + 2868 = 24072 <= 32768
    assert res.authorized_output_token_budget == 32768
    assert res.allocated_output_tokens == 24072
    assert res.token_usage_unreported_calls == 0

    asi5 = res.asi_results["ASI05"]
    assert asi5.status == "completed"
    assert asi5.chunking_used is True
    assert asi5.planned_chunk_count == 4
    assert asi5.executed_chunk_count == 4
    assert asi5.completed_chunk_count == 4
    assert asi5.call_count == 4
    assert [cs.requested_count for cs in asi5.chunk_summaries] == [15, 15, 15, 5]
    assert [cs.accepted_count for cs in asi5.chunk_summaries] == [15, 15, 15, 5]
    assert [cs.chunk_index for cs in asi5.chunk_summaries] == [1, 2, 3, 4]
    assert [cs.call_count for cs in asi5.chunk_summaries] == [1, 1, 1, 1]

    # Unique IDs and monotonic source_index 0..49
    cand_ids = [c.candidate_id for c in res.accepted_candidates]
    src_indices = [c.source_index for c in res.accepted_candidates]
    assert len(set(cand_ids)) == 50
    assert src_indices == list(range(50))
    assert cand_ids[0] == "gen-chunk50ok01:asi05:001"
    assert cand_ids[-1] == "gen-chunk50ok01:asi05:050"

    # Per-chunk token budget fits <= 7068 <= 8192 and raw prompts are NEVER echoed to later chunks
    assert [r.requested_count for r in provider.received_requests] == [15, 15, 15, 5]
    assert [r.max_tokens for r in provider.received_requests] == [7068, 7068, 7068, 2868]
    chunk2_payload = json.loads(provider.received_requests[1].user_payload_json)
    assert chunk2_payload["generation_parameters"]["chunk_index"] == 2
    assert chunk2_payload["generation_parameters"]["total_chunks"] == 4
    assert "prior_chunk_strategy_tags" in chunk2_payload["generation_parameters"]
    assert "boundary probe #1]" not in provider.received_requests[1].user_payload_json


def test_b_last_chunk_five_excess_candidate_rejected_not_silently_truncated(tmp_path: Path) -> None:
    """Off-by-one guard: if final chunk (requested=5) returns 6 valid candidates, #6 is explicitly rejected."""
    env = _setup_service_env(tmp_path)
    fixtures = [
        MockFixtureResponse(mode="success", raw_text=_chunk_payload("ASI05", [_cand(i, "ASI05") for i in range(0, 15)])),
        MockFixtureResponse(mode="success", raw_text=_chunk_payload("ASI05", [_cand(i, "ASI05") for i in range(15, 30)])),
        MockFixtureResponse(mode="success", raw_text=_chunk_payload("ASI05", [_cand(i, "ASI05") for i in range(30, 45)])),
        MockFixtureResponse(mode="success", raw_text=_chunk_payload("ASI05", [_cand(i, "ASI05") for i in range(45, 51)])),
    ]
    provider = MockGeneratorProvider(fixtures=fixtures)
    svc = GeneratorService(
        catalog=env["catalog"],
        application_contexts=env["app_ctx"],
        provider=provider,
        policy_store=env["policy_store"],
    )

    res = svc.generate(
        GenerationServiceRequest(
            target_id="chunk-target",
            counts_by_asi={"ASI05": 50},
            policy_ids_by_asi={"ASI05": env["policies_by_asi"]["ASI05"]},
        )
    )
    asi5 = res.asi_results["ASI05"]
    assert res.overall_status == "completed"
    assert res.total_generated == 51
    assert res.total_accepted == 50
    assert res.total_rejected == 1
    assert asi5.rejection_reason_counts == {"exceeds_requested_count": 1}
    assert asi5.rejected_candidates[0].source_index == 50
    assert asi5.chunk_summaries[3].generated_count == 6
    assert asi5.chunk_summaries[3].accepted_count == 5
    assert asi5.chunk_summaries[3].rejected_count == 1


# =============================================================================
# C. Duplicate Across Chunks
# =============================================================================


def test_c_cross_chunk_dedup_rejects_duplicate_and_points_to_chunk1_source(tmp_path: Path) -> None:
    env = _setup_service_env(tmp_path)
    chunk1 = [_cand(i, "ASI03") for i in range(15)]
    # Chunk 2 duplicates chunk 1's index 2 (exact) and index 5 (NFKC/whitespace variant)
    chunk2 = [
        _cand(15, "ASI03", prompt=chunk1[2]["prompt"]),
        _cand(16, "ASI03", prompt="  " + chunk1[5]["prompt"].replace(" ", "   ") + "  "),
        _cand(17, "ASI03"),
        _cand(18, "ASI03"),
        _cand(19, "ASI03"),
    ]
    provider = MockGeneratorProvider(
        fixtures=[
            MockFixtureResponse(mode="success", raw_text=_chunk_payload("ASI03", chunk1)),
            MockFixtureResponse(mode="success", raw_text=_chunk_payload("ASI03", chunk2)),
        ]
    )
    svc = GeneratorService(
        catalog=env["catalog"],
        application_contexts=env["app_ctx"],
        provider=provider,
        policy_store=env["policy_store"],
    )

    res = svc.generate(
        GenerationServiceRequest(
            target_id="chunk-target",
            counts_by_asi={"ASI03": 20},
            policy_ids_by_asi={"ASI03": env["policies_by_asi"]["ASI03"]},
        ),
        generation_id="gen-dedupchunk01",
    )

    asi3 = res.asi_results["ASI03"]
    assert res.overall_status == "partial"
    assert res.meets_requested_counts is False
    assert asi3.status == "partial"
    assert asi3.requested_count == 20
    assert asi3.generated_count == 20
    assert asi3.accepted_count == 18
    assert asi3.rejected_count == 2
    assert asi3.duplicate_rejected_count == 2
    assert asi3.rejection_reason_counts == {"duplicate_within_asi": 2}

    rej0, rej1 = asi3.rejected_candidates
    assert rej0.source_index == 15
    assert rej0.reason_code == "duplicate_within_asi"
    assert rej0.duplicate_of_asi_code == "ASI03"
    assert rej0.duplicate_of_source_index == 2
    assert rej0.duplicate_of_candidate_id == "gen-dedupchunk01:asi03:003"

    assert rej1.source_index == 16
    assert rej1.reason_code == "duplicate_within_asi"
    assert rej1.duplicate_of_source_index == 5
    assert rej1.duplicate_of_candidate_id == "gen-dedupchunk01:asi03:006"


# =============================================================================
# D. Partial Generation (42/50) Across Generate Only & Generate & Run
# =============================================================================


def test_d_partial_42_of_50_generate_only_and_generate_and_run_fail_closed(tmp_path: Path) -> None:
    target_calls: list[str] = []
    server, endpoint = _start_stub_chat_server(target_calls)
    try:
        # 50 raw generated across 4 chunks -> 42 accepted, 8 rejected (5 invalid context_basis + 3 cross-chunk dups)
        c1 = [_cand(i, "ASI03") for i in range(15)]  # 15 valid
        c2 = (
            [_cand(i, "ASI03") for i in range(15, 27)]  # 12 valid
            + [_cand(i, "ASI03", prompt=c1[i - 27]["prompt"]) for i in range(27, 30)]  # 3 cross-chunk dups
        )
        c3 = (
            [_cand(i, "ASI03") for i in range(30, 40)]  # 10 valid
            + [_cand(i, "ASI03", context_basis=["domain_industry"]) for i in range(40, 45)]  # 5 missing_context_basis
        )
        c4 = [_cand(i, "ASI03") for i in range(45, 50)]  # 5 valid -> total 15+12+10+5 = 42

        def _make_provider() -> MockGeneratorProvider:
            return MockGeneratorProvider(
                fixtures=[
                    MockFixtureResponse(mode="success", raw_text=_chunk_payload("ASI03", c1)),
                    MockFixtureResponse(mode="success", raw_text=_chunk_payload("ASI03", c2)),
                    MockFixtureResponse(mode="success", raw_text=_chunk_payload("ASI03", c3)),
                    MockFixtureResponse(mode="success", raw_text=_chunk_payload("ASI03", c4)),
                ]
            )

        # 1. Generate Only -> preview shows 42/50 partial; save blocked without partial_save_confirmed=True
        env_go = _setup_app(tmp_path / "go", endpoint=endpoint, provider=_make_provider())
        r_gen = env_go["client"].post(
            "/api/testing/generator/generate",
            headers=_headers(env_go["nonce"], env_go["token"]),
            data=json.dumps(
                {
                    "target_id": "chunk-target",
                    "counts_by_asi": {"ASI03": 50},
                    "policy_ids_by_asi": {"ASI03": env_go["policies_by_asi"]["ASI03"]},
                }
            ),
        )
        assert r_gen.status_code == 201, r_gen.text
        preview = r_gen.get_json()["preview"]
        assert preview["overall_status"] == "partial"
        assert preview["meets_requested_counts"] is False
        assert preview["requires_partial_confirmation"] is True
        assert preview["total_requested"] == 50
        assert preview["total_generated"] == 50
        assert preview["total_accepted"] == 42
        assert preview["total_rejected"] == 8
        assert preview["total_call_count"] == 4
        assert preview["asi_summaries"]["ASI03"]["chunking_used"] is True
        assert preview["asi_summaries"]["ASI03"]["planned_chunk_count"] == 4
        assert preview["asi_summaries"]["ASI03"]["executed_chunk_count"] == 4
        assert preview["asi_summaries"]["ASI03"]["completed_chunk_count"] == 4

        # Save without partial_save_confirmed -> 409 fail-closed
        r_save_deny = env_go["client"].post(
            f"/api/testing/generator/previews/{preview['preview_id']}/save",
            headers=_headers(env_go["nonce"], env_go["token"]),
            data=json.dumps({"dataset_name": "partial-42", "save_confirmed": True, "partial_save_confirmed": False}),
        )
        assert r_save_deny.status_code == 409
        assert r_save_deny.get_json()["error"]["code"] == "partial_save_confirmation_required"

        # Save with explicit partial_save_confirmed=True -> 201
        r_save_ok = env_go["client"].post(
            f"/api/testing/generator/previews/{preview['preview_id']}/save",
            headers=_headers(env_go["nonce"], env_go["token"]),
            data=json.dumps({"dataset_name": "partial-42", "save_confirmed": True, "partial_save_confirmed": True}),
        )
        assert r_save_ok.status_code == 201, r_save_ok.text
        assert r_save_ok.get_json()["save_record"]["saved_count"] == 42

        # 2. Generate & Run with allow_partial_execution=False -> partial_stopped, 0 target/Judge calls
        env_gnr = _setup_app(tmp_path / "gnr", endpoint=endpoint, provider=_make_provider())
        r_wf = env_gnr["client"].post(
            "/api/testing/generator/generate-and-run",
            headers=_headers(env_gnr["nonce"], env_gnr["token"]),
            data=json.dumps(
                {
                    "target_id": "chunk-target",
                    "counts_by_asi": {"ASI03": 50},
                    "evaluation_mode": "hybrid",
                    "execution_mode": "live",
                    "authorization_confirmed": True,
                    "allow_partial_execution": False,
                    "policy_ids_by_asi": {"ASI03": env_gnr["policies_by_asi"]["ASI03"]},
                    "async_execution": False,
                    "expected_target_revision": env_gnr["target_rev"],
                }
            ),
        )
        assert r_wf.status_code == 201, r_wf.text
        wf = r_wf.get_json()["workflow"]
        assert wf["status"] == "partial_stopped"
        assert wf["error_code"] == "partial_generation_not_executed"
        assert wf["requested_count"] == 50
        assert wf["accepted_count"] == 42
        assert wf["rejected_count"] == 8
        assert wf["auto_persisted"] is False
        assert target_calls == []
        assert env_gnr["judge"].calls == []
        assert env_gnr["locks"].list_reservations() == []
    finally:
        server.shutdown()
        server.server_close()


# =============================================================================
# E. Provider Failures, Bounded Retry (Zero Amplification) & Token Honesty
# =============================================================================


@pytest.mark.parametrize(
    ("error_fixture", "expected_cat"),
    [
        (MockFixtureResponse(mode="timeout"), ProviderErrorCategory.TIMEOUT),
        (
            MockFixtureResponse(
                mode="provider_error",
                error_category=ProviderErrorCategory.NETWORK_ERROR,
                error_message="Connection reset.",
            ),
            ProviderErrorCategory.NETWORK_ERROR,
        ),
        (
            MockFixtureResponse(
                mode="provider_error",
                error_category=ProviderErrorCategory.RATE_LIMITED,
                error_message="HTTP 429 rate limited.",
                http_status=429,
            ),
            ProviderErrorCategory.RATE_LIMITED,
        ),
        (
            MockFixtureResponse(
                mode="provider_error",
                error_category=ProviderErrorCategory.HTTP_ERROR,
                error_message="HTTP 503 service unavailable.",
                http_status=503,
            ),
            ProviderErrorCategory.HTTP_ERROR,
        ),
    ],
)
def test_e_transient_retry_bounded_to_one_across_entire_asi_no_amplification(
    tmp_path: Path,
    error_fixture: MockFixtureResponse,
    expected_cat: ProviderErrorCategory,
) -> None:
    """When max_calls_per_asi=2, at most 1 retry is allowed across the ENTIRE ASI (total calls <= 5).
    If Chunk 2 retries and succeeds (consuming the single ASI retry), and Chunk 3 also fails transiently,
    Chunk 3 MUST NOT retry -> total calls == 4 (1+2+1), Chunk 4 NOT called, 30 accepted preserved as partial."""
    env = _setup_service_env(tmp_path)
    provider = MockGeneratorProvider(
        fixtures=[
            MockFixtureResponse(mode="success", raw_text=_chunk_payload("ASI05", [_cand(i, "ASI05") for i in range(0, 15)])),
            error_fixture,  # Chunk 2 attempt 1 -> fails transiently
            MockFixtureResponse(mode="success", raw_text=_chunk_payload("ASI05", [_cand(i, "ASI05") for i in range(15, 30)])),  # Chunk 2 retry succeeds!
            error_fixture,  # Chunk 3 attempt 1 -> fails transiently, NO retry budget left!
            MockFixtureResponse(mode="success", raw_text=_chunk_payload("ASI05", [_cand(i, "ASI05") for i in range(30, 45)])),  # MUST NOT BE CALLED
        ]
    )
    svc = GeneratorService(
        catalog=env["catalog"],
        application_contexts=env["app_ctx"],
        provider=provider,
        policy_store=env["policy_store"],
    )

    res = svc.generate(
        GenerationServiceRequest(
            target_id="chunk-target",
            counts_by_asi={"ASI05": 50},
            policy_ids_by_asi={"ASI05": env["policies_by_asi"]["ASI05"]},
            max_calls_per_asi=2,
        )
    )

    asi5 = res.asi_results["ASI05"]
    assert res.overall_status == "partial"
    assert res.meets_requested_counts is False
    assert asi5.status == "partial"
    assert asi5.accepted_count == 30
    assert asi5.call_count == 4  # 1 (c1) + 2 (c2 + 1 retry) + 1 (c3, no 2nd retry)
    assert asi5.call_count <= MAX_TOTAL_PROVIDER_CALLS_PER_ASI
    assert provider.total_calls == 4
    assert asi5.planned_chunk_count == 4
    assert asi5.executed_chunk_count == 3
    assert asi5.completed_chunk_count == 2
    assert asi5.provider_error_category == expected_cat
    assert asi5.chunk_summaries[1].call_count == 2
    assert asi5.chunk_summaries[2].call_count == 1
    assert asi5.chunk_summaries[2].status == "provider_error"


def test_e_single_retry_succeeds_all_4_chunks_total_5_calls_50_accepted(tmp_path: Path) -> None:
    """50/50 with 1 transient timeout on Chunk 2 + max_calls_per_asi=2 -> succeeds in exactly 5 calls."""
    env = _setup_service_env(tmp_path)
    provider = MockGeneratorProvider(
        fixtures=[
            MockFixtureResponse(mode="success", raw_text=_chunk_payload("ASI05", [_cand(i, "ASI05") for i in range(0, 15)])),
            MockFixtureResponse(mode="timeout"),
            MockFixtureResponse(mode="success", raw_text=_chunk_payload("ASI05", [_cand(i, "ASI05") for i in range(15, 30)])),
            MockFixtureResponse(mode="success", raw_text=_chunk_payload("ASI05", [_cand(i, "ASI05") for i in range(30, 45)])),
            MockFixtureResponse(mode="success", raw_text=_chunk_payload("ASI05", [_cand(i, "ASI05") for i in range(45, 50)])),
        ]
    )
    svc = GeneratorService(
        catalog=env["catalog"],
        application_contexts=env["app_ctx"],
        provider=provider,
        policy_store=env["policy_store"],
    )

    res = svc.generate(
        GenerationServiceRequest(
            target_id="chunk-target",
            counts_by_asi={"ASI05": 50},
            policy_ids_by_asi={"ASI05": env["policies_by_asi"]["ASI05"]},
            max_calls_per_asi=2,
        )
    )
    assert res.overall_status == "completed"
    assert res.total_accepted == 50
    assert res.total_call_count == 5
    assert res.asi_results["ASI05"].call_count == 5
    # 7068*4 + 2868 = 31140 <= 32768
    assert res.allocated_output_tokens == 31140
    assert res.allocated_output_tokens <= MAX_GENERATION_OUTPUT_TOKEN_BUDGET


@pytest.mark.parametrize(
    ("fixture", "expected_status", "expected_calls"),
    [
        (MockFixtureResponse(mode="credential_unavailable"), "provider_error", 0),
        (
            MockFixtureResponse(
                mode="provider_error",
                error_category=ProviderErrorCategory.AUTH_REJECTED,
                error_message="Invalid DeepSeek API key (HTTP 401).",
                http_status=401,
            ),
            "provider_error",
            1,
        ),
        (
            MockFixtureResponse(
                mode="provider_error",
                error_category=ProviderErrorCategory.MODEL_REJECTED,
                error_message="Unknown model (HTTP 404).",
                http_status=404,
            ),
            "provider_error",
            1,
        ),
        (MockFixtureResponse(mode="truncated_response"), "truncated", 1),
        (MockFixtureResponse(mode="invalid_json"), "invalid_output", 1),
    ],
)
def test_e_non_retryable_failures_fail_fast_chunk1_no_wasted_chunks(
    tmp_path: Path,
    fixture: MockFixtureResponse,
    expected_status: str,
    expected_calls: int,
) -> None:
    """Permanent/non-retryable errors on Chunk 1 stop immediately even with max_calls_per_asi=2."""
    env = _setup_service_env(tmp_path)
    provider = MockGeneratorProvider(
        fixtures=[fixture, MockFixtureResponse(mode="success")],
        credential_available=(fixture.mode != "credential_unavailable"),
    )
    svc = GeneratorService(
        catalog=env["catalog"],
        application_contexts=env["app_ctx"],
        provider=provider,
        policy_store=env["policy_store"],
    )

    res = svc.generate(
        GenerationServiceRequest(
            target_id="chunk-target",
            counts_by_asi={"ASI05": 50},
            policy_ids_by_asi={"ASI05": env["policies_by_asi"]["ASI05"]},
            max_calls_per_asi=2,
        )
    )

    asi5 = res.asi_results["ASI05"]
    assert res.overall_status == "failed"
    assert res.total_accepted == 0
    assert asi5.status == expected_status
    assert asi5.call_count == expected_calls
    assert provider.total_calls == expected_calls
    assert asi5.attempted_chunk_count == 1
    assert asi5.executed_chunk_count == (1 if expected_calls > 0 else 0)
    assert asi5.completed_chunk_count == 0
    assert asi5.chunk_summaries[0].dispatched is (expected_calls > 0)
    assert asi5.chunk_summaries[0].blocked_before_dispatch is (expected_calls == 0)
    if expected_calls == 0:
        assert asi5.sanitized_request_sha256 is None
        assert asi5.dispatched_request_sha256s == ()
        assert asi5.provenance_inputs is None
    else:
        assert asi5.sanitized_request_sha256 is not None
        assert len(asi5.dispatched_request_sha256s) == 1


def test_e_mid_chunk_truncation_and_invalid_json_preserve_prior_accepted_as_partial(tmp_path: Path) -> None:
    env = _setup_service_env(tmp_path)
    for bad_mode, expected_err in (("truncated_response", "truncated_output"), ("invalid_json", "malformed_json")):
        provider = MockGeneratorProvider(
            fixtures=[
                MockFixtureResponse(mode="success", raw_text=_chunk_payload("ASI03", [_cand(i, "ASI03") for i in range(0, 15)])),
                MockFixtureResponse(mode="success", raw_text=_chunk_payload("ASI03", [_cand(i, "ASI03") for i in range(15, 30)])),
                MockFixtureResponse(mode=bad_mode),
                MockFixtureResponse(mode="success"),  # MUST NOT BE CALLED
            ]
        )
        svc = GeneratorService(
            catalog=env["catalog"],
            application_contexts=env["app_ctx"],
            provider=provider,
            policy_store=env["policy_store"],
        )
        res = svc.generate(
            GenerationServiceRequest(
                target_id="chunk-target",
                counts_by_asi={"ASI03": 50},
                policy_ids_by_asi={"ASI03": env["policies_by_asi"]["ASI03"]},
            )
        )
        asi3 = res.asi_results["ASI03"]
        assert res.overall_status == "partial"
        assert asi3.status == "partial"
        assert asi3.accepted_count == 30
        assert asi3.error_code == expected_err
        assert asi3.executed_chunk_count == 3
        assert asi3.completed_chunk_count == 2
        assert provider.total_calls == 3


def test_e_null_token_usage_never_fabricated_and_allocated_budget_tracked(tmp_path: Path) -> None:
    """When provider omits token_usage (None), total_token_usage MUST remain None (never fabricated as 0)."""
    env = _setup_service_env(tmp_path)
    call_idx = 0

    def _null_usage_handler(req: ProviderGenerationRequest) -> ProviderGenerationResponse:
        nonlocal call_idx
        start = call_idx * 15
        call_idx += 1
        return ProviderGenerationResponse(
            provider_id="mock",
            model="mock-null-usage",
            ok=True,
            raw_text=_chunk_payload("ASI05", [_cand(i, "ASI05") for i in range(start, start + req.requested_count)]),
            finish_reason="stop",
            token_usage=None,
            duration_ms=4.0,
            call_count=1,
            http_status=200,
        )

    provider = MockGeneratorProvider(handler=_null_usage_handler)
    svc = GeneratorService(
        catalog=env["catalog"],
        application_contexts=env["app_ctx"],
        provider=provider,
        policy_store=env["policy_store"],
    )
    res = svc.generate(
        GenerationServiceRequest(
            target_id="chunk-target",
            counts_by_asi={"ASI05": 50},
            policy_ids_by_asi={"ASI05": env["policies_by_asi"]["ASI05"]},
        )
    )
    assert res.overall_status == "completed"
    assert res.total_accepted == 50
    assert res.total_token_usage is None
    assert res.asi_results["ASI05"].token_usage is None
    assert all(cs.token_usage is None for cs in res.asi_results["ASI05"].chunk_summaries)
    assert res.token_usage_unreported_calls == 4
    assert res.allocated_output_tokens == 24072


def test_e_multi_asi_output_token_budget_32768_fails_closed_before_overbudget_call(tmp_path: Path) -> None:
    """Multi-ASI request [16, 16, 16, 2] (7 planned chunks = 26,376 allocated) + transient retry on ASI01
    chunk 1 (+7,068 -> 33,444 > 32,768) stops fail-closed BEFORE dispatching the over-budget final chunk."""
    env = _setup_service_env(tmp_path)
    fixtures = [
        MockFixtureResponse(mode="timeout"),  # ASI01 c1 attempt 1 (7068 allocated)
        MockFixtureResponse(mode="success", raw_text=_chunk_payload("ASI01", [_cand(i, "ASI01") for i in range(15)])),  # ASI01 c1 retry (14136)
        MockFixtureResponse(mode="success", raw_text=_chunk_payload("ASI01", [_cand(15, "ASI01")])),  # ASI01 c2 (15324)
        MockFixtureResponse(mode="success", raw_text=_chunk_payload("ASI02", [_cand(i, "ASI02") for i in range(15)])),  # ASI02 c1 (22392)
        MockFixtureResponse(mode="success", raw_text=_chunk_payload("ASI02", [_cand(15, "ASI02")])),  # ASI02 c2 (23580)
        MockFixtureResponse(mode="success", raw_text=_chunk_payload("ASI03", [_cand(i, "ASI03") for i in range(15)])),  # ASI03 c1 (30648)
        MockFixtureResponse(mode="success", raw_text=_chunk_payload("ASI03", [_cand(15, "ASI03")])),  # ASI03 c2 (31836)
        MockFixtureResponse(mode="success", raw_text=_chunk_payload("ASI05", [_cand(i, "ASI05") for i in range(2)])),  # ASI05 c1 would be 31836+1608=33444 > 32768 -> BLOCKED!
    ]
    provider = MockGeneratorProvider(fixtures=fixtures)
    svc = GeneratorService(
        catalog=env["catalog"],
        application_contexts=env["app_ctx"],
        provider=provider,
        policy_store=env["policy_store"],
    )

    res = svc.generate(
        GenerationServiceRequest(
            target_id="chunk-target",
            counts_by_asi={"ASI01": 16, "ASI02": 16, "ASI03": 16, "ASI05": 2},
            policy_ids_by_asi=env["policies_by_asi"],
            max_calls_per_asi=2,
        )
    )
    assert res.overall_status == "partial"
    assert res.total_requested == 50
    assert res.total_accepted == 48
    assert res.total_call_count == 7
    assert res.allocated_output_tokens == 31836
    assert res.allocated_output_tokens <= MAX_GENERATION_OUTPUT_TOKEN_BUDGET
    assert provider.total_calls == 7  # 8th call (ASI05) was NOT dispatched!

    # R1: ASI01 had 2 planned chunks, 1 transient retry on chunk 1 -> 3 physical calls, 2 dispatched chunks
    asi1 = res.asi_results["ASI01"]
    assert asi1.call_count == 3
    assert asi1.planned_chunk_count == 2
    assert asi1.attempted_chunk_count == 2
    assert asi1.executed_chunk_count == 2
    assert asi1.completed_chunk_count == 2
    assert asi1.budget_blocked_chunk_count == 0
    assert asi1.chunk_summaries[0].call_count == 2
    assert asi1.chunk_summaries[0].dispatched is True
    assert asi1.chunk_summaries[0].blocked_before_dispatch is False
    assert asi1.chunk_summaries[0].sanitized_request_sha256 is not None
    assert len(asi1.dispatched_request_sha256s) == 2
    assert asi1.sanitized_request_sha256 == sha256(
        "|".join(asi1.dispatched_request_sha256s).encode("utf-8")
    ).hexdigest()

    # R1: ASI05 was budget-blocked before dispatch -> 0 physical calls, executed_chunk_count=0,
    # diagnostic summary preserved, composite dispatched provenance is None
    asi5 = res.asi_results["ASI05"]
    assert asi5.status == "provider_error"
    assert asi5.error_code == "generation_output_token_budget_exceeded"
    assert asi5.call_count == 0
    assert asi5.planned_chunk_count == 1
    assert asi5.attempted_chunk_count == 1
    assert asi5.executed_chunk_count == 0
    assert asi5.completed_chunk_count == 0
    assert asi5.budget_blocked_chunk_count == 1
    assert asi5.dispatched_request_sha256s == ()
    assert asi5.sanitized_request_sha256 is None
    assert asi5.provenance_inputs is None
    assert len(asi5.chunk_summaries) == 1
    blocked_summary = asi5.chunk_summaries[0]
    assert blocked_summary.dispatched is False
    assert blocked_summary.blocked_before_dispatch is True
    assert blocked_summary.call_count == 0
    assert blocked_summary.error_code == "generation_output_token_budget_exceeded"
    assert blocked_summary.sanitized_request_sha256 is not None  # prepared hash retained in diagnostic only


def test_r2_last_chunk_excess_candidate_6_and_duplicate_candidate_7_reference_semantics(tmp_path: Path) -> None:
    """R2: Last chunk requests 5, provider returns 7 (#6 unique excess, #7 duplicate of #6).
    Verify #6 is rejected as exceeds_requested_count, #7 is rejected as duplicate_within_asi
    with duplicate_of_source_index=50 and duplicate_of_candidate_id=None (never a bogus ID)."""
    env = _setup_service_env(tmp_path)
    overflow_prompt = "Overflow unique security boundary probe #6 beyond final chunk cap."
    c4_seven = [
        *[_cand(i, "ASI05") for i in range(45, 50)],  # 5 accepted (source_index 45..49)
        _cand(50, "ASI05", prompt=overflow_prompt),  # #6 excess (source_index 50)
        _cand(51, "ASI05", prompt=overflow_prompt),  # #7 duplicate of #6 (source_index 51)
    ]
    provider = MockGeneratorProvider(
        fixtures=[
            MockFixtureResponse(mode="success", raw_text=_chunk_payload("ASI05", [_cand(i, "ASI05") for i in range(0, 15)])),
            MockFixtureResponse(mode="success", raw_text=_chunk_payload("ASI05", [_cand(i, "ASI05") for i in range(15, 30)])),
            MockFixtureResponse(mode="success", raw_text=_chunk_payload("ASI05", [_cand(i, "ASI05") for i in range(30, 45)])),
            MockFixtureResponse(mode="success", raw_text=_chunk_payload("ASI05", c4_seven)),
        ]
    )
    svc = GeneratorService(
        catalog=env["catalog"],
        application_contexts=env["app_ctx"],
        provider=provider,
        policy_store=env["policy_store"],
    )

    res = svc.generate(
        GenerationServiceRequest(
            target_id="chunk-target",
            counts_by_asi={"ASI05": 50},
            policy_ids_by_asi={"ASI05": env["policies_by_asi"]["ASI05"]},
        ),
        generation_id="gen-r2excess001",
    )

    asi5 = res.asi_results["ASI05"]
    assert res.overall_status == "completed"
    assert res.meets_requested_counts is True
    assert asi5.generated_count == 52
    assert asi5.pre_dedup_valid_count == 52
    assert asi5.post_dedup_valid_count == 51
    assert asi5.accepted_count == 50
    assert asi5.rejected_count == 2
    assert asi5.duplicate_rejected_count == 1
    assert asi5.accepted_count + asi5.rejected_count == asi5.generated_count
    assert asi5.rejection_reason_counts == {
        "duplicate_within_asi": 1,
        "exceeds_requested_count": 1,
    }
    accepted_ids = {c.candidate_id for c in asi5.accepted_candidates}
    assert len(accepted_ids) == 50
    assert all(c.prompt != overflow_prompt for c in asi5.accepted_candidates)

    rej_6, rej_7 = asi5.rejected_candidates
    assert rej_6.source_index == 50
    assert rej_6.reason_code == "exceeds_requested_count"
    assert rej_6.duplicate_of_candidate_id is None

    assert rej_7.source_index == 51
    assert rej_7.reason_code == "duplicate_within_asi"
    assert rej_7.duplicate_of_asi_code == "ASI05"
    assert rej_7.duplicate_of_source_index == 50
    assert rej_7.duplicate_of_candidate_id is None
    assert "exceeds_requested_count" in rej_7.reason_message


def test_r3_saved_dataset_retains_compact_chunk_provenance_after_preview_expires(tmp_path: Path) -> None:
    """R3: Persisted dataset retains secret-free per-chunk & budget-blocked provenance after preview is gone,
    without modifying testcase/Judge schema or storing raw LLM output / secrets."""
    fixtures = [
        MockFixtureResponse(mode="timeout"),  # ASI01 c1 attempt 1
        MockFixtureResponse(mode="success", raw_text=_chunk_payload("ASI01", [_cand(i, "ASI01") for i in range(15)])),
        MockFixtureResponse(mode="success", raw_text=_chunk_payload("ASI01", [_cand(15, "ASI01")])),
        MockFixtureResponse(mode="success", raw_text=_chunk_payload("ASI02", [_cand(i, "ASI02") for i in range(15)])),
        MockFixtureResponse(mode="success", raw_text=_chunk_payload("ASI02", [_cand(15, "ASI02")])),
        MockFixtureResponse(mode="success", raw_text=_chunk_payload("ASI03", [_cand(i, "ASI03") for i in range(15)])),
        MockFixtureResponse(mode="success", raw_text=_chunk_payload("ASI03", [_cand(15, "ASI03")])),
        MockFixtureResponse(mode="success", raw_text=_chunk_payload("ASI05", [_cand(i, "ASI05") for i in range(2)])),
    ]
    provider = MockGeneratorProvider(fixtures=fixtures)
    env = _setup_app(tmp_path, endpoint="http://127.0.0.1:19991/v1/chat/completions", provider=provider)
    client, nonce, token = env["client"], env["nonce"], env["token"]

    r_gen = client.post(
        "/api/testing/generator/generate",
        headers=_headers(nonce, token),
        data=json.dumps(
            {
                "target_id": "chunk-target",
                "counts_by_asi": {"ASI01": 16, "ASI02": 16, "ASI03": 16, "ASI05": 2},
                "policy_ids_by_asi": env["policies_by_asi"],
                "max_calls_per_asi": 2,
            }
        ),
    )
    assert r_gen.status_code == 201, r_gen.text
    preview = r_gen.get_json()["preview"]
    assert preview["overall_status"] == "partial"
    assert preview["total_accepted"] == 48
    assert preview["total_call_count"] == 7
    assert preview["asi_summaries"]["ASI05"]["executed_chunk_count"] == 0
    assert preview["asi_summaries"]["ASI05"]["budget_blocked_chunk_count"] == 1

    r_save = client.post(
        f"/api/testing/generator/previews/{preview['preview_id']}/save",
        headers=_headers(nonce, token),
        data=json.dumps(
            {
                "dataset_name": "r3-chunk-provenance",
                "save_confirmed": True,
                "partial_save_confirmed": True,
            }
        ),
    )
    assert r_save.status_code == 201, r_save.text
    dataset_id = r_save.get_json()["save_record"]["dataset_id"]

    # Read persisted dataset directly from disk/repo (independent of in-memory preview lifecycle)
    ds = env["repo"].get_dataset(dataset_id)
    assert ds is not None
    assert ds.total_testcases == 48
    assert all(tc.assertions == [] for tc in ds.testcases)

    prov = ds.source_metadata["generation_provenance"]
    acct = prov["execution_accounting"]
    assert acct["total_call_count"] == 7
    assert acct["authorized_output_token_budget"] == 32768
    assert acct["allocated_output_tokens"] == 31836
    assert acct["asi_chunk_accounting"]["ASI01"]["call_count"] == 3
    assert acct["asi_chunk_accounting"]["ASI01"]["executed_chunk_count"] == 2
    assert acct["asi_chunk_accounting"]["ASI05"]["call_count"] == 0
    assert acct["asi_chunk_accounting"]["ASI05"]["executed_chunk_count"] == 0
    assert acct["asi_chunk_accounting"]["ASI05"]["budget_blocked_chunk_count"] == 1
    assert acct["asi_chunk_accounting"]["ASI05"]["sanitized_request_sha256"] is None
    assert acct["asi_chunk_accounting"]["ASI05"]["error_code"] == "generation_output_token_budget_exceeded"

    # Saved ASI skills include compact per-chunk summaries & dispatched request hashes
    asi1_skill = prov["asi_skills"]["ASI01"]
    assert asi1_skill["chunking_used"] is True
    assert asi1_skill["planned_chunk_count"] == 2
    assert asi1_skill["executed_chunk_count"] == 2
    assert len(asi1_skill["dispatched_request_sha256s"]) == 2
    assert len(asi1_skill["chunk_summaries"]) == 2
    assert asi1_skill["chunk_summaries"][0]["call_count"] == 2
    assert asi1_skill["chunk_summaries"][0]["dispatched"] is True

    # Zero raw LLM prompts or secret keys inside generation_provenance
    prov_json = json.dumps(prov)
    assert "Chunked ASI01 security probe" not in prov_json
    assert "DEEPSEEK_API_KEY" not in prov_json

    # G11.5 evaluate_persisted_dataset remains 100% compatible
    q_rep = evaluate_persisted_dataset(ds)
    assert q_rep.provenance_completeness.complete is True
    assert q_rep.overall_metrics.accepted_count == 48


# =============================================================================
# F. Deterministic Event-Gated G15 Stop/Cancel During Chunking
# =============================================================================


def test_f_cancel_before_chunk1_raises_run_cancelled_zero_calls(tmp_path: Path) -> None:
    env = _setup_service_env(tmp_path)
    provider = MockGeneratorProvider(mode="success")
    svc = GeneratorService(
        catalog=env["catalog"],
        application_contexts=env["app_ctx"],
        provider=provider,
        policy_store=env["policy_store"],
    )
    cancel_evt = threading.Event()
    cancel_evt.set()
    with pytest.raises(RunCancelledError):
        svc.generate(
            GenerationServiceRequest(
                target_id="chunk-target",
                counts_by_asi={"ASI05": 50},
                policy_ids_by_asi={"ASI05": env["policies_by_asi"]["ASI05"]},
            ),
            cancel_event=cancel_evt,
        )
    assert provider.total_calls == 0


def test_f_cancel_between_chunk1_and_chunk2_stops_cleanly_in_generate_and_run(tmp_path: Path) -> None:
    """Deterministic Event gate: Chunk 1 completes -> cancel requested -> Chunk 2..4 NEVER called,
    workflow ends 'cancelled' (not 'failed'), 0 datasets saved, 0 target/Judge calls, lock released."""
    target_calls: list[str] = []
    server, endpoint = _start_stub_chat_server(target_calls)
    try:
        chunk1_entered = threading.Event()
        release_chunk1 = threading.Event()
        calls_seen: list[str] = []

        def _gated_handler(req: ProviderGenerationRequest) -> ProviderGenerationResponse:
            calls_seen.append(req.request_id)
            if len(calls_seen) == 1:
                chunk1_entered.set()
                assert release_chunk1.wait(timeout=5.0), "Test gate timed out waiting for cancel"
            return ProviderGenerationResponse(
                provider_id="mock",
                model="mock-v1",
                ok=True,
                raw_text=_chunk_payload("ASI05", [_cand(i, "ASI05") for i in range(req.requested_count)]),
                finish_reason="stop",
                token_usage=TokenUsage(prompt_tokens=100, completion_tokens=500, total_tokens=600),
                duration_ms=5.0,
                call_count=1,
                http_status=200,
            )

        provider = MockGeneratorProvider(handler=_gated_handler)
        env = _setup_app(tmp_path, endpoint=endpoint, provider=provider)
        client, nonce, token = env["client"], env["nonce"], env["token"]

        r_start = client.post(
            "/api/testing/generator/generate-and-run",
            headers=_headers(nonce, token),
            data=json.dumps(
                {
                    "target_id": "chunk-target",
                    "counts_by_asi": {"ASI05": 50},
                    "evaluation_mode": "hybrid",
                    "execution_mode": "live",
                    "authorization_confirmed": True,
                    "policy_ids_by_asi": {"ASI05": env["policies_by_asi"]["ASI05"]},
                    "async_execution": True,
                    "expected_target_revision": env["target_rev"],
                }
            ),
        )
        assert r_start.status_code == 202, r_start.text
        wf_id = r_start.get_json()["workflow"]["workflow_id"]

        assert chunk1_entered.wait(timeout=5.0), "Chunk 1 did not start"

        r_cancel = client.post(
            f"/api/testing/generator/generate-and-run/{wf_id}/cancel",
            headers=_headers(nonce, token),
            data=json.dumps({}),
        )
        assert r_cancel.status_code == 202, r_cancel.text
        release_chunk1.set()

        # Poll deterministically via GET until terminal (no fixed sleep race)
        final_wf: dict[str, Any] = {}
        for _ in range(200):
            r_get = client.get(
                f"/api/testing/generator/generate-and-run/{wf_id}",
                headers=_headers(nonce, token, post=False),
            )
            final_wf = r_get.get_json()["workflow"]
            if final_wf["status"] in {"cancelled", "failed", "completed"}:
                break
            threading.Event().wait(0.01)

        assert final_wf["status"] == "cancelled", final_wf
        assert final_wf["error_code"] is None
        assert final_wf["dataset_id"] is None
        assert final_wf["auto_persisted"] is False
        assert len(calls_seen) == 1  # Chunks 2, 3, 4 NEVER dispatched!
        assert target_calls == []
        assert env["judge"].calls == []
        assert env["locks"].list_reservations() == []
        assert env["repo"].list_datasets() == []

        # Durable disk state reflects cancelled (G15 persistence)
        persisted = json.loads((env["workflows_root"] / f"{wf_id}.json").read_text(encoding="utf-8"))
        persisted_snap = persisted.get("snapshot", persisted)
        assert persisted_snap["status"] == "cancelled"
        assert persisted_snap["error_code"] is None

        # Idempotent second cancel returns already_cancelled
        r_cancel2 = client.post(
            f"/api/testing/generator/generate-and-run/{wf_id}/cancel",
            headers=_headers(nonce, token),
            data=json.dumps({}),
        )
        assert r_cancel2.status_code == 200
        assert r_cancel2.get_json()["cancel_outcome"] == "already_cancelled"
    finally:
        server.shutdown()
        server.server_close()


def test_f_cancel_during_chunk2_inflight_and_post_return_stops_before_chunk3(tmp_path: Path) -> None:
    """Chunk 1 succeeds -> Chunk 2 enters HTTP call -> Stop arrives while Chunk 2 is in-flight ->
    Chunk 2 returns valid 15 candidates after Stop -> post-call checkpoint aborts -> Chunk 3 & 4 NEVER called."""
    target_calls: list[str] = []
    server, endpoint = _start_stub_chat_server(target_calls)
    try:
        chunk2_inflight = threading.Event()
        allow_chunk2_return = threading.Event()
        calls_seen: list[int] = []

        def _handler(req: ProviderGenerationRequest) -> ProviderGenerationResponse:
            call_num = len(calls_seen) + 1
            calls_seen.append(call_num)
            if call_num == 2:
                chunk2_inflight.set()
                assert allow_chunk2_return.wait(timeout=5.0), "Timed out waiting for cancel during chunk 2"
            offset = (call_num - 1) * 15
            return ProviderGenerationResponse(
                provider_id="mock",
                model="mock-v1",
                ok=True,
                raw_text=_chunk_payload("ASI03", [_cand(offset + i, "ASI03") for i in range(req.requested_count)]),
                finish_reason="stop",
                token_usage=TokenUsage(prompt_tokens=100, completion_tokens=500, total_tokens=600),
                duration_ms=5.0,
                call_count=1,
                http_status=200,
            )

        provider = MockGeneratorProvider(handler=_handler)
        env = _setup_app(tmp_path, endpoint=endpoint, provider=provider)
        client, nonce, token = env["client"], env["nonce"], env["token"]

        r_start = client.post(
            "/api/testing/generator/generate-and-run",
            headers=_headers(nonce, token),
            data=json.dumps(
                {
                    "target_id": "chunk-target",
                    "counts_by_asi": {"ASI03": 50},
                    "evaluation_mode": "hybrid",
                    "execution_mode": "live",
                    "authorization_confirmed": True,
                    "policy_ids_by_asi": {"ASI03": env["policies_by_asi"]["ASI03"]},
                    "async_execution": True,
                    "expected_target_revision": env["target_rev"],
                }
            ),
        )
        assert r_start.status_code == 202
        wf_id = r_start.get_json()["workflow"]["workflow_id"]

        assert chunk2_inflight.wait(timeout=5.0), "Chunk 2 did not enter in-flight"
        r_cancel = client.post(
            f"/api/testing/generator/generate-and-run/{wf_id}/cancel",
            headers=_headers(nonce, token),
            data=json.dumps({}),
        )
        assert r_cancel.status_code == 202, r_cancel.text
        # Now let in-flight Chunk 2 finish and return valid payload AFTER cancel
        allow_chunk2_return.set()

        final_wf: dict[str, Any] = {}
        for _ in range(200):
            final_wf = client.get(
                f"/api/testing/generator/generate-and-run/{wf_id}",
                headers=_headers(nonce, token, post=False),
            ).get_json()["workflow"]
            if final_wf["status"] in {"cancelled", "failed", "completed"}:
                break
            threading.Event().wait(0.01)

        assert final_wf["status"] == "cancelled", final_wf
        assert final_wf["error_code"] is None
        assert calls_seen == [1, 2]  # Chunks 3 and 4 NEVER dispatched
        assert final_wf["dataset_id"] is None
        assert target_calls == []
        assert env["judge"].calls == []
        assert env["locks"].list_reservations() == []
    finally:
        server.shutdown()
        server.server_close()


def test_f_cancel_between_two_asis_skips_second_asi_completely(tmp_path: Path) -> None:
    """ASI03=20 + ASI05=20: Stop requested right as ASI03 chunk 2 finishes -> ASI05 gets 0 provider calls."""
    env = _setup_service_env(tmp_path)
    cancel_evt = threading.Event()
    called_asis: list[str] = []

    def _handler(req: ProviderGenerationRequest) -> ProviderGenerationResponse:
        called_asis.append(req.asi_code)
        offset = (len(called_asis) - 1) * 15
        if len(called_asis) == 2:
            # ASI03's 2nd (final) chunk returns just as operator triggers Stop -> ASI05 must NEVER run
            cancel_evt.set()
        return ProviderGenerationResponse(
            provider_id="mock",
            model="mock-v1",
            ok=True,
            raw_text=_chunk_payload(req.asi_code, [_cand(offset + i, req.asi_code) for i in range(req.requested_count)]),
            finish_reason="stop",
            token_usage=TokenUsage(prompt_tokens=100, completion_tokens=300, total_tokens=400),
            duration_ms=4.0,
            call_count=1,
            http_status=200,
        )

    provider = MockGeneratorProvider(handler=_handler)
    svc = GeneratorService(
        catalog=env["catalog"],
        application_contexts=env["app_ctx"],
        provider=provider,
        policy_store=env["policy_store"],
    )

    with pytest.raises(RunCancelledError):
        svc.generate(
            GenerationServiceRequest(
                target_id="chunk-target",
                counts_by_asi={"ASI03": 20, "ASI05": 20},
                policy_ids_by_asi={
                    "ASI03": env["policies_by_asi"]["ASI03"],
                    "ASI05": env["policies_by_asi"]["ASI05"],
                },
            ),
            cancel_event=cancel_evt,
        )
    assert called_asis == ["ASI03", "ASI03"]
    assert "ASI05" not in called_asis


# =============================================================================
# G. Backward Compatibility, Multi-ASI, Readiness Block, Cross-ASI Dedup & Quality
# =============================================================================


def test_g_single_chunk_under_15_preserves_legacy_contract_and_payload(tmp_path: Path) -> None:
    env = _setup_service_env(tmp_path)
    provider = MockGeneratorProvider(mode="success")
    svc = GeneratorService(
        catalog=env["catalog"],
        application_contexts=env["app_ctx"],
        provider=provider,
        policy_store=env["policy_store"],
    )

    res = svc.generate(
        GenerationServiceRequest(
            target_id="chunk-target",
            counts_by_asi={"ASI01": 15},
            policy_ids_by_asi={"ASI01": env["policies_by_asi"]["ASI01"]},
        )
    )
    asi1 = res.asi_results["ASI01"]
    assert res.overall_status == "completed"
    assert asi1.chunking_used is False
    assert asi1.planned_chunk_count == 1
    assert asi1.executed_chunk_count == 1
    assert asi1.completed_chunk_count == 1
    assert asi1.call_count == 1
    assert len(asi1.chunk_summaries) == 1
    sent_payload = json.loads(provider.received_requests[0].user_payload_json)
    assert "chunk_index" not in sent_payload["generation_parameters"]
    assert "total_chunks" not in sent_payload["generation_parameters"]
    assert "prior_chunk_strategy_tags" not in sent_payload["generation_parameters"]


def test_g_readiness_blocked_makes_zero_provider_calls_even_for_50(tmp_path: Path) -> None:
    env = _setup_service_env(tmp_path, with_context=False)
    provider = MockGeneratorProvider(mode="success")
    svc = GeneratorService(
        catalog=env["catalog"],
        application_contexts=env["app_ctx"],
        provider=provider,
        policy_store=env["policy_store"],
    )
    res = svc.generate(GenerationServiceRequest(target_id="chunk-target", counts_by_asi={"ASI05": 50}))
    asi5 = res.asi_results["ASI05"]
    assert res.overall_status == "blocked"
    assert asi5.status == "blocked"
    assert asi5.call_count == 0
    assert asi5.planned_chunk_count == 4
    assert asi5.executed_chunk_count == 0
    assert asi5.completed_chunk_count == 0
    assert provider.total_calls == 0


def test_g_multi_asi_chunked_cross_asi_dedup_and_quality_evaluator(tmp_path: Path) -> None:
    """ASI03=20 ([15,5]) + ASI05=20 ([15,5]): ASI05 chunk 2 duplicates ASI03 chunk 1 prompt ->
    rejected as duplicate_across_asi pointing to ASI03 candidate; quality evaluator & policy untouched."""
    env = _setup_service_env(tmp_path)
    asi3_c1 = [_cand(i, "ASI03") for i in range(15)]
    asi3_c2 = [_cand(i, "ASI03") for i in range(15, 20)]
    asi5_c1 = [_cand(i, "ASI05") for i in range(15)]
    # ASI05 chunk 2 duplicates ASI03 chunk 1 candidate #0
    asi5_c2 = [
        _cand(15, "ASI05", prompt=asi3_c1[0]["prompt"]),
        *[_cand(i, "ASI05") for i in range(16, 20)],
    ]
    provider = MockGeneratorProvider(
        fixtures=[
            MockFixtureResponse(mode="success", raw_text=_chunk_payload("ASI03", asi3_c1)),
            MockFixtureResponse(mode="success", raw_text=_chunk_payload("ASI03", asi3_c2)),
            MockFixtureResponse(mode="success", raw_text=_chunk_payload("ASI05", asi5_c1)),
            MockFixtureResponse(mode="success", raw_text=_chunk_payload("ASI05", asi5_c2)),
        ]
    )
    svc = GeneratorService(
        catalog=env["catalog"],
        application_contexts=env["app_ctx"],
        provider=provider,
        policy_store=env["policy_store"],
    )

    res = svc.generate(
        GenerationServiceRequest(
            target_id="chunk-target",
            counts_by_asi={"ASI03": 20, "ASI05": 20},
            policy_ids_by_asi={
                "ASI03": env["policies_by_asi"]["ASI03"],
                "ASI05": env["policies_by_asi"]["ASI05"],
            },
            deduplicate_across_asi=True,
        ),
        generation_id="gen-crossasi001",
    )

    assert res.overall_status == "partial"
    assert res.total_requested == 40
    assert res.total_accepted == 39
    assert res.total_rejected == 1
    assert res.total_call_count == 4
    assert res.asi_results["ASI03"].status == "completed"
    assert res.asi_results["ASI03"].reviewed_policy_id == env["policies_by_asi"]["ASI03"]
    assert res.asi_results["ASI05"].status == "partial"
    assert res.asi_results["ASI05"].reviewed_policy_id == env["policies_by_asi"]["ASI05"]
    cross_rej = res.asi_results["ASI05"].rejected_candidates[0]
    assert cross_rej.reason_code == "duplicate_across_asi"
    assert cross_rej.duplicate_of_asi_code == "ASI03"
    assert cross_rej.duplicate_of_source_index == 0
    assert cross_rej.duplicate_of_candidate_id == "gen-crossasi001:asi03:001"

    # G11.5 Quality Evaluator handles multi-chunk GenerationResult cleanly
    q_report = evaluate_generation_result(res)
    assert q_report.overall_metrics.requested_count == 40
    assert q_report.overall_metrics.accepted_count == 39
    assert q_report.overall_metrics.duplicate_rejected_count == 1
    assert q_report.per_asi_summaries["ASI03"].call_count == 2
    assert q_report.per_asi_summaries["ASI05"].call_count == 2

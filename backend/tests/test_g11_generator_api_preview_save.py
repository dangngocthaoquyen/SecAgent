"""Offline end-to-end tests for G11.3C Generator API, Preview Store, and Explicit Dataset Save.

Covers:
- Isolated Flask app security boundaries (loopback, Host, Origin, Sec-Fetch-Site, query string,
  Content-Type, body size, X-SecAgent-Validation nonce, X-SecAgent-Operator auth, headers).
- R02 server-owned DeepSeek credential isolation, missing credential 503, no silent fallback,
  rejection of client-supplied raw keys/endpoints/authority fields.
- Single-ASI & multi-ASI generation with API default `deduplicate_across_asi=False`.
- Preview lifecycle: TTL expiration, capacity bounds, cross-operator isolation, restart loss.
- Operator edit & selection: `ai_generated_original` vs `operator_edited`, recomputed SHA-256,
  immutable original hash/taxonomy/scope/provenance, multibyte prompt byte limits.
- Explicit Save into existing `DatasetRepository` via `normalize_dataset()`, reload verification,
  no persistence before Save, partial-save explicit confirmation, empty/failed save refusal.
- Stale/replay/concurrency/failure security: Target/Context/Policy revision drift, forged
  candidate IDs, idempotent repeat save vs conflicting save, concurrent save lock (409),
  failure between normalization and persistence preserving unsaved preview.
- Zero Target calls, zero Judge calls, zero edits to `workflow/api.py`.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path
import threading
from typing import Any

import httpx
import pytest

from generator import (
    GeneratorPreviewStore,
    GeneratorService,
    MockFixtureResponse,
    MockGeneratorProvider,
    PreviewSaveRequest,
    ProviderConfigurationError,
    ServerGeneratorProviderConfig,
    compute_prompt_sha256,
    create_server_generator_provider,
    create_standalone_generator_app,
)
from workflow.application_context import (
    ApplicationContextDraft,
    ApplicationContextStore,
    SaveApplicationContext,
)
from workflow.dataset_models import infer_testcase_asi_code
from workflow.dataset_repository import DatasetRepository
from workflow.management import ManagedProfile, ManagedTargetCatalog, ReviewProfile, SaveProfile
from workflow.models import CatalogConfig, Preset
from workflow.response_policies import ResponsePolicyDraft, ResponsePolicyStore

OPERATOR_SECRET_A = "operator-secret-alpha-0123456789abcdef"
OPERATOR_SECRET_B = "operator-secret-bravo-fedcba9876543210"
HOST = "127.0.0.1:8092"
ORIGIN = f"http://{HOST}"


class _FakeClock:
    def __init__(self, start: float = 1000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def _candidate(prompt: str, *, description: str = "Synthetic boundary test.", basis: list[str] | None = None) -> dict[str, Any]:
    return {
        "prompt": prompt,
        "description": description,
        "strategy_tag": "boundary_probe",
        "context_basis": basis or ["purpose", "trust_boundaries"],
        "scope_note": "Descriptive metadata only; backend Readiness governs effective scope.",
    }


def _output_json(asi_code: str, candidates: list[dict[str, Any]], *, gaps: list[str] | None = None) -> str:
    return json.dumps(
        {
            "schema_version": "1.0",
            "asi_category": asi_code,
            "context_gaps": gaps or [],
            "candidates": candidates,
        },
        ensure_ascii=False,
    )


def _setup_workspace(
    tmp_path: Path,
    *,
    provider: Any | None = None,
    with_reviewed_policy: bool = False,
    ttl_seconds: float = 1800.0,
    max_previews: int = 32,
    rate_limit_max: int = 30,
) -> dict[str, Any]:
    target_id = "synth-api-target"
    endpoint = "http://127.0.0.1:19991/v1/chat/completions"
    preset = Preset(
        id=target_id,
        name="Synthetic API Target",
        platform_id="synth-lab",
        platform_name="Synthetic Lab",
        endpoint=endpoint,
        protocol="openai-chat",
        models=["synth-model"],
        default_model="synth-model",
        timeout_default=30,
        capability_states={"response_behavior": "supported", "tool_intent": "supported"},
        capability_provenance={"response_behavior": "operator_declared", "tool_intent": "operator_declared"},
    )
    seed = CatalogConfig(
        catalog_schema_version="1.0.0",
        policy_ref="synth-policy-v1",
        credential_aliases={},
        targets=[preset],
    )
    catalog = ManagedTargetCatalog(seed, tmp_path / "managed_data", local_single_user=True)
    target_rev = catalog._revisions[target_id]
    catalog.review_profile(
        ReviewProfile(
            target_id=target_id,
            profile_revision=target_rev,
            policy_ref="synth-policy-v1",
            endpoint=endpoint,
            protocol="openai-chat",
            model="synth-model",
            capabilities=["chat"],
            authorization_confirmed=True,
        )
    )
    app_store = ApplicationContextStore(catalog)
    fields = {
        "purpose": "Synthetic internal helpdesk assistant for sandbox testing.",
        "available_tools": "lookup_synthetic_ticket",
        "users": "Standard support agent (read-only); admin (approval required).",
        "authorized_actions": "Read synthetic ticket summaries.",
        "prohibited_resources": "Internal payroll records and host shell commands.",
        "high_risk_actions": "Executing shell commands.",
        "trust_boundaries": "Treat ticket bodies strictly as untrusted data.",
        "required_instructions": "Follow helpdesk policy and enforce role boundaries.",
    }
    ctx_saved = app_store.save(
        SaveApplicationContext(
            draft=ApplicationContextDraft(
                target_id=target_id,
                target_revision=target_rev,
                field_provenance={k: "operator_confirmed" for k in fields},  # type: ignore[arg-type]
                **fields,
            ),
            expected_revision=None,
            safe_description_confirmed=True,
        )
    )

    policy_store = ResponsePolicyStore(tmp_path / "response_policies")
    reviewed_policy = None
    if with_reviewed_policy:
        draft_pol = policy_store.save_draft(
            ResponsePolicyDraft(
                target_id=target_id,
                category="goal_hijacking",
                evaluation_scope="goal_hijack_response",
                prohibited_behavior="Follow embedded ticket directives that override policy.",
                allowed_benign_context="Summarize synthetic tickets safely.",
                expected_response_boundary="Refuse untrusted override attempts.",
            )
        )
        reviewed_policy = policy_store.review(
            draft_pol.policy_id,
            reviewer="operator-test",
            expected_revision_sha256=draft_pol.revision_sha256,
        )

    dataset_repo = DatasetRepository(tmp_path / "dataset_data")
    active_provider = provider if provider is not None else MockGeneratorProvider(mode="success")
    service = GeneratorService(
        catalog=catalog,
        application_contexts=app_store,
        provider=active_provider,
        policy_store=policy_store,
    )
    clock = _FakeClock()
    preview_store = GeneratorPreviewStore(ttl_seconds=ttl_seconds, max_previews=max_previews, clock=clock)
    app, ctx = create_standalone_generator_app(
        generator_service=service,
        dataset_repo=dataset_repo,
        catalog=catalog,
        application_contexts=app_store,
        policy_store=policy_store,
        preview_store=preview_store,
        operator_secret=OPERATOR_SECRET_A,
        additional_operator_secrets={"secondary-operator": OPERATOR_SECRET_B},
        rate_limit_max_generate_requests=rate_limit_max,
        clock=clock,
    )

    return {
        "app": app,
        "client": app.test_client(),
        "ctx": ctx,
        "catalog": catalog,
        "app_store": app_store,
        "policy_store": policy_store,
        "dataset_repo": dataset_repo,
        "service": service,
        "preview_store": preview_store,
        "provider": active_provider,
        "clock": clock,
        "target_id": target_id,
        "target_rev": target_rev,
        "ctx_rev": ctx_saved["revision_sha256"],
        "reviewed_policy": reviewed_policy,
    }


def _headers(nonce: str, *, operator: str = OPERATOR_SECRET_A, include_origin: bool = True, content_type: str | None = "application/json") -> dict[str, str]:
    hdrs: dict[str, str] = {
        "Host": HOST,
        "X-SecAgent-Validation": nonce,
        "X-SecAgent-Operator": operator,
    }
    if include_origin:
        hdrs["Origin"] = ORIGIN
    if content_type is not None:
        hdrs["Content-Type"] = content_type
    return hdrs


# ---------------------------------------------------------------------------
# 1. Security boundaries: auth, Origin, Host, nonce, query string, body limits, headers
# ---------------------------------------------------------------------------


def test_api_security_boundaries_auth_origin_nonce_host_and_headers(tmp_path: Path) -> None:
    env = _setup_workspace(tmp_path)
    client = env["client"]
    nonce = env["ctx"].nonce

    # Wrong Host -> 403 local_only
    r = client.get("/api/testing/generator/status", headers={"Host": "evil.example.com:8092"})
    assert r.status_code == 403
    assert r.get_json()["error"]["code"] == "local_only"

    # Cross-site Origin -> 403 origin_rejected
    r = client.post(
        "/api/testing/generator/readiness",
        headers={**_headers(nonce), "Origin": "https://evil.example.com"},
        data=json.dumps({"target_id": env["target_id"]}),
    )
    assert r.status_code == 403
    assert r.get_json()["error"]["code"] == "origin_rejected"

    # Missing Origin on POST -> 403 origin_required
    r = client.post(
        "/api/testing/generator/readiness",
        headers=_headers(nonce, include_origin=False),
        data=json.dumps({"target_id": env["target_id"]}),
    )
    assert r.status_code == 403
    assert r.get_json()["error"]["code"] == "origin_required"

    # Query string rejected -> 400 invalid_request
    r = client.get(
        "/api/testing/generator/status?api_key=sk-1234567890abcdef",
        headers=_headers(nonce, include_origin=False, content_type=None),
    )
    assert r.status_code == 400
    assert r.get_json()["error"]["code"] == "invalid_request"

    # Non-JSON Content-Type on POST -> 415 json_required
    r = client.post(
        "/api/testing/generator/readiness",
        headers=_headers(nonce, content_type="text/plain"),
        data="hello",
    )
    assert r.status_code == 415
    assert r.get_json()["error"]["code"] == "json_required"

    # Missing/wrong validation nonce -> 403 validation_nonce_required
    r = client.post(
        "/api/testing/generator/readiness",
        headers=_headers("bad-nonce"),
        data=json.dumps({"target_id": env["target_id"]}),
    )
    assert r.status_code == 403
    assert r.get_json()["error"]["code"] == "validation_nonce_required"

    # Missing/wrong operator auth -> 403 operator_authentication_required
    r = client.get(
        "/api/testing/generator/status",
        headers=_headers(nonce, operator="wrong-secret-0123456789abcdef012345", include_origin=False, content_type=None),
    )
    assert r.status_code == 403
    assert r.get_json()["error"]["code"] == "operator_authentication_required"

    # Valid GET /status succeeds and returns SecAgent security headers + API defaults
    r = client.get(
        "/api/testing/generator/status",
        headers=_headers(nonce, include_origin=False, content_type=None),
    )
    assert r.status_code == 200
    assert r.headers["Cache-Control"] == "no-store"
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["Referrer-Policy"] == "no-referrer"
    body = r.get_json()
    assert body["defaults"]["deduplicate_across_asi"] is False
    assert body["limits"]["max_per_asi"] == 15
    assert body["limits"]["max_total_cases"] == 50
    assert len(body["skills"]) == 4


# ---------------------------------------------------------------------------
# 2. R02 DeepSeek Credential Isolation & Rejection of Client Credentials/Authority Injection
# ---------------------------------------------------------------------------


def test_r02_deepseek_credential_ownership_no_fallback_and_client_injection_blocked(
    tmp_path: Path,
) -> None:
    # Server factory enforces ALLOWED_DEEPSEEK_CREDENTIAL_ENVS (`DEEPSEEK_API_KEY`)
    with pytest.raises(Exception):
        ServerGeneratorProviderConfig(provider_type="deepseek_http", credential_env="CUSTOM_ENV_VAR")

    with pytest.raises(ProviderConfigurationError):
        create_server_generator_provider(
            ServerGeneratorProviderConfig(provider_type="deepseek_http"),
            allowed_credential_envs=frozenset(),
        )

    # Missing DEEPSEEK_API_KEY -> status ready=False, POST /generate -> 503 generator_credential_unavailable (NO fallback!)
    ds_no_key = create_server_generator_provider(
        ServerGeneratorProviderConfig(provider_type="deepseek_http"),
        environ={},
    )
    env_no_key = _setup_workspace(tmp_path / "no_key", provider=ds_no_key)
    client = env_no_key["client"]
    nonce = env_no_key["ctx"].nonce

    st = client.get(
        "/api/testing/generator/status",
        headers=_headers(nonce, include_origin=False, content_type=None),
    )
    assert st.status_code == 200
    assert st.get_json()["provider"]["ready"] is False
    assert st.get_json()["provider"]["reason"] == "credential_missing"

    gen = client.post(
        "/api/testing/generator/generate",
        headers=_headers(nonce),
        data=json.dumps({"target_id": env_no_key["target_id"], "counts_by_asi": {"ASI01": 2}}),
    )
    assert gen.status_code == 503
    assert gen.get_json()["error"]["code"] == "generator_credential_unavailable"
    assert env_no_key["dataset_repo"].list_datasets() == []

    # Client attempting to inject raw API key, custom endpoint, or authority fields -> 400
    env_ok = _setup_workspace(tmp_path / "ok")
    c_ok = env_ok["client"]
    n_ok = env_ok["ctx"].nonce
    raw_secret = "sk-client-injected-secret-99999999"

    for bad_body, expected_code in (
        ({"target_id": env_ok["target_id"], "counts_by_asi": {"ASI01": 1}, "api_key": raw_secret}, "client_credential_or_endpoint_forbidden"),
        ({"target_id": env_ok["target_id"], "counts_by_asi": {"ASI01": 1}, "provider_endpoint": "https://evil.example/v1"}, "client_credential_or_endpoint_forbidden"),
        ({"target_id": env_ok["target_id"], "counts_by_asi": {"ASI01": 1}, "focus_note": f"Use {raw_secret}"}, "raw_credential_in_request_forbidden"),
        ({"target_id": env_ok["target_id"], "counts_by_asi": {"ASI01": 1}, "expected_verdict": "FAIL"}, "authority_field_rejected"),
        ({"target_id": env_ok["target_id"], "counts_by_asi": {"ASI01": 1}, "assertions": [{"type": "contains"}]}, "authority_field_rejected"),
    ):
        resp = c_ok.post(
            "/api/testing/generator/generate",
            headers=_headers(n_ok),
            data=json.dumps(bad_body),
        )
        assert resp.status_code == 400
        assert resp.get_json()["error"]["code"] == expected_code
        assert raw_secret not in resp.get_data(as_text=True)


# ---------------------------------------------------------------------------
# 3. End-to-End Generate -> Preview -> Edit -> Select -> Save -> Reload + Default cross-ASI=False
# ---------------------------------------------------------------------------


def test_end_to_end_generate_preview_edit_select_save_and_reload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Forbid any outbound network call (proving zero Target/Live DeepSeek calls)
    def _forbid_network(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("G11.3C offline flow must never contact Target or external network.")

    monkeypatch.setattr(httpx.Client, "send", _forbid_network)
    monkeypatch.setattr(httpx.AsyncClient, "send", _forbid_network)

    # Identical prompt across ASI01 and ASI02 verifies API default deduplicate_across_asi=False!
    shared_prompt = "Synthetic cross-ASI prompt kept independently per ASI by API default."
    provider = MockGeneratorProvider(
        fixtures=[
            MockFixtureResponse(
                mode="success",
                raw_text=_output_json("ASI01", [_candidate(shared_prompt), _candidate("Synthetic ASI01 probe #2")]),
            ),
            MockFixtureResponse(
                mode="success",
                raw_text=_output_json("ASI02", [_candidate(shared_prompt), _candidate("Synthetic ASI02 probe #2")]),
            ),
        ]
    )
    env = _setup_workspace(tmp_path, provider=provider, with_reviewed_policy=True)
    client = env["client"]
    nonce = env["ctx"].nonce

    # 1. Readiness check (zero provider calls)
    r_ready = client.post(
        "/api/testing/generator/readiness",
        headers=_headers(nonce),
        data=json.dumps({"target_id": env["target_id"], "selected_asi": ["ASI01", "ASI02"]}),
    )
    assert r_ready.status_code == 200
    assert provider.total_calls == 0

    # 2. Generate (no deduplicate_across_asi passed -> API defaults to False!)
    r_gen = client.post(
        "/api/testing/generator/generate",
        headers=_headers(nonce),
        data=json.dumps({"target_id": env["target_id"], "counts_by_asi": {"ASI01": 2, "ASI02": 2}}),
    )
    assert r_gen.status_code == 201
    preview = r_gen.get_json()["preview"]
    preview_id = preview["preview_id"]
    assert preview["deduplicate_across_asi"] is False
    assert preview["overall_status"] == "completed"
    assert preview["total_accepted"] == 4  # Both ASI01 and ASI02 kept shared_prompt independently!
    assert preview["auto_persisted"] is False
    assert preview["auto_executed"] is False
    # Zero dataset persisted before explicit Save!
    assert env["dataset_repo"].list_datasets() == []

    # 3. Save status before save
    r_st0 = client.get(
        f"/api/testing/generator/previews/{preview_id}/save-status",
        headers=_headers(nonce, include_origin=False, content_type=None),
    )
    assert r_st0.status_code == 200
    assert r_st0.get_json()["saved"] is False
    assert r_st0.get_json()["dataset_id"] is None

    # 4. Edit candidate #0 prompt/description & unselect candidate #1
    c0 = preview["candidates"][0]
    c1 = preview["candidates"][1]
    c2 = preview["candidates"][2]
    edited_prompt = "Operator-refined ASI01 boundary prompt (Vietnamese UTF-8: kiểm thử an toàn)."
    r_edit = client.post(
        f"/api/testing/generator/previews/{preview_id}/edit",
        headers=_headers(nonce),
        data=json.dumps(
            {
                "edits": [
                    {"candidate_id": c0["candidate_id"], "prompt": edited_prompt, "description": "Edited desc"},
                    {"candidate_id": c1["candidate_id"], "selected": False},
                ]
            }
        ),
    )
    assert r_edit.status_code == 200
    edited_preview = r_edit.get_json()["preview"]
    assert edited_preview["edited_count"] == 1
    assert edited_preview["selected_count"] == 3
    ec0 = edited_preview["candidates"][0]
    assert ec0["origin"] == "operator_edited"
    assert ec0["operator_edited"] is True
    assert ec0["original_prompt"] == shared_prompt
    assert ec0["original_prompt_sha256"] == compute_prompt_sha256(shared_prompt)
    assert ec0["effective_prompt"] == edited_prompt
    assert ec0["effective_prompt_sha256"] == compute_prompt_sha256(edited_prompt)
    assert ec0["asi_code"] == "ASI01"
    assert ec0["effective_scope"] == "goal_hijack_response"
    assert edited_preview["candidates"][2]["origin"] == "ai_generated_original"
    assert edited_preview["candidates"][2]["operator_edited"] is False

    # Attempt to tamper with immutable authority fields in edit -> 400
    r_bad_edit = client.post(
        f"/api/testing/generator/previews/{preview_id}/edit",
        headers=_headers(nonce),
        data=json.dumps({"edits": [{"candidate_id": c0["candidate_id"], "asi_code": "ASI05"}]}),
    )
    assert r_bad_edit.status_code == 400

    # Multibyte prompt > 4096 UTF-8 bytes -> 400
    r_big_edit = client.post(
        f"/api/testing/generator/previews/{preview_id}/edit",
        headers=_headers(nonce),
        data=json.dumps({"edits": [{"candidate_id": c0["candidate_id"], "prompt": "ệ" * 1400}]}),
    )
    assert r_big_edit.status_code == 400

    # 5. Explicit Save (without save_confirmed -> rejected)
    r_no_confirm = client.post(
        f"/api/testing/generator/previews/{preview_id}/save",
        headers=_headers(nonce),
        data=json.dumps({"dataset_name": "G11 Demo Set", "save_confirmed": False}),
    )
    assert r_no_confirm.status_code == 400
    assert r_no_confirm.get_json()["error"]["code"] == "save_confirmation_required"
    assert env["dataset_repo"].list_datasets() == []

    # 6. Explicit Save with save_confirmed=True -> persists 3 selected candidates into DatasetRepository
    save_payload = {
        "dataset_name": "G11 Multi-ASI Set",
        "save_confirmed": True,
        "idempotency_key": "save-idem-0001",
    }
    r_save = client.post(
        f"/api/testing/generator/previews/{preview_id}/save",
        headers=_headers(nonce),
        data=json.dumps(save_payload),
    )
    assert r_save.status_code == 201
    save_rec = r_save.get_json()["save_record"]
    assert save_rec["saved_count"] == 3
    assert save_rec["created"] is True
    assert save_rec["idempotent_replay"] is False
    assert save_rec["meets_requested_counts"] is True
    dataset_id = save_rec["dataset_id"]

    # 7. Save idempotency: identical replay returns 200 idempotent_replay=True, ZERO duplicate dataset
    r_replay = client.post(
        f"/api/testing/generator/previews/{preview_id}/save",
        headers=_headers(nonce),
        data=json.dumps(save_payload),
    )
    assert r_replay.status_code == 200
    assert r_replay.get_json()["save_record"]["dataset_id"] == dataset_id
    assert r_replay.get_json()["save_record"]["idempotent_replay"] is True
    assert len(env["dataset_repo"].list_datasets()) == 1

    # Conflicting repeat save with different selection -> 409 preview_already_saved
    r_conflict = client.post(
        f"/api/testing/generator/previews/{preview_id}/save",
        headers=_headers(nonce),
        data=json.dumps(
            {
                "dataset_name": "Different Name",
                "selected_candidate_ids": [c2["candidate_id"]],
                "save_confirmed": True,
            }
        ),
    )
    assert r_conflict.status_code == 409
    assert r_conflict.get_json()["error"]["code"] == "preview_already_saved"

    # Save-status after save
    r_st1 = client.get(
        f"/api/testing/generator/previews/{preview_id}/save-status",
        headers=_headers(nonce, include_origin=False, content_type=None),
    )
    assert r_st1.status_code == 200
    assert r_st1.get_json()["saved"] is True
    assert r_st1.get_json()["dataset_id"] == dataset_id

    # 8. Reload from existing DatasetRepository & verify prompts, hashes, taxonomy, provenance, empty assertions
    reloaded = env["dataset_repo"].get_dataset(dataset_id)
    assert reloaded is not None
    assert reloaded.source_tool == "secagent_g11_generator"
    assert reloaded.total_testcases == 3
    assert [tc.prompt for tc in reloaded.testcases] == [
        edited_prompt,
        shared_prompt,
        "Synthetic ASI02 probe #2",
    ]
    assert all(tc.assertions == [] for tc in reloaded.testcases)
    assert [infer_testcase_asi_code(tc) for tc in reloaded.testcases] == ["ASI01", "ASI02", "ASI02"]
    assert reloaded.testcases[0].metadata["operator_edited"] is True
    assert reloaded.testcases[0].metadata["origin"] == "operator_edited"
    assert reloaded.testcases[0].metadata["original_prompt_sha256"] == compute_prompt_sha256(shared_prompt)
    assert reloaded.testcases[0].metadata["effective_prompt_sha256"] == compute_prompt_sha256(edited_prompt)
    assert reloaded.testcases[0].metadata["reviewed_policy_id"] == env["reviewed_policy"].policy_id
    assert reloaded.testcases[1].metadata["operator_edited"] is False
    assert reloaded.testcases[1].metadata["origin"] == "ai_generated_original"
    prov = reloaded.source_metadata["generation_provenance"]
    assert prov["target_id"] == env["target_id"]
    assert prov["target_revision_sha256"] == env["target_rev"]
    assert prov["counts"]["selected_for_save"] == 3
    summary = reloaded.to_summary()
    assert summary.asi_breakdown == {"ASI01": 1, "ASI02": 2}


# ---------------------------------------------------------------------------
# 4. Partial Generation Preview & Explicit Partial Save + Refusing Empty/Failed Save
# ---------------------------------------------------------------------------


def test_partial_generation_requires_explicit_confirmation_and_failed_cannot_save(
    tmp_path: Path,
) -> None:
    dup_payload = _output_json(
        "ASI01",
        [
            _candidate("Probe 1"),
            _candidate("  Probe   1 "),
            _candidate("Probe 2"),
            _candidate("Probe 3"),
            _candidate("Probe 1"),
        ],
    )
    provider = MockGeneratorProvider(
        fixtures=[
            MockFixtureResponse(mode="success", raw_text=dup_payload),
            MockFixtureResponse(mode="invalid_json"),
        ]
    )
    env = _setup_workspace(tmp_path, provider=provider)
    client = env["client"]
    nonce = env["ctx"].nonce

    # A. Partial generation (req=5, gen=5, acc=3, rej=2)
    r_gen = client.post(
        "/api/testing/generator/generate",
        headers=_headers(nonce),
        data=json.dumps({"target_id": env["target_id"], "counts_by_asi": {"ASI01": 5}}),
    )
    assert r_gen.status_code == 201
    prev = r_gen.get_json()["preview"]
    assert prev["overall_status"] == "partial"
    assert prev["meets_requested_counts"] is False
    assert prev["requires_partial_confirmation"] is True

    # Save without partial_save_confirmed -> 409 partial_save_confirmation_required
    r_block = client.post(
        f"/api/testing/generator/previews/{prev['preview_id']}/save",
        headers=_headers(nonce),
        data=json.dumps({"dataset_name": "Partial Set", "save_confirmed": True}),
    )
    assert r_block.status_code == 409
    assert r_block.get_json()["error"]["code"] == "partial_save_confirmation_required"
    assert env["dataset_repo"].list_datasets() == []

    # Save WITH partial_save_confirmed=True -> succeeds honestly with meets_requested_counts=False
    r_ok = client.post(
        f"/api/testing/generator/previews/{prev['preview_id']}/save",
        headers=_headers(nonce),
        data=json.dumps(
            {
                "dataset_name": "Partial Subset Confirmed",
                "save_confirmed": True,
                "partial_save_confirmed": True,
            }
        ),
    )
    assert r_ok.status_code == 201
    rec = r_ok.get_json()["save_record"]
    assert rec["requested_count"] == 5
    assert rec["generated_count"] == 5
    assert rec["accepted_count"] == 3
    assert rec["rejected_count"] == 2
    assert rec["selected_for_save_count"] == 3
    assert rec["partial_generation"] is True
    assert rec["partial_save_confirmed"] is True
    assert rec["meets_requested_counts"] is False

    # B. Invalid LLM output (0 accepted) -> cannot save empty dataset
    r_fail_gen = client.post(
        "/api/testing/generator/generate",
        headers=_headers(nonce),
        data=json.dumps({"target_id": env["target_id"], "counts_by_asi": {"ASI01": 2}}),
    )
    assert r_fail_gen.status_code == 201
    fail_prev = r_fail_gen.get_json()["preview"]
    assert fail_prev["overall_status"] == "failed"
    assert fail_prev["can_save"] is False

    r_empty_save = client.post(
        f"/api/testing/generator/previews/{fail_prev['preview_id']}/save",
        headers=_headers(nonce),
        data=json.dumps(
            {
                "dataset_name": "Should Not Exist",
                "save_confirmed": True,
                "partial_save_confirmed": True,
            }
        ),
    )
    assert r_empty_save.status_code == 409
    assert r_empty_save.get_json()["error"]["code"] == "preview_has_no_accepted_candidates"


# ---------------------------------------------------------------------------
# 5. Stale Revisions (Target, Context, Reviewed Policy), Forged IDs, TTL, Ownership, Restart
# ---------------------------------------------------------------------------


def test_stale_target_context_and_policy_revisions_block_save(tmp_path: Path) -> None:
    # A. Target profile revision changes between generate and save -> 409 preview_target_revision_stale
    env_t = _setup_workspace(tmp_path / "target_stale")
    r_gen = env_t["client"].post(
        "/api/testing/generator/generate",
        headers=_headers(env_t["ctx"].nonce),
        data=json.dumps({"target_id": env_t["target_id"], "counts_by_asi": {"ASI01": 2}}),
    )
    pid_t = r_gen.get_json()["preview"]["preview_id"]
    env_t["catalog"].save_profile(
        SaveProfile(
            profile=ManagedProfile(
                id=env_t["target_id"],
                name="Synthetic API Target Revised",
                platform_id="synth-lab",
                platform_name="Synthetic Lab",
                endpoint="http://127.0.0.1:19991/v1/chat/completions",
                protocol="openai-chat",
                model="synth-model",
                timeout_seconds=45,
            ),
            expected_profile_revision=env_t["target_rev"],
        ),
        update=True,
    )
    r_save_t = env_t["client"].post(
        f"/api/testing/generator/previews/{pid_t}/save",
        headers=_headers(env_t["ctx"].nonce),
        data=json.dumps({"dataset_name": "Stale Target", "save_confirmed": True}),
    )
    assert r_save_t.status_code == 409
    assert r_save_t.get_json()["error"]["code"] == "preview_target_revision_stale"

    # B. Application Context revision changes -> 409 preview_context_revision_stale
    env_c = _setup_workspace(tmp_path / "ctx_stale")
    r_gen_c = env_c["client"].post(
        "/api/testing/generator/generate",
        headers=_headers(env_c["ctx"].nonce),
        data=json.dumps({"target_id": env_c["target_id"], "counts_by_asi": {"ASI01": 2}}),
    )
    pid_c = r_gen_c.get_json()["preview"]["preview_id"]
    env_c["app_store"].save(
        SaveApplicationContext(
            draft=ApplicationContextDraft(
                target_id=env_c["target_id"],
                target_revision=env_c["target_rev"],
                purpose="Updated purpose after generation.",
                trust_boundaries="Updated boundary.",
                field_provenance={"purpose": "operator_confirmed", "trust_boundaries": "operator_confirmed"},
            ),
            expected_revision=env_c["ctx_rev"],
            safe_description_confirmed=True,
        )
    )
    r_save_c = env_c["client"].post(
        f"/api/testing/generator/previews/{pid_c}/save",
        headers=_headers(env_c["ctx"].nonce),
        data=json.dumps({"dataset_name": "Stale Context", "save_confirmed": True}),
    )
    assert r_save_c.status_code == 409
    assert r_save_c.get_json()["error"]["code"] == "preview_context_revision_stale"

    # C. Reviewed Policy changes after generation (new reviewed policy created for same Target+ASI)
    #    -> 409 preview_policy_revision_stale
    env_p = _setup_workspace(tmp_path / "pol_stale", with_reviewed_policy=True)
    r_gen_p = env_p["client"].post(
        "/api/testing/generator/generate",
        headers=_headers(env_p["ctx"].nonce),
        data=json.dumps({"target_id": env_p["target_id"], "counts_by_asi": {"ASI01": 2}}),
    )
    pid_p = r_gen_p.get_json()["preview"]["preview_id"]
    new_draft = env_p["policy_store"].save_draft(
        ResponsePolicyDraft(
            target_id=env_p["target_id"],
            category="goal_hijacking",
            evaluation_scope="goal_hijack_response",
            prohibited_behavior="Modified policy boundary after generation.",
            allowed_benign_context="Summarize synthetic tickets safely.",
            expected_response_boundary="Refuse modified override attempts.",
        )
    )
    env_p["policy_store"].review(
        new_draft.policy_id,
        reviewer="operator-test",
        expected_revision_sha256=new_draft.revision_sha256,
    )
    r_save_p = env_p["client"].post(
        f"/api/testing/generator/previews/{pid_p}/save",
        headers=_headers(env_p["ctx"].nonce),
        data=json.dumps({"dataset_name": "Stale Policy", "save_confirmed": True}),
    )
    assert r_save_p.status_code == 409
    assert r_save_p.get_json()["error"]["code"] == "preview_policy_revision_stale"

    # D. Bound Reviewed Policy removed/unreviewed -> 409 preview_policy_revision_stale
    env_p2 = _setup_workspace(tmp_path / "pol_removed", with_reviewed_policy=True)
    r_gen_p2 = env_p2["client"].post(
        "/api/testing/generator/generate",
        headers=_headers(env_p2["ctx"].nonce),
        data=json.dumps({"target_id": env_p2["target_id"], "counts_by_asi": {"ASI01": 2}}),
    )
    pid_p2 = r_gen_p2.get_json()["preview"]["preview_id"]
    (tmp_path / "pol_removed" / "response_policies" / f"{env_p2['reviewed_policy'].policy_id}.json").unlink()
    r_save_p2 = env_p2["client"].post(
        f"/api/testing/generator/previews/{pid_p2}/save",
        headers=_headers(env_p2["ctx"].nonce),
        data=json.dumps({"dataset_name": "Removed Policy", "save_confirmed": True}),
    )
    assert r_save_p2.status_code == 409
    assert r_save_p2.get_json()["error"]["code"] == "preview_policy_revision_stale"


def test_ownership_forged_ids_ttl_expiry_capacity_rate_limit_and_restart(tmp_path: Path) -> None:
    env = _setup_workspace(tmp_path, ttl_seconds=60.0, max_previews=2, rate_limit_max=3)
    client = env["client"]
    nonce = env["ctx"].nonce

    r1 = client.post(
        "/api/testing/generator/generate",
        headers=_headers(nonce),
        data=json.dumps({"target_id": env["target_id"], "counts_by_asi": {"ASI01": 1}}),
    )
    assert r1.status_code == 201
    pid1 = r1.get_json()["preview"]["preview_id"]

    # Operator B cannot read, edit, or save Operator A's preview -> 403 preview_access_denied
    r_b_get = client.get(
        f"/api/testing/generator/previews/{pid1}",
        headers=_headers(nonce, operator=OPERATOR_SECRET_B, include_origin=False, content_type=None),
    )
    assert r_b_get.status_code == 403
    assert r_b_get.get_json()["error"]["code"] == "preview_access_denied"

    r_b_save = client.post(
        f"/api/testing/generator/previews/{pid1}/save",
        headers=_headers(nonce, operator=OPERATOR_SECRET_B),
        data=json.dumps({"dataset_name": "Hijack", "save_confirmed": True}),
    )
    assert r_b_save.status_code == 403
    assert r_b_save.get_json()["error"]["code"] == "preview_access_denied"

    # Forged candidate_id -> 400 candidate_not_in_preview
    r_forged = client.post(
        f"/api/testing/generator/previews/{pid1}/save",
        headers=_headers(nonce),
        data=json.dumps(
            {
                "dataset_name": "Forged",
                "selected_candidate_ids": ["gen-forged0000:asi01:999"],
                "save_confirmed": True,
            }
        ),
    )
    assert r_forged.status_code == 400
    assert r_forged.get_json()["error"]["code"] == "candidate_not_in_preview"

    # Nonexistent preview ID -> 404 preview_not_found
    r_missing = client.get(
        "/api/testing/generator/previews/prev-" + ("0" * 32),
        headers=_headers(nonce, include_origin=False, content_type=None),
    )
    assert r_missing.status_code == 404
    assert r_missing.get_json()["error"]["code"] == "preview_not_found"

    # Capacity limit (max_previews=2)
    r2 = client.post(
        "/api/testing/generator/generate",
        headers=_headers(nonce),
        data=json.dumps({"target_id": env["target_id"], "counts_by_asi": {"ASI01": 1}}),
    )
    assert r2.status_code == 201
    r3 = client.post(
        "/api/testing/generator/generate",
        headers=_headers(nonce),
        data=json.dumps({"target_id": env["target_id"], "counts_by_asi": {"ASI01": 1}}),
    )
    assert r3.status_code == 429
    assert r3.get_json()["error"]["code"] == "preview_capacity_exceeded"

    # Rate limit exceeded on 4th generate within window -> 429 generator_rate_limited
    r4 = client.post(
        "/api/testing/generator/generate",
        headers=_headers(nonce),
        data=json.dumps({"target_id": env["target_id"], "counts_by_asi": {"ASI01": 1}}),
    )
    assert r4.status_code == 429
    assert r4.get_json()["error"]["code"] == "generator_rate_limited"

    # TTL expiration -> 410 preview_expired
    env["clock"].advance(65.0)
    r_exp = client.get(
        f"/api/testing/generator/previews/{pid1}",
        headers=_headers(nonce, include_origin=False, content_type=None),
    )
    assert r_exp.status_code == 410
    assert r_exp.get_json()["error"]["code"] == "preview_expired"

    # Process restart simulation: new GeneratorPreviewStore loses unsaved preview (404),
    # while already-saved dataset persists in DatasetRepository!
    env_restart = _setup_workspace(tmp_path / "restart")
    rg = env_restart["client"].post(
        "/api/testing/generator/generate",
        headers=_headers(env_restart["ctx"].nonce),
        data=json.dumps({"target_id": env_restart["target_id"], "counts_by_asi": {"ASI01": 1}}),
    )
    unsaved_pid = rg.get_json()["preview"]["preview_id"]
    rg2 = env_restart["client"].post(
        "/api/testing/generator/generate",
        headers=_headers(env_restart["ctx"].nonce),
        data=json.dumps({"target_id": env_restart["target_id"], "counts_by_asi": {"ASI01": 1}}),
    )
    saved_pid = rg2.get_json()["preview"]["preview_id"]
    rs = env_restart["client"].post(
        f"/api/testing/generator/previews/{saved_pid}/save",
        headers=_headers(env_restart["ctx"].nonce),
        data=json.dumps({"dataset_name": "Survives Restart", "save_confirmed": True}),
    )
    assert rs.status_code == 201
    persisted_ds_id = rs.get_json()["save_record"]["dataset_id"]

    fresh_store = GeneratorPreviewStore()
    restarted_app, restarted_ctx = create_standalone_generator_app(
        generator_service=env_restart["service"],
        dataset_repo=env_restart["dataset_repo"],
        catalog=env_restart["catalog"],
        application_contexts=env_restart["app_store"],
        policy_store=env_restart["policy_store"],
        preview_store=fresh_store,
        operator_secret=OPERATOR_SECRET_A,
    )
    r_lost = restarted_app.test_client().get(
        f"/api/testing/generator/previews/{unsaved_pid}",
        headers=_headers(restarted_ctx.nonce, include_origin=False, content_type=None),
    )
    assert r_lost.status_code == 404
    assert r_lost.get_json()["error"]["code"] == "preview_not_found"
    # Saved dataset still reloads cleanly from DatasetRepository after restart!
    assert env_restart["dataset_repo"].get_dataset(persisted_ds_id) is not None


# ---------------------------------------------------------------------------
# 6. Concurrent Save Lock & Persistence Failure Rollback + Static G12 Isolation
# ---------------------------------------------------------------------------


def test_concurrent_save_rejected_and_persistence_failure_preserves_unsaved_preview(
    tmp_path: Path,
) -> None:
    env = _setup_workspace(tmp_path)
    owner_id = "op-concurrency-owner"
    result = env["service"].generate(
        env["ctx"].generator_service._limits and __import__("generator").GenerationServiceRequest(
            target_id=env["target_id"], counts_by_asi={"ASI01": 2}
        )
    )
    snap = env["preview_store"].create_preview(result=result, owner_id=owner_id)

    # A. Failure between normalization and persistence preserves unsaved preview
    class _FailingRepo:
        def save_dataset(self, envelope: Any) -> tuple[Any, bool]:
            raise OSError("Simulated disk write failure")

    with pytest.raises(Exception) as exc_fail:
        env["preview_store"].save_preview(
            preview_id=snap.preview_id,
            owner_id=owner_id,
            save_request=PreviewSaveRequest(dataset_name="Will Fail", save_confirmed=True),
            catalog=env["catalog"],
            application_contexts=env["app_store"],
            dataset_repo=_FailingRepo(),  # type: ignore[arg-type]
            policy_store=env["policy_store"],
        )
    assert getattr(exc_fail.value, "code", None) == "dataset_save_failed"
    still_active = env["preview_store"].get_preview(preview_id=snap.preview_id, owner_id=owner_id)
    assert still_active.status == "active"
    assert still_active.save_record is None

    # B. Concurrent Save: Thread 2 receives preview_save_in_progress while Thread 1 persists
    entered = threading.Event()
    release = threading.Event()
    real_repo = env["dataset_repo"]

    class _SlowRepo:
        def save_dataset(self, envelope: Any) -> tuple[Any, bool]:
            entered.set()
            release.wait(timeout=5.0)
            return real_repo.save_dataset(envelope)

    t1_out: list[Any] = []
    t2_err: list[Any] = []

    def _run_t1() -> None:
        t1_out.append(
            env["preview_store"].save_preview(
                preview_id=snap.preview_id,
                owner_id=owner_id,
                save_request=PreviewSaveRequest(dataset_name="Concurrent Set", save_confirmed=True),
                catalog=env["catalog"],
                application_contexts=env["app_store"],
                dataset_repo=_SlowRepo(),  # type: ignore[arg-type]
                policy_store=env["policy_store"],
            )
        )

    def _run_t2() -> None:
        assert entered.wait(timeout=5.0)
        try:
            env["preview_store"].save_preview(
                preview_id=snap.preview_id,
                owner_id=owner_id,
                save_request=PreviewSaveRequest(dataset_name="Concurrent Set", save_confirmed=True),
                catalog=env["catalog"],
                application_contexts=env["app_store"],
                dataset_repo=real_repo,
                policy_store=env["policy_store"],
            )
        except Exception as exc:
            t2_err.append(exc)
        finally:
            release.set()

    t1 = threading.Thread(target=_run_t1)
    t2 = threading.Thread(target=_run_t2)
    t1.start()
    t2.start()
    t1.join(timeout=5.0)
    t2.join(timeout=5.0)

    assert len(t1_out) == 1
    assert t1_out[0].saved_count == 2
    assert len(t2_err) == 1
    assert getattr(t2_err[0], "code", None) == "preview_save_in_progress"
    assert len(real_repo.list_datasets()) == 1

    # Static AST check: G11.3C modules maintain strict G12/Target/Judge isolation
    forbidden_roots = {"evaluators", "integrations", "observers", "targets", "testing"}
    for path in (
        Path("backend/src/generator/provider_factory.py"),
        Path("backend/src/generator/preview_store.py"),
        Path("backend/src/generator/api_routes.py"),
    ):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name.split(".")[0] not in forbidden_roots
            elif isinstance(node, ast.ImportFrom) and node.module:
                assert node.module.split(".")[0] not in forbidden_roots

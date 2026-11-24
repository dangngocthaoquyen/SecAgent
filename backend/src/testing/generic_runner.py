"""Unified target-agnostic Live & Offline Test Runner pipeline (Gate 2).

Connects:
- Live mode: TestCase + TargetProfile (HTTP, MCP, Hosted MCP Agent) -> Runner ->
  Evidence Collectors -> HybridEvaluator -> ExecutionReport-compatible artifact.
- Offline mode: Phase 1A BlindEvaluationDataset (or stored JSON records) ->
  OfflineStoredTargetAdapter -> Runner -> Evidence Collectors -> HybridEvaluator ->
  ExecutionReport-compatible artifact (with zero Target HTTP calls).
"""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import sys
from typing import Any, Literal, Sequence
from uuid import uuid4

import yaml

from attack_modules import BaseAttackModule, build_default_attack_module_registry
from core.models import EvaluationConfig, EvaluationRule, TargetProfile, TestCase, TestInput
from core.models.execution import resolve_response_completeness
from core.models.provenance import (
    build_case_research_provenance,
    summarize_run_research_provenance,
)
from evaluators.contract import RuleOrigin, validate_evaluation_rules
from observers import EvidenceCollector
from targets.adapters import (
    HttpTargetAdapter,
    McpJsonRpcTargetAdapter,
    OfflineStoredTargetAdapter,
)
from testing.evaluation_config import RunnerEvaluationConfig
from testing.executor import Executor
from testing.offline_stored_import import (
    BlindEvaluationDataset,
    BlindEvaluationRecord,
    build_offline_stored_datasets,
)
from testing.report_builder import build_summary, build_test_input
from testing.runner import Runner
from testing.testcase_binding import bind_testcase_variables
from testing.testcase_loader import TestCaseLoader
from workflow.response_policies import (
    DEFAULT_EVALUATION_SCOPES,
    POLICY_REVISION_KEYS,
    ResponsePolicyStore,
    normalize_policy_category,
)
import re

ROOT = Path(__file__).resolve().parents[3]

_SEMANTIC_LABELS_BY_CATEGORY: dict[str, list[str]] = {
    "goal_hijacking": ["ORIGINAL_GOAL", "ATTACKER_GOAL", "MIXED", "UNCLEAR"],
    "tool_misuse": ["UNSAFE_TOOL_INTENT", "TOOL_BOUNDARY_PRESERVED", "UNCLEAR"],
    "identity_privilege_abuse": [
        "FIRST_PARTY_IDENTITY_CLAIM",
        "FIRST_PARTY_AUTHORITY_CLAIM",
        "IDENTITY_BOUNDARY_PRESERVED",
        "UNCLEAR",
    ],
    "unexpected_code_execution": [
        "PROHIBITED_COMMAND_ARTIFACT",
        "RESPONSE_BOUNDARY_PRESERVED",
        "UNCLEAR",
    ],
}


def build_blind_record_testcase(
    record: BlindEvaluationRecord,
    *,
    category_override: str | None = None,
    policy_store: ResponsePolicyStore | None = None,
    policy_id: str | None = None,
    use_semantic: bool = True,
) -> tuple[TestCase, TestInput]:
    """Convert a Phase 1A BlindEvaluationRecord into a canonical TestCase + TestInput."""
    raw_cat = category_override or record.category
    if not raw_cat:
        raise ValueError(f"Case '{record.case_id}' has no ASI category; specify category_override.")
    category = normalize_policy_category(raw_cat)

    rule_prov_meta: dict[str, Any] = {"rule_origin": "none"}
    if policy_store is not None and policy_id is not None:
        expected_target = record.provenance.target_id
        reviewed = policy_store.require_reviewed(policy_id, target_id=expected_target)
        if reviewed.category != category:
            raise ValueError(
                f"Reviewed policy '{policy_id}' is for '{reviewed.category}', not '{category}'."
            )
        reviewed_rules = policy_store.reviewed_rules(reviewed)
        rule_prov_meta = {
            "rule_origin": "reviewed_policy" if reviewed_rules else "none",
            "reviewed_policy_id": reviewed.policy_id,
            "reviewed_policy_revision_sha256": reviewed.revision_sha256,
            "reviewed_policy_status": reviewed.review_status,
            "evaluation_scope": reviewed.draft.evaluation_scope,
        }
        if use_semantic:
            context = policy_store.to_trusted_context(reviewed)
            if category == "goal_hijacking":
                context.setdefault("source_text", record.prompt)
            evaluation_cfg: dict[str, Any] = {
                "strategy": "hybrid" if reviewed_rules else "semantic",
                "rules": [r.model_dump(mode="json") for r in reviewed_rules],
                "semantic": {
                    "enabled": True,
                    "skill": category,
                    "trusted_context": context,
                    "expected_labels": _SEMANTIC_LABELS_BY_CATEGORY[category],
                },
            }
        elif reviewed_rules:
            evaluation_cfg = {
                "strategy": "deterministic",
                "rules": [r.model_dump(mode="json") for r in reviewed_rules],
            }
        else:
            evaluation_cfg = {"strategy": "unavailable", "rules": []}
    else:
        evaluation_cfg = {"strategy": "unavailable", "rules": []}

    attack_module = "offline_stored" if policy_store is not None or category in {"identity_privilege_abuse", "unexpected_code_execution"} else category
    tc = TestCase(
        id=record.case_id,
        name=f"Offline stored case {record.case_id}" + (f" ({record.plugin_id})" if record.plugin_id else ""),
        category=category,
        attack_module=attack_module,
        objective=f"Evaluate stored {category} response without assuming unverified execution.",
        variables={"untrusted_source_prompt": record.prompt},
        evaluation=evaluation_cfg,
    )
    ti = TestInput(
        id=f"offline-{record.case_id}",
        prompt=record.prompt,
        parameters={
            "stored_record": record.model_dump(mode="json"),
            "request_id": record.response_id or record.case_id,
        },
        metadata={"evaluation_rule_provenance": rule_prov_meta},
    )
    return tc, ti


def build_offline_target_profile(dataset: BlindEvaluationDataset, *, target_id: str | None = None) -> TargetProfile:
    """Create a generic offline TargetProfile from dataset provenance."""
    first = dataset.records[0] if dataset.records else None
    resolved_id = target_id or (first.provenance.target_id if first and first.provenance.target_id else "offline-stored-target")
    return TargetProfile(
        id=resolved_id,
        name=f"Offline Stored Target ({resolved_id})",
        target_type="offline_stored",
        interface={"type": "offline", "adapter": "offline_stored", "config": {}},
        capabilities=["stored_response_replay"],
        capability_states={"stored_response_replay": "supported"},
    )


class _PassThroughDelivery(BaseAttackModule):
    """Preserves reviewed prompt text for offline replay and response-first live chat."""

    def prepare(self, testcase: TestCase, test_input: TestInput) -> TestInput:
        del testcase
        return test_input.model_copy(deep=True)


def run_generic_cases(
    *,
    mode: Literal["live", "offline"],
    target: TargetProfile,
    cases: Sequence[tuple[TestCase, TestInput]],
    output_dir: str | Path,
    evaluation_config: RunnerEvaluationConfig | None = None,
    judge_provider: Any = None,
    executor: Executor | None = None,
    collectors: Sequence[EvidenceCollector] = (),
    allowed_collector_roots: tuple[Path, ...] = (),
    allowed_collector_endpoints: tuple[str, ...] = (),
    require_complete_response: bool = True,
    generic_run_id: str | None = None,
    case_progress_callback: Any = None,
    target_revision_sha256: str | None = None,
    dataset_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Execute one or more cases through Runner -> Collectors -> HybridEvaluator -> Report."""
    out_root = Path(output_dir).resolve()
    runs_dir = out_root / "runs"
    runs_dir.mkdir(parents=True, exist_ok=True)

    resolved_executor = executor or Executor({
        "generic_http": HttpTargetAdapter(response_only_completion=True),
        "generic_mcp_jsonrpc": McpJsonRpcTargetAdapter(),
        "offline_stored": OfflineStoredTargetAdapter(),
    })
    registry = build_default_attack_module_registry()
    registry.register("offline_stored", _PassThroughDelivery())
    registry.register("direct_chat", _PassThroughDelivery())

    active_case_meta: dict[str, str] = {"case_id": "", "category": ""}

    def _on_runner_stage(stage: str) -> None:
        if callable(case_progress_callback) and active_case_meta["case_id"]:
            try:
                case_progress_callback({
                    "event": "case_stage",
                    "case_id": active_case_meta["case_id"],
                    "category": active_case_meta["category"],
                    "stage": stage,
                })
            except Exception:
                pass

    runner = Runner(
        executor=resolved_executor,
        attack_module_registry=registry,
        evaluation_config=evaluation_config or RunnerEvaluationConfig(),
        judge_provider=judge_provider,
        progress_sink=_on_runner_stage if callable(case_progress_callback) else None,
        require_complete_response_for_pass=require_complete_response,
        require_complete_response_for_fail=require_complete_response,
        collectors=collectors,
        allowed_collector_roots=allowed_collector_roots,
        allowed_collector_endpoints=allowed_collector_endpoints,
        include_submitted_prompt_preview=True,
    )

    verdict_counts: Counter[str] = Counter()
    case_summaries: list[dict[str, Any]] = []
    batch_id = f"batch-{uuid4().hex[:12]}"

    for idx, (testcase, test_input) in enumerate(cases):
        active_case_meta["case_id"] = testcase.id
        active_case_meta["category"] = testcase.category
        if callable(case_progress_callback):
            try:
                case_progress_callback({
                    "event": "case_started",
                    "index": idx,
                    "case_id": testcase.id,
                    "category": testcase.category,
                    "stage": "sending_request_to_target",
                })
            except Exception:
                pass

        result = runner.run(testcase, target, test_input)
        snapshot = runner.last_report or {}
        run_id = str(snapshot.get("run_id") or uuid4().hex)
        envelope = build_summary(
            testcase,
            target,
            result,
            getattr(runner, "_execution_result", None),
            datetime.now(timezone.utc),
        )
        if target.interface.adapter == "generic_mcp_jsonrpc" and isinstance(test_input.parameters.get("tool_call"), dict):
            sent_material = json.dumps(test_input.parameters["tool_call"], sort_keys=True, separators=(",", ":"))
        else:
            sent_material = test_input.prompt or ""
        sent_payload_sha256 = sha256(sent_material.encode("utf-8")).hexdigest()
        stored_rec = test_input.parameters.get("stored_record")
        stored_prov = (
            runner.redact_report_value(target, dict(stored_rec["provenance"]))
            if isinstance(stored_rec, dict) and isinstance(stored_rec.get("provenance"), dict)
            else None
        )
        sanitized_dataset_meta = (
            runner.redact_report_value(target, dict(dataset_metadata))
            if isinstance(dataset_metadata, dict)
            else None
        )
        merged_ds_meta: dict[str, Any] = {}
        if isinstance(sanitized_dataset_meta, dict):
            merged_ds_meta.update(sanitized_dataset_meta)
        if stored_prov is not None:
            merged_ds_meta.update(stored_prov)
        case_prov = snapshot.get("research_provenance")
        if isinstance(case_prov, dict):
            ds_block = case_prov.get("dataset")
            if isinstance(ds_block, dict):
                ds_block["sent_payload_sha256"] = sent_payload_sha256
                if ds_block.get("dataset_id") is None and merged_ds_meta.get("dataset_id"):
                    ds_block["dataset_id"] = merged_ds_meta.get("dataset_id")
                if ds_block.get("dataset_revision_sha256") is None:
                    rev_sha = merged_ds_meta.get("dataset_revision_sha256") or merged_ds_meta.get("source_file_sha256")
                    if isinstance(rev_sha, str) and len(rev_sha) == 64:
                        ds_block["dataset_revision_sha256"] = rev_sha
                if ds_block.get("source_filename") is None and merged_ds_meta.get("source_filename"):
                    ds_block["source_filename"] = merged_ds_meta.get("source_filename")
                if ds_block.get("source_tool") is None and merged_ds_meta.get("source_tool"):
                    ds_block["source_tool"] = merged_ds_meta.get("source_tool")
            tgt_block = case_prov.get("target")
            if isinstance(tgt_block, dict) and target_revision_sha256 and tgt_block.get("target_revision_sha256") is None:
                tgt_block["target_revision_sha256"] = target_revision_sha256
            snapshot["research_provenance"] = runner.redact_report_value(target, case_prov)
        envelope["evaluation"] = snapshot
        envelope["source_provenance"] = "synthetic_mock" if mode == "offline" else "target_observation"
        envelope["batch_provenance"] = runner.redact_report_value(target, {
            "execution_mode": mode,
            "batch_id": batch_id,
            **({"generic_run_id": generic_run_id} if generic_run_id else {}),
            "case_id": testcase.id,
            "run_id": run_id,
            "payload_ref": test_input.payload_ref,
            "sent_payload_sha256": sent_payload_sha256,
            **({"stored_provenance": stored_prov} if stored_prov is not None else {}),
        })
        report_file = runs_dir / f"native-{testcase.id}-{run_id}.secagent.json"
        report_bytes = (json.dumps(envelope, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
        report_file.write_bytes(report_bytes)

        verdict_counts[result.status.value] += 1
        ev_class = snapshot.get("evidence_classification") or {}
        judge_info = snapshot.get("judge") if isinstance(snapshot.get("judge"), dict) else {}
        obs_info = snapshot.get("observation") if isinstance(snapshot.get("observation"), dict) else {}
        resp_text = obs_info.get("response_text")
        case_summary = {
            "case_id": testcase.id,
            "run_id": run_id,
            "target_id": target.id,
            "category": testcase.category,
            "payload_ref": test_input.payload_ref,
            "sent_payload_sha256": sent_payload_sha256,
            "verdict": result.status.value,
            "reason": result.reason,
            "classification": judge_info.get("classification"),
            "judge_reason": judge_info.get("judge_reason"),
            "response_spans": judge_info.get("judge_evidence") or [],
            "semantic_invoked": bool(judge_info.get("semantic_invoked")),
            "request_sha256": judge_info.get("request_sha256"),
            "provider_duration_ms": judge_info.get("provider_duration_ms"),
            "provider_fault_code": judge_info.get("provider_fault_code"),
            "json_validation_status": judge_info.get("json_validation_status"),
            "provider_exit_code": judge_info.get("provider_exit_code"),
            "response_preview": (resp_text[:200] if isinstance(resp_text, str) else None),
            "evidence_level": result.evidence_level or ev_class.get("evidence_level"),
            "provenance_tiers": result.evidence_provenance or ev_class.get("provenance_tiers", []),
            "collector_diagnostics": snapshot.get("collector_diagnostics", []),
            "research_provenance": snapshot.get("research_provenance"),
            **({"stored_provenance": stored_prov} if stored_prov is not None else {}),
            "report_path": str(report_file),
        }
        case_summaries.append(case_summary)
        if callable(case_progress_callback):
            case_progress_callback({
                "event": "case_completed",
                "index": idx,
                "case_id": testcase.id,
                "case_summary": case_summary,
                "report_bytes": report_bytes,
                "report_doc": envelope,
                "test_input": test_input,
            })

    safe_batch_ds = (
        runner.redact_report_value(target, dict(dataset_metadata))
        if isinstance(dataset_metadata, dict)
        else None
    )
    run_provenance = runner.redact_report_value(
        target,
        summarize_run_research_provenance(
            [c.get("research_provenance") for c in case_summaries if isinstance(c.get("research_provenance"), dict)],
            target=target,
            target_revision_sha256=target_revision_sha256,
            dataset_id=safe_batch_ds.get("dataset_id") if isinstance(safe_batch_ds, dict) else None,
            dataset_revision_sha256=(
                (safe_batch_ds.get("dataset_revision_sha256") or safe_batch_ds.get("source_file_sha256"))
                if isinstance(safe_batch_ds, dict)
                else None
            ),
            dataset_name=safe_batch_ds.get("source_filename") if isinstance(safe_batch_ds, dict) else None,
        ),
    )
    batch_summary = {
        "schema_version": "secagent.generic_batch.v1",
        "batch_id": batch_id,
        "mode": mode,
        "target_id": target.id,
        "target_name": target.name,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "total_cases": len(case_summaries),
        "verdict_counts": dict(sorted(verdict_counts.items())),
        "research_provenance": run_provenance,
        "cases": case_summaries,
    }
    summary_path = out_root / "batch-summary.json"
    summary_path.write_text(json.dumps(batch_summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    batch_summary["summary_path"] = str(summary_path)
    return batch_summary


def _resolve_reviewed_policy_for_record(
    policy_store: ResponsePolicyStore,
    target_id: str,
    category: str,
) -> tuple[str, str]:
    """Resolve the single reviewed policy matching exact (target_id, category)."""
    matches = [
        p
        for p in policy_store.list_for_target(target_id, category=category)
        if p.review_status == "reviewed"
    ]
    if not matches:
        raise ValueError(
            f"No reviewed policy found for target_id={target_id!r}, category={category!r}. "
            f"Review the draft policy first via `python -m workflow.response_policies review`."
        )
    if len(matches) > 1:
        ids = ", ".join(m.policy_id for m in matches)
        raise ValueError(
            f"Multiple reviewed policies match target_id={target_id!r}, category={category!r} ({ids}); pass explicit --policy-id."
        )
    rec = policy_store.require_reviewed(matches[0].policy_id, target_id=target_id)
    return rec.policy_id, rec.draft.evaluation_scope


_UNVERIFIED_PROVENANCE = frozenset({"discovered_observed", "suggested_unverified"})


def resolve_trusted_context_for_target_category(
    *,
    target_id: str,
    norm_category: str,
    policy_store: ResponsePolicyStore | None,
    policy_id: str | None = None,
    app_ctx_row: dict[str, Any] | None = None,
    current_target_revision: str | None = None,
    allow_generic_stored_fallback: bool = False,
) -> tuple[dict[str, Any] | None, Any | None, str | None]:
    """Shared Web + CLI resolver for reviewed ResponsePolicyStore or operator-confirmed ApplicationContext.

    Target boundary:
    - By default (allow_generic_stored_fallback=False, required for all live targets),
      a target may ONLY receive policies explicitly reviewed for its exact target_id.
    - Explicit offline stored-response compatibility (allow_generic_stored_fallback=True)
      permits falling back to policies reviewed for 'generic-stored-target' only.
      Policies reviewed for any other named target are always rejected.
    """
    allowed_policy_targets = (
        {target_id, "generic-stored-target"} if allow_generic_stored_fallback else {target_id}
    )
    reviewed_policy = None
    if policy_store is not None:
        if policy_id:
            try:
                rec = policy_store.get(policy_id)
                if rec.target_id not in allowed_policy_targets:
                    return None, None, "policy_review_required"
                reviewed_policy = policy_store.require_reviewed(policy_id, target_id=rec.target_id)
            except (FileNotFoundError, ValueError):
                return None, None, "policy_review_required"
            if reviewed_policy.category != norm_category:
                return None, None, "policy_category_mismatch"
        else:
            candidates = [
                p for p in policy_store.list_for_target(target_id, category=norm_category)
                if p.review_status == "reviewed"
            ]
            if not candidates and allow_generic_stored_fallback:
                candidates = [
                    p for p in policy_store.list_for_target("generic-stored-target", category=norm_category)
                    if p.review_status == "reviewed"
                ]
            if candidates:
                chosen = candidates[-1]
                reviewed_policy = policy_store.require_reviewed(chosen.policy_id, target_id=chosen.target_id)

    verified_app_draft: dict[str, Any] | None = None
    app_rev_sha: str | None = None
    has_unverified_fields = False

    if isinstance(app_ctx_row, dict) and app_ctx_row.get("provenance") == "operator_declared":
        raw_draft = app_ctx_row.get("draft")
        if isinstance(raw_draft, dict):
            if current_target_revision and raw_draft.get("target_revision") != current_target_revision:
                if reviewed_policy is None:
                    return None, None, "application_context_stale"
            else:
                prov_map = raw_draft.get("field_provenance")
                prov_dict = prov_map if isinstance(prov_map, dict) else {}
                cleaned_draft: dict[str, Any] = {}
                for k, v in raw_draft.items():
                    if k in {"target_id", "target_revision", "field_provenance"}:
                        cleaned_draft[k] = v
                        continue
                    if prov_dict.get(k) in _UNVERIFIED_PROVENANCE:
                        if isinstance(v, str) and v.strip():
                            has_unverified_fields = True
                        cleaned_draft[k] = ""
                    else:
                        cleaned_draft[k] = v
                verified_app_draft = cleaned_draft
                app_rev_sha = str(app_ctx_row.get("revision_sha256") or "")

    if reviewed_policy is not None and policy_store is not None:
        ctx = policy_store.to_trusted_context(reviewed_policy)
        if verified_app_draft is not None and app_rev_sha:
            ctx["context_source"] = "reviewed_policy_with_application_context"
            ctx["application_details"] = verified_app_draft
            ctx["application_context_id"] = f"appctx-{target_id}"
            ctx["application_context_sha256"] = app_rev_sha
            ctx["application_context_revision_sha256"] = app_rev_sha
            ctx["application_context_provenance"] = "operator_declared"
        return ctx, reviewed_policy, None

    if verified_app_draft is not None and app_rev_sha:
        purpose = str(verified_app_draft.get("purpose") or "").strip()
        general_boundary = (
            str(verified_app_draft.get("prohibited_resources") or "").strip()
            or str(verified_app_draft.get("trust_boundaries") or "").strip()
            or str(verified_app_draft.get("high_risk_actions") or "").strip()
            or str(verified_app_draft.get("operational_constraints") or "").strip()
        )
        if not purpose or not general_boundary:
            return None, None, ("unverified_discovery_metadata_rejected" if has_unverified_fields else "policy_review_required")

        if norm_category == "identity_privilege_abuse":
            id_boundary = (
                str(verified_app_draft.get("users") or "").strip()
                or str(verified_app_draft.get("authorized_actions") or "").strip()
                or str(verified_app_draft.get("authorization_required") or "").strip()
                or str(verified_app_draft.get("trust_boundaries") or "").strip()
            )
            if not id_boundary:
                return None, None, "policy_review_required"

        if norm_category == "unexpected_code_execution":
            exec_boundary = (
                str(verified_app_draft.get("prohibited_resources") or "").strip()
                or str(verified_app_draft.get("high_risk_actions") or "").strip()
                or str(verified_app_draft.get("trust_boundaries") or "").strip()
            )
            if not exec_boundary:
                return None, None, "policy_review_required"

        rev_key = POLICY_REVISION_KEYS[norm_category]
        prohibited = (
            verified_app_draft.get("prohibited_resources")
            or verified_app_draft.get("high_risk_actions")
            or verified_app_draft.get("business_restrictions")
            or general_boundary
        )
        allowed = (
            purpose
            + (f" Features: {verified_app_draft['features']}." if verified_app_draft.get("features") else "")
            + (f" Allowed resources: {verified_app_draft['allowed_resources']}." if verified_app_draft.get("allowed_resources") else "")
        )
        boundary = (
            verified_app_draft.get("trust_boundaries")
            or verified_app_draft.get("operational_constraints")
            or verified_app_draft.get("required_instructions")
            or general_boundary
        )
        raw_tools = str(verified_app_draft.get("available_tools") or "")
        tool_list = [t.strip() for t in re.split(r"[,;\n]+", raw_tools) if t.strip()]
        ctx = {
            "evaluation_scope": DEFAULT_EVALUATION_SCOPES[norm_category],
            "context_source": "application_context",
            "policy_id": f"appctx-{target_id}",
            "reviewed_policy_id": None,
            "reviewed_policy_revision_sha256": None,
            rev_key: app_rev_sha,
            "policy_review_status": "reviewed",
            "delivery_surface": "direct_chat",
            "allowed_benign_context": allowed,
            "expected_response_boundary": boundary,
            "application_details": verified_app_draft,
            "application_context_id": f"appctx-{target_id}",
            "application_context_sha256": app_rev_sha,
            "application_context_revision_sha256": app_rev_sha,
            "application_context_provenance": "operator_declared",
        }
        if norm_category == "goal_hijacking":
            ctx["original_goal"] = allowed
            ctx["attacker_goal"] = prohibited
            ctx["trust_boundary"] = boundary
            ctx["prohibited_goal_behavior"] = prohibited
        elif norm_category == "tool_misuse":
            ctx["prohibited_tool_behavior"] = prohibited
            ctx["authorized_tools"] = tool_list
        elif norm_category == "identity_privilege_abuse":
            ctx["prohibited_identity_claim"] = prohibited
            ctx["prohibited_authority_claim"] = prohibited
            ctx["asi03_policy_id"] = f"appctx-{target_id}"
        elif norm_category == "unexpected_code_execution":
            ctx["prohibited_command_behavior"] = prohibited
            ctx["asi05_policy_id"] = f"appctx-{target_id}"
        return ctx, None, None

    if has_unverified_fields:
        return None, None, "unverified_discovery_metadata_rejected"
    return None, None, "policy_review_required"


def prepare_generic_case_pair(
    *,
    mode: Literal["live", "offline"],
    target: TargetProfile,
    case_id: str,
    norm_category: str,
    prompt: str,
    trusted_context: dict[str, Any] | None = None,
    reviewed_rules: Sequence[EvaluationRule | dict[str, Any]] | None = None,
    rule_origin: RuleOrigin | None = None,
    reviewed_policy: Any | None = None,
    evaluation_strategy: Literal["deterministic", "action", "semantic", "hybrid", "unavailable"] | None = None,
    imported_assertions_count: int = 0,
    stored_response: str | None = None,
    finish_reason: str | None = None,
    response_complete: bool | None = None,
    tool_calls: list[dict[str, Any]] | None = None,
    response_id: str | None = None,
    target_model: str | None = None,
    required_capability: str | None = None,
    tool_name: str | None = None,
    source_provenance: dict[str, Any] | None = None,
    environment: dict[str, Any] | None = None,
    repository_root: Path = ROOT,
) -> tuple[TestCase, TestInput]:
    """Unified TestCase + TestInput builder shared by Web GenericRunService and CLI generic_runner."""
    eval_scope: str | None = None
    if isinstance(trusted_context, dict) and isinstance(trusted_context.get("evaluation_scope"), str):
        eval_scope = trusted_context["evaluation_scope"]
    elif reviewed_policy is not None and hasattr(reviewed_policy, "draft"):
        eval_scope = getattr(reviewed_policy.draft, "evaluation_scope", None)

    validated_rules: list[EvaluationRule] = []
    if reviewed_rules:
        validated_rules, diagnostics = validate_evaluation_rules(
            reviewed_rules,
            evaluation_scope=eval_scope,
        )
        if diagnostics:
            summary = "; ".join(f"{d.code}: {d.message}" for d in diagnostics)
            raise ValueError(f"invalid_evaluation_rule_contract: {summary}")

    serialized_rules = [r.model_dump(mode="json") for r in validated_rules]
    if trusted_context is not None:
        ctx = {**trusted_context}
        if norm_category == "goal_hijacking":
            ctx.setdefault("source_text", prompt)
        eval_cfg: dict[str, Any] = {
            "strategy": evaluation_strategy or ("hybrid" if serialized_rules else "semantic"),
            "rules": serialized_rules,
            "semantic": {
                "enabled": True,
                "skill": norm_category,
                "trusted_context": ctx,
                "expected_labels": _SEMANTIC_LABELS_BY_CATEGORY[norm_category],
            },
        }
    elif serialized_rules:
        eval_cfg = {
            "strategy": evaluation_strategy or "deterministic",
            "rules": serialized_rules,
        }
    else:
        eval_cfg = {"strategy": "unavailable", "rules": []}

    effective_origin: RuleOrigin = (
        rule_origin
        if rule_origin is not None
        else ("reviewed_policy" if (serialized_rules and reviewed_policy is not None) else ("native_testcase" if serialized_rules else "none"))
    )
    rule_prov_meta: dict[str, Any] = {
        "rule_origin": effective_origin,
        "imported_assertions_non_executable_count": max(0, int(imported_assertions_count or 0)),
    }
    if reviewed_policy is not None:
        rule_prov_meta["reviewed_policy_id"] = getattr(reviewed_policy, "policy_id", None)
        rule_prov_meta["reviewed_policy_revision_sha256"] = getattr(reviewed_policy, "revision_sha256", None)
        rule_prov_meta["reviewed_policy_status"] = getattr(reviewed_policy, "review_status", None)
        if eval_scope is not None:
            rule_prov_meta["evaluation_scope"] = eval_scope

    if mode == "live":
        variables: dict[str, Any] = {"untrusted_source_prompt": prompt}
        if tool_name:
            variables["tool_name"] = tool_name
        base_tc = TestCase(
            id=case_id,
            name=f"Generic Live {norm_category} · {case_id}",
            category=norm_category,
            attack_module="direct_chat",
            objective=f"Evaluate {norm_category} response under reviewed target policy.",
            variables=variables,
            evaluation=eval_cfg,
        )
        bound_tc, ti = build_live_case_and_input(
            base_tc,
            target,
            prompt_override=prompt,
            environment=environment,
            repository_root=repository_root,
        )
        params = {**ti.parameters, "request_id": response_id or case_id}
        if isinstance(required_capability, str) and required_capability.strip():
            params["required_capability"] = required_capability.strip()
        meta = {**ti.metadata, "evaluation_rule_provenance": rule_prov_meta}
        ti = ti.model_copy(update={"parameters": params, "metadata": meta})
        return bound_tc, ti

    if not isinstance(stored_response, str):
        raise ValueError("generic_stored_response_required_for_offline")
    eff_finish = finish_reason.strip() if isinstance(finish_reason, str) and finish_reason.strip() else None
    is_complete = resolve_response_completeness(
        finish_reason=eff_finish,
        explicit_response_complete=response_complete if isinstance(response_complete, bool) else None,
        is_offline=True,
    )
    tc = TestCase(
        id=case_id,
        name=f"Generic Offline {norm_category} · {case_id}",
        category=norm_category,
        attack_module="offline_stored",
        objective=f"Evaluate {norm_category} response under reviewed target policy.",
        variables={"untrusted_source_prompt": prompt},
        evaluation=eval_cfg,
    )
    safe_prov: dict[str, Any] = {}
    if isinstance(source_provenance, dict):
        for p_key in (
            "source_tool",
            "adapter_name",
            "dataset_id",
            "source_filename",
            "source_file_sha256",
            "source_eval_id",
            "source_timestamp",
            "provider_label",
        ):
            val = source_provenance.get(p_key)
            if isinstance(val, str) and val.strip():
                safe_prov[p_key] = val.strip()
    if "source_tool" not in safe_prov or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", safe_prov["source_tool"]):
        safe_prov["source_tool"] = "canonical_stored_json"

    params = {
        "request_id": response_id or case_id,
        "stored_record": {
            "case_id": case_id,
            "prompt": prompt,
            "stored_response": stored_response,
            "finish_reason": eff_finish,
            "response_complete": is_complete,
            "tool_calls": tool_calls or [],
            "response_id": response_id,
            "target_model": target_model,
            "provenance": safe_prov,
        },
    }
    if isinstance(required_capability, str) and required_capability.strip():
        params["required_capability"] = required_capability.strip()
    ti = TestInput(
        id=f"offline-{case_id}-{uuid4().hex[:8]}",
        prompt=prompt,
        parameters=params,
        metadata={"evaluation_rule_provenance": rule_prov_meta},
    )
    return tc, ti


def build_live_case_and_input(
    testcase: TestCase,
    target: TargetProfile,
    *,
    prompt_override: str | None = None,
    environment: dict[str, Any] | None = None,
    policy_store: ResponsePolicyStore | None = None,
    policy_id: str | None = None,
    category_override: str | None = None,
    repository_root: Path = ROOT,
) -> tuple[TestCase, TestInput]:
    """Bind payloads, parameters, environment prerequisites, and optional reviewed policy for live CLI."""
    bound_tc = bind_testcase_variables(testcase, None)
    if prompt_override is not None:
        parameters: dict[str, Any] = {}
        if target.interface.adapter == "generic_mcp_jsonrpc":
            tool_name = bound_tc.variables.get("tool_name")
            if not isinstance(tool_name, str) or not tool_name.strip():
                raise ValueError("MCP testcase requires a tool_name variable.")
            parameters = {
                "tool_call": {
                    "name": tool_name,
                    "arguments": {"command": prompt_override},
                }
            }
        test_input = TestInput(
            id=f"live-{uuid4().hex[:12]}",
            prompt=prompt_override,
            parameters=parameters,
            environment=dict(environment or {}),
        )
    elif len(bound_tc.payload_refs) == 1:
        test_input = build_test_input(bound_tc, target, repository_root=repository_root)
        test_input = test_input.model_copy(
            update={
                "id": f"live-{uuid4().hex[:12]}",
                "environment": dict(environment or {}),
            }
        )
    elif isinstance(bound_tc.variables.get("untrusted_source_prompt"), str) and bound_tc.variables["untrusted_source_prompt"].strip():
        explicit_prompt = str(bound_tc.variables["untrusted_source_prompt"])
        parameters = {}
        if target.interface.adapter == "generic_mcp_jsonrpc":
            tool_name = bound_tc.variables.get("tool_name")
            if not isinstance(tool_name, str) or not tool_name.strip():
                raise ValueError("MCP testcase requires a tool_name variable.")
            parameters = {
                "tool_call": {
                    "name": tool_name,
                    "arguments": {"command": explicit_prompt},
                }
            }
        test_input = TestInput(
            id=f"live-{uuid4().hex[:12]}",
            prompt=explicit_prompt,
            parameters=parameters,
            environment=dict(environment or {}),
        )
    else:
        raise ValueError(
            f"Testcase '{bound_tc.id}' has no payload_refs or explicit --prompt; refusing to send testcase objective."
        )

    if target.interface.adapter == "generic_mcp_jsonrpc":
        tool_call = test_input.parameters.get("tool_call")
        if not isinstance(tool_call, dict) or not tool_call.get("name"):
            raise ValueError("Direct MCP target requires structured TestInput.parameters['tool_call'].")

    if policy_store is not None and policy_id:
        reviewed = policy_store.require_reviewed(policy_id, target_id=target.id)
        norm_cat = normalize_policy_category(category_override or bound_tc.category)
        if reviewed.category != norm_cat:
            raise ValueError(f"Reviewed policy '{policy_id}' is for '{reviewed.category}', not '{norm_cat}'.")
        trusted_ctx = policy_store.to_trusted_context(reviewed)
        if norm_cat == "goal_hijacking":
            trusted_ctx.setdefault("source_text", test_input.prompt or "")
        policy_rules = policy_store.reviewed_rules(reviewed)
        combined_rules = list(bound_tc.evaluation.rules) + list(policy_rules)
        if combined_rules:
            validated_combined, diags = validate_evaluation_rules(
                combined_rules,
                evaluation_scope=reviewed.draft.evaluation_scope,
            )
            if diags:
                summary = "; ".join(f"{d.code}: {d.message}" for d in diags)
                raise ValueError(f"invalid_evaluation_rule_contract: {summary}")
        else:
            validated_combined = []
        updates: dict[str, Any] = {
            "category": norm_cat,
            "evaluation": EvaluationConfig.model_validate({
                "strategy": "hybrid" if validated_combined else "semantic",
                "rules": [r.model_dump(mode="json") for r in validated_combined],
                "semantic": {
                    "enabled": True,
                    "skill": norm_cat,
                    "trusted_context": trusted_ctx,
                    "expected_labels": _SEMANTIC_LABELS_BY_CATEGORY[norm_cat],
                },
            }),
        }
        # Allow response-only live runs for ASI03/ASI05 when operator explicitly uses a response-first policy without action env.
        if (
            norm_cat in {"identity_privilege_abuse", "unexpected_code_execution"}
            and trusted_ctx.get("evaluation_scope") in {"identity_claim_response", "response_command_artifact"}
            and not test_input.environment
        ):
            updates["attack_module"] = "direct_chat"
        bound_tc = bound_tc.model_copy(update=updates)

    # Preflight check: validate attack module prerequisites (e.g. ASI03 baseline / ASI05 sandbox) BEFORE calling Target.
    if bound_tc.attack_module not in {"direct_chat", "offline_stored"}:
        preflight_reg = build_default_attack_module_registry()
        preflight_reg.resolve(bound_tc.attack_module).prepare(bound_tc, test_input)

    serialized_input = json.dumps(
        {"prompt": test_input.prompt, "parameters": test_input.parameters},
        default=str,
    )
    if "{{" in serialized_input:
        raise ValueError("Unbound template placeholder remains in live TestInput.")

    return bound_tc, test_input


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SecAgent Generic Live & Offline Runner (CLI-first).")
    parser.add_argument("--mode", required=True, choices=["offline", "live"])
    parser.add_argument("--output-dir", required=True, help="Directory for per-case reports and batch summary.")
    parser.add_argument("--input", help="Offline dataset path (JSON/JSONL or Promptfoo report) for --mode offline.")
    parser.add_argument("--dataset", help="Imported/external dataset path (JSON/YAML/JSONL or Promptfoo report) for --mode live or --mode offline.")
    parser.add_argument("--testcase", help="Single YAML testcase path for --mode live.")
    parser.add_argument("--target", help="TargetProfile JSON/YAML file path for --mode live.")
    parser.add_argument("--prompt", default=None, help="Explicit prompt override for --mode live.")
    parser.add_argument("--env-file", default=None, help="Optional JSON/YAML environment/sandbox/authorization context file for --mode live.")
    parser.add_argument("--repository-root", default=None, help="Optional repository root override for payload lookup.")
    parser.add_argument("--category", default=None, help="Optional ASI category filter/override.")
    parser.add_argument("--target-id", default=None, help="Optional target_id filter in --mode offline.")
    parser.add_argument("--policy-dir", default=None, help="Optional ResponsePolicyStore directory.")
    parser.add_argument("--policy-id", default=None, help="Optional reviewed policy ID in --policy-dir.")
    parser.add_argument("--app-context", default=None, help="Optional saved ApplicationContext JSON file path.")
    parser.add_argument(
        "--group-by-target-policy",
        action="store_true",
        help="Offline mode: group records by (target_id, category) and bind each group to its exact reviewed policy.",
    )
    parser.add_argument("--use-judge", action="store_true", help="Enable real PiEvaluatorProvider semantic Judge.")
    parser.add_argument("--pi-provider", default="deepseek", help="Pi provider name (default: deepseek).")
    parser.add_argument("--pi-model", default="deepseek-v4-flash", help="Pi model name (default: deepseek-v4-flash).")
    parser.add_argument("--pi-timeout", type=float, default=60.0, help="Pi timeout seconds (default: 60).")
    parser.add_argument("--no-pi-auth-file", action="store_true", help="Disable reading ~/.pi/agent/auth.json.")
    parser.add_argument("--allowed-collector-root", action="append", default=[], help="Allowed root dir for file/log collectors.")
    parser.add_argument("--allowed-collector-endpoint", action="append", default=[], help="Allowed endpoint URL for HTTP callback collectors.")
    parser.add_argument("--limit", type=int, default=0, help="Optional max cases to run (0 = all).")
    args = parser.parse_args(argv)

    policy_store = ResponsePolicyStore(args.policy_dir) if args.policy_dir else None
    app_ctx_row: dict[str, Any] | None = None
    if args.app_context:
        app_ctx_row = json.loads(Path(args.app_context).read_text(encoding="utf-8-sig"))
    collector_roots = tuple(Path(p).resolve() for p in args.allowed_collector_root if p.strip())
    collector_endpoints = tuple(u.strip() for u in args.allowed_collector_endpoint if u.strip())
    repo_root = Path(args.repository_root).resolve() if args.repository_root else ROOT

    def build_eval_and_provider(call_budget: int):
        if not args.use_judge:
            return RunnerEvaluationConfig(), None
        from integrations.external_evaluator.pi import PiEvaluatorConfig, PiEvaluatorProvider
        import shutil

        pi_exe = shutil.which("pi")
        if not pi_exe:
            raise ValueError("Pi executable ('pi') not found on PATH.")
        pi_cfg = PiEvaluatorConfig(
            executable=pi_exe,
            provider=args.pi_provider,
            model=args.pi_model,
            timeout_seconds=args.pi_timeout,
            max_output_bytes=65536,
            use_pi_auth_file=not args.no_pi_auth_file,
        )
        eval_cfg = RunnerEvaluationConfig(
            mode="hybrid",
            judge_enabled=True,
            allow_live_judge=True,
            max_judge_calls=max(1, call_budget),
            pi=pi_cfg,
            require_complete_response_for_semantic=True,
        )
        return eval_cfg, PiEvaluatorProvider(pi_cfg)

    if args.mode == "offline":
        offline_input = args.input or args.dataset
        if not offline_input:
            raise ValueError("--input or --dataset is required in offline mode.")
        cat_arg = None if args.group_by_target_policy else args.category
        blind_ds, _, _, _ = build_offline_stored_datasets(offline_input, category=cat_arg)
        records = list(blind_ds.records)
        if args.target_id:
            records = [r for r in records if r.provenance.target_id == args.target_id]
        if args.group_by_target_policy and args.category:
            wanted_cat = normalize_policy_category(args.category)
            records = [r for r in records if r.category and normalize_policy_category(r.category) == wanted_cat]
        if args.limit and args.limit > 0:
            records = records[: args.limit]
        if not records:
            raise ValueError("No matching offline stored records to evaluate.")

        if args.group_by_target_policy:
            if policy_store is None:
                raise ValueError("--group-by-target-policy requires --policy-dir.")
            grouped: dict[tuple[str, str, str, str], list[BlindEvaluationRecord]] = {}
            for rec in records:
                t_id = rec.provenance.target_id
                if not t_id or not rec.category:
                    raise ValueError(f"Record '{rec.case_id}' missing target_id or category for policy grouping.")
                norm_cat = normalize_policy_category(rec.category)
                pol_id, scope = _resolve_reviewed_policy_for_record(policy_store, t_id, norm_cat)
                grouped.setdefault((t_id, norm_cat, scope, pol_id), []).append(rec)

            out_root = Path(args.output_dir).resolve()
            out_root.mkdir(parents=True, exist_ok=True)
            all_cases: list[dict[str, Any]] = []
            group_summaries: list[dict[str, Any]] = []
            verdict_totals: Counter[str] = Counter()

            for idx, ((t_id, norm_cat, scope, pol_id), grp_records) in enumerate(grouped.items(), start=1):
                grp_target = TargetProfile(
                    id=t_id,
                    name=f"Offline Stored Target ({t_id})",
                    target_type="offline_stored",
                    interface={"type": "offline", "adapter": "offline_stored", "config": {}},
                    capabilities=["stored_response_replay"],
                    capability_states={"stored_response_replay": "supported"},
                )
                grp_cases = [
                    build_blind_record_testcase(
                        rec,
                        policy_store=policy_store,
                        policy_id=pol_id,
                    )
                    for rec in grp_records
                ]
                eval_cfg, provider = build_eval_and_provider(len(grp_cases))
                grp_dir = out_root / f"group-{idx}-{t_id}-{norm_cat}"
                grp_summary = run_generic_cases(
                    mode="offline",
                    target=grp_target,
                    cases=grp_cases,
                    output_dir=grp_dir,
                    evaluation_config=eval_cfg,
                    judge_provider=provider,
                    allowed_collector_roots=collector_roots,
                    allowed_collector_endpoints=collector_endpoints,
                )
                for k, v in grp_summary["verdict_counts"].items():
                    verdict_totals[k] += v
                all_cases.extend(grp_summary["cases"])
                group_summaries.append({
                    "target_id": t_id,
                    "category": norm_cat,
                    "evaluation_scope": scope,
                    "policy_id": pol_id,
                    "total_cases": grp_summary["total_cases"],
                    "verdict_counts": grp_summary["verdict_counts"],
                    "summary_path": grp_summary["summary_path"],
                })

            summary = {
                "schema_version": "secagent.generic_grouped_batch.v1",
                "mode": "offline",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "total_cases": len(all_cases),
                "verdict_counts": dict(sorted(verdict_totals.items())),
                "groups": group_summaries,
                "cases": all_cases,
            }
            combined_path = out_root / "grouped-batch-summary.json"
            combined_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
            summary["summary_path"] = str(combined_path)
        else:
            target = build_offline_target_profile(blind_ds, target_id=args.target_id)
            if app_ctx_row is not None:
                cases = []
                for rec in records:
                    raw_cat = args.category or rec.category
                    if not raw_cat:
                        raise ValueError(f"Case '{rec.case_id}' has no ASI category; specify --category.")
                    norm_cat = normalize_policy_category(raw_cat)
                    trusted_ctx, rev_pol, blocker = resolve_trusted_context_for_target_category(
                        target_id=target.id,
                        norm_category=norm_cat,
                        policy_store=policy_store,
                        policy_id=args.policy_id,
                        app_ctx_row=app_ctx_row,
                        allow_generic_stored_fallback=True,
                    )
                    if blocker:
                        raise ValueError(blocker)
                    rev_rules = (
                        policy_store.reviewed_rules(rev_pol)
                        if (policy_store is not None and rev_pol is not None)
                        else []
                    )
                    effective_ctx = trusted_ctx if args.use_judge else None
                    cases.append(
                        prepare_generic_case_pair(
                            mode="offline",
                            target=target,
                            case_id=rec.case_id,
                            norm_category=norm_cat,
                            prompt=rec.prompt,
                            trusted_context=effective_ctx,
                            reviewed_rules=rev_rules,
                            rule_origin="reviewed_policy" if rev_rules else "none",
                            reviewed_policy=rev_pol,
                            stored_response=rec.stored_response,
                            finish_reason=rec.finish_reason,
                            response_complete=rec.response_complete,
                            tool_calls=rec.tool_calls,
                            response_id=rec.response_id,
                            target_model=rec.target_model,
                            source_provenance=rec.provenance.model_dump(mode="json"),
                        )
                    )
            else:
                cases = [
                    build_blind_record_testcase(
                        rec,
                        category_override=args.category,
                        policy_store=policy_store,
                        policy_id=args.policy_id,
                    )
                    for rec in records
                ]
            eval_cfg, provider = build_eval_and_provider(len(cases))
            summary = run_generic_cases(
                mode="offline",
                target=target,
                cases=cases,
                output_dir=args.output_dir,
                evaluation_config=eval_cfg,
                judge_provider=provider,
                allowed_collector_roots=collector_roots,
                allowed_collector_endpoints=collector_endpoints,
            )
    else:
        if not args.target or (not args.testcase and not args.dataset):
            raise ValueError("--target and either --testcase or --dataset are required in live mode.")
        raw_target_text = Path(args.target).read_text(encoding="utf-8-sig")
        raw_target_obj = yaml.safe_load(raw_target_text) if Path(args.target).suffix.lower() in {".yaml", ".yml"} else json.loads(raw_target_text)
        target = TargetProfile.model_validate(raw_target_obj)
        env_ctx: dict[str, Any] = {}
        if args.env_file:
            env_path = Path(args.env_file)
            raw_env = env_path.read_text(encoding="utf-8-sig")
            parsed_env = yaml.safe_load(raw_env) if env_path.suffix.lower() in {".yaml", ".yml"} else json.loads(raw_env)
            if not isinstance(parsed_env, dict):
                raise ValueError("--env-file must parse to a JSON/YAML mapping.")
            env_ctx = parsed_env

        if args.dataset:
            from workflow.dataset_models import infer_testcase_asi_code
            from workflow.dataset_normalizer import normalize_dataset

            ds_path = Path(args.dataset)
            envelope = normalize_dataset(ds_path.read_bytes(), ds_path.name)
            ds_cases = list(envelope.testcases)
            if args.limit and args.limit > 0:
                ds_cases = ds_cases[: args.limit]
            live_pairs: list[tuple[TestCase, TestInput]] = []
            for item in ds_cases:
                inferred_cat = infer_testcase_asi_code(item, fallback_run_id=envelope.run_id)
                eff_cat_raw = args.category or (inferred_cat if inferred_cat != "unmapped" else None)
                if not eff_cat_raw:
                    raise ValueError(f"Case '{item.testcase_id}' has unmapped ASI category; pass --category or metadata.asi_category.")
                norm_cat = normalize_policy_category(eff_cat_raw)
                trusted_ctx = None
                rev_pol = None
                rev_rules: list[EvaluationRule] = []
                if policy_store is not None or app_ctx_row is not None:
                    trusted_ctx, rev_pol, blocker = resolve_trusted_context_for_target_category(
                        target_id=target.id,
                        norm_category=norm_cat,
                        policy_store=policy_store,
                        policy_id=args.policy_id,
                        app_ctx_row=app_ctx_row,
                        allow_generic_stored_fallback=False,
                    )
                    if blocker and (args.use_judge or args.policy_id or app_ctx_row is not None):
                        raise ValueError(blocker)
                    if policy_store is not None and rev_pol is not None:
                        rev_rules = policy_store.reviewed_rules(rev_pol)
                effective_ctx = trusted_ctx if args.use_judge else None
                b_tc, b_ti = prepare_generic_case_pair(
                    mode="live",
                    target=target,
                    case_id=item.testcase_id,
                    norm_category=norm_cat,
                    prompt=item.prompt,
                    trusted_context=effective_ctx,
                    reviewed_rules=rev_rules,
                    rule_origin="reviewed_policy" if rev_rules else "none",
                    reviewed_policy=rev_pol,
                    imported_assertions_count=len(item.assertions) if isinstance(item.assertions, list) else 0,
                    environment=env_ctx,
                    repository_root=repo_root,
                )
                live_pairs.append((b_tc, b_ti))
            eval_cfg, provider = build_eval_and_provider(len(live_pairs))
            summary = run_generic_cases(
                mode="live",
                target=target,
                cases=live_pairs,
                output_dir=args.output_dir,
                evaluation_config=eval_cfg,
                judge_provider=provider,
                allowed_collector_roots=collector_roots,
                allowed_collector_endpoints=collector_endpoints,
            )
        else:
            tc = TestCaseLoader().load(args.testcase)
            bound_tc, ti = build_live_case_and_input(
                tc,
                target,
                prompt_override=args.prompt,
                environment=env_ctx,
                policy_store=policy_store,
                policy_id=args.policy_id,
                category_override=args.category,
                repository_root=repo_root,
            )
            eval_cfg, provider = build_eval_and_provider(1)
            summary = run_generic_cases(
                mode="live",
                target=target,
                cases=[(bound_tc, ti)],
                output_dir=args.output_dir,
                evaluation_config=eval_cfg,
                judge_provider=provider,
                allowed_collector_roots=collector_roots,
                allowed_collector_endpoints=collector_endpoints,
            )

    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

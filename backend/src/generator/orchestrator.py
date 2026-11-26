"""Generate & Run Backend Orchestration Service (G11.6 — Mode 1 Primary Workflow).

Implements SecAgent's end-to-end automated pipeline without any manual Preview/Edit/Save gate:
    Configure -> Generate -> Validate -> Auto-Save Dataset -> Preflight -> Execute -> Evaluate -> Report

Architectural boundaries & G12 isolation invariants:
- NEVER imports from `evaluators`, `integrations`, `observers`, `targets`, or `testing`.
- Delegates ALL Target execution, Evidence collection, Judge evaluation, and Resume
  checkpointing to SecAgent's existing `GenericRunService` through a clean Protocol seam.
- NEVER creates a second Runner or a second Judge.
- Auto-persists validated datasets directly via `DatasetNormalizer` and `DatasetRepository`
  (reusing canonical G11 provenance contracts) BEFORE any Target execution begins.
- R01: Enforces fail-closed partial generation AND fail-closed partial execution guards
  after Runner preflight (never silently executes a subset when cases are unsupported/skipped).
- R02: Supports immediate workflow acceptance + live status lookup by workflow_id or
  submission_id from acceptance through Generation, Persistence, Preflight, Execution,
  Evaluation, and Reporting for idempotent network recovery.
- R03: Strictly sanitizes all external exception text and blocker strings through an
  allowlisted error catalog; never leaks raw exception text, headers, tokens, or secrets.
- R04: Tracks effective evaluation_mode per run/rerun so Judge error detection, provenance,
  and rerun history always reflect the actual mode used by the active execution.
"""

from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import json
import re
from threading import Event, RLock, Thread
from typing import Any, Callable, Literal, Protocol, runtime_checkable
from uuid import uuid4

from pydantic import Field, field_validator

from generator.constants import AsiCode, GENERATOR_SOURCE_TOOL
from generator.models import StrictGeneratorModel, normalize_asi_code
from generator.preview_store import (
    MAX_DATASET_NAME_CHARS,
    _sanitize_dataset_filename,
    serialize_generation_result_to_dataset_json,
)
from generator.providers.base import ProviderErrorCategory, TokenUsage
from generator.quality_evaluator import evaluate_generation_result
from generator.readiness import assess_target_readiness, build_context_snapshot
from generator.request_builder import SupportedLanguage
from generator.service import (
    GenerationResult,
    GenerationServiceError,
    GenerationServiceRequest,
    GeneratorService,
)
from workflow.dataset_normalizer import DatasetValidationError, normalize_dataset
from workflow.dataset_repository import DatasetRepository

WORKFLOW_STAGES: tuple[str, ...] = (
    "generating",
    "validating",
    "saving_dataset",
    "preflight",
    "executing",
    "evaluating",
    "reporting",
)

WorkflowStageName = Literal[
    "generating",
    "validating",
    "saving_dataset",
    "preflight",
    "executing",
    "evaluating",
    "reporting",
]
StageStatus = Literal["pending", "running", "completed", "failed", "blocked", "skipped"]
WorkflowOverallStatus = Literal[
    "running",
    "completed",
    "failed",
    "blocked",
    "partial_stopped",
]
EvaluationMode = Literal["rule_only", "hybrid"]
ExecutionMode = Literal["live"]

_WORKFLOW_ID_RE = re.compile(r"^gnr-[a-f0-9]{32}$")
_HEX32_RE = re.compile(r"^[a-f0-9]{32}$")
_HEX64_RE = re.compile(r"^[a-f0-9]{64}$")
_SAFE_ERROR_CODE_RE = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
_REVIEWED_AUTH_STATUSES = {"reviewed_for_offline_configuration", "reviewed", "authorized"}
DEFAULT_MAX_WORKFLOWS = 64

# R03: Explicit allowlist of normalized runner/preflight/evaluation error codes.
# Raw exception text outside this exact catalog is NEVER forwarded to API/snapshots/reports.
_PREFLIGHT_ERROR_CODES: frozenset[str] = frozenset({
    "preflight_failed",
    "generic_target_not_found",
    "dataset_not_found",
    "generic_invalid_mode",
    "generic_invalid_target_id",
    "generic_asi_category_required",
    "generic_too_many_cases",
    "generic_missing_prompt",
    "generic_no_executable_cases",
    "generic_target_revision_stale",
    "generic_session_credential_stale",
    "generic_session_credential_authorization_required",
    "generic_submission_conflict",
    "generic_submission_in_progress",
    "generic_submission_init_failed",
    "generic_submission_record_unavailable",
    "generic_collector_root_not_allowed",
    "generic_authorization_required",
    "generic_managed_target_override_forbidden",
    "credential_unavailable",
    "policy_review_required",
    "policy_category_mismatch",
    "unmapped_asi_category",
    "application_context_stale",
    "unverified_discovery_metadata_rejected",
    "unreviewed_inline_rules_rejected",
    "invalid_evaluation_rule_contract",
    "partial_execution_not_authorized",
})

_EVALUATION_ERROR_CODES: frozenset[str] = frozenset({
    "judge_provider_unavailable",
    "judge_evaluation_error",
    "judge_timeout",
    "judge_credential_missing",
    "judge_executable_missing",
    "judge_configuration_missing",
})

_EXECUTION_ERROR_CODES: frozenset[str] = frozenset({
    "runner_execution_failed",
    "runner_failed",
    "runner_interrupted",
    "runner_cancelled",
    "dispatch_checkpoint_write_failed",
    "persistence_integrity_failed",
})

_ALL_ALLOWED_RUNNER_ERROR_CODES: frozenset[str] = (
    _PREFLIGHT_ERROR_CODES | _EVALUATION_ERROR_CODES | _EXECUTION_ERROR_CODES
)

_SAFE_PUBLIC_ERROR_MESSAGES: dict[str, str] = {
    "preflight_failed": "Execution preflight failed; persisted dataset was not executed.",
    "generic_target_not_found": "Selected target was not found during execution preflight.",
    "dataset_not_found": "Persisted dataset was not found in DatasetRepository.",
    "generic_no_executable_cases": "No executable testcases passed Generic Runner preflight.",
    "generic_target_revision_stale": "Target profile revision changed between generation and preflight.",
    "generic_session_credential_stale": "Target session credential changed; refresh target authentication before running.",
    "generic_session_credential_authorization_required": "Target session credential authorization is required before execution.",
    "generic_submission_conflict": "Submission ID conflicted with an existing runner submission.",
    "generic_submission_in_progress": "Runner submission is already in progress.",
    "generic_collector_root_not_allowed": "Configured evidence collector directory is outside allowed roots.",
    "credential_unavailable": "Required target credential is unavailable in the local session or server environment.",
    "policy_review_required": "A reviewed ResponsePolicy is required before executing this target.",
    "policy_category_mismatch": "Selected ResponsePolicy does not match the testcase ASI category.",
    "unmapped_asi_category": "One or more testcases could not be mapped to a supported ASI category.",
    "application_context_stale": "Application Context is stale relative to the current target revision.",
    "unverified_discovery_metadata_rejected": "Unverified discovery metadata cannot authorize execution.",
    "unreviewed_inline_rules_rejected": "Unreviewed inline evaluation rules are rejected.",
    "invalid_evaluation_rule_contract": "Reviewed ResponsePolicy contains an invalid evaluation rule contract.",
    "partial_execution_not_authorized": "Runner preflight skipped one or more testcases; partial execution is blocked unless explicitly allowed.",
    "judge_provider_unavailable": "Hybrid Judge provider is unavailable; configure server Judge credentials or explicitly select rule_only.",
    "judge_evaluation_error": "Hybrid Judge reported an evaluation error; inspect the run report.",
    "judge_timeout": "Hybrid Judge timed out during evaluation; inspect the run report.",
    "judge_credential_missing": "Hybrid Judge credential is missing on the server.",
    "judge_executable_missing": "Hybrid Judge executable is unavailable on the server.",
    "judge_configuration_missing": "Hybrid Judge configuration is missing on the server.",
    "runner_execution_failed": "Generic Runner failed during execution; persisted dataset remains saved.",
    "runner_failed": "Generic Runner ended in failed state.",
    "runner_interrupted": "Generic Runner execution was interrupted; inspect checkpoint resume eligibility.",
    "runner_cancelled": "Generic Runner execution was cancelled.",
    "dispatch_checkpoint_write_failed": "Runner failed to write execution checkpoint safely.",
    "persistence_integrity_failed": "Run report persistence integrity verification failed.",
}


def _sanitize_runner_error_code(
    raw_value: Any,
    *,
    default_code: str,
    default_stage: WorkflowStageName,
) -> tuple[str, WorkflowStageName, int, str]:
    """Normalize an external error/blocker into a bounded, secret-free code, stage, HTTP status, and message."""
    candidate = str(raw_value or "").strip() if raw_value is not None else ""
    if (
        candidate
        and len(candidate) <= 64
        and _SAFE_ERROR_CODE_RE.fullmatch(candidate)
        and candidate in _ALL_ALLOWED_RUNNER_ERROR_CODES
    ):
        code = candidate
    else:
        code = default_code

    if code in _EVALUATION_ERROR_CODES:
        stage: WorkflowStageName = "evaluating"
        http_status = 409
    elif code in _PREFLIGHT_ERROR_CODES:
        stage = "preflight"
        http_status = 404 if code in {"generic_target_not_found", "dataset_not_found"} else 409
    elif code in _EXECUTION_ERROR_CODES:
        stage = "executing"
        http_status = 500 if code in {"dispatch_checkpoint_write_failed", "persistence_integrity_failed"} else 409
    else:
        stage = default_stage
        http_status = 500 if default_stage == "executing" else 409

    message = _SAFE_PUBLIC_ERROR_MESSAGES.get(
        code,
        _SAFE_PUBLIC_ERROR_MESSAGES.get(default_code, "Generate & Run encountered a stage failure."),
    )
    return code, stage, http_status, message


def _sanitize_skipped_cases(raw_skipped: Any) -> tuple[dict[str, Any], ...]:
    """Extract only bounded, secret-free metadata for preflight-skipped/unsupported testcases."""
    if not isinstance(raw_skipped, list):
        return ()
    out: list[dict[str, Any]] = []
    for item in raw_skipped[:100]:
        if not isinstance(item, dict):
            continue
        case_id = str(item.get("case_id") or "")[:96]
        status = str(item.get("status") or "skipped")[:32]
        raw_reason = str(item.get("reason") or "skipped").strip()
        if _SAFE_ERROR_CODE_RE.fullmatch(raw_reason):
            reason = raw_reason
        else:
            reason = "unsupported_or_skipped"
        out.append({"case_id": case_id, "status": status, "reason": reason})
    return tuple(out)


@runtime_checkable
class GenericRunRunnerProtocol(Protocol):
    """Minimal supported interface to SecAgent's existing GenericRunService."""

    def judge_status(self) -> dict[str, Any]: ...

    def preview_run(self, payload: dict[str, Any]) -> dict[str, Any]: ...

    def start_run(self, payload: dict[str, Any]) -> dict[str, Any]: ...

    def get_run(self, run_id: str) -> dict[str, Any] | None: ...


class OrchestrationError(ValueError):
    """Structured, secret-free error for Generate & Run orchestration failures."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        status_code: int = 400,
        stage: WorkflowStageName | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
        self.stage = stage


class GenerateAndRunRequest(StrictGeneratorModel):
    """Strict validated request contract for Mode 1 (Generate & Run)."""

    target_id: str = Field(min_length=1, max_length=128)
    counts_by_asi: dict[str, int]
    language: SupportedLanguage = "en"
    focus_note: str | None = Field(default=None, max_length=1000)
    requested_scopes: dict[str, str] = Field(default_factory=dict)
    policy_ids_by_asi: dict[str, str] = Field(default_factory=dict)
    deduplicate_across_asi: bool = Field(default=False, strict=True)
    max_calls_per_asi: int = Field(default=1, ge=1, le=2, strict=True)
    timeout_seconds: float | None = Field(default=None, gt=0.0, le=120.0, allow_inf_nan=False)
    evaluation_mode: EvaluationMode = "rule_only"
    execution_mode: ExecutionMode = "live"
    authorization_confirmed: bool = Field(strict=True)
    allow_partial_execution: bool = Field(default=False, strict=True)
    dataset_name: str | None = Field(default=None, min_length=1, max_length=MAX_DATASET_NAME_CHARS)
    submission_id: str | None = Field(default=None, pattern=r"^[a-f0-9]{32}$")
    async_execution: bool = Field(default=False, strict=True)
    expected_target_revision: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    expected_session_credential_generation: str | None = Field(default=None, pattern=r"^[a-f0-9]{32}$")

    @field_validator("target_id")
    @classmethod
    def check_target_id(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("target_id must not be blank.")
        return cleaned

    @field_validator("dataset_name")
    @classmethod
    def check_dataset_name(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("dataset_name must not be blank.")
        return cleaned

    def to_generation_request(self) -> GenerationServiceRequest:
        return GenerationServiceRequest(
            target_id=self.target_id,
            counts_by_asi=self.counts_by_asi,
            language=self.language,
            focus_note=self.focus_note,
            requested_scopes=self.requested_scopes,
            policy_ids_by_asi=self.policy_ids_by_asi,
            deduplicate_across_asi=self.deduplicate_across_asi,
            max_calls_per_asi=self.max_calls_per_asi,
            timeout_seconds=self.timeout_seconds,
        )


class GenerateAndRunRerunRequest(StrictGeneratorModel):
    """Strict request contract to rerun a persisted Generate & Run dataset WITHOUT regeneration."""

    authorization_confirmed: bool = Field(strict=True)
    evaluation_mode: EvaluationMode | None = None
    allow_partial_execution: bool | None = Field(default=None, strict=True)
    submission_id: str | None = Field(default=None, pattern=r"^[a-f0-9]{32}$")
    async_execution: bool = Field(default=False, strict=True)
    expected_target_revision: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    expected_session_credential_generation: str | None = Field(default=None, pattern=r"^[a-f0-9]{32}$")


class WorkflowStageRecord(StrictGeneratorModel):
    """Execution status of a single stage in the Generate & Run pipeline."""

    stage: WorkflowStageName
    status: StageStatus = "pending"
    started_at: str | None = None
    finished_at: str | None = None
    detail: str | None = None
    error_code: str | None = None
    error_message: str | None = None


class RerunHistoryEntry(StrictGeneratorModel):
    """Record of a dataset rerun (new run_id, zero Generator calls)."""

    operation: Literal["rerun"] = "rerun"
    run_id: str
    previous_run_id: str | None = None
    dataset_id: str
    evaluation_mode: EvaluationMode
    started_at: str
    run_status: str
    generator_called: Literal[False] = False
    regenerated: Literal[False] = False


class GenerateAndRunSnapshot(StrictGeneratorModel):
    """Immutable, secret-free status & provenance snapshot of a Generate & Run workflow."""

    workflow_id: str = Field(pattern=r"^gnr-[a-f0-9]{32}$")
    mode: Literal["generate_and_run"] = "generate_and_run"
    submission_id: str | None = None
    idempotent_replay: bool = False
    status: WorkflowOverallStatus
    current_stage: WorkflowStageName
    created_at: str
    updated_at: str
    completed_at: str | None = None

    # Target & configuration binding
    target_id: str
    target_revision_sha256: str | None = None
    application_context_revision_sha256: str | None = None
    context_snapshot_sha256: str | None = None
    selected_asi: tuple[AsiCode, ...]
    requested_scopes: dict[str, str] = Field(default_factory=dict)
    policy_ids_by_asi: dict[str, str] = Field(default_factory=dict)
    language: SupportedLanguage = "en"
    evaluation_mode: EvaluationMode
    initial_evaluation_mode: EvaluationMode
    execution_mode: ExecutionMode = "live"
    allow_partial_execution: bool = False

    # Stage progress
    stages: tuple[WorkflowStageRecord, ...]

    # 1) Generation outcome (strictly separate from execution & verdict)
    generation_id: str | None = None
    provider_id: str | None = None
    model: str | None = None
    generation_overall_status: str | None = None
    requested_count: int = 0
    generated_count: int = 0
    accepted_count: int = 0
    rejected_count: int = 0
    meets_requested_counts: bool = False
    partial_generation: bool = False
    rejection_reason_counts: dict[str, int] = Field(default_factory=dict)
    asi_generation_summaries: dict[str, dict[str, Any]] = Field(default_factory=dict)
    generation_token_usage: TokenUsage | None = None
    quality_summary: dict[str, Any] | None = None

    # 2) Auto-persisted dataset reference
    auto_persisted: bool = False
    dataset_id: str | None = None
    dataset_name: str | None = None
    dataset_file_sha256: str | None = None
    testcase_ids: tuple[str, ...] = ()

    # 2b) Preflight execution coverage (R01: explicitly separated from partial_generation)
    partial_execution: bool = False
    preflight_selected_cases: int = 0
    preflight_ready_count: int = 0
    preflight_skipped_count: int = 0
    preflight_unsupported_count: int = 0
    preflight_skipped_reasons: tuple[dict[str, Any], ...] = ()

    # 3) Runner execution & 4) Evaluation/Judge verdict (strictly separate from generation)
    run_id: str | None = None
    run_status: str | None = None
    executed_cases: int = 0
    total_cases: int = 0
    progress_percent: int = 0
    verdict_counts: dict[str, int] = Field(default_factory=dict)
    verdict_schema_version: str | None = None
    verdict_policy_version: str | None = None
    evaluation_summary: dict[str, Any] | None = None
    evidence_summary: dict[str, Any] = Field(default_factory=dict)
    judge_metadata: dict[str, Any] | None = None
    evaluation_error_code: str | None = None
    cases_summary: tuple[dict[str, Any], ...] = ()

    # Navigation & Report linkage
    dataset_url: str | None = None
    report_url: str | None = None
    report_export_url: str | None = None

    # Rerun vs Resume semantics (strictly distinct)
    rerun_supported: bool = False
    rerun_history: tuple[RerunHistoryEntry, ...] = ()
    resume_supported: bool = False
    resume_endpoint: str | None = None
    resume_note: str = (
        "Rerun executes the persisted dataset under a new run_id with zero Generator calls. "
        "Resume continues an interrupted run from Generic Runner checkpoints without regenerating prompts."
    )

    # Error reporting
    error_stage: WorkflowStageName | None = None
    error_code: str | None = None
    error_message: str | None = None

    # Unified reproducibility provenance
    provenance: dict[str, Any] = Field(default_factory=dict)


def _hash_owner(owner_id: str) -> str:
    cleaned = (owner_id or "").strip()
    if not cleaned:
        raise OrchestrationError(
            "operator_authentication_required",
            "Operator authentication is required for Generate & Run workflows.",
            status_code=403,
        )
    return sha256(cleaned.encode("utf-8")).hexdigest()


def _request_fingerprint(req: GenerateAndRunRequest, service_req: GenerationServiceRequest) -> str:
    canonical = {
        "target_id": service_req.target_id,
        "counts_by_asi": {k: service_req.counts_by_asi[k] for k in sorted(service_req.counts_by_asi)},
        "language": service_req.language,
        "focus_note": service_req.focus_note,
        "requested_scopes": {
            k: service_req.requested_scopes[k] for k in sorted(service_req.requested_scopes)
        },
        "policy_ids_by_asi": {
            k: service_req.policy_ids_by_asi[k] for k in sorted(service_req.policy_ids_by_asi)
        },
        "deduplicate_across_asi": service_req.deduplicate_across_asi,
        "max_calls_per_asi": service_req.max_calls_per_asi,
        "evaluation_mode": req.evaluation_mode,
        "execution_mode": req.execution_mode,
        "allow_partial_execution": req.allow_partial_execution,
        "dataset_name": req.dataset_name,
    }
    encoded = json.dumps(
        canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")
    return sha256(encoded).hexdigest()


def _make_initial_stages() -> dict[WorkflowStageName, dict[str, Any]]:
    return {
        name: {
            "stage": name,
            "status": "pending",
            "started_at": None,
            "finished_at": None,
            "detail": None,
            "error_code": None,
            "error_message": None,
        }
        for name in WORKFLOW_STAGES
    }


def _map_judge_fault_to_code(raw_fault: Any) -> str:
    """Map GenericRunService / HybridEvaluator fault tokens onto allowlisted evaluation error codes."""
    token = str(raw_fault or "").strip().lower()
    if not token:
        return "judge_evaluation_error"
    if "timeout" in token:
        return "judge_timeout"
    if token in {"credential_missing", "judge_credential_missing"}:
        return "judge_credential_missing"
    if token in {"executable_missing", "judge_executable_missing"}:
        return "judge_executable_missing"
    if token in {"judge_configuration_missing", "configuration_missing"}:
        return "judge_configuration_missing"
    if token in {"judge_provider_unavailable", "provider_unavailable", "unavailable"}:
        return "judge_provider_unavailable"
    return token if token in _EVALUATION_ERROR_CODES else "judge_evaluation_error"


def _detect_judge_evaluation_issue(
    *,
    evaluation_mode: EvaluationMode,
    run_record: dict[str, Any],
) -> tuple[str | None, str | None]:
    """Inspect a completed/failed Generic Runner record for Judge/evaluation errors.

    Inspects BOTH G12 `GenericRunService._build_judge_metadata()` fields
    (`invocation_status`, `failure_count`, `error_categories`) and per-case
    Judge fault fields (`provider_fault_code`, `json_validation_status`), as well
    as legacy/synthetic `status`/`reason` fields.
    Uses the active run's effective `evaluation_mode` (R04) and sanitizes any
    external reason through the strict allowlist (R03).
    """
    if evaluation_mode != "hybrid":
        return None, None
    judge_meta = run_record.get("judge_metadata")
    if isinstance(judge_meta, dict):
        j_status = str(judge_meta.get("status") or "").lower()
        inv_status = str(judge_meta.get("invocation_status") or "").lower()
        failure_count = int(judge_meta.get("failure_count") or 0)
        raw_err_cats = judge_meta.get("error_categories")
        err_cats = [str(c).strip() for c in raw_err_cats if isinstance(c, str) and c.strip()] if isinstance(raw_err_cats, list) else []
        raw_reason = judge_meta.get("reason") or judge_meta.get("error_code")
        if (
            j_status in {"failed", "error", "unavailable"}
            or inv_status in {"failed", "partial_failure", "unknown_unverified"}
            or failure_count > 0
            or bool(err_cats)
        ):
            mapped_raw = (
                _map_judge_fault_to_code(err_cats[0])
                if err_cats
                else _map_judge_fault_to_code(raw_reason)
            )
            safe_code, _, _, safe_msg = _sanitize_runner_error_code(
                mapped_raw,
                default_code="judge_evaluation_error",
                default_stage="evaluating",
            )
            if failure_count > 0:
                safe_msg = (
                    f"{safe_msg} ({failure_count} testcase(s) failed semantic evaluation; "
                    f"invocation_status={inv_status or 'failed'})."
                )
            return safe_code, safe_msg
    cases = run_record.get("cases")
    if isinstance(cases, list):
        judge_error_cases = 0
        first_fault: str | None = None
        for item in cases:
            if not isinstance(item, dict):
                continue
            reason = str(item.get("reason") or item.get("evaluation_reason") or "").lower()
            j_err = item.get("judge_error") or item.get("evaluator_error")
            judge_status = str(item.get("judge_status") or "").lower()
            provider_fault = item.get("provider_fault_code")
            val_status = str(item.get("json_validation_status") or "").lower()
            verdict = str(item.get("verdict") or item.get("final_verdict") or "").upper()
            if (
                j_err
                or bool(provider_fault)
                or val_status == "provider_fault"
                or judge_status in {"error", "failed", "unavailable"}
                or ("judge" in reason and ("error" in reason or "fail" in reason or "unavailable" in reason))
                or (verdict == "ERROR" and "judge" in reason)
            ):
                judge_error_cases += 1
                if first_fault is None and provider_fault:
                    first_fault = str(provider_fault)
        if judge_error_cases > 0:
            mapped_code = _map_judge_fault_to_code(first_fault)
            safe_code, _, _, _ = _sanitize_runner_error_code(
                mapped_code,
                default_code="judge_evaluation_error",
                default_stage="evaluating",
            )
            return (
                safe_code,
                f"Hybrid Judge reported an evaluation error on {judge_error_cases} testcase(s); inspect run report.",
            )
    return None, None


def _summarize_cases(run_record: dict[str, Any]) -> tuple[dict[str, Any], ...]:
    cases = run_record.get("cases")
    if not isinstance(cases, list):
        return ()
    out: list[dict[str, Any]] = []
    for item in cases:
        if not isinstance(item, dict):
            continue
        raw_reason = item.get("reason")
        safe_reason = (
            raw_reason
            if isinstance(raw_reason, str) and len(raw_reason) <= 128 and _SAFE_ERROR_CODE_RE.fullmatch(raw_reason)
            else None
        )
        raw_fault = item.get("provider_fault_code")
        safe_fault = (
            raw_fault.strip()
            if isinstance(raw_fault, str) and _SAFE_ERROR_CODE_RE.fullmatch(raw_fault.strip())
            else None
        )
        raw_val_status = item.get("json_validation_status")
        safe_val_status = (
            raw_val_status.strip()
            if isinstance(raw_val_status, str) and _SAFE_ERROR_CODE_RE.fullmatch(raw_val_status.strip())
            else None
        )
        out.append(
            {
                "case_id": item.get("case_id") or item.get("testcase_id"),
                "asi_code": item.get("asi_code"),
                "category": item.get("category"),
                "verdict": item["verdict"] if "verdict" in item else item.get("final_verdict"),
                "evaluation_status": item.get("evaluation_status"),
                "evaluation_reason_code": item.get("evaluation_reason_code"),
                "status": item.get("status"),
                "evidence_level": item.get("evidence_level"),
                "evaluation_mode": item.get("evaluation_mode"),
                "semantic_invoked": bool(item["semantic_invoked"]) if "semantic_invoked" in item else None,
                "provider_fault_code": safe_fault,
                "json_validation_status": safe_val_status,
                "reason": safe_reason,
            }
        )
    return tuple(out)


def _sanitize_judge_metadata_for_snapshot(raw: Any) -> dict[str, Any] | None:
    """Keep only non-secret structured summary keys from runner judge_metadata."""
    if not isinstance(raw, dict):
        return None
    allowed_keys = (
        "mode",
        "enabled",
        "judge_configured",
        "credential_available",
        "judge_ready",
        "status",
        "invocation_status",
        "provider",
        "model",
        "request_count",
        "success_count",
        "failure_count",
        "error_categories",
        "invoked_cases",
        "evaluated_cases",
        "failed_cases",
        "timeout_cases",
        "unclear_cases",
        "reason",
    )
    out: dict[str, Any] = {}
    for k in allowed_keys:
        if k not in raw:
            continue
        val = raw[k]
        if k == "reason":
            if isinstance(val, str) and _SAFE_ERROR_CODE_RE.fullmatch(val.strip()):
                out[k] = val.strip()
            elif val is not None:
                out[k] = "judge_evaluation_error"
        elif k == "error_categories":
            if isinstance(val, list):
                cleaned_cats: list[str] = []
                for entry in val[:16]:
                    if isinstance(entry, str) and _SAFE_ERROR_CODE_RE.fullmatch(entry.strip()):
                        cleaned_cats.append(entry.strip())
                    elif entry is not None:
                        cleaned_cats.append("judge_evaluation_error")
                out[k] = cleaned_cats
        elif isinstance(val, (str, int, float, bool)) or val is None:
            out[k] = val[:128] if isinstance(val, str) else val
    return out


class _WorkflowEntry:
    def __init__(
        self,
        *,
        workflow_id: str,
        owner_digest: str,
        submission_id: str | None,
        request_digest: str,
        req: GenerateAndRunRequest,
        selected_asi: tuple[AsiCode, ...],
        requested_count: int,
        created_at: str,
    ) -> None:
        self.workflow_id = workflow_id
        self.owner_digest = owner_digest
        self.submission_id = submission_id
        self.request_digest = request_digest
        self.req = req
        self.active_evaluation_mode: EvaluationMode = req.evaluation_mode
        self.selected_asi = selected_asi
        self.requested_count = requested_count
        self.created_at = created_at
        self.updated_at = created_at
        self.completed_at: str | None = None

        self.status: WorkflowOverallStatus = "running"
        self.current_stage: WorkflowStageName = "generating"
        self.stages: dict[WorkflowStageName, dict[str, Any]] = _make_initial_stages()

        self.target_revision_sha256: str | None = None
        self.application_context_revision_sha256: str | None = None
        self.context_snapshot_sha256: str | None = None

        self.generation_id: str | None = None
        self.provider_id: str | None = None
        self.model: str | None = None
        self.generation_overall_status: str | None = None
        self.generated_count: int = 0
        self.accepted_count: int = 0
        self.rejected_count: int = 0
        self.meets_requested_counts: bool = False
        self.partial_generation: bool = False
        self.rejection_reason_counts: dict[str, int] = {}
        self.asi_generation_summaries: dict[str, dict[str, Any]] = {}
        self.generation_token_usage: TokenUsage | None = None
        self.quality_summary: dict[str, Any] | None = None
        self.reviewed_policies: dict[str, dict[str, str]] = {}

        self.auto_persisted: bool = False
        self.dataset_id: str | None = None
        self.dataset_name: str | None = None
        self.dataset_file_sha256: str | None = None
        self.testcase_ids: tuple[str, ...] = ()

        # R01: Preflight partial execution tracking (separate from partial_generation)
        self.partial_execution: bool = False
        self.preflight_selected_cases: int = 0
        self.preflight_ready_count: int = 0
        self.preflight_skipped_count: int = 0
        self.preflight_unsupported_count: int = 0
        self.preflight_skipped_reasons: tuple[dict[str, Any], ...] = ()

        self.run_id: str | None = None
        self.run_status: str | None = None
        self.executed_cases: int = 0
        self.total_cases: int = 0
        self.progress_percent: int = 0
        self.verdict_counts: dict[str, int] = {}
        self.verdict_schema_version: str | None = None
        self.verdict_policy_version: str | None = None
        self.evaluation_summary: dict[str, Any] | None = None
        self.evidence_summary: dict[str, Any] = {}
        self.judge_metadata: dict[str, Any] | None = None
        self.evaluation_error_code: str | None = None
        self.cases_summary: tuple[dict[str, Any], ...] = ()
        self.runner_asi_category: str = "auto"
        self.runner_policy_id: str | None = None
        self.runner_policy_ids_by_asi: dict[str, str] = {}
        self.rerun_history: list[RerunHistoryEntry] = []
        self.rerun_starting: bool = False

        self.error_stage: WorkflowStageName | None = None
        self.error_code: str | None = None
        self.error_message: str | None = None

    def mark_stage(
        self,
        stage: WorkflowStageName,
        status: StageStatus,
        now_iso: str,
        *,
        detail: str | None = None,
        error_code: str | None = None,
        error_message: str | None = None,
    ) -> None:
        st = self.stages[stage]
        if st["started_at"] is None and status in {"running", "completed", "failed", "blocked"}:
            st["started_at"] = now_iso
        if status in {"completed", "failed", "blocked", "skipped"}:
            st["finished_at"] = now_iso
        st["status"] = status
        if detail is not None:
            st["detail"] = detail
        if error_code is not None:
            st["error_code"] = error_code
        if error_message is not None:
            st["error_message"] = error_message
        if status in {"running", "completed"} and error_code is None:
            st["error_code"] = None
            st["error_message"] = None
        self.current_stage = stage
        self.updated_at = now_iso

    def skip_remaining_after(self, stage: WorkflowStageName, now_iso: str) -> None:
        seen = False
        for name in WORKFLOW_STAGES:
            if name == stage:
                seen = True
                continue
            if seen and self.stages[name]["status"] == "pending":
                self.stages[name]["status"] = "skipped"
                self.stages[name]["finished_at"] = now_iso

    def sync_from_run_record(
        self,
        run_record: dict[str, Any],
        now_iso: str,
        *,
        evaluation_mode: EvaluationMode | None = None,
    ) -> None:
        effective_mode: EvaluationMode = evaluation_mode or self.active_evaluation_mode
        self.active_evaluation_mode = effective_mode

        run_status = str(run_record.get("status") or "running").lower()
        self.run_status = run_status
        self.executed_cases = int(run_record.get("executed_cases") or 0)
        self.total_cases = int(run_record.get("total_cases") or len(self.testcase_ids))
        self.progress_percent = int(run_record.get("progress_percent") or 0)
        vc = run_record.get("verdict_counts")
        self.verdict_counts = {str(k): int(v) for k, v in vc.items()} if isinstance(vc, dict) else {}
        ev_sum = run_record.get("evaluation_summary")
        self.evaluation_summary = dict(ev_sum) if isinstance(ev_sum, dict) else None
        raw_vsv = run_record.get("verdict_schema_version") or (ev_sum.get("schema_version") if isinstance(ev_sum, dict) else None)
        raw_vpv = run_record.get("verdict_policy_version") or (ev_sum.get("policy_version") if isinstance(ev_sum, dict) else None)
        self.verdict_schema_version = str(raw_vsv) if isinstance(raw_vsv, str) and raw_vsv else None
        self.verdict_policy_version = str(raw_vpv) if isinstance(raw_vpv, str) and raw_vpv else None
        ev = run_record.get("evidence_summary")
        self.evidence_summary = dict(ev) if isinstance(ev, dict) else {}
        self.judge_metadata = _sanitize_judge_metadata_for_snapshot(run_record.get("judge_metadata"))
        self.cases_summary = _summarize_cases(run_record)
        self.updated_at = now_iso

        if self.rerun_history and self.rerun_history[-1].run_id == self.run_id:
            self.rerun_history[-1] = self.rerun_history[-1].model_copy(
                update={"run_status": run_status, "evaluation_mode": effective_mode}
            )

        if run_status in {"queued", "preparing", "running"}:
            self.status = "running"
            self.error_stage = None
            self.error_code = None
            self.error_message = None
            self.evaluation_error_code = None
            self.mark_stage("executing", "running", now_iso, detail=f"Executed {self.executed_cases}/{self.total_cases}")
            return

        if run_status == "completed":
            self.mark_stage(
                "executing",
                "completed",
                now_iso,
                detail=f"Executed {self.executed_cases}/{self.total_cases} testcase(s)",
            )
            judge_err_code, judge_err_msg = _detect_judge_evaluation_issue(
                evaluation_mode=effective_mode,
                run_record=run_record,
            )
            if judge_err_code is not None:
                self.evaluation_error_code = judge_err_code
                self.mark_stage(
                    "evaluating",
                    "failed",
                    now_iso,
                    error_code=judge_err_code,
                    error_message=judge_err_msg,
                )
                self.mark_stage(
                    "reporting",
                    "completed",
                    now_iso,
                    detail="Report persisted with evaluation error provenance.",
                )
                self.status = "failed"
                self.error_stage = "evaluating"
                self.error_code = judge_err_code
                self.error_message = judge_err_msg
                self.completed_at = now_iso
                return

            self.evaluation_error_code = None
            self.error_stage = None
            self.error_code = None
            self.error_message = None
            self.mark_stage(
                "evaluating",
                "completed",
                now_iso,
                detail=f"Mode: {effective_mode}; verdicts: {self.verdict_counts}",
            )
            self.mark_stage(
                "reporting",
                "completed",
                now_iso,
                detail=f"Run report persisted as {self.run_id}",
            )
            self.status = "completed"
            self.completed_at = now_iso
            return

        # failed / interrupted / cancelled
        raw_err = run_record.get("error_code") or f"runner_{run_status}"
        safe_code, stage, _, safe_msg = _sanitize_runner_error_code(
            raw_err,
            default_code="runner_execution_failed",
            default_stage="executing",
        )
        if stage == "evaluating":
            self.mark_stage("executing", "completed", now_iso)
            self.evaluation_error_code = safe_code
            self.mark_stage("evaluating", "failed", now_iso, error_code=safe_code, error_message=safe_msg)
            self.skip_remaining_after("evaluating", now_iso)
        else:
            self.mark_stage("executing", "failed", now_iso, error_code=safe_code, error_message=safe_msg)
            self.skip_remaining_after("executing", now_iso)
        self.status = "failed"
        self.error_stage = stage
        self.error_code = safe_code
        self.error_message = safe_msg
        self.completed_at = now_iso

    def to_snapshot(self, *, idempotent_replay: bool = False) -> GenerateAndRunSnapshot:
        resumable = bool(
            self.run_id
            and self.run_status in {"interrupted", "failed", "cancelled"}
            and self.executed_cases < self.total_cases
        )
        provenance: dict[str, Any] = {
            "workflow_id": self.workflow_id,
            "workflow_mode": "generate_and_run",
            "target_id": self.req.target_id,
            "target_revision_sha256": self.target_revision_sha256,
            "application_context_revision_sha256": self.application_context_revision_sha256,
            "context_snapshot_sha256": self.context_snapshot_sha256,
            "generation_id": self.generation_id,
            "generator_provider_id": self.provider_id,
            "generator_model": self.model,
            "dataset_id": self.dataset_id,
            "dataset_file_sha256": self.dataset_file_sha256,
            "dataset_source_tool": GENERATOR_SOURCE_TOOL if self.dataset_id else None,
            "run_id": self.run_id,
            "selected_asi": list(self.selected_asi),
            "testcase_ids": list(self.testcase_ids),
            "counts": {
                "requested": self.requested_count,
                "generated": self.generated_count,
                "accepted": self.accepted_count,
                "rejected": self.rejected_count,
            },
            "partial_generation": self.partial_generation,
            "partial_execution": self.partial_execution,
            "preflight_coverage": {
                "selected_cases": self.preflight_selected_cases,
                "ready_count": self.preflight_ready_count,
                "skipped_count": self.preflight_skipped_count,
                "unsupported_count": self.preflight_unsupported_count,
                "skipped_reasons": list(self.preflight_skipped_reasons),
            },
            "evaluation_mode": self.active_evaluation_mode,
            "initial_evaluation_mode": self.req.evaluation_mode,
            "reviewed_policies": dict(self.reviewed_policies),
            "judge_metadata": self.judge_metadata,
            "evidence_summary": self.evidence_summary,
            "verdict_counts": self.verdict_counts,
            "verdict_schema_version": self.verdict_schema_version,
            "verdict_policy_version": self.verdict_policy_version,
            "evaluation_summary": self.evaluation_summary,
            "rerun_count": len(self.rerun_history),
        }
        return GenerateAndRunSnapshot(
            workflow_id=self.workflow_id,
            submission_id=self.submission_id,
            idempotent_replay=idempotent_replay,
            status=self.status,
            current_stage=self.current_stage,
            created_at=self.created_at,
            updated_at=self.updated_at,
            completed_at=self.completed_at,
            target_id=self.req.target_id,
            target_revision_sha256=self.target_revision_sha256,
            application_context_revision_sha256=self.application_context_revision_sha256,
            context_snapshot_sha256=self.context_snapshot_sha256,
            selected_asi=self.selected_asi,
            requested_scopes=dict(self.req.requested_scopes),
            policy_ids_by_asi=dict(self.req.policy_ids_by_asi),
            language=self.req.language,
            evaluation_mode=self.active_evaluation_mode,
            initial_evaluation_mode=self.req.evaluation_mode,
            execution_mode=self.req.execution_mode,
            allow_partial_execution=self.req.allow_partial_execution,
            stages=tuple(WorkflowStageRecord(**self.stages[name]) for name in WORKFLOW_STAGES),
            generation_id=self.generation_id,
            provider_id=self.provider_id,
            model=self.model,
            generation_overall_status=self.generation_overall_status,
            requested_count=self.requested_count,
            generated_count=self.generated_count,
            accepted_count=self.accepted_count,
            rejected_count=self.rejected_count,
            meets_requested_counts=self.meets_requested_counts,
            partial_generation=self.partial_generation,
            rejection_reason_counts=dict(self.rejection_reason_counts),
            asi_generation_summaries=dict(self.asi_generation_summaries),
            generation_token_usage=self.generation_token_usage,
            quality_summary=self.quality_summary,
            auto_persisted=self.auto_persisted,
            dataset_id=self.dataset_id,
            dataset_name=self.dataset_name,
            dataset_file_sha256=self.dataset_file_sha256,
            testcase_ids=self.testcase_ids,
            partial_execution=self.partial_execution,
            preflight_selected_cases=self.preflight_selected_cases,
            preflight_ready_count=self.preflight_ready_count,
            preflight_skipped_count=self.preflight_skipped_count,
            preflight_unsupported_count=self.preflight_unsupported_count,
            preflight_skipped_reasons=self.preflight_skipped_reasons,
            run_id=self.run_id,
            run_status=self.run_status,
            executed_cases=self.executed_cases,
            total_cases=self.total_cases,
            progress_percent=self.progress_percent,
            verdict_counts=dict(self.verdict_counts),
            verdict_schema_version=self.verdict_schema_version,
            verdict_policy_version=self.verdict_policy_version,
            evaluation_summary=dict(self.evaluation_summary) if isinstance(self.evaluation_summary, dict) else None,
            evidence_summary=dict(self.evidence_summary),
            judge_metadata=self.judge_metadata,
            evaluation_error_code=self.evaluation_error_code,
            cases_summary=self.cases_summary,
            dataset_url="#datasets" if self.dataset_id else None,
            report_url=f"#scan/{self.run_id}" if self.run_id else None,
            report_export_url=f"/api/testing/generic-runs/{self.run_id}/report.json" if self.run_id else None,
            rerun_supported=bool(
                self.dataset_id
                and self.status != "running"
                and self.run_status not in {"queued", "preparing", "running"}
                and not self.rerun_starting
            ),
            rerun_history=tuple(self.rerun_history),
            resume_supported=resumable,
            resume_endpoint=f"/api/testing/generic-runs/{self.run_id}/resume/preview" if self.run_id else None,
            error_stage=self.error_stage,
            error_code=self.error_code,
            error_message=self.error_message,
            provenance=provenance,
        )


class GenerateAndRunOrchestrator:
    """Thread-safe coordinator for Mode 1 (Generate & Run) backed by existing SecAgent services."""

    def __init__(
        self,
        *,
        generator_service: GeneratorService,
        dataset_repo: DatasetRepository,
        catalog: Any,
        application_contexts: Any | None,
        generic_run_service: GenericRunRunnerProtocol | None,
        policy_store: Any | None = None,
        normalizer: Callable[[bytes, str], Any] = normalize_dataset,
        max_workflows: int = DEFAULT_MAX_WORKFLOWS,
        wall_clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._generator_service = generator_service
        self._dataset_repo = dataset_repo
        self._catalog = catalog
        self._application_contexts = application_contexts
        self._generic_run_service = generic_run_service
        self._policy_store = policy_store
        self._normalizer = normalizer
        self._max_workflows = max_workflows
        self._wall_clock = wall_clock or (lambda: datetime.now(timezone.utc))
        self._lock = RLock()
        self._workflows: dict[str, _WorkflowEntry] = {}
        self._submissions: dict[str, tuple[str, str, str]] = {}  # sub_id -> (owner_digest, req_digest, workflow_id)
        self._in_flight_submissions: dict[str, tuple[str, str, Event]] = {}

    @property
    def available(self) -> bool:
        return self._generic_run_service is not None

    def judge_status(self) -> dict[str, Any] | None:
        """Expose non-secret Judge readiness metadata from GenericRunService for UI default selection."""
        if self._generic_run_service is None:
            return None
        try:
            raw = self._generic_run_service.judge_status()
            if not isinstance(raw, dict):
                return None
            return {
                "judge_configured": bool(raw.get("judge_configured")),
                "credential_available": bool(raw.get("credential_available")),
                "judge_ready": bool(raw.get("judge_ready")),
                "provider": raw.get("provider") if isinstance(raw.get("provider"), str) else None,
                "model": raw.get("model") if isinstance(raw.get("model"), str) else None,
                "reason": raw.get("reason") if isinstance(raw.get("reason"), str) else "unknown",
            }
        except Exception:
            return {
                "judge_configured": False,
                "credential_available": False,
                "judge_ready": False,
                "provider": None,
                "model": None,
                "reason": "judge_status_unavailable",
            }

    def _now_iso(self) -> str:
        return self._wall_clock().isoformat()

    def _lookup_target(self, target_id: str) -> Any | None:
        if self._catalog is None:
            return None
        if hasattr(self._catalog, "get"):
            return self._catalog.get(target_id)
        targets = getattr(self._catalog, "_targets", None)
        if isinstance(targets, dict):
            return targets.get(target_id)
        return None

    def _is_target_authorized(self, target_id: str, preset: Any) -> bool:
        """Check whether a managed target has been explicitly reviewed/authorized (fail closed)."""
        if self._catalog is not None and hasattr(self._catalog, "public_targets"):
            try:
                for entry in self._catalog.public_targets():
                    if isinstance(entry, dict) and entry.get("id") == target_id:
                        status = entry.get("authorization_status")
                        if status is not None:
                            return str(status) in _REVIEWED_AUTH_STATUSES
            except Exception:
                return False
        reviewed_flag = getattr(preset, "reviewed", None)
        if isinstance(reviewed_flag, bool):
            return reviewed_flag
        auth_status = getattr(preset, "authorization_status", None)
        if auth_status is not None:
            return str(auth_status) in _REVIEWED_AUTH_STATUSES
        return False

    def _evict_if_full_locked(self) -> None:
        if len(self._workflows) < self._max_workflows:
            return
        completed = [
            w for w in self._workflows.values() if w.status in {"completed", "failed", "blocked", "partial_stopped"}
        ]
        if completed:
            oldest = min(completed, key=lambda w: w.created_at)
            self._workflows.pop(oldest.workflow_id, None)

    def _persist_generated_dataset(
        self,
        *,
        workflow_id: str,
        result: GenerationResult,
        dataset_name: str | None,
        allow_partial_execution: bool,
    ) -> tuple[str, str, str, tuple[str, ...]]:
        """Auto-persist validated candidates through DatasetNormalizer + DatasetRepository."""
        raw_name = dataset_name or f"g11-{result.target_id}-{result.generation_id[:12]}.json"
        safe_name = _sanitize_dataset_filename(raw_name)
        raw_bytes = serialize_generation_result_to_dataset_json(
            result=result,
            workflow_id=workflow_id,
            partial_execution_confirmed=allow_partial_execution and not result.meets_requested_counts,
        )
        try:
            normalized = self._normalizer(raw_bytes, safe_name)
        except (DatasetValidationError, ValueError, TypeError):
            raise OrchestrationError(
                "dataset_normalization_failed",
                "Auto-save dataset normalization failed; execution aborted.",
                status_code=500,
                stage="saving_dataset",
            ) from None

        try:
            saved_envelope, _ = self._dataset_repo.save_dataset(normalized)
            verified = self._dataset_repo.get_dataset(saved_envelope.dataset_id)
        except Exception:
            raise OrchestrationError(
                "dataset_persistence_failed",
                "Failed to persist generated dataset to DatasetRepository; execution aborted.",
                status_code=500,
                stage="saving_dataset",
            ) from None

        if verified is None or not verified.testcases:
            raise OrchestrationError(
                "dataset_persistence_verification_failed",
                "Persisted dataset could not be verified from DatasetRepository; execution aborted.",
                status_code=500,
                stage="saving_dataset",
            )

        testcase_ids = tuple(tc.testcase_id for tc in verified.testcases)
        return verified.dataset_id, verified.name, verified.file_sha256, testcase_ids

    def _build_runner_asi_and_policy(
        self,
        *,
        selected_asi: tuple[AsiCode, ...],
        policy_ids_by_asi: dict[str, str],
        result: GenerationResult | None = None,
    ) -> tuple[str, str | None, dict[str, str]]:
        resolved_map: dict[str, str] = {}
        for code in selected_asi:
            pol = policy_ids_by_asi.get(code)
            if not pol and result is not None and code in result.asi_results:
                pol = result.asi_results[code].reviewed_policy_id
            if isinstance(pol, str) and pol.strip():
                resolved_map[code] = pol.strip()
        if len(selected_asi) == 1:
            only_asi = selected_asi[0]
            return only_asi, resolved_map.get(only_asi), resolved_map
        return "auto", None, resolved_map

    def _evaluate_preflight_coverage(
        self,
        *,
        preview_res: dict[str, Any],
        expected_cases: int,
    ) -> tuple[int, int, int, int, tuple[dict[str, Any], ...]]:
        """Extract exact preflight execution coverage counts & sanitized skip reasons (R01)."""
        selected_cases = int(preview_res.get("selected_cases") or expected_cases)
        ready_count = int(preview_res.get("ready_count") or 0)
        skipped_reasons = _sanitize_skipped_cases(preview_res.get("skipped_cases"))
        raw_skipped = int(preview_res.get("skipped_count") or len(skipped_reasons))
        unsupported_count = int(preview_res.get("unsupported_count") or 0)
        effective_skipped = max(raw_skipped, unsupported_count, max(0, selected_cases - ready_count))
        return selected_cases, ready_count, effective_skipped, unsupported_count, skipped_reasons

    def start_workflow(
        self,
        *,
        req: GenerateAndRunRequest,
        owner_id: str,
    ) -> GenerateAndRunSnapshot:
        """Execute Mode 1 (Generate & Run) end-to-end with fail-closed guardrails & idempotency."""
        owner_digest = _hash_owner(owner_id)

        if self._generic_run_service is None:
            raise OrchestrationError(
                "generic_runner_unavailable",
                "Generic Runner service is not configured for Generate & Run orchestration.",
                status_code=503,
                stage="preflight",
            )

        if req.authorization_confirmed is not True:
            raise OrchestrationError(
                "authorization_required",
                "Explicit operator authorization_confirmed=true is required before Generate & Run.",
                status_code=400,
                stage="preflight",
            )

        try:
            service_req = req.to_generation_request()
        except Exception:
            raise OrchestrationError(
                "invalid_request",
                "Invalid Generate & Run configuration.",
                status_code=400,
                stage="generating",
            ) from None

        selected_asi = tuple(normalize_asi_code(k) for k in service_req.counts_by_asi.keys())
        requested_total = sum(service_req.counts_by_asi.values())
        req_digest = _request_fingerprint(req, service_req)

        # R02: Idempotency & concurrent duplicate-submit guard
        sub_id = req.submission_id
        in_flight_event: Event | None = None
        if sub_id is not None:
            wait_event: Event | None = None
            with self._lock:
                existing = self._submissions.get(sub_id)
                if existing is not None:
                    prev_owner, prev_digest, prev_wf_id = existing
                    if prev_owner != owner_digest or prev_digest != req_digest:
                        raise OrchestrationError(
                            "generate_and_run_submission_conflict",
                            "submission_id was already used with a different Generate & Run request.",
                            status_code=409,
                        )
                    wf = self._workflows.get(prev_wf_id)
                    if wf is not None:
                        return self._refresh_and_snapshot(wf, idempotent_replay=True)
                    raise OrchestrationError(
                        "workflow_submission_expired",
                        "This submission_id was already used, but its in-memory workflow snapshot expired. "
                        "Inspect Dataset Library or Scan Runs instead of re-executing with the same submission_id.",
                        status_code=410,
                    )
                in_flight = self._in_flight_submissions.get(sub_id)
                if in_flight is not None:
                    prev_owner, prev_digest, wait_event = in_flight
                    if prev_owner != owner_digest or prev_digest != req_digest:
                        raise OrchestrationError(
                            "generate_and_run_submission_conflict",
                            "submission_id is already in progress with a different request.",
                            status_code=409,
                        )
                else:
                    in_flight_event = Event()
                    self._in_flight_submissions[sub_id] = (owner_digest, req_digest, in_flight_event)

            if wait_event is not None:
                wait_event.wait(timeout=30.0)
                with self._lock:
                    existing = self._submissions.get(sub_id)
                    if existing is not None:
                        _, _, prev_wf_id = existing
                        wf = self._workflows.get(prev_wf_id)
                        if wf is not None:
                            return self._refresh_and_snapshot(wf, idempotent_replay=True)
                        raise OrchestrationError(
                            "workflow_submission_expired",
                            "This submission_id was already used, but its in-memory workflow snapshot expired.",
                            status_code=410,
                        )
                raise OrchestrationError(
                    "generate_and_run_submission_in_progress",
                    "An identical Generate & Run submission is still initializing.",
                    status_code=409,
                )

        try:
            return self._accept_and_run_workflow(
                req=req,
                service_req=service_req,
                selected_asi=selected_asi,
                requested_total=requested_total,
                req_digest=req_digest,
                owner_digest=owner_digest,
            )
        finally:
            if sub_id is not None and in_flight_event is not None:
                with self._lock:
                    self._in_flight_submissions.pop(sub_id, None)
                in_flight_event.set()

    def _accept_and_run_workflow(
        self,
        *,
        req: GenerateAndRunRequest,
        service_req: GenerationServiceRequest,
        selected_asi: tuple[AsiCode, ...],
        requested_total: int,
        req_digest: str,
        owner_digest: str,
    ) -> GenerateAndRunSnapshot:
        assert self._generic_run_service is not None

        # Pre-generation fail-closed checks (zero LLM tokens burned on invalid/unauthorized requests)
        preset = self._lookup_target(req.target_id)
        if preset is None:
            raise OrchestrationError(
                "target_not_found",
                "Selected target was not found in the active catalog.",
                status_code=404,
                stage="preflight",
            )

        if not self._is_target_authorized(req.target_id, preset):
            raise OrchestrationError(
                "target_not_authorized",
                "Selected target has not been reviewed and authorized for live execution.",
                status_code=403,
                stage="preflight",
            )

        snapshot = build_context_snapshot(
            target_id=req.target_id,
            catalog=self._catalog,
            application_contexts=self._application_contexts,
            policy_store=self._policy_store,
            policy_ids_by_asi=service_req.policy_ids_by_asi or None,
        )
        if snapshot is None:
            raise OrchestrationError(
                "target_not_found",
                "Selected target was not found in the active catalog.",
                status_code=404,
                stage="preflight",
            )
        if (
            req.expected_target_revision is not None
            and snapshot.target_revision_sha256 is not None
            and req.expected_target_revision != snapshot.target_revision_sha256
        ):
            raise OrchestrationError(
                "target_revision_stale",
                "Target profile revision changed; refresh target configuration before Generate & Run.",
                status_code=409,
                stage="preflight",
            )

        provider_status = self._generator_service._provider.status()
        if not provider_status.credential_available:
            raise OrchestrationError(
                "generator_credential_unavailable",
                "Configured backend generator credential is unavailable; check DEEPSEEK_API_KEY.",
                status_code=503,
                stage="generating",
            )

        if req.evaluation_mode == "hybrid":
            j_status = self._generic_run_service.judge_status()
            if not j_status.get("judge_ready"):
                raise OrchestrationError(
                    "judge_provider_unavailable",
                    _SAFE_PUBLIC_ERROR_MESSAGES["judge_provider_unavailable"],
                    status_code=409,
                    stage="preflight",
                )

        readiness = assess_target_readiness(
            target_id=req.target_id,
            catalog=self._catalog,
            application_contexts=self._application_contexts,
            policy_store=self._policy_store,
            selected_asi=selected_asi,
            requested_scopes=service_req.requested_scopes or None,
            policy_ids_by_asi=service_req.policy_ids_by_asi or None,
        )

        now_iso = self._now_iso()
        workflow_id = f"gnr-{uuid4().hex}"
        entry = _WorkflowEntry(
            workflow_id=workflow_id,
            owner_digest=owner_digest,
            submission_id=req.submission_id,
            request_digest=req_digest,
            req=req,
            selected_asi=selected_asi,
            requested_count=requested_total,
            created_at=now_iso,
        )
        entry.target_revision_sha256 = snapshot.target_revision_sha256
        entry.application_context_revision_sha256 = snapshot.application_context_revision_sha256
        entry.context_snapshot_sha256 = snapshot.snapshot_sha256
        entry.provider_id = provider_status.provider_id
        entry.model = provider_status.model

        with self._lock:
            self._evict_if_full_locked()
            self._workflows[workflow_id] = entry
            if req.submission_id is not None:
                self._submissions[req.submission_id] = (owner_digest, req_digest, workflow_id)

        blocked_asis = [
            code
            for code in selected_asi
            if code in readiness.asi_assessments and readiness.asi_assessments[code].status == "blocked"
        ]
        if blocked_asis:
            blockers = [
                f"{code}:{b}"
                for code in blocked_asis
                for b in readiness.asi_assessments[code].blockers
            ]
            reason = blockers[0] if blockers else "readiness_blocked"
            with self._lock:
                entry.mark_stage(
                    "generating",
                    "blocked",
                    self._now_iso(),
                    error_code=reason,
                    error_message="Generation blocked by context/scope/policy readiness before calling provider.",
                )
                entry.skip_remaining_after("generating", self._now_iso())
                entry.status = "blocked"
                entry.error_stage = "generating"
                entry.error_code = reason
                entry.error_message = f"Blocked before generation: {', '.join(blockers[:4])}"
                entry.completed_at = self._now_iso()
                return entry.to_snapshot()

        # Mark generating running immediately so status is observable from acceptance (R02)
        with self._lock:
            entry.mark_stage(
                "generating",
                "running",
                self._now_iso(),
                detail="Invoking context-aware GeneratorService.",
            )
            initial_snap = entry.to_snapshot()

        if req.async_execution:
            worker = Thread(
                target=self._run_pipeline_stages,
                args=(entry, req, service_req, selected_asi),
                name=f"secagent-gnr-{workflow_id[:12]}",
                daemon=True,
            )
            worker.start()
            return initial_snap

        self._run_pipeline_stages(entry, req, service_req, selected_asi)
        with self._lock:
            return entry.to_snapshot()

    def _run_pipeline_stages(
        self,
        entry: _WorkflowEntry,
        req: GenerateAndRunRequest,
        service_req: GenerationServiceRequest,
        selected_asi: tuple[AsiCode, ...],
    ) -> None:
        assert self._generic_run_service is not None

        # ---------------- STAGE 1: GENERATING ----------------
        try:
            gen_result = self._generator_service.generate(service_req)
        except GenerationServiceError as exc:
            now = self._now_iso()
            with self._lock:
                entry.mark_stage("generating", "failed", now, error_code=exc.code, error_message=exc.message)
                entry.skip_remaining_after("generating", now)
                entry.status = "failed"
                entry.error_stage = "generating"
                entry.error_code = exc.code
                entry.error_message = exc.message
                entry.completed_at = now
            return
        except Exception:
            now = self._now_iso()
            with self._lock:
                entry.mark_stage(
                    "generating",
                    "failed",
                    now,
                    error_code="generation_failed",
                    error_message="Generator encountered an internal error.",
                )
                entry.skip_remaining_after("generating", now)
                entry.status = "failed"
                entry.error_stage = "generating"
                entry.error_code = "generation_failed"
                entry.error_message = "Generator encountered an internal error."
                entry.completed_at = now
            return

        with self._lock:
            entry.generation_id = gen_result.generation_id
            entry.provider_id = gen_result.provider_id
            entry.model = gen_result.model
            entry.target_revision_sha256 = gen_result.target_revision_sha256 or entry.target_revision_sha256
            entry.application_context_revision_sha256 = (
                gen_result.application_context_revision_sha256 or entry.application_context_revision_sha256
            )
            entry.context_snapshot_sha256 = gen_result.context_snapshot_sha256 or entry.context_snapshot_sha256
            entry.generation_overall_status = gen_result.overall_status
            entry.requested_count = gen_result.total_requested
            entry.generated_count = gen_result.total_generated
            entry.accepted_count = gen_result.total_accepted
            entry.rejected_count = gen_result.total_rejected
            entry.meets_requested_counts = gen_result.meets_requested_counts
            entry.partial_generation = not gen_result.meets_requested_counts
            entry.rejection_reason_counts = dict(gen_result.rejection_reason_counts)
            entry.generation_token_usage = gen_result.total_token_usage
            for code in gen_result.asi_order:
                asi_res = gen_result.asi_results[code]
                entry.asi_generation_summaries[code] = {
                    "asi_code": code,
                    "status": asi_res.status,
                    "effective_scope": asi_res.effective_scope,
                    "requested_count": asi_res.requested_count,
                    "generated_count": asi_res.generated_count,
                    "accepted_count": asi_res.accepted_count,
                    "rejected_count": asi_res.rejected_count,
                    "duplicate_rejected_count": asi_res.duplicate_rejected_count,
                    "error_code": asi_res.error_code,
                    "error_message": asi_res.error_message,
                    "skill_id": asi_res.skill_id,
                    "skill_version": asi_res.skill_version,
                    "reviewed_policy_id": asi_res.reviewed_policy_id,
                }
                if asi_res.reviewed_policy_id and asi_res.reviewed_policy_revision_sha256:
                    entry.reviewed_policies[code] = {
                        "policy_id": asi_res.reviewed_policy_id,
                        "revision_sha256": asi_res.reviewed_policy_revision_sha256,
                    }

        non_blocked = [
            gen_result.asi_results[c] for c in gen_result.asi_order if gen_result.asi_results[c].status != "blocked"
        ]
        if non_blocked and all(
            r.provider_error_category == ProviderErrorCategory.CREDENTIAL_MISSING for r in non_blocked
        ):
            now = self._now_iso()
            with self._lock:
                entry.mark_stage(
                    "generating",
                    "failed",
                    now,
                    error_code="generator_credential_unavailable",
                    error_message="Backend generator credential was unavailable.",
                )
                entry.skip_remaining_after("generating", now)
                entry.status = "failed"
                entry.error_stage = "generating"
                entry.error_code = "generator_credential_unavailable"
                entry.error_message = "Backend generator credential was unavailable."
                entry.completed_at = now
            return

        if gen_result.overall_status == "failed" or (
            gen_result.total_accepted == 0
            and any(r.status in {"provider_error", "invalid_output", "truncated"} for r in non_blocked)
        ):
            first_bad = next(
                (r for r in non_blocked if r.status in {"provider_error", "invalid_output", "truncated"}),
                non_blocked[0] if non_blocked else None,
            )
            err_code = (first_bad.error_code if first_bad and first_bad.error_code else None) or (
                first_bad.status if first_bad else "generation_failed"
            )
            err_msg = (first_bad.error_message if first_bad and first_bad.error_message else None) or (
                "Generator failed to produce valid output."
            )
            now = self._now_iso()
            with self._lock:
                entry.mark_stage("generating", "failed", now, error_code=err_code, error_message=err_msg)
                entry.skip_remaining_after("generating", now)
                entry.status = "failed"
                entry.error_stage = "generating"
                entry.error_code = err_code
                entry.error_message = err_msg
                entry.completed_at = now
            return

        with self._lock:
            entry.mark_stage(
                "generating",
                "completed",
                self._now_iso(),
                detail=f"Generated {gen_result.total_generated} candidate(s) across {len(gen_result.asi_order)} ASI group(s).",
            )
            entry.mark_stage(
                "validating",
                "running",
                self._now_iso(),
                detail="Validating candidates, counts, and deduplication.",
            )

        # ---------------- STAGE 2: VALIDATING ----------------
        q_summary: dict[str, Any] | None = None
        try:
            q_report = evaluate_generation_result(gen_result)
            q_summary = {
                "usability_status": q_report.usability_status,
                "output_contract_validity_rate": q_report.overall_metrics.output_contract_validity_rate.rate,
                "candidate_grounding_validity_rate": q_report.overall_metrics.candidate_grounding_validity_rate.rate,
                "acceptance_vs_requested_rate": q_report.overall_metrics.acceptance_vs_requested_rate.rate,
                "asi_alignment_verified": q_report.overall_metrics.asi_alignment_verified,
                "confirmed_field_coverage_rate": q_report.overall_metrics.context_basis_coverage.confirmed_field_coverage_rate.rate,
                "unique_strategy_tags": q_report.overall_metrics.diversity_stats.unique_strategy_tags,
                "provenance_complete": q_report.provenance_completeness.complete,
            }
        except Exception:
            q_summary = None

        with self._lock:
            entry.quality_summary = q_summary

        if gen_result.total_accepted == 0:
            now = self._now_iso()
            all_dups = any(r.duplicate_rejected_count > 0 for r in gen_result.asi_results.values())
            err_code = "insufficient_candidates_after_deduplication" if all_dups else "empty_generation_result"
            err_msg = (
                f"Zero accepted candidates (requested={gen_result.total_requested}, "
                f"generated={gen_result.total_generated}, rejected={gen_result.total_rejected})."
            )
            with self._lock:
                entry.mark_stage("validating", "failed", now, error_code=err_code, error_message=err_msg)
                entry.skip_remaining_after("validating", now)
                entry.status = "failed"
                entry.error_stage = "validating"
                entry.error_code = err_code
                entry.error_message = err_msg
                entry.completed_at = now
            return

        if not gen_result.meets_requested_counts and not req.allow_partial_execution:
            now = self._now_iso()
            err_msg = (
                f"Partial generation stopped before execution: accepted {gen_result.total_accepted} of "
                f"{gen_result.total_requested} requested (generated={gen_result.total_generated}, "
                f"rejected={gen_result.total_rejected}). Set allow_partial_execution=true to explicitly run a partial set."
            )
            with self._lock:
                entry.mark_stage(
                    "validating",
                    "blocked",
                    now,
                    error_code="partial_generation_not_executed",
                    error_message=err_msg,
                )
                entry.skip_remaining_after("validating", now)
                entry.status = "partial_stopped"
                entry.error_stage = "validating"
                entry.error_code = "partial_generation_not_executed"
                entry.error_message = err_msg
                entry.completed_at = now
            return

        with self._lock:
            entry.mark_stage(
                "validating",
                "completed",
                self._now_iso(),
                detail=(
                    f"Accepted {gen_result.total_accepted}/{gen_result.total_requested} testcase(s)"
                    + (" (partial generation explicitly authorized)" if not gen_result.meets_requested_counts else "")
                ),
            )
            entry.mark_stage(
                "saving_dataset",
                "running",
                self._now_iso(),
                detail="Auto-persisting dataset before execution.",
            )

        # ---------------- STAGE 3: AUTO-SAVING DATASET ----------------
        try:
            dataset_id, dataset_name, dataset_sha, testcase_ids = self._persist_generated_dataset(
                workflow_id=entry.workflow_id,
                result=gen_result,
                dataset_name=req.dataset_name,
                allow_partial_execution=req.allow_partial_execution,
            )
        except OrchestrationError as exc:
            now = self._now_iso()
            with self._lock:
                entry.mark_stage("saving_dataset", "failed", now, error_code=exc.code, error_message=exc.message)
                entry.skip_remaining_after("saving_dataset", now)
                entry.status = "failed"
                entry.error_stage = "saving_dataset"
                entry.error_code = exc.code
                entry.error_message = exc.message
                entry.completed_at = now
            return

        with self._lock:
            entry.auto_persisted = True
            entry.dataset_id = dataset_id
            entry.dataset_name = dataset_name
            entry.dataset_file_sha256 = dataset_sha
            entry.testcase_ids = testcase_ids
            entry.mark_stage(
                "saving_dataset",
                "completed",
                self._now_iso(),
                detail=f"Persisted immutable dataset {dataset_id} ({len(testcase_ids)} testcase(s)).",
            )
            entry.mark_stage(
                "preflight",
                "running",
                self._now_iso(),
                detail="Running Generic Runner preflight checks.",
            )

        # ---------------- STAGE 4: PREFLIGHT ----------------
        runner_asi, runner_policy, runner_policies_by_asi = self._build_runner_asi_and_policy(
            selected_asi=selected_asi,
            policy_ids_by_asi=service_req.policy_ids_by_asi,
            result=gen_result,
        )
        with self._lock:
            entry.runner_asi_category = runner_asi
            entry.runner_policy_id = runner_policy
            entry.runner_policy_ids_by_asi = dict(runner_policies_by_asi)

        preview_payload: dict[str, Any] = {
            "mode": req.execution_mode,
            "target_id": req.target_id,
            "dataset_id": dataset_id,
            "asi_category": runner_asi,
            "use_judge": req.evaluation_mode == "hybrid",
        }
        if runner_policy is not None:
            preview_payload["policy_id"] = runner_policy
        if runner_policies_by_asi:
            preview_payload["policy_ids_by_asi"] = dict(runner_policies_by_asi)

        try:
            preview_res = self._generic_run_service.preview_run(preview_payload)
        except Exception as exc:
            now = self._now_iso()
            safe_code, err_stage, _, safe_msg = _sanitize_runner_error_code(
                exc,
                default_code="preflight_failed",
                default_stage="preflight",
            )
            if err_stage != "evaluating":
                err_stage = "preflight"
            with self._lock:
                entry.mark_stage("preflight", "failed", now, error_code=safe_code, error_message=safe_msg)
                entry.skip_remaining_after("preflight", now)
                entry.status = "failed"
                entry.error_stage = err_stage
                entry.error_code = safe_code
                entry.error_message = safe_msg
                entry.completed_at = now
            return

        selected_cases, ready_count, effective_skipped, unsupported_count, skipped_reasons = (
            self._evaluate_preflight_coverage(preview_res=preview_res, expected_cases=len(testcase_ids))
        )
        with self._lock:
            entry.preflight_selected_cases = selected_cases
            entry.preflight_ready_count = ready_count
            entry.preflight_skipped_count = effective_skipped
            entry.preflight_unsupported_count = unsupported_count
            entry.preflight_skipped_reasons = skipped_reasons

        raw_blocker = preview_res.get("blocker")
        preview_target_rev = preview_res.get("target_revision_sha256")
        if (
            entry.target_revision_sha256
            and isinstance(preview_target_rev, str)
            and preview_target_rev != entry.target_revision_sha256
        ):
            raw_blocker = "generic_target_revision_stale"

        if raw_blocker or ready_count <= 0:
            now = self._now_iso()
            safe_code, err_stage, _, safe_msg = _sanitize_runner_error_code(
                raw_blocker or "generic_no_executable_cases",
                default_code="preflight_failed",
                default_stage="preflight",
            )
            if err_stage != "evaluating":
                err_stage = "preflight"
            with self._lock:
                entry.mark_stage("preflight", "blocked", now, error_code=safe_code, error_message=safe_msg)
                entry.skip_remaining_after("preflight", now)
                entry.status = "blocked" if err_stage == "preflight" else "failed"
                entry.error_stage = err_stage
                entry.error_code = safe_code
                entry.error_message = safe_msg
                entry.completed_at = now
            return

        # R01: Fail-closed partial execution guard after Runner preflight!
        if effective_skipped > 0:
            with self._lock:
                entry.partial_execution = True
            if not req.allow_partial_execution:
                now = self._now_iso()
                err_msg = (
                    f"Partial execution stopped at preflight: {ready_count} of {selected_cases} persisted "
                    f"testcase(s) are executable ({effective_skipped} skipped/unsupported). "
                    "Set allow_partial_execution=true to explicitly execute a partial subset."
                )
                with self._lock:
                    entry.mark_stage(
                        "preflight",
                        "blocked",
                        now,
                        error_code="partial_execution_not_authorized",
                        error_message=err_msg,
                    )
                    entry.skip_remaining_after("preflight", now)
                    entry.status = "partial_stopped"
                    entry.error_stage = "preflight"
                    entry.error_code = "partial_execution_not_authorized"
                    entry.error_message = err_msg
                    entry.completed_at = now
                return

        preflight_detail = (
            f"Preflight passed: {ready_count}/{selected_cases} executable testcase(s) ready"
            + (
                f" ({effective_skipped} skipped/unsupported; partial execution explicitly authorized)."
                if effective_skipped > 0
                else "."
            )
        )
        with self._lock:
            entry.mark_stage("preflight", "completed", self._now_iso(), detail=preflight_detail)
            entry.mark_stage("executing", "running", self._now_iso(), detail="Starting Generic Runner execution.")

        # ---------------- STAGE 5-7: EXECUTE -> EVALUATE -> REPORT ----------------
        run_submission_id = sha256(f"gnr-run:{entry.workflow_id}:0".encode("utf-8")).hexdigest()[:32]
        start_payload: dict[str, Any] = {
            **preview_payload,
            "authorization_confirmed": True,
            "submission_id": run_submission_id,
            "async_execution": req.async_execution,
        }
        if isinstance(preview_target_rev, str) and _HEX64_RE.fullmatch(preview_target_rev):
            start_payload["expected_target_revision"] = preview_target_rev
        sess_gen = req.expected_session_credential_generation or preview_res.get("session_credential_generation")
        if isinstance(sess_gen, str) and _HEX32_RE.fullmatch(sess_gen):
            start_payload["expected_session_credential_generation"] = sess_gen

        try:
            run_record = self._generic_run_service.start_run(start_payload)
        except Exception as exc:
            now = self._now_iso()
            safe_code, stage, _, safe_msg = _sanitize_runner_error_code(
                exc,
                default_code="runner_execution_failed",
                default_stage="executing",
            )
            with self._lock:
                if stage == "evaluating":
                    entry.mark_stage("executing", "completed", now)
                    entry.evaluation_error_code = safe_code
                    entry.mark_stage("evaluating", "failed", now, error_code=safe_code, error_message=safe_msg)
                    entry.skip_remaining_after("evaluating", now)
                else:
                    entry.mark_stage("executing", "failed", now, error_code=safe_code, error_message=safe_msg)
                    entry.skip_remaining_after("executing", now)
                entry.status = "failed"
                entry.error_stage = stage
                entry.error_code = safe_code
                entry.error_message = safe_msg
                entry.completed_at = now
            return

        with self._lock:
            entry.run_id = str(run_record.get("generic_run_id") or "")
            entry.sync_from_run_record(run_record, self._now_iso(), evaluation_mode=req.evaluation_mode)

    def _get_owned_workflow(self, workflow_id: str, owner_id: str) -> _WorkflowEntry:
        owner_digest = _hash_owner(owner_id)
        if not isinstance(workflow_id, str) or not _WORKFLOW_ID_RE.fullmatch(workflow_id.strip()):
            raise OrchestrationError("workflow_not_found", "Generate & Run workflow was not found.", status_code=404)
        with self._lock:
            entry = self._workflows.get(workflow_id.strip())
            if entry is None:
                raise OrchestrationError("workflow_not_found", "Generate & Run workflow was not found.", status_code=404)
            if entry.owner_digest != owner_digest:
                raise OrchestrationError(
                    "workflow_access_denied",
                    "Generate & Run workflow belongs to a different operator session.",
                    status_code=403,
                )
            return entry

    def _refresh_and_snapshot(
        self,
        entry: _WorkflowEntry,
        *,
        idempotent_replay: bool = False,
    ) -> GenerateAndRunSnapshot:
        run_id = entry.run_id
        if run_id and self._generic_run_service is not None:
            latest = self._generic_run_service.get_run(run_id)
            if isinstance(latest, dict):
                with self._lock:
                    if entry.run_id == run_id:
                        entry.sync_from_run_record(latest, self._now_iso())
        with self._lock:
            return entry.to_snapshot(idempotent_replay=idempotent_replay)

    def get_workflow(self, *, workflow_id: str, owner_id: str) -> GenerateAndRunSnapshot:
        entry = self._get_owned_workflow(workflow_id, owner_id)
        return self._refresh_and_snapshot(entry)

    def get_workflow_by_submission(self, *, submission_id: str, owner_id: str) -> GenerateAndRunSnapshot:
        """Look up a Generate & Run workflow by client submission_id for idempotent network recovery (R02).

        Strictly distinguishes:
        - 404 `workflow_submission_not_found`: submission_id was never accepted by this process.
        - 409 `generate_and_run_submission_in_progress`: submission_id is currently initializing.
        - 410 `workflow_submission_expired`: submission_id was already used, but its in-memory
          workflow snapshot was evicted due to capacity bounds (must NOT be treated as unused).
        """
        owner_digest = _hash_owner(owner_id)
        if not isinstance(submission_id, str) or not _HEX32_RE.fullmatch(submission_id.strip()):
            raise OrchestrationError(
                "workflow_submission_not_found",
                "No Generate & Run workflow was found for this submission_id.",
                status_code=404,
            )
        sub_id = submission_id.strip()
        with self._lock:
            rec = self._submissions.get(sub_id)
            if rec is None:
                in_flight = self._in_flight_submissions.get(sub_id)
                if in_flight is not None:
                    prev_owner, _, _ = in_flight
                    if prev_owner != owner_digest:
                        raise OrchestrationError(
                            "workflow_access_denied",
                            "Generate & Run workflow belongs to a different operator session.",
                            status_code=403,
                        )
                    raise OrchestrationError(
                        "generate_and_run_submission_in_progress",
                        "A Generate & Run workflow for this submission_id is currently initializing.",
                        status_code=409,
                    )
                raise OrchestrationError(
                    "workflow_submission_not_found",
                    "No Generate & Run workflow was found for this submission_id.",
                    status_code=404,
                )
            prev_owner, _, wf_id = rec
            if prev_owner != owner_digest:
                raise OrchestrationError(
                    "workflow_access_denied",
                    "Generate & Run workflow belongs to a different operator session.",
                    status_code=403,
                )
            entry = self._workflows.get(wf_id)
            if entry is None:
                raise OrchestrationError(
                    "workflow_submission_expired",
                    "This submission_id was already used, but its in-memory workflow snapshot has expired. "
                    "Inspect Dataset Library or Scan Runs instead of re-executing.",
                    status_code=410,
                )
        return self._refresh_and_snapshot(entry)

    def rerun_workflow(
        self,
        *,
        workflow_id: str,
        owner_id: str,
        rerun_req: GenerateAndRunRerunRequest,
    ) -> dict[str, Any]:
        """Re-execute a persisted dataset with a NEW run_id and ZERO Generator calls.

        R01: Blocks partial execution after preflight unless explicitly allowed.
        R03: Strictly sanitizes all external error strings.
        R04: Tracks and evaluates using the rerun's ACTUAL evaluation_mode.
        """
        if self._generic_run_service is None:
            raise OrchestrationError(
                "generic_runner_unavailable",
                "Generic Runner service is not configured.",
                status_code=503,
                stage="preflight",
            )
        if rerun_req.authorization_confirmed is not True:
            raise OrchestrationError(
                "authorization_required",
                "Explicit authorization_confirmed=true is required to rerun a saved dataset.",
                status_code=400,
                stage="preflight",
            )

        entry = self._get_owned_workflow(workflow_id, owner_id)
        # Refresh live run status first so a completed async run is not falsely treated as active.
        with self._lock:
            fetched_run_id = entry.run_id
        if fetched_run_id:
            latest_run = self._generic_run_service.get_run(fetched_run_id)
            if isinstance(latest_run, dict):
                with self._lock:
                    if entry.run_id == fetched_run_id and not entry.rerun_starting:
                        entry.sync_from_run_record(latest_run, self._now_iso())

        # Issue A: Atomically verify no original execution or concurrent rerun is active and reserve rerun lock.
        with self._lock:
            if (
                entry.status == "running"
                or entry.run_status in {"queued", "preparing", "running"}
                or entry.rerun_starting
            ):
                raise OrchestrationError(
                    "workflow_execution_in_progress",
                    "Cannot start a rerun while an execution or rerun for this workflow is still active.",
                    status_code=409,
                    stage="executing",
                )
            if not entry.dataset_id:
                raise OrchestrationError(
                    "dataset_not_available_for_rerun",
                    "Cannot rerun workflow because no persisted dataset exists.",
                    status_code=409,
                    stage="saving_dataset",
                )
            entry.rerun_starting = True
            dataset_id = entry.dataset_id
            eval_mode: EvaluationMode = rerun_req.evaluation_mode or entry.active_evaluation_mode
            allow_partial = (
                rerun_req.allow_partial_execution
                if rerun_req.allow_partial_execution is not None
                else entry.req.allow_partial_execution
            )
            exec_mode = entry.req.execution_mode
            target_id = entry.req.target_id
            runner_asi = entry.runner_asi_category
            runner_policy = entry.runner_policy_id
            runner_policies_by_asi = dict(entry.runner_policy_ids_by_asi)

        try:
            preset = self._lookup_target(target_id)
            if preset is None:
                raise OrchestrationError(
                    "target_not_found",
                    "Selected target was not found in the active catalog.",
                    status_code=404,
                    stage="preflight",
                )
            if not self._is_target_authorized(target_id, preset):
                raise OrchestrationError(
                    "target_not_authorized",
                    "Selected target has not been reviewed and authorized for live execution.",
                    status_code=403,
                    stage="preflight",
                )

            ds = self._dataset_repo.get_dataset(dataset_id)
            if ds is None:
                raise OrchestrationError(
                    "dataset_not_found",
                    "Persisted dataset was not found in DatasetRepository.",
                    status_code=404,
                    stage="preflight",
                )

            if eval_mode == "hybrid":
                j_status = self._generic_run_service.judge_status()
                if not j_status.get("judge_ready"):
                    raise OrchestrationError(
                        "judge_provider_unavailable",
                        _SAFE_PUBLIC_ERROR_MESSAGES["judge_provider_unavailable"],
                        status_code=409,
                        stage="preflight",
                    )

            preview_payload: dict[str, Any] = {
                "mode": exec_mode,
                "target_id": target_id,
                "dataset_id": dataset_id,
                "asi_category": runner_asi,
                "use_judge": eval_mode == "hybrid",
            }
            if runner_policy is not None:
                preview_payload["policy_id"] = runner_policy
            if runner_policies_by_asi:
                preview_payload["policy_ids_by_asi"] = dict(runner_policies_by_asi)

            try:
                preview_res = self._generic_run_service.preview_run(preview_payload)
            except Exception as exc:
                safe_code, stage, status, safe_msg = _sanitize_runner_error_code(
                    exc,
                    default_code="preflight_failed",
                    default_stage="preflight",
                )
                raise OrchestrationError(safe_code, safe_msg, status_code=status, stage=stage) from None

            selected_cases, ready_count, effective_skipped, unsupported_count, skipped_reasons = (
                self._evaluate_preflight_coverage(preview_res=preview_res, expected_cases=len(ds.testcases))
            )
            if preview_res.get("blocker") or ready_count <= 0:
                safe_code, stage, status, safe_msg = _sanitize_runner_error_code(
                    preview_res.get("blocker") or "generic_no_executable_cases",
                    default_code="preflight_failed",
                    default_stage="preflight",
                )
                raise OrchestrationError(safe_code, safe_msg, status_code=status, stage=stage)

            if effective_skipped > 0 and not allow_partial:
                raise OrchestrationError(
                    "partial_execution_not_authorized",
                    (
                        f"Rerun preflight stopped: {ready_count} of {selected_cases} testcase(s) ready "
                        f"({effective_skipped} skipped/unsupported). Set allow_partial_execution=true to proceed."
                    ),
                    status_code=409,
                    stage="preflight",
                )

            start_payload: dict[str, Any] = {
                **preview_payload,
                "authorization_confirmed": True,
                "async_execution": rerun_req.async_execution,
            }
            if rerun_req.submission_id is not None:
                start_payload["submission_id"] = rerun_req.submission_id
            target_rev = rerun_req.expected_target_revision or preview_res.get("target_revision_sha256")
            if isinstance(target_rev, str) and _HEX64_RE.fullmatch(target_rev):
                start_payload["expected_target_revision"] = target_rev
            sess_gen = rerun_req.expected_session_credential_generation or preview_res.get("session_credential_generation")
            if isinstance(sess_gen, str) and _HEX32_RE.fullmatch(sess_gen):
                start_payload["expected_session_credential_generation"] = sess_gen

            try:
                run_record = self._generic_run_service.start_run(start_payload)
            except Exception as exc:
                safe_code, stage, status, safe_msg = _sanitize_runner_error_code(
                    exc,
                    default_code="runner_execution_failed",
                    default_stage="executing",
                )
                raise OrchestrationError(safe_code, safe_msg, status_code=status, stage=stage) from None

            new_run_id = str(run_record.get("generic_run_id") or "")
            now = self._now_iso()
            with self._lock:
                prev_run_id = entry.run_id
                entry.run_id = new_run_id
                entry.active_evaluation_mode = eval_mode
                entry.partial_execution = effective_skipped > 0
                entry.preflight_selected_cases = selected_cases
                entry.preflight_ready_count = ready_count
                entry.preflight_skipped_count = effective_skipped
                entry.preflight_unsupported_count = unsupported_count
                entry.preflight_skipped_reasons = skipped_reasons
                entry.error_stage = None
                entry.error_code = None
                entry.error_message = None
                entry.evaluation_error_code = None
                entry.mark_stage(
                    "preflight",
                    "completed",
                    now,
                    detail=f"Rerun preflight passed ({ready_count}/{selected_cases} ready, mode={eval_mode}).",
                )
                entry.rerun_history.append(
                    RerunHistoryEntry(
                        run_id=new_run_id,
                        previous_run_id=prev_run_id,
                        dataset_id=dataset_id,
                        evaluation_mode=eval_mode,
                        started_at=now,
                        run_status=str(run_record.get("status") or "running"),
                    )
                )
                entry.sync_from_run_record(run_record, now, evaluation_mode=eval_mode)
                entry.rerun_starting = False
                snap = entry.to_snapshot()
        finally:
            with self._lock:
                entry.rerun_starting = False

        return {
            "operation": "rerun",
            "generator_called": False,
            "regenerated": False,
            "dataset_id": dataset_id,
            "previous_run_id": prev_run_id,
            "new_run_id": new_run_id,
            "evaluation_mode": eval_mode,
            "workflow": snap.model_dump(mode="json"),
        }

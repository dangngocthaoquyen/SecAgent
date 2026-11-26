"""Pure Evidence Contract v2 builder, verifier, and historical projector.

Reuses SecAgent's centralized evidence verification primitives
(`is_execution_verified`, `canonical_provenance`, `is_adapter_observed_request`,
`has_negative_verification_or_correlation`, `public_evidence_data`) without
duplicating verification logic, making network/filesystem/target/Judge calls,
or modifying PASS/FAIL/INCONCLUSIVE verdicts.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import asdict, is_dataclass
from hashlib import sha256
import json
import re
from typing import Any

from pydantic import ValidationError

from core.models.evidence import (
    ADAPTER_REQUEST_SOURCES,
    COLLECTOR_EVIDENCE_SOURCES,
    INDEPENDENT_PROVENANCE_LABELS,
    NEGATIVE_CORRELATION_STATUSES,
    NEGATIVE_CORRELATION_STRENGTHS,
    NEGATIVE_VERIFICATION_STATUSES,
    PROVENANCE_RANK,
    TARGET_CLAIM_EVIDENCE_KINDS,
    TRUSTED_INDEPENDENT_OBSERVER_SOURCES,
    TRUSTED_LOCAL_COLLECTOR_SOURCES,
    WRAPPER_EVIDENCE_KINDS,
    Evidence,
    canonical_provenance,
    has_negative_verification_or_correlation,
    is_adapter_observed_request,
    is_execution_verified,
    public_evidence_data,
)
from core.models.evidence_v2 import (
    EVIDENCE_CONTRACT_V2_VERSION,
    EXECUTION_SCOPES,
    MAX_CONTRADICTIONS,
    MAX_EVIDENCE_REFERENCES,
    MAX_INPUT_DEPTH,
    MAX_LIMITATIONS,
    MAX_MISSING_INDICATORS,
    MAX_OBSERVATION_RECORDS,
    MAX_REASON_CODES,
    MAX_RESPONSE_CHARS,
    MAX_TEXT_PREVIEW,
    RESPONSE_ONLY_SCOPES,
    SUPPORTED_EVALUATION_SCOPES,
    ActionPresenceState,
    CorrelationContextV2,
    CorrelationStrengthV2,
    CoverageState,
    EvidenceContractV2,
    EvidenceFindingV2,
    ExecutionObservationKind,
    ExecutionObservationRecordV2,
    ExecutionVerificationStatus,
    HighestTrustClassification,
    ObservationCoverageV2,
    RefusalState,
    ResponseCompleteness,
    ResponseObservationV2,
    ScopeAlignmentStatus,
    ScopeAlignmentV2,
    ScopeFamily,
    ToolIntentOrigin,
    ToolIntentRecordV2,
    TrustClassification,
)
from core.models.execution import ExecutionResult
from core.models.observation import Observation
from core.models.provenance import canonical_sha256
from core.models.tool_intent import extract_tool_intent_signals

_HEX64_RE = re.compile(r"^[a-f0-9]{64}$")
_CORR_REF_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
_CANONICAL_SHA_REF_RE = re.compile(r"^(?:(?:response|(?:v1-)?ev-\d+):)?sha256:[a-f0-9]{64}$")
_OPAQUE_HEX_RE = re.compile(r"\b[a-fA-F0-9]{24,}\b")
_MAX_SURFACE_SCAN_CHARS = 131_072

_SAFE_SHA256_KEYS = frozenset({
    "response_sha256",
    "arguments_sha256",
    "effect_sha256",
    "evidence_sha256",
    "envelope_sha256",
})

_SAFE_ENUM_VALUES_BY_KEY: dict[str, frozenset[str]] = {
    "contract_version": frozenset({EVIDENCE_CONTRACT_V2_VERSION}),
    "projection_origin": frozenset({"live_observation", "historical_v1_projection"}),
    "completeness": frozenset({"complete", "partial", "unknown", "missing"}),
    "response_completeness": frozenset({"complete", "partial", "unknown", "missing"}),
    "request_trace_completeness": frozenset({"complete", "partial", "unknown", "missing"}),
    "action_trace_completeness": frozenset({
        "complete",
        "partial",
        "unknown",
        "missing",
        "contradicted",
        "verified_absence",
    }),
    "action_presence": frozenset({
        "action_observed",
        "no_action_within_complete_coverage",
        "coverage_incomplete_or_unknown",
    }),
    "refusal_state": frozenset({"refusal_observed", "refusal_not_established", "not_applicable"}),
    "explicit_refusal": frozenset({"refusal_observed", "refusal_not_established", "not_applicable"}),
    "trust_classification": frozenset({
        "model_reported",
        "target_reported",
        "adapter_observed",
        "independently_verified",
    }),
    "highest_trust_classification": frozenset({
        "none",
        "model_reported",
        "target_reported",
        "adapter_observed",
        "independently_verified",
    }),
    "verified_execution_status": frozenset({
        "verified_runtime_effect",
        "verified_attempted_failed",
        "verified_simulated_effect",
        "unverified_claim",
        "contradicted",
        "none",
    }),
    "execution_kind": frozenset({
        "real_runtime_effect",
        "simulated_handler_effect",
        "verified_attempted_failed",
        "target_reported_result",
        "unverified_execution_claim",
    }),
    "intent_origin": frozenset({
        "model_emitted_text",
        "declared_tool_call",
        "adapter_observed_request",
        "mcp_request_dispatched",
        "rejected_tool_call",
    }),
    "correlation_strength": frozenset({"strong", "weak", "none", "unknown"}),
    "scope_family": frozenset({"response_only", "execution", "unknown", "unsupported"}),
    "alignment_status": frozenset({
        "compatible",
        "insufficient_evidence_for_scope",
        "scope_mismatch",
        "scope_unknown",
    }),
    "category": frozenset({
        "contradiction",
        "missing",
        "correlation",
        "trust_escalation_blocked",
        "scope_gap",
    }),
    "effective_scope": SUPPORTED_EVALUATION_SCOPES,
    "effective_evaluation_scope": SUPPORTED_EVALUATION_SCOPES,
}

_PRESERVED_MARKER_RE = re.compile(
    r"(\[(?:CANARY_SHA256|ID_SHA256):[a-f0-9]{64}\]|\[URL_REDACTED:[a-f0-9]{16}\]|\[(?:CREDENTIAL_REDACTED|TOKEN_REDACTED|OPAQUE_REDACTED|REDACTED)\])"
)
_PRIVATE_KEY_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]{0,4096}?(?:-----END [A-Z ]*PRIVATE KEY-----|$)")
_URL_RE = re.compile(r'https?://[^\s"<>]+')
_CANARY_RE = re.compile(r"(?i)canary[-_][A-Za-z0-9_-]+")
_SK_RE = re.compile(r"\bsk-[A-Za-z0-9_-]+")
_BEARER_RE = re.compile(r"(?i)\bBearer\s+[^\s\"<>]+")
_BASIC_RE = re.compile(r"(?i)\bBasic\s+[A-Za-z0-9+/=]{6,}")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
_KV_SECRET_RE = re.compile(
    r'''(?ix)(\b(?:api[_-]?key|password|secret|access[_-]?token|canary|authorization|cookie|session[_-]?token)\b["']?\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s,;<>"']+)'''
)

# Conservative explicit surface cues (metadata facts only — never a PASS/FAIL grader).
_EXPLICIT_REFUSAL_RE = re.compile(
    r"(?i)(?:"
    r"\bi\s+(?:cannot|can't|will\s+not|won't|must\s+not|am\s+unable\s+to|refuse\s+to)\b"
    r"|\bi'm\s+(?:unable\s+to|not\s+able\s+to|sorry,?\s+(?:but\s+)?i\s+(?:cannot|can't))\b"
    r"|\b(?:cannot|can't|unable\s+to)\s+(?:comply|fulfill|assist\s+with|execute|perform|run|provide|disclose)\b"
    r"|\b(?:not\s+permitted|not\s+authorized|against\s+(?:my\s+)?(?:policy|guidelines))\b"
    r"|tôi\s+(?:không\s+thể|từ\s+chối|không\s+được\s+phép)"
    r")"
)
_IDENTITY_CLAIM_RE = re.compile(
    r"(?i)(?:"
    r"\b(?:i\s+am|acting\s+as|logged\s+in\s+as|authenticated\s+as|granted)\s+(?:an?\s+)?(?:admin|administrator|root|superuser|system\s+admin|privileged\s+user)\b"
    r"|\b(?:elevated|admin|administrator|root)\s+(?:privileges?|access|role)\s+(?:granted|enabled|active)\b"
    r")"
)
_COMMAND_SUGGESTION_RE = re.compile(
    r"(?i)(?:"
    r"```(?:bash|sh|shell|zsh|cmd|powershell|pwsh)\b"
    r"|\b(?:sudo\s+\S+|rm\s+-rf\b|chmod\s+[0-7]{3,4}\b|curl\s+[^\n]{0,120}\|\s*(?:sh|bash)\b|bash\s+-c\b|powershell\s+-|os\.system\(|subprocess\.(?:run|Popen|call)\()"
    r")"
)

_TOOL_INTENT_KINDS = frozenset({
    "model_reported_tool_intent",
    "agent_tool_intent",
    "declared_tool_call",
    "tool_request",
    "secagent_mcp_request",
    "rejected_tool_call",
})

_TRACE_COVERAGE_KINDS = frozenset({
    "tool_trace",
    "asi05_execution_trace",
    "agent_bridge_trace",
    "collector_diagnostic",
})

_EXECUTION_KINDS = frozenset({
    "tool_call",
    "collected_evidence",
    "collector_receipt",
    "target_tool_result",
    "target_mcp_response",
    "target_inline_event",
    "target_web_fetch",
    "target_outbound_callback",
    "agent_bridge_tool_call",
    "handler_receipt",
    "asi05_execution_action",
})

_TRUSTED_TRACE_SOURCES = (
    TRUSTED_INDEPENDENT_OBSERVER_SOURCES
    | TRUSTED_LOCAL_COLLECTOR_SOURCES
    | COLLECTOR_EVIDENCE_SOURCES
    | frozenset({"asi05_execution_fixture", "asi05_agent_mcp_observer", "asi05_mcp_request_observer"})
)


class _TextSanitizer:
    """Bounded secret/PII sanitizer for Evidence Contract v2 strings."""

    def __init__(self, sensitive_values: Sequence[str] = ()) -> None:
        cleaned = sorted(
            {v for v in sensitive_values if isinstance(v, str) and v},
            key=len,
            reverse=True,
        )
        self._secret_re = (
            re.compile("|".join(re.escape(v) for v in cleaned))
            if cleaned
            else None
        )

    def contains_secret(self, text: str) -> bool:
        return bool(self._secret_re and text and self._secret_re.search(text))

    def redact_secrets(self, text: str) -> str:
        if not self._secret_re or not text:
            return text
        parts = _PRESERVED_MARKER_RE.split(text)
        for idx in range(0, len(parts), 2):
            if parts[idx]:
                parts[idx] = self._secret_re.sub("[REDACTED]", parts[idx])
        return "".join(parts)

    def clean(
        self,
        value: Any,
        *,
        limit: int = 256,
        preserve_hex64: bool = False,
        redact_opaque: bool = False,
    ) -> str | None:
        if value is None or not isinstance(value, str):
            return None
        text = value.strip()
        if not text:
            return None
        if preserve_hex64 and _HEX64_RE.fullmatch(text) and not self.contains_secret(text):
            return text
        if _CANONICAL_SHA_REF_RE.fullmatch(text) and not self.contains_secret(text):
            return text
        text = _PRIVATE_KEY_RE.sub("[CREDENTIAL_REDACTED]", text)
        text = _URL_RE.sub(
            lambda m: "[URL_REDACTED:" + sha256(m[0].encode("utf-8")).hexdigest()[:16] + "]",
            text,
        )
        text = _CANARY_RE.sub(
            lambda m: "[CANARY_SHA256:" + sha256(m[0].encode("utf-8")).hexdigest() + "]",
            text,
        )
        text = self.redact_secrets(text)
        parts = _PRESERVED_MARKER_RE.split(text)
        for idx in range(0, len(parts), 2):
            seg = parts[idx]
            if not seg:
                continue
            seg = _SK_RE.sub("[CREDENTIAL_REDACTED]", seg)
            seg = _BEARER_RE.sub("Bearer [REDACTED]", seg)
            seg = _BASIC_RE.sub("Basic [REDACTED]", seg)
            seg = _JWT_RE.sub("[TOKEN_REDACTED]", seg)
            seg = _KV_SECRET_RE.sub(lambda m: m[1] + "[REDACTED]", seg)
            if redact_opaque:
                seg = _OPAQUE_HEX_RE.sub("[OPAQUE_REDACTED]", seg)
            parts[idx] = seg
        out = "".join(parts).strip()
        if not out:
            return None
        return out[:limit]


def _exceeds_depth(obj: Any, *, max_depth: int = MAX_INPUT_DEPTH) -> bool:
    stack: list[tuple[Any, int]] = [(obj, 0)]
    while stack:
        current, depth = stack.pop()
        if depth > max_depth:
            return True
        if isinstance(current, Mapping):
            for v in current.values():
                if isinstance(v, (Mapping, list, tuple)):
                    stack.append((v, depth + 1))
        elif isinstance(current, (list, tuple)):
            for v in current:
                if isinstance(v, (Mapping, list, tuple)):
                    stack.append((v, depth + 1))
    return False


def _valid_hex64(value: Any) -> str | None:
    if isinstance(value, str) and _HEX64_RE.fullmatch(value):
        return value
    return None


def _valid_corr_ref(value: Any) -> str | None:
    if isinstance(value, str) and _CORR_REF_RE.fullmatch(value):
        return value
    return None


def _normalize_scope(effective_scope: Any) -> tuple[str | None, ScopeFamily, list[str]]:
    if effective_scope is None:
        return None, "unknown", ["evaluation_scope_unspecified"]
    if not isinstance(effective_scope, str) or not effective_scope.strip() or effective_scope != effective_scope.strip():
        return None, "unsupported", ["evaluation_scope_invalid"]
    if effective_scope in RESPONSE_ONLY_SCOPES:
        return effective_scope, "response_only", []
    if effective_scope in EXECUTION_SCOPES:
        return effective_scope, "execution", []
    return effective_scope[:128], "unsupported", ["evaluation_scope_unsupported"]


def _add_unique(target: list[str], item: str, *, limit: int) -> None:
    if item and item not in target and len(target) < limit:
        target.append(item)


def _add_finding(
    target: list[EvidenceFindingV2],
    *,
    code: str,
    category: str,
    message: str,
    record_ids: Sequence[str] = (),
    limit: int,
) -> None:
    if len(target) >= limit:
        return
    clean_ids = [rid for rid in record_ids if isinstance(rid, str) and rid][:16]
    for existing in target:
        if existing.code == code and existing.record_ids == clean_ids and existing.message == message:
            return
    target.append(
        EvidenceFindingV2(
            code=code[:256],
            category=category,  # type: ignore[arg-type]
            message=message[:512],
            record_ids=clean_ids,
        )
    )


def _coerce_diagnostic_dict(item: Any) -> dict[str, Any] | None:
    if isinstance(item, Mapping):
        return dict(item)
    if is_dataclass(item) and not isinstance(item, type):
        return asdict(item)
    return None


def _build_response_observation(
    observation: Observation | None,
    execution_result: ExecutionResult | None,
    sanitizer: _TextSanitizer,
    *,
    include_response_preview: bool,
    contradictions: list[EvidenceFindingV2],
    missing_indicators: list[EvidenceFindingV2],
    limitations: list[str],
    reason_codes: list[str],
) -> ResponseObservationV2:
    meta = observation.metadata if observation is not None and isinstance(observation.metadata, dict) else {}
    raw_text = observation.response_text if observation is not None else None
    if raw_text is None and execution_result is not None:
        raw_text = execution_result.output_text

    obs_complete = meta.get("response_complete") if type(meta.get("response_complete")) is bool else None
    exec_complete = (
        execution_result.response_complete
        if execution_result is not None and type(execution_result.response_complete) is bool
        else None
    )
    if obs_complete is not None and exec_complete is not None and obs_complete != exec_complete:
        _add_finding(
            contradictions,
            code="conflicting_response_completeness",
            category="contradiction",
            message="ExecutionResult.response_complete and Observation.metadata['response_complete'] disagree.",
            limit=MAX_CONTRADICTIONS,
        )
        _add_unique(reason_codes, "conflicting_response_completeness", limit=MAX_REASON_CODES)
        effective_complete: bool | None = False if (obs_complete is False or exec_complete is False) else None
    else:
        effective_complete = obs_complete if obs_complete is not None else exec_complete

    exec_failed = execution_result is not None and execution_result.success is False
    observed = isinstance(raw_text, str) and len(raw_text) > 0 and not exec_failed

    if not observed:
        completeness: ResponseCompleteness = "missing" if (raw_text is None or exec_failed) else "unknown"
        return ResponseObservationV2(
            observed=False,
            completeness=completeness,
            response_sha256=None,
            response_char_count=0,
            response_preview=None,
            explicit_refusal="not_applicable",
            identity_claim_present=False,
            command_suggestion_present=False,
            textual_tool_claim_present=False,
            trust_classification="target_reported",
            proves_execution=False,
        )

    assert isinstance(raw_text, str)
    raw_len = len(raw_text)
    oversized = raw_len > MAX_RESPONSE_CHARS
    if oversized:
        bounded_text = raw_text[:MAX_RESPONSE_CHARS]
        char_count = MAX_RESPONSE_CHARS
        completeness = "partial"
        _add_finding(
            missing_indicators,
            code="response_text_exceeded_max_chars",
            category="missing",
            message=(
                f"Observed response exceeded maximum bounded length ({MAX_RESPONSE_CHARS} chars); "
                "truncated for evidence normalization and marked partial."
            ),
            limit=MAX_MISSING_INDICATORS,
        )
        _add_unique(reason_codes, "response_text_exceeded_max_chars", limit=MAX_REASON_CODES)
        _add_unique(
            limitations,
            f"Response text exceeded {MAX_RESPONSE_CHARS} chars; truncated and never treated as complete.",
            limit=MAX_LIMITATIONS,
        )
    else:
        bounded_text = raw_text
        char_count = raw_len
        if effective_complete is True:
            completeness = "complete"
        elif effective_complete is False:
            completeness = "partial"
        else:
            completeness = "unknown"

    response_digest = sha256(bounded_text.encode("utf-8", errors="replace")).hexdigest()
    scan_text = bounded_text[:_MAX_SURFACE_SCAN_CHARS]
    preview = (
        sanitizer.clean(bounded_text[: MAX_TEXT_PREVIEW * 4], limit=MAX_TEXT_PREVIEW)
        if include_response_preview
        else None
    )

    explicit_refusal_meta = meta.get("refusal_observed")
    if explicit_refusal_meta is True:
        refusal_state: RefusalState = "refusal_observed"
    elif explicit_refusal_meta is False:
        refusal_state = "refusal_not_established"
    else:
        refusal_state = "refusal_observed" if _EXPLICIT_REFUSAL_RE.search(scan_text) else "refusal_not_established"

    identity_claim = bool(_IDENTITY_CLAIM_RE.search(scan_text))
    command_suggestion = bool(_COMMAND_SUGGESTION_RE.search(scan_text))

    textual_tool_claim = False
    if observation is not None and any(ev.kind == "model_reported_tool_intent" for ev in observation.evidence):
        textual_tool_claim = True
    else:
        try:
            signal = extract_tool_intent_signals(scan_text)
            textual_tool_claim = bool(signal.detected)
        except Exception:
            textual_tool_claim = False

    return ResponseObservationV2(
        observed=True,
        completeness=completeness,
        response_sha256=response_digest,
        response_char_count=char_count,
        response_preview=preview,
        explicit_refusal=refusal_state,
        identity_claim_present=identity_claim,
        command_suggestion_present=command_suggestion,
        textual_tool_claim_present=textual_tool_claim,
        trust_classification="target_reported",
        proves_execution=False,
    )


def _check_correlation_against_context(
    data: Mapping[str, Any],
    corr_ctx: CorrelationContextV2,
    *,
    is_collector: bool,
    is_local_receipt: bool,
    is_trusted_observer: bool,
    observed_request_corr_refs: frozenset[str] = frozenset(),
    observed_request_inv_ids: frozenset[str] = frozenset(),
) -> tuple[bool, CorrelationStrengthV2, str, list[str]]:
    """Verify record correlation strictly against SecAgent's trusted correlation context.

    Never equates bare identifier existence with verified binding to the current
    run/execution/testcase/target context.

    Returns (correlation_verified, correlation_strength, correlation_status, mismatch_codes).
    """
    mismatches: list[str] = []
    checks: tuple[tuple[str, str | None], ...] = (
        ("run_id", corr_ctx.secagent_run_id),
        ("execution_id", corr_ctx.secagent_execution_id),
        ("case_id", corr_ctx.secagent_testcase_id),
        ("testcase_id", corr_ctx.secagent_testcase_id),
        ("target_id", corr_ctx.secagent_target_id),
        ("request_id", corr_ctx.request_id),
        ("session_id", corr_ctx.session_id),
    )
    matched_fields: list[str] = []
    for key, expected in checks:
        raw_val = data.get(key)
        if isinstance(raw_val, str) and raw_val.strip():
            actual = raw_val.strip()
            if expected and actual != expected:
                mismatches.append(f"mismatched_{key}")
            elif expected and actual == expected:
                matched_fields.append(key)

    # Target-reported correlation IDs never establish independent verification,
    # but a direct conflict with the observation's target_correlation_id must fail closed.
    raw_tcorr = data.get("target_correlation_id")
    if (
        isinstance(raw_tcorr, str)
        and raw_tcorr.strip()
        and corr_ctx.target_correlation_id
        and raw_tcorr.strip() != corr_ctx.target_correlation_id
    ):
        mismatches.append("mismatched_target_correlation_id")

    if mismatches:
        return False, "none", "mismatch", mismatches

    raw_status = data.get("correlation_status")
    norm_status = raw_status.strip().lower() if isinstance(raw_status, str) and raw_status.strip() else None
    raw_strength = data.get("correlation_strength")
    norm_strength = raw_strength.strip().lower() if isinstance(raw_strength, str) and raw_strength.strip() else None

    if data.get("correlation_valid") is False:
        return False, "none", norm_status or "invalid", []
    if norm_status in NEGATIVE_CORRELATION_STATUSES:
        return False, "none", norm_status, []
    if norm_strength in NEGATIVE_CORRELATION_STRENGTHS:
        strength_val: CorrelationStrengthV2 = "weak" if norm_strength == "weak" else "none"
        return False, strength_val, norm_status or "weak_correlation", []

    corr_ref = _valid_corr_ref(data.get("correlation_reference"))
    raw_inv_id = data.get("invocation_id")
    inv_id = raw_inv_id.strip() if isinstance(raw_inv_id, str) and raw_inv_id.strip() else None
    has_backend_req_binding = bool(
        (corr_ref is not None and corr_ref in observed_request_corr_refs)
        or (inv_id is not None and inv_id in observed_request_inv_ids)
    )
    has_context_binding = bool(matched_fields)

    if is_collector:
        if norm_status in {"matched", "verified"} and norm_strength == "strong":
            if has_context_binding:
                return True, "strong", norm_status, []
            return False, "none", "missing_context_binding", []
        if norm_strength == "weak":
            return False, "weak", norm_status or "weak", []
        return False, "none" if norm_strength == "none" else "unknown", norm_status or "missing", []

    if is_local_receipt:
        if data.get("correlation_valid") is True and data.get("page_served") is True:
            if has_context_binding:
                return True, "strong", norm_status or "verified", []
            return False, "none", "missing_context_binding", []
        return False, "none", norm_status or "unverified", []

    if is_trusted_observer:
        if has_context_binding or has_backend_req_binding:
            strength_obs: CorrelationStrengthV2 = (
                "strong"
                if (
                    len(matched_fields) >= 2
                    or has_backend_req_binding
                    or "execution_id" in matched_fields
                    or "run_id" in matched_fields
                )
                else "weak"
            )
            return True, strength_obs, norm_status or "verified", []
        return False, "none", "missing_context_binding", []

    if matched_fields:
        strength_fallback: CorrelationStrengthV2 = "strong" if len(matched_fields) >= 2 else "weak"
        return False, strength_fallback, norm_status or "untrusted_source", []
    return False, "unknown", norm_status or "unverified", []


def _intent_origin_for(item: Evidence) -> ToolIntentOrigin:
    if item.kind in {"model_reported_tool_intent", "agent_tool_intent"}:
        return "model_emitted_text"
    if item.kind == "declared_tool_call":
        return "declared_tool_call"
    if item.kind == "secagent_mcp_request":
        return "mcp_request_dispatched"
    if item.kind == "rejected_tool_call":
        return "rejected_tool_call"
    return "adapter_observed_request"


def _is_synthetic_evidence(item: Evidence) -> bool:
    data = item.data if isinstance(item.data, dict) else {}
    return bool(
        data.get("synthetic_mock") is True
        or data.get("source_provenance") == "synthetic_mock"
        or data.get("execution_semantics") in {"simulated_handler_effect", "simulated_handler_invocation"}
        or item.source in {"local_tool_fixture", "asi05_execution_fixture"}
    )


def boundary_covers_execution_scope(
    boundary: str | None,
    effective_scope: str | None,
    *,
    required_trace_scope: str | None = None,
) -> bool:
    """Return True ONLY when a trusted verified_absence_boundary covers the required execution scope.

    Relies strictly on SecAgent's trusted producer/collector boundary tokens
    (never on arbitrary target-declared labels or unrelated surfaces).
    """
    if not isinstance(boundary, str) or not boundary.strip():
        return False
    target_scope = (
        required_trace_scope.strip()
        if isinstance(required_trace_scope, str) and required_trace_scope.strip()
        else effective_scope
    )
    if not isinstance(target_scope, str) or target_scope not in EXECUTION_SCOPES:
        return False

    tokens = [part.strip() for part in boundary.split(",") if part.strip()]
    if not tokens:
        return False

    trusted_runtime_sources = TRUSTED_INDEPENDENT_OBSERVER_SOURCES | frozenset({"asi05_execution_fixture"})
    for token in tokens:
        if ":" not in token:
            continue
        source, surface = token.split(":", 1)
        source = source.strip()
        surface = surface.strip()
        if not source or not surface:
            continue

        if target_scope == "web_callback":
            if (source == "local_collector" and surface == "collector_receipt") or (
                source == "http_callback_collector" and surface in {"http_callback", "web_callback", "collector"}
            ) or (source in trusted_runtime_sources and surface == "web_callback"):
                return True
        elif target_scope == "web_fetch":
            if source in trusted_runtime_sources and surface == "web_fetch":
                return True
        elif target_scope == "direct_request":
            if (source in trusted_runtime_sources and surface == "direct_request") or (
                source == "mcp_receipt_collector" and surface in {"direct_request", "mcp_receipt"}
            ):
                return True
        elif target_scope == "agent_run":
            if source in (trusted_runtime_sources - {"local_tool_fixture"}) and surface == "agent_run":
                return True
        elif target_scope == "execution_action":
            if (
                (source in (trusted_runtime_sources - {"local_tool_fixture"}) and surface == "execution_action")
                or (source == "sandbox_log_collector" and surface in {"execution_action", "sandbox_log"})
                or (source == "file_artifact_collector" and surface in {"execution_action", "file_artifact"})
            ):
                return True
    return False


def _classify_scope_alignment(
    effective_scope: str | None,
    scope_family: ScopeFamily,
    response_obs: ResponseObservationV2,
    coverage: ObservationCoverageV2,
    verified_execution_status: ExecutionVerificationStatus,
    verified_execution_present: bool,
    contradictions: Sequence[EvidenceFindingV2],
    scope_init_reasons: Sequence[str],
) -> ScopeAlignmentV2:
    reasons: list[str] = list(scope_init_reasons)
    limitations: list[str] = []

    if scope_family == "unknown":
        limitations.append("No backend-confirmed evaluation_scope was supplied; scope alignment is unknown.")
        return ScopeAlignmentV2(
            effective_scope=None,
            scope_family="unknown",
            alignment_status="scope_unknown",
            requires_execution_evidence=False,
            response_evidence_sufficient_for_scope=response_obs.observed and response_obs.completeness == "complete",
            execution_evidence_sufficient_for_scope=verified_execution_present,
            reason_codes=reasons[:MAX_REASON_CODES],
            limitations=limitations[:MAX_LIMITATIONS],
        )

    if scope_family == "unsupported":
        limitations.append(
            "Declared evaluation_scope is not in SecAgent's supported scope taxonomy; scope was not downgraded."
        )
        return ScopeAlignmentV2(
            effective_scope=effective_scope,
            scope_family="unsupported",
            alignment_status="scope_mismatch",
            requires_execution_evidence=False,
            response_evidence_sufficient_for_scope=False,
            execution_evidence_sufficient_for_scope=False,
            reason_codes=reasons[:MAX_REASON_CODES],
            limitations=limitations[:MAX_LIMITATIONS],
        )

    if scope_family == "response_only":
        resp_sufficient = response_obs.observed and response_obs.completeness == "complete"
        if not response_obs.observed:
            _add_unique(reasons, "missing_response_observation", limit=MAX_REASON_CODES)
            limitations.append("Response-only scope requires an observed response text.")
            alignment: ScopeAlignmentStatus = "insufficient_evidence_for_scope"
        elif response_obs.completeness != "complete":
            _add_unique(reasons, f"response_completeness_{response_obs.completeness}", limit=MAX_REASON_CODES)
            limitations.append(
                f"Response completeness is '{response_obs.completeness}'; complete response is required for decisive response-only assessment."
            )
            alignment = "insufficient_evidence_for_scope"
        else:
            _add_unique(reasons, "response_scope_evidence_available", limit=MAX_REASON_CODES)
            alignment = "compatible"
        limitations.append(
            "Response-only scope does not observe runtime execution or external side effects; agent speech never proves execution."
        )
        return ScopeAlignmentV2(
            effective_scope=effective_scope,
            scope_family="response_only",
            alignment_status=alignment,
            requires_execution_evidence=False,
            response_evidence_sufficient_for_scope=resp_sufficient,
            execution_evidence_sufficient_for_scope=verified_execution_present,
            reason_codes=reasons[:MAX_REASON_CODES],
            limitations=limitations[:MAX_LIMITATIONS],
        )

    # Execution scope (never downgraded to response-only).
    absence_covers_scope = (
        coverage.action_presence == "no_action_within_complete_coverage"
        and boundary_covers_execution_scope(coverage.verified_absence_boundary, effective_scope)
    )
    exec_sufficient = (
        not contradictions
        and (
            verified_execution_present
            or absence_covers_scope
        )
    )
    if contradictions and verified_execution_status == "contradicted":
        _add_unique(reasons, "execution_evidence_contradicted", limit=MAX_REASON_CODES)
        limitations.append("Contradictory execution or correlation evidence prevents verified execution proof.")
        alignment = "insufficient_evidence_for_scope"
    elif exec_sufficient:
        if verified_execution_present:
            _add_unique(reasons, "verified_execution_evidence_available", limit=MAX_REASON_CODES)
        else:
            _add_unique(reasons, "verified_absence_within_complete_trace", limit=MAX_REASON_CODES)
        alignment = "compatible"
    elif coverage.action_presence == "no_action_within_complete_coverage" and not absence_covers_scope:
        _add_unique(reasons, "absence_boundary_scope_mismatch", limit=MAX_REASON_CODES)
        limitations.append(
            f"Verified absence boundary '{coverage.verified_absence_boundary}' does not cover execution scope '{effective_scope}'."
        )
        alignment = "insufficient_evidence_for_scope"
    else:
        _add_unique(reasons, "missing_verified_execution_evidence", limit=MAX_REASON_CODES)
        limitations.append(
            f"Execution scope '{effective_scope}' requires independently verified execution evidence or a proven complete trace covering the required scope; response claims or incomplete traces are insufficient and scope was not downgraded."
        )
        alignment = "insufficient_evidence_for_scope"

    return ScopeAlignmentV2(
        effective_scope=effective_scope,
        scope_family="execution",
        alignment_status=alignment,
        requires_execution_evidence=True,
        response_evidence_sufficient_for_scope=False,
        execution_evidence_sufficient_for_scope=exec_sufficient,
        reason_codes=reasons[:MAX_REASON_CODES],
        limitations=limitations[:MAX_LIMITATIONS],
    )


def build_evidence_contract_v2(
    *,
    observation: Observation | None = None,
    execution_result: ExecutionResult | None = None,
    effective_scope: str | None = None,
    run_id: str | None = None,
    execution_id: str | None = None,
    testcase_id: str | None = None,
    target_id: str | None = None,
    request_id: str | None = None,
    session_id: str | None = None,
    collector_diagnostics: Sequence[Any] = (),
    sensitive_values: Sequence[str] = (),
    include_response_preview: bool = False,
) -> EvidenceContractV2:
    """Build a fail-closed EvidenceContractV2 from an Observation and ExecutionResult.

    Pure, offline, side-effect-free function:
    - Never performs network, filesystem, shell, Docker, Target, or Judge calls.
    - Never reads untrusted URLs or file paths.
    - Never alters verdicts or downgrades evaluation scopes.
    """
    sanitizer = _TextSanitizer(sensitive_values)
    meta = observation.metadata if observation is not None and isinstance(observation.metadata, dict) else {}

    # Trusted correlation context comes strictly from caller/Runner metadata.
    eff_run_id = sanitizer.clean(run_id or meta.get("secagent_run_id"), limit=256, preserve_hex64=True)
    eff_exec_id = sanitizer.clean(execution_id or meta.get("secagent_execution_id"), limit=256, preserve_hex64=True)
    eff_case_id = sanitizer.clean(testcase_id or meta.get("secagent_testcase_id"), limit=256, preserve_hex64=True)
    eff_target_id = sanitizer.clean(target_id or meta.get("secagent_target_id"), limit=256, preserve_hex64=True)
    raw_target_corr = meta.get("target_correlation_id") or (
        execution_result.target_correlation_id if execution_result is not None else None
    )
    eff_target_corr = sanitizer.clean(raw_target_corr, limit=256, preserve_hex64=True)
    eff_req_id = sanitizer.clean(request_id, limit=256, preserve_hex64=True)
    eff_sess_id = sanitizer.clean(session_id, limit=256, preserve_hex64=True)

    corr_ctx = CorrelationContextV2(
        secagent_run_id=eff_run_id,
        secagent_execution_id=eff_exec_id,
        secagent_testcase_id=eff_case_id,
        secagent_target_id=eff_target_id,
        target_correlation_id=eff_target_corr,
        request_id=eff_req_id,
        session_id=eff_sess_id,
    )

    contradictions: list[EvidenceFindingV2] = []
    missing_indicators: list[EvidenceFindingV2] = []
    reason_codes: list[str] = []
    limitations: list[str] = []
    evidence_references: list[str] = []

    norm_scope, scope_family, scope_init_reasons = _normalize_scope(effective_scope)
    for code in scope_init_reasons:
        _add_unique(reason_codes, code, limit=MAX_REASON_CODES)

    response_obs = _build_response_observation(
        observation,
        execution_result,
        sanitizer,
        include_response_preview=include_response_preview,
        contradictions=contradictions,
        missing_indicators=missing_indicators,
        limitations=limitations,
        reason_codes=reason_codes,
    )
    if response_obs.response_sha256:
        _add_unique(evidence_references, f"response:sha256:{response_obs.response_sha256}", limit=MAX_EVIDENCE_REFERENCES)

    raw_evidence = list(observation.evidence) if observation is not None else []
    if len(raw_evidence) > MAX_OBSERVATION_RECORDS:
        _add_unique(
            limitations,
            f"Evidence list truncated from {len(raw_evidence)} to {MAX_OBSERVATION_RECORDS} records.",
            limit=MAX_LIMITATIONS,
        )
        _add_unique(reason_codes, "evidence_records_truncated", limit=MAX_REASON_CODES)
        raw_evidence = raw_evidence[:MAX_OBSERVATION_RECORDS]

    # Collect backend-observed adapter request correlation bindings for this run.
    observed_req_corr_refs_set: set[str] = set()
    observed_req_inv_ids_set: set[str] = set()
    for ev in raw_evidence:
        if not is_adapter_observed_request(ev):
            continue
        ev_data = ev.data if isinstance(ev.data, dict) else {}
        if _exceeds_depth(ev_data):
            continue
        _, _, _, req_mismatches = _check_correlation_against_context(
            ev_data,
            corr_ctx,
            is_collector=False,
            is_local_receipt=False,
            is_trusted_observer=False,
        )
        if req_mismatches:
            continue
        ref_val = _valid_corr_ref(ev_data.get("correlation_reference"))
        if ref_val is not None:
            observed_req_corr_refs_set.add(ref_val)
        inv_val = ev_data.get("invocation_id")
        if isinstance(inv_val, str) and inv_val.strip():
            observed_req_inv_ids_set.add(inv_val.strip())
    observed_req_corr_refs = frozenset(observed_req_corr_refs_set)
    observed_req_inv_ids = frozenset(observed_req_inv_ids_set)

    tool_intents: list[ToolIntentRecordV2] = []
    execution_records: list[ExecutionObservationRecordV2] = []
    tiers_seen: set[TrustClassification] = set()
    if response_obs.observed:
        tiers_seen.add("target_reported")

    # Track trace completeness signals across trusted observers/collectors.
    complete_trace_boundaries: list[str] = []
    partial_trace_seen = False
    unknown_trace_seen = False
    trace_claims_nonzero_actions = False
    request_trace_states: set[str] = set()
    observer_fault = meta.get("asi05_execution_evidence_fault")
    if isinstance(observer_fault, str) and observer_fault.strip():
        _add_finding(
            contradictions,
            code="observer_evidence_fault",
            category="contradiction",
            message=f"Trusted observer reported an evidence fault ({sanitizer.clean(observer_fault, limit=128) or 'fault'}).",
            limit=MAX_CONTRADICTIONS,
        )
        _add_unique(reason_codes, "observer_evidence_fault", limit=MAX_REASON_CODES)

    # Check collector diagnostics for unavailable/error/scope_rejected/uncorrelated collectors.
    collector_coverage_broken = False
    for raw_diag in collector_diagnostics:
        diag = _coerce_diagnostic_dict(raw_diag)
        if diag is None:
            continue
        c_status = str(diag.get("status") or "").strip().lower()
        c_id = sanitizer.clean(str(diag.get("collector_id") or "collector"), limit=64) or "collector"
        if c_status in {"unavailable", "error", "scope_rejected"}:
            collector_coverage_broken = True
            _add_finding(
                missing_indicators,
                code=f"collector_{c_status}",
                category="missing",
                message=f"Evidence collector '{c_id}' reported status '{c_status}'; observation coverage is incomplete.",
                limit=MAX_MISSING_INDICATORS,
            )
            _add_unique(reason_codes, f"collector_{c_status}", limit=MAX_REASON_CODES)
        elif c_status == "uncorrelated":
            collector_coverage_broken = True
            _add_finding(
                missing_indicators,
                code="collector_uncorrelated",
                category="correlation",
                message=f"Evidence collector '{c_id}' returned only uncorrelated records.",
                limit=MAX_MISSING_INDICATORS,
            )
            _add_unique(reason_codes, "collector_uncorrelated", limit=MAX_REASON_CODES)

    # Track inter-record consistency keys -> list of (record_id, execution_verified, action_succeeded, explicit_executed).
    consistency_buckets: dict[str, list[tuple[str, bool, bool | None, bool | None]]] = {}

    for idx, item in enumerate(raw_evidence):
        rec_id = f"ev-{idx}"
        data = item.data if isinstance(item.data, dict) else {}
        if _exceeds_depth(data):
            _add_finding(
                contradictions,
                code="excessive_evidence_nesting",
                category="contradiction",
                message=f"Evidence record '{rec_id}' exceeded maximum allowed nesting depth; metadata ignored.",
                record_ids=[rec_id],
                limit=MAX_CONTRADICTIONS,
            )
            _add_unique(reason_codes, "excessive_evidence_nesting", limit=MAX_REASON_CODES)
            data = {}

        # Untrusted evidence must NEVER alter effective_evaluation_scope.
        ev_claimed_scope = data.get("evaluation_scope")
        if (
            isinstance(ev_claimed_scope, str)
            and ev_claimed_scope.strip()
            and norm_scope is not None
            and ev_claimed_scope.strip() != norm_scope
        ):
            _add_finding(
                contradictions,
                code="untrusted_scope_override_ignored",
                category="trust_escalation_blocked",
                message="Evidence record declared a different evaluation_scope than backend-confirmed scope; ignored.",
                record_ids=[rec_id],
                limit=MAX_CONTRADICTIONS,
            )
            _add_unique(reason_codes, "untrusted_scope_override_ignored", limit=MAX_REASON_CODES)

        pub = public_evidence_data(item)
        ev_digest = canonical_sha256({
            "kind": item.kind,
            "source": item.source,
            "name": sanitizer.clean(item.name, limit=128),
            "success": item.success,
            "reference": sanitizer.clean(item.reference, limit=256),
            "public_data": pub,
        })
        if item.reference:
            clean_ref = sanitizer.clean(item.reference, limit=200)
            if clean_ref:
                _add_unique(evidence_references, clean_ref, limit=MAX_EVIDENCE_REFERENCES)
        _add_unique(evidence_references, f"{rec_id}:sha256:{ev_digest}", limit=MAX_EVIDENCE_REFERENCES)

        base_provenance: TrustClassification = canonical_provenance(item)
        raw_claims_verified = data.get("execution_verified") is True
        raw_claims_independent = (
            isinstance(data.get("provenance"), str)
            and data["provenance"] in INDEPENDENT_PROVENANCE_LABELS
        )
        base_verified = is_execution_verified(item)

        # Wrapper records (http_response_metadata / stored_response) carry response completeness/metadata only.
        if item.kind in WRAPPER_EVIDENCE_KINDS:
            tiers_seen.add(base_provenance)
            if raw_claims_verified:
                _add_finding(
                    contradictions,
                    code="forged_execution_verified",
                    category="trust_escalation_blocked",
                    message="Response wrapper record attempted to claim execution_verified=True; rejected fail-closed.",
                    record_ids=[rec_id],
                    limit=MAX_CONTRADICTIONS,
                )
                _add_unique(reason_codes, "forged_execution_verified", limit=MAX_REASON_CODES)
            if raw_claims_independent:
                _add_finding(
                    contradictions,
                    code="forged_independent_provenance",
                    category="trust_escalation_blocked",
                    message="Response wrapper record attempted to claim independent provenance; rejected fail-closed.",
                    record_ids=[rec_id],
                    limit=MAX_CONTRADICTIONS,
                )
                _add_unique(reason_codes, "forged_independent_provenance", limit=MAX_REASON_CODES)
            continue

        # Tool intent / request records (Section 4.B).
        if item.kind in _TOOL_INTENT_KINDS or (
            item.kind == "asi05_execution_action"
            and data.get("execution_level") == "tool_invocation"
            and item.source in ADAPTER_REQUEST_SOURCES
        ):
            tiers_seen.add(base_provenance)
            if raw_claims_verified:
                _add_finding(
                    contradictions,
                    code="forged_execution_verified",
                    category="trust_escalation_blocked",
                    message="Tool intent/request record claimed execution_verified=True; tool intent never proves execution.",
                    record_ids=[rec_id],
                    limit=MAX_CONTRADICTIONS,
                )
                _add_unique(reason_codes, "forged_execution_verified", limit=MAX_REASON_CODES)
            tool_name = sanitizer.clean(item.name, limit=128)
            if tool_name is None and isinstance(data.get("invoked_tool_names"), list) and data["invoked_tool_names"]:
                tool_name = sanitizer.clean(data["invoked_tool_names"][0], limit=128)
            tool_intents.append(
                ToolIntentRecordV2(
                    record_id=rec_id,
                    kind=sanitizer.clean(item.kind, limit=128) or "tool_intent",
                    source=sanitizer.clean(item.source, limit=128) or "unknown",
                    tool_name=tool_name,
                    arguments_sha256=_valid_hex64(data.get("arguments_sha256")),
                    correlation_reference=_valid_corr_ref(data.get("correlation_reference")),
                    intent_origin=_intent_origin_for(item),
                    trust_classification=base_provenance,
                    proves_execution_success=False,
                    evidence_sha256=ev_digest,
                )
            )
            continue

        # Trace coverage / diagnostic records (Section 4.D).
        if item.kind in _TRACE_COVERAGE_KINDS:
            tiers_seen.add(base_provenance)
            is_trusted_source = item.source in _TRUSTED_TRACE_SOURCES
            corr_ok, _, _, corr_mismatches = _check_correlation_against_context(
                data,
                corr_ctx,
                is_collector=item.source in COLLECTOR_EVIDENCE_SOURCES,
                is_local_receipt=item.source in TRUSTED_LOCAL_COLLECTOR_SOURCES,
                is_trusted_observer=is_trusted_source,
                observed_request_corr_refs=observed_req_corr_refs,
                observed_request_inv_ids=observed_req_inv_ids,
            )
            if corr_mismatches:
                _add_finding(
                    contradictions,
                    code="cross_run_or_target_mismatch",
                    category="correlation",
                    message=f"Trace record '{rec_id}' failed correlation against current run/target ({', '.join(corr_mismatches)}).",
                    record_ids=[rec_id],
                    limit=MAX_CONTRADICTIONS,
                )
                _add_unique(reason_codes, "cross_run_or_target_mismatch", limit=MAX_REASON_CODES)

            req_comp = data.get("request_trace_completeness")
            if isinstance(req_comp, str) and req_comp in {"complete", "partial", "unknown"}:
                request_trace_states.add(req_comp)

            raw_comp = data.get("trace_completeness") or data.get("completeness")
            obs_complete_flag = data.get("observation_complete")
            if raw_comp == "complete" or obs_complete_flag is True:
                if (
                    is_trusted_source
                    and corr_ok
                    and not has_negative_verification_or_correlation(data)
                    and item.source not in {"http_response"}
                ):
                    scope_lbl = sanitizer.clean(str(data.get("scope") or data.get("source_provenance") or "trace"), limit=64) or "trace"
                    complete_trace_boundaries.append(f"{item.source}:{scope_lbl}")
                else:
                    partial_trace_seen = True
            elif raw_comp == "partial" or obs_complete_flag is False:
                partial_trace_seen = True
            else:
                unknown_trace_seen = True

            obs_count = data.get("observed_action_count")
            if type(obs_count) is int and obs_count > 0:
                trace_claims_nonzero_actions = True
            continue

        # Execution / receipt / collector / target-reported action records (Section 4.C).
        is_collector = item.kind == "collected_evidence" and item.source in COLLECTOR_EVIDENCE_SOURCES
        is_local_receipt = item.kind == "collector_receipt" and item.source in TRUSTED_LOCAL_COLLECTOR_SOURCES
        is_trusted_obs = item.kind in {"tool_call", "tool_trace"} and item.source in TRUSTED_INDEPENDENT_OBSERVER_SOURCES

        corr_ok, corr_strength, corr_status, corr_mismatches = _check_correlation_against_context(
            data,
            corr_ctx,
            is_collector=is_collector,
            is_local_receipt=is_local_receipt,
            is_trusted_observer=is_trusted_obs,
            observed_request_corr_refs=observed_req_corr_refs,
            observed_request_inv_ids=observed_req_inv_ids,
        )

        rec_contradictions: list[str] = []
        has_neg_meta = has_negative_verification_or_correlation(
            data, require_effect_observed=(item.source == "file_artifact_collector")
        )
        ver_status_raw = data.get("verification_status")
        ver_status_norm = ver_status_raw.strip().lower() if isinstance(ver_status_raw, str) else ""
        explicit_meta_conflict = (
            ver_status_norm.startswith("conflicting")
            or (raw_claims_verified and has_neg_meta)
            or (data.get("executed") is not None and type(data.get("executed")) is not bool)
            or (data.get("execution_verified") is not None and type(data.get("execution_verified")) is not bool)
            or (data.get("execution_verified") is True and data.get("executed") is False)
            or (data.get("execution_verified") is True and data.get("effect_verified") is False)
            or (data.get("execution_verified") is True and data.get("correlation_valid") is False)
        )

        # Fail-closed correlation and trust-escalation enforcement (Section 5).
        effective_verified = bool(base_verified and corr_ok and not corr_mismatches and not explicit_meta_conflict)
        effective_trust: TrustClassification = base_provenance
        if not effective_verified and effective_trust == "independently_verified":
            effective_trust = "target_reported" if corr_mismatches else "adapter_observed"
        if corr_mismatches:
            effective_trust = "target_reported"

        if corr_mismatches:
            msg = f"Record '{rec_id}' mismatched trusted correlation identifiers ({', '.join(corr_mismatches)})."
            rec_contradictions.append(msg)
            _add_finding(
                contradictions,
                code="cross_run_or_target_mismatch",
                category="correlation",
                message=msg,
                record_ids=[rec_id],
                limit=MAX_CONTRADICTIONS,
            )
            _add_unique(reason_codes, "cross_run_or_target_mismatch", limit=MAX_REASON_CODES)

        if explicit_meta_conflict:
            msg = f"Record '{rec_id}' contains conflicting execution/verification metadata; downgraded to unverified."
            rec_contradictions.append(msg)
            _add_finding(
                contradictions,
                code="conflicting_verification_metadata",
                category="contradiction",
                message=msg,
                record_ids=[rec_id],
                limit=MAX_CONTRADICTIONS,
            )
            _add_unique(reason_codes, "conflicting_verification_metadata", limit=MAX_REASON_CODES)
        elif raw_claims_verified and not base_verified:
            msg = f"Record '{rec_id}' claimed execution_verified=True without trusted independent verification; blocked fail-closed."
            rec_contradictions.append(msg)
            _add_finding(
                contradictions,
                code="forged_execution_verified",
                category="trust_escalation_blocked",
                message=msg,
                record_ids=[rec_id],
                limit=MAX_CONTRADICTIONS,
            )
            _add_unique(reason_codes, "forged_execution_verified", limit=MAX_REASON_CODES)

        if raw_claims_independent and not (is_collector or is_local_receipt or is_trusted_obs):
            msg = f"Record '{rec_id}' from untrusted source '{sanitizer.clean(item.source, limit=64)}' self-claimed independent provenance; blocked."
            rec_contradictions.append(msg)
            _add_finding(
                contradictions,
                code="forged_independent_provenance",
                category="trust_escalation_blocked",
                message=msg,
                record_ids=[rec_id],
                limit=MAX_CONTRADICTIONS,
            )
            _add_unique(reason_codes, "forged_independent_provenance", limit=MAX_REASON_CODES)

        if (is_collector or is_local_receipt or is_trusted_obs) and not corr_ok and not corr_mismatches:
            _add_finding(
                missing_indicators,
                code="weak_or_missing_correlation",
                category="correlation",
                message=f"Evidence record '{rec_id}' lacks verified correlation to current context (strength={corr_strength}, status={corr_status}).",
                record_ids=[rec_id],
                limit=MAX_MISSING_INDICATORS,
            )
            _add_unique(reason_codes, "weak_or_missing_correlation", limit=MAX_REASON_CODES)

        # Special case: zero-receipt local collector — proves absence ONLY when correlation to current context is verified!
        if (
            is_local_receipt
            and data.get("receipt_count") == 0
            and not effective_verified
        ):
            tiers_seen.add(effective_trust)
            if corr_ok and data.get("observation_complete") is True:
                complete_trace_boundaries.append(f"{item.source}:collector_receipt")
            else:
                partial_trace_seen = True
            continue

        # Also harvest trace completeness from verified collector receipts / tool calls if present.
        if is_local_receipt and corr_ok:
            if data.get("observation_complete") is True:
                complete_trace_boundaries.append(f"{item.source}:collector_receipt")
            elif data.get("observation_complete") is False:
                partial_trace_seen = True
        elif is_trusted_obs and corr_ok:
            if data.get("completeness") == "complete":
                complete_trace_boundaries.append(f"{item.source}:{data.get('scope') or 'tool_call'}")
            elif data.get("completeness") == "partial":
                partial_trace_seen = True
        elif is_collector and corr_ok:
            if data.get("trace_completeness") == "complete" or data.get("observation_complete") is True:
                complete_trace_boundaries.append(f"{item.source}:{data.get('collector_kind') or 'collector'}")
            elif data.get("trace_completeness") == "partial" or data.get("observation_complete") is False:
                partial_trace_seen = True

        # Check for zero-action complete collector record (empty verified trace marker).
        if (
            is_collector
            and corr_ok
            and data.get("observed_action_count") == 0
            and data.get("trace_completeness") == "complete"
            and not effective_verified
            and item.name is None
            and data.get("observed_action") is None
        ):
            tiers_seen.add(effective_trust)
            continue

        is_synth = _is_synthetic_evidence(item)
        action_succeeded: bool | None = item.success if type(item.success) is bool else None
        if action_succeeded is None and type(data.get("target_reported_success")) is bool:
            action_succeeded = data["target_reported_success"]
        if action_succeeded is None and isinstance(data.get("handler_status"), str):
            hs = data["handler_status"].strip().lower()
            if hs == "succeeded":
                action_succeeded = True
            elif hs in {"failed", "rejected"}:
                action_succeeded = False

        if effective_verified:
            if action_succeeded is False:
                exec_kind: ExecutionObservationKind = "verified_attempted_failed"
            elif is_synth:
                exec_kind = "simulated_handler_effect"
            else:
                exec_kind = "real_runtime_effect"
        elif item.kind in TARGET_CLAIM_EVIDENCE_KINDS or (
            item.source == "http_response"
        ):
            exec_kind = "target_reported_result"
        else:
            exec_kind = "unverified_execution_claim"

        tiers_seen.add(effective_trust)
        raw_action_name = (
            data.get("observed_action") or data.get("action") or data.get("claimed_action") or item.name
            if item.kind == "collected_evidence"
            else item.name or data.get("observed_action") or data.get("action") or data.get("claimed_action")
        )
        action_name = sanitizer.clean(raw_action_name, limit=128)
        arg_hash = _valid_hex64(data.get("arguments_sha256"))
        eff_hash = _valid_hex64(data.get("effect_sha256"))
        clean_ref = sanitizer.clean(item.reference, limit=256)

        rec = ExecutionObservationRecordV2(
            record_id=rec_id,
            kind=sanitizer.clean(item.kind, limit=128) or "execution",
            source=sanitizer.clean(item.source, limit=128) or "unknown",
            action_name=action_name,
            trust_classification=effective_trust,
            execution_kind=exec_kind,
            execution_verified=effective_verified,
            is_synthetic=is_synth,
            action_succeeded=action_succeeded,
            correlation_verified=corr_ok,
            correlation_strength=corr_strength,
            correlation_status=sanitizer.clean(corr_status, limit=64) or "unknown",
            arguments_sha256=arg_hash,
            effect_sha256=eff_hash,
            reference=clean_ref,
            evidence_sha256=ev_digest,
            contradictions=rec_contradictions[:16],
        )
        execution_records.append(rec)

        # Register in inter-record consistency bucket.
        bucket_key = (
            data.get("event_fingerprint")
            if isinstance(data.get("event_fingerprint"), str) and data["event_fingerprint"].strip()
            else (
                f"inv:{data['invocation_id']}"
                if isinstance(data.get("invocation_id"), str) and data["invocation_id"].strip()
                else (f"act:{action_name}:{arg_hash or ''}" if action_name else None)
            )
        )
        if bucket_key:
            explicit_exec = data.get("executed") if type(data.get("executed")) is bool else None
            consistency_buckets.setdefault(bucket_key, []).append(
                (rec_id, effective_verified, action_succeeded, explicit_exec)
            )

    # Detect inter-record contradictions (Section 5 rule 9: never silently pick higher trust).
    contradicted_record_ids: set[str] = set()
    for bucket_entries in consistency_buckets.values():
        if len(bucket_entries) < 2:
            continue
        rids = [e[0] for e in bucket_entries]
        verified_vals = {e[1] for e in bucket_entries}
        success_vals = {e[2] for e in bucket_entries if e[2] is not None}
        executed_vals = {e[3] for e in bucket_entries if e[3] is not None}
        if (
            (True in verified_vals and False in executed_vals)
            or (len(success_vals) > 1 and True in verified_vals)
            or (len(executed_vals) > 1)
        ):
            contradicted_record_ids.update(rids)
            _add_finding(
                contradictions,
                code="conflicting_execution_records",
                category="contradiction",
                message="Multiple evidence records for the same action disagree on execution or outcome.",
                record_ids=rids,
                limit=MAX_CONTRADICTIONS,
            )
            _add_unique(reason_codes, "conflicting_execution_records", limit=MAX_REASON_CODES)

    # If a record participates in an inter-record execution contradiction, downgrade it fail-closed.
    if contradicted_record_ids:
        updated_records: list[ExecutionObservationRecordV2] = []
        for rec in execution_records:
            if rec.record_id in contradicted_record_ids and rec.execution_verified:
                updated_records.append(
                    ExecutionObservationRecordV2(
                        record_id=rec.record_id,
                        kind=rec.kind,
                        source=rec.source,
                        action_name=rec.action_name,
                        trust_classification="adapter_observed",
                        execution_kind="unverified_execution_claim",
                        execution_verified=False,
                        is_synthetic=rec.is_synthetic,
                        action_succeeded=rec.action_succeeded,
                        correlation_verified=rec.correlation_verified,
                        correlation_strength=rec.correlation_strength,
                        correlation_status=rec.correlation_status,
                        arguments_sha256=rec.arguments_sha256,
                        effect_sha256=rec.effect_sha256,
                        reference=rec.reference,
                        evidence_sha256=rec.evidence_sha256,
                        contradictions=[*rec.contradictions, "conflicting_execution_records"][:16],
                    )
                )
            else:
                updated_records.append(rec)
        execution_records = updated_records

    # Trace completeness conflict check.
    trace_contradicted = False
    if complete_trace_boundaries and partial_trace_seen:
        trace_contradicted = True
        _add_finding(
            contradictions,
            code="conflicting_trace_completeness",
            category="contradiction",
            message="Conflicting trace completeness claims (both complete and partial observed).",
            limit=MAX_CONTRADICTIONS,
        )
        _add_unique(reason_codes, "conflicting_trace_completeness", limit=MAX_REASON_CODES)

    # Determine request_trace_completeness.
    if "complete" in request_trace_states and "partial" in request_trace_states:
        req_trace_comp: ResponseCompleteness = "partial"
    elif "complete" in request_trace_states:
        req_trace_comp = "complete"
    elif "partial" in request_trace_states:
        req_trace_comp = "partial"
    elif "unknown" in request_trace_states:
        req_trace_comp = "unknown"
    elif any(ti.intent_origin in {"adapter_observed_request", "mcp_request_dispatched"} for ti in tool_intents):
        req_trace_comp = "unknown"
    else:
        req_trace_comp = "missing"

    # Determine action presence and action_trace_completeness (Section 4.D & Section 7).
    has_observed_actions = bool(execution_records or tool_intents or trace_claims_nonzero_actions)
    verified_absence_boundary: str | None = None

    if trace_contradicted or (
        any(c.code in {"observer_evidence_fault", "conflicting_execution_records"} for c in contradictions)
    ):
        action_trace_comp: CoverageState = "contradicted"
        action_presence: ActionPresenceState = (
            "action_observed" if has_observed_actions else "coverage_incomplete_or_unknown"
        )
    elif complete_trace_boundaries and not collector_coverage_broken and not partial_trace_seen:
        if not has_observed_actions:
            action_trace_comp = "verified_absence"
            action_presence = "no_action_within_complete_coverage"
            verified_absence_boundary = ", ".join(dict.fromkeys(complete_trace_boundaries))[:512]
        else:
            action_trace_comp = "complete"
            action_presence = "action_observed"
    elif partial_trace_seen or collector_coverage_broken:
        action_trace_comp = "partial"
        action_presence = "action_observed" if has_observed_actions else "coverage_incomplete_or_unknown"
        if not has_observed_actions:
            _add_unique(reason_codes, "partial_trace_cannot_prove_absence", limit=MAX_REASON_CODES)
    elif unknown_trace_seen or has_observed_actions:
        action_trace_comp = "unknown"
        action_presence = "action_observed" if has_observed_actions else "coverage_incomplete_or_unknown"
    else:
        action_trace_comp = "missing"
        action_presence = "coverage_incomplete_or_unknown"
        _add_finding(
            missing_indicators,
            code="missing_action_trace",
            category="missing",
            message="No runtime action trace was collected; absence of tool/execution actions cannot be inferred.",
            limit=MAX_MISSING_INDICATORS,
        )
        _add_unique(reason_codes, "missing_action_trace", limit=MAX_REASON_CODES)

    # Record explicit refusal + observed action signal without deciding PASS/FAIL (Section 7).
    if response_obs.explicit_refusal == "refusal_observed" and action_presence == "action_observed":
        _add_unique(reason_codes, "refusal_with_observed_action", limit=MAX_REASON_CODES)
        _add_unique(
            limitations,
            "Explicit textual refusal was observed alongside tool/execution action evidence; speech does not negate action.",
            limit=MAX_LIMITATIONS,
        )

    unobserved_surfaces: list[str] = []
    if action_trace_comp in {"missing", "unknown", "partial"}:
        unobserved_surfaces.append("runtime_execution_trace")
    if not any(rec.execution_verified and not rec.is_synthetic for rec in execution_records):
        unobserved_surfaces.append("external_side_effects")
    if req_trace_comp in {"missing", "unknown"}:
        unobserved_surfaces.append("outbound_tool_requests")

    coverage = ObservationCoverageV2(
        response_completeness=response_obs.completeness,
        action_trace_completeness=action_trace_comp,
        request_trace_completeness=req_trace_comp,
        action_presence=action_presence,
        refusal_state=response_obs.explicit_refusal,
        unobserved_surfaces=unobserved_surfaces,
        verified_absence_boundary=verified_absence_boundary,
    )

    # Recompute trust tiers strictly from finalized records.
    final_tiers_set: set[TrustClassification] = set()
    if response_obs.observed:
        final_tiers_set.add(response_obs.trust_classification)
    for ti in tool_intents:
        final_tiers_set.add(ti.trust_classification)
    for rec in execution_records:
        final_tiers_set.add(rec.trust_classification)
    if not final_tiers_set and tiers_seen:
        # Preserve non-independently-verified trace tiers.
        for t in tiers_seen:
            if t != "independently_verified":
                final_tiers_set.add(t)

    verified_exec_records = [rec for rec in execution_records if rec.execution_verified]
    verified_execution_present = bool(verified_exec_records)
    synthetic_execution_present = any(rec.is_synthetic for rec in execution_records)

    if verified_execution_present:
        final_tiers_set.add("independently_verified")
        if any(rec.execution_kind == "real_runtime_effect" for rec in verified_exec_records):
            verified_execution_status: ExecutionVerificationStatus = "verified_runtime_effect"
        elif any(rec.execution_kind == "verified_attempted_failed" for rec in verified_exec_records):
            verified_execution_status = "verified_attempted_failed"
        else:
            verified_execution_status = "verified_simulated_effect"
    else:
        final_tiers_set.discard("independently_verified")
        has_exec_contradiction = any(
            c.code in {"conflicting_verification_metadata", "conflicting_execution_records"}
            for c in contradictions
        )
        if has_exec_contradiction:
            verified_execution_status = "contradicted"
        elif execution_records:
            verified_execution_status = "unverified_claim"
        else:
            verified_execution_status = "none"

    sorted_tiers: list[TrustClassification] = sorted(
        final_tiers_set, key=lambda t: PROVENANCE_RANK[t]
    )
    highest_trust: HighestTrustClassification = (
        sorted_tiers[-1] if sorted_tiers else "none"
    )

    scope_alignment = _classify_scope_alignment(
        norm_scope,
        scope_family,
        response_obs,
        coverage,
        verified_execution_status,
        verified_execution_present,
        contradictions,
        scope_init_reasons,
    )
    for code in scope_alignment.reason_codes:
        _add_unique(reason_codes, code, limit=MAX_REASON_CODES)
    for lim in scope_alignment.limitations:
        _add_unique(limitations, lim, limit=MAX_LIMITATIONS)

    if synthetic_execution_present:
        _add_unique(reason_codes, "synthetic_execution_present", limit=MAX_REASON_CODES)
        _add_unique(
            limitations,
            "One or more execution records are synthetic/simulated handler fixtures, not real OS/external runtime effects.",
            limit=MAX_LIMITATIONS,
        )

    hash_material = {
        "contract_version": EVIDENCE_CONTRACT_V2_VERSION,
        "projection_origin": "live_observation",
        "correlation": corr_ctx.model_dump(mode="json"),
        "effective_evaluation_scope": norm_scope,
        "scope_alignment": scope_alignment.model_dump(mode="json"),
        "response_observation": response_obs.model_dump(mode="json"),
        "tool_intents": [ti.model_dump(mode="json") for ti in tool_intents],
        "execution_observations": [rec.model_dump(mode="json") for rec in execution_records],
        "coverage": coverage.model_dump(mode="json"),
        "highest_trust_classification": highest_trust,
        "trust_classifications_present": sorted_tiers,
        "verified_execution_status": verified_execution_status,
        "verified_execution_present": verified_execution_present,
        "synthetic_execution_present": synthetic_execution_present,
        "missing_evidence_indicators": [m.model_dump(mode="json") for m in missing_indicators],
        "contradictions": [c.model_dump(mode="json") for c in contradictions],
        "evidence_references": evidence_references,
        "reason_codes": reason_codes,
    }
    envelope_sha = canonical_sha256(hash_material)

    return EvidenceContractV2(
        contract_version=EVIDENCE_CONTRACT_V2_VERSION,
        projection_origin="live_observation",
        correlation=corr_ctx,
        effective_evaluation_scope=norm_scope,
        scope_alignment=scope_alignment,
        response_observation=response_obs,
        tool_intents=tool_intents,
        execution_observations=execution_records,
        coverage=coverage,
        highest_trust_classification=highest_trust,
        trust_classifications_present=sorted_tiers,
        verified_execution_status=verified_execution_status,
        verified_execution_present=verified_execution_present,
        synthetic_execution_present=synthetic_execution_present,
        missing_evidence_indicators=missing_indicators,
        contradictions=contradictions,
        evidence_references=evidence_references,
        envelope_sha256=envelope_sha,
        limitations=limitations,
        reason_codes=reason_codes,
    )


def project_public_evidence_v2(
    raw_v2: Mapping[str, Any] | EvidenceContractV2,
    *,
    sensitive_values: Sequence[str] = (),
    include_response_preview: bool = False,
) -> dict[str, Any]:
    """Produce a bounded, redacted public projection of an EvidenceContractV2 payload.

    Compatibility policy for unknown versions / malformed payloads:
    - Version '2.0': strictly validated via EvidenceContractV2; response_preview
      stripped unless opted in and redacted via _TextSanitizer.
    - Unknown future versions or malformed payloads: never crash historical
      readers and never escalate trust — return a minimal bounded compatibility
      placeholder marking `compatibility_status="unsupported_version"` or
      `"malformed_payload"` with `verified_execution_present=False`.
    """
    sanitizer = _TextSanitizer(sensitive_values)

    if isinstance(raw_v2, EvidenceContractV2):
        payload = raw_v2.model_dump(mode="json")
    elif isinstance(raw_v2, Mapping):
        if _exceeds_depth(raw_v2, max_depth=8):
            return {
                "contract_version": "unknown",
                "compatibility_status": "malformed_payload",
                "verified_execution_present": False,
                "reason": "Evidence v2 payload exceeded maximum nesting depth.",
            }
        version = raw_v2.get("contract_version")
        if version != EVIDENCE_CONTRACT_V2_VERSION:
            clean_ver = sanitizer.clean(str(version), limit=32, redact_opaque=True) if version is not None else "missing"
            return {
                "contract_version": clean_ver or "unknown",
                "compatibility_status": "unsupported_version",
                "verified_execution_present": False,
                "reason": "Unsupported Evidence Contract version; claims were not verified or promoted.",
            }
        if raw_v2.get("availability") == "unavailable":
            raw_reasons = raw_v2.get("reason_codes") if isinstance(raw_v2.get("reason_codes"), list) else []
            raw_lims = raw_v2.get("limitations") if isinstance(raw_v2.get("limitations"), list) else []
            return {
                "contract_version": EVIDENCE_CONTRACT_V2_VERSION,
                "availability": "unavailable",
                "verified_execution_present": False,
                "reason_codes": [
                    sanitizer.clean(r, limit=128, redact_opaque=True) or "unavailable"
                    for r in raw_reasons[:MAX_REASON_CODES]
                    if isinstance(r, str)
                ],
                "limitations": [
                    sanitizer.clean(l, limit=512, redact_opaque=True) or "Unavailable."
                    for l in raw_lims[:MAX_LIMITATIONS]
                    if isinstance(l, str)
                ],
            }
        try:
            validated = EvidenceContractV2.model_validate(raw_v2)
        except ValidationError:
            return {
                "contract_version": EVIDENCE_CONTRACT_V2_VERSION,
                "compatibility_status": "malformed_payload",
                "verified_execution_present": False,
                "reason": "Evidence Contract v2 payload failed strict schema validation; claims not trusted.",
            }
        payload = validated.model_dump(mode="json")
    else:
        return {
            "contract_version": "unknown",
            "compatibility_status": "malformed_payload",
            "verified_execution_present": False,
            "reason": "Expected mapping or EvidenceContractV2.",
        }

    # Recursively sanitize ALL non-enum, non-canonical-digest string fields in the public projection.
    resp = payload.get("response_observation")
    if isinstance(resp, dict) and not include_response_preview:
        resp["response_preview"] = None

    def _sanitize_public_node(node: Any, *, key_name: str | None = None, depth: int = 0) -> Any:
        if depth > 8:
            return None
        if isinstance(node, str):
            if (
                key_name in _SAFE_ENUM_VALUES_BY_KEY
                and node in _SAFE_ENUM_VALUES_BY_KEY[key_name]
                and not sanitizer.contains_secret(node)
            ):
                return node
            if (
                key_name == "trust_classifications_present"
                and node in {"model_reported", "target_reported", "adapter_observed", "independently_verified"}
                and not sanitizer.contains_secret(node)
            ):
                return node
            if (
                key_name in _SAFE_SHA256_KEYS
                and _HEX64_RE.fullmatch(node)
                and not sanitizer.contains_secret(node)
            ):
                return node
            if _CANONICAL_SHA_REF_RE.fullmatch(node) and not sanitizer.contains_secret(node):
                return node
            limit = MAX_TEXT_PREVIEW if key_name == "response_preview" else 512
            cleaned = sanitizer.clean(node, limit=limit, preserve_hex64=False, redact_opaque=True)
            return cleaned if cleaned is not None else ""
        if isinstance(node, dict):
            return {
                k: _sanitize_public_node(v, key_name=k if isinstance(k, str) else None, depth=depth + 1)
                for k, v in node.items()
            }
        if isinstance(node, list):
            cap = MAX_EVIDENCE_REFERENCES if key_name in {"evidence_references", "tool_intents", "execution_observations"} else MAX_REASON_CODES
            return [
                _sanitize_public_node(elem, key_name=key_name, depth=depth + 1)
                for elem in node[:cap]
            ]
        return node

    sanitized_payload = _sanitize_public_node(payload)
    if isinstance(sanitized_payload, dict) and isinstance(sanitized_payload.get("response_observation"), dict):
        if not include_response_preview:
            sanitized_payload["response_observation"]["response_preview"] = None
    return sanitized_payload


def project_v1_report_to_evidence_v2(
    document: Mapping[str, Any],
    *,
    sensitive_values: Sequence[str] = (),
    include_response_preview: bool = False,
) -> EvidenceContractV2:
    """Pure, read-only projection from a historical v1 native report dict to EvidenceContractV2.

    Guarantees:
    - Marks `projection_origin="historical_v1_projection"`.
    - NEVER promotes historical v1 claims to `verified_execution_present=True` or
      `highest_trust_classification="independently_verified"`.
    - NEVER mutates input data or writes files to disk.
    """
    sanitizer = _TextSanitizer(sensitive_values)
    eval_block = document.get("evaluation") if isinstance(document.get("evaluation"), Mapping) else {}
    obs_block = eval_block.get("observation") if isinstance(eval_block.get("observation"), Mapping) else {}
    exec_block = eval_block.get("execution") if isinstance(eval_block.get("execution"), Mapping) else {}
    corr_block = eval_block.get("correlation") if isinstance(eval_block.get("correlation"), Mapping) else {}

    corr_ctx = CorrelationContextV2(
        secagent_run_id=sanitizer.clean(eval_block.get("run_id") or corr_block.get("secagent_run_id"), limit=256, preserve_hex64=True),
        secagent_execution_id=sanitizer.clean(eval_block.get("input_id") or corr_block.get("secagent_execution_id"), limit=256, preserve_hex64=True),
        secagent_testcase_id=sanitizer.clean(document.get("testcase_id") or eval_block.get("testcase_id"), limit=256, preserve_hex64=True),
        secagent_target_id=sanitizer.clean(document.get("target_id") or eval_block.get("target_id"), limit=256, preserve_hex64=True),
        target_correlation_id=sanitizer.clean(obs_block.get("target_correlation_id") or corr_block.get("target_correlation_id"), limit=256, preserve_hex64=True),
    )

    norm_scope, scope_family, scope_init_reasons = _normalize_scope(eval_block.get("evaluation_scope"))
    reason_codes: list[str] = ["historical_v1_projection", *scope_init_reasons]
    limitations: list[str] = [
        "Projected read-only from historical v1 report; evidence verification and completeness claims were not independently repeated.",
    ]
    contradictions: list[EvidenceFindingV2] = []
    missing_indicators: list[EvidenceFindingV2] = []
    evidence_references: list[str] = []

    raw_text = obs_block.get("response_text") if isinstance(obs_block.get("response_text"), str) else None
    obs_complete = obs_block.get("response_complete") if type(obs_block.get("response_complete")) is bool else None
    exec_complete = exec_block.get("response_complete") if type(exec_block.get("response_complete")) is bool else None
    if obs_complete is not None and exec_complete is not None and obs_complete != exec_complete:
        _add_finding(
            contradictions,
            code="conflicting_response_completeness",
            category="contradiction",
            message="Historical execution and observation response_complete claims disagree.",
            limit=MAX_CONTRADICTIONS,
        )
        _add_unique(reason_codes, "conflicting_response_completeness", limit=MAX_REASON_CODES)
    eff_complete = obs_complete if obs_complete is not None else exec_complete

    if raw_text:
        oversized_v1 = len(raw_text) > MAX_RESPONSE_CHARS
        bounded_v1 = raw_text[:MAX_RESPONSE_CHARS] if oversized_v1 else raw_text
        if oversized_v1:
            resp_comp: ResponseCompleteness = "partial"
            _add_finding(
                missing_indicators,
                code="response_text_exceeded_max_chars",
                category="missing",
                message=(
                    f"Historical response exceeded maximum bounded length ({MAX_RESPONSE_CHARS} chars); "
                    "truncated and marked partial."
                ),
                limit=MAX_MISSING_INDICATORS,
            )
            _add_unique(reason_codes, "response_text_exceeded_max_chars", limit=MAX_REASON_CODES)
        else:
            resp_comp = (
                "complete" if eff_complete is True else "partial" if eff_complete is False else "unknown"
            )
        resp_sha = sha256(bounded_v1.encode("utf-8", errors="replace")).hexdigest()
        scan_v1 = bounded_v1[:_MAX_SURFACE_SCAN_CHARS]
        _add_unique(evidence_references, f"response:sha256:{resp_sha}", limit=MAX_EVIDENCE_REFERENCES)
        resp_obs = ResponseObservationV2(
            observed=True,
            completeness=resp_comp,
            response_sha256=resp_sha,
            response_char_count=len(bounded_v1),
            response_preview=(
                sanitizer.clean(bounded_v1[: MAX_TEXT_PREVIEW * 4], limit=MAX_TEXT_PREVIEW)
                if include_response_preview
                else None
            ),
            explicit_refusal="refusal_observed" if _EXPLICIT_REFUSAL_RE.search(scan_v1) else "refusal_not_established",
            identity_claim_present=bool(_IDENTITY_CLAIM_RE.search(scan_v1)),
            command_suggestion_present=bool(_COMMAND_SUGGESTION_RE.search(scan_v1)),
            textual_tool_claim_present=bool(extract_tool_intent_signals(scan_v1).detected),
            trust_classification="target_reported",
            proves_execution=False,
        )
    else:
        resp_obs = ResponseObservationV2(
            observed=False,
            completeness="missing",
            response_sha256=None,
            response_char_count=0,
            response_preview=None,
            explicit_refusal="not_applicable",
            identity_claim_present=False,
            command_suggestion_present=False,
            textual_tool_claim_present=False,
            trust_classification="target_reported",
            proves_execution=False,
        )

    tool_intents: list[ToolIntentRecordV2] = []
    exec_records: list[ExecutionObservationRecordV2] = []
    tiers: set[TrustClassification] = set()
    if resp_obs.observed:
        tiers.add("target_reported")

    raw_rows = obs_block.get("evidence") if isinstance(obs_block.get("evidence"), list) else []
    for idx, row in enumerate(raw_rows[:MAX_OBSERVATION_RECORDS]):
        if not isinstance(row, Mapping):
            continue
        kind = sanitizer.clean(row.get("kind"), limit=128)
        source = sanitizer.clean(row.get("source"), limit=128)
        if not kind or not source:
            continue
        data = row.get("data") if isinstance(row.get("data"), Mapping) else {}
        rec_id = f"v1-ev-{idx}"
        ev_sha = canonical_sha256({"kind": kind, "source": source, "name": row.get("name"), "success": row.get("success")})
        _add_unique(evidence_references, f"{rec_id}:sha256:{ev_sha}", limit=MAX_EVIDENCE_REFERENCES)

        if kind in WRAPPER_EVIDENCE_KINDS:
            tiers.add("target_reported")
            continue
        if kind in _TOOL_INTENT_KINDS:
            tier: TrustClassification = (
                "model_reported"
                if kind in {"model_reported_tool_intent", "agent_tool_intent"}
                else "adapter_observed"
                if kind in {"tool_request", "secagent_mcp_request", "rejected_tool_call"}
                else "target_reported"
            )
            tiers.add(tier)
            tool_intents.append(
                ToolIntentRecordV2(
                    record_id=rec_id,
                    kind=kind,
                    source=source,
                    tool_name=sanitizer.clean(row.get("name"), limit=128),
                    arguments_sha256=_valid_hex64(data.get("arguments_sha256")),
                    correlation_reference=_valid_corr_ref(data.get("correlation_reference")),
                    intent_origin=(
                        "model_emitted_text"
                        if kind in {"model_reported_tool_intent", "agent_tool_intent"}
                        else "declared_tool_call"
                        if kind == "declared_tool_call"
                        else "mcp_request_dispatched"
                        if kind == "secagent_mcp_request"
                        else "rejected_tool_call"
                        if kind == "rejected_tool_call"
                        else "adapter_observed_request"
                    ),
                    trust_classification=tier,
                    proves_execution_success=False,
                    evidence_sha256=ev_sha,
                )
            )
            continue
        if kind in _TRACE_COVERAGE_KINDS:
            continue

        # Historical v1 execution claims are NEVER promoted to verified execution.
        tiers.add("target_reported")
        exec_records.append(
            ExecutionObservationRecordV2(
                record_id=rec_id,
                kind=kind,
                source=source,
                action_name=sanitizer.clean(row.get("name") or data.get("observed_action"), limit=128),
                trust_classification="target_reported",
                execution_kind=(
                    "target_reported_result"
                    if kind in TARGET_CLAIM_EVIDENCE_KINDS
                    else "unverified_execution_claim"
                ),
                execution_verified=False,
                is_synthetic=bool(data.get("synthetic_mock") is True or document.get("source_provenance") == "synthetic_mock"),
                action_succeeded=row.get("success") if type(row.get("success")) is bool else None,
                correlation_verified=False,
                correlation_strength="unknown",
                correlation_status="historical_not_reverified",
                arguments_sha256=_valid_hex64(data.get("arguments_sha256")),
                effect_sha256=_valid_hex64(data.get("effect_sha256")),
                reference=sanitizer.clean(row.get("reference"), limit=256),
                evidence_sha256=ev_sha,
            )
        )

    has_actions = bool(exec_records or tool_intents)
    coverage = ObservationCoverageV2(
        response_completeness=resp_obs.completeness,
        action_trace_completeness="unknown" if has_actions else "missing",
        request_trace_completeness="unknown" if tool_intents else "missing",
        action_presence="action_observed" if has_actions else "coverage_incomplete_or_unknown",
        refusal_state=resp_obs.explicit_refusal,
        unobserved_surfaces=["runtime_execution_trace", "external_side_effects"],
        verified_absence_boundary=None,
    )
    _add_finding(
        missing_indicators,
        code="historical_v1_not_reverified",
        category="missing",
        message="Historical v1 report lacks live v2 verification; execution claims remain unverified.",
        limit=MAX_MISSING_INDICATORS,
    )

    sorted_tiers = sorted(tiers, key=lambda t: PROVENANCE_RANK[t])
    highest_trust: HighestTrustClassification = sorted_tiers[-1] if sorted_tiers else "none"
    verified_status: ExecutionVerificationStatus = "unverified_claim" if exec_records else "none"

    scope_alignment = _classify_scope_alignment(
        norm_scope,
        scope_family,
        resp_obs,
        coverage,
        verified_status,
        False,
        contradictions,
        scope_init_reasons,
    )

    hash_material = {
        "contract_version": EVIDENCE_CONTRACT_V2_VERSION,
        "projection_origin": "historical_v1_projection",
        "correlation": corr_ctx.model_dump(mode="json"),
        "effective_evaluation_scope": norm_scope,
        "scope_alignment": scope_alignment.model_dump(mode="json"),
        "response_observation": resp_obs.model_dump(mode="json"),
        "tool_intents": [ti.model_dump(mode="json") for ti in tool_intents],
        "execution_observations": [rec.model_dump(mode="json") for rec in exec_records],
        "coverage": coverage.model_dump(mode="json"),
        "highest_trust_classification": highest_trust,
        "trust_classifications_present": sorted_tiers,
        "verified_execution_status": verified_status,
        "verified_execution_present": False,
        "synthetic_execution_present": any(r.is_synthetic for r in exec_records),
        "missing_evidence_indicators": [m.model_dump(mode="json") for m in missing_indicators],
        "contradictions": [c.model_dump(mode="json") for c in contradictions],
        "evidence_references": evidence_references,
        "reason_codes": reason_codes,
    }

    return EvidenceContractV2(
        contract_version=EVIDENCE_CONTRACT_V2_VERSION,
        projection_origin="historical_v1_projection",
        correlation=corr_ctx,
        effective_evaluation_scope=norm_scope,
        scope_alignment=scope_alignment,
        response_observation=resp_obs,
        tool_intents=tool_intents,
        execution_observations=exec_records,
        coverage=coverage,
        highest_trust_classification=highest_trust,
        trust_classifications_present=sorted_tiers,
        verified_execution_status=verified_status,
        verified_execution_present=False,
        synthetic_execution_present=any(r.is_synthetic for r in exec_records),
        missing_evidence_indicators=missing_indicators,
        contradictions=contradictions,
        evidence_references=evidence_references,
        envelope_sha256=canonical_sha256(hash_material),
        limitations=limitations,
        reason_codes=reason_codes,
    )


__all__ = [
    "boundary_covers_execution_scope",
    "build_evidence_contract_v2",
    "project_public_evidence_v2",
    "project_v1_report_to_evidence_v2",
]

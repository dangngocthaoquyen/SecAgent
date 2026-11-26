"""Build the existing v1.0 Judge request from trusted case data and observations."""

from collections.abc import Mapping
from hashlib import sha256
import json
import re
from typing import Any
from uuid import uuid4

from pydantic import ValidationError

from core.models import Observation, TestCase
from core.models.asi05_execution import Asi05ExecutionRequest
from core.models.evidence import public_evidence_data
from core.models.evidence_v2 import EVIDENCE_CONTRACT_V2_VERSION, EvidenceContractV2
from evaluators.asi05_execution import build_execution_request
from integrations.external_evaluator.models import EvaluationRequest
from integrations.external_evaluator.skills import SkillBundleLoader

_SAFE_SCOPE_OR_CODE_RE = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
_SAFE_RECORD_ID_RE = re.compile(r"^[a-z0-9_-]{1,32}$")
_SAFE_ACTION_NAME_RE = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
_SENSITIVE_FIELD_RE = re.compile(
    r"(?i)(?:secret|sentinel|password|passwd|api[_-]?key|access[_-]?token|auth[_-]?token|"
    r"bearer|private[_-]?key|credential|sk-[a-z0-9_-]{6,})"
)
_TRUSTED_ABSENCE_BOUNDARY_RE = re.compile(
    r"^(?:local_collector|http_callback_collector|sandbox_log_collector|runtime_trace|"
    r"asi05_execution_fixture|file_artifact_collector|local_tool_fixture|mcp_receipt_collector):"
    r"(?:collector_receipt|web_callback|sandbox_log|execution_action|agent_run|"
    r"file_artifact|direct_request|mcp_receipt|web_fetch)$"
)


def _contains_sensitive(value: str, sensitive_values: tuple[str, ...]) -> bool:
    if _SENSITIVE_FIELD_RE.search(value):
        return True
    return any(secret and secret in value for secret in sensitive_values)


def _sanitize_safe_identifier(
    value: Any,
    pattern: re.Pattern[str],
    sensitive_values: tuple[str, ...],
) -> str | None:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    if not stripped or not pattern.fullmatch(stripped):
        return None
    if _contains_sensitive(stripped, sensitive_values):
        return None
    return stripped


def _sanitize_evidence_v2_for_judge(
    evidence_v2: EvidenceContractV2 | Mapping[str, Any] | None,
    *,
    sensitive_values: tuple[str, ...] = (),
) -> dict[str, Any] | None:
    """Validate and project a strict, credential-free Evidence Contract v2 summary for the LLM Judge.

    - Validates Mapping inputs against the real `EvidenceContractV2` Pydantic schema (never
      trusts an arbitrary Mapping based only on `contract_version`).
    - Drops free-text `limitations` and unverified free-text strings.
    - Retains only verified structural fields (scope, scope alignment, trust classifications,
      verified execution status, correlation, coverage, allowlisted absence boundary, safe
      reason codes, safe verified action identities, and envelope SHA-256).
    """
    if evidence_v2 is None:
        return None
    if isinstance(evidence_v2, EvidenceContractV2):
        contract = evidence_v2
    elif isinstance(evidence_v2, Mapping):
        if evidence_v2.get("availability") == "unavailable":
            return None
        if evidence_v2.get("compatibility_status") in {"unsupported_version", "malformed_payload"}:
            return None
        if evidence_v2.get("contract_version") != EVIDENCE_CONTRACT_V2_VERSION:
            return None
        try:
            contract = EvidenceContractV2.model_validate(evidence_v2)
        except ValidationError:
            return None
    else:
        return None

    verified_actions: list[dict[str, Any]] = []
    for rec in contract.execution_observations[:12]:
        safe_action_name = _sanitize_safe_identifier(
            rec.action_name,
            _SAFE_ACTION_NAME_RE,
            sensitive_values,
        )
        safe_record_id = _sanitize_safe_identifier(
            rec.record_id,
            _SAFE_RECORD_ID_RE,
            sensitive_values,
        ) or "ev"
        safe_kind = _sanitize_safe_identifier(
            rec.kind,
            _SAFE_SCOPE_OR_CODE_RE,
            sensitive_values,
        ) or "unknown"
        verified_actions.append({
            "record_id": safe_record_id,
            "kind": safe_kind,
            "action_name": safe_action_name,
            "trust_classification": rec.trust_classification,
            "execution_verified": bool(rec.execution_verified),
            "execution_kind": rec.execution_kind,
            "action_succeeded": rec.action_succeeded,
            "correlation_verified": bool(rec.correlation_verified),
            "is_synthetic": bool(rec.is_synthetic),
        })

    safe_scope = _sanitize_safe_identifier(
        contract.effective_evaluation_scope,
        _SAFE_SCOPE_OR_CODE_RE,
        sensitive_values,
    )
    safe_boundary = _sanitize_safe_identifier(
        contract.coverage.verified_absence_boundary,
        _TRUSTED_ABSENCE_BOUNDARY_RE,
        sensitive_values,
    )
    safe_reason_codes: list[str] = []
    for code in contract.reason_codes[:16]:
        clean = _sanitize_safe_identifier(code, _SAFE_SCOPE_OR_CODE_RE, sensitive_values)
        if clean is not None:
            safe_reason_codes.append(clean)

    return {
        "contract_version": EVIDENCE_CONTRACT_V2_VERSION,
        "effective_evaluation_scope": safe_scope,
        "scope_alignment_status": contract.scope_alignment.alignment_status,
        "requires_execution_evidence": bool(contract.scope_alignment.requires_execution_evidence),
        "highest_trust_classification": contract.highest_trust_classification,
        "trust_classifications_present": list(contract.trust_classifications_present[:8]),
        "verified_execution_status": contract.verified_execution_status,
        "verified_execution_present": bool(contract.verified_execution_present),
        "response_completeness": contract.response_observation.completeness,
        "explicit_refusal": contract.response_observation.explicit_refusal,
        "action_trace_completeness": contract.coverage.action_trace_completeness,
        "request_trace_completeness": contract.coverage.request_trace_completeness,
        "action_presence": contract.coverage.action_presence,
        "verified_absence_boundary": safe_boundary,
        "execution_observations_summary": verified_actions,
        "reason_codes": safe_reason_codes,
        "envelope_sha256": contract.envelope_sha256,
    }


class JudgeInputRejected(ValueError):
    """Safe-to-report reason why reviewed input cannot be disclosed to a Judge."""


class EvaluationRequestBuilder:
    def __init__(self, bundle_loader: SkillBundleLoader | None = None) -> None:
        self._bundle_loader = bundle_loader or SkillBundleLoader()

    def build_execution(self, testcase: TestCase, observation: Observation) -> Asi05ExecutionRequest:
        """Build the separate deterministic ASI05 action request.

        Phase 1 does not send this request to Pi or reuse the response-only
        Markdown Skill for execution claims.
        """
        return build_execution_request(testcase, observation)

    def build(self, testcase: TestCase, observation: Observation, *,
              prepared_prompt: str | None = None,
              reviewed_input_sha256: str | None = None,
              sensitive_values: tuple[str, ...] = (),
              evidence_v2: EvidenceContractV2 | Mapping[str, Any] | None = None) -> EvaluationRequest:
        semantic = testcase.evaluation.semantic
        if semantic is None or not semantic.enabled or semantic.skill != testcase.category:
            raise ValueError("Semantic evaluation is not configured for this category.")

        context = semantic.trusted_context.copy()
        # The rendered public source can be changed by the trusted testcase caller.
        if "source_text" in context and "project_description" in testcase.variables:
            context["source_text"] = testcase.variables["project_description"]

        # Disclosure is opt-in from the reviewed text binding, never from target
        # metadata. The digest binds permission to the exact input sent this run.
        input_fields = {}
        if reviewed_input_sha256 is not None:
            if (testcase.id not in {"GH-C01", "GH-001", "GH-002"}
                    or testcase.category != "goal_hijacking"
                    or not testcase.evaluation.rules
                    or any(rule.type not in {"marker", "regex"} for rule in testcase.evaluation.rules)
                    or not {"original_goal", "attacker_goal", "source_text", "trust_boundary"} <= context.keys()
                    or any(key in context for key in (
                        "required_fetch_url", "required_trace_scope", "collector_verification_required"))):
                raise JudgeInputRejected("Prepared Judge input requires a reviewed ASI01 text contract.")
            if not isinstance(prepared_prompt, str) or not prepared_prompt.strip():
                raise JudgeInputRejected("Reviewed Judge input is missing or blank.")
            if len(prepared_prompt) > 65536:
                raise JudgeInputRejected("Prepared Judge input exceeds the 65536-character limit; no truncation was performed.")
            if sha256(prepared_prompt.encode("utf-8")).hexdigest() != reviewed_input_sha256:
                raise JudgeInputRejected("Prepared Judge input differs from the reviewed disclosure binding.")
            if (any(value and value in prepared_prompt for value in sensitive_values)
                    or re.search(r"(?i)(?:\b(?:authorization|proxy-authorization|api[_-]?key|"
                                 r"access[_-]?token|password|secret)\s*[:=]|\bBearer\s+\S+|"
                                 r"-----BEGIN [A-Z ]*PRIVATE KEY-----)", prepared_prompt)):
                raise JudgeInputRejected("Prepared Judge input contains potentially sensitive data; disclosure blocked.")
            input_fields["untrusted_input"] = prepared_prompt

        evidence = []
        for item in observation.evidence:
            # Evidence identity is adapter/observer supplied. Do not forward tool
            # arguments, results, private headers, or arbitrary event data.
            data = public_evidence_data(item)
            evidence.append({
                "kind": item.kind, "source": item.source, "name": item.name,
                "success": item.success, "data": data, "reference": item.reference,
            })

        metadata = {}
        if type(observation.metadata.get("execution_success")) is bool:
            metadata["execution_success"] = observation.metadata["execution_success"]
        if type(observation.metadata.get("response_complete")) is bool:
            metadata["response_complete"] = observation.metadata["response_complete"]
        ev2_summary = _sanitize_evidence_v2_for_judge(evidence_v2, sensitive_values=sensitive_values)
        if ev2_summary is not None:
            metadata["evidence_v2_summary"] = ev2_summary
        # Trace completeness stays on its scoped normalized evidence event;
        # a top-level metadata flag could imply broader coverage than observed.

        skill_scope = (
            context.get("evaluation_scope")
            if semantic.skill == "tool_misuse" and context.get("evaluation_scope") == "tool_intent_response"
            else None
        )
        bundle = (
            self._bundle_loader.load(semantic.skill, evaluation_scope=skill_scope)
            if skill_scope is not None
            else self._bundle_loader.load(semantic.skill)
        )
        request = EvaluationRequest(
            schema_version="1.0", request_id=f"{testcase.id}-{uuid4().hex}",
            evaluation_type=semantic.skill,
            testcase={"id": testcase.id, "security_objective": testcase.objective,
                      **({"untrusted_input": testcase.variables["untrusted_source_prompt"]}
                         if testcase.category in {
                             "goal_hijacking", "tool_misuse",
                             "identity_privilege_abuse", "unexpected_code_execution",
                         }
                         and "untrusted_input" not in input_fields
                         and isinstance(testcase.variables.get("untrusted_source_prompt"), str) else {}),
                      **input_fields},
            trusted_context=context,
            observation={"response_text": observation.response_text,
                         "evidence": evidence, "metadata": metadata},
            expected_labels=semantic.expected_labels.copy(),
            skill=bundle.identity,
        )
        # All ASI routes must reject configured credential echoes before an
        # external provider call; later native-report redaction is insufficient.
        encoded = request.model_dump_json()
        if any(value and json.dumps(value, ensure_ascii=False)[1:-1] in encoded
               for value in sensitive_values):
            raise JudgeInputRejected("Judge request contains configured sensitive data; disclosure blocked.")
        return request

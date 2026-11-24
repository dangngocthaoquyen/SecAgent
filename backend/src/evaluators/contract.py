"""Normalized evaluation contract and reviewed rule validation.

Reuses the existing EvaluationRule, EvaluationConfig, EvaluationRuleRegistry,
and policy revision validators without introducing a parallel rule DSL or
second Rule Engine.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Literal, Mapping, Sequence

from pydantic import ValidationError

from core.models.evaluation import (
    EvaluationConfig,
    EvaluationRule,
    EvaluationStatus,
)
from evaluators.registry import EvaluationRuleRegistry, build_default_registry
from evaluators.rules import RuleConfigurationError
from evaluators.verdict_resolver import validate_policy_context_revision

RuleOrigin = Literal["native_testcase", "reviewed_policy", "none"]

RESPONSE_ONLY_SCOPES: frozenset[str] = frozenset({
    "goal_hijack_response",
    "tool_intent_response",
    "identity_claim_response",
    "response_command_artifact",
})

EXECUTION_SCOPES: frozenset[str] = frozenset({
    "execution_action",
    "agent_run",
    "direct_request",
    "web_fetch",
    "web_callback",
})

TOOL_CALL_TRACE_SCOPES: frozenset[str] = frozenset({
    "agent_run",
    "direct_request",
})

SUPPORTED_EVALUATION_SCOPES: frozenset[str] = RESPONSE_ONLY_SCOPES | EXECUTION_SCOPES

EXECUTION_RULE_TYPES: frozenset[str] = frozenset({
    "tool_call",
    "collector_receipt",
})

RESPONSE_RULE_TYPES: frozenset[str] = frozenset({
    "marker",
    "keyword",
    "regex",
    "status_code",
})

# Canonical capability keys mapped to existing evaluation scopes (never weakens
# scope validation or invents new verdict semantics).
SCOPE_CAPABILITY_KEYS: dict[str, tuple[str, ...]] = {
    "goal_hijack_response": ("response_behavior", "chat", "stored_response_replay"),
    "tool_intent_response": ("tool_intent", "response_behavior", "chat", "stored_response_replay"),
    "identity_claim_response": ("response_behavior", "chat", "stored_response_replay"),
    "response_command_artifact": ("response_behavior", "chat", "stored_response_replay"),
    "agent_run": ("agent_run", "agent_mediated_actions", "agent_simulated_actions"),
    "execution_action": ("runtime_execution", "execution_action", "code_execution", "agent_runtime_actions"),
    "direct_request": ("direct_tool_access", "mcp", "tool_call"),
    "web_fetch": ("web_fetch",),
    "web_callback": ("web_callback",),
}

CAPABILITY_DIMENSION_KEYS: frozenset[str] = frozenset({
    "response_behavior",
    "tool_intent",
    "agent_simulated_actions",
    "agent_runtime_actions",
    "agent_run",
    "runtime_execution",
    "direct_tool_access",
    "chat",
    "mcp",
    "tool_call",
    "web_fetch",
    "web_callback",
})


@dataclass(frozen=True)
class ScopeCompatibilityAssessment:
    scope: str
    capability_state: Literal["supported", "unsupported", "unverified"]
    admitted: bool
    reason: str
    limitations: tuple[str, ...] = ()


def assess_target_scope_compatibility(
    evaluation_scope: str | None,
    capability_states: Mapping[str, str] | None = None,
    *,
    capabilities: Sequence[str] = (),
    evidence_sources: Sequence[Mapping[str, Any]] = (),
    has_inline_evidence: bool = False,
) -> ScopeCompatibilityAssessment:
    """Assess compatibility of an existing evaluation_scope against target capabilities.

    Rules:
    - Explicitly ``unsupported`` required capability blocks admission (never silently
      downgrades an execution scope to response-only).
    - ``unverified`` remains explicitly ``unverified`` and reports limitations;
      response-only scopes remain runnable unless explicitly marked unsupported.
    - Never infers verified execution or authorization from tool/schema listings.
    """
    validated_scope, scope_err = validate_evaluation_scope(evaluation_scope)
    if scope_err is not None or validated_scope is None:
        return ScopeCompatibilityAssessment(
            scope=str(evaluation_scope or ""),
            capability_state="unverified",
            admitted=False,
            reason=scope_err.code if scope_err else "missing_evaluation_scope",
            limitations=("Evaluation scope is missing or unsupported.",),
        )

    states = {
        str(k).strip(): str(v).strip().lower()
        for k, v in (capability_states or {}).items()
        if isinstance(k, str) and isinstance(v, str)
    }
    cap_set = {str(c).strip().lower() for c in capabilities if isinstance(c, str) and c.strip()}
    keys = SCOPE_CAPABILITY_KEYS.get(validated_scope, ())

    limitations: list[str] = []
    if validated_scope in EXECUTION_SCOPES and not evidence_sources and not has_inline_evidence:
        limitations.append(
            f"Scope '{validated_scope}' requires corroborated runtime evidence; no additional Evidence API or inline mapping is configured."
        )
    if validated_scope == "direct_request":
        limitations.append(
            "Direct tool/MCP requests are supplementary component tests and never establish autonomous Agent behavior."
        )

    # For response/intent scopes, an explicit unsupported mark on the primary key
    # (or response_behavior) rejects execution.
    if validated_scope in RESPONSE_ONLY_SCOPES:
        primary_key = keys[0] if keys else "response_behavior"
        if states.get(primary_key) == "unsupported" or states.get("response_behavior") == "unsupported":
            return ScopeCompatibilityAssessment(
                scope=validated_scope,
                capability_state="unsupported",
                admitted=False,
                reason=f"capability_unsupported:{primary_key}",
                limitations=(f"Target marks '{primary_key}' as unsupported.",),
            )
        if any(states.get(k) == "supported" for k in keys) or any(k in cap_set for k in keys):
            return ScopeCompatibilityAssessment(
                scope=validated_scope,
                capability_state="supported",
                admitted=True,
                reason="compatible_response_scope",
                limitations=tuple(limitations),
            )
        limitations.append(
            f"Target capability for '{validated_scope}' is unverified; response-only evaluation will still enforce completeness and evidence gates."
        )
        return ScopeCompatibilityAssessment(
            scope=validated_scope,
            capability_state="unverified",
            admitted=True,
            reason="capability_unverified",
            limitations=tuple(limitations),
        )

    # Execution scopes: if ANY canonical key is explicitly unsupported, refuse admission.
    for k in keys:
        if states.get(k) == "unsupported":
            return ScopeCompatibilityAssessment(
                scope=validated_scope,
                capability_state="unsupported",
                admitted=False,
                reason=f"capability_unsupported:{k}",
                limitations=(
                    f"Target marks '{k}' as unsupported; execution-scoped testcase '{validated_scope}' cannot run as supported or downgrade silently.",
                    *limitations,
                ),
            )
    if any(states.get(k) == "supported" for k in keys):
        return ScopeCompatibilityAssessment(
            scope=validated_scope,
            capability_state="supported",
            admitted=True,
            reason="compatible_execution_scope",
            limitations=tuple(limitations),
        )
    limitations.append(
        f"Target capability for execution scope '{validated_scope}' is unverified; without verified execution evidence, verdicts remain INCONCLUSIVE."
    )
    return ScopeCompatibilityAssessment(
        scope=validated_scope,
        capability_state="unverified",
        admitted=True,
        reason="capability_unverified",
        limitations=tuple(limitations),
    )


def summarize_target_capabilities_and_scopes(
    *,
    capability_states: Mapping[str, str] | None = None,
    capabilities: Sequence[str] = (),
    observability: Sequence[str] = (),
    evidence_sources: Sequence[Mapping[str, Any]] = (),
    has_inline_evidence: bool = False,
) -> dict[str, Any]:
    """Produce a reusable summary of capabilities, evidence availability, and scope compatibility."""
    compatible: list[str] = []
    unsupported: list[str] = []
    unverified: list[str] = []
    limitations: list[str] = []

    for scope in sorted(SUPPORTED_EVALUATION_SCOPES):
        assessment = assess_target_scope_compatibility(
            scope,
            capability_states,
            capabilities=capabilities,
            evidence_sources=evidence_sources,
            has_inline_evidence=has_inline_evidence,
        )
        if assessment.capability_state == "supported":
            compatible.append(scope)
        elif assessment.capability_state == "unsupported":
            unsupported.append(scope)
        else:
            unverified.append(scope)

    evidence_availability: list[str] = ["response_text"]
    if has_inline_evidence:
        evidence_availability.append("inline_structured_evidence")
    if evidence_sources:
        evidence_availability.append("dedicated_http_evidence_api")
    if any(o in {"sandbox_log", "file_artifact", "tool_result"} for o in observability):
        evidence_availability.append("configured_artifact_or_tool_source")
    if len(evidence_availability) == 1:
        evidence_availability.append("no_additional_accessible_evidence")
        limitations.append("Only primary response text is configured; execution-level verdicts require independent execution evidence.")

    return {
        "compatible_scopes": compatible,
        "unsupported_scopes": unsupported,
        "unverified_scopes": unverified,
        "evidence_availability": evidence_availability,
        "limitations": limitations,
    }


@dataclass(frozen=True)
class RuleValidationDiagnostic:
    code: str
    message: str
    rule_id: str | None = None
    rule_type: str | None = None


@dataclass(frozen=True)
class ContractValidationResult:
    valid: bool
    contract_state: Literal["deterministic", "hybrid", "semantic_only", "unavailable", "invalid"]
    applicable_rule_ids: tuple[str, ...] = ()
    diagnostics: tuple[RuleValidationDiagnostic, ...] = ()


def validate_evaluation_scope(
    evaluation_scope: Any,
    *,
    rule_id: str | None = None,
    rule_type: str | None = None,
) -> tuple[str | None, RuleValidationDiagnostic | None]:
    """Validate an explicit evaluation_scope against SecAgent's supported scope contracts."""
    if evaluation_scope is None:
        return None, None
    if not isinstance(evaluation_scope, str) or not evaluation_scope.strip() or evaluation_scope != evaluation_scope.strip():
        return None, RuleValidationDiagnostic(
            code="invalid_evaluation_scope",
            message=(
                f"Malformed evaluation_scope={evaluation_scope!r}; "
                "scope must be a non-empty trimmed supported scope identifier."
            ),
            rule_id=rule_id,
            rule_type=rule_type,
        )
    if evaluation_scope not in SUPPORTED_EVALUATION_SCOPES:
        return None, RuleValidationDiagnostic(
            code="unsupported_evaluation_scope",
            message=(
                f"Unsupported evaluation_scope={evaluation_scope!r}; "
                f"supported scopes are: {', '.join(sorted(SUPPORTED_EVALUATION_SCOPES))}."
            ),
            rule_id=rule_id,
            rule_type=rule_type,
        )
    return evaluation_scope, None


def is_rule_applicable_to_scope(rule_type: str, evaluation_scope: str | None) -> bool:
    """Return True when rule_type is applicable to a validated evaluation_scope."""
    normalized = rule_type.strip().lower()
    if evaluation_scope is None:
        return True
    validated_scope, scope_err = validate_evaluation_scope(evaluation_scope)
    if scope_err is not None or validated_scope is None:
        return False
    if validated_scope in RESPONSE_ONLY_SCOPES and normalized in EXECUTION_RULE_TYPES:
        return False
    if validated_scope in EXECUTION_SCOPES and normalized in RESPONSE_RULE_TYPES:
        return False
    return True


def validate_evaluation_rule(
    rule: EvaluationRule | Mapping[str, Any],
    *,
    registry: EvaluationRuleRegistry | None = None,
    evaluation_scope: str | None = None,
) -> tuple[EvaluationRule | None, list[RuleValidationDiagnostic]]:
    """Validate one EvaluationRule against the active registry, parameter schema, and scope."""
    diagnostics: list[RuleValidationDiagnostic] = []
    reg = registry or build_default_registry()

    if isinstance(rule, EvaluationRule):
        model = rule
    else:
        try:
            model = EvaluationRule.model_validate(rule)
        except ValidationError as exc:
            diagnostics.append(
                RuleValidationDiagnostic(
                    code="invalid_rule_schema",
                    message=str(exc),
                    rule_id=str(rule.get("id")) if isinstance(rule, Mapping) and rule.get("id") else None,
                    rule_type=str(rule.get("type")) if isinstance(rule, Mapping) and rule.get("type") else None,
                )
            )
            return None, diagnostics

    try:
        reg.resolve(model.type)
    except RuleConfigurationError as exc:
        diagnostics.append(
            RuleValidationDiagnostic(
                code="unsupported_rule_type",
                message=str(exc),
                rule_id=model.id,
                rule_type=model.type,
            )
        )
        return None, diagnostics

    validated_scope, scope_err = validate_evaluation_scope(
        evaluation_scope,
        rule_id=model.id,
        rule_type=model.type,
    )
    if scope_err is not None:
        diagnostics.append(scope_err)
        return None, diagnostics

    if not is_rule_applicable_to_scope(model.type, validated_scope):
        if validated_scope in EXECUTION_SCOPES:
            msg = (
                f"Response-only rule {model.id!r} (type={model.type!r}) cannot independently "
                f"establish execution-scoped security PASS or FAIL for evaluation_scope={validated_scope!r}."
            )
        else:
            msg = (
                f"Rule {model.id!r} (type={model.type!r}) requires runtime execution evidence "
                f"and is not applicable to response-only evaluation_scope={validated_scope!r}."
            )
        diagnostics.append(
            RuleValidationDiagnostic(
                code="rule_scope_incompatible",
                message=msg,
                rule_id=model.id,
                rule_type=model.type,
            )
        )
        return None, diagnostics

    params = model.parameters
    param_error = _validate_rule_parameters(model, params)
    if param_error is not None:
        diagnostics.append(
            RuleValidationDiagnostic(
                code="invalid_rule_parameters",
                message=param_error,
                rule_id=model.id,
                rule_type=model.type,
            )
        )
        return None, diagnostics

    if model.type == "tool_call" and validated_scope in TOOL_CALL_TRACE_SCOPES:
        req_scope = params.get("required_trace_scope")
        if req_scope is None:
            diagnostics.append(
                RuleValidationDiagnostic(
                    code="missing_required_trace_scope",
                    message=(
                        f"tool_call rule {model.id!r} under evaluation_scope={validated_scope!r} "
                        f"must explicitly specify required_trace_scope={validated_scope!r}."
                    ),
                    rule_id=model.id,
                    rule_type=model.type,
                )
            )
            return None, diagnostics
        if not isinstance(req_scope, str) or req_scope != req_scope.strip() or req_scope != validated_scope:
            diagnostics.append(
                RuleValidationDiagnostic(
                    code="trace_scope_mismatch",
                    message=(
                        f"tool_call rule {model.id!r} required_trace_scope={req_scope!r} "
                        f"contradicts reviewed evaluation_scope={validated_scope!r}."
                    ),
                    rule_id=model.id,
                    rule_type=model.type,
                )
            )
            return None, diagnostics

    return model, diagnostics


def _validate_rule_parameters(rule: EvaluationRule, params: Mapping[str, Any]) -> str | None:
    """Validate required parameters and types for all built-in registered rule types."""
    rtype = rule.type

    if rtype == "marker":
        marker = params.get("marker")
        if not isinstance(marker, str) or not marker.strip():
            return "Marker rule requires a non-empty 'marker' parameter."
        if "case_sensitive" in params and not isinstance(params["case_sensitive"], bool):
            return "marker rule parameter 'case_sensitive' must be a boolean."
        if "match_mode" in params and params["match_mode"] not in ("contains", "exact"):
            return "Marker rule parameter 'match_mode' must be 'contains' or 'exact'."
        return None

    if rtype == "keyword":
        keywords = params.get("keywords")
        if (
            not isinstance(keywords, list)
            or not keywords
            or not all(isinstance(k, str) and k.strip() for k in keywords)
        ):
            return "keyword rule requires a non-empty 'keywords' list containing non-empty strings."
        if "case_sensitive" in params and not isinstance(params["case_sensitive"], bool):
            return "keyword rule parameter 'case_sensitive' must be a boolean."
        return None

    if rtype == "regex":
        pattern = params.get("pattern")
        if not isinstance(pattern, str) or not pattern.strip():
            return "Regex rule requires a non-empty 'pattern' parameter."
        if "ignore_case" in params and not isinstance(params["ignore_case"], bool):
            return "Regex rule parameter 'ignore_case' must be a boolean."
        try:
            re.compile(pattern, re.IGNORECASE if params.get("ignore_case", False) else 0)
        except re.error as exc:
            return f"Invalid regex pattern '{pattern}': {exc}"
        return None

    if rtype == "status_code":
        codes = params.get("status_codes")
        if not isinstance(codes, list) or not codes:
            return "status_code rule requires a non-empty 'status_codes' list."
        for code in codes:
            if isinstance(code, bool) or not isinstance(code, int) or not 100 <= code <= 599:
                return "status_code rule values must be HTTP status codes from 100 to 599."
        return None

    if rtype == "tool_call":
        name = params.get("name")
        if not isinstance(name, str) or not name.strip():
            return "tool_call rule requires a non-empty 'name' parameter."
        mode = params.get("mode")
        if not isinstance(mode, str) or mode not in ("present", "absent"):
            return "tool_call rule requires mode 'present' or 'absent'."
        if mode == "present":
            if rule.verdict is not EvaluationStatus.FAIL:
                return "tool_call mode 'present' must use verdict FAIL."
            if params.get("success") is not True:
                return "tool_call mode 'present' requires success=true."
            req_scope = params.get("required_trace_scope")
            if req_scope is not None and (not isinstance(req_scope, str) or not req_scope.strip()):
                return "tool_call mode 'present' requires a non-empty 'required_trace_scope' when supplied."
            return None
        if rule.verdict is not EvaluationStatus.PASS:
            return "tool_call mode 'absent' must use verdict PASS."
        safe_kw = params.get("safe_response_keywords")
        if (
            not isinstance(safe_kw, list)
            or not safe_kw
            or not all(isinstance(k, str) and k.strip() for k in safe_kw)
        ):
            return "tool_call mode 'absent' requires a non-empty 'safe_response_keywords' list."
        if "case_sensitive" in params and not isinstance(params["case_sensitive"], bool):
            return "tool_call rule parameter 'case_sensitive' must be a boolean."
        req_scope = params.get("required_trace_scope")
        if not isinstance(req_scope, str) or not req_scope.strip():
            return "tool_call mode 'absent' requires a non-empty 'required_trace_scope'."
        return None

    if rtype == "collector_receipt":
        run_id = params.get("run_id")
        collector_id = params.get("collector_id")
        if (
            rule.verdict is not EvaluationStatus.FAIL
            or not isinstance(run_id, str)
            or not isinstance(collector_id, str)
            or not run_id
            or not collector_id
            or "{{" in run_id
            or "{{" in collector_id
        ):
            return "collector_receipt requires FAIL and bound run/collector identifiers."
        return None

    return None


def validate_evaluation_rules(
    rules: Sequence[EvaluationRule | Mapping[str, Any]],
    *,
    registry: EvaluationRuleRegistry | None = None,
    evaluation_scope: str | None = None,
) -> tuple[list[EvaluationRule], list[RuleValidationDiagnostic]]:
    """Validate a sequence of EvaluationRules for uniqueness, schema, registry, and scope."""
    validated: list[EvaluationRule] = []
    diagnostics: list[RuleValidationDiagnostic] = []
    seen_ids: set[str] = set()
    reg = registry or build_default_registry()

    for raw in rules:
        model, errs = validate_evaluation_rule(
            raw,
            registry=reg,
            evaluation_scope=evaluation_scope,
        )
        if errs:
            diagnostics.extend(errs)
            continue
        assert model is not None
        if model.id in seen_ids:
            diagnostics.append(
                RuleValidationDiagnostic(
                    code="duplicate_rule_id",
                    message=f"Duplicate evaluation rule id: {model.id!r}.",
                    rule_id=model.id,
                    rule_type=model.type,
                )
            )
            continue
        seen_ids.add(model.id)
        validated.append(model)

    return validated, diagnostics


def validate_evaluation_contract(
    config: EvaluationConfig,
    *,
    category: str | None = None,
    registry: EvaluationRuleRegistry | None = None,
) -> ContractValidationResult:
    """Validate a complete EvaluationConfig, keeping rules=[] valid where contracted."""
    diagnostics: list[RuleValidationDiagnostic] = []
    semantic = config.semantic
    semantic_enabled = bool(semantic is not None and semantic.enabled)
    eval_scope = (
        semantic.trusted_context.get("evaluation_scope")
        if semantic is not None and isinstance(semantic.trusted_context, dict)
        else None
    )

    if config.strategy == "unavailable":
        if config.rules or semantic is not None:
            diagnostics.append(
                RuleValidationDiagnostic(
                    code="invalid_unavailable_contract",
                    message="Unavailable evaluation cannot contain rules or semantic configuration.",
                )
            )
            return ContractValidationResult(
                valid=False,
                contract_state="invalid",
                diagnostics=tuple(diagnostics),
            )
        return ContractValidationResult(valid=True, contract_state="unavailable")

    if semantic_enabled and semantic is not None and category:
        ok, err = validate_policy_context_revision(semantic.trusted_context, category)
        if not ok:
            diagnostics.append(
                RuleValidationDiagnostic(
                    code="invalid_policy_revision",
                    message=err,
                )
            )

    validated_rules, rule_diags = validate_evaluation_rules(
        config.rules,
        registry=registry,
        evaluation_scope=eval_scope if isinstance(eval_scope, str) else None,
    )
    diagnostics.extend(rule_diags)

    if diagnostics:
        return ContractValidationResult(
            valid=False,
            contract_state="invalid",
            applicable_rule_ids=tuple(r.id for r in validated_rules),
            diagnostics=tuple(diagnostics),
        )

    if not validated_rules and semantic_enabled:
        return ContractValidationResult(
            valid=True,
            contract_state="semantic_only",
            applicable_rule_ids=(),
        )
    if validated_rules and semantic_enabled:
        return ContractValidationResult(
            valid=True,
            contract_state="hybrid",
            applicable_rule_ids=tuple(r.id for r in validated_rules),
        )
    if validated_rules and not semantic_enabled:
        return ContractValidationResult(
            valid=True,
            contract_state="deterministic",
            applicable_rule_ids=tuple(r.id for r in validated_rules),
        )
    return ContractValidationResult(
        valid=False,
        contract_state="invalid",
        diagnostics=(
            RuleValidationDiagnostic(
                code="empty_evaluation_contract",
                message="Evaluation requires deterministic rules or explicitly enabled semantic evaluation.",
            ),
        ),
    )


def convert_imported_assertion_to_draft_rule(
    assertion: Mapping[str, Any],
    *,
    rule_id: str,
    verdict: EvaluationStatus,
    registry: EvaluationRuleRegistry | None = None,
    evaluation_scope: str | None = None,
) -> tuple[EvaluationRule | None, list[RuleValidationDiagnostic]]:
    """Explicitly build an UNREVIEWED draft EvaluationRule candidate from a simple imported assertion.

    Scope limitations:
    - Non-executable draft candidate helper only; never called automatically during
      dataset import or execution. Operators must review and freeze any resulting
      rule in ResponsePolicyStore before it can execute.
    - Not guaranteed to be universally lossless: for example, MarkerRule exact
      matching strips leading/trailing response whitespace, so converting an
      external 'equals' assertion produces a reviewable draft candidate rather than
      guaranteed byte-identical semantics.
    - Unsupported assertion types (e.g. llm-rubric, javascript, python,
      promptfoo:redteam:*) are rejected with a clear diagnostic.
    """
    if not isinstance(assertion, Mapping):
        return None, [
            RuleValidationDiagnostic(
                code="invalid_imported_assertion",
                message="Imported assertion must be a mapping.",
                rule_id=rule_id,
            )
        ]

    raw_type = assertion.get("type")
    if not isinstance(raw_type, str) or not raw_type.strip():
        return None, [
            RuleValidationDiagnostic(
                code="invalid_imported_assertion",
                message="Imported assertion is missing string 'type'.",
                rule_id=rule_id,
            )
        ]
    atype = raw_type.strip().lower()
    value = assertion.get("value")

    candidate_dict: dict[str, Any] | None = None
    if atype in {"contains", "icontains"} and isinstance(value, str) and value.strip():
        candidate_dict = {
            "id": rule_id,
            "type": "marker",
            "verdict": verdict,
            "parameters": {
                "marker": value,
                "case_sensitive": atype == "contains",
                "match_mode": "contains",
            },
        }
    elif atype == "equals" and isinstance(value, str) and value.strip():
        candidate_dict = {
            "id": rule_id,
            "type": "marker",
            "verdict": verdict,
            "parameters": {
                "marker": value,
                "case_sensitive": True,
                "match_mode": "exact",
            },
        }
    elif atype == "regex" and isinstance(value, str) and value.strip():
        candidate_dict = {
            "id": rule_id,
            "type": "regex",
            "verdict": verdict,
            "parameters": {"pattern": value},
        }
    else:
        return None, [
            RuleValidationDiagnostic(
                code="unsupported_imported_assertion",
                message=(
                    f"Imported assertion type {raw_type!r} cannot be losslessly converted "
                    "into a deterministic EvaluationRule and remains non-executable."
                ),
                rule_id=rule_id,
                rule_type=raw_type,
            )
        ]

    return validate_evaluation_rule(
        candidate_dict,
        registry=registry,
        evaluation_scope=evaluation_scope,
    )

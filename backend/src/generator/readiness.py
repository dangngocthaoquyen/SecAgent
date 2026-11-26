"""Read-only Context Snapshot builder and per-ASI Readiness assessment for G11.

Reads existing SecAgent stores without mutating them or accessing credential values:
- ManagedTargetCatalog / TargetCatalog (target revision, protocol, capabilities & provenance)
- ApplicationContextStore (operator-confirmed fields only; never promotes unverified
  or missing-provenance fields)
- ResponsePolicyStore (optional reviewed policy boundary descriptions; fail-closed on
  multi-policy ambiguity; never copies executable evaluation rules)

Never calls an LLM and never contacts a Target.
"""

from __future__ import annotations

from hashlib import sha256
import json
import re
from typing import Any, Literal, Mapping

from pydantic import Field

from generator.constants import (
    ASI_CODE_TO_CATEGORY,
    AsiCategory,
    AsiCode,
    SUPPORTED_ASI_CODES,
)
from generator.models import StrictGeneratorModel, normalize_asi_code

ReadinessStatus = Literal["ready", "ready_with_warnings", "blocked"]
CapabilityVerdict = Literal["supported", "unsupported", "unverified", "unknown"]
CapabilityProvenanceVerdict = Literal[
    "runtime_confirmed", "operator_declared", "discovery_suggested", "undeclared"
]
ContextBindingStatus = Literal["current", "stale", "missing", "invalid"]

SUPPORTED_GENERATOR_PROTOCOLS: frozenset[str] = frozenset({"openai-chat", "http-json"})

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
ALL_KNOWN_SCOPES: frozenset[str] = RESPONSE_ONLY_SCOPES | EXECUTION_SCOPES

DEFAULT_SCOPE_BY_ASI: dict[AsiCode, str] = {
    "ASI01": "goal_hijack_response",
    "ASI02": "tool_intent_response",
    "ASI03": "identity_claim_response",
    "ASI05": "response_command_artifact",
}

# R03A: Exact per-ASI scope allowlist grounded in HEAD contracts
# (verdict_resolver.py, asi05_execution.py, response_policies.py, contract.py).
ALLOWED_SCOPES_BY_ASI: dict[AsiCode, frozenset[str]] = {
    "ASI01": frozenset({"goal_hijack_response", "web_fetch", "web_callback", "agent_run"}),
    "ASI02": frozenset({"tool_intent_response", "agent_run", "direct_request"}),
    "ASI03": frozenset({"identity_claim_response"}),
    "ASI05": frozenset({"response_command_artifact", "execution_action", "agent_run", "direct_request"}),
}

# Mirrors evaluators/contract.py SCOPE_CAPABILITY_KEYS without coupling generator/ to evaluators/.
_SCOPE_CAPABILITY_KEYS: dict[str, tuple[str, ...]] = {
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

# Canonical 18 ApplicationContextDraft text fields + optional forward-compatible agent_identity.
APPLICATION_CONTEXT_TEXT_FIELDS: tuple[str, ...] = (
    "purpose",
    "features",
    "domain_industry",
    "operational_constraints",
    "available_tools",
    "users",
    "allowed_resources",
    "prohibited_resources",
    "authorized_actions",
    "authorization_required",
    "trust_boundaries",
    "sensitive_data_categories",
    "protected_assets",
    "high_risk_actions",
    "data_handling_restrictions",
    "required_instructions",
    "business_restrictions",
    "redteam_personas",
    "agent_identity",
)

_UNVERIFIED_PROVENANCE_VALUES: frozenset[str] = frozenset({
    "discovered_observed",
    "suggested_unverified",
})
_GENERAL_BOUNDARY_FIELDS: tuple[str, ...] = (
    "prohibited_resources",
    "trust_boundaries",
    "high_risk_actions",
    "operational_constraints",
    "business_restrictions",
    "required_instructions",
)
_ASI02_TOOL_BOUNDARY_FIELDS: tuple[str, ...] = (
    "available_tools",
    "authorized_actions",
    "high_risk_actions",
    "prohibited_resources",
)
# R01: generic trust_boundaries alone is NOT sufficient proof of ASI03 identity/privilege applicability.
_ASI03_IDENTITY_FIELDS: tuple[str, ...] = (
    "users",
    "authorized_actions",
    "authorization_required",
    "redteam_personas",
    "agent_identity",
)
# R01: arbitrary available_tools alone is NOT evidence of ASI05 code-execution applicability.
_ASI05_BOUNDARY_FIELDS: tuple[str, ...] = (
    "high_risk_actions",
    "prohibited_resources",
    "trust_boundaries",
)

_DETERMINISTIC_READINESS_LIMITATIONS: tuple[str, ...] = (
    "Deterministic readiness checks structure, provenance, and explicit conflicts only; "
    "it cannot exhaustively detect subtle free-text semantic contradictions.",
    "Readiness never probes the Target and cannot verify whether synthetic sandbox resources "
    "actually exist at runtime.",
    "Semantic applicability of a prompt category is distinct from runtime execution eligibility "
    "and independent evidence verification.",
)


class ReadinessFinding(StrictGeneratorModel):
    """Structured blocker or warning surfaced during deterministic readiness assessment."""

    severity: Literal["blocker", "warning"]
    code: str = Field(min_length=1, max_length=96)
    message: str = Field(min_length=1, max_length=512)


class ReviewedPolicyCandidateRef(StrictGeneratorModel):
    """Deterministic reference to a reviewed ResponsePolicy candidate for explicit selection."""

    policy_id: str = Field(min_length=1, max_length=128)
    revision_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    evaluation_scope: str = Field(min_length=1, max_length=128)
    reviewed_at: str | None = None


class ReviewedPolicySummary(StrictGeneratorModel):
    """Read-only, non-executable boundary summary extracted from a reviewed ResponsePolicy."""

    policy_id: str = Field(min_length=1, max_length=128)
    category: AsiCategory
    revision_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    evaluation_scope: str = Field(min_length=1, max_length=128)
    delivery_surface: str = Field(min_length=1, max_length=256)
    prohibited_behavior: str = Field(min_length=1, max_length=4000)
    allowed_benign_context: str = Field(min_length=1, max_length=4000)
    expected_response_boundary: str = Field(min_length=1, max_length=4000)
    established_identity: str | None = Field(default=None, max_length=1000)
    has_evaluation_rules: bool = False


class ConfirmedContextSnapshot(StrictGeneratorModel):
    """Credential-free, read-only snapshot of confirmed Target, Context, and optional Policy metadata."""

    target_id: str = Field(min_length=1, max_length=128)
    target_name: str = Field(min_length=1, max_length=160)
    target_revision_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    target_reviewed: bool
    target_protocol: str = Field(min_length=1, max_length=64)
    application_context_revision_sha256: str | None = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    application_context_binding_status: ContextBindingStatus
    confirmed_fields: dict[str, str] = Field(default_factory=dict)
    excluded_unverified_fields: tuple[str, ...] = ()
    excluded_missing_provenance_fields: tuple[str, ...] = ()
    capability_states: dict[str, str] = Field(default_factory=dict)
    capability_provenance: dict[str, str] = Field(default_factory=dict)
    compatible_scopes: tuple[str, ...] = ()
    unsupported_scopes: tuple[str, ...] = ()
    unverified_scopes: tuple[str, ...] = ()
    evidence_availability: tuple[str, ...] = ()
    reviewed_policies: dict[AsiCode, ReviewedPolicySummary] = Field(default_factory=dict)
    ambiguous_policy_candidates: dict[AsiCode, tuple[ReviewedPolicyCandidateRef, ...]] = Field(
        default_factory=dict
    )
    policy_lookup_errors: dict[AsiCode, str] = Field(default_factory=dict)
    snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class AsiReadinessAssessment(StrictGeneratorModel):
    """Per-ASI deterministic readiness assessment with explicit blockers, warnings, and scope."""

    asi_code: AsiCode
    asi_category: AsiCategory
    status: ReadinessStatus
    effective_scope: str | None = None
    requested_scope: str | None = None
    scope_capability_state: CapabilityVerdict
    scope_capability_provenance: CapabilityProvenanceVerdict = "undeclared"
    blockers: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    findings: tuple[ReadinessFinding, ...] = ()
    has_reviewed_policy: bool = False
    reviewed_policy_id: str | None = None
    reviewed_policy_revision_sha256: str | None = None
    ambiguous_policy_candidates: tuple[ReviewedPolicyCandidateRef, ...] = ()
    deterministic_limitations: tuple[str, ...] = _DETERMINISTIC_READINESS_LIMITATIONS


class TargetReadinessReport(StrictGeneratorModel):
    """Complete deterministic readiness report for one Target across selected/all OWASP ASI groups."""

    target_id: str = Field(min_length=1, max_length=128)
    target_exists: bool
    snapshot: ConfirmedContextSnapshot | None = None
    overall_status: ReadinessStatus
    asi_assessments: dict[AsiCode, AsiReadinessAssessment]


def _canonical_sha256(payload: Any) -> str:
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")
    return sha256(encoded).hexdigest()


def _normalize_phrase(text: str) -> str:
    return re.sub(r"\s+", " ", text.strip().lower())


def _split_declared_items(text: str) -> list[str]:
    """Extract normalized delimiter-separated items (>= 4 chars) for explicit conflict checks."""
    items: list[str] = []
    for raw in re.split(r"[,;\n]+", text):
        norm = _normalize_phrase(raw)
        if len(norm) >= 4:
            items.append(norm)
    return items


def _detect_deterministic_policy_context_conflict(
    confirmed_fields: Mapping[str, str],
    policy: ReviewedPolicySummary,
) -> str | None:
    """Detect unambiguous structural/phrase contradictions between Context and Reviewed Policy."""
    prohibited_pol = _normalize_phrase(policy.prohibited_behavior)
    allowed_pol = _normalize_phrase(policy.allowed_benign_context)

    for ctx_key in ("authorized_actions", "allowed_resources"):
        raw_val = confirmed_fields.get(ctx_key, "")
        for item in _split_declared_items(raw_val):
            pattern = r"(?<!\w)" + re.escape(item) + r"(?!\w)"
            if re.search(pattern, prohibited_pol):
                return (
                    f"Confirmed Application Context '{ctx_key}' item ({item!r}) directly "
                    f"conflicts with Reviewed Policy '{policy.policy_id}' prohibited_behavior."
                )

    raw_prohibited = confirmed_fields.get("prohibited_resources", "")
    for item in _split_declared_items(raw_prohibited):
        pattern = r"(?<!\w)" + re.escape(item) + r"(?!\w)"
        if re.search(pattern, allowed_pol):
            return (
                f"Confirmed Application Context 'prohibited_resources' item ({item!r}) directly "
                f"conflicts with Reviewed Policy '{policy.policy_id}' allowed_benign_context."
            )

    return None


def _resolve_scope_capability_state(
    scope: str,
    snapshot: ConfirmedContextSnapshot,
) -> CapabilityVerdict:
    if scope in snapshot.unsupported_scopes:
        return "unsupported"
    if scope in snapshot.compatible_scopes:
        return "supported"
    if scope in snapshot.unverified_scopes:
        return "unverified"
    return "unknown"


def _resolve_scope_capability_provenance(
    scope: str,
    snapshot: ConfirmedContextSnapshot,
) -> CapabilityProvenanceVerdict:
    """Identify provenance backing a supported scope capability without fabricating verification."""
    keys = _SCOPE_CAPABILITY_KEYS.get(scope, ())
    supporting_provs: list[str] = []
    for key in keys:
        if snapshot.capability_states.get(key) == "supported":
            prov = snapshot.capability_provenance.get(key)
            if isinstance(prov, str) and prov:
                supporting_provs.append(prov)
    if "runtime_confirmed" in supporting_provs:
        return "runtime_confirmed"
    if "operator_declared" in supporting_provs:
        return "operator_declared"
    if "discovery_suggested" in supporting_provs:
        return "discovery_suggested"
    return "undeclared"


def _has_runtime_evidence(snapshot: ConfirmedContextSnapshot) -> bool:
    return any(
        ev in {
            "inline_structured_evidence",
            "dedicated_http_evidence_api",
            "configured_artifact_or_tool_source",
        }
        for ev in snapshot.evidence_availability
    )


def _read_reviewed_policies(
    *,
    target_id: str,
    policy_store: Any | None,
    policy_ids_by_asi: Mapping[AsiCode, str] | None = None,
) -> tuple[
    dict[AsiCode, ReviewedPolicySummary],
    dict[AsiCode, tuple[ReviewedPolicyCandidateRef, ...]],
    dict[AsiCode, str],
]:
    if policy_store is None:
        return {}, {}, {}

    policies: dict[AsiCode, ReviewedPolicySummary] = {}
    ambiguous_candidates: dict[AsiCode, tuple[ReviewedPolicyCandidateRef, ...]] = {}
    errors: dict[AsiCode, str] = {}

    for asi_code in SUPPORTED_ASI_CODES:
        category = ASI_CODE_TO_CATEGORY[asi_code]
        explicit_id = policy_ids_by_asi.get(asi_code) if policy_ids_by_asi else None
        chosen = None

        if explicit_id:
            try:
                chosen = policy_store.require_reviewed(explicit_id, target_id=target_id)
            except (FileNotFoundError, ValueError):
                errors[asi_code] = "policy_not_reviewed_or_invalid"
                continue
            if chosen.category != category:
                errors[asi_code] = "policy_category_mismatch"
                continue
        else:
            try:
                raw_candidates = [
                    rec
                    for rec in policy_store.list_for_target(target_id, category=category)
                    if getattr(rec, "review_status", None) == "reviewed"
                ]
            except Exception:
                errors[asi_code] = "policy_store_unavailable"
                continue
            if not raw_candidates:
                continue

            # Deterministic ordering independent of filesystem glob / UUID4 order.
            ordered_candidates = sorted(
                raw_candidates,
                key=lambda rec: (str(getattr(rec, "reviewed_at", None) or ""), str(rec.policy_id)),
            )

            # R04: Fail-closed on multi-policy ambiguity; never auto-pick candidates[-1] or newest.
            if len(ordered_candidates) > 1:
                refs: list[ReviewedPolicyCandidateRef] = []
                for rec in ordered_candidates:
                    try:
                        verified = policy_store.require_reviewed(rec.policy_id, target_id=target_id)
                    except (FileNotFoundError, ValueError):
                        continue
                    refs.append(
                        ReviewedPolicyCandidateRef(
                            policy_id=verified.policy_id,
                            revision_sha256=verified.revision_sha256,
                            evaluation_scope=verified.draft.evaluation_scope,
                            reviewed_at=getattr(verified, "reviewed_at", None),
                        )
                    )
                if len(refs) > 1:
                    ambiguous_candidates[asi_code] = tuple(refs)
                    errors[asi_code] = "multiple_reviewed_policies_ambiguous"
                    continue
                if len(refs) == 0:
                    errors[asi_code] = "policy_not_reviewed_or_invalid"
                    continue
                # Exactly one candidate survived cryptographic verification.
                chosen = policy_store.require_reviewed(refs[0].policy_id, target_id=target_id)
            else:
                only = ordered_candidates[0]
                try:
                    chosen = policy_store.require_reviewed(only.policy_id, target_id=target_id)
                except (FileNotFoundError, ValueError):
                    errors[asi_code] = "policy_not_reviewed_or_invalid"
                    continue

        extra_rules = chosen.draft.extra_rules if isinstance(chosen.draft.extra_rules, dict) else {}
        est_id = extra_rules.get("established_identity")
        clean_est_id = (
            est_id.strip()
            if isinstance(est_id, str) and est_id.strip() and est_id.strip().lower() != "unknown"
            else None
        )
        policies[asi_code] = ReviewedPolicySummary(
            policy_id=chosen.policy_id,
            category=chosen.category,
            revision_sha256=chosen.revision_sha256,
            evaluation_scope=chosen.draft.evaluation_scope,
            delivery_surface=chosen.draft.delivery_surface,
            prohibited_behavior=chosen.draft.prohibited_behavior,
            allowed_benign_context=chosen.draft.allowed_benign_context,
            expected_response_boundary=chosen.draft.expected_response_boundary,
            established_identity=clean_est_id,
            has_evaluation_rules=bool(chosen.draft.evaluation_rules),
        )

    return policies, ambiguous_candidates, errors


def build_context_snapshot(
    *,
    target_id: str,
    catalog: Any,
    application_contexts: Any | None,
    policy_store: Any | None = None,
    policy_ids_by_asi: Mapping[AsiCode, str] | None = None,
) -> ConfirmedContextSnapshot | None:
    """Build a read-only, credential-free ConfirmedContextSnapshot for one Target."""
    public_rows = catalog.public_targets() if hasattr(catalog, "public_targets") else []
    target_row = next((r for r in public_rows if isinstance(r, dict) and r.get("id") == target_id), None)
    if target_row is None:
        return None

    target_rev = str(target_row["profile_revision"])
    target_reviewed = target_row.get("authorization_status") == "reviewed_for_offline_configuration"
    target_protocol = str(target_row.get("protocol") or "")
    target_name = str(target_row.get("name") or target_id)

    raw_cap_states = target_row.get("capability_states")
    cap_states = (
        {str(k): str(v) for k, v in raw_cap_states.items()}
        if isinstance(raw_cap_states, Mapping)
        else {}
    )
    raw_cap_prov = target_row.get("capability_provenance")
    cap_prov = (
        {str(k): str(v) for k, v in raw_cap_prov.items()}
        if isinstance(raw_cap_prov, Mapping)
        else {}
    )
    cap_summary = target_row.get("capability_summary")
    cap_summary_dict = cap_summary if isinstance(cap_summary, Mapping) else {}
    compatible_scopes = tuple(str(s) for s in (cap_summary_dict.get("compatible_scopes") or ()))
    unsupported_scopes = tuple(str(s) for s in (cap_summary_dict.get("unsupported_scopes") or ()))
    unverified_scopes = tuple(str(s) for s in (cap_summary_dict.get("unverified_scopes") or ()))
    evidence_availability = tuple(str(s) for s in (cap_summary_dict.get("evidence_availability") or ()))

    # Read Application Context strictly read-only and verify integrity + binding.
    binding_status: ContextBindingStatus = "missing"
    app_ctx_rev: str | None = None
    confirmed_fields: dict[str, str] = {}
    excluded_unverified: list[str] = []
    excluded_missing_prov: list[str] = []

    if application_contexts is not None:
        try:
            row = application_contexts.read(target_id)
        except Exception:
            row = None
            binding_status = "invalid"
        else:
            if row is None:
                binding_status = "missing"
            elif (
                not isinstance(row, dict)
                or row.get("schema_version") != "1.0.0"
                or row.get("provenance") != "operator_declared"
                or not isinstance(row.get("draft"), dict)
            ):
                binding_status = "invalid"
            else:
                raw_draft = row["draft"]
                raw_rev = row.get("revision_sha256")
                expected_rev = sha256(
                    json.dumps(raw_draft, sort_keys=True, separators=(",", ":")).encode("utf-8")
                ).hexdigest()
                if raw_draft.get("target_id") != target_id or raw_rev != expected_rev:
                    binding_status = "invalid"
                else:
                    app_ctx_rev = raw_rev
                    if raw_draft.get("target_revision") != target_rev:
                        binding_status = "stale"
                    else:
                        binding_status = "current"

                    prov_map = raw_draft.get("field_provenance")
                    prov_dict = prov_map if isinstance(prov_map, dict) else {}
                    # Strict provenance gate: ONLY explicit "operator_confirmed" enters confirmed_fields.
                    for field_name in APPLICATION_CONTEXT_TEXT_FIELDS:
                        raw_val = raw_draft.get(field_name)
                        if not isinstance(raw_val, str) or not raw_val.strip():
                            continue
                        field_prov = prov_dict.get(field_name)
                        if field_prov == "operator_confirmed":
                            confirmed_fields[field_name] = raw_val.strip()
                        elif field_prov in _UNVERIFIED_PROVENANCE_VALUES:
                            excluded_unverified.append(field_name)
                        else:
                            excluded_missing_prov.append(field_name)

    reviewed_policies, ambiguous_candidates, policy_errors = _read_reviewed_policies(
        target_id=target_id,
        policy_store=policy_store,
        policy_ids_by_asi=policy_ids_by_asi,
    )

    # R04: Include both selected policy_id and revision_sha256 (plus capability_provenance and
    # ambiguous candidates) in snapshot_sha256 so distinct research selections yield distinct hashes.
    hash_material = {
        "target_id": target_id,
        "target_revision_sha256": target_rev,
        "target_protocol": target_protocol,
        "application_context_revision_sha256": app_ctx_rev,
        "application_context_binding_status": binding_status,
        "confirmed_fields": confirmed_fields,
        "capability_states": cap_states,
        "capability_provenance": cap_prov,
        "reviewed_policies": {
            code: {"policy_id": pol.policy_id, "revision_sha256": pol.revision_sha256}
            for code, pol in sorted(reviewed_policies.items())
        },
        "ambiguous_policy_candidates": {
            code: [
                {"policy_id": ref.policy_id, "revision_sha256": ref.revision_sha256}
                for ref in refs
            ]
            for code, refs in sorted(ambiguous_candidates.items())
        },
    }
    snap_hash = _canonical_sha256(hash_material)

    return ConfirmedContextSnapshot(
        target_id=target_id,
        target_name=target_name,
        target_revision_sha256=target_rev,
        target_reviewed=target_reviewed,
        target_protocol=target_protocol,
        application_context_revision_sha256=app_ctx_rev,
        application_context_binding_status=binding_status,
        confirmed_fields=confirmed_fields,
        excluded_unverified_fields=tuple(excluded_unverified),
        excluded_missing_provenance_fields=tuple(excluded_missing_prov),
        capability_states=cap_states,
        capability_provenance=cap_prov,
        compatible_scopes=compatible_scopes,
        unsupported_scopes=unsupported_scopes,
        unverified_scopes=unverified_scopes,
        evidence_availability=evidence_availability,
        reviewed_policies=reviewed_policies,
        ambiguous_policy_candidates=ambiguous_candidates,
        policy_lookup_errors=policy_errors,
        snapshot_sha256=snap_hash,
    )


def assess_target_readiness(
    *,
    target_id: str,
    catalog: Any,
    application_contexts: Any | None,
    policy_store: Any | None = None,
    selected_asi: tuple[str, ...] | list[str] | None = None,
    requested_scopes: Mapping[str, str] | None = None,
    policy_ids_by_asi: Mapping[str, str] | None = None,
) -> TargetReadinessReport:
    """Assess deterministic per-ASI generation readiness without contacting LLM or Target."""
    asi_list: tuple[AsiCode, ...] = (
        tuple(normalize_asi_code(code) for code in selected_asi)
        if selected_asi is not None
        else SUPPORTED_ASI_CODES
    )
    norm_req_scopes: dict[AsiCode, str] = {}
    if requested_scopes:
        for k, v in requested_scopes.items():
            norm_req_scopes[normalize_asi_code(k)] = v.strip()

    norm_policy_ids: dict[AsiCode, str] = {}
    if policy_ids_by_asi:
        for k, v in policy_ids_by_asi.items():
            norm_policy_ids[normalize_asi_code(k)] = v.strip()

    snapshot = build_context_snapshot(
        target_id=target_id,
        catalog=catalog,
        application_contexts=application_contexts,
        policy_store=policy_store,
        policy_ids_by_asi=norm_policy_ids or None,
    )

    if snapshot is None:
        missing_finding = ReadinessFinding(
            severity="blocker",
            code="target_not_found",
            message=f"Target '{target_id}' was not found in the active catalog.",
        )
        assessments = {
            code: AsiReadinessAssessment(
                asi_code=code,
                asi_category=ASI_CODE_TO_CATEGORY[code],
                status="blocked",
                effective_scope=None,
                requested_scope=norm_req_scopes.get(code),
                scope_capability_state="unknown",
                blockers=("target_not_found",),
                findings=(missing_finding,),
            )
            for code in asi_list
        }
        return TargetReadinessReport(
            target_id=target_id,
            target_exists=False,
            snapshot=None,
            overall_status="blocked",
            asi_assessments=assessments,
        )

    assessments: dict[AsiCode, AsiReadinessAssessment] = {}
    for asi_code in asi_list:
        assessments[asi_code] = _assess_single_asi(
            snapshot=snapshot,
            asi_code=asi_code,
            requested_scope=norm_req_scopes.get(asi_code),
        )

    statuses = {a.status for a in assessments.values()}
    if not assessments or statuses == {"blocked"}:
        overall: ReadinessStatus = "blocked"
    elif "blocked" in statuses or "ready_with_warnings" in statuses:
        overall = "ready_with_warnings" if any(s != "blocked" for s in statuses) else "blocked"
    else:
        overall = "ready"

    return TargetReadinessReport(
        target_id=target_id,
        target_exists=True,
        snapshot=snapshot,
        overall_status=overall,
        asi_assessments=assessments,
    )


def _assess_single_asi(
    *,
    snapshot: ConfirmedContextSnapshot,
    asi_code: AsiCode,
    requested_scope: str | None,
) -> AsiReadinessAssessment:
    category = ASI_CODE_TO_CATEGORY[asi_code]
    findings: list[ReadinessFinding] = []

    def add_blocker(code: str, message: str) -> None:
        findings.append(ReadinessFinding(severity="blocker", code=code, message=message))

    def add_warning(code: str, message: str) -> None:
        findings.append(ReadinessFinding(severity="warning", code=code, message=message))

    # 1. Target transport / protocol check
    if snapshot.target_protocol not in SUPPORTED_GENERATOR_PROTOCOLS:
        add_blocker(
            "unsupported_target_protocol",
            f"Target protocol '{snapshot.target_protocol}' is not supported for natural-language "
            "prompt generation; select an 'openai-chat' or 'http-json' target.",
        )

    if not snapshot.target_reviewed:
        add_warning(
            "target_unreviewed",
            "Target profile is unreviewed. Dataset generation does not contact the Target, "
            "but Target review is required before running a live Scan.",
        )

    # 2. Application Context presence, integrity, and revision freshness
    if snapshot.application_context_binding_status == "missing":
        add_blocker(
            "application_context_missing",
            "Application Context is missing for this Target. Declare and confirm Application Context first.",
        )
    elif snapshot.application_context_binding_status == "invalid":
        add_blocker(
            "application_context_invalid",
            "Stored Application Context failed integrity or provenance verification.",
        )
    elif snapshot.application_context_binding_status == "stale":
        add_blocker(
            "application_context_stale",
            "Application Context is bound to an older Target revision. Re-save Application Context "
            "against the current Target revision before generating.",
        )

    if snapshot.excluded_unverified_fields:
        add_warning(
            "unverified_context_fields_excluded",
            "Excluded unverified discovery/suggested fields until confirmed by operator: "
            + ", ".join(snapshot.excluded_unverified_fields)
            + ".",
        )
    if snapshot.excluded_missing_provenance_fields:
        add_warning(
            "missing_provenance_fields_excluded",
            "Excluded Application Context fields lacking explicit 'operator_confirmed' provenance: "
            + ", ".join(snapshot.excluded_missing_provenance_fields)
            + ".",
        )

    confirmed = snapshot.confirmed_fields
    policy = snapshot.reviewed_policies.get(asi_code)
    ambiguous_refs = snapshot.ambiguous_policy_candidates.get(asi_code, ())
    policy_err = snapshot.policy_lookup_errors.get(asi_code)
    if policy_err == "multiple_reviewed_policies_ambiguous":
        candidate_ids = ", ".join(ref.policy_id for ref in ambiguous_refs)
        add_blocker(
            "multiple_reviewed_policies_ambiguous",
            f"Multiple reviewed policies exist for Target '{snapshot.target_id}' and {asi_code} "
            f"({candidate_ids}). Pass an explicit policy_id rather than selecting implicitly.",
        )
    elif policy_err:
        add_blocker(
            policy_err,
            f"Reviewed ResponsePolicy lookup failed for {asi_code} ({policy_err}).",
        )

    # 3. Core confirmed purpose & general security boundary check
    has_unverified_only = bool(
        snapshot.excluded_unverified_fields or snapshot.excluded_missing_provenance_fields
    )
    if snapshot.application_context_binding_status == "current":
        if not confirmed.get("purpose"):
            if has_unverified_only:
                add_blocker(
                    "purpose_not_confirmed",
                    "Application Context 'purpose' is not operator-confirmed (unverified or missing provenance).",
                )
            else:
                add_blocker(
                    "purpose_not_confirmed",
                    "Operator-confirmed Application Context 'purpose' is required before generation.",
                )

        has_general_boundary = any(confirmed.get(k) for k in _GENERAL_BOUNDARY_FIELDS) or (policy is not None)
        if not has_general_boundary:
            add_blocker(
                "security_boundary_insufficient",
                "At least one operator-confirmed security boundary field (or reviewed ResponsePolicy) "
                "is required to ground testcase generation.",
            )

    # 4. R03A: ASI-specific scope resolution & compatibility (NEVER silently downgrade!)
    allowed_for_asi = ALLOWED_SCOPES_BY_ASI[asi_code]
    effective_scope: str | None = None
    if requested_scope is not None:
        if requested_scope not in ALL_KNOWN_SCOPES:
            add_blocker(
                "unsupported_evaluation_scope",
                f"Requested evaluation scope '{requested_scope}' is unsupported.",
            )
        elif requested_scope not in allowed_for_asi:
            add_blocker(
                "asi_scope_incompatible",
                f"Requested scope '{requested_scope}' is incompatible with {asi_code} ({category}); "
                f"supported scopes for {asi_code} are: {', '.join(sorted(allowed_for_asi))}.",
            )
            effective_scope = requested_scope
        else:
            effective_scope = requested_scope
            if policy is not None and policy.evaluation_scope != requested_scope:
                add_blocker(
                    "policy_scope_conflict",
                    f"Requested scope '{requested_scope}' conflicts with Reviewed Policy "
                    f"'{policy.policy_id}' scope '{policy.evaluation_scope}'.",
                )
    else:
        effective_scope = policy.evaluation_scope if policy is not None else DEFAULT_SCOPE_BY_ASI[asi_code]

    # Always validate effective_scope (including Reviewed Policy scope) against ASI compatibility.
    if (
        policy is not None
        and policy.evaluation_scope not in allowed_for_asi
        and not any(f.code == "asi_scope_incompatible" for f in findings)
    ):
        add_blocker(
            "asi_scope_incompatible",
            f"Reviewed Policy '{policy.policy_id}' scope '{policy.evaluation_scope}' is incompatible "
            f"with {asi_code} ({category}); supported scopes are: {', '.join(sorted(allowed_for_asi))}.",
        )

    scope_cap_state: CapabilityVerdict = (
        _resolve_scope_capability_state(effective_scope, snapshot)
        if effective_scope is not None
        else "unknown"
    )
    scope_cap_prov: CapabilityProvenanceVerdict = (
        _resolve_scope_capability_provenance(effective_scope, snapshot)
        if effective_scope is not None and scope_cap_state == "supported"
        else "undeclared"
    )

    if effective_scope is not None and effective_scope in allowed_for_asi:
        if scope_cap_state == "unsupported":
            add_blocker(
                "scope_capability_unsupported",
                f"Target explicitly marks scope '{effective_scope}' as unsupported; "
                "generation will not silently downgrade scope.",
            )
        elif effective_scope in EXECUTION_SCOPES:
            if scope_cap_state in {"unverified", "unknown"}:
                add_blocker(
                    "execution_scope_capability_unverified",
                    f"Execution scope '{effective_scope}' requires confirmed execution capability "
                    f"(current state: '{scope_cap_state}'); refusing to silently downgrade to response-only.",
                )
            elif scope_cap_prov == "discovery_suggested":
                add_blocker(
                    "capability_discovery_suggested_unconfirmed",
                    f"Target capability for execution scope '{effective_scope}' is only "
                    "'discovery_suggested' (not yet confirmed by operator); confirm Target capability "
                    "before generating execution-scoped testcases.",
                )
            elif scope_cap_prov != "runtime_confirmed":
                add_warning(
                    "capability_not_runtime_verified",
                    f"Target capability for execution scope '{effective_scope}' is {scope_cap_prov} "
                    "(not independently runtime-verified). Generation does not authorize execution; "
                    "Generic Scan preflight remains authoritative.",
                )
            if not _has_runtime_evidence(snapshot):
                add_blocker(
                    "execution_scope_evidence_unavailable",
                    f"Execution scope '{effective_scope}' has no configured runtime evidence source; "
                    "select a response-level scope explicitly or configure runtime evidence.",
                )
        elif effective_scope in RESPONSE_ONLY_SCOPES:
            if scope_cap_state in {"unverified", "unknown"}:
                add_warning(
                    "response_capability_unverified",
                    f"Target capability for response scope '{effective_scope}' is '{scope_cap_state}' "
                    "(declared/unverified, not runtime-confirmed).",
                )
            elif scope_cap_prov == "discovery_suggested":
                add_warning(
                    "capability_discovery_suggested_unconfirmed",
                    f"Target capability for response scope '{effective_scope}' is only "
                    "'discovery_suggested' (not yet confirmed by operator).",
                )
            elif scope_cap_prov != "runtime_confirmed":
                add_warning(
                    "capability_not_runtime_verified",
                    f"Target capability for response scope '{effective_scope}' is {scope_cap_prov} "
                    "(configured claim, not independently runtime-verified).",
                )

    # 5. Deterministic conflict check between confirmed Application Context and Reviewed Policy
    if policy is not None and snapshot.application_context_binding_status == "current":
        if policy.evaluation_scope in snapshot.unsupported_scopes:
            add_blocker(
                "policy_scope_unsupported",
                f"Reviewed Policy '{policy.policy_id}' scope '{policy.evaluation_scope}' is unsupported by Target.",
            )
        conflict_msg = _detect_deterministic_policy_context_conflict(confirmed, policy)
        if conflict_msg is not None:
            add_blocker("policy_context_boundary_conflict", conflict_msg)

    # 6. Per-ASI semantic applicability & context prerequisites (aligned with R01 & R02)
    if snapshot.application_context_binding_status == "current":
        if asi_code == "ASI01":
            if not confirmed.get("required_instructions") and policy is None:
                add_warning(
                    "required_instructions_not_declared",
                    "ASI01 'required_instructions' is not declared; generation will rely on "
                    "confirmed purpose and declared constraint/boundary fields.",
                )
        elif asi_code == "ASI02":
            if not any(confirmed.get(k) for k in _ASI02_TOOL_BOUNDARY_FIELDS) and policy is None:
                add_blocker(
                    "asi02_tool_boundary_insufficient",
                    "ASI02 requires at least one confirmed tool/action boundary field "
                    "(available_tools, authorized_actions, high_risk_actions, or prohibited_resources) "
                    "or a reviewed ASI02 policy.",
                )
            if not confirmed.get("available_tools"):
                add_warning(
                    "available_tools_not_confirmed",
                    "No confirmed 'available_tools' declared; Generator must not fabricate tool names.",
                )
            if not _has_runtime_evidence(snapshot):
                add_warning(
                    "no_independent_tool_observer",
                    "No independent runtime tool observer is configured. Absence of an observer does "
                    "not prove the Target lacks tool execution; it limits verifiable execution evidence.",
                )
        elif asi_code == "ASI03":
            has_identity_ctx = any(confirmed.get(k) for k in _ASI03_IDENTITY_FIELDS) or (policy is not None)
            if not has_identity_ctx:
                add_blocker(
                    "asi03_identity_boundary_insufficient",
                    "ASI03 requires confirmed identity, role, or delegated-privilege context "
                    "(users, authorized_actions, authorization_required, redteam_personas, "
                    "agent_identity, or reviewed ASI03 policy). Generic trust_boundaries alone is insufficient.",
                )
            has_agent_identity = bool(confirmed.get("agent_identity")) or bool(
                policy is not None and policy.established_identity
            )
            if not has_agent_identity:
                add_warning(
                    "agent_identity_not_declared",
                    "No explicit 'agent_identity' is declared in Application Context or Reviewed Policy; "
                    "Generator must not fabricate an official agent identity.",
                )
        elif asi_code == "ASI05":
            has_asi05_boundary = any(confirmed.get(k) for k in _ASI05_BOUNDARY_FIELDS) or (policy is not None)
            if not has_asi05_boundary:
                add_blocker(
                    "asi05_execution_boundary_insufficient",
                    "ASI05 requires an explicit execution/command risk boundary "
                    "(high_risk_actions, prohibited_resources, trust_boundaries, or reviewed ASI05 policy). "
                    "Arbitrary available_tools alone is not evidence of code execution capability.",
                )
            if not confirmed.get("authorized_actions") and policy is None:
                add_warning(
                    "asi05_coding_boundary_ambiguous",
                    "Confirmed 'authorized_actions' is empty; clarify whether benign coding assistance "
                    "is permitted to avoid conflating legitimate coding help with ASI05.",
                )
            if effective_scope == "response_command_artifact":
                add_warning(
                    "asi05_response_artifact_scope_note",
                    "Scope 'response_command_artifact' tests prohibited command/code output boundaries; "
                    "generating code text does not prove code execution or RCE.",
                )

    # Always remind operator about sandbox resource confirmation vs hypothetical placeholders.
    add_warning(
        "synthetic_sandbox_resources_unverified",
        "Deterministic readiness does not probe the Target; distinguish operator-confirmed "
        "synthetic sandbox resources from hypothetical placeholders during review.",
    )

    blockers = tuple(f.code for f in findings if f.severity == "blocker")
    warnings = tuple(f.code for f in findings if f.severity == "warning")
    status: ReadinessStatus = (
        "blocked" if blockers else ("ready_with_warnings" if warnings else "ready")
    )

    return AsiReadinessAssessment(
        asi_code=asi_code,
        asi_category=category,
        status=status,
        effective_scope=effective_scope,
        requested_scope=requested_scope,
        scope_capability_state=scope_cap_state,
        scope_capability_provenance=scope_cap_prov,
        blockers=blockers,
        warnings=warnings,
        findings=tuple(findings),
        has_reviewed_policy=policy is not None,
        reviewed_policy_id=policy.policy_id if policy is not None else None,
        reviewed_policy_revision_sha256=policy.revision_sha256 if policy is not None else None,
        ambiguous_policy_candidates=ambiguous_refs,
    )

"""Pure aggregation of explicitly selected normalized records; no evaluation or IO."""
from collections import Counter
import hashlib
import json
from typing import Literal

from pydantic import Field

from reporting.models import (
    ArchivedAssessmentReport, ExecutionReport, Model, REPORT_ADAPTER, SHA256,
    Text, VerificationState,
)
from reporting.redaction import Redactor


class AggregationError(ValueError):
    """Malformed or conflicting projections; messages omit source content."""


class Rate(Model):
    numerator: int | None = Field(ge=0)
    denominator: int = Field(ge=0)
    value: float | None
    status: Literal["available", "zero_denominator", "unavailable_contract"]
    definition: Text


class ScopeCount(Model):
    reported_true: int = 0
    reported_false: int = 0
    unknown: int = 0
    total_if_fully_known: int | None = None


class Counts(Model):
    recorded_execution_reports: int
    distinct_testcase_ids: int
    distinct_testcase_definitions: int | None
    known_definition_identities: int
    records_without_definition_identity: int
    records_without_testcase_id: int
    recorded_execution_attempts: ScopeCount
    confirmed_target_invocations: ScopeCount
    planned: ScopeCount
    successful_execution_reports: int
    execution_errors: int
    execution_statuses: dict[str, int]
    security_verdicts: dict[str, int]
    records_with_technical_errors: int
    technical_errors_by_stage: dict[str, int]
    response_completeness: dict[str, int]
    evidence_file_integrity_states: dict[str, int]
    local_consistency_verified_records: int
    locally_consistent_callback_records: int
    human_reference_statuses: dict[str, int]


ComparisonState = Literal["agreement", "disagreement", "valid_not_comparable", "not_requested",
    "skipped_decisive", "prevented", "judge_unavailable_or_failed", "comparison_not_recorded",
    "source_inconsistent", "unlinked"]
LinkageState = Literal["matched_selected_source", "missing_parent_execution", "parent_hash_mismatch",
    "parent_id_mismatch", "unverified_parent_linkage", "verification_mismatch", "snapshot_mismatch"]


class JudgeComparison(Model):
    source_sha256: SHA256
    mode: Literal["production", "archived"]
    parent_source_sha256: SHA256 | None = None
    linkage: LinkageState | None = None
    state: ComparisonState
    reported_comparison: Literal["agreement", "disagreement", "unavailable"] | None = None
    rule_status: Text | None = None
    classification: Text | None = None
    recommendation: Text | None = None
    provider: Text | None = None
    model: Text | None = None
    skill_sha256: SHA256 | None = None
    provider_fault_code: Text | None = None
    json_validation_status: Text | None = None


class Group(Model):
    key: Text | None
    counts: Counts


class Metrics(Model):
    decision_coverage: Rate = Field(description="Deprecated alias for decisive_verdict_rate_among_classified.")
    decisive_verdict_rate_among_classified: Rate
    decision_coverage_over_all_records: Rate
    evidence_coverage: Rate
    verified_artifact_coverage: Rate
    production_judge_comparison_coverage: Rate
    archived_judge_comparison_coverage: Rate


class AggregationSummary(Model):
    summary_schema_version: Literal["1.0.0"] = "1.0.0"
    input_report_schema_version: Literal["2.0.0"] = "2.0.0"
    metric_definition_version: Literal["2C.2.0"] = "2C.2.0"
    selection_policy: Literal["all_explicit_unique_sources_no_assessment_selection"] = "all_explicit_unique_sources_no_assessment_selection"
    snapshot_sha256: SHA256
    selected_input_records: int
    duplicate_inputs_removed: int
    unique_execution_sources: list[SHA256]
    unique_assessment_sources: list[SHA256]
    execution_identity_conflicts: int
    archived_assessments: int
    executions_without_linked_crosscheck: int
    executions_with_multiple_linked_assessments: int
    counts: Counts
    groups: dict[str, list[Group]]
    metrics: Metrics
    production_comparison_counts: dict[str, int]
    archived_comparison_counts: dict[str, int]
    archived_reported_comparison_claims: dict[str, int]
    assessment_linkage_counts: dict[str, int]
    comparisons: list[JudgeComparison]
    source_limitations: list[Text]
    aggregation_performed_archive_verification: Literal[False] = False
    historical_verdicts_modified: Literal[False] = False
    limitations: list[Text] = Field(default_factory=lambda: [
        "Counts describe selected report records; execution failures do not prove target invocation.",
        "Missing definition hashes prevent an exact count of distinct testcase definitions.",
        "Target ID grouping does not establish equivalent target configurations.",
        "Verification metadata is supplied by the caller; aggregation does not reverify archive files or event authenticity.",
        "Response completeness is a source claim, not a complete ASI evidence-sufficiency contract.",
        "No detection accuracy, precision, recall, defense success rate or autonomous LLM behavior is established.",
        "Multiple assessments remain separate; comparison counts are assessment-level, not independent target runs.",
    ])


COMPARISON_STATES = ("agreement", "disagreement", "valid_not_comparable", "not_requested", "skipped_decisive",
    "prevented", "judge_unavailable_or_failed", "comparison_not_recorded", "source_inconsistent", "unlinked")
LINKAGE_STATES = ("matched_selected_source", "missing_parent_execution", "parent_hash_mismatch",
    "parent_id_mismatch", "unverified_parent_linkage", "verification_mismatch", "snapshot_mismatch")
ASI = {"goal_hijacking": "ASI01", "tool_misuse": "ASI02", "identity_privilege_abuse": "ASI03", "unexpected_code_execution": "ASI05"}


def _rate(numerator, denominator, definition):
    return Rate(numerator=numerator, denominator=denominator,
        value=None if not denominator or numerator is None else numerator / denominator,
        status="unavailable_contract" if numerator is None else "zero_denominator" if not denominator else "available",
        definition=definition)


def _counter(values, keys):
    counts = Counter(values)
    return {key: counts[key] for key in keys}


def _scope(records, key):
    values = [getattr(row.execution, key) for row in records]
    return ScopeCount(reported_true=values.count(True), reported_false=values.count(False), unknown=values.count(None),
                      total_if_fully_known=None if None in values else values.count(True))


def _artifact_state(row) -> VerificationState:
    metadata = row.artifact_verification
    if metadata is None:
        return "not_performed"
    if metadata.file_integrity != "verified":
        return metadata.file_integrity
    # Do not count a bare source-provided string as verified artifact coverage.
    roles = {"manifest", "events", "collector_export", "execution"}
    checks = [c for c in metadata.artifacts if c.artifact_role in roles]
    if len(checks) != 4 or {c.artifact_role for c in checks} != roles or any(
        c.state != "verified" or not c.actual_file_byte_sha256 or c.actual_file_byte_sha256 != c.expected_file_byte_sha256 for c in checks):
        return "unsupported"
    if next(c for c in checks if c.artifact_role == "execution").actual_file_byte_sha256 != row.source.file_byte_sha256:
        return "mismatch"
    return "verified"


def _counts(records):
    ids = {r.identity.testcase_id for r in records if r.identity.testcase_id is not None}
    definitions = {(r.identity.testcase_id, r.historical_integrity.testcase_file_byte_sha256) for r in records
                   if r.identity.testcase_id and r.historical_integrity.testcase_file_byte_sha256}
    missing_definitions = sum(not (r.identity.testcase_id and r.historical_integrity.testcase_file_byte_sha256) for r in records)
    return Counts(recorded_execution_reports=len(records), distinct_testcase_ids=len(ids),
        distinct_testcase_definitions=None if missing_definitions else len(definitions),
        known_definition_identities=len(definitions), records_without_definition_identity=missing_definitions,
        records_without_testcase_id=sum(r.identity.testcase_id is None for r in records),
        recorded_execution_attempts=_scope(records, "attempted"), confirmed_target_invocations=_scope(records, "confirmed_target_invocation"),
        planned=_scope(records, "planned"), successful_execution_reports=sum(r.execution.status == "succeeded" for r in records),
        execution_errors=sum(r.execution.status == "failed" for r in records),
        execution_statuses=_counter((r.execution.status for r in records), ("succeeded", "failed", "skipped", "not_started", "unknown")),
        security_verdicts=_counter((r.security.verdict or "unknown" for r in records), ("PASS", "FAIL", "INCONCLUSIVE", "unknown")),
        records_with_technical_errors=sum(bool(r.technical_errors) for r in records),
        technical_errors_by_stage=_counter((e.stage for r in records for e in r.technical_errors), ("execution", "evaluation", "judge", "report", "unknown")),
        response_completeness=_counter((r.observation.response_completeness.state for r in records), ("complete", "partial", "unknown")),
        evidence_file_integrity_states=_counter((_artifact_state(r) for r in records), ("verified", "mismatch", "missing", "unsupported", "not_performed")),
        local_consistency_verified_records=sum(_artifact_state(r) == "verified" and r.artifact_verification.internal_evidence_consistency == "verified" for r in records),
        locally_consistent_callback_records=sum(_artifact_state(r) == "verified" and r.artifact_verification.internal_evidence_consistency == "verified"
                                               and (r.artifact_verification.receipt_count or 0) > 0 for r in records),
        human_reference_statuses=_counter((r.human_reference.status for r in records), ("unavailable", "provisional", "human_verified")))


def _comparison_state(row, rule):
    judge = row.judge
    if row.comparison.source_inconsistent:
        return "source_inconsistent"
    if judge.invocation_state in {"not_requested", "skipped_decisive", "prevented"}:
        return judge.invocation_state
    if judge.invocation_state != "result_available" or judge.reported_json_validation_status != "valid" or not judge.classification:
        return "judge_unavailable_or_failed"
    if row.comparison.reported_status == "unavailable" or rule not in {"PASS", "FAIL"} or judge.recommendation not in {"PASS", "FAIL"}:
        return "valid_not_comparable"
    # Arithmetic comparison of reported values, not a new security decision.
    return "agreement" if rule == judge.recommendation else "disagreement"


def _entry(row, rule, *, linkage=None, parent=None):
    r = Redactor()
    return JudgeComparison(source_sha256=row.source.file_byte_sha256,
        mode="archived" if isinstance(row, ArchivedAssessmentReport) else "production",
        parent_source_sha256=parent, linkage=linkage,
        state="unlinked" if linkage not in {None, "matched_selected_source"} else _comparison_state(row, rule),
        reported_comparison=row.comparison.reported_status, rule_status=rule,
        classification=r.clean(row.judge.classification), recommendation=row.judge.recommendation,
        provider=r.clean(row.judge.provider), model=r.clean(row.judge.model), skill_sha256=row.judge.skill_sha256,
        provider_fault_code=r.clean(row.judge.provider_fault_code), json_validation_status=r.clean(row.judge.reported_json_validation_status))


def _link(row, executions):
    parent = row.source_execution
    if not parent.execution_id or not parent.report_file_byte_sha256:
        return None, "unverified_parent_linkage"
    exact = [r for r in executions if r.execution_id == parent.execution_id and r.source.file_byte_sha256 == parent.report_file_byte_sha256]
    if not exact:
        state = "parent_hash_mismatch" if any(r.execution_id == parent.execution_id for r in executions) else (
            "parent_id_mismatch" if any(r.source.file_byte_sha256 == parent.report_file_byte_sha256 for r in executions) else "missing_parent_execution")
        return None, state
    execution = exact[0]
    metadata = row.artifact_verification
    if metadata and (metadata.crosscheck_linkage in {"mismatch", "missing", "unsupported"} or any(
            value in {"mismatch", "missing", "unsupported"} for key, value in metadata.checks.items() if key.startswith("crosscheck_"))):
        return execution, "verification_mismatch"
    original = execution.deterministic.original
    # An ID+hash match does not excuse contradictory parent snapshots or identity claims.
    if ((parent.deterministic_verdict is not None and parent.deterministic_verdict != (original.status if original else None))
        or (parent.original_verdict_snapshot is not None and parent.original_verdict_snapshot != execution.security.historical_status)
        or any(a is not None and b is not None and a != b for a, b in (
            (row.identity.testcase_id, execution.identity.testcase_id), (row.identity.target_id, execution.identity.target_id),
            (row.identity.asi_category, execution.identity.asi_category)))):
        return execution, "snapshot_mismatch"
    return execution, "matched_selected_source"


def aggregate_reports(records):
    """Aggregate typed normalizer/verifier outputs only. Never loads artifacts or modifies records."""
    selected = list(records)
    unique = {}
    for source in selected:
        if not isinstance(source, (ExecutionReport, ArchivedAssessmentReport)):
            raise AggregationError("Expected normalized execution or assessment records.")
        try:
            row = REPORT_ADAPTER.validate_python(source.model_dump(mode="python"))
        except ValueError:
            raise AggregationError("Malformed normalized record.") from None
        digest = row.source.file_byte_sha256
        prefix = "execution:" if isinstance(row, ExecutionReport) else "assessment:"
        if row.source.identity != "sha256:" + digest or row.report_id != prefix + digest:
            raise AggregationError("Source hash identity is inconsistent.")
        if row.identity.category in ASI and row.identity.asi_category not in {None, ASI[row.identity.category]}:
            raise AggregationError("Contradictory taxonomy claims.")
        key = (row.report_kind, digest)
        if key in unique and unique[key].model_dump(mode="json") != row.model_dump(mode="json"):
            raise AggregationError("Conflicting projections of the same source bytes; select one representation explicitly.")
        unique[key] = row
    rows = [unique[key] for key in sorted(unique)]
    executions = [r for r in rows if isinstance(r, ExecutionReport)]
    assessments = [r for r in rows if isinstance(r, ArchivedAssessmentReport)]
    counts = _counts(executions)
    production = [_entry(r, r.deterministic.original.status if r.deterministic.original else None) for r in executions]
    archived, linked = [], Counter()
    for row in assessments:
        execution, state = _link(row, executions)
        rule = execution.deterministic.original.status if execution and execution.deterministic.original else None
        archived.append(_entry(row, rule, linkage=state, parent=execution.source.file_byte_sha256 if execution else None))
        if state == "matched_selected_source":
            linked[execution.source.file_byte_sha256] += 1
    groups = {}
    for name, getter in {
        "asi_category": lambda r: r.identity.asi_category,
        "target_id": lambda r: r.identity.target_id,
        "testcase_id": lambda r: r.identity.testcase_id,
        "security_verdict": lambda r: r.security.verdict,
        "evidence_verification_state": _artifact_state,
    }.items():
        keys = {getter(r) for r in executions}
        groups[name] = [Group(key=Redactor().identifier(key), counts=_counts([r for r in executions if getter(r) == key]))
                        for key in sorted(keys, key=lambda v: (v is not None, v or ""))]
    p = _counter((r.state for r in production), COMPARISON_STATES)
    a = _counter((r.state for r in archived), COMPARISON_STATES)
    security = counts.security_verdicts
    n_sec = security["PASS"] + security["FAIL"] + security["INCONCLUSIVE"]
    id_counts = Counter(r.execution_id for r in executions if r.execution_id is not None)
    canonical = json.dumps([r.model_dump(mode="json") for r in rows], sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return AggregationSummary(snapshot_sha256=hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        selected_input_records=len(selected), duplicate_inputs_removed=len(selected) - len(rows),
        unique_execution_sources=[r.source.file_byte_sha256 for r in executions], unique_assessment_sources=[r.source.file_byte_sha256 for r in assessments],
        execution_identity_conflicts=sum(n > 1 for n in id_counts.values()), archived_assessments=len(assessments),
        executions_without_linked_crosscheck=len(executions) - len(linked),
        executions_with_multiple_linked_assessments=sum(n > 1 for n in linked.values()), counts=counts, groups=groups,
        metrics=Metrics(
            decision_coverage=_rate(security["PASS"] + security["FAIL"], n_sec, "Deprecated compatibility alias for decisive_verdict_rate_among_classified; unknown excluded and disclosed in counts."),
            decisive_verdict_rate_among_classified=_rate(security["PASS"] + security["FAIL"], n_sec, "Historical PASS+FAIL / historical PASS+FAIL+INCONCLUSIVE; unknown excluded and disclosed in counts."),
            decision_coverage_over_all_records=_rate(security["PASS"] + security["FAIL"], len(executions), "Historical PASS+FAIL / all selected execution records, including unknown, technical-error, skipped and incomplete records; no eligibility exclusions."),
            evidence_coverage=_rate(None, len(executions), "Unavailable: schema has no all-ASI evidence-sufficiency contract. Denominator is selected execution records, not confirmed applicable invocations."),
            verified_artifact_coverage=_rate(counts.evidence_file_integrity_states["verified"], len(executions), "Records with supplied verified four-file metadata bound to execution source SHA256 / all selected execution records; no re-verification by aggregation."),
            production_judge_comparison_coverage=_rate(p["agreement"] + p["disagreement"], len(executions), "Comparable production pairs / all selected execution records, including skipped/not-requested/unavailable."),
            archived_judge_comparison_coverage=_rate(a["agreement"] + a["disagreement"], len(assessments), "Comparable linked archived pairs / all selected unique assessments, including unlinked and unavailable; no favorable-result selection.")),
        production_comparison_counts=p, archived_comparison_counts=a,
        archived_reported_comparison_claims=_counter((r.comparison.reported_status or "not_recorded" for r in assessments), ("agreement", "disagreement", "unavailable", "not_recorded")),
        assessment_linkage_counts=_counter((r.linkage for r in archived), LINKAGE_STATES), comparisons=production + archived,
        source_limitations=sorted({Redactor().clean(text) for row in rows for text in row.limitations + row.normalization_notes
                                   + (row.artifact_verification.limitations if row.artifact_verification else [])}))

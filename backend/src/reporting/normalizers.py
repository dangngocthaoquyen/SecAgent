"""Pure historical projections. No evaluator, target, provider or archive verifier imports."""
from datetime import datetime
import hashlib
import json
from pathlib import Path

from pydantic import ValidationError

from reporting.models import (
    ArchivedAssessmentReport, Citation, Comparison, Completeness, Context, DeterministicResult,
    ExecutionReport, ExecutionState, HistoricalIntegrityClaims, HistoricalResult, HistoricalSecurity, HumanReference,
    Identity, Judge, Observation, ParentExecution, ReportedEvidence, SourceReport, TechnicalError, Verification,
)
from reporting.redaction import Redactor

MAX_BYTES = 10 * 1024 * 1024
ASI = {"goal_hijacking": "ASI01", "tool_misuse": "ASI02", "identity_privilege_abuse": "ASI03", "unexpected_code_execution": "ASI05"}
STATUSES = {"PASS", "FAIL", "INCONCLUSIVE", "ERROR"}
DETAILS = {"scope", "completeness", "finish_reason", "declared_tool_call_count", "tool_calls_truncated",
    "webFetchAttempted", "webFetchExecuted", "webFetchUrl", "webFetchSource", "error_present", "error_category",
    "httpPostAttempted", "httpPostExecuted", "injectionKind", "destination_id", "run_id", "result_ok", "result_status_code",
    "collector_id", "condition", "correlation_valid", "page_served", "receipt_count", "observation_complete",
    "manifest_sha256", "log_sha256", "observed_method", "receipt_timestamp", "status"}


class NormalizationError(ValueError):
    """Unsupported or malformed source; no raw input is included in messages."""


def _object(value):
    if not isinstance(value, dict):
        raise NormalizationError("Expected a report object.")
    return value


def _optional_object(value):
    return {} if value is None else _object(value)


def _bool(value):
    if value is not None and type(value) is not bool:
        raise NormalizationError("Invalid report boolean.")
    return value


def _status(value):
    if value is not None and (not isinstance(value, str) or value not in STATUSES):
        raise NormalizationError("Unsupported historical status.")
    return value


def _identifier(value, redact):
    if value is not None and (not isinstance(value, str) or not value.strip() or len(value) > 256):
        raise NormalizationError("Invalid source identity.")
    return redact.identifier(value, limit=256)


def _time(value, notes, field):
    if value is None: return None
    if not isinstance(value, str): raise NormalizationError("Invalid source timestamp type.")
    try:
        if datetime.fromisoformat(value).tzinfo is not None: return value
    except ValueError:
        pass
    notes.append("Timestamp unavailable or lacks timezone: " + field)
    return None


def _result(value, r):
    if value is None: return None
    value = _object(value)
    return HistoricalResult(status=_status(value.get("status")), reason=r.clean(value.get("reason")),
        evidence_preview=r.clean(value.get("evidence")), matched_rule_id=_identifier(value.get("matched_rule_id"), r),
        matched_rule_type=_identifier(value.get("matched_rule_type"), r), reported_passed=_bool(value.get("passed")))


def _security(status, reason=None, *, partial=False):
    return HistoricalSecurity(historical_status=status, verdict=status if status in {"PASS", "FAIL", "INCONCLUSIVE"} and not partial else None,
        decisiveness="unknown" if partial or status is None else "technical_error" if status == "ERROR" else
            "inconclusive" if status == "INCONCLUSIVE" else "decisive", reason=reason)


def _identity(outer, nested, r, notes):
    if outer.get("category") is not None and nested.get("category") is not None and outer["category"] != nested["category"]:
        raise NormalizationError("Conflicting report categories.")
    def pick(key):
        a, b = outer.get(key), nested.get(key)
        if a is not None and b is not None and a != b:
            raise NormalizationError("Conflicting report identities.")
        value = a if a is not None else b
        if value is None: notes.append("Missing source identity: " + key)
        return _identifier(value, r)
    category = pick("category")
    explicit = pick("asi_category")
    if explicit is not None and category in ASI and explicit != ASI[category]:
        raise NormalizationError("Conflicting category and ASI taxonomy claims.")
    asi = explicit if explicit is not None else ASI.get(category)
    adapter = _identifier(outer.get("adapter", nested.get("adapter")), r)
    protocol = outer.get("protocol", nested.get("protocol", "unknown"))
    # generic_http alone does not prove the OpenAI chat-completions protocol.
    if protocol == "unknown" and adapter == "generic_mcp_jsonrpc": protocol = "mcp_jsonrpc_http"
    return Identity(testcase_id=pick("testcase_id"), target_id=pick("target_id"),
        target_label=r.clean(nested.get("target_name")), adapter=adapter, protocol=protocol,
        category=category, asi_category=asi, taxonomy_basis="source_claim" if explicit else "category_mapping" if asi else "unknown")


def _execution(value, r, notes):
    value = _optional_object(value)
    success = _bool(value.get("success"))
    explicit_status = value.get("status")
    status = explicit_status if explicit_status is not None else "unknown" if success is None else "succeeded" if success else "failed"
    if type(value.get("duration_ms")) is bool: raise NormalizationError("Invalid duration.")
    return ExecutionState(status=status, planned=_bool(value.get("planned")), attempted=_bool(value.get("attempted")),
        confirmed_target_invocation=_bool(value.get("confirmed_target_invocation")), reported_success=success,
        reported_response_complete=_bool(value.get("response_complete")),
        status_basis="source_claim" if value else "unavailable", http_status=value.get("status_code"),
        duration_ms=value.get("duration_ms"), started_at=_time(value.get("started_at"), notes, "execution.started_at"),
        ended_at=_time(value.get("ended_at"), notes, "execution.ended_at"))


def _observation(value, r):
    value = _optional_object(value)
    text = value.get("response_text")
    clean_full = r.clean(text, limit=MAX_BYTES)
    clean = clean_full[:4096] if clean_full is not None else None
    rows = value.get("evidence", [])
    if not isinstance(rows, list) or len(rows) > 1000:
        raise NormalizationError("Invalid evidence list.")
    evidence, scopes = [], []
    for index, row in enumerate(rows):
        row = _object(row)
        data = _optional_object(row.get("data"))
        details = {}
        for key in sorted(DETAILS & data.keys()):
            v = data[key]
            if v is None or type(v) in {bool, int, float}:
                details[key] = v
            elif isinstance(v, str):
                details[key] = r.identifier(v) if key in {"run_id", "collector_id", "destination_id"} else r.clean(v, opaque=False)
            # Never retain nested arguments, raw result bodies or headers.
        kind = _identifier(row.get("kind"), r)
        source = _identifier(row.get("source"), r)
        if kind is None or source is None: raise NormalizationError("Evidence kind/source missing.")
        item = ReportedEvidence(id=f"evidence-{index}", kind=kind, reported_source=source,
            reported_provenance=r.clean(data.get("provenance")), name=r.identifier(row.get("name")),
            source_reference=r.identifier(row.get("reference")), reported_success=_bool(row.get("success")), details=details,
            verification=Verification(reported_status=r.clean(data.get("verification_status")),
                reported_execution_verified=_bool(data.get("execution_verified"))))
        evidence.append(item)
        if isinstance(data.get("scope"), str) and isinstance(data.get("completeness"), str):
            scopes.append({"scope": r.clean(data["scope"]), "reported_completeness": r.clean(data["completeness"]), "evidence_id": item.id})
    complete = _bool(value.get("response_complete"))
    return Observation(response_preview=clean, preview_redacted=clean_full != text,
        preview_truncated=isinstance(clean_full, str) and len(clean_full) > 4096,
        evidence=evidence, response_completeness=Completeness(
            state="unknown" if complete is None else "complete" if complete else "partial",
            reported_value=complete, source_field_present="response_complete" in value, reported_scopes=scopes))


def _judge(value, r, *, archived=False, mode=None, deterministic=None, semantic_enabled=None):
    row = _optional_object(value)
    result = _optional_object(row.get("validated_response")) if archived else row
    if archived and any(row.get(key) is not None and result.get(other) is not None and row[key] != result[other]
                        for key, other in (("classification", "classification"), ("recommendation", "verdict"))):
        raise NormalizationError("Conflicting historical Judge fields.")
    classification = row.get("classification") if row.get("classification") is not None else result.get("classification")
    recommendation = _status(row.get("recommendation") if row.get("recommendation") is not None else result.get("verdict"))
    fault = row.get("provider_fault_code")
    validation = row.get("json_validation_status")
    semantic = _bool(row.get("semantic_invoked"))
    provider_invoked = _bool(row.get("invoked")) if archived else _bool(row.get("provider_invoked"))
    state, reason = "unknown", None
    if fault in {"judge_disabled", "budget_exhausted", "skill_unavailable", "skill_mismatch"}:
        state, reason = "prevented", fault
    elif fault is not None:
        state, reason = "attempted_failed", fault
    elif validation == "valid" and classification is not None and recommendation is not None:
        state = "result_available"
    elif not archived and semantic is False and deterministic in {"PASS", "FAIL"}:
        state, reason = "skipped_decisive", "legacy_rule_first_diagnostic"
    elif not archived and (mode == "rule_only" or semantic_enabled is False):
        state, reason = "not_requested", "rule_only_or_semantic_disabled"
    elif validation in {"invalid", "provider_fault"}:
        state, reason = "attempted_failed", "invalid_or_unavailable_result"
    citations = result.get("evidence", []) if archived else row.get("judge_evidence", [])
    if not isinstance(citations, list): raise NormalizationError("Invalid citations.")
    confidence = result.get("confidence") if archived else row.get("confidence")
    if type(confidence) is bool: raise NormalizationError("Invalid confidence.")
    return Judge(mode="archived_research" if archived else "production_fallback", invocation_state=state,
        reason=reason, reported_semantic_invoked=semantic, reported_provider_invoked=provider_invoked,
        provider=r.clean(row.get("provider")), model=r.clean(row.get("model")), classification=r.clean(classification),
        recommendation=recommendation, explanation=r.clean(result.get("reason") if archived else row.get("judge_reason")),
        reported_confidence=confidence, reported_json_validation_status=r.clean(validation), provider_fault_code=r.clean(fault),
        provider_exit_code=row.get("provider_exit_code"), provider_duration_ms=row.get("provider_duration_ms"),
        request_canonical_sha256=row.get("request_sha256"), skill_version=r.clean(row.get("skill_version")),
        skill_sha256=row.get("skill_sha256"), downgrade_reason=r.clean(row.get("downgrade_reason")),
        citations=[Citation(type=_object(c)["type"], value_preview=r.clean(c.get("value"))) for c in citations])


def _comparison(judge, deterministic, row=None):
    row = _optional_object(row)
    status = row.get("status")
    if status not in {None, "agreement", "disagreement", "unavailable"}: raise NormalizationError("Invalid comparison status.")
    if _bool(row.get("original_final_verdict_overridden")) is True:
        raise NormalizationError("Archived assessment claims to override historical verdict.")
    comparable = judge.invocation_state == "result_available" and deterministic in {"PASS", "FAIL"} and judge.recommendation in {"PASS", "FAIL"}
    inconsistent = comparable and status in {"agreement", "disagreement"} and (
        (deterministic == judge.recommendation) != (status == "agreement"))
    if inconsistent:
        state, reason = "unknown", "Contradictory historical comparison claim; no verdict was recalculated."
    elif status == "unavailable" and judge.invocation_state == "result_available":
        state, reason = "valid_not_comparable", "Historical source marks comparison unavailable despite a reported valid result."
    elif comparable:
        state = "comparable_" + status if status in {"agreement", "disagreement"} else "comparable_not_recorded"
        reason = None if status in {"agreement", "disagreement"} else "Comparable fields exist; no comparison is recorded."
    elif judge.invocation_state == "result_available":
        state, reason = "valid_not_comparable", "Reported Judge result is not a comparable binary verdict pair."
    else:
        state = judge.invocation_state if judge.invocation_state in {"not_requested", "skipped_decisive", "prevented", "attempted_failed"} else "unknown"
        reason = judge.reason
    return Comparison(state=state, reported_status=status, basis="source_reported" if status else "not_recorded", reason=reason, source_inconsistent=inconsistent)


def _context(value, r):
    if not value: return Context()
    value = _object(value)
    return Context(legitimate_goal=r.clean(value.get("original_goal")), attacker_goal=r.clean(value.get("attacker_goal")),
        trust_boundary=r.clean(value.get("trust_boundary")), attack_entry_point=r.clean(value.get("attack_surface")), origin="source_report_claim")


def _limitations(value, r):
    if value is None: return []
    if isinstance(value, list): return [r.clean(v) for v in value]
    if isinstance(value, dict): return [key + ": " + r.clean(value[key]) for key in (
        "scope", "attack_surface", "trust_boundary", "actual_lower_trust_boundary", "completeness") if isinstance(value.get(key), str)]
    raise NormalizationError("Invalid limitations.")


def _human(value, r):
    row = _optional_object(value)
    return HumanReference(status=row.get("status", "unavailable"), label=r.clean(row.get("label")),
        reviewer_ref=r.clean(row.get("reviewer_ref")), verification_basis=r.clean(row.get("verification_basis")))


def _native(document, source, r):
    notes = ["Historical verdict projection only; evidence verification and completeness claims were not independently repeated."]
    e = _optional_object(document.get("evaluation"))
    partial = not e
    identity = _identity(document, e, r, notes)
    execution = _execution(e.get("execution"), r, notes)
    deterministic = _result(e.get("deterministic_result"), r)
    final = _result(e.get("final_result"), r)
    statuses = [_status(v) for v in (e.get("final_verdict"), final.status if final else None, document.get("evaluation_status"), document.get("final_verdict")) if v is not None]
    if len(set(statuses)) > 1: raise NormalizationError("Conflicting historical final verdicts.")
    status = statuses[0] if statuses else None
    judge_row = _optional_object(e.get("judge"))
    effective = _result(judge_row.get("effective_deterministic_result"), r)
    judge = _judge(e.get("judge"), r, mode=e.get("evaluation_mode"),
        deterministic=effective.status if effective else deterministic.status if deterministic else None,
        semantic_enabled=_bool(e.get("semantic_enabled")))
    errors = []
    if status == "ERROR": errors.append(TechnicalError(stage="execution" if execution.reported_success is False else "unknown", code="legacy_error", safe_message=final.reason if final else None))
    if document.get("report_fault") is not None:
        errors.append(TechnicalError(stage="report", code="report_fault", safe_message=r.clean(document["report_fault"])))
    if judge.provider_fault_code:
        errors.append(TechnicalError(stage="judge", code="judge_status", safe_message=judge.provider_fault_code))
    execution_id = _identifier(e.get("run_id"), r)
    if execution_id is None: notes.append("Execution identity unavailable; report_id identifies source bytes only.")
    if partial: notes.append("Partial/report_fault record: retain status as a historical claim, without assigning a security verdict.")
    observation = _observation(e.get("observation"), r)
    if execution.reported_response_complete != observation.response_completeness.reported_value:
        notes.append("Execution and observation completeness claims differ; neither was promoted or independently verified.")
    context = _context(e.get("evidence_limitations"), r)
    return ExecutionReport(report_id="execution:" + source.file_byte_sha256, source=source, identity=identity,
        execution_id=execution_id, record_status="partial" if document.get("report_fault") is not None or partial or execution_id is None or e.get("execution") is None or e.get("observation") is None else "complete", execution=execution,
        reported_wrapper_execution_success=_bool(document.get("smoke_execution_succeeded")),
        original_execution_result=execution if e.get("execution") is not None else None,
        source_reported_at=_time(e.get("timestamp", document.get("timestamp")), notes, "report.timestamp"),
        context=context, deterministic=DeterministicResult(original=deterministic,
            baseline=_result(judge_row.get("deterministic_result"), r), effective=effective),
        original_final_result=final, security=_security(status, final.reason if final else None, partial=partial),
        observation=observation, judge=judge,
        comparison=_comparison(judge, deterministic.status if deterministic else None),
        human_reference=_human(document.get("human_reference"), r),
        technical_errors=errors, limitations=_limitations(e.get("evidence_limitations"), r), normalization_notes=notes)


def _archived(document, source, r):
    if document.get("target_execution_performed") is not False:
        raise NormalizationError("Archived assessment must explicitly declare no target execution.")
    original, judge_row, comparison = (_object(document.get(k)) for k in ("original", "judge", "comparison"))
    notes = ["Parent report, archive hashes and evidence verification claims were not independently checked or joined."]
    identity = _identity({}, original, r, notes)
    request = _optional_object(document.get("judge_request"))
    skill = _optional_object(request.get("skill"))
    judge_fields = {**judge_row}
    judge_fields.setdefault("request_sha256", document.get("judge_request_canonical_sha256"))
    judge_fields.setdefault("skill_version", skill.get("version"))
    judge_fields.setdefault("skill_sha256", skill.get("sha256"))
    judge = _judge(judge_fields, r, archived=True)
    request_observation = _optional_object(request.get("observation"))
    metadata = _optional_object(request_observation.get("metadata"))
    observation = _observation({**request_observation, **({"response_complete": metadata["response_complete"]} if "response_complete" in metadata else {})}, r)
    parent = ParentExecution(execution_id=_identifier(original.get("secagent_run_id"), r),
        report_file_byte_sha256=original.get("report_file_byte_sha256"), fixture_correlation_id=_identifier(original.get("fixture_correlation_id"), r),
        deterministic_verdict=_status(original.get("deterministic_verdict")), original_verdict_snapshot=_status(original.get("final_verdict")),
        reported_response_complete=_bool(original.get("response_complete")),
        matched_rule_id=_identifier(original.get("matched_rule_id"), r))
    errors = [TechnicalError(stage="judge", code="judge_status", safe_message=judge.provider_fault_code)] if judge.provider_fault_code else []
    provenance = _optional_object(document.get("provenance"))
    digests = _optional_object(provenance.get("collector_digests"))
    integrity = HistoricalIntegrityClaims(inventory_file_byte_sha256=provenance.get("inventory_file_byte_sha256"),
        testcase_file_byte_sha256=provenance.get("testcase_file_byte_sha256"),
        collector_manifest_file_byte_sha256=digests.get("manifest_file_byte_sha256"),
        collector_events_file_byte_sha256=digests.get("events_jsonl_file_byte_sha256"),
        collector_log_canonical_json_sha256=digests.get("collector_log_canonical_json_sha256"),
        collector_serialization=r.clean(digests.get("canonicalization")))
    return ArchivedAssessmentReport(report_id="assessment:" + source.file_byte_sha256, source=source, identity=identity,
        source_execution=parent, judge=judge, comparison=_comparison(judge, parent.deterministic_verdict, comparison),
        reported_archive_integrity_unchanged=_bool(document.get("archive_integrity_unchanged_after_assessment")),
        observation=observation, context=_context(request.get("trusted_context"), r), technical_errors=errors,
        source_reported_at=_time(document.get("created_at"), notes, "assessment.created_at"),
        limitations=_limitations(document.get("limitations"), r), historical_integrity=integrity, normalization_notes=notes)


def normalize_report_bytes(raw: bytes, *, redact_values=()):
    """Normalize source bytes only; deterministic for the same bytes/redaction values."""
    if not isinstance(raw, bytes) or len(raw) > MAX_BYTES:
        raise NormalizationError("Expected bounded source bytes.")
    def pairs(items):
        row = {}
        for key, value in items:
            if key in row: raise NormalizationError("Duplicate JSON key.")
            row[key] = value
        return row
    def nonfinite(_): raise NormalizationError("Nonfinite JSON number.")
    try:
        document = _object(json.loads(raw.decode("utf-8-sig"), object_pairs_hook=pairs, parse_constant=nonfinite))
        native = document.get("engine") == "native"
        archived = document.get("report_type") == "archived_hybrid_cross_check"
        minimal = set(document) <= {"final_verdict", "report_fault", "report_sink_fault"} and "report_fault" in document
        if (native and archived) or "report_schema_version" in document or (
                (native or archived) and any(key in document for key in ("tool_name", "gradingResult"))):
            raise NormalizationError("Ambiguous or unsupported source format.")
        if "report_type" in document and not archived:
            raise NormalizationError("Unsupported source report type.")
        if archived:
            if document.get("schema_version") != "1.0": raise NormalizationError("Unsupported archived schema version.")
            format_name = "archived_crosscheck_v1"
        elif native or minimal:
            if document.get("schema_version") is not None: raise NormalizationError("Unsupported native source version.")
            format_name = "native_legacy" if document.get("evaluation") else "native_partial"
        else:
            raise NormalizationError("Unsupported source format; filename suffix is not sufficient.")
        digest = hashlib.sha256(raw).hexdigest()
        provenance = document.get("source_provenance") if native else None
        if provenance not in {None, "synthetic_mock"}:
            raise NormalizationError("Unsupported source provenance claim.")
        source = SourceReport(format=format_name, identity="sha256:" + digest,
            file_byte_sha256=digest, reported_provenance=provenance)
        return (_archived if archived else _native)(document, source, Redactor(redact_values))
    except NormalizationError:
        raise
    except (ValueError, TypeError, KeyError, UnicodeError, ValidationError) as exc:
        raise NormalizationError("Malformed source report fields.") from exc


def normalize_report_file(path: str | Path, *, redact_values=()):
    path = Path(path)
    if not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise NormalizationError("Missing or oversized source file.")
    with path.open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    return normalize_report_bytes(raw, redact_values=redact_values)


def normalize_native_report(raw: bytes, *, redact_values=()):
    report = normalize_report_bytes(raw, redact_values=redact_values)
    if not isinstance(report, ExecutionReport): raise NormalizationError("Expected native execution source.")
    return report


def normalize_archived_assessment(raw: bytes, *, redact_values=()):
    report = normalize_report_bytes(raw, redact_values=redact_values)
    if not isinstance(report, ArchivedAssessmentReport): raise NormalizationError("Expected archived assessment source.")
    return report

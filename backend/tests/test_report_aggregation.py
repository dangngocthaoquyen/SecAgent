"""Synthetic Phase 2C.1 input selections, no dependence on results/ archives."""
import copy
import hashlib
import json
from pathlib import Path
import socket
import subprocess

import httpx
import pytest

from reporting import normalize_report_bytes
from reporting.aggregate import main
from reporting.aggregation import AggregationError, aggregate_reports
from reporting.models import ArchiveVerification, ArtifactCheck

FIXTURES = Path(__file__).parent / "fixtures/reporting"


@pytest.fixture(autouse=True)
def no_execution_or_network(monkeypatch):
    def blocked(*a, **k): raise AssertionError("Aggregation is read-only and offline")
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(httpx.Client, "request", blocked)
    monkeypatch.setattr(subprocess, "Popen", blocked)


def native(verdict="FAIL", *, run="run-1", testcase="GH-WEB-001", target="synthetic-researchbot", category="goal_hijacking", **execution):
    row = json.loads((FIXTURES / "native-fail.json").read_text(encoding="utf-8"))
    row.update(testcase_id=testcase, target_id=target, category=category)
    e = row["evaluation"]
    e.update(run_id=run, testcase_id=testcase, target_id=target, final_verdict=verdict)
    row["evaluation_status"] = verdict
    for key in ("final_result", "deterministic_result"):
        e[key]["status"] = verdict
    e["execution"].update(execution)
    return row


def norm(row):
    return normalize_report_bytes(json.dumps(row).encode())


def archived(parent, recommendation="FAIL", *, nonce="1", **original):
    row = json.loads((FIXTURES / "archived-agreement.json").read_text(encoding="utf-8"))
    row["created_at"] = "2026-11-07T02:30:0" + nonce + "Z"
    row["original"].update(secagent_run_id=parent.execution_id,
        report_file_byte_sha256=parent.source.file_byte_sha256,
        testcase_id=parent.identity.testcase_id, target_id=parent.identity.target_id,
        deterministic_verdict=parent.deterministic.original.status,
        final_verdict=parent.security.historical_status, **original)
    row["judge"]["recommendation"] = recommendation
    row["judge"]["validated_response"]["verdict"] = recommendation
    classification = "ORIGINAL_GOAL" if recommendation == "PASS" else "ATTACKER_GOAL"
    row["judge"]["classification"] = row["judge"]["validated_response"]["classification"] = classification
    row["comparison"]["status"] = "agreement" if recommendation == parent.deterministic.original.status else "disagreement"
    return row


def metadata(parent, state="verified"):
    checks = [ArtifactCheck(artifact_role=role, state="verified", expected_file_byte_sha256=digest,
                            actual_file_byte_sha256=digest, size_bytes=1) for role, digest in (
        ("manifest", "a" * 64), ("events", "b" * 64), ("collector_export", "c" * 64),
        ("execution", parent.source.file_byte_sha256))]
    return ArchiveVerification(file_integrity=state, artifacts=checks,
        internal_evidence_consistency="verified", receipt_count=1)


def test_security_counts_and_decision_denominator_preserve_unknown():
    reports = [norm(native(verdict, run=str(i))) for i, verdict in enumerate(["PASS", "FAIL", "INCONCLUSIVE", "ERROR"])]
    summary = aggregate_reports(reports)
    assert summary.counts.security_verdicts == {"PASS": 1, "FAIL": 1, "INCONCLUSIVE": 1, "unknown": 1}
    assert summary.metrics.decision_coverage.numerator == 2
    assert summary.metrics.decision_coverage.denominator == 3
    assert summary.metrics.decision_coverage.value == 2 / 3
    assert summary.counts.records_with_technical_errors >= 1


def test_multiple_runs_targets_asi_and_distinct_definitions_remain_unknown():
    rows = [norm(native(run="a")), norm(native(run="b")), norm(native(run="c", target="other")),
        norm(native(run="d", testcase="TM-001", category="tool_misuse")),
        norm(native(run="e", testcase="IP-001", category="identity_privilege_abuse")),
        norm(native(run="f", testcase="CE-001", category="unexpected_code_execution"))]
    result = aggregate_reports(rows)
    assert result.counts.recorded_execution_reports == 6
    assert result.counts.distinct_testcase_ids == 4
    assert result.counts.distinct_testcase_definitions is None
    assert result.counts.records_without_definition_identity == 6
    assert len(result.groups["target_id"]) == 2
    assert {g.key for g in result.groups["asi_category"]} == {"ASI01", "ASI02", "ASI03", "ASI05"}


def test_known_definition_revisions_not_merged_by_testcase_id():
    p = norm(native())
    a = p.model_copy(update={"historical_integrity": p.historical_integrity.model_copy(update={"testcase_file_byte_sha256": "a" * 64})})
    q = norm(native(run="other"))
    b = q.model_copy(update={"historical_integrity": q.historical_integrity.model_copy(update={"testcase_file_byte_sha256": "b" * 64})})
    result = aggregate_reports([a, b])
    assert result.counts.distinct_testcase_definitions == 2
    assert result.counts.distinct_testcase_ids == 1


def test_dedup_exact_sources_not_same_testcase_and_stable_order():
    a, b = norm(native()), norm(native(run="other"))
    result = aggregate_reports([a, a, b])
    assert result.duplicate_inputs_removed == 1
    assert result.counts.recorded_execution_reports == 2
    assert result.model_dump() == aggregate_reports([b, a, a]).model_dump()
    assert result.snapshot_sha256 == aggregate_reports([a, b]).snapshot_sha256


def test_conflicting_same_source_projections_are_rejected():
    a = norm(native())
    b = a.model_copy(update={"artifact_verification": metadata(a)})
    with pytest.raises(AggregationError, match="Conflicting projections"): aggregate_reports([a, b])


def test_same_execution_id_with_changed_bytes_flagged_not_silently_merged():
    a = norm(native("FAIL"))
    b = norm(native("INCONCLUSIVE"))
    result = aggregate_reports([a, b])
    assert result.execution_identity_conflicts == 1
    assert result.counts.recorded_execution_reports == 2


def test_assessments_not_executions_and_all_conflicting_judges_counted():
    parent = norm(native())
    a, b = norm(archived(parent)), norm(archived(parent, "PASS", nonce="2"))
    result = aggregate_reports([parent, a, b, a])
    assert result.archived_assessments == 2
    assert result.duplicate_inputs_removed == 1
    assert result.counts.recorded_execution_reports == 1
    assert result.counts.security_verdicts["FAIL"] == 1
    assert result.archived_comparison_counts["agreement"] == result.archived_comparison_counts["disagreement"] == 1
    assert result.archived_reported_comparison_claims["agreement"] == 1
    assert result.executions_with_multiple_linked_assessments == 1
    assert result.metrics.archived_judge_comparison_coverage.value == 1


@pytest.mark.parametrize("mutation,state", [("hash", "parent_hash_mismatch"), ("id", "parent_id_mismatch"),
    ("missing_identity", "unverified_parent_linkage"), ("missing", "missing_parent_execution")])
def test_parent_link_requires_execution_id_and_hash(mutation, state):
    parent = norm(native())
    row = archived(parent)
    if mutation == "hash": row["original"]["report_file_byte_sha256"] = "d" * 64
    elif mutation == "id": row["original"]["secagent_run_id"] = "wrong"
    elif mutation == "missing_identity": row["original"]["secagent_run_id"] = None
    assessment = norm(row)
    result = aggregate_reports([assessment] if mutation == "missing" else [parent, assessment])
    assert result.assessment_linkage_counts[state] == 1
    assert result.archived_comparison_counts["agreement"] == 0
    assert result.archived_reported_comparison_claims["agreement"] == 1


def test_archive_verifier_mismatch_blocks_comparison():
    parent = norm(native())
    a = norm(archived(parent))
    a = a.model_copy(update={"artifact_verification": ArchiveVerification(crosscheck_linkage="mismatch")})
    result = aggregate_reports([parent, a])
    assert result.assessment_linkage_counts["verification_mismatch"] == 1


def test_snapshot_claim_conflict_blocks_comparison():
    parent = norm(native())
    row = archived(parent)
    row["original"]["final_verdict"] = "PASS"
    result = aggregate_reports([parent, norm(row)])
    assert result.assessment_linkage_counts["snapshot_mismatch"] == 1


@pytest.mark.parametrize("change,state", [
    ({"provider_fault_code": "timeout", "json_validation_status": "provider_fault"}, "judge_unavailable_or_failed"),
    ({"json_validation_status": "invalid"}, "judge_unavailable_or_failed"),
    ({"provider_fault_code": "budget_exhausted"}, "prevented")])
def test_judge_faults_are_not_disagreements(change, state):
    parent = norm(native())
    row = archived(parent)
    row["judge"].update(change)
    result = aggregate_reports([parent, norm(row)])
    assert result.archived_comparison_counts[state] == 1
    assert result.archived_comparison_counts["disagreement"] == 0
    assert result.counts.execution_errors == 0


def test_rule_skipped_not_requested_missing_crosscheck():
    a = native()
    b = native("INCONCLUSIVE", run="other")
    b["evaluation"].update(evaluation_mode="rule_only", semantic_enabled=False)
    b["evaluation"]["judge"] = {"semantic_invoked": False}
    result = aggregate_reports([norm(a), norm(b)])
    assert result.production_comparison_counts["skipped_decisive"] == 1
    assert result.production_comparison_counts["not_requested"] == 1
    assert result.executions_without_linked_crosscheck == 2
    assert result.production_comparison_counts["disagreement"] == 0


def test_valid_unclear_result_not_comparable():
    parent = norm(native())
    row = archived(parent)
    row["judge"]["classification"] = row["judge"]["validated_response"]["classification"] = "UNCLEAR"
    row["judge"]["recommendation"] = row["judge"]["validated_response"]["verdict"] = "INCONCLUSIVE"
    row["comparison"]["status"] = "unavailable"
    result = aggregate_reports([parent, norm(row)])
    assert result.archived_comparison_counts["valid_not_comparable"] == 1


def test_failed_execution_does_not_imply_attempt_or_invocation():
    a = norm(native("ERROR", success=False))
    b = norm(native(run="b", attempted=True, confirmed_target_invocation=True))
    result = aggregate_reports([a, b])
    assert result.counts.execution_errors == 1
    assert result.counts.recorded_execution_attempts.reported_true == 1
    assert result.counts.recorded_execution_attempts.unknown == 1
    assert result.counts.confirmed_target_invocations.total_if_fully_known is None
    assert result.counts.confirmed_target_invocations.reported_true == 1


def test_response_completeness_not_evidence_or_artifact_coverage():
    a = norm(native())
    result = aggregate_reports([a])
    assert result.counts.response_completeness["unknown"] == 1
    assert result.metrics.evidence_coverage.numerator is None
    assert result.metrics.evidence_coverage.value is None
    assert result.metrics.evidence_coverage.status == "unavailable_contract"
    assert result.metrics.verified_artifact_coverage.value == 0


def test_bound_verified_artifact_metadata_counted_separately():
    a, b = norm(native()), norm(native(run="b"))
    a = a.model_copy(update={"artifact_verification": metadata(a)})
    result = aggregate_reports([a, b])
    assert result.metrics.verified_artifact_coverage.numerator == 1
    assert result.metrics.verified_artifact_coverage.denominator == 2
    assert result.counts.local_consistency_verified_records == 1
    assert result.counts.locally_consistent_callback_records == 1
    assert result.aggregation_performed_archive_verification is False


def test_bare_verified_claim_not_counted_as_verified_coverage():
    a = norm(native())
    a = a.model_copy(update={"artifact_verification": ArchiveVerification(file_integrity="verified")})
    result = aggregate_reports([a])
    assert result.counts.evidence_file_integrity_states["unsupported"] == 1
    assert result.metrics.verified_artifact_coverage.numerator == 0


def test_metadata_bound_to_another_source_is_mismatch():
    a, b = norm(native()), norm(native(run="b"))
    a = a.model_copy(update={"artifact_verification": metadata(b)})
    result = aggregate_reports([a])
    assert result.counts.evidence_file_integrity_states["mismatch"] == 1


def test_empty_selection_zero_denominators_are_unavailable():
    result = aggregate_reports([])
    for metric in result.metrics.model_dump().values():
        assert metric["denominator"] == 0 and metric["value"] is None
    assert result.counts.distinct_testcase_definitions == 0
    assert result.counts.recorded_execution_reports == 0


def test_no_reference_labels_no_accuracy_claim_and_no_mutation():
    a = norm(native())
    before = copy.deepcopy(a.model_dump())
    result = aggregate_reports([a])
    assert result.counts.human_reference_statuses["unavailable"] == 1
    assert a.model_dump() == before
    assert result.historical_verdicts_modified is False
    assert not {"accuracy", "precision", "recall", "defense_success_rate"} & result.model_dump().keys()


def test_unsupported_input_and_forged_source_identity_rejected():
    with pytest.raises(AggregationError): aggregate_reports([{}])
    a = norm(native())
    with pytest.raises(AggregationError):
        aggregate_reports([a.model_copy(update={"source": a.source.model_copy(update={"identity": "not-a-verified-source"})})])
    with pytest.raises(AggregationError):
        aggregate_reports([a.model_copy(update={"identity": a.identity.model_copy(update={"asi_category": "ASI05"})})])


def test_unknown_asi_not_inferred_by_aggregator():
    a = norm(native())
    a = a.model_copy(update={"identity": a.identity.model_copy(update={"category": "unsupported", "asi_category": None})})
    assert aggregate_reports([a]).groups["asi_category"][0].key is None


def test_cli_explicit_files_duplicate_sources_and_unchanged_inputs(tmp_path, capsys):
    path = tmp_path / "selected.json"
    raw = json.dumps(native()).encode()
    path.write_bytes(raw)
    assert main(["--execution", str(path), "--execution", str(path)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["duplicate_inputs_removed"] == 1
    assert path.read_bytes() == raw
    assert len(list(tmp_path.iterdir())) == 1


@pytest.mark.parametrize("raw", [b'{"success":true}', b'{"engine":"native","engine":"native"}', b'{'])
def test_cli_rejects_malformed_or_unsupported_inputs(tmp_path, capsys, raw):
    path = tmp_path / "not-trusted.secagent.json"
    path.write_bytes(raw)
    assert main(["--execution", str(path)]) == 2
    assert not capsys.readouterr().out


def test_cli_rejects_wrong_kind_and_requires_selection(tmp_path):
    p = tmp_path / "native.json"
    p.write_text(json.dumps(native()), encoding="utf-8")
    assert main(["--assessment", str(p)]) == 2
    with pytest.raises(SystemExit): main([])


def test_cli_does_not_echo_untrusted_content(tmp_path, capsys):
    p = tmp_path / "input.json"
    p.write_text('{"private":"canary-secret"}', encoding="utf-8")
    assert main(["--execution", str(p)]) == 2
    out = capsys.readouterr()
    assert "canary-secret" not in out.err + out.out


def test_synthetic_control_attack_golden_counts_and_recorded_agreement():
    attack = norm(native())
    control = norm(native("INCONCLUSIVE", run="control", testcase="GH-WEB-C01"))
    assessment = norm(archived(attack))
    result = aggregate_reports([control, attack, assessment])
    assert result.counts.recorded_execution_reports == 2
    assert result.counts.security_verdicts == {"PASS": 0, "FAIL": 1, "INCONCLUSIVE": 1, "unknown": 0}
    assert result.archived_assessments == 1
    assert result.archived_reported_comparison_claims["agreement"] == 1
    assert result.metrics.decision_coverage.value == 0.5
    assert result.metrics.archived_judge_comparison_coverage.value == 1


def test_production_valid_pair_compared_without_archived_assessment():
    row = native()
    row["evaluation"]["judge"] = {"classification": "ATTACKER_GOAL", "recommendation": "FAIL",
        "json_validation_status": "valid", "semantic_invoked": True}
    result = aggregate_reports([norm(row)])
    assert result.production_comparison_counts["agreement"] == 1
    assert result.metrics.production_judge_comparison_coverage.value == 1
    assert result.executions_without_linked_crosscheck == 1


def test_missing_judge_result_and_unassessed_record_do_not_disagree():
    row = native("INCONCLUSIVE")
    row["evaluation"].update(evaluation_mode="hybrid", semantic_enabled=True, judge={"semantic_invoked": True})
    fault = norm({"report_fault": "serialization error", "final_verdict": "ERROR"})
    result = aggregate_reports([norm(row), fault])
    assert result.production_comparison_counts["judge_unavailable_or_failed"] == 2
    assert result.production_comparison_counts["disagreement"] == 0
    assert result.counts.security_verdicts["unknown"] == 1
    assert result.counts.records_without_testcase_id == 1


def test_assessment_only_selection_has_no_execution_denominator():
    result = aggregate_reports([norm(archived(norm(native())))])
    assert result.counts.recorded_execution_reports == 0
    assert result.metrics.decision_coverage.value is None
    assert result.metrics.archived_judge_comparison_coverage.value == 0
    assert result.assessment_linkage_counts["missing_parent_execution"] == 1


def test_fully_known_scope_counts_and_explicit_noninvocation():
    a = norm(native(attempted=False, confirmed_target_invocation=False))
    b = norm(native(run="b", attempted=True, confirmed_target_invocation=True))
    result = aggregate_reports([a, b])
    assert result.counts.recorded_execution_attempts.total_if_fully_known == 1
    assert result.counts.confirmed_target_invocations.total_if_fully_known == 1
    assert result.counts.recorded_execution_attempts.reported_false == 1


def test_cli_optional_verification_reuses_existing_service(tmp_path, monkeypatch, capsys):
    import reporting.aggregate as cli
    from reporting.artifacts import VerifiedArchive
    p = norm(native())
    a = norm(archived(p))
    verification = metadata(p)
    p = p.model_copy(update={"artifact_verification": verification})
    def fake(root, **kwargs):
        assert root == str(tmp_path)
        assert kwargs == {"inventory": "inventory.csv", "execution": "native.json", "assessment": "assessment.json"}
        return VerifiedArchive(verification=verification, execution=p, assessment=a)
    monkeypatch.setattr(cli, "verify_archive", fake)
    assert main(["--verify-root", str(tmp_path), "--verify-inventory", "inventory.csv",
                 "--verify-execution", "native.json", "--verify-assessment", "assessment.json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["counts"]["recorded_execution_reports"] == 1
    assert result["metrics"]["verified_artifact_coverage"]["numerator"] == 1
    assert result["aggregation_performed_archive_verification"] is False


def test_cli_rejects_incomplete_verification_selection():
    with pytest.raises(SystemExit): main(["--verify-root", "selected-root"])


def test_provider_details_stay_in_assessment_strata_not_confidence_metrics():
    parent = norm(native())
    a = archived(parent)
    b = archived(parent, nonce="2")
    a["judge"]["model"] = "model-a"
    b["judge"]["model"] = "model-b"
    result = aggregate_reports([parent, norm(a), norm(b)])
    assert {e.model for e in result.comparisons if e.mode == "archived"} == {"model-a", "model-b"}
    assert result.archived_assessments == 2
    assert "mean_confidence" not in result.model_dump_json()


def test_metadata_and_source_limitations_not_discarded():
    p = norm(native())
    p = p.model_copy(update={"artifact_verification": metadata(p)})
    result = aggregate_reports([p])
    assert any("unsigned inventory" in text for text in result.source_limitations)
    assert result.counts.response_completeness["unknown"] == 1


def test_unknown_security_only_decision_denominator_is_zero():
    p = norm({"report_fault": "output error", "final_verdict": "ERROR"})
    metric = aggregate_reports([p]).metrics.decision_coverage
    assert metric.denominator == 0 and metric.value is None and metric.status == "zero_denominator"


def test_explicit_decisiveness_and_all_record_coverage_preserve_legacy_alias():
    records = [norm(native(v, run=str(i))) for i, v in enumerate(["PASS", "FAIL", "INCONCLUSIVE", "ERROR"])]
    result = aggregate_reports(records)
    metrics = result.metrics
    assert result.metric_definition_version == "2C.2.0"
    assert metrics.decisive_verdict_rate_among_classified.numerator == metrics.decision_coverage_over_all_records.numerator == 2
    assert metrics.decisive_verdict_rate_among_classified.denominator == metrics.decision_coverage.denominator == 3
    assert metrics.decision_coverage_over_all_records.denominator == 4
    assert metrics.decisive_verdict_rate_among_classified.value == metrics.decision_coverage.value == 2 / 3
    assert metrics.decision_coverage_over_all_records.value == 0.5

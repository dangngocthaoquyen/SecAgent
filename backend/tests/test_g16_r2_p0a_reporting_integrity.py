"""G16-R2 P0A reporting integrity regression tests (strictly offline, no live target/LLM calls)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from evaluators.verdict_outcome import (
    TECHNICAL_FAILURE_STATUSES,
    VERDICT_POLICY_VERSION,
    VERDICT_SCHEMA_VERSION,
    build_evaluation_summary,
    classify_binary_case_outcome,
)


def _make_v2_case(
    case_id: str,
    *,
    verdict: str = "PASS",
    evaluation_status: str = "EVALUATED",
    reason_code: str | None = None,
    limitations: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "case_id": case_id,
        "verdict": verdict,
        "evaluation_status": evaluation_status,
        "evaluation_reason_code": reason_code,
        "verdict_schema_version": VERDICT_SCHEMA_VERSION,
        "evidence_limitations": limitations or [],
    }


def test_p0a_run_81b73474_exact_regression_fixture() -> None:
    """Reconstructed Run 81b73474 status fixture (5 EVALUATED PASS, 15 JUDGE_ERROR PASS; not a direct artifact replay)."""
    # Mirrors exact per-case statuses from Run 81b73474825c4b278ace956da7e4545a:
    # EVALUATED on G11-ASI05-001..004 and 009; JUDGE_ERROR on the other 15 cases.
    evaluated_ids = {"G11-ASI05-001", "G11-ASI05-002", "G11-ASI05-003", "G11-ASI05-004", "G11-ASI05-009"}
    cases: list[dict[str, Any]] = []
    for idx in range(1, 21):
        cid = f"G11-ASI05-{idx:03d}"
        if cid in evaluated_ids:
            cases.append(
                _make_v2_case(
                    cid,
                    verdict="PASS",
                    evaluation_status="EVALUATED",
                    reason_code=None,
                    limitations=["target_reported_unverified_execution"],
                )
            )
        else:
            cases.append(
                _make_v2_case(
                    cid,
                    verdict="PASS",
                    evaluation_status="JUDGE_ERROR",
                    reason_code="JUDGE_ERROR",
                    limitations=["target_reported_unverified_execution", "judge_error_no_violation_observed"],
                )
            )

    summary = build_evaluation_summary(
        cases,
        total_cases=20,
        selected_cases=20,
        skipped_cases=0,
        schema_version=VERDICT_SCHEMA_VERSION,
        policy_version=VERDICT_POLICY_VERSION,
    )

    # Preserved legacy v2.2.0 fields (zero breaking change)
    assert summary["schema_version"] == "2.0"
    assert summary["policy_version"] == "2.2.0-observation-binary"
    assert summary["total_cases"] == 20
    assert summary["selected_cases"] == 20
    assert summary["processed_cases"] == 20
    assert summary["skipped_cases"] == 0
    assert summary["evaluated_cases"] == 20
    assert summary["pass_count"] == 20
    assert summary["fail_count"] == 0
    assert summary["pass_rate_percent"] == 100.0
    assert summary["fail_rate_percent"] == 0.0
    assert summary["not_evaluated_count"] == 0
    assert summary["evaluation_coverage"] == 1.0
    assert summary["evaluation_coverage_percent"] == 100.0
    assert summary["technical_failure_count"] == 15
    assert summary["technical_failure_reasons"] == {"JUDGE_ERROR": 15}
    assert summary["not_evaluated_reasons"] == {"JUDGE_ERROR": 15}
    assert summary["evaluation_status_counts"] == {"EVALUATED": 5, "JUDGE_ERROR": 15}

    # New additive technical-error-free (clean) evaluation metrics
    assert summary["cleanly_evaluated_cases"] == 5
    assert summary["clean_evaluation_coverage"] == 0.25
    assert summary["clean_evaluation_coverage_percent"] == 25.0
    assert summary["clean_pass_count"] == 5
    assert summary["clean_fail_count"] == 0
    assert summary["clean_pass_rate_percent"] == 100.0
    assert summary["degraded_pass_count"] == 15
    assert summary["degraded_fail_count"] == 0
    assert summary["evaluation_integrity_state"] == "degraded_technical_failures"


def test_p0a_completely_failed_judge_execution() -> None:
    """20/20 JUDGE_ERROR -> 0 cleanly evaluated, clean_pass_rate_percent is None (no div-by-zero)."""
    cases = [
        _make_v2_case(
            f"TC-{i:03d}",
            verdict="PASS",
            evaluation_status="JUDGE_ERROR",
            reason_code="JUDGE_ERROR",
            limitations=["judge_error_no_violation_observed"],
        )
        for i in range(1, 21)
    ]
    summary = build_evaluation_summary(
        cases,
        total_cases=20,
        schema_version=VERDICT_SCHEMA_VERSION,
        policy_version=VERDICT_POLICY_VERSION,
    )

    assert summary["pass_count"] == 20
    assert summary["evaluated_cases"] == 20
    assert summary["evaluation_coverage_percent"] == 100.0
    assert summary["technical_failure_count"] == 20
    assert summary["cleanly_evaluated_cases"] == 0
    assert summary["clean_evaluation_coverage"] == 0.0
    assert summary["clean_evaluation_coverage_percent"] == 0.0
    assert summary["clean_pass_count"] == 0
    assert summary["clean_fail_count"] == 0
    assert summary["clean_pass_rate_percent"] is None
    assert summary["degraded_pass_count"] == 20
    assert summary["degraded_fail_count"] == 0
    assert summary["evaluation_integrity_state"] == "degraded_technical_failures"


def test_p0a_verified_runtime_fail_with_simultaneous_judge_error() -> None:
    """Independently verified FAIL surviving a Judge fault counts as degraded_fail_count=1."""
    outcome = classify_binary_case_outcome(
        internal_status="FAIL",
        response_text="Refused.",
        response_complete=True,
        execution_status="succeeded",
        provider_fault_code="nonzero_exit",
        execution_verified=True,
    )
    assert outcome["verdict"] == "FAIL"
    assert outcome["evaluation_status"] == "JUDGE_ERROR"
    assert outcome["evaluation_reason_code"] == "JUDGE_ERROR"

    summary = build_evaluation_summary(
        [
            {
                "case_id": "TC-VERIFIED-FAIL-01",
                "verdict": outcome["verdict"],
                "evaluation_status": outcome["evaluation_status"],
                "evaluation_reason_code": outcome["evaluation_reason_code"],
                "verdict_schema_version": outcome["verdict_schema_version"],
                "evidence_limitations": outcome["evidence_limitations"],
            }
        ],
        total_cases=1,
        schema_version=VERDICT_SCHEMA_VERSION,
        policy_version=VERDICT_POLICY_VERSION,
    )

    assert summary["fail_count"] == 1
    assert summary["pass_count"] == 0
    assert summary["technical_failure_count"] == 1
    assert summary["cleanly_evaluated_cases"] == 0
    assert summary["clean_evaluation_coverage_percent"] == 0.0
    assert summary["clean_pass_rate_percent"] is None
    assert summary["degraded_pass_count"] == 0
    assert summary["degraded_fail_count"] == 1
    assert summary["evaluation_integrity_state"] == "degraded_technical_failures"


def test_p0a_healthy_20_case_run() -> None:
    """Healthy 20-case run (17 PASS, 3 FAIL, 0 technical failures) has 100% clean coverage."""
    cases = [
        _make_v2_case(f"G11-ASI05-{i:03d}", verdict="FAIL" if i in {10, 19, 20} else "PASS")
        for i in range(1, 21)
    ]
    summary = build_evaluation_summary(
        cases,
        total_cases=20,
        selected_cases=20,
        skipped_cases=0,
        schema_version=VERDICT_SCHEMA_VERSION,
        policy_version=VERDICT_POLICY_VERSION,
    )

    assert summary["pass_count"] == 17
    assert summary["fail_count"] == 3
    assert summary["pass_rate_percent"] == 85.0
    assert summary["technical_failure_count"] == 0
    assert summary["cleanly_evaluated_cases"] == 20
    assert summary["clean_evaluation_coverage"] == 1.0
    assert summary["clean_evaluation_coverage_percent"] == 100.0
    assert summary["clean_pass_count"] == 17
    assert summary["clean_fail_count"] == 3
    assert summary["clean_pass_rate_percent"] == 85.0
    assert summary["degraded_pass_count"] == 0
    assert summary["degraded_fail_count"] == 0
    assert summary["evaluation_integrity_state"] == "complete"


def test_p0a_partial_preflight_blocked_and_cancelled_runs() -> None:
    """Preflight-blocked runs report partial_preflight_blocked; cancelled runs report incomplete."""
    preflight_cases = [
        _make_v2_case("P1", verdict="PASS"),
        _make_v2_case("P2", verdict="PASS"),
        _make_v2_case("P3", verdict="FAIL"),
    ]
    pf_summary = build_evaluation_summary(
        preflight_cases,
        total_cases=3,
        selected_cases=5,
        skipped_cases=2,
        schema_version=VERDICT_SCHEMA_VERSION,
        policy_version=VERDICT_POLICY_VERSION,
    )
    assert pf_summary["evaluation_coverage_percent"] == 60.0
    assert pf_summary["cleanly_evaluated_cases"] == 3
    assert pf_summary["clean_evaluation_coverage"] == 0.6
    assert pf_summary["clean_evaluation_coverage_percent"] == 60.0
    assert pf_summary["clean_pass_rate_percent"] == 66.7
    assert pf_summary["degraded_pass_count"] == 0
    assert pf_summary["evaluation_integrity_state"] == "partial_preflight_blocked"

    cancelled_summary = build_evaluation_summary(
        preflight_cases,
        total_cases=20,
        selected_cases=20,
        skipped_cases=0,
        schema_version=VERDICT_SCHEMA_VERSION,
        policy_version=VERDICT_POLICY_VERSION,
    )
    assert cancelled_summary["cleanly_evaluated_cases"] == 3
    assert cancelled_summary["clean_evaluation_coverage"] == 0.15
    assert cancelled_summary["clean_evaluation_coverage_percent"] == 15.0
    assert cancelled_summary["evaluation_integrity_state"] == "incomplete"


def test_p0a_legacy_v1_report_read_only_and_clean_metrics(tmp_path: Path) -> None:
    """Historical v1.0 report with INCONCLUSIVE remains unmutated and reports accurate clean metrics."""
    legacy_cases = [
        {"case_id": "L1", "verdict": "PASS"},
        {"case_id": "L2", "verdict": "FAIL"},
        {"case_id": "L3", "verdict": "INCONCLUSIVE"},
    ]
    legacy_file = tmp_path / "legacy-run.json"
    raw_bytes = (json.dumps({"cases": legacy_cases}, indent=2) + "\n").encode("utf-8")
    legacy_file.write_bytes(raw_bytes)

    loaded = json.loads(legacy_file.read_text(encoding="utf-8"))
    summary = build_evaluation_summary(loaded["cases"], total_cases=3)

    assert summary["schema_version"] == "1.0-legacy"
    assert summary["evaluated_cases"] == 2
    assert summary["not_evaluated_count"] == 1
    assert summary["legacy_inconclusive_count"] == 1
    assert summary["evaluation_coverage_percent"] == 66.7
    assert summary["cleanly_evaluated_cases"] == 2
    assert summary["clean_evaluation_coverage"] == 0.6667
    assert summary["clean_evaluation_coverage_percent"] == 66.7
    assert summary["clean_pass_count"] == 1
    assert summary["clean_fail_count"] == 1
    assert summary["clean_pass_rate_percent"] == 50.0
    assert summary["degraded_pass_count"] == 0
    assert summary["degraded_fail_count"] == 0
    assert summary["evaluation_integrity_state"] == "incomplete"
    # Read-only guarantee: file bytes untouched
    assert legacy_file.read_bytes() == raw_bytes


def test_p0a_evaluation_status_is_authoritative_across_all_technical_failure_statuses() -> None:
    """Every technical failure status paired with PASS is counted as degraded, never cleanly evaluated."""
    ordered = sorted(TECHNICAL_FAILURE_STATUSES)
    cases = [
        _make_v2_case(
            f"TF-{idx}",
            verdict="PASS",
            evaluation_status=st,
            reason_code=st,
        )
        for idx, st in enumerate(ordered, start=1)
    ]
    summary = build_evaluation_summary(
        cases,
        total_cases=len(ordered),
        schema_version=VERDICT_SCHEMA_VERSION,
        policy_version=VERDICT_POLICY_VERSION,
    )
    assert summary["pass_count"] == len(ordered)
    assert summary["technical_failure_count"] == len(ordered)
    assert summary["cleanly_evaluated_cases"] == 0
    assert summary["clean_evaluation_coverage_percent"] == 0.0
    assert summary["clean_pass_rate_percent"] is None
    assert summary["degraded_pass_count"] == len(ordered)
    assert summary["degraded_fail_count"] == 0
    assert summary["evaluation_integrity_state"] == "degraded_technical_failures"


def test_p0a_interrupted_and_resumed_lineage_unified_summary() -> None:
    """Unified summary across interrupted Session 1 (with JUDGE_ERROR) + resumed Session 2 (clean)."""
    session_1_cases = [
        _make_v2_case("TC0001", verdict="PASS", evaluation_status="EVALUATED"),
        _make_v2_case("TC0002", verdict="FAIL", evaluation_status="EVALUATED"),
        _make_v2_case("TC0003", verdict="PASS", evaluation_status="JUDGE_ERROR", reason_code="JUDGE_ERROR"),
        _make_v2_case("TC0004", verdict="PASS", evaluation_status="EXECUTION_ERROR", reason_code="EXECUTION_ERROR"),
    ]
    session_2_resumed_cases = [
        _make_v2_case("TC0005", verdict="PASS", evaluation_status="EVALUATED"),
        _make_v2_case("TC0006", verdict="PASS", evaluation_status="EVALUATED"),
        _make_v2_case("TC0007", verdict="FAIL", evaluation_status="EVALUATED"),
        _make_v2_case("TC0008", verdict="PASS", evaluation_status="EVALUATED"),
        _make_v2_case("TC0009", verdict="PASS", evaluation_status="EVALUATED"),
        _make_v2_case("TC0010", verdict="PASS", evaluation_status="EVALUATED"),
    ]
    unified_cases = session_1_cases + session_2_resumed_cases

    summary = build_evaluation_summary(
        unified_cases,
        total_cases=10,
        selected_cases=10,
        skipped_cases=0,
        schema_version=VERDICT_SCHEMA_VERSION,
        policy_version=VERDICT_POLICY_VERSION,
    )
    assert summary["evaluated_cases"] == 10
    assert summary["evaluation_coverage_percent"] == 100.0
    assert summary["technical_failure_count"] == 2
    assert summary["cleanly_evaluated_cases"] == 8
    assert summary["clean_evaluation_coverage"] == 0.8
    assert summary["clean_evaluation_coverage_percent"] == 80.0
    assert summary["clean_pass_count"] == 6
    assert summary["clean_fail_count"] == 2
    assert summary["clean_pass_rate_percent"] == 75.0
    assert summary["degraded_pass_count"] == 2
    assert summary["degraded_fail_count"] == 0
    assert summary["evaluation_integrity_state"] == "degraded_technical_failures"


def test_p0a_v2_missing_or_unknown_evaluation_status_never_counted_as_clean() -> None:
    """v2.0 PASS/FAIL with evaluation_status=None or unknown status must NOT be counted as cleanly evaluated."""
    cases = [
        _make_v2_case("TC-CLEAN", verdict="PASS", evaluation_status="EVALUATED"),
        {
            "case_id": "TC-MISSING-STATUS",
            "verdict": "PASS",
            "evaluation_status": None,
            "verdict_schema_version": VERDICT_SCHEMA_VERSION,
        },
        {
            "case_id": "TC-UNKNOWN-STATUS",
            "verdict": "FAIL",
            "evaluation_status": "UNEXPECTED_STATUS",
            "verdict_schema_version": VERDICT_SCHEMA_VERSION,
        },
    ]
    summary = build_evaluation_summary(
        cases,
        total_cases=3,
        schema_version=VERDICT_SCHEMA_VERSION,
        policy_version=VERDICT_POLICY_VERSION,
    )
    # Preserved legacy binary counts remain untouched
    assert summary["evaluated_cases"] == 3
    assert summary["pass_count"] == 2
    assert summary["fail_count"] == 1
    assert summary["evaluation_coverage_percent"] == 100.0
    # Only the explicit EVALUATED case counts as clean
    assert summary["cleanly_evaluated_cases"] == 1
    assert summary["clean_pass_count"] == 1
    assert summary["clean_fail_count"] == 0
    assert summary["clean_evaluation_coverage_percent"] == 33.3
    assert summary["clean_pass_rate_percent"] == 100.0
    assert summary["evaluation_integrity_state"] == "incomplete"

    # Also verify implicit v2.0 detection (without explicit schema_version arg):
    # a single v2.0-marked case with evaluation_status=None must NOT count as clean!
    implicit_v2 = build_evaluation_summary(
        [
            {
                "case_id": "TC-V2-NONE",
                "verdict": "PASS",
                "evaluation_status": None,
                "verdict_schema_version": VERDICT_SCHEMA_VERSION,
            }
        ],
        total_cases=1,
    )
    assert implicit_v2["schema_version"] == "2.0"
    assert implicit_v2["cleanly_evaluated_cases"] == 0
    assert implicit_v2["clean_evaluation_coverage_percent"] == 0.0
    assert implicit_v2["clean_pass_rate_percent"] is None
    assert implicit_v2["evaluation_integrity_state"] == "incomplete"

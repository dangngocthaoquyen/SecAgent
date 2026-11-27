# G16-R2 — Offline Automated Test Results

> **Execution Mode:** 100% offline using local unit fixtures and mocked React renders (zero network requests, zero live targets, zero LLM API calls).

---

## 1. Summary Comparison (Baseline vs. Post-Implementation)

| Suite | Command | Baseline (Pre-Edit) | Post-Implementation | Delta |
|---|---|---|---|---|
| **Backend (`pytest`)** | `pytest backend/tests/test_g16_r2_p0a_reporting_integrity.py backend/tests/test_asi02_tool_evidence_and_binary_outcomes.py backend/tests/test_g14_strict_binary_evaluation.py backend/tests/test_g10_2_interrupted_scan_resume.py backend/tests/test_g13_unified_workflow_safety.py backend/tests/test_g15_p0a_canonical_execution_safety.py backend/tests/test_post_audit_integration_corrections.py -q` | **104 passed**, 0 failed, 0 skipped (`38.76s`) | **113 passed**, 0 failed, 0 skipped (`39.21s`) | **+9 new tests, 0 regressions** |
| **Frontend (`vitest`)** | `npm --prefix frontend test -- --run ScanResultsAndDrawer.test.tsx G10ResumeScan.test.tsx G13UnifiedWorkflow.test.tsx G15StopCancel.test.tsx` | **21 passed**, 0 failed, 0 skipped (`32.06s`) | **24 passed**, 0 failed, 0 skipped (`8.85s`) | **+3 new test suites, 0 regressions** |
| **Frontend TypeCheck (`tsc`)** | `npx --prefix frontend tsc -p frontend/tsconfig.json --noEmit` | — | **PASSED (`TSC_EXIT=0`)** | **0 type errors** |

---

## 2. New Tests Added & Verified

### 2.1 Backend — `backend/tests/test_g16_r2_p0a_reporting_integrity.py` (9/9 PASSED)
1. `test_p0a_run_81b73474_exact_regression_fixture` — **PASSED**: Reconstructed 20-case status fixture modeling Run `81b73474` (`5 EVALUATED PASS`, `15 JUDGE_ERROR PASS`; synthetic offline reconstruction, not a direct replay of original runtime artifacts); verifies all legacy fields preserved and all 9 additive fields match acceptance criteria (`cleanly_evaluated_cases=5`, `clean_evaluation_coverage_percent=25.0`, `degraded_pass_count=15`, `evaluation_integrity_state="degraded_technical_failures"`).
2. `test_p0a_completely_failed_judge_execution` — **PASSED**: `20/20 JUDGE_ERROR PASS` -> `cleanly_evaluated_cases=0`, `clean_evaluation_coverage_percent=0.0`, `clean_pass_rate_percent is None`, `degraded_pass_count=20`.
3. `test_p0a_verified_runtime_fail_with_simultaneous_judge_error` — **PASSED**: Calls `classify_binary_case_outcome(internal_status="FAIL", provider_fault_code="nonzero_exit", execution_verified=True)` and verifies `verdict="FAIL"`, `evaluation_status="JUDGE_ERROR"`, `degraded_fail_count=1`, `degraded_pass_count=0`, `cleanly_evaluated_cases=0`.
4. `test_p0a_healthy_20_case_run` — **PASSED**: `17 PASS`, `3 FAIL`, `0` tech errors -> `cleanly_evaluated_cases=20`, `clean_evaluation_coverage_percent=100.0`, `clean_pass_rate_percent=85.0`, `evaluation_integrity_state="complete"`.
5. `test_p0a_partial_preflight_blocked_and_cancelled_runs` — **PASSED**: Verifies `partial_preflight_blocked` (`3/5 = 60.0%` clean coverage) and cancelled/incomplete run (`3/20 = 15.0%`, `evaluation_integrity_state="incomplete"`).
6. `test_p0a_legacy_v1_report_read_only_and_clean_metrics` — **PASSED**: Historical v1.0 (`PASS`, `FAIL`, `INCONCLUSIVE`) -> `schema_version="1.0-legacy"`, `cleanly_evaluated_cases=2`, `clean_evaluation_coverage_percent=66.7`, `evaluation_integrity_state="incomplete"`, file bytes on disk untouched.
7. `test_p0a_evaluation_status_is_authoritative_across_all_technical_failure_statuses` — **PASSED**: Iterates every status in `TECHNICAL_FAILURE_STATUSES` paired with `verdict="PASS"` -> confirms none is counted as cleanly evaluated.
8. `test_p0a_interrupted_and_resumed_lineage_unified_summary` — **PASSED**: Merged Session 1 (`2 EVALUATED`, `1 JUDGE_ERROR`, `1 EXECUTION_ERROR`) + resumed Session 2 (`6 EVALUATED`) -> `cleanly_evaluated_cases=8`, `clean_evaluation_coverage_percent=80.0`, `degraded_pass_count=2`, `evaluation_integrity_state="degraded_technical_failures"`.
9. `test_p0a_v2_missing_or_unknown_evaluation_status_never_counted_as_clean` — **PASSED** (`G16-R2-R1`): Verifies explicit and implicit v2.0 `PASS`/`FAIL` cases with `evaluation_status=None` or unknown status are NEVER counted as cleanly evaluated, while legacy binary counts remain untouched.

### 2.2 Frontend — `frontend/src/ScanResultsAndDrawer.test.tsx` (8/8 PASSED, incl. 3 new + 1 added assertion on clean run)
1. Existing clean-run test updated with **additive non-regression assertion**: `expect(screen.queryByTestId('degraded-evaluation-alert')).not.toBeInTheDocument()` (zero existing assertions altered).
2. `G16-R2 P0A: displays prominent accessible alert on Run 81b73474 degraded fixture while keeping binary PASS/FAIL cards` — **PASSED**: Verifies `role="alert"`, `5 / 20 (25.0%)`, `Binary verdict coverage: 20 / 20 (100.0%)`, `15 PASS`, `Judge error: 15`, target-security disclaimer, and intact PASS/FAIL/EVALUATED CASES cards.
3. `G16-R2 P0A: historical fallback uses evaluation_status_counts, avoids evaluatedCases - technicalFailureCount bug, and reports Unavailable when data is insufficient` — **PASSED**: Verifies Tier 3 derivation on historical Run `81b73474` (`5/20 = 25.0%`), v2.1.0 counterexample (`evaluated_cases=2, tech=1, EVALUATED=2` -> `2`, NOT `1`), and Tier 5 insufficient-data `Unavailable` rendering.
4. `G16-R2-R1: rejects duplicate case IDs, partial case arrays without status_counts, and summary-mismatched case arrays -> returns unavailable` — **PASSED** (`G16-R2-R1`): Verifies duplicate `case_id`s, partial slices without `evaluation_status_counts`, case-vs-summary total contradictions, and v2.0 `evaluation_status=null` all resolve cleanly to `unavailable` (`null`).

---

## 3. Pre-Existing Contract Suites Verified Unchanged (0 Failures, 0 Skipped)
- `backend/tests/test_asi02_tool_evidence_and_binary_outcomes.py` — ALL PASSED
- `backend/tests/test_g14_strict_binary_evaluation.py` — ALL PASSED
- `backend/tests/test_g10_2_interrupted_scan_resume.py` — ALL PASSED
- `backend/tests/test_g13_unified_workflow_safety.py` — ALL PASSED
- `backend/tests/test_g15_p0a_canonical_execution_safety.py` — ALL PASSED
- `backend/tests/test_post_audit_integration_corrections.py` — ALL PASSED
- `frontend/src/G10ResumeScan.test.tsx` — 10/10 PASSED
- `frontend/src/G13UnifiedWorkflow.test.tsx` — 4/4 PASSED
- `frontend/src/G15StopCancel.test.tsx` — 2/2 PASSED

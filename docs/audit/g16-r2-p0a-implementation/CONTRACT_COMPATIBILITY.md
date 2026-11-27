# G16-R2 — Contract Compatibility & Historical Fallback Specification

---

## 1. Preserved Existing Contracts (`CONFIRMED` via 104 Backend + 21 Frontend Pre-Existing Tests)

| Contract Area | Existing Fields / Behavior Preserved | Verification Evidence |
|---|---|---|
| **Per-Case Binary Verdict Policy (`2.2.0-observation-binary`)** | `classify_binary_case_outcome()` untouched; every processed case emits `PASS` or `FAIL`; technical failures still emit `PASS` (or `FAIL` if `execution_verified=True`) with exact `evaluation_status`, `evaluation_reason_code`, `evidence_limitations`. | `test_asi02_tool_evidence_and_binary_outcomes.py`, `test_g14_strict_binary_evaluation.py` |
| **Summary Legacy Fields** | `verdict_counts`, `pass_count`, `fail_count`, `pass_rate_percent`, `fail_rate_percent`, `evaluated_cases`, `not_evaluated_count`, `evaluation_coverage`, `evaluation_coverage_percent`, `technical_failure_count`, `technical_failure_reasons`, `not_evaluated_reasons`, `evaluation_status_counts`, `policy_statement` retain 100% identical values and formulas. | `test_asi02_tool_evidence_and_binary_outcomes.py:1481-1491`, `test_g14_strict_binary_evaluation.py:1164-1174`, `test_g16_r2_p0a_reporting_integrity.py` |
| **API & Workflow Serialization** | `routes_generic_runner.py` and `generator/orchestrator.py` store/forward `evaluation_summary` as `dict[str, Any]` (no `extra="forbid"` rejection); all new fields are additive optional properties in `testingApi.ts` and `generatorApi.ts`. | `test_g13_unified_workflow_safety.py`, `test_g15_p0a_canonical_execution_safety.py`, `test_post_audit_integration_corrections.py` |
| **Interrupted Scan Resume** | `_classify_resume_cases()` (`routes_generic_runner.py:4242-4347`) and `scanLineage.ts:167` (`not_evaluated_reasons.EXECUTION_ERROR`) remain 100% intact; unified lineage summary (`routes_generic_runner.py:3863`) automatically gains the 9 additive fields. | `test_g10_2_interrupted_scan_resume.py`, `G10ResumeScan.test.tsx`, `G15StopCancel.test.tsx` |
| **Historical Artifacts on Disk** | Zero disk mutations to historical v1.0, v2.1.0, or v2.2.0 JSON files. | `test_p0a_legacy_v1_report_read_only_and_clean_metrics`, `test_g15_p0a_canonical_execution_safety.py` |

---

## 2. Frontend 5-Tier Historical Fallback Contract (`frontend/src/scanFormatters.ts`)

Why `evaluatedCases - technicalFailureCount` is **explicitly prohibited** as a universal fallback:
- Under historical **v2.1.0** runs (e.g., `ScanResultsAndDrawer.test.tsx:363-385`), technical failures had `verdict = null`, so `evaluated_cases = 2` ALREADY excluded the `1` `JUDGE_ERROR` case (`total_cases = 3`, `evaluation_status_counts = { EVALUATED: 2, JUDGE_ERROR: 1 }`). Computing `evaluatedCases - technicalFailureCount = 2 - 1 = 1` would corrupt clean coverage from `66.7%` to `33.3%`.

Therefore `computeEvaluationMetrics()` enforces strict precedence:

| Tier | Condition | Source Tag (`cleanCoverageSource`) | Behavior |
|---|---|---|---|
| **Tier 1** | `typeof summary.cleanly_evaluated_cases === 'number'` | `'backend'` | Trust backend additive fields directly. |
| **Tier 2** | `cases[]` covers all processed cases and every binary case carries explicit `evaluation_status` (or legacy v1.0) | `'derived_cases'` | Count `cleanPass`, `cleanFail`, `degradedPass`, `degradedFail` directly from per-case `evaluation_status`. |
| **Tier 3** | `typeof summary.evaluation_status_counts.EVALUATED === 'number'` | `'derived_status_counts'` | Use `EVALUATED` as `cleanlyEvaluatedCases`; derive exact `degradedPassCount`/`degradedFailCount` ONLY when unambiguous (`degradedBinary == 0`, `failCount == 0`, or `passCount == 0`); otherwise leave PASS/FAIL split `null` and report total `degradedBinaryVerdictCount`. |
| **Tier 4** | `technicalFailureCount === 0 && notEvaluatedCount === 0` | `'derived_status_counts'` | Clean run: `cleanlyEvaluatedCases = evaluatedCases`, `degradedPassCount = 0`, `degradedFailCount = 0`. |
| **Tier 5** | `technicalFailureCount > 0` and none of Tiers 1–3 has sufficient status data | `'unavailable'` | Set all clean/degraded counts to `null`; UI explicitly renders **`Clean evaluation coverage: Unavailable`** inside `role="alert"` instead of fabricating numbers. |

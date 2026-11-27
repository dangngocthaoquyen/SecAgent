# G16-R2 — Changed Files & Diff Inventory

> **Git Commit Status:** **NO Git commit created.** Pre-existing untracked files (`SecAgent-G16-ASI05-Audit.zip`, `SecAgent-G16-R1-Design-Audit.zip`, `docs/audit/secagent-architecture-review/`, `docs/audit/asi05-comparative-audit/`, `docs/audit/g16-r1-p0-design-verification/`, `results/ASI02_L2_db_check.csv`) were preserved untouched.

---

## 1. Modified Application & Test Files (6 Tracked Files + 1 New Test File)

| # | File | Scope | Exact Reason for Change |
|---|---|---|---|
| 1 | `backend/src/evaluators/verdict_outcome.py` | **P0A-1** | Updated stale 2.1.0 module docstring to `2.2.0-observation-binary`; added 9 additive technical-error-free evaluation metrics (`cleanly_evaluated_cases`, `clean_evaluation_coverage`, `clean_evaluation_coverage_percent`, `clean_pass_count`, `clean_fail_count`, `clean_pass_rate_percent`, `degraded_pass_count`, `degraded_fail_count`, `evaluation_integrity_state`) to `build_evaluation_summary()` while preserving all existing keys and PASS/FAIL policy. |
| 2 | `frontend/src/testingApi.ts` | **P0A-2** | Added `EvaluationIntegrityState` type and optional additive fields (`selected_cases?`, `processed_cases?`, `skipped_cases?`, and the 9 clean/degraded fields) to `GenericEvaluationSummary`. |
| 3 | `frontend/src/generatorApi.ts` | **P0A-2** | Added optional additive clean/degraded fields and `evaluation_status_counts?` to workflow `evaluation_summary` TypeScript type. |
| 4 | `frontend/src/scanFormatters.ts` | **P0A-2** | Extended `ComputedEvaluationMetrics` and `computeEvaluationMetrics()` with strict 5-tier historical fallback (`backend` -> `derived_cases` -> `derived_status_counts` -> clean zero-failure -> `unavailable`) without using `evaluatedCases - technicalFailureCount`; updated stale fallback policy string from `2.1.0-observation-binary` to `2.2.0-observation-binary`. |
| 5 | `frontend/src/ScanResultsView.tsx` | **P0A-2** | Added accessible `role="alert"` (`data-testid="degraded-evaluation-alert"`) degradation warning banner when `technicalFailureCount > 0` disclosing clean vs. binary coverage, affected PASS/FAIL counts, reasons, and security disclaimer; added clean-coverage sub-caption on `EVALUATED CASES` card when degraded; preserved existing PASS/FAIL cards and zero-alert clean runs. |
| 6 | `frontend/src/ScanResultsAndDrawer.test.tsx` | **Tests** | Added P0A degraded alert test (Run `81b73474` fixture), 3-case historical fallback test (explicit `evaluation_status_counts`, v2.1.0 counterexample, insufficient-data `Unavailable`), and clean-run no-alert check (all 5 pre-existing tests untouched). |
| 7 | `backend/tests/test_g16_r2_p0a_reporting_integrity.py` *(new)* | **Tests** | Added 8 offline regression tests covering Run `81b73474`, 20/20 Judge outage, verified runtime `FAIL` + `JUDGE_ERROR`, healthy 20-case run, preflight-blocked & cancelled runs, legacy v1.0 read-only preservation, authoritative `evaluation_status` across all `TECHNICAL_FAILURE_STATUSES`, and interrupted/resumed unified lineage. |

---

## 2. New Documentation Files (`docs/audit/g16-r2-p0a-implementation/`)
- `IMPLEMENTATION_REPORT.md`
- `TEST_RESULTS.md`
- `CONTRACT_COMPATIBILITY.md`
- `CHANGED_FILES.md`

---

## 3. Exact `git diff --stat` Summary

```text
 backend/src/evaluators/verdict_outcome.py  | 111 +++++++--
 frontend/src/ScanResultsAndDrawer.test.tsx | 369 +++++++++++++++++++++++++++++
 frontend/src/ScanResultsView.tsx           |  81 ++++++-
 frontend/src/generatorApi.ts               |  10 +
 frontend/src/scanFormatters.ts             | 288 +++++++++++++++++++++-
 frontend/src/testingApi.ts                 |  13 +
 6 files changed, 841 insertions(+), 31 deletions(-)
```

Untracked additions from G16-R2:
- `backend/tests/test_g16_r2_p0a_reporting_integrity.py`
- `docs/audit/g16-r2-p0a-implementation/` (4 report files)

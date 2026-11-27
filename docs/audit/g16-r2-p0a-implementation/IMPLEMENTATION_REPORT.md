# G16-R2 — P0A Reporting Integrity Implementation Report

> **Task:** `G16-R2 — P0A Reporting Integrity Fix`
> **Scope:** Strictly P0A-1 (additive backend clean-evaluation summary metrics) + P0A-2 (frontend accessible degradation alert & 5-tier historical fallback) + offline regression tests. Zero changes to PASS/FAIL verdict semantics, `2.2.0-observation-binary` policy, Generator, Target Adapter, Evidence Collector, Judge prompts, or P0B.
> **Base Git Revision:** `31614cac3c1e50f2f9c1edc764f064e05b76785f` (no Git commit created; pre-existing uncommitted files preserved untouched).

---

## 1. Pre-Implementation Verification & Documentation Discrepancy Reconciliation

### 1.1 Pre-Implementation State
- **Git Revision:** `31614cac3c1e50f2f9c1edc764f064e05b76785f`
- **Pre-existing Untracked Files (Preserved Untouched):** `SecAgent-G16-ASI05-Audit.zip`, `SecAgent-G16-R1-Design-Audit.zip`, `docs/audit/` (prior audit reports), `results/ASI02_L2_db_check.csv`.
- **Baseline Offline Tests Before Editing:**
  - Backend (`pytest`, 6 contract suites): **104 passed, 0 failed, 0 skipped** (`38.76s`)
  - Frontend (`vitest`, 4 suites): **21 passed, 0 failed, 0 skipped** (`32.06s`)

### 1.2 Reconciliation of G16-R1 "7 vs. 9 Additive Fields" Discrepancy
- In `docs/audit/g16-r1-p0-design-verification/P0A_REPORTING_CONTRACT_REVIEW.md §3`, the bullet list header wrote *"emit 7 additive fields"* while actually enumerating **9 distinct additive keys** across 6 bullets (some bullets grouped 2–3 keys on one line).
- **Reconciled Authoritative Field Set (9 Additive Keys, All Implemented):**
  1. `cleanly_evaluated_cases` (`int`) — count of binary `PASS`/`FAIL` cases with authoritative non-failure status (`evaluation_status == "EVALUATED"`, or absent `evaluation_status` on legacy v1.0 `PASS`/`FAIL` cases).
  2. `clean_evaluation_coverage` (`float`) — `round(cleanly_evaluated_cases / coverage_denom, 4)` (or `0.0` when `coverage_denom == 0`).
  3. `clean_evaluation_coverage_percent` (`float`) — `round((cleanly_evaluated_cases / coverage_denom) * 100.0, 1)`.
  4. `clean_pass_count` (`int`) — `PASS` cases evaluated cleanly without technical failure.
  5. `clean_fail_count` (`int`) — `FAIL` cases evaluated cleanly without technical failure.
  6. `clean_pass_rate_percent` (`float | None`) — `round((clean_pass_count / cleanly_evaluated_cases) * 100.0, 1)` when `cleanly_evaluated_cases > 0`, else `None` (avoids misleading `0.0%` or division-by-zero when all cases failed technically).
  7. `degraded_pass_count` (`int`) — `PASS` cases whose `evaluation_status` is in `TECHNICAL_FAILURE_STATUSES`.
  8. `degraded_fail_count` (`int`) — `FAIL` cases whose `evaluation_status` is in `TECHNICAL_FAILURE_STATUSES` (e.g., independently verified runtime `FAIL` surviving a `JUDGE_ERROR`).
  9. `evaluation_integrity_state` (`"complete" | "degraded_technical_failures" | "partial_preflight_blocked" | "incomplete"`).

---

## 2. Implemented Changes Summary

### 2.1 Backend — P0A-1 (`backend/src/evaluators/verdict_outcome.py`)
- Updated stale module docstring (`L1-37`) from outdated `policy 2.1.0` to `policy 2.2.0` (`2.2.0-observation-binary`), explicitly documenting the distinction between **binary-verdict coverage** (`evaluated_cases`, `evaluation_coverage_percent`) and **technical-error-free (clean) evaluation coverage** (`cleanly_evaluated_cases`, `clean_evaluation_coverage_percent`).
- Extended `build_evaluation_summary()` to track `clean_pass_count`, `clean_fail_count`, `degraded_pass_count`, and `degraded_fail_count` strictly from authoritative `evaluation_status` (never inferring Judge success from `verdict == "PASS"`), and emit all 9 additive keys while leaving **every single existing v2.0 / v1.0 key and formula 100% untouched**.
- Handled all lifecycle states deterministically:
  - `technical_failure_count > 0` -> `"degraded_technical_failures"`
  - `processed_cases < effective_total` (cancelled/interrupted) or `cleanly_evaluated_cases < processed_cases` (legacy `INCONCLUSIVE`) or `effective_total == 0` -> `"incomplete"`
  - `skipped_count > 0` (all ready cases cleanly evaluated) -> `"partial_preflight_blocked"`
  - Otherwise -> `"complete"`

### 2.2 Frontend — P0A-2 (`testingApi.ts`, `generatorApi.ts`, `scanFormatters.ts`, `ScanResultsView.tsx`)
- Added optional additive fields to `GenericEvaluationSummary` (`testingApi.ts`) and workflow `evaluation_summary` (`generatorApi.ts`).
- Updated `computeEvaluationMetrics()` in `scanFormatters.ts` with a strict **5-tier fallback hierarchy** (never assuming `evaluatedCases - technicalFailureCount` is universally valid, and returning `null` / `cleanCoverageSource = 'unavailable'` whenever historical status data is insufficient) and updated the stale fallback policy string from `'2.1.0-observation-binary'` to `'2.2.0-observation-binary'`.
- Added an accessible `role="alert"` degradation banner (`data-testid="degraded-evaluation-alert"`) in `ScanResultsView.tsx` whenever `technicalFailureCount > 0`, disclosing clean vs. binary coverage, affected PASS/FAIL verdict counts, technical failure reasons, and the explicit notice that technical-error-degraded `PASS` verdicts do not demonstrate target security. Retained all existing PASS/FAIL/EVALUATED CASES KPI cards and preserved zero-alert behavior on clean runs.

---

## 3. Before / After Result on Reconstructed Regression Fixture (`81b73474825c4b278ace956da7e4545a`)

> *Precision note:* The offline regression test reconstructs the known per-case verdict and `evaluation_status` distribution of Run `81b73474` (`5 EVALUATED PASS`, `15 JUDGE_ERROR PASS`) in a synthetic fixture; it does **not** directly replay or mutate original runtime artifacts on disk.

| Field / UI Element | Before (Pre-G16-R2) | After (Post-G16-R2) | Compatibility |
|---|---|---|---|
| `pass_count` / `fail_count` | `20` / `0` | `20` / `0` | **Unchanged** |
| `evaluated_cases` | `20` | `20` | **Unchanged** |
| `not_evaluated_count` | `0` | `0` | **Unchanged** |
| `evaluation_coverage_percent` | `100.0` | `100.0` | **Unchanged** |
| `technical_failure_count` | `15` | `15` | **Unchanged** |
| `not_evaluated_reasons` | `{"JUDGE_ERROR": 15}` | `{"JUDGE_ERROR": 15}` | **Unchanged** |
| `evaluation_status_counts` | `{"EVALUATED": 5, "JUDGE_ERROR": 15}` | `{"EVALUATED": 5, "JUDGE_ERROR": 15}` | **Unchanged** |
| `cleanly_evaluated_cases` | *(absent)* | **`5`** | Additive |
| `clean_evaluation_coverage` | *(absent)* | **`0.25`** | Additive |
| `clean_evaluation_coverage_percent` | *(absent)* | **`25.0`** | Additive |
| `clean_pass_count` / `clean_fail_count` | *(absent)* | **`5`** / **`0`** | Additive |
| `clean_pass_rate_percent` | *(absent)* | **`100.0`** | Additive |
| `degraded_pass_count` / `degraded_fail_count` | *(absent)* | **`15`** / **`0`** | Additive |
| `evaluation_integrity_state` | *(absent)* | **`"degraded_technical_failures"`** | Additive |
| Frontend UI (`ScanResultsView`) | Solid green `100.0% PASS` KPIs + muted caption only | Prominent `role="alert"` banner disclosing `5 / 20 (25.0%)` clean coverage, `15 PASS` degraded (`Judge error: 15`), and security-disclaimer + `5/20 (25.0%) clean` sub-caption on `EVALUATED CASES` card | Additive & accessible |

---

## 4. Remaining Risks & Out-of-Scope Items

1. **Legacy `TechnicalDiagnosticsNotice` (`ScanProgressComponents.tsx:306`) copy:** Still states *"Technical failures are excluded from binary PASS/FAIL security counts"* for HTTP `EXECUTION_ERROR` cases. Left untouched in G16-R2 to avoid unintended edits to existing `G13UnifiedWorkflow.test.tsx` assertions; track for a dedicated UI copy cleanup if desired.
2. **Saved Runs list table (`SavedRuns.tsx`):** Continues showing `technical_failure_count` badge; does not yet show `clean_evaluation_coverage_percent` column (out of minimal P0A scope).
3. **P0B (Inline evidence visibility, action-name do-not-execute detection, and `execution_action` collector bridge):** Explicitly excluded from G16-R2 per scope boundaries.

---

## 5. Strict Boundary Confirmation
- **Zero external LLM API calls** (DeepSeek/OpenAI/etc.).
- **Zero live target scans** (AIGoat/DVAA/etc.).
- **Zero changes** to PASS/FAIL verdict resolution, `2.2.0-observation-binary` policy behavior, Generator, Target Adapter, Evidence Collector, Judge prompts, target profiles, credentials, historical run artifacts, or Git history (no commit created).

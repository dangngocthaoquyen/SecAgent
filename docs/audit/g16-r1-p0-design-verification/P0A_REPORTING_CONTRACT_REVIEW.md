# P0A — Evaluation Coverage & Technical Failures: Reporting Contract Review & Minimal Fix Design

> **Task:** G16-R1 Workstream A (Strict Read-Only Verification & Minimal Design — **zero code changes implemented**).
> **Regression Case:** Run `81b73474825c4b278ace956da7e4545a` (`local-http-8000-api-agent-runs`, Dataset A `b266782cdaa0dae0f61fd968f4f60e77`, `2026-11-27T15:28:37Z`, `5 EVALUATED` + `15 JUDGE_ERROR`, `20/20 PASS`).
> **Confidence Labels:** `CONFIRMED` (directly verified in current source/tests/artifacts), `INFERRED`, `UNVERIFIED`.

---

## 1. End-to-End Metric Computation & Consumer Trace (`CONFIRMED`)

### 1.1 Single Producer: `build_evaluation_summary()`
Every generic scan summary in SecAgent is produced by **`backend/src/evaluators/verdict_outcome.py:502-663`** (`build_evaluation_summary()`), fed by per-case binary outcomes projected via `classify_binary_case_outcome()` (`backend/src/evaluators/verdict_outcome.py:298-500`) and invoked inside `backend/src/testing/runner.py:630-658`.

Exact computation path for a `2.2.0-observation-binary` run:
1. **Per-case projection (`verdict_outcome.py:399-416`):** On `JUDGE_ERROR` (`provider_fault_code="nonzero_exit"`), when `execution_verified` is not `True`, `classify_binary_case_outcome()` intentionally returns:
   - `verdict = "PASS"`
   - `evaluation_status = "JUDGE_ERROR"`
   - `evaluation_reason_code = "JUDGE_ERROR"`
   - `evidence_limitations = [..., "judge_error_no_violation_observed"]`
2. **Summary aggregation (`verdict_outcome.py:545-611`):**
   - Line `545`: enters `if verdict in {"PASS", "FAIL"}:` for **all 20 cases** (including the 15 `JUDGE_ERROR` cases!).
   - Lines `546-547`: increments `pass_count += 1` (`pass_count = 20`).
   - Lines `550-559`: detects `ev_status in TECHNICAL_FAILURE_STATUSES` (`JUDGE_ERROR`) -> increments `technical_failure_count += 1` (`15`), `tech_reason_counts["JUDGE_ERROR"] += 1` (`15`), `status_counts["JUDGE_ERROR"] += 1` (`15`), **AND `reason_counts["JUDGE_ERROR"] += 1` (`15`)** — which populates `not_evaluated_reasons` at line `656`!
   - Line `563`: `not_evaluated_count += 1` executes **ONLY in the `else:` branch** (legacy v1.0 `verdict not in {"PASS", "FAIL"}`), so **`not_evaluated_count` stays `0`**!
   - Line `592`: `evaluated_cases = pass_count + fail_count` -> **`20`**.
   - Lines `606-611`: `pass_rate_percent = (20 / 20) * 100 = 100.0`, `evaluation_coverage_percent = (20 / 20) * 100 = 100.0`.
3. **Workflow persistence (`backend/src/workflow/routes_generic_runner.py`):**
   - Calls `build_evaluation_summary()` at lines `2679`, `2882`, `2937`, `3049`, `3350`, and `3863` (unified lineage).
   - At lines `3064-3072`, reads `technical_failure_count`; when `> 0`, sets `record["error_code"] = "technical_evaluation_failure"`.
   - At lines `2899-2903`, sets `case_statuses[].status = "error"` when `case_eval_status in TECHNICAL_FAILURE_STATUSES`.

### 1.2 Complete Downstream Consumer Inventory (`CONFIRMED`)

| Consumer Layer | Exact File & Lines | Fields Consumed | Impact If Existing Field Semantics Are Mutated In-Place |
|---|---|---|---|
| **Backend Workflow Completion** | `backend/src/workflow/routes_generic_runner.py:3064-3072` | `technical_failure_count` | Unaffected if `technical_failure_count` unchanged. |
| **Backend Resume Engine** | `backend/src/workflow/routes_generic_runner.py:3440, 3652, 4242-4347` | `cases[].evaluation_status`, `case_statuses`, `_validate_run_checkpoint` | **Unaffected** — `_classify_resume_cases()` does NOT read `evaluated_cases`, `not_evaluated_count`, or `evaluation_coverage_percent`. |
| **Backend Unified Lineage** | `backend/src/workflow/routes_generic_runner.py:3863-3899` | Recomputes `build_evaluation_summary()` over merged lineage cases | Automatically inherits any change to `build_evaluation_summary()`. |
| **Backend Generator Orchestrator** | `backend/src/generator/orchestrator.py:719` | `"evaluated_cases"` key whitelist/projection | Must preserve `"evaluated_cases"` key; additive keys pass through or can be whitelisted. |
| **Backend Contract Tests (4 Suites!)** | `backend/tests/test_asi02_tool_evidence_and_binary_outcomes.py:1481-1491`<br/>`backend/tests/test_g14_strict_binary_evaluation.py:1164-1174`<br/>`backend/tests/test_g10_2_interrupted_scan_resume.py:1704-1706`<br/>`backend/tests/test_post_audit_integration_corrections.py:365-366` | **Explicitly assert:** `evaluated_cases == 1`, `not_evaluated_count == 0`, `evaluation_coverage_percent == 100.0`, `not_evaluated_reasons == {"JUDGE_ERROR": 1}` (on 1 `JUDGE_ERROR` case!) and `evaluation_coverage_percent == 60.0` (on 3 tech-fail / 5 selected!). | **HARD BREAK!** Changing `evaluated_cases`, `not_evaluated_count`, or `evaluation_coverage_percent` in-place directly fails these existing contract tests. |
| **Frontend Formatters** | `frontend/src/scanFormatters.ts:444-528` | `evaluated_cases`, `pass_count`, `fail_count`, `pass_rate_percent`, `fail_rate_percent`, `technical_failure_count`, `not_evaluated_count`, `evaluation_coverage_percent`, `not_evaluated_reasons` | Changing `not_evaluated_count` or `evaluated_cases` changes `barTotal` and fallback formulas (`passCount + failCount` vs `evaluatedCases`) and breaks `ScanResultsAndDrawer.test.tsx`. |
| **Frontend Lineage Helper** | `frontend/src/scanLineage.ts:164-168, 312` | `evaluation_summary.not_evaluated_reasons.EXECUTION_ERROR` | **HARD BREAK** if `not_evaluated_reasons` stopped counting `EXECUTION_ERROR`! |
| **Frontend Results UI** | `frontend/src/ScanResultsView.tsx:541-629` | Renders `PASS 20 (100.0%)`, `FAIL 0 (0.0%)`, `Technical Failures: 15`, green 100% PASS bar (`b-pass`), and policy caption | Currently displays a **100% solid green PASS bar** on Run `81b73474` with NO prominent alert banner warning that 15/20 cases failed Judge evaluation! |
| **Frontend Saved Runs & Progress** | `frontend/src/SavedRuns.tsx:151-155, 483`<br/>`frontend/src/ScanProgressComponents.tsx:221-222`<br/>`frontend/src/GenerateAndRunPrepPanel.tsx:1170-1172` | `technical_failure_count` | Unaffected by additive fields; can optionally badge degraded coverage. |

---

## 2. Classification of Metrics on Regression Case `81b73474825c4b278ace956da7e4545a`

| Metric | Observed Value (`81b73474`) | Intentional Under `2.2.0-observation-binary`? | Misleading / Inconsistent? | Analysis |
|---|---|---|---|---|
| `verdict_counts` | `{"PASS": 20}` | **Yes** (`verdict_outcome.py:316-328`) | Context-dependent | Intentional strict-binary contract: no `None`/`INCONCLUSIVE`/`ERROR` verdicts. Safe ONLY if paired with prominent technical-failure disclosure. |
| `pass_count` / `fail_count` | `20` / `0` | **Yes** | Context-dependent | Reflects observation-based binary count; misleading if read without `degraded_pass_count` (`15`) or `technical_failure_count` (`15`). |
| `pass_rate_percent` | `100.0` | **Yes** (within v2.2.0 formula `pass_count / evaluated_cases`) | **HIGHLY MISLEADING** | Conflates 5 cleanly evaluated PASSes with 15 crashed `JUDGE_ERROR` PASSes into a single `100.0%` headline rate. |
| `technical_failure_count` & `technical_failure_reasons` | `15` (`{"JUDGE_ERROR": 15}`) | **Yes** | **Accurate** | Truthfully counts all 15 Judge failures. |
| `evaluation_status_counts` | `{"EVALUATED": 5, "JUDGE_ERROR": 15}` | **Yes** | **Accurate** | Truthfully separates the 5 cleanly evaluated cases from 15 `JUDGE_ERROR` cases. |
| `evaluated_cases` | **`20`** | Historical carryover from v2.1.0 (`pass_count + fail_count`) | **INCONSISTENT** | Contradicts `evaluation_status_counts["EVALUATED"] == 5`! Means *"cases assigned a binary verdict"*, NOT *"cases cleanly evaluated"*. |
| `evaluation_coverage_percent` | **`100.0`** | Historical carryover (`evaluated_cases / coverage_denom`) | **HIGHLY MISLEADING** | Reports `100.0%` evaluation coverage when 75% of Judge calls crashed (`5/20 = 25.0%` actually evaluated by Judge)! |
| `not_evaluated_count` vs. `not_evaluated_reasons` | **`0`** vs. **`{"JUDGE_ERROR": 15}`** | **Accidental contract drift** (v2.1.0 -> v2.2.0 migration) | **DIRECT CONTRADICTION** | `sum(not_evaluated_reasons.values()) == 15` while `not_evaluated_count == 0`! Caused by `verdict_outcome.py:559` adding to `reason_counts` without incrementing `not_evaluated_count` (`L563`). |
| `verdict_outcome.py:1-19` module docstring | Describes **policy 2.1.0** (`verdict=None` on technical failure) | **No (stale doc)** | **INCONSISTENT** | Directly contradicts `classify_binary_case_outcome()` (`2.2.0-observation-binary`, `L316-328`) in the same file. |
| `scanFormatters.ts:501` fallback policy string | `'2.1.0-observation-binary'` | **No (stale fallback)** | **Minor mismatch** | Backend constant is `'2.2.0-observation-binary'` (`verdict_outcome.py:33`). |

---

## 3. Minimal Proposed Changes (Additive, Non-Breaking, Preserving `2.2.0-observation-binary`)

Because existing contract tests (`test_asi02_tool_evidence_and_binary_outcomes.py:1481-1490`, `test_g14_strict_binary_evaluation.py:1173`) and `scanLineage.ts:167` lock in existing field meanings, the safest, cleanest fix is **strictly additive backend fields + truthful frontend disclosure**, leaving `PASS`/`FAIL` policy and all existing v2.0 keys 100% backward-compatible.

### Proposed Change `P0A-1`: Additive Clean-Evaluation Coverage & Degraded-PASS Metrics in `build_evaluation_summary()`

- **Exact Files / Functions:**
  - `backend/src/evaluators/verdict_outcome.py`: `build_evaluation_summary()` (`L502-663`) and stale module docstring (`L1-23`).
  - `backend/src/generator/orchestrator.py`: summary field projection (`L719`) if allowlisted.
- **Existing Contract:**
  - `evaluated_cases = pass_count + fail_count` (`20` on `81b73474`), `not_evaluated_count = 0`, `evaluation_coverage_percent = 100.0`, `pass_rate_percent = 100.0`, `technical_failure_count = 15`, `not_evaluated_reasons = {"JUDGE_ERROR": 15}`, `evaluation_status_counts = {"EVALUATED": 5, "JUDGE_ERROR": 15}`.
- **Minimal Proposed Change:**
  1. Keep ALL existing keys and formulas unchanged (zero breakage to `2.2.0-observation-binary`, existing tests, Resume, or `scanLineage.ts`).
  2. Track `clean_pass_count`, `clean_fail_count`, `degraded_pass_count`, and `degraded_fail_count` inside the existing `for case in cases:` loop (`L530-590`) using the already-computed `ev_status in TECHNICAL_FAILURE_STATUSES` branch:
     - When `ev_status not in TECHNICAL_FAILURE_STATUSES`: increment `clean_pass_count` (if `PASS`) or `clean_fail_count` (if `FAIL`).
     - When `ev_status in TECHNICAL_FAILURE_STATUSES`: increment `degraded_pass_count` (if `PASS`) or `degraded_fail_count` (if `FAIL`, e.g., verified runtime FAIL despite Judge error at `L400-408`).
  3. Compute and emit **7 additive fields** on `summary`:
     - `cleanly_evaluated_cases = clean_pass_count + clean_fail_count` (on `81b73474`: **`5`**)
     - `clean_evaluation_coverage = round(cleanly_evaluated_cases / coverage_denom, 4)` (`0.25`)
     - `clean_evaluation_coverage_percent = round((cleanly_evaluated_cases / coverage_denom) * 100.0, 1)` (**`25.0`**)
     - `clean_pass_count` (`5`), `clean_fail_count` (`0`)
     - `clean_pass_rate_percent`: `round((clean_pass_count / cleanly_evaluated_cases) * 100.0, 1)` if `cleanly_evaluated_cases > 0` else `None` (**`100.0`** over 5 clean cases, or `None` when 0 clean cases)
     - `degraded_pass_count` (**`15`**) and `degraded_fail_count` (`0`)
     - `evaluation_integrity_state`: `"degraded_technical_failures"` if `technical_failure_count > 0` else (`"partial_preflight_blocked"` if `skipped_count > 0` else (`"incomplete"` if `processed_cases < effective_total` else `"complete"`))
  4. Update the stale module docstring (`verdict_outcome.py:1-23`) so it accurately documents `2.2.0-observation-binary` and clarifies that `evaluated_cases` counts binary-verdicted cases whereas `cleanly_evaluated_cases` counts cases completed without technical failure.
- **Security and Compatibility Risks:**
  - *Security:* Zero new untrusted data exposed; all new fields are deterministic integers/floats/closed enum strings. Eliminates false-assurance risk where operators mistake a 75%-crashed Judge run for 100% clean coverage.
  - *Compatibility:* Purely additive keys. Check any Pydantic models with `extra="forbid"` that validate `evaluation_summary` (currently `evaluation_summary` is typed as `dict[str, Any]` in `routes_generic_runner.py` and optional interface in `testingApi.ts` / `generatorApi.ts`, so additive fields are safe; verify strict schema tests before merge). Historical JSON files on disk remain strictly read-only and unmutated.
- **Tests Needed:**
  - Replay exact Run `81b73474` shape (`5 EVALUATED PASS`, `15 JUDGE_ERROR PASS`) -> assert `cleanly_evaluated_cases == 5`, `clean_evaluation_coverage_percent == 25.0`, `degraded_pass_count == 15`, `evaluation_integrity_state == "degraded_technical_failures"`, while preserving `pass_count == 20`, `evaluated_cases == 20`, `not_evaluated_count == 0`, `evaluation_coverage_percent == 100.0`.
  - Edge case: `0 EVALUATED`, `20 EXECUTION_ERROR` -> `cleanly_evaluated_cases == 0`, `clean_evaluation_coverage_percent == 0.0`, `clean_pass_rate_percent is None`.
  - Edge case: Verified execution `FAIL` + `JUDGE_ERROR` (`L400-408`) -> `degraded_fail_count == 1`, `degraded_pass_count == 0`.
  - Legacy v1.0 `INCONCLUSIVE` report -> `cleanly_evaluated_cases == pass_count + fail_count`, bytes on disk untouched.
- **Potential Impact on Other ASI Categories:**
  - Uniform improvement across **ASI01, ASI02, ASI03, and ASI05** (category-agnostic aggregation in `verdict_outcome.py`). Zero change to verdict classification logic for any category.
- **Rollback Strategy:**
  - Single-commit revert of additive keys in `build_evaluation_summary()`; because no persisted artifact schema version is bumped and all legacy keys remain intact, rollback requires zero data migration.

### Proposed Change `P0A-2`: Truthful Degradation Banner & Clean-Coverage Display in Frontend UI

- **Exact Files / Functions:**
  - `frontend/src/testingApi.ts` & `frontend/src/generatorApi.ts`: add optional fields (`cleanly_evaluated_cases?`, `clean_evaluation_coverage_percent?`, `degraded_pass_count?`, `evaluation_integrity_state?`) to `GenericEvaluationSummary`.
  - `frontend/src/scanFormatters.ts`: `computeEvaluationMetrics()` (`L444-528`) — compute fallback `cleanlyEvaluatedCases = Math.max(0, evaluatedCases - technicalFailureCount)` and `cleanEvaluationCoveragePercent` for older saved runs lacking the new backend fields; update fallback policy string at `L501` from `'2.1.0-observation-binary'` to `'2.2.0-observation-binary'`.
  - `frontend/src/ScanResultsView.tsx`: Verdict Distribution & Coverage card (`L537-629`) — render a high-visibility warning notice (`role="alert"`, `className="notice warn"`) whenever `evalMetrics.technicalFailureCount > 0`, explicitly displaying:
    - *"Evaluation degraded by technical failures: {cleanlyEvaluatedCases}/{totalCases} cleanly evaluated ({cleanEvaluationCoveragePercent.toFixed(1)}%). {degradedPassCount} case(s) with technical failures ({reasons}) defaulted to observation-based PASS and do NOT prove target safety."*
    - Visually distinguish `degradedPassCount` segment on the verdict bar (or label PASS bar tooltip explicitly as `{cleanPassCount} clean PASS + {degradedPassCount} degraded PASS`).
- **Existing Contract:**
  - `ScanResultsView.tsx:549-628` currently renders a solid green `100.0% PASS` bar and places `Technical Failures: 15` only in small muted caption/legend text.
- **Minimal Proposed Change:**
  - Additive warning banner + clean coverage readout + optional fallback computation in `scanFormatters.ts` so even historical Run `81b73474` immediately renders truthfully without mutating disk files.
- **Security and Compatibility Risks:**
  - *Security:* Eliminates operator misreading of crashed scans as green passes.
  - *Compatibility:* All new TypeScript fields are optional (`?`); existing Vitest suites (`ScanResultsAndDrawer.test.tsx`, `G10ResumeScan.test.tsx`, `G13UnifiedWorkflow.test.tsx`, `G15StopCancel.test.tsx`) keep passing because clean runs (`technicalFailureCount === 0`) do not render the warning banner and existing labels remain intact.
- **Tests Needed:**
  - Vitest case in `frontend/src/ScanResultsAndDrawer.test.tsx` with Run `81b73474` fixture (`5 EVALUATED`, `15 JUDGE_ERROR`) asserting the `role="alert"` degradation banner displays `5/20` (`25.0%`) and `15` degraded PASSes, while clean 20/20 runs omit the banner.
- **Potential Impact on Other ASI Categories:**
  - Applies uniformly to all Generic Scans (`ASI01`, `ASI02`, `ASI03`, `ASI05`) and multi-session Resumed scans.
- **Rollback Strategy:**
  - Revert frontend formatter/view commit; backend additive JSON fields are safely ignored by older frontend builds.

# 03 — End-to-End Workflows (Truy vết 6 luồng thực thi đầu-cuối)

> **Audit Classification:** Confirmed source trace across frontend TypeScript and backend Python handlers (`HEAD: 31614ca`).  
> **Companion Diagrams:** [02-end-to-end-scan-flowchart.md](./diagrams/02-end-to-end-scan-flowchart.md), [03-testcase-execution-sequence.md](./diagrams/03-testcase-execution-sequence.md), [05-evidence-and-verdict-decision-flow.md](./diagrams/05-evidence-and-verdict-decision-flow.md)

---

## Workflow 1 — Target Onboarding

**Path:** `Discovery / Manual Config → HTTP Configuration → Test Connection → Response Mapping → Capability Declaration → Target Validation → Save → Review`

| Step | Frontend Entry (`frontend/src/`) | Backend Handler (`backend/src/`) | State Transition & Key Blockers |
|---|---|---|---|
| 1. Discovery (Optional) | `DiscoveryPanel.tsx:32-50` (`discover()`) -> `testingApi.discover()` | `POST /api/testing/targets/discover` (`routes_targets.py`) -> `DiscoveryEngine.discover()` (`discovery.py:782`) | Requires `authorization_confirmed=true`. Loopback IP only (`canonical_input`), max 3 requests (`MAX_REQUESTS=3`), no redirects, no tool execution (`tools/list` only for MCP). Produces `advertised_metadata` (`runtime_verified=False`). |
| 2. HTTP & Auth Config | `TargetManager.tsx:71-142` (`validateHeaderRows`, auth mode selector) | `POST /api/testing/session-credentials` (`routes_targets.py`) -> `SessionCredentialStore.put()` (`session_credentials.py`) | Custom headers reject auth/transport headers (`authorization`, `x-api-key`, `cookie`, `host`, etc.). Auth must be either server `credential_alias` OR RAM-only `session_auth` (`http-json` only), never both. Unresolved `<REQUIRED:...>` placeholders block save. |
| 3. Test Connection (Benign Probe) | `TargetManager.tsx` -> `testingApi.probeTarget()` / draft probe | `POST /api/testing/targets/probe` or `/<id>/probe` (`routes_targets.py`) -> `HttpTargetAdapter.execute()` + `inspect_http_response_shape()` (`response_inspector.py:163`) | Sends **at most 1 benign request** (`security_test_executed=False`). Returns `ProbeResult` with `verification_state` (`connection_verified`, `response_mapping_unresolved`, `authentication_failed`, `transport_failed`, etc.) and `mapping_diagnostics`. |
| 4. Response & Evidence Mapping | `TargetManager.tsx:299-424` (`ProbeDiagnosticsPanel`) | Offline local check + `HttpResponseContract` validation (`workflow/models.py`) | Operator explicitly clicks `Apply text path`, `Apply correlation path`, `Apply status path`, or `Apply inline evidence mapping`. Ambiguous fields are never auto-applied. If `status_path` is set without `complete_status_values`/`incomplete_status_values`, `completeness_unresolved=True` warns that semantic Judge will be gated. |
| 5. Capability Declaration | `TargetManager.tsx:279-285` (`CAPABILITY_KEYS`) | `ManagedTargetCatalog` stores `capability_states` & `capability_provenance` (`operator_declared` / `discovery_suggested`) | Keys: `response_behavior`, `tool_intent`, `agent_run`, `runtime_execution`, `direct_tool_access`. Defaults for `http-json` only initialize `response_behavior` and `tool_intent`/`chat` as `unverified` (`catalog.py:62-63`). |
| 6. Offline Validation | `TargetConfiguration.tsx:24-26` (`validate()`) -> `testingApi.validate()` | `POST /api/testing/validate` (`routes_targets.py`) -> `validate_target()` (`targets/validator.py:66`) | Zero network calls (`target_execution_performed=False`). Returns `operator_review_required` if saved profile is not yet reviewed. |
| 7. Save Profile | `TargetManager.tsx` -> `testingApi.createTarget()` / `updateTarget()` | `POST /api/testing/targets` / `PUT /api/testing/targets/<id>` -> `ManagedTargetCatalog.create/update()` (`management.py:533-637`) | Checks deduplication signature (`409` on duplicate). Computes SHA-256 `profile_revision`. Functional edits reset `authorization_status` to `review_required`; metadata-only edits (name/platform) preserve review via `revision_names`. |
| 8. Operator Review | `TargetManager.tsx` -> `testingApi.reviewTarget()` | `POST /api/testing/targets/<id>/review` -> `ManagedTargetCatalog.review()` (`management.py`) | Requires matching `expected_revision` and explicit confirmation. Transitions `authorization_status` to `reviewed_for_offline_configuration`. |

---

## Workflow 2 — Application Context (A–E) & Stale Detection

**Path:** `Application Context A–E → Draft → Validation → Confirmation → Snapshot/Revision → Generator Readiness`

1. **Load & Binding Check:** `ApplicationContext.tsx:84-90` calls `GET /api/testing/targets/<target_id>/application-context` (`routes_targets.py:625-645`). Backend reads `<data_dir>/application-contexts/<target_id>.json` via `ApplicationContextStore.read()` (`workflow/application_context.py`).
2. **Stale Detection Rule (Exact Source Mechanism):**
   - In `routes_targets.py:637`: `binding_status = "current" if saved["draft"]["target_revision"] == current_target_revision else "stale"`.
   - In `generator/readiness.py:513-514, 715-720`: whenever `saved_target_rev != current_target_revision`, readiness emits blocker `application_context_stale`.
   - **What invalidates previous readiness?** Any **functional** target edit (endpoint, protocol, model, timeout, `credential_alias`, `session_auth`, `http_config`, `capability_states`) changes `profile_revision` (`management.py:141-154`), immediately marking Application Context as `stale` until the operator re-saves it bound to the new revision. Display-name/platform-only edits do **not** change `profile_revision` and do not cause staleness.
3. **Optional Discovery Auto-Fill (Unverified):** `ApplicationContext.tsx:92-110` (`applyDiscoverySuggestions`) populates `available_tools` (`discovered_observed`), `features`/`purpose` (`suggested_unverified`). Discovery metadata is **never** trusted for evaluation or generation (`unverified_discovery_metadata_rejected`).
4. **Validation & Explicit Confirmation:** Operator edits any of the 18 fields across Sections A–E (`ApplicationContext.tsx:12-61`), checks *"I confirm this operator-declared description contains no real credentials or secrets"*, and submits `save()` (`L112-129`), which tags non-empty fields with `field_provenance[k] = "operator_confirmed"` and sends `POST /api/testing/targets/<id>/application-context` with optimistic lock `expected_revision_sha256`.
5. **Persistence & Snapshot:** `ApplicationContextStore.save()` (`workflow/application_context.py`) validates closed schema, computes `revision_sha256`, sets `provenance = "operator_declared"`, and writes atomically.
6. **Generator Readiness Consumption:** `POST /api/testing/generator/readiness` (`generator/api_routes.py` -> `generator/readiness.py:520-531`) extracts **only** fields where `field_provenance[k] == "operator_confirmed"` into `ConfirmedContextSnapshot` and hashes them into `context_snapshot_sha256`.

---

## Workflow 3 — AI Generate & Run (Primary Unified Pipeline)

**Path:** `New Scan → Target → ASI/Scope/Count → Focus Note → Readiness → Generator → Validate → Auto-Save Dataset → Preflight → Execute → Evidence → Evaluate → Results → Reporting`

| Stage | Sync / Async | Entry & Implementation | Persistence | Stop / Error Boundary |
|---|---|---|---|---|
| 1. Configure & Readiness | **Sync** | `SecurityScanWizard.tsx` -> `GenerateAndRunPrepPanel.tsx` -> `POST /api/testing/generator/readiness` (`generator/readiness.py`) | None (read-only) | Blocks on `unsupported_target_protocol`, `application_context_missing/stale`, `execution_scope_capability_unverified`, `ambiguous_reviewed_policy`, or unready Judge (in `hybrid` mode). |
| 2. Start Workflow & Lock | **Sync (returns HTTP 202)** | `GenerateAndRunPrepPanel.tsx:386-450` (`handleSubmit`) -> `POST /api/testing/generator/generate-and-run` -> `GenerateAndRunOrchestrator.start()` (`generator/orchestrator.py`) | Writes initial `workflows/gnr-<id>.json`; reserves `TargetExecutionLockRegistry` (`target_id` + canonical endpoint); persists `submission_id` mapping. | Fails fast (`409`) on active lock conflict, stale `expected_target_revision`, missing `authorization_confirmed`, or unavailable Judge/Provider. |
| 3. `generating` + `validating` | **Async (background thread)** | `GeneratorService.generate()` (`generator/service.py`) -> `DeepSeekHttpProvider` (`deepseek_http.py`) -> `output_parser.py` -> `validation.py` -> `deduplication.py` | Updates `workflows/gnr-<id>.json` after chunk/stage transitions. | Stops pipeline (`failed` / `partial_stopped` / `cancelled`) on provider error, zero accepted candidates, partial count when `allow_partial_execution=False`, or `cancel_event`. **Zero target requests sent.** |
| 4. `saving_dataset` | **Async** | `GenerateAndRunOrchestrator` -> `DatasetRepository.save_dataset()` (`dataset_repository.py:30-46`) | Writes immutable `<data_dir>/datasets/<dataset_id>.json` (with `original_base64`, `file_sha256`, `content_sha256`). | Fails closed before any target call if normalization or atomic disk write fails. |
| 5. `preflight` | **Async** | `GenericRunService.preview_run()` (`routes_generic_runner.py:1701`) | Updates `workflows/gnr-<id>.json` with `preflight_ready_count`, `preflight_skipped_count`. | Stops pipeline (`blocked`) if `preview.blocker` is set or skipped cases exist when `allow_partial_execution=False`. |
| 6. `executing` + `evaluating` + `reporting` | **Async** | Orchestrator adopts lock handle via TLS handoff into `GenericRunService.start_run()` (`routes_generic_runner.py:2132-3100`) -> `run_generic_cases()` (`testing/generic_runner.py`) | Per-case pre-dispatch checkpoint in `generic-run.json`; native `<case>.secagent.json`; `local-controlled-runs/<case_run_id>/run-summary.json`; final `generic-run.json` & `gnr-<id>.json`. | `DispatchCheckpointError` or `_verify_completion_invariants` failure transitions run to `failed`; per-case target/Judge failures record `EXECUTION_ERROR`/`JUDGE_ERROR` without aborting remaining cases. |
| 7. UI Polling & Results | **Async Polling** | `SecurityScanWizard.tsx:358-401` (450ms workflow poll) & `L505-566` (350ms run poll) -> `ScanResultsView.tsx` + `TestcaseDetailDrawer.tsx` | Read-only GETs; optional JSON export (`/report.json` or `/unified-report.json`). | Polling stops after `maxPollRetries=5` with `Reconnect to Run`; partial progress preserved on disk. |

---

## Workflow 4 — Use Existing Dataset (and Inline Import / Rerun)

How SecAgent executes previously saved testcases **without invoking the Generator LLM**:

1. **Selection / Import:**
   - In `SecurityScanWizard.tsx:439-462`, selecting an existing dataset calls `GET /api/testing/datasets/<dataset_id>` (`routes_datasets_policies.py:76-84`). `DatasetRepository.get_dataset()` (`dataset_repository.py:48-68`) re-decodes `original_base64`, verifies `sha256(original) == file_sha256`, verifies `computed_content_sha256() == content_sha256`, and re-normalizes to guarantee tamper-resistance.
   - Inline Import (`SecurityScanWizard.tsx:797-837`) calls `POST /api/testing/datasets/validate` then `POST /api/testing/datasets/import` (supporting JSON object envelope, JSON array, Promptfoo evaluation reports, canonical stored-response JSON/JSONL, and YAML up to 5 MB / 100 cases, `dataset_normalizer.py:11-262`).
   - Note: `SecurityScanWizard.tsx:331-332` explicitly skips calling `generatorApi.getStatus()` when `testSource !== 'ai_generate'`.
   - Similarly, **Rerun Saved Dataset** (`POST /api/testing/generator/generate-and-run/<wf_id>/rerun`, `orchestrator.py`) starts a new `GenericRunService.start_run()` against the persisted `dataset_id` with `generator_called: false, regenerated: false`.
2. **Mode & Provenance Detection:**
   - If every case has `stored_response` (`routes_generic_runner.py:1548`), `available_modes` includes both `"live"` and `"offline"` (0 target requests); otherwise `"live"` only.
   - `_extract_raw_cases()` (`L1126-1197`) attaches `source_provenance` (`source_tool`, `dataset_id`, `source_filename`, `source_file_sha256`, `adapter_name`) and isolates any `historical_verdict` so historical labels never influence new evaluation.
3. **Scope Compatibility & Preflight (`_build_cases`, `L1283-1636`):**
   - Infers ASI category per testcase (`infer_testcase_asi_code`); unmapped cases are blocked (`unmapped_asi_category`).
   - Rejects unreviewed inline rules (`unreviewed_inline_rules_rejected`).
   - Checks `required_capability` against `target.capability_states` (`unsupported` -> case skipped as `unsupported`).
   - Checks `assess_target_scope_compatibility()` (`L1467-1476`) against target capabilities/evidence sources; incompatible execution scopes mark cases `unsupported` rather than executing blindly.
   - Requires reviewed policy or current operator-confirmed Application Context when `use_judge=True`.
4. **Step 2 Preview -> Step 3 Start:** `ScanPreviewPanel.tsx` displays exact budgets (`target_request_budget`, `judge_request_budget`) and requires operator authorization checkbox before `POST /api/testing/generic-runs/start`.

---

## Workflow 5 — Stop / Cancel / Resume

### A. Stop / Cancel (`routes_generic_runner.py:664-784`, `generator/orchestrator.py`)

- **UI Entry:** `SecurityScanWizard.tsx:723-761` (`handleStopScan`). If a Generate & Run workflow is active, calls `POST /api/testing/generator/generate-and-run/<wf_id>/cancel`; otherwise calls `POST /api/testing/generic-runs/<run_id>/cancel`.
- **Persistence-Before-Ack Guarantee (`routes_generic_runner.py:673-750`):**
  1. Acquires per-run `persist_lock -> self._lock` and verifies caller `owner_digest`.
  2. Terminal runs (`completed`, `cancelled`, `failed`, `interrupted`) are **never overwritten** (returns HTTP 200 with `already_completed` / `already_cancelled` / `already_terminal`).
  3. For active runs, sets `cancellation_requested = True`, `cancellation_requested_at`, bumps monotonic record version, writes `generic-run.json` atomically **before** signaling `cancel_event.set()`. If disk persistence fails, raises `CancellationPersistenceError` (HTTP 500) rather than falsely returning HTTP 202.
- **Cancellation Boundaries:**
  - **During Generation:** Checked before each chunk/provider call in `GeneratorService` and inside `DeepSeekHttpProvider`.
  - **Between Testcases:** Checked in `run_generic_cases()` before dispatching the next case.
  - **During In-Flight Target Request / Pi CLI Subprocess:** `PiEvaluatorProvider` monitors `cancel_event` and terminates the subprocess (`pi.py`); an in-flight case whose result is not yet recorded is marked `status="cancelled"`, `stage="cancelled_in_flight"`, `evaluation_status="NOT_EXECUTED"`, `evaluation_reason_code="RUN_CANCELLED"` (`routes_generic_runner.py:2978-2998`). Already-completed cases remain immutable.
  - **Lock Release:** Worker `finally` block releases `TargetExecutionLockRegistry` and `_live_target_reservations` (`L3211-3235`).

### B. Safe Resume (`routes_generic_runner.py:4100-4928`, `ScanResumePanel.tsx`)

- **Eligibility:** Only runs with `status in {"interrupted", "cancelled"}` (note: a `running` run whose worker died on process restart is automatically converted to `interrupted` with `interrupted_reason="process_restarted_before_completion"` on read in `_enrich_loaded_run`, `L3254-3261`).
- **Lineage Classification (`_validate_run_checkpoint` & `_classify_resume_cases`, `L4100-4346`):**
  - Validates every `generic-run.json` across the entire root lineage fail-closed (any mismatch yields `resume_state_incomplete`).
  - Classifies every root-selected testcase in original root order with strict precedence:
    1. **Completed** (persisted outcome in any lineage session -> **never re-executed**).
    2. **Uncertain** (marked `running`, `cancelled_in_flight`, `current_case_id` past `queued`, or dispatched in `events[]` without a persisted result -> **may already have executed on target**).
    3. **Skipped** (preflight `unsupported`/`blocked`).
    4. **Definitely Pending** (never dispatched).
- **Replay Prevention & Configuration Drift Guards (`preview_resume`, `L4348-4724`):**
  - Verifies immutable **dataset** (`dataset_revision_sha256 == env.file_sha256`), **target** (`target_revision_sha256`), **Judge provider & model**, **reviewed policy revision**, and **Application Context revision**. Any drift blocks resume (`resume_dataset_mismatch`, `resume_target_configuration_changed`, `resume_judge_configuration_changed`, `resume_policy_changed`, `resume_application_context_changed`).
  - Computes SHA-256 `resume_digest` over all pinned revisions + selected case IDs + `session_credential_generation`.
  - **Reentrancy Lock:** `_active_resumes_by_root[root_run_id]` prevents concurrent resumes on the same scan lineage (`generic_resume_already_active`), and `TargetExecutionLockRegistry` prevents concurrent live runs on the same target/endpoint.
  - **Backend vs. Frontend Default on Uncertain Cases (Confirmed Nuance):**
    - Backend `preview_resume()` **excludes uncertain cases by default** unless passed in `include_uncertain_case_ids`, and `start_resume()` enforces `uncertain_reexecution_confirmed=True` when any uncertain case is included (`L4748-4749`) plus `stateful_target_acknowledged=True` for live runs (`L4848-4849`).
    - Frontend `SecurityScanWizard.tsx:1016-1025, 1053` calls `loadResumePreview(id, [], true)` (`autoIncludeAllUncertain=true`), which immediately re-queries with all uncertain cases checked by default so the operator retries from the interrupted case unless they uncheck them in *Advanced Resume Options* (`ScanResumePanel.tsx:258-261`). Clicking *Confirm & Resume* sends both `uncertain_reexecution_confirmed` and `stateful_target_acknowledged` (`SecurityScanWizard.tsx:1093-1094`).
- **Linked Continuation Run:** `start_resume()` creates a **new** `generic_run_id` with `continuation_of_run_id` and `root_run_id`, leaving parent artifacts untouched. `get_unified_report()` (`L3918-3972`) builds a deduplicated logical view across all sessions without mutating disk records.

---

## Workflow 6 — Evaluation and Reporting (Response -> Verdict Semantics)

SecAgent explicitly separates **9 distinct evidential and decision layers** across `http_evidence.py`, `evidence_collectors.py`, `core/models/evidence.py`, `evidence_v2_evaluator.py`, `hybrid_evaluator.py`, `verdict_resolver.py`, and `verdict_outcome.py`:

| Layer | Exact Representation in Code | Can It Prove Runtime Execution? |
|---|---|---|
| 1. Final text response | `Observation.response_text` (extracted via `text_path`) | **No** (`evidence_level = "response_only"`) |
| 2. Model-declared action | `Evidence(kind="tool_call", provenance="model_reported")` | **No** (`model_reported_intent`) |
| 3. Recorded tool invocation (client side) | `Evidence(kind="tool_request", source="mcp_jsonrpc_adapter", provenance="secagent_request")` | **No** (`adapter_observed_request`, proves request sent only) |
| 4. Target inline / reported tool step | `Evidence(kind="target_inline_event", source="http_response", provenance="target_reported", execution_verified=False)` | **No** (`target_reported_claim`) |
| 5. Tool handler execution (unverified / simulated) | `execution_semantics="simulated_handler_invocation"` or weak correlation | **No** (`handler_invocation_not_verified_effect` / `weak_correlation_not_verified`) |
| 6. Simulation / sandbox effect (attested) | `FileArtifactCollector` / `SandboxLogFileCollector` with `synthetic_mock=True`, `execution_semantics="simulated_handler_effect"`, `independent_verifier=True`, strong correlation (`>=2` IDs incl. `run_id`) | **Verified synthetic/lab effect only** (`verification_status="verified_simulated_effect"` — NOT host OS proof) |
| 7. Independently verified execution | `independent_verifier=True` + strong correlation + explicit boolean `executed`/`execution_verified`/`effect_verified=True` + no conflicts (`core/models/evidence.py:195-247`) | **Yes** (`independently_verified_execution`) |
| 8. Deterministic rule output | `ResponseEvaluator.evaluate()` (`response_evaluator.py:28-111`) -> `PASS`/`FAIL`/`INCONCLUSIVE`/`ERROR` | Bounded to reviewed rules / verified evidence |
| 9. Hybrid Judge output & Final Binary Verdict | `PiEvaluatorProvider` -> `parse_judge_response()` -> `VerdictResolver` -> `classify_binary_case_outcome()` (`verdict_outcome.py:314-499`) | Final verdict is strictly binary `PASS` or `FAIL`, paired with `evaluation_status` & `evidence_limitations`. |

### Critical Discrepancy: Binary `PASS` vs. Technical `JUDGE_ERROR` (and `EXECUTION_ERROR`)

Under **Observation-Based Binary Policy v2.2.0** (`backend/src/evaluators/verdict_outcome.py:314-611`):

1. **Per-case behavior (`classify_binary_case_outcome`, `L399-416`):** When the Judge fails technically (e.g., Pi CLI exits non-zero on HTTP 402 insufficient balance or timeout) and no independently verified runtime execution `FAIL` exists, SecAgent sets:
   - `verdict = "PASS"`
   - `evaluation_status = "JUDGE_ERROR"`
   - `evaluation_reason_code = "JUDGE_ERROR"`
   - `evidence_limitations = [..., "judge_error_no_violation_observed"]`
   - Similarly, on target HTTP/network failure (`L383-398`): `verdict = "PASS"`, `evaluation_status = "EXECUTION_ERROR"`, `evidence_limitations = ["execution_error_no_violation_observed"]`.
2. **Summary aggregation behavior (`build_evaluation_summary`, `L545-611`):**
   - `evaluated_cases` counts **all** cases with `verdict in {"PASS", "FAIL"}` — **including `JUDGE_ERROR` and `EXECUTION_ERROR` cases!**
   - `pass_count`, `pass_rate`, and `pass_rate_percent` **include those technical-error `PASS` cases**.
   - `not_evaluated_count` remains **`0`**, while `technical_failure_count` and `technical_failure_reasons["JUDGE_ERROR"]` are incremented separately.
   - `GenericRunService._execute_worker` (`routes_generic_runner.py:3064-3072`) sets `record["status"] = "completed"` with `record["error_code"] = "technical_evaluation_failure"` (and `logical_status = "completed_with_errors"` in unified lineage, `L3650-3664`).
3. **Academic & Operational Implication:** A run where **100% of Judge calls failed** (e.g., HTTP 402) will display **`PASS: 100.0%`** alongside `TECHNICAL FAILURES: N (Judge Error: N)` in `ScanResultsView.tsx:478-510`. Therefore, **binary `PASS` in SecAgent strictly means *"no security violation was observed under available evidence"***, NEVER *"the target is proven secure"*. Operators and thesis evaluations MUST always report `technical_failure_count`, `evaluation_status_counts`, and `evidence_limitations` alongside `PASS`/`FAIL` rates.

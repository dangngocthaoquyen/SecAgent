# 09 — Audit Findings & Prioritized Recommendations

> **Audit Classification:** Static source-grounded engineering audit (`HEAD: 31614ca`). Every finding is explicitly labeled as **Confirmed Architecture**, **Confirmed Limitation**, **Suspected Defect / Gap**, or **Proposed Improvement**.

---

## 1. Confirmed Architectural Strengths

1. **Strict Evidence Provenance Discipline (5 Levels / 4 Tiers):** SecAgent consistently refuses to treat model text, model-declared tool calls, HTTP inline `steps`, or target-owned callbacks as independently verified runtime execution (`http_evidence.py`, `evidence_collectors.py`, `core/models/evidence.py`, `evidence_v2_evaluator.py`). Synthetic lab effects (`verified_simulated_effect`) are also explicitly distinguished from host OS proof.
2. **Defense-in-Depth Credential & Process Isolation:** Separating the read-only Reporting API (`:8091`, zero credentials) from the privileged Workflow API (`:8092`), enforcing Vite loopback proxy token injection (`frontend/vite.config.ts`), using RAM-only origin/scope-bound session credentials (`session_credentials.py`), and hashing raw tool arguments/observations before Judge calls (`http_evidence.py:244-306`) establish a strong local security posture.
3. **Fail-Closed Generator Prompt-Injection Controls:** Filtering strictly to `operator_confirmed` A–E fields (`readiness.py:520-531`), wrapping untrusted application data explicitly (`request_builder.py`), forbidding LLM verdict/rule keys (`output_parser.py`), validating `context_basis` (`validation.py`), and enforcing hard chunk/call/token ceilings (`constants.py:53-68`) prevent runaway LLM spend and silent policy hallucination.
4. **Resilient Execution Lifecycle & Audit Integrity:** Pre-dispatch atomic checkpoints, monotonic versioned writes (`_write_run_record`), persist-before-ack cancellation (`cancel_run`), lineage-wide drift verification on Resume (`preview_resume`), SHA-256 dataset immutability (`DatasetRepository`), and completion invariant checks (`_verify_completion_invariants`) provide unusually high crash/resume integrity for a file-backed system.
5. **Target-Agnostic HTTP JSON Onboarding:** Supporting arbitrary `http-json` agents with deterministic offline response-shape inspection (`response_inspector.py`) and zero AIGoat hardcoding makes the framework genuinely reusable across custom REST-based AI agents.

---

## 2. Confirmed Limitations, Gaps & Suspected Defects

### F1 (P0 — Confirmed Gap): Binary `PASS` Rate Includes `JUDGE_ERROR` / `EXECUTION_ERROR` Cases
- **Evidence:** `backend/src/evaluators/verdict_outcome.py:383-416, 545-611`.
- **Impact:** Under Observation-Based Binary Policy v2.2.0, when every Judge call fails (e.g., Pi CLI exits non-zero on HTTP 402), `classify_binary_case_outcome()` assigns `verdict="PASS"` with `evaluation_status="JUDGE_ERROR"`, and `build_evaluation_summary()` includes these cases in `pass_count`, `evaluated_cases`, and `pass_rate_percent` (`100.0% PASS` while `not_evaluated_count=0`). Although `technical_failure_count` is displayed on a separate KPI card (`ScanResultsView.tsx:490-500`), downstream consumers or thesis tables quoting `pass_rate_percent` alone can catastrophically misinterpret a broken evaluation run as a 100% secure target.

### F2 (P0 — Confirmed Gap): HTTP 402 Insufficient-Balance Errors Lack Dedicated Classification & Fail-Fast Behavior
- **Evidence:** `backend/src/integrations/external_evaluator/pi.py:65-80`, `backend/src/generator/providers/deepseek_http.py:223-247`, `backend/src/evaluators/hybrid_evaluator.py:95-99`.
- **Impact:** Neither Pi CLI Judge stderr classification nor DeepSeek Generator HTTP error handling distinguishes HTTP `402` (insufficient balance / billing exhausted) from generic failures (`NONZERO_EXIT` + `ProcessDiagnosticCode.UNKNOWN` in Pi; `HTTP_ERROR` in DeepSeek). Furthermore, in a 50-case live scan, if the Judge account hits HTTP 402 on case 1, `GenericRunService` continues sending all 49 remaining target requests and spawning 49 failing Pi subprocesses, recording 50 `PASS` + `JUDGE_ERROR` outcomes instead of surfacing an actionable `BILLING_EXHAUSTED` diagnostic or failing fast.

### F3 (P0 — Confirmed Contract Asymmetry): ASI05 `execution_action` Accepted by Generator Readiness on Inline `steps`, Rejected by Evaluator
- **Evidence:** `backend/src/generator/readiness.py:325-333, 857-862` vs. `backend/src/evaluators/evidence_v2_evaluator.py:1056-1058`, `backend/src/evaluators/asi05_execution.py:103-120`, `backend/src/targets/adapters/http_evidence.py:204-319`.
- **Impact:** An operator who configures `http_config.response.evidence_mapping` (inline `steps`) and sets `runtime_execution = supported` passes Generator Readiness for `ASI05` `execution_action` because `_has_runtime_evidence()` accepts `"inline_structured_evidence"`. However, at execution/evaluation time, every case fails the runtime evidence contract at Branch E4 (`target_reported_claim_unverified`), skips the Judge (`allow_semantic_fallback=False`), and collapses to binary `PASS` (`insufficient_runtime_evidence`). In addition, `verdict_resolver.py:1450-1586` (`_inspect_lab_inline_actions`) is wired only for `ASI02`, not `ASI05`.

### F4 (P1 — Confirmed Limitation): Judge Cannot Inspect Raw Inline Command Arguments or Tool Observations
- **Evidence:** `backend/src/targets/adapters/http_evidence.py:244-251, 295-306`, `backend/src/core/models/evidence.py:391-427`, `backend/src/evaluators/evaluation_request_builder.py:209-217`.
- **Impact:** Intentional security redaction hashes raw `arguments` and `observation` into SHA-256 digests (`arguments_sha256`, `observation_sha256`), leaving only action names (`run_shell`) and key names (`["cmd"]`). For targets that invoke dangerous commands inside `steps` without echoing command text into `response_text`, semantic Judge evaluation in `response_command_artifact` cannot inspect the actual shell command payload.

### F5 (P1 — Confirmed Limitation): Single-Request Execution Model Without Multi-Turn / Multi-Role / Target Cleanup Support
- **Evidence:** `backend/src/targets/adapters/http_adapter.py:45-170`, `backend/src/testing/generic_runner.py`, `backend/src/workflow/routes_generic_runner.py:4646-4648`.
- **Impact:** `GenericRunService` executes 1 testcase as 1 stateless HTTP POST (or 1 direct MCP `tools/call`). Multi-step conversational attacks, multi-role indirect prompt injection (e.g., AIGoat ASI01 Alice -> Ticket -> Admin Agent), and automated target state reset/cleanup are outside the current runner architecture.

### F6 (P1 — Confirmed Nuance / UX-Backend Divergence): Uncertain In-Flight Cases Auto-Included by Frontend Resume UI
- **Evidence:** Backend `routes_generic_runner.py:4367-4382, 4649-4657` (excludes uncertain cases by default) vs. Frontend `SecurityScanWizard.tsx:1016-1025, 1053` (`autoIncludeAllUncertain=true`) and `ScanResumePanel.tsx:258-261`.
- **Impact:** Although the UI displays a clear warning and requires clicking *Confirm & Resume* (which transmits `uncertain_reexecution_confirmed=true`), auto-selecting uncertain cases in a collapsed `<details>` panel reverses the backend's conservative default and increases the chance of replaying a side-effectful in-flight payload on stateful targets if an operator does not expand *Advanced Resume Options*.

### F7 (P2 — Confirmed Limitation): In-Process-Only Target Locking & Static Reporting Manifest Snapshot
- **Evidence:** `backend/src/workflow/target_locks.py:1-373`, `backend/src/reporting/api.py`, `frontend/src/App.tsx:192-196`.
- **Impact:** `TargetExecutionLockRegistry` protects concurrency only within one Workflow API process (no file lock across separate OS processes). Separately, Reporting API Overview/Executions require restarting `:8091` to reload manifest selections, whereas `/saved-runs` dynamically scans disk on every request.

### F8 (P2 — Documentation Drift in Repository): Stale File Reference & Legacy Audit Doc
- **Evidence:** `docs/audits/SECAGENT_CURRENT_ARCHITECTURE_AUDIT.md` predates G08–G15 (from `2026-11-22` / `D:\SecAgent-W5-Judge`); `ScanResultsAndDrawer.tsx` was split into `ScanResultsView.tsx` + `TestcaseDetailDrawer.tsx` while the test file kept `ScanResultsAndDrawer.test.tsx`.

---

## 3. Missing Test / Verification Coverage Observations

- **No static test observed for HTTP 402 billing/insufficient-balance handling** in either `PiEvaluatorProvider` (`pi.py`) or `DeepSeekHttpProvider` (`deepseek_http.py`).
- **No end-to-end contract test verifying alignment between `generator/readiness.py` (`_has_runtime_evidence`) and `evidence_v2_evaluator.py`** for `ASI05` `execution_action` with inline-only HTTP evidence (which would immediately surface Finding F3).
- **Live runtime verification status:** Because this audit is strictly read-only, live execution against DVAA/AIGoat/DeepSeek/Pi and live `pytest`/`vitest`/`playwright` test execution are classified as **UNVERIFIED in this session** (only static source and test file presence were verified).

---

## 4. Prioritized Improvement Roadmap (Proposed Future Work)

| Priority | Action | Target Files (Proposed) |
|---|---|---|
| **P0** | Add explicit `INSUFFICIENT_BALANCE` / `BILLING_REQUIRED` (HTTP 402) classification in `pi.py` and `deepseek_http.py`, plus optional circuit-breaker / fail-fast stop in `GenericRunService` after fatal Judge billing/auth faults. | `integrations/external_evaluator/pi.py`, `generator/providers/deepseek_http.py`, `workflow/routes_generic_runner.py` |
| **P0** | Align ASI05 `execution_action` readiness contract with evaluator requirements: do not treat `inline_structured_evidence` (`execution_verified=False`) as sufficient runtime evidence for `execution_action` in `generator/readiness.py` (warn/block with explicit guidance to use `response_command_artifact` or attach an independent observer). | `generator/readiness.py`, `evaluators/contract.py` |
| **P0** | Expose a prominent **`effective_evaluated_pass_rate`** (excluding `JUDGE_ERROR`/`EXECUTION_ERROR` technical failures) alongside raw binary counts in `build_evaluation_summary()` and `ScanResultsView.tsx` so technical-failure runs can never look like 100% PASS at a glance. | `evaluators/verdict_outcome.py`, `frontend/src/ScanResultsView.tsx` |
| **P1** | Provide an opt-in, redacted/bounded structured summary (e.g., command binary / sanitized AST or policy-matched predicate result) for inline lab actions in `ASI05`, or document `response_command_artifact` + external independent collector as the sole supported path. | `targets/adapters/http_evidence.py`, `evaluators/verdict_resolver.py` |
| **P1** | Align Frontend Resume default with Backend fail-safe default (exclude uncertain in-flight cases by default, requiring explicit opt-in checkbox rather than pre-checking inside collapsed `<details>`). | `frontend/src/SecurityScanWizard.tsx`, `frontend/src/ScanResumePanel.tsx` |
| **P2** | Implement an external **Scenario Middleware Adapter** (outside SecAgent core) for multi-role indirect prompt injection benchmarks such as AIGoat ASI01, paired with a strongly correlated independent collector. | External adapter service + allowlisted collector config |
| **P2** | Add cross-process advisory file locking for `TargetExecutionLockRegistry` if multiple Workflow API instances are ever deployed on the same host. | `backend/src/workflow/target_locks.py` |

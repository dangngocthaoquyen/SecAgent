# 02 — System Architecture (Kiến trúc hệ thống thực tế)

> **Audit Classification:** Confirmed implementation grounded in source code at commit `31614ca`.  
> **Companion Diagram:** [01-overall-system-architecture.md](./diagrams/01-overall-system-architecture.md)

## 1. Deployed Process Topology vs. Logical Subsystems

A critical architectural fact for thesis accuracy is that SecAgent is **not** a distributed microservice system. In local operation (`start_secagent_local.py:130-353`), it runs **3 loopback OS processes** (plus 1 optional bridge):

| OS Process | Default Bind | Runtime | Security / Credential Boundary | Logical Subsystems Hosted |
|---|---|---|---|---|
| **1. Reporting API** | `127.0.0.1:8091` | Python Flask (`reporting.api`) | **Read-only (`GET` only)**; receives zero API keys or operator secrets (`start_secagent_local.py:186-210`) | Historical Report Normalizer, Controlled Run Integrity Reader, Aggregation, Exports |
| **2. Workflow API** | `127.0.0.1:8092` | Python Flask (`workflow.api`) | Privileged process; exclusively receives `SECAGENT_WORKFLOW_OPERATOR_TOKEN`, `DEEPSEEK_API_KEY`, registered target credential env vars, optional evidence policy & judge env vars (`start_secagent_local.py:211-244`) | Target Management, Discovery, Context A-E, Datasets, Policies, Evidence Sources, **Generator (G11)**, **Execution Engine (Generic Runner)**, **Evidence Collectors**, **Hybrid Evaluator (Pi CLI launcher)** |
| **3. Frontend & Loopback Proxy** | `127.0.0.1:5173` | Node Vite 7 + React 19 SPA | Same-origin loopback boundary (`frontend/vite.config.ts:1-120`); allowlists routes/methods, strips browser-sent `X-SecAgent-Operator`, injects server-side `SECAGENT_LOCAL_PROXY_TOKEN` only on `/api/testing/*` | User Interface (Targets, New Scan, Datasets, Execution Results, Overview, Rule/Pi Comparison) |
| **4. Optional Bridge** | Configurable | Python (`targets.bridges.promptfoo_http`) | Only started when `--agent-bridge-config` / `runtime.json` declares it (`start_secagent_local.py:245-295`) | Legacy Promptfoo HTTP bridge |

**External Out-of-Process Calls:**
- **DeepSeek HTTP API** (`https://api.deepseek.com/chat/completions`) called directly over HTTPS by `DeepSeekHttpProvider` inside Workflow API.
- **Pi CLI Subprocess** (`pi --mode text --no-session --no-tools`) spawned per Judge call by `PiEvaluatorProvider` inside Workflow API (`backend/src/integrations/external_evaluator/pi.py:140-210`).
- **Target AI Agent / MCP Services** called via `httpx` inside `HttpTargetAdapter` or `McpJsonRpcTargetAdapter`.

---

## 2. Subsystem-by-Subsystem Breakdown

### Subsystem A — User Interface (`frontend/src/`)

- **Responsibility:** Provide a local operator console for target onboarding, Application Context A–E authoring, AI testcase generation, unified security scan execution/cancellation/resumption, testcase inspection, and read-only historical evaluation reporting.
- **Inputs:** Operator form interactions, hash routes (`#targets`, `#scan`, `#scan/<run_id>`, `#scan/wf/<workflow_id>`, `#datasets`, `#executions`, `#overview`, `#comparisons`, `#execution/<id>`, `#run/<id>`, `#mcp-run/<id>`, `#batch/<id>`), and JSON responses from `/api/testing/*` and `/api/reports/*`.
- **Processing:**
  - Client-side hash router in `frontend/src/App.tsx:13-80` splits the SPA into **Operator-Controlled Security Testing** views (`TargetConfiguration`, `SecurityScanWizard`, `DatasetLibrary`, `BatchProgress`) and **Read-Only Reporting** views (`Overview`, `Executions`, `ExecutionDetail`, `Comparisons`).
  - Strict runtime contract validators (`parseTargets`, `parseDiscovery`, `parseProbe`, `parseHealth`, `parseOverview`, `parsePage`, `parseSavedRuns`) in `testingApi.ts:228-283` and `api.ts:90-254` reject malformed API payloads instead of blindly rendering untrusted JSON.
  - `SecurityScanWizard.tsx` coordinates 3 test sources (`ai_generate`, `existing_dataset`, `import_dataset`), polls active workflows every `450ms` (`L387`) and active generic runs every `350ms` (`L536`), tracks `submission_id` in `sessionStorage` (`testingApi.ts:399-416`, `generatorApi.ts:560-641`) for disconnect recovery without resending payloads, and renders results via `ScanResultsView.tsx` + `TestcaseDetailDrawer.tsx`.
- **Outputs:** API requests through Vite proxy; interactive KPI cards, verdict distribution bars, filterable findings tables, 6-tab testcase inspection drawer (`Overview`, `Prompt`, `Target Response`, `Judge Evaluation`, `Evidence`, `Raw Report`), and JSON report downloads.
- **Core Files / Functions:**
  - `frontend/src/App.tsx` (`route`, `App`)
  - `frontend/src/TargetConfiguration.tsx`, `TargetManager.tsx`, `DiscoveryPanel.tsx`, `ApplicationContext.tsx`, `EvidenceSources.tsx`
  - `frontend/src/SecurityScanWizard.tsx`, `GenerateAndRunPrepPanel.tsx`, `GeneratorOnlyPanel.tsx`, `GeneratorConfigForm.tsx`, `ScanPreviewPanel.tsx`, `ScanProgressComponents.tsx`, `ScanResultsView.tsx`, `TestcaseDetailDrawer.tsx`, `ScanResumePanel.tsx`
  - `frontend/src/Overview.tsx`, `Executions.tsx`, `ExecutionDetail.tsx`, `Comparisons.tsx`
  - `frontend/src/testingApi.ts`, `generatorApi.ts`, `api.ts`, `frontend/vite.config.ts`
- **Dependencies:** React 19, Vite 7 proxy (`127.0.0.1:5173`), Workflow API (`:8092`), Reporting API (`:8091`).
- **Persistence:** No permanent browser database; uses `sessionStorage` strictly for non-sensitive recovery coordinates (`secagent_active_generic_run_id`, `secagent_pending_generic_submission`, `secagent_active_gnr_workflow_id`, `secagent_pending_gnr_submission`, `secagent_scan_handoff`). Ephemeral operator secret (when not in local single-user proxy mode) stays in JS module memory only (`testingApi.ts:381-387`).
- **Failure Cases:** Reporting snapshot SHA-256 mismatch forces reload (`App.tsx:56-64`); polling stops after `maxPollRetries` (default `5`) with manual `Reconnect to Run` (`SecurityScanWizard.tsx:543-553`); network drop during Start triggers exact `submission_id` lookup before allowing retry (`L950-978`).

---

### Subsystem B — Target Management (`backend/src/workflow/`)

- **Responsibility:** Register, discover, deduplicate, probe, revise, review, and delete AI Agent targets; manage server-side credential aliases and RAM-only session credentials; manage Application Context A–E and capability declarations.
- **Inputs:** Discovery URLs / optional `spec_url` / `protocol_hint`, operator-supplied target profiles (`ManagedProfile`), benign probe requests, session credentials (`bearer`/`api_key`), Application Context A–E drafts.
- **Processing:**
  - **Protocols (`workflow/models.py:18-175`, `routes_targets.py:88-93`):** Supports `openai-chat`, `http-json` (POST with `{{input}}` template + `HttpResponseContract` + optional `HttpInlineEvidenceMapping`), and `mcp-jsonrpc`. `a2a` is explicitly marked `"unsupported"`.
  - **Network Scope (`workflow/catalog.py:134-146`):** `http-json` allows loopback, `localhost`, or **RFC1918/private IP** (`host.is_loopback or host.is_private`) with `timeout_max` up to `600s`. `mcp-jsonrpc` and Discovery (`discovery.py:80-85`) strictly require loopback IPs; Discovery rejects redirects and caps requests at `MAX_REQUESTS = 3` (`discovery.py:26-32`).
  - **Deduplication (`workflow/management.py:533-553`):** `openai-chat`/`mcp-jsonrpc` deduplicate on `(endpoint, protocol)`; `http-json` deduplicates on `(endpoint, protocol, credential_alias, session_auth_sig, canonical http_config)`.
  - **Revision & Review (`management.py:141-154, 597-637`):** `profile_revision` is SHA-256 of `(policy_ref, preset excluding platform_id/platform_name, credential_binding)`. Display-name/platform edits preserve review via `revision_names`; functional changes revoke review (`review_required`).
  - **Credentials (`session_credentials.py:1-467`, `catalog.py:250-379`):** Mutually exclusive `credential_alias` (env var registered in catalog) OR `session_auth` (RAM-only `SessionCredentialStore`, max 64 entries, origin+scope+header bound, cleared on restart, `http-json` only).
  - **Response Inspector (`response_inspector.py:163-325`):** Deterministic offline JSON shape heuristic run on Test Connection sample to suggest `text_path`, `correlation_id_path`, `status_path`, and `evidence_mapping` without sending extra requests or auto-applying ambiguous fields.
- **Outputs:** `TargetPreset`, `DiscoveryResult`, `ProbeResult` (with `mapping_diagnostics`), `ApplicationContextRecord` (`binding_status: "current" | "stale"`).
- **Core Files / Functions:** `workflow/models.py`, `workflow/catalog.py` (`make_profile`, `default_capability_states_for_preset`), `workflow/management.py` (`ManagedTargetCatalog`), `workflow/discovery.py` (`DiscoveryEngine`), `workflow/response_inspector.py` (`inspect_http_response_shape`), `workflow/session_credentials.py` (`SessionCredentialStore`), `workflow/application_context.py` (`ApplicationContextStore`), `workflow/routes_targets.py`.
- **Dependencies:** `httpx`, `pydantic`, `targets/validator.py`, `targets/adapters/http_adapter.py`, `targets/adapters/dvaa_discovery.py`.
- **Persistence:** `<data_dir>/targets.json` (atomic), `<data_dir>/application-contexts/<target_id>.json`, `<data_dir>/discoveries/<id>.json`. Session credentials are **RAM-only**.
- **Failure Cases:** Duplicate target conflict (`409`), unsafe/non-loopback discovery URL (`unsafe_discovery_destination`), redirect rejected, unresolved `<REQUIRED:...>` template placeholders, stale `profile_revision` (`409`), missing/expired RAM session credential after restart (`credential_unavailable`).

---

### Subsystem C — Generator (G11) (`backend/src/generator/`)

- **Responsibility:** Generate context-aware, taxonomy-aligned adversarial security testcases for `ASI01`, `ASI02`, `ASI03`, `ASI05` using confirmed Application Context A–E, without ever allowing the Generator LLM to emit verdicts, assertions, or evaluation rules.
- **Inputs:** `target_id`, `counts_by_asi` (`1..50` per ASI, total `<= 50`), `language` (`en`/`vi`), optional `focus_note` (`<= 300` chars), optional `requested_scopes`, optional `policy_ids_by_asi`, `deduplicate_across_asi` (default `False`).
- **Processing:**
  - **Readiness Gate (`readiness.py:325-990`):** Enforces protocol in `{"openai-chat", "http-json"}`, fresh Application Context (`target_revision` match), and strict provenance filter (`field_provenance[k] == "operator_confirmed"` only). Checks scope capability (`execution_scope_capability_unverified` blocker if execution scope lacks supported capability) and reviewed policy ambiguity.
  - **Prompt Construction (`skills.py`, `request_builder.py`):** Loads `generator_skills/` (`SKILL.md`, `safety-and-scope-policy.md`, `untrusted-context-policy.md`, `profiles/asiXX-*.md`; refuses `evaluator_skills/`). Isolates `untrusted_application_data` (`trust_level: "untrusted_data_not_instructions"`) and scrubs secrets/PEM/paths/private IPs.
  - **Bounded Multi-Chunk Provider Calls (`service.py`, `constants.py:53-68`, `deepseek_http.py`):** Chunks large counts (`DEFAULT_GENERATION_CHUNK_SIZE=15`, `MAX_PLANNED_CHUNKS_PER_ASI=4`, `MAX_TOTAL_PROVIDER_CALLS_PER_ASI=5`, `MAX_GENERATION_TOTAL_PROVIDER_CALLS=8`, `MAX_GENERATION_OUTPUT_TOKEN_BUDGET=32768`). Calls server-owned `DeepSeekHttpProvider` (`deepseek-flash`, `temperature=0.3`, `thinking: disabled`, `response_format: json_object`, `DEEPSEEK_API_KEY` env only, zero fallback to Mock).
  - **Parsing, Validation, Deduplication (`output_parser.py`, `validation.py`, `deduplication.py`):** Rejects fences/trailing prose/duplicate keys/NaN/depth > 16/> 256 KiB/`FORBIDDEN_LLM_OUTPUT_KEYS`. Validates ASI alignment, UTF-8 prompt `<= 4096B`, and confirms every `context_basis` key is in the confirmed snapshot. Deduplicates via NFKC + whitespace-collapsed SHA-256 (`exact_normalized_text_v1`).
  - **Two Output Modes:** `GeneratorPreviewStore` (RAM-only, 30m TTL, max 32 previews, explicit edit & save) vs. `GenerateAndRunOrchestrator` (7-stage background workflow auto-saving an immutable dataset and handing off execution to `GenericRunService`).
- **Outputs:** `GeneratorPreviewSnapshot` (Mode 2) or `GenerateAndRunSnapshot` + immutable `DatasetEnvelope` + linked `GenericRunRecord` (Mode 1).
- **Core Files / Functions:** `generator/constants.py`, `models.py`, `readiness.py`, `skills.py`, `request_builder.py`, `output_parser.py`, `validation.py`, `deduplication.py`, `providers/deepseek_http.py`, `provider_factory.py`, `service.py`, `preview_store.py`, `orchestrator.py`, `api_routes.py`.
- **Dependencies:** `ManagedTargetCatalog`, `ApplicationContextStore`, `ResponsePolicyStore`, `DatasetRepository`, `GenericRunService`, `TargetExecutionLockRegistry`, DeepSeek HTTPS API.
- **Persistence:** Previews in RAM (`GeneratorPreviewStore`); Generate & Run workflows in `<workflows_root>/gnr-<id>.json`; saved datasets in `<data_dir>/datasets/<dataset_id>.json`.
- **Failure Cases:** `application_context_stale`, `execution_scope_capability_unverified`, `unsupported_target_protocol`, `credential_missing` (`DEEPSEEK_API_KEY`), provider HTTP errors/timeouts/truncation (note: HTTP 402 maps to generic `HTTP_ERROR`), partial generation blocking automatic execution unless `allow_partial_execution=True`, cancellation during chunking.

---

### Subsystem D — Execution Engine (`backend/src/workflow/routes_generic_runner.py`, `backend/src/testing/`, `backend/src/targets/`)

- **Responsibility:** Perform zero-request preflight preview, enforce operator consent, prevent concurrent live runs on the same target/endpoint, dispatch bounded per-case target requests, support safe cancellation and lineage-verified resume, and enforce completion invariants.
- **Inputs:** `GenericRunRequest` (`mode`, `target_id`, `dataset_id`/`cases`/`stored_payload`, `testcase_ids`, `use_judge`, `authorization_confirmed`, `submission_id`, `expected_target_revision`, `expected_session_credential_generation`).
- **Processing:**
  - **Preflight (`GenericRunService.preview_run`, `_build_cases`):** Evaluates capabilities, MCP tool names, credential availability, reviewed policies/Application Context, Judge readiness, and request budgets without sending any target or Judge call.
  - **Shared Target Locking (`workflow/target_locks.py`, `workflow/api.py:464-595`):** `TargetExecutionLockRegistry` locks both logical `target:<target_id>` and canonical physical `endpoint:<scheme>://<host>:<port><path>` (normalizing `localhost`/`127.0.0.1`/`::1`) across Generic Runner, Generate & Run, Imported Batch, and MCP Actions. **In-process only.**
  - **TOCTOU & Idempotency (`routes_generic_runner.py:2171-2358`):** Verifies `expected_target_revision` and `expected_session_credential_generation` under lock before starting; deduplicates retries via `submissions/<submission_id>.json` and request fingerprint.
  - **Adapter Dispatch (`testing/generic_runner.py`, `testing/runner.py`, `targets/adapters/`):** Selects `HttpTargetAdapter` (`generic_http`), `McpJsonRpcTargetAdapter` (`generic_mcp_jsonrpc`), `OfflineStoredTargetAdapter` (`offline_stored`), or `McpAgentRuntimeAdapter` (`mcp_agent_runtime`, used in Hosted MCP Agent batch).
  - **Sequential Worker & Checkpoints (`routes_generic_runner.py:2746-3240`):** Writes atomic pre-dispatch checkpoint before every target request (`DispatchCheckpointError` aborts safely if disk write fails), enforces per-run monotonic versions (`_write_run_record`), checks `cancel_event` between cases and inside HTTP/Pi subprocess calls, and verifies completion invariants (`_verify_completion_invariants`, `L2028-2131`) before setting `status="completed"`.
- **Outputs:** Per-case `<case>.secagent.json`, `local-controlled-runs/<case_run_id>/run-summary.json`, and `generic-runs/<generic_run_id>/generic-run.json`.
- **Core Files / Functions:** `workflow/routes_generic_runner.py` (`GenericRunService`), `workflow/target_locks.py` (`TargetExecutionLockRegistry`), `testing/generic_runner.py` (`run_generic_cases`), `testing/runner.py` (`TargetRunner`), `targets/adapters/http_adapter.py`, `targets/adapters/mcp_jsonrpc_adapter.py`, `targets/runtimes/mcp_agent.py`.
- **Dependencies:** `httpx`, `TargetValidator`, `ResponseObserver`, `EvidenceCollectors`, `HybridEvaluator`.
- **Persistence:** `results/generic-runs/<run_id>/generic-run.json`, `results/generic-runs/submissions/<submission_id>.json`, `results/local-controlled-runs/<case_run_id>/`.
- **Failure Cases:** `generic_target_execution_in_progress` (409), `generic_target_revision_stale` (409), `generic_session_credential_stale` (409), `dispatch_checkpoint_write_failed`, `persistence_integrity_failed`, process crash (`interrupted` on next read via `_enrich_loaded_run:3254-3261`).

---

### Subsystem E — Evidence Collection (`backend/src/targets/adapters/http_evidence.py`, `backend/src/observers/`, `backend/src/core/`)

- **Responsibility:** Extract inline response evidence, query optional scoped external evidence sources, correlate events to the current run/case, redact sensitive payloads via SHA-256 hashing, and enforce strict provenance tiers separating target claims from independently verified execution.
- **Inputs:** Raw HTTP/MCP target responses, `HttpResponseContract` / `HttpInlineEvidenceMapping`, `TargetProfile.evidence_sources`, `CollectorContext` (`run_id`, `case_id`, `execution_id`, `request_id`, `session_id`, `target_correlation_id`, `allowed_roots`, `allowed_endpoints`).
- **Processing:**
  - **Inline HTTP Extraction (`http_evidence.py:204-319`):** Extracts mapped `items` array (e.g., `steps`) into `Evidence(kind="target_inline_event", source="http_response", data={provenance: "target_reported", execution_verified: False, ...})`. Hashes raw `arguments` -> `arguments_sha256` (retaining top-level `argument_keys` only) and `observation` -> `observation_sha256` (retaining `observation_type` only).
  - **External Scoped Collectors (`observers/evidence_collectors.py:404-1271`):**
    - `HttpCallbackCollector`: GET against allowlisted endpoint (no redirects, bounded bytes/events). Saved UI evidence sources are always forced to `provenance="target_reported", independent_verifier=False` (`routes_generic_runner.py:925-926`).
    - `SandboxLogFileCollector` & `FileArtifactCollector`: Local path-scoped JSON/JSONL/artifact readers rejecting symlinks/reparse points (`_resolve_scoped_path`).
  - **Correlation & Promotion Gate (`evidence_collectors.py:174-268`, `core/models/evidence.py:195-247`):** Strong correlation requires `>= 2` non-conflicting context IDs including `run_id`. Only trusted independent verifiers with strong correlation, explicit boolean execution flags, and no negative/conflicting metadata can attain `provenance="independently_verified"` and `execution_verified=True`.
  - **Evidence v2 Projection (`core/evidence_v2.py`):** Classifies canonical evidence levels: `response_only`, `model_reported_intent`, `target_reported_claim`, `adapter_observed_request`, `independently_verified_execution`.
- **Outputs:** Normalized `Observation.evidence[]`, `EvidenceV2Bundle`, `CollectorDiagnostic[]`.
- **Core Files / Functions:** `targets/adapters/http_evidence.py`, `observers/evidence_collectors.py`, `observers/response_observer.py`, `observers/dvaa_mcp_execution_observer.py`, `core/models/evidence.py`, `core/evidence_v2.py`, `workflow/evidence_sources.py`.
- **Dependencies:** `httpx`, `hashlib.sha256`, `targets/validator.py`.
- **Persistence:** Embedded inside `<case>.secagent.json` and `generic-run.json`; manual snapshots from UI stored in `<data_dir>/evidence-sources/`.
- **Failure Cases:** `scope_rejected` (URL/path outside allowlist or redirect/symlink), `unavailable` (HTTP 4xx/5xx or missing file), `uncorrelated` (missing/mismatched IDs), `conflicting_execution_metadata`, response exceeding `max_response_bytes`. Collector errors degrade gracefully without crashing response evaluation.

---

### Subsystem F — Evaluation (`backend/src/evaluators/`, `backend/src/integrations/external_evaluator/`)

- **Responsibility:** Evaluate each testcase observation using deterministic rules, Evidence v2 runtime gates, and optional Hybrid LLM Judge (Pi CLI), producing canonical binary security verdicts (`PASS`/`FAIL`) alongside separate technical evaluation status (`EVALUATED`, `EXECUTION_ERROR`, `JUDGE_ERROR`, etc.).
- **Inputs:** `TestCase` (with reviewed rules and/or trusted context), `Observation` (response text, completeness, normalized evidence), `RunnerEvaluationConfig`.
- **Processing:**
  - **Deterministic Layer (`response_evaluator.py`, `evidence_v2_evaluator.py`, `asi05_execution.py`):** Evaluates reviewed policy rules (`ResponseEvaluator`) and Evidence v2 runtime requirements. For execution scopes (`execution_action`, `agent_run`, `direct_request`, etc.), `EvidenceV2Evaluator` requires `execution_verified and correlation_verified`; unverified inline events hit Branch E4 (`target_reported_claim_unverified`, `allow_semantic_fallback=False`), skipping the LLM Judge.
  - **Hybrid Semantic Judge (`hybrid_evaluator.py`, `evaluation_request_builder.py`, `integrations/external_evaluator/pi.py`, `skills.py`, `validation.py`):**
    - Gated by `BudgetedJudgeProvider` (`max_judge_calls = len(pairs)`), `response_complete == True`, and trusted context availability.
    - Loads `evaluator_skills/security/*.md` (or `response_first/tool-misuse-response.md` for `tool_intent_response`), computes SHA-256 identity, constructs canonical JSON `EvaluationRequest` with allowlisted public evidence only (`public_evidence_data`).
    - Invokes `pi --mode text --no-session --no-tools` as a subprocess, parses strict JSON v1.0 output (`parse_judge_response`), verifies classification-to-verdict mapping and exact response-span / evidence-reference citations.
    - Retries only on `TIMEOUT`, `PROCESS_ERROR`, `INVALID_OUTPUT` (up to `max_technical_retries`, default `0` in `GenericRunService`, `max_judge_calls` enforced). Does **not** retry `NONZERO_EXIT`.
  - **Verdict Resolution & Binary Policy v2.2.0 (`verdict_resolver.py`, `verdict_outcome.py:314-611`):** Resolves deterministic vs. Judge recommendations (verified runtime `FAIL` cannot be downgraded by Judge) and maps every processed case to binary `PASS`/`FAIL` + `evaluation_status` + `evidence_limitations`.
- **Outputs:** `EvaluationResult`, `JudgeDiagnostic`, `BinaryCaseOutcome`, `EvaluationSummary`.
- **Core Files / Functions:** `evaluators/contract.py`, `response_evaluator.py`, `evidence_v2_evaluator.py`, `asi05_execution.py`, `hybrid_evaluator.py`, `evaluation_request_builder.py`, `verdict_resolver.py`, `verdict_outcome.py`, `integrations/external_evaluator/pi.py`, `skills.py`, `validation.py`.
- **Dependencies:** `evaluator_skills/`, local `pi` executable + `~/.pi/agent/auth.json` (or configured env vars), `BudgetedJudgeProvider`.
- **Persistence:** Persisted per case inside `.secagent.json` and summarized in `generic-run.json`.
- **Failure Cases:** `credential_missing`, `executable_missing`, `NONZERO_EXIT` (including unclassified HTTP 402 insufficient-balance), `TIMEOUT`, `INVALID_OUTPUT`, `BUDGET_EXHAUSTED`, `incomplete_response` gating semantic Judge.

---

### Subsystem G — Persistence and Reporting (`backend/src/reporting/`, `backend/src/workflow/routes_generic_runner.py`)

- **Responsibility:** Persist immutable datasets, scan checkpoints, native per-case reports, and lineage summaries; expose a strictly read-only Reporting API (`:8091`) for historical overviews, filtered execution tables, Rule/Pi comparisons, and verified report exports.
- **Inputs:** Selected dataset manifest (`DatasetManifest`), `results/local-controlled-runs/<run_id>/`, `results/generic-runs/<run_id>/`.
- **Processing:**
  - **Atomic File Persistence:** Every JSON write in Workflow API uses temp-file + atomic replace (`write_atomic_bytes` / `_write_atomic`) with per-run persistence locking and monotonic version guards (`_write_run_record`).
  - **Read-Only Reporting API (`reporting/api.py`, `repository.py`, `normalizers.py`, `aggregation.py`, `exports.py`):** Loads selected manifests at startup into an immutable `ReportDataset` snapshot (`snapshot_sha256`), validates controlled-run `run-summary.json` SHA-256 digests against `.secagent.json` bytes on demand, applies deterministic `Redactor` (`redaction.py`) to strip URLs/canaries/credentials/opaque tokens, and computes strict coverage metrics (`decision_coverage_over_all_records`, `decisive_verdict_rate_among_classified`, `verified_artifact_coverage`, `evidence_coverage`) without recalculating historical verdicts.
  - **Unified Lineage Export (`routes_generic_runner.py:3918-3973, 5321-5359`):** Deduplicates cases across resumed continuation runs in root order without modifying disk artifacts; blocks unified export (`409 unified_report_integrity_failed`) if checkpoint integrity fails.
- **Outputs:** REST JSON endpoints (`/api/reports/health`, `/overview`, `/executions`, `/executions/<id>`, `/comparisons`, `/saved-runs`, `/runs/<id>`, `/runs/<id>/download`, `/api/testing/generic-runs/<id>/report.json`, `/unified-report.json`), downloadable JSON/archive bundles.
- **Core Files / Functions:** `reporting/api.py`, `repository.py`, `normalizers.py`, `aggregation.py`, `exports.py`, `redaction.py`, `workflow/dataset_repository.py`, `workflow/routes_generic_runner.py`.
- **Dependencies:** Local filesystem only (explicitly rejects UNC/network paths and mapped Windows network drives via `GetDriveTypeW == 4`, `reporting/repository.py:249-257`).
- **Persistence:** Atomic JSON files under `<data_dir>` and `results/`.
- **Failure Cases:** Corrupted JSON or SHA-256 mismatch (`ControlledRunInvalid`), symlink/reparse point rejected (`ArchiveReader`), network drive rejected (`DatasetError`), Reporting API stale startup snapshot (requires service restart to pick up manifest changes, whereas `/saved-runs` rebuilds index per request).

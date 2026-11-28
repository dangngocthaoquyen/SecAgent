# 05 — Data Models, Evidence Provenance & Reporting Rules

> **Audit Classification:** Confirmed source audit (`HEAD: 31614ca`).  
> **Companion Diagram:** [06-data-and-persistence-model.md](./diagrams/06-data-and-persistence-model.md)

## 1. Canonical Domain & Workflow Data Models

### 1.1 Core Testing & Evidence Models (`backend/src/core/models/`)
- **`TargetProfile`:** `id`, `name`, `target_type` (`llm_chat`, `tool_service`, `mcp_server`, `offline_stored`), `interface` (`type`: `http`/`mcp`/`agent`/`offline`, `adapter`: `generic_http`/`generic_mcp_jsonrpc`/`mcp_agent_runtime`/`offline_stored`, `config`), `capabilities`, `capability_states`, `observability`, `credential_refs`, `evidence_sources`, `metadata`.
- **`TestCase` & `TestInput`:** `id`, `category`, `evaluation` (`strategy`, `rules[]`), `prompt`, `parameters` (e.g., `tool_call`, `stored_record`), `metadata` (including `trusted_context`, `research_dataset_provenance`, `isolated_historical_verdict`).
- **`ExecutionResult`:** `success`, `status_code`, `output_text`, `raw_output`, `headers`, `duration_ms`, `error`, `events[]`.
- **`Observation`:** `response_text`, `response_complete`, `evidence: list[Evidence]`, `metadata`.
- **`Evidence` (`core/models/evidence.py:1-727`):** `kind` (`target_inline_event`, `tool_request`, `target_tool_result`, `collected_evidence`, `asi05_execution_trace`, `tool_call`, etc.), `source`, `name`, `success`, `reference`, `data: dict`.

### 1.2 Target Onboarding & Context Models (`backend/src/workflow/`)
- **`Preset` (`workflow/models.py`):** `id`, `name`, `platform_id`, `platform_name`, `protocol` (`openai-chat`/`http-json`/`mcp-jsonrpc`), `endpoint`, `models`, `default_model`, `timeout_min/max/default`, `credential_alias`, `session_auth` (`SessionAuthReference`), `http_config` (`HttpContractConfig`), `capability_states`, `capability_provenance`, `profile_revision` (SHA-256).
- **`ApplicationContextRecord` (`workflow/application_context.py`):** 18 text fields grouped into Sections **A (Core)**, **B (Access & Permissions)**, **C (Data & Content)**, **D (Business Context)**, **E (Red Team User)** + `field_provenance` (`discovered_observed`, `suggested_unverified`, `operator_confirmed`) + `target_revision` + `revision_sha256`.
- **`DatasetEnvelope` & `ImportedTestcase` (`workflow/dataset_models.py`, `dataset_normalizer.py`):** Content-addressed `dataset_id = sha256(f"{file_sha256}:{count}")[:32]`, `file_sha256`, `content_sha256`, `source_tool`, `total_testcases` (`1..100`), `testcases[]` (`internal_id`, `testcase_id`, `prompt`, `prompt_sha256`, `assertions`, `metadata`, `extra`).

---

## 2. Storage Layout & Persistence Guarantees

SecAgent uses **zero relational databases and zero message queues**. All durable artifacts are local JSON files written via atomic temp-file replacement (`write_atomic_bytes` / `_write_atomic`):

| Store / Artifact | Location | Lifetime | Integrity / Concurrency Mechanism |
|---|---|---|---|
| Managed Targets | `<data_dir>/targets.json` | Durable | `RLock`, atomic write, SHA-256 `profile_revision`, deduplication check |
| Session Credentials | RAM (`SessionCredentialStore`) | **Process RAM only** (cleared on restart) | Max 64 entries, bound to `(origin, scope_id, scope_kind, auth_type, header_name)`, `generation` 32-hex token |
| Application Context A–E | `<data_dir>/application-contexts/<target_id>.json` | Durable | Optimistic `expected_revision_sha256`, pinned to `target_revision` |
| Discovery Records | `<data_dir>/discoveries/<discovery_id>.json` | Durable | Loopback-only metadata snapshots, symlink rejected |
| Response Policies | `<data_dir>/response-policies/<policy_id>.json` | Durable | SHA-256 `revision_sha256`, explicit `review_status="reviewed"` |
| Evidence Sources | `<data_dir>/evidence-sources/` | Durable | Must match `--evidence-policy` exact endpoint allowlist |
| Generator Previews | RAM (`GeneratorPreviewStore`) | **Process RAM only** (30 min TTL, max 32) | Re-checks target/context/policy revisions at explicit Save |
| Immutable Datasets | `<data_dir>/datasets/<32hex>.json` | Durable (immutable) | Stores `original_base64` + `envelope`; every `get_dataset()` re-verifies `file_sha256`, `content_sha256`, and re-normalizes (`dataset_repository.py:48-68`) |
| Generate & Run Workflows | `<workflows_root>/gnr-<32hex>.json` | Durable | 7-stage state machine, `rerun_history`, `submission_id` dedup |
| Generic Scan Runs | `results/generic-runs/<32hex>/generic-run.json` | Durable | Per-run `persist_lock -> self._lock`, monotonic `_record_versions`, terminal-state disk guard (`routes_generic_runner.py:1837-1907`) |
| Idempotent Submissions | `results/generic-runs/submissions/<32hex>.json` | Durable | `request_fingerprint` SHA-256 conflict detection |
| Per-Case Native Reports | `results/generic-runs/<run_id>/<case>.secagent.json` & `results/local-controlled-runs/<case_run_id>/` | Durable | Verified via `run-summary.json` (`report_sha256`) at run completion (`_verify_completion_invariants`) and at Reporting API read (`_load_controlled_run`) |

*(Default `<data_dir>` on Windows: `%LOCALAPPDATA%\SecAgent`, kept outside the Git repository by `start_secagent_local.py`.)*

---

## 3. Evidence Provenance Hierarchy & Verification Levels

SecAgent enforces a 5-level canonical evidence classification (`core/evidence_v2.py`) and 4-tier provenance model (`observers/evidence_collectors.py:50-55`):

| Canonical Evidence Level | Provenance Tier | Typical Source | `execution_verified` | Satisfies Execution Scope (`execution_action` / `agent_run`)? |
|---|---|---|---|---|
| `response_only` | `model_reported` | Final HTTP response text (`text_path`) | `False` | **No** |
| `model_reported_intent` | `model_reported` | OpenAI `tool_calls` / model-declared intent | `False` | **No** |
| `target_reported_claim` | `target_reported` | HTTP inline `steps[]` (`target_inline_event`), MCP `target_tool_result`, UI `HttpCallbackCollector` | `False` | **No** |
| `adapter_observed_request` | `adapter_observed` | `McpJsonRpcTargetAdapter` outbound `tool_request`, weakly correlated or unverified independent collector record | `False` | **No** |
| `independently_verified_execution` | `independently_verified` | Trusted `SandboxLogFileCollector` / `FileArtifactCollector` / `DvaaInstrumentedReceiptCollector` with `independent_verifier=True` + **strong correlation** + explicit execution boolean + no conflicts | **`True`** | **Yes** (distinguishing real vs. `verified_simulated_effect` when `synthetic_mock=True`) |

### Correlation & Fail-Closed Verification Rules (`observers/evidence_collectors.py:174-364`)

1. **Immediate Conflict Rejection:** If ANY identifier present on a log/artifact record (`run_id`, `case_id`, `execution_id`, `request_id`, `session_id`, `target_correlation_id`) contradicts the active `CollectorContext`, correlation fails immediately (`mismatched_<field>`).
2. **Weak vs. Strong Correlation:**
   - **Weak (`1` matching field, or `target_correlation_id` match only):** Can **never** promote to `independently_verified` or `execution_verified=True`.
   - **Strong (`>= 2` distinct matching fields, including `run_id` when in scope):** Required prerequisite for `independently_verified`.
3. **Execution vs. Action Success Separation (`_evaluate_execution_flags`, `L233-267`):** Generic `success=True` alone never proves execution. Explicit boolean `executed=True`, `execution_verified=True`, or (for `FileArtifactCollector`) `effect_verified=True` is required. Any explicit `False` flag or malformed non-boolean type fails closed (`conflicting_execution_metadata`).
4. **Simulated Effect Guard (`L480-493, 682-683`):** `execution_semantics == "simulated_handler_effect"` requires `synthetic_mock=True` and produces `verification_status="verified_simulated_effect"` so synthetic lab effects are never misrepresented as real host OS compromise.

---

## 4. Redaction, Hashing & Disclosure Controls

| Layer | Implementation | What Is Redacted / Hashed |
|---|---|---|
| HTTP Inline Evidence | `targets/adapters/http_evidence.py:244-251, 295-306` | Raw `arguments` -> `arguments_sha256` (+ top-level `argument_keys` only); raw `observation` -> `observation_sha256` (+ `observation_type` only). Raw values never stored in `Evidence.data` or sent to Judge. |
| Evidence Public Allowlist | `core/models/evidence.py:391-427` (`public_evidence_data`) | Strictly allowlists safe metadata keys before building Judge `EvaluationRequest`. |
| Generic Runner API Sanitization | `routes_generic_runner.py` (`_sanitize_for_api`) | Scrubs session secrets (`extra_secrets=session_secrets`) plus standard patterns from case records. |
| Reporting Redactor | `reporting/redaction.py:6-71` (`Redactor`) | Deterministically replaces URLs (`[URL_REDACTED:<16hex>]`), `canary-*` (`[CANARY_SHA256:<64hex>]`), `sk-*`, `Bearer ...`, JWT `eyJ...`, `api_key/password/secret/token=...`, and opaque 24+ hex strings (`[OPAQUE_REDACTED]` or `[ID_SHA256:<64hex>]`). |
| Frontend Defense-in-Depth | `frontend/src/api.ts:317-326` (`safeLabel`) | Redacts URLs, absolute paths, canaries, and `sk-`/`Bearer` strings before rendering labels. |

---

## 5. Reporting & Reproducibility Rules

- **Strict Read-Only Separation (`reporting/api.py`, `reporting/normalizers.py`):** The Reporting API (`:8091`) imports **no evaluator, target adapter, or LLM provider**. It projects historical bytes deterministically (`normalize_report_bytes`) without recalculating verdicts.
- **Controlled Run Integrity Verification (`reporting/repository.py:63-155`):** Before serving `/api/reports/runs/<run_id>`, verifies `run-summary.json` -> `report_file` regex -> `sha256(raw_report) == report_sha256` -> cross-check `run_id`, `native_execution_id`, `testcase_id`, `target_id` -> optional `tool-receipt.json` / `tool-effect.json` SHA-256 verification.
- **Export Formats:**
  - Single-session Generic Scan report: `GET /api/testing/generic-runs/<run_id>/report.json` (`X-SecAgent-Export-Schema: 1.0.0`).
  - Unified multi-session lineage report: `GET /api/testing/generic-runs/<run_id>/unified-report.json` (blocked with `409` if checkpoint integrity fails).
  - Native per-case archive/report: `GET /api/reports/runs/<run_id>` and `/api/reports/runs/<run_id>/download` (and `/api/reports/executions/<id>/download` in `reporting/exports.py`).
- **Reporting Overview & Rule/Pi Comparison (`reporting/aggregation.py`, `Overview.tsx`, `Comparisons.tsx`):**
  - Separates **Production** vs. **Archived** Judge comparisons; explicitly states that *"Agreement is not detection accuracy or ground truth"*.
  - Keeps `unknown` counts explicit (`Unknown values stay unknown`) and distinguishes execution success (`successful_execution_reports`) from security `PASS`.
  - **Operational Caveat:** Reporting Overview/Executions load a static manifest snapshot at process startup (requiring `:8091` restart to refresh manifest files), whereas **Saved Runs** (`/api/reports/saved-runs`) rebuilds its index from `local-controlled-runs/` on each request (`repository.py:204-246`).

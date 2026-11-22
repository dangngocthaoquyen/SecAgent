# SecAgent Module Inventory & Classification (Post-Audit Correction)

**Status:** Corrected Inventory (supersedes v1 pre-correction inventory)  
**Aligned With:** [`SECAGENT_AUDIT_CORRECTIONS.md`](./SECAGENT_AUDIT_CORRECTIONS.md), [`SECAGENT_FULL_ARCHITECTURE_AUDIT.md`](./SECAGENT_FULL_ARCHITECTURE_AUDIT.md), [`SECAGENT_MCP_ARCHITECTURE_DECISION.md`](./SECAGENT_MCP_ARCHITECTURE_DECISION.md)  
**Repository:** `D:\SecAgent-W5-Judge`  
**Audit Scope Policy:** Read-only code audit; AST/symbol caller verification completed across `backend/src/`, `backend/tests/`, `backend/scripts/`, `frontend/src/`, and `start_secagent_local.py`.

---

## 1. Authoritative Baseline Inventory & LOC Accounting

Measured non-overlapping LOC across `D:\SecAgent-W5-Judge` (strictly separating Production Source, Tests, and Research Scripts):

| Layer / Bucket | Scope | Files | LOC | Share of Total |
|---|---|---:|---:|---:|
| **Backend Production (`backend/src`)** | Core runtime, targets, evaluators, observers, workflows, reporting, integrations | 135 | 17,493 | 33.0% |
| **Local Launcher (`start_secagent_local.py`)** | Unified local supervisor (`:8910`, `:5173`, optional `:7019`) | 1 | 332 | 0.6% |
| **Frontend Production (`frontend/src` prod + configs)** | `30` prod `.ts/.tsx` files (`3,973` LOC) + `vite.config.ts` / `playwright.config.ts` (`117` LOC) | 32 | 4,090 | 7.7% |
| **SUBTOTAL — PRODUCTION SOURCE** | **All shipped runtime & operator UI code** | **168** | **21,915** | **41.3%** |
| **Backend Tests (`backend/tests`)** | Unit, contract, policy, evaluator, reporting, and workflow tests | 96 | 21,835 | 41.2% |
| **Frontend Tests & Fixtures (`frontend/src` test/fixture)** | Vitest specs & typed API/report fixtures | 24 | 2,609 | 4.9% |
| **Frontend Browser Specs (`frontend/browser-tests`)** | Playwright mocked & E2E specs | 22 | 2,359 | 4.4% |
| **SUBTOTAL — TEST CODE** | **Protected regression suite (never deleted to pad LOC)** | **142** | **26,803** | **50.6%** |
| **Research & Experiment Scripts (`backend/scripts`)** | Smoke runners, pilot scripts, frozen replays (`run_native_smoke.py` = `265` LOC) | 20 | 4,299 | 8.1% |
| **GRAND TOTAL (Python + TS/JS)** | **`252` Python (`43,959` LOC) + `78` TS/JS (`9,058` LOC)** | **330** | **53,017** | **100.0%** |

> [!IMPORTANT]
> Historical Phase 3 reports checked 554 historical run folders under `results/local-controlled-runs` (readable index), **not** zero-cost runtime LOC. Script relocation (`4,299` LOC) and test preservation (`26,803` LOC) are strictly separated from net production code reduction (**`~780–1,320` LOC** net across Stages 1–5).

### Backend Production Sub-Package Breakdown (`backend/src`: 135 files, 17,493 LOC)

| Sub-Package | LOC | Role | Target Direction |
|---|---:|---|---|
| `backend/src/workflow` | 8,553 | HTTP API, batch workflows, MCP actions, ASI03 contracts, web/offline/toolbot labs | Consolidate overlapping HTTP workflows; split `api.py` & extract shared runner/assets |
| `backend/src/reporting` | 2,569 | Run history index, sidecar hashes, PDF/JSON/SARIF/artifact views | Keep core repository/API; tighten sidecar/index boundaries |
| `backend/src/evaluators` | 1,500 | ASI01/ASI02/ASI03/ASI05 rules, Shared Hybrid Pi Judge client, response evaluator | Keep & standardize `asi05_execution.py` dual-subject contract |
| `backend/src/targets` | 1,233 | `McpJsonRpcTargetAdapter` (`mcp_jsonrpc_adapter.py`), HTTP chat adapters, discovery, Temporary Bridge `:7019` | Keep generic adapters; introduce `McpAgentRuntime` (`targets/runtimes/mcp_agent.py`); retire Bridge `:7019` only in Stage 3 |
| `backend/src/testing` | 974 | Canonical `Runner`, campaign/run specs, policies | Expand cleanly to host extracted `run_native_smoke` report builders |
| `backend/src/integrations` | 869 | Promptfoo dataset importer & `security_tools/garak.py` | Keep Promptfoo importer; isolate/mark Garak as `RESEARCH_EXPERIMENT_SUPPORT` |
| `backend/src/core` | 614 | Config, schemas, shared primitives | Keep |
| `backend/src/observers` | 561 | Evidence capture (`Asi05ExecutionObserver`, `DvaaMcpExecutionObserver`, `ToolActionObserver`) | Keep active observers; retain `ToolActionObserver` until `ToolBotLab` retires |
| `backend/src/attack_modules` | 447 | Attack taxonomy/module registry | Keep / audit for overlap with workflows |
| `backend/src/tools` | 90 | Utility helpers | Keep |
| `backend/src/payloads` | 83 | Seed payload definitions | Keep |

---

## 2. Classification Taxonomy (Corrected for Audit Review)

Every flagged module is classified under a strict 7-label discipline rather than simplistic `KEEP` vs `REMOVE`:

1. **`CORE`** — Canonical production capability belonging in Target Architecture.
2. **`MISPLACED_CORE_HELPER`** — Live production dependency currently housed outside `backend/src/` (e.g., `backend/scripts/run_native_smoke.py`).
3. **`TEMPORARY_MIGRATION_DEPENDENCY`** — Required in Unified Runtime today (`promptfoo_http.py` Bridge `:7019`), allowed for removal **only** in Stage 3 after `McpAgentRuntime` passes multi-MCP offline verification.
4. **`SHARED_WEB_ASSET_HELPER` + `TEST_ONLY`** — Mixed file containing both shared production helper exports and test-only workflow class (`web_mock_batch.py`).
5. **`TEST_AND_DISPATCH_CONTRACT`** — Test/fixture class wired directly into dispatcher contracts (`fixture_runtime.py`).
6. **`LEGACY_COMPATIBILITY` / `LEGACY_DEPENDENCY` / `LEGACY_SYNTHETIC_EXPERIMENT`** — Older report/experiment paths retained during grace/migration periods so historical reports and replays do not break.
7. **`RESEARCH_EXPERIMENT_SUPPORT`** — Academic experiment tooling (`garak.py`, `pilot_*.py`, `run_garak_smoke.py`), isolated from shipped core runtime rather than purged from git history.

Zero `.py` files under `backend/src/` were verified to be 100% zero-caller dead code once package `__init__.py` re-exports, launcher hooks, scripts, and regression tests were included in the AST graph.

---

## 3. Reclassified Sensitive Modules (AST Caller Evidence)

| Module / Asset | Verified AST & Symbol Callers | Corrected Classification | Action by Stage | Risk if Deleted Prematurely |
|---|---|---|---|---|
| `backend/src/targets/bridges/promptfoo_http.py` | Imported by `start_secagent_local.py` (L219, L240), `test_promptfoo_agent_bridge.py`, `test_unified_startup_and_vite_proxy.py` | `TEMPORARY_MIGRATION_DEPENDENCY` | **Keep Stages 0–2.** Replace with Python `McpAgentRuntime` (`attribution="agent_selected"`); remove **only** in Stage 3 after offline multi-MCP verification (`ToolBot :7010`, `DataBot :7011`, `PluginBot :7012`, `ProxyBot :7013`) passes and 30 ASI05 cases stay runnable. | **HIGH** (breaks all 30 natural-language Agent-level ASI05 cases). |
| `backend/src/workflow/web_mock_batch.py` | `load_web_assets`, `_input`, `WEB_ATTACK`, `WEB_CONTROL` imported by **`backend/src/workflow/web_live_batch.py:24`**; plus `test_researchbot_web_batch.py`, `test_web_mock_batch.py` | `SHARED_WEB_ASSET_HELPER` (`load_web_assets` etc.) + `TEST_ONLY` (`MockWebBatchWorkflow`) | **NEVER delete wholesale.** Stage 1: extract shared helpers to `workflow/web_lab_assets.py` (keeping `web_live_batch.py` clean); isolate `MockWebBatchWorkflow` to test support only in Stage 2/4. | **HIGH** (`ImportError` immediately breaks `web_live_batch.py`). |
| `backend/src/workflow/fixture_runtime.py` | `LocalMockFixtureRuntime` imported by **`backend/src/workflow/dispatch.py:24,133`**, `web_mock_batch.py`, `test_workflow_dispatch.py` | `TEST_AND_DISPATCH_CONTRACT` | Keep untouched in Stage 1. Remove from `workflow/` only after dispatcher fixture contract is refactored cleanly in Stage 2/4. | **HIGH** (breaks `dispatch.py` import & tests). |
| `backend/src/observers/tool_action_observer.py` | Re-exported via **`backend/src/observers/__init__.py:5`**; imported by **`backend/src/workflow/toolbot_lab_batch.py:21`**, `test_tool_action_observer.py`, `test_evidence_contract_phase1a.py` | `LEGACY_DEPENDENCY` | **Keep** as long as `ToolBotLabBatchWorkflow` or observer contract tests remain; retire together with `toolbot_lab_batch.py` in Stage 4 after migration. | **HIGH** (breaks `observers/__init__.py` & `toolbot_lab_batch.py`). |
| `backend/src/workflow/asi03_contracts.py` (`ASI03ContractStore`) + `Asi03Review.tsx` | Imported by `workflow/api.py`, `workflow/generic_imported_batch.py`, `DatasetLibrary.tsx:250`, `test_asi03_contracts.py`, `test_asi05_judge_correctness.py`, `test_replay_asi05_frozen.py`, `pilot_asi03_dvaa_response.py`, `run_asi05_semantic_pilot.py` | `LEGACY_COMPATIBILITY + REPLAY_SUPPORT` | Keep in Stages 1–3; in Stage 4, move read-only contract viewer/replay compat behind versioned report/replay boundary instead of silent deletion. Note: 554 historical `run-summary.json` files at root showed `ASI03_POL: 0`, `ASI05_POL: 0`, `CONTRACT_SUM: 0`, `MCP_IN_ROOT: 0`. | **MEDIUM-HIGH** (breaks frozen ASI05/ASI03 replay scripts, tests, and `DatasetLibrary.tsx`). |
| `backend/src/workflow/toolbot_lab_batch.py` | Registered in `workflow/api.py:1401-1405` behind `--enable-toolbot-lab-batch`; referenced by `TargetManager.tsx:190`, `serve_toolbot_lab_offline.py`, `test_toolbot_lab_batch.py` | `LEGACY_SYNTHETIC_EXPERIMENT` | Keep opt-in behind flag during Stages 1–3; deprecate and migrate remaining synthetic scenarios to `McpAgentRuntime` fixtures in Stage 4. | **MEDIUM** (breaks CLI flag, `TargetManager.tsx` lab preset, and lab tests). |
| `backend/src/integrations/security_tools/garak.py` + `smoke_summary.py` | Used by `backend/scripts/run_garak_smoke.py`, `test_garak_provider.py`, `test_garak_smoke_script.py` | `RESEARCH_EXPERIMENT_SUPPORT` | Isolate behind experiment namespace / optional extras (`experiments/` or `integrations/research/`); **keep tests intact** unless user drops Garak research track explicitly. | **LOW-MEDIUM** (breaks thesis experiment scripts if removed unannounced). |
| `backend/scripts/run_native_smoke.py` (`265` LOC) | Imported by **7 `backend/src/workflow/` modules** (`asi01_batch.py`, `dispatch.py`, `generic_imported_batch.py`, `offline_batch.py`, `toolbot_lab_batch.py`, `web_live_batch.py`, `web_mock_batch.py`), `3` tests, `4` scripts | `MISPLACED_CORE_HELPER` | **Stage 1 Priority:** Move shared native report / summary builder functions from `backend/scripts/run_native_smoke.py` into `backend/src/testing/report_builder.py` (with thin backward-compat shim in `scripts/`). | **HIGH** if `scripts/` relocated without extracting helpers first (7 production workflow modules break!). |

---

## 4. Production Module-Level Target Decisions Summary

### Core Runtime & Targets (`KEEP` / `EVOLVE`)
- `start_secagent_local.py` (`332` LOC) — `KEEP`, remove optional `:7019` subprocess management only in Stage 3 after `McpAgentRuntime` is live-ready offline.
- `backend/src/testing/runner.py` (`249` LOC) — `CORE`, expand incrementally to absorb extracted report builder helpers and serve `McpAgentRuntime` loop limits (`max_model_calls`, `max_tool_calls`, `total_timeout_seconds`, `max_nested_requests=0`).
- `backend/src/targets/adapters/mcp_jsonrpc_adapter.py`, `dvaa_action_evidence.py`, `dvaa_discovery.py`, `http_evidence.py` — `CORE`, reused directly by both `McpActionWorkflow` (`attribution="direct_request"`) and the planned `McpAgentRuntime` (`attribution="agent_selected"`).
- `backend/src/evaluators/asi05_execution.py` (`165` LOC) — `CORE`, canonical contract enforcing strict separation between `subject in {"agent_run", "tool_service"}` and `attribution in {"agent_selected", "direct_request"}`.
- `backend/src/observers/asi05_execution_observer.py` & `dvaa_mcp_execution_observer.py` — `CORE`, canonical evidence observers for agent-level vs direct-request MCP execution.
- `backend/src/reporting/*` (`2,569` LOC) — `CORE`, preserve saved reports, SHA sidecars, and Phase 3 filters (`ERROR` verdict, date bounds).

### Workflows Requiring Phased Consolidation (Stages 2–4)
- `backend/src/workflow/api.py` — `SPLIT / REFACTOR`: Separate HTTP router blueprints (batches, datasets, mcp-actions, targets/health) cleanly rather than keeping a single large router file.
- `backend/src/workflow/asi01_batch.py` + `generic_imported_batch.py` + `web_live_batch.py` + `offline_batch.py` — `CONSOLIDATE IN STAGE 2`: Merge duplicated HTTP batch runner plumbing onto shared `Runner` + target adapter execution instead of deleting features; retain protocol-specific rules cleanly.
- `backend/src/workflow/mcp_actions.py` — `KEEP (direct_request lane)`: Direct MCP `tools/call` assessment without autonomous LLM selection. Coexists explicitly alongside `McpAgentRuntime` (`agent_selected` lane) — neither replaces the other.
- `backend/src/targets/runtimes/mcp_agent.py` *(planned in Stage 3)* — `NEW CORE`: Generic Python configurable MCP-enabled LLM Agent Runtime supporting any configured MCP server (`ToolBot :7010`, `DataBot :7011`, `PluginBot :7012`, `ProxyBot :7013`, or future labs) via target/profile JSON/YAML config — zero hardcoded `.cjs`, zero DeepSeek hardcoding, zero per-bot Python subclasses.

### Protected Research & Test Assets (`DO NOT COUNT AS CODE CLEANUP SAVINGS`)
- All `142` test files (`26,803` LOC) remain protected by default; only obsolete tests tied to **confirmed retired features after Stage 3/4** (e.g., Bridge `:7019` `.cjs` launcher tests after Stage 3 completion) may be archived/replaced by `McpAgentRuntime` contract tests with equal or greater coverage.
- All `20` scripts in `backend/scripts/` (`4,299` LOC) outside `run_native_smoke.py` shared helpers may be organized into `experiments/` or kept as research utilities; moving files equals **0 LOC deleted**.

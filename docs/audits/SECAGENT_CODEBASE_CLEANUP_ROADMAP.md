# SecAgent Codebase Cleanup & Refactoring Roadmap (Corrected)

**Status:** Corrected Multi-Stage Migration Plan (supersedes v1 pre-correction roadmap)  
**Aligned With:** [`SECAGENT_AUDIT_CORRECTIONS.md`](./SECAGENT_AUDIT_CORRECTIONS.md), [`SECAGENT_MCP_ARCHITECTURE_DECISION.md`](./SECAGENT_MCP_ARCHITECTURE_DECISION.md), [`SECAGENT_MODULE_INVENTORY.md`](./SECAGENT_MODULE_INVENTORY.md)  
**Repository:** `D:\SecAgent-W5-Judge`

---

## 1. Non-Negotiable Safety Principles

1. **Zero feature loss on Agent-level MCP testing:** Bridge `:7019` (`promptfoo_http.py`) is classified `TEMPORARY_MIGRATION_DEPENDENCY` and stays operational until `McpAgentRuntime` is implemented AND passes multi-MCP offline contract verification (`ToolBot :7010`, `DataBot :7011`, `PluginBot :7012`, `ProxyBot :7013`) while keeping the 30 imported ASI05 testcases runnable.
2. **AST-verified extraction before deletion:** Never delete `web_mock_batch.py`, `fixture_runtime.py`, `tool_action_observer.py`, or `backend/scripts/run_native_smoke.py` without first extracting active production callers (`web_live_batch.py:24`, `dispatch.py:24,133`, `toolbot_lab_batch.py:21`, and 7 workflow modules importing `run_native_smoke.py`).
3. **Truthful, non-overlapping LOC accounting:** Separate **Production LOC (`21,915`)**, **Test LOC (`26,803`)**, and **Research Script LOC (`4,299`)**. File relocations count as `0` deleted LOC. Regression tests are **never** deleted just to hit a LOC target.
4. **Realistic risk assessment & explicit regression gates:** No stage is marked complete without running its defined offline verification gates (`py_compile`, backend `pytest`, frontend `vitest` + `tsc`/`vite build`, and mocked Playwright suites).

---

## 2. Corrected Non-Overlapping LOC Budget (Stages 1–5)

| Stage | Primary Architectural Objective | Production Deletions (Est. LOC) | New Shared Runtime Code (Est. LOC) | Net Production LOC Delta | Test / Script Impact (Non-Overlapping) |
|---|---|---:|---:|---:|---|
| **Stage 0 (Current)** | Freeze baselines & enforce audit corrections | 0 | 0 | **0** | `46 passed` offline gate + historical `1,584` / `181` / `19` baseline recorded |
| **Stage 1** | Safe Boundary Extraction (`run_native_smoke` helpers -> `testing/report_builder.py`; `load_web_assets` -> `workflow/web_lab_assets.py`; split `workflow/api.py`) | `0` *(safe extraction only)* | +120 *(extracted report builder)* | **+120** | Unblocks all future cleanups without breaking 7 workflows or `web_live_batch.py`; `0` script deletions |
| **Stage 2** | HTTP Batch Workflow Consolidation (`asi01_batch`, `generic_imported_batch`, `web_live_batch`, `offline_batch` onto shared `Runner` + retire `MockWebBatchWorkflow` + decouple `fixture_runtime`) | -550 to -780 | +120 to +160 | **-390 to -660** | Tests updated cleanly to match consolidated runner without shrinking testcase coverage |
| **Stage 3** | Build Generic Python `McpAgentRuntime` (`attribution="agent_selected"`), pass multi-MCP offline verification, THEN retire Bridge `:7019` (`promptfoo_http.py`) | -283 *(Bridge + `secagent_bridge` + launcher hook)* | +260 to +350 *(`McpAgentRuntime` + config schema)* | **-23 to +67** | Replace Bridge-specific `.cjs` tests with generic multi-MCP `McpAgentRuntime` contract tests; keeps 30 ASI05 testcases |
| **Stage 4** | Legacy Retirement & Research Isolation (`toolbot_lab_batch` + `ToolActionObserver` retirement if migrated, `asi03_contracts` moved behind explicit legacy boundary, externalize DVAA configs) | -390 to -620 | +20 to +40 | **-350 to -600** | Research scripts (`backend/scripts/`, `garak.py`) organized cleanly without purging thesis experiments |
| **Stage 5** | Frontend Panel & Contract Hygiene (`TargetManager`, `DatasetLibrary`, unified target-capability switches, dead UI props cleanup) | -180 to -310 | 0 | **-180 to -310** | Update/preserve Playwright + Vitest suites |
| **TOTAL (Stages 1–5)** | **Net Shipped Production Source Reduction (`21,915` baseline)** | **-1,403 to -1,993** *(gross cuts)* | **+520 to +670** *(shared modules)* | **~ -780 to -1,320** *(~3.6%–6.0% net prod reduction)* | **0 LOC falsely claimed from moving scripts or deleting coverage** |

> [!NOTE]
> Even with a modest net reduction (`~780–1,320` production LOC instead of the inaccurate `5,000–6,500` claim), architectural clarity improves substantially: 4 overlapping HTTP workflows collapse into one shared `Runner` pipeline, hardcoded `.cjs` DeepSeek subprocess delegation (`:7019`) becomes a first-class configurable Python `McpAgentRuntime`, and `backend/src/` stops importing `backend/scripts/`.

---

## 3. Detailed Stage Plan, Risks & Verification Gates

### Stage 1 — Safe Dependency & Boundary Extraction (Do This First)
**Risk:** **LOW–MEDIUM** (Mechanical extraction; high payoff, zero behavior change expected if thin compatibility re-exports are kept during transition).

**Concrete Actions (Strictly Non-Destructive):**
1. **Untangle `backend/scripts/run_native_smoke.py` (`265` LOC):** Move shared report/summary helper functions imported by 7 production modules (`asi01_batch.py`, `dispatch.py`, `generic_imported_batch.py`, `offline_batch.py`, `toolbot_lab_batch.py`, `web_live_batch.py`, `web_mock_batch.py`) into `backend/src/testing/report_builder.py`. Keep re-export shims inside `backend/scripts/run_native_smoke.py` for script callers.
2. **Untangle `workflow/web_mock_batch.py` shared helper (`load_web_assets`, `_input`, `WEB_ATTACK`, `WEB_CONTROL`):** Extract those pure asset helpers into `backend/src/workflow/web_lab_assets.py` and switch `web_live_batch.py:24` to import from `web_lab_assets.py`. Leave `MockWebBatchWorkflow` untouched until Stage 2/4.
3. **Modularize `backend/src/workflow/api.py`:** Split HTTP handlers into focused sub-routers (`batches`, `datasets`, `mcp_actions`, `targets`) without changing any route path, HTTP method, nonce check, origin check, or JSON response contract.

**Stage 1 Acceptance Gate:**
- `python -m py_compile` clean across all modified files.
- Full `pytest` backend suite passes (`1,584+` cases, zero skipped regressions).
- `vitest` + `tsc` / `vite build` pass.
- `test_researchbot_web_batch.py`, `test_web_mock_batch.py`, `test_workflow_dispatch.py`, and smoke helper tests pass unchanged.

---

### Stage 2 — HTTP Workflow Consolidation onto Shared `Runner`
**Risk:** **MEDIUM–HIGH** (Core batch execution paths touch ASI01, imported datasets, web targets, offline dry-runs, and saved report formats).

**Concrete Actions:**
1. Audit exact contract differences between `asi01_batch.py`, `generic_imported_batch.py`, `web_live_batch.py`, and `offline_batch.py` (protocol fields, evidence fields, evaluator selection, report metadata).
2. Unify HTTP chat/web execution loops behind `backend/src/testing/runner.py` with protocol-agnostic target bindings and policy-driven evaluators.
3. Preserve all `run-summary.json` and sidecar schemas expected by `reporting/repository.py` and `SavedRuns.tsx` (including `ERROR` verdicts, date filters, and ASI01/02/03/05 scopes).
4. Refactor `LocalMockFixtureRuntime` (`workflow/fixture_runtime.py`) out of production dispatcher default paths if no longer needed for live execution, moving fixture doubles under `tests/` or explicit `--fixture-mode`.

**Stage 2 Acceptance Gate:**
- Saved report viewer parity tests pass against both synthetic fixtures and existing historical reports.
- Full backend `pytest` + frontend `vitest` + mocked Playwright suite pass.
- Offline ASI01 & ASI03 & ASI05 replay tests (`test_replay_asi05_frozen.py`, `test_asi05_judge_correctness.py`) pass identically.

---

### Stage 3 — Generic `McpAgentRuntime` & Safe Removal of Bridge `:7019`
**Risk:** **HIGH** (Replaces live agent tool-selection execution currently handled by Node `.cjs` bridge `:7019`). **Do NOT remove `promptfoo_http.py` until every sub-gate below is green.**

**Concrete Actions:**
1. **Build `backend/src/targets/runtimes/mcp_agent.py`** (`attribution="agent_selected"`, `subject="agent_run"`):
   - Uses existing `McpJsonRpcTargetAdapter` (`tools/list`, `tools/call`) — never hardcodes tool names or target bots.
   - Configurable LLM client (OpenAI-compatible endpoint / operator credential via `runtime.json` or env) — zero hardcoded DeepSeek or `.cjs` strings.
   - Configurable profile fields: `mcp_endpoint`, `mcp_transport` (`http_jsonrpc`), `system_prompt`, `tool_allowlist`, `model_profile`, and **hard loop bounds** (`max_model_calls`, `max_tool_calls`, `total_timeout_seconds`, `max_nested_requests=0`).
   - Emits standardized `trace.source`, `tool_calls[]`, `model_calls`, latency, token/step budget termination reason (`completed`, `max_tool_calls_reached`, `max_model_calls_reached`, `timeout`, `blocked_by_policy`), and `subject="agent_run"` + `attribution="agent_selected"` metadata for `asi05_execution.py` + `Asi05ExecutionObserver`.
2. **Coexistence Check (`direct_request` vs `agent_selected`):**
   - Keep `McpActionWorkflow` strictly for `attribution="direct_request"`, `subject="tool_service"`.
   - Keep `McpAgentRuntime` strictly for `attribution="agent_selected"`, `subject="agent_run"`.
   - Never collapse verdicts across different scopes in UI, reporting, or cross-tool Promptfoo comparisons.
3. **Validate Offline Across 4 Synthetic/Mock MCP Profiles (Mandatory Pre-Removal Gate):**
   - `ToolBot (:7010 profile)` — including all 30 imported natural-language ASI05 cases (`e4ea927a...`) via synthetic mock LLM tool-selector + mock MCP server.
   - `DataBot (:7011 profile)` — config-only switch (new `mcp_endpoint` + `system_prompt`, zero new Python adapter code).
   - `PluginBot (:7012 profile)` — config-only switch.
   - `ProxyBot (:7013 profile)` — config-only switch.
4. **Remove Bridge `:7019` Only After Gate Passes:**
   - Remove `backend/src/targets/bridges/promptfoo_http.py` and `:7019` spawn logic from `start_secagent_local.py`.
   - Update `Unified Runtime` configuration and `tests/test_unified_startup_and_vite_proxy.py` cleanly.

**Stage 3 Acceptance Gate:**
- Offline multi-MCP contract suite (4 server profiles + loop limit exhaustion tests + nested request denial + budget timeout) **100% PASS**.
- All 30 imported ASI05 testcases execute end-to-end against `McpAgentRuntime` (offline mock LLM + mock MCP) and produce valid `Asi05ExecutionObserver` evidence + saved native report with `attribution="agent_selected"`.
- Cross-scope comparison rules verified (`agent_selected` vs `direct_request` vs Promptfoo baseline clearly labeled with system-prompt/model provenance caveats).
- Optional manual live verification check against DVAA ToolBot (`:7010`) documented separately as live smoke test if credentials/DVAA available.

---

### Stage 4 — Legacy Compatibility & Research Experiment Isolation
**Risk:** **MEDIUM–HIGH** (`asi03_contracts.py` & `toolbot_lab_batch.py` tie into frozen replay tests, `DatasetLibrary.tsx`, `TargetManager.tsx`, and pilot scripts).

**Concrete Actions:**
1. Audit remaining callers of `ASI03ContractStore` and `Asi03Review.tsx`: isolate legacy contract schema rendering behind read-only historical/replay support or complete migration to Evidence Policy + Shared Judge rules once parity is proven.
2. Retire `toolbot_lab_batch.py` (`--enable-toolbot-lab-batch`) and `observers/tool_action_observer.py` **together** once `McpAgentRuntime` covers any needed lab demos, OR retain behind an explicit `legacy_lab` namespace if thesis appendix requires exact reproduction.
3. Isolate `garak.py`, `smoke_summary.py`, and thesis `pilot_*.py` scripts cleanly without deleting active unit/smoke tests (`test_garak_provider.py`, `test_garak_smoke_script.py`) unless explicitly approved.

**Stage 4 Acceptance Gate:**
- `DatasetLibrary.tsx`, `TargetManager.tsx`, `SavedRuns.tsx` load and filter both legacy and unified reports cleanly.
- Frozen replay tests pass or are formally archived with explicit user sign-off.

---

### Stage 5 — Frontend Contract Hygiene & Final Verification
**Risk:** **MEDIUM** (Browser E2E specs & Vite proxy rules must remain locked).

**Concrete Actions:**
1. Simplify redundant frontend API adapters/flags left over from pre-Unified phases while preserving every Phase 3 P0 fix (Vite MCP Action proxy allowlist, nonce forwarding, `ERROR` verdict support, date filters).
2. Run complete offline + mocked Playwright regression suite (`tsc`, `vitest`, `vite build`, `playwright test`, `pytest`).
3. Perform optional live unified acceptance pass (`python start_secagent_local.py` with live DVAA + operator Judge key) clearly distinguished from deterministic offline suite results.

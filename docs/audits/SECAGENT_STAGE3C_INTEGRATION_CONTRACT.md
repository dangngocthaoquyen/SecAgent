# SECAGENT — STAGE 3C.1 SOURCE-LEVEL INTEGRATION CONTRACT
# `GENERIC-MCP-AGENT` EXECUTION PATH

- **Version:** Stage 3C.1 (Pre-Implementation Source Contract)
- **Date:** 2026-11-22
- **Branch:** `Q/w5-external-judge`
- **Base Commit:** `5d144ffb8ff2a930f015fb1a7299e99e3953f1b8`
- **Historical Baseline:** 1675 backend tests passed (Stage 3B)

---

## 1. Architectural Feasibility Assessment

All required pipeline layers can be integrated safely without rewriting Runner, HybridEvaluator, ControlledDispatcher, BatchOrchestrator, ExecutionGrant, Stage 3B `McpAgentRuntime`, or Reporting normalizers, and without altering `GENERIC-DIRECT-CHAT` semantics.

---

## 2. Dual-Path Design in `GenericImportedBatchWorkflow`

`GenericImportedBatchWorkflow` registers two distinct native execution bindings in `ExecutionBindingRegistry`:

1. **`GENERIC-DIRECT-CHAT`** (existing, unchanged):
   - `protocol="openai-chat"`, `adapter_family="generic_http"`, `request_budget=1`, `allow_variable_request_budget=False`
   - Selected when `ImportedBatchSelection.execution_path == "direct_chat"` (default).
   - Preserves `total_request_budget == len(testcase_ids)` (`<= 100`).

2. **`GENERIC-MCP-AGENT`** (new Stage 3C path):
   - `protocol="openai-chat+mcp-jsonrpc"`, `adapter_family="mcp_agent_runtime"`, `evidence_contract="trusted_agent_runtime_trace"`, `request_budget=7` (`MAX_AGENT_REQUEST_BUDGET = 4 LLM + 3 MCP`), `allow_variable_request_budget=True`.
   - Selected only when `ImportedBatchSelection.execution_path == "mcp_agent_runtime"`.
   - Requires BOTH `target` (`protocol="openai-chat"`) AND `mcp_target` (`protocol="mcp-jsonrpc"`), plus a reviewed `McpAgentRuntimeBindingStore` entry binding those exact target revisions, models, endpoints, `system_prompt_sha256`, `tool_catalog_sha256`, budgets, and timeouts.

---

## 3. Reviewed Two-Target Runtime Binding (`McpAgentRuntimeBindingStore`)

Module: `backend/src/workflow/mcp_agent_runtime_binding.py`

- Persists operator drafts & reviewed revisions under `<catalog.data_dir>/mcp-agent-bindings/<binding_id>.json` with symlink checks (`_no_links`), atomic writes (`_write_atomic`), `ArchiveReader`, and `revision_sha256` verification.
- Trusted snapshot fields:
  - **LLM identity:** `llm_target_id`, `llm_profile_revision`, `llm_endpoint`, `model`, `credential_alias` (mapped server-side to `credential_env`), `system_prompt`, `system_prompt_sha256`.
  - **MCP identity:** `mcp_target_id`, `mcp_profile_revision`, `mcp_endpoint`, `mcp_credential_alias` (mapped server-side to `mcp_credential_env`, strictly distinct from `credential_env` when configured), `reviewed_tools` (`tuple[ReviewedToolSpec, ...]`), `tool_catalog_sha256`.
  - **Bounded runtime limits:** `max_model_calls` (`1..4`), `max_tool_calls` (`0..3`), `max_nested_requests=0`, `llm_timeout_seconds`, `mcp_timeout_seconds`, `total_timeout_seconds`, `max_response_bytes`.
  - **Action policy signatures (optional/ASI05):** reviewed `authorized_actions` / `prohibited_actions` bound per testcase into `Asi05ExecutionPolicy(subject="agent_run")`.
- Preview `plan_id` binds dataset hashes, both target drafts, policy config, reviewed binding `revision_sha256`, `McpAgentRuntimeConfig.config_digest()`, ordered case items (`asset_sha256`, `input_sha256`), `total_request_budget`, `evaluation_mode`, `asi_category`, `execution_path`, `transport_mode`, and `evidence_provenance`.
- Any mutation to LLM model, system prompt, MCP URL, tool catalog/schemas, limits, target revisions, or dataset content after `preview()` invalidates `plan_id` (before `start()`) and triggers immediate fail-closed drift denial (before every LLM/MCP step).

---

## 4. `BatchPlan`, Budgets, and 30-Case Sequential Grant Pool

1. **Per-case admission budget vs outbound runtime requests:**
   - For `GENERIC-MCP-AGENT`, each reviewed binding fixes `case_request_budget = max_model_calls + max_tool_calls` (`1 <= case_request_budget <= 7`, bounded by `McpAgentRuntimeConfig` limits `max_model_calls <= 4`, `max_tool_calls <= 3`).
   - Every `BatchCase` receives `request_budget = case_request_budget`, and `ImportedBatchSelection` requires `total_request_budget == len(testcase_ids) * case_request_budget` (extended up to `700` solely for `execution_path == "mcp_agent_runtime"`; capped at `100` for `direct_chat`).
   - `ExecutionBindingRegistry.execute_binding` validates `1 <= case.request_budget <= binding.request_budget` when `binding.allow_variable_request_budget is True` (preserving strict `!=` otherwise), and `_run_agent_case` asserts `case.request_budget == config.max_model_calls + config.max_tool_calls`.
   - `CaseResult.request_count` reports exact `model_call_count + tool_call_count`, matching `runtime_snapshot["target_request_count"]` and `run-summary.json["target_request_count"]` for `BatchOrchestrator._verify_imported_state()`.

2. **One-use `ExecutionGrant` & 30-case sequential pool:**
   - Before admitting case `i`, `GenericImportedBatchWorkflow` prunes inactive owned grants (`self._owned_grants - {self._active_grant_id}`).
   - One single-use `ExecutionGrant` (`authorization_id`, `scope="security_test_execution"`, `expires_at`, matching `target_id`, `profile_revision`, `policy_ref`, `testcase_id`, `asset_sha256`) is minted inside `dispatcher._lock`, verified against `AdmissionPolicy.grants` (`max_length=20`), claimed exclusively via `write_exclusive_json(self.root / f"grant-{auth_id}", ...)` before execution, re-verified on every LLM/MCP turn by `WorkflowAgentExecutionGuard`, and pruned upon case completion/failure in `finally`.
   - Consequently, even a 30-case sequential batch holds at most `1` owned grant in `policy.grants` at any moment and cannot exhaust the 20-grant pool or permit replay.

---

## 5. Production `ExecutionGuard` (`WorkflowAgentExecutionGuard`)

Implemented in `backend/src/workflow/mcp_agent_runtime_binding.py`:
- Satisfies Stage 3B `ExecutionGuard.check(GuardCheckContext) -> GuardDecision`.
- Checked by `McpAgentRuntime` before **every** LLM completion and **every** MCP `tools/call`:
  1. Operator cancellation (`orchestrator.cancellation_requested()`) -> `GuardDecision(allowed=False, cancelled=True, reason="operator_cancelled")`.
  2. Active batch ownership (`dispatcher._active`, `workflow._batch_id`, and `.active-batch` marker matching `(batch_id, os.getpid())`).
  3. Grant identity (`workflow._active_grant_id == grant.authorization_id`) & expiry (`grant.expires_at > now_utc`).
  4. Reviewed config digest integrity (`context.config_digest == started_config_digest`) plus live re-check of `target_error`, live binding revision, and immutable dataset/case hashes.
  5. Endpoint and tool allowlist check (`context.target_endpoint == expected_endpoint`, and for `mcp_tool_call`, `context.tool_name in allowed_tool_names`).
  6. Remaining per-case request budget (`model_calls_used + tool_calls_used < case_request_budget`).

---

## 6. Target Adapter, Runner & Trusted Observer (`McpAgentExecutionObserver`)

1. **`McpAgentRuntimeTargetAdapter`** (`backend/src/targets/adapters/mcp_agent_adapter.py`):
   - Registered under `"mcp_agent_runtime"` (`interface={"type": "agent", "adapter": "mcp_agent_runtime", "config": {"url": ..., "mcp_url": ...}}`, `validator.py` extended for `"agent": "mcp_agent_runtime"`).
   - Runs `McpAgentRuntime.run(test_input.prompt, config)` and returns `ExecutionResult`:
     - `success=True`, `status_code=200` ONLY when `runtime_result.status == "completed"` and `runtime_result.response_complete is True`.
     - `success=False`, `response_complete=False` for `blocked`, `budget_exhausted`, `incomplete`, `timeout`, `error`, or `cancelled`.
     - Emits sanitized `ExecutionResult.events` for each Stage 3B `AgentRuntimeTraceEvent` (attaching `execution_id = test_input.id`), plus full in-memory metadata in `raw_output["agent_runtime_record"]` (omitted from persisted reports via `Runner._build_report`).

2. **`McpAgentExecutionObserver`** (`backend/src/observers/mcp_agent_execution_observer.py`):
   - Subclasses `ResponseObserver`; correlates `ExecutionResult` strictly against `(testcase_id, target_id, execution_id=test_input.id, expected_tool_names)`.
   - Rejects (`asi05_execution_evidence_fault`): forged pre-injected `asi05_execution_*` or `handler_receipt` events, missing/mismatched `execution_id`, non-`False` `execution_verified` flags, missing `agent_tool_intent` / `secagent_mcp_request` correlation, duplicate `invocation_id`, `target_reported` impersonation of SecAgent requests, or missing/mismatched `HandlerReceipt` when an `ActionEvidenceCollector` is attached.
   - Without an external `HandlerReceipt`, emits ONLY:
     - `asi05_execution_trace` (`source="asi05_agent_mcp_observer"`, `attribution="agent_selected"`, `provenance="secagent_observed_request"`, `source_provenance="live_mcp_request"`, `trace_completeness="partial"`, `observed_action_count=len(dispatched)`)
     - `asi05_execution_action` (`execution_level="tool_invocation"`, `handler_status="unverified"`, `effect_sha256=None`) — NEVER auto-promoting to `simulated_execution` or `sandbox_effect`, and NEVER setting `execution_verified=True`.
   - With a genuinely correlated `HandlerReceipt` (when `ActionEvidenceCollector` is configured), emits correlated `handler_receipt` and `instrumented_handler_receipt` (`execution_level="simulated_execution"` for invoked handler or `"tool_invocation"` for `"rejected"`), still preserving `execution_verified=False`.

---

## 7. `asi05_execution.py`, `evidence.py`, Judge & Reporting Extensions

- **`backend/src/core/models/evidence.py` (`public_evidence_data`):**
  - Allowlist `agent_tool_intent`, `secagent_mcp_request`, `target_mcp_response`, `rejected_tool_call` (from `source="mcp_agent_runtime"`), retaining only schema-safe correlation fields (`provenance`, `execution_verified=False`, `subject`, `attribution`, `run_id`, `sequence_index`, `model_call_index`, `tool_call_id`, `invocation_id`, `arguments_sha256`, `request_status`, `response_status`, `result_sha256`, `reason`, `timestamp`).
  - Include `"asi05_agent_mcp_observer"` in the `asi05_execution_trace` / `asi05_execution_action` allowlist branch.
- **`backend/src/evaluators/asi05_execution.py` (`build_execution_request`):**
  - Support `trace.source == "asi05_agent_mcp_observer"` with strict checks: `attribution == "agent_selected"`, `trace_completeness == "partial"`, `action.execution_level == "tool_invocation"`, `action.handler_status == "unverified"`, `action.effect_sha256 is None`, plus 1-to-1 verification against `secagent_mcp_request` events (`source == "mcp_agent_runtime"`, `provenance == "secagent_request"`, matching `execution_id`, `invocation_id`, `tool_name`, `arguments_sha256`).
  - Support `trace.source == "instrumented_handler_receipt"` for both `"direct_request"` (unchanged) and `"agent_selected"` (when correlated against `secagent_mcp_request`).
  - Blocked, errored, or truncated agent runs (`execution_success=False`) fail `target_transport_unavailable` -> `INCONCLUSIVE` under `execution_action`, or `ERROR` under rule-only response checks; never converted to synthetic `FAIL`.
- **`backend/src/reporting/models.py` & `backend/src/reporting/normalizers.py`:**
  - Extend `ImportedProvenance` (`binding_id` includes `"GENERIC-MCP-AGENT"`, `adapter` includes `"mcp_agent_runtime"`, `delivery_surface` includes `"mcp_agent_loop"`, `target_request_count` up to `7` validated per binding, `evaluation_readiness` includes `"reviewed_asi05_execution_action"`, `evidence_contract` includes `"trusted_agent_runtime_trace"`, `evaluation_scope` includes `"execution_action"`, plus optional `llm_target_id`, `llm_profile_revision`, `model`, `system_prompt_sha256`, `mcp_target_id`, `mcp_profile_revision`, `tool_catalog_sha256`, `model_call_budget`, `tool_call_budget`, `model_call_count`, `tool_call_count`, `attribution`, `evidence_source`, `trace_completeness`).
  - Add matching safe keys to `DETAILS` in `reporting/normalizers.py`.

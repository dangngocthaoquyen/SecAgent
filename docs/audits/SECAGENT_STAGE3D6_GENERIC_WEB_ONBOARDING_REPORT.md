# SecAgent Stage 3D.6 Generic MCP Onboarding & Web Acceptance Report

- **Repository:** `D:\SecAgent-W5-Judge`
- **Branch:** `Q/w5-external-judge`
- **Decision:** **`STAGE_3D6_WEB_READY`**
- **Scope:** Generic Capability Discovery (Phase A), Server-Owned Tool Catalog & Hosted MCP Agent Binding APIs (Phase B), Generic Second-MCP-Server End-to-End Proof (Phase C), and Human-Operated React Web UI + Playwright Real Browser Acceptance (Phase D).

---

## 1. Architectural Objectives & Guarantees Verified

1. **Zero Target Hardcoding:** SecAgent treats arbitrary OpenAI-compatible chat hosts (`openai-chat`) and arbitrary MCP JSON-RPC tool servers (`mcp-jsonrpc`) uniformly via Web UI discovery, schema validation, catalog review, and binding composition. DVAA ToolBot remains an optional reference fixture (`configs/mcp_agents/dvaa_toolbot_hosted_catalog.json`), not a hardcoded runtime rule.
2. **Clear Architectural Separation:**
   - **Native Chat Agent (`GENERIC-DIRECT-CHAT`):** Direct chat workflow preserved intact under `Chat prompt assessment`.
   - **Hosted MCP Agent (`GENERIC-MCP-AGENT`, `target_composition="hosted_mcp_agent"`):** Composes `LLM Target + System Prompt + Reviewed Tool Catalog + MCP Server Target` with separated **Tool Exposure** (`McpToolCatalogStore`), **Operator Safety Scope** (`EnvironmentAuthorizationScope`), and **ASI05 Action Policy** (`authorized_predicates` / `prohibited_predicates`).
   - **Standalone MCP Tool Service (`McpActionWorkflow`):** Structured direct tool-action workflow preserved intact under `MCP tool-action assessment`.
3. **Fail-Closed Security Invariants:**
   - Discovery sends `tools/list` only and never dispatches `tools/call` or attack payloads.
   - Server ignores/rejects client-supplied `review_status`; creates always persist `"draft"` with server-computed SHA-256 digests (`revision_sha256`, `tool_catalog_sha256`).
   - Unsupported JSON Schema constructs (`$ref`, `anyOf`, etc.) or missing `inputSchema` are flagged (`schema_compatible: false`) and rejected from catalog creation rather than guessed.
   - Editing an MCP/LLM target profile or catalog automatically marks dependent catalogs and agent bindings `"stale"` and blocks batch execution fail-closed.
   - Credential aliases and secret environment values are never emitted in catalog, binding, batch, or Native Report payloads.

---

## 2. Implemented Changes by Phase

### Phase A — Generic Capability Discovery
- [mcp_agent.py](file:///D:/SecAgent-W5-Judge/backend/src/targets/runtimes/mcp_agent.py): Added `validate_restricted_tool_schema(schema)` returning `(schema_compatible, safe_error_code)` against `_validate_restricted_schema`.
- [discovery.py](file:///D:/SecAgent-W5-Judge/backend/src/workflow/discovery.py): Extended `DiscoveryEngine._read_mcp_tools()` and `discover()` to collect `name`, bounded `description`, `input_schema`, `schema_sha256`, `schema_compatible`, `schema_error`, `source_endpoint`, `discovered_at`, and canonical `advertised_tool_manifest_sha256`; persisted bounded capability manifests in `<discovery_id>.mcp-tools.json` readable via `DiscoveryEngine.load_mcp_capabilities(discovery_id)` while preserving raw-description sanitization on primary `discoveries/<id>.json` records.
- [routes_targets.py](file:///D:/SecAgent-W5-Judge/backend/src/workflow/routes_targets.py): Registered `GET /api/testing/discoveries/<discovery_id>/mcp-tools`.

### Phase B — Tool Catalog & Hosted MCP Agent Binding API
- [mcp_tool_catalog.py](file:///D:/SecAgent-W5-Judge/backend/src/workflow/mcp_tool_catalog.py): Added `McpToolCatalogDraft` and `McpToolCatalogStore` (`create`, `create_from_discovery`, `load`, `status`, `review`, `list_all`, `for_target`) enforcing schema validation, exact revision review confirmation, and target staleness detection.
- [mcp_agent_runtime_binding.py](file:///D:/SecAgent-W5-Judge/backend/src/workflow/mcp_agent_runtime_binding.py): Extended `ReviewedAgentRuntimeDraft` with optional `catalog_id` and `catalog_revision_sha256`, added `tool_catalog_store` dependency staleness checks and `list_all()` on `McpAgentRuntimeBindingStore`.
- [routes_agent_onboarding.py](file:///D:/SecAgent-W5-Judge/backend/src/workflow/routes_agent_onboarding.py): Added authenticated routes:
  - `GET /api/testing/mcp-catalogs`, `GET /api/testing/mcp-catalogs/target/<target_id>`, `POST /api/testing/mcp-catalogs/drafts`, `GET /api/testing/mcp-catalogs/<catalog_id>`, `POST /api/testing/mcp-catalogs/<catalog_id>/review`
  - `GET /api/testing/agent-bindings`, `POST /api/testing/agent-bindings/drafts`, `GET /api/testing/agent-bindings/<binding_id>`, `POST /api/testing/agent-bindings/<binding_id>/review`
  - Public serialization `_public_binding()` strips credential aliases while retaining boolean `has_llm_credential` / `has_mcp_credential`.
- [api.py](file:///D:/SecAgent-W5-Judge/backend/src/workflow/api.py) & [vite.config.ts](file:///D:/SecAgent-W5-Judge/frontend/vite.config.ts): Synchronized exact route allowlists, Vite dev proxy operator header injection, shared `McpToolCatalogStore`/`McpAgentRuntimeBindingStore` wiring on `WorkflowApiContext`, and 64 KiB payload ceiling for onboarding drafts.
- [test_stage1b2_api_contract_parity.py](file:///D:/SecAgent-W5-Judge/backend/tests/test_stage1b2_api_contract_parity.py): Updated frozen `EXPECTED_URL_MAP` (`67` rules / `65` endpoints).

### Phase C — Generic Second-MCP-Server End-to-End Backend Proof
- [test_stage3d6_generic_web_onboarding.py](file:///D:/SecAgent-W5-Judge/backend/tests/test_stage3d6_generic_web_onboarding.py): Proved Phase A schema inspection + non-invocation, Phase B fail-closed review/staleness/credential redaction, and Phase C end-to-end execution over an arbitrary mock MCP server (`ops-notes-mcp`: `append_note`, `run_diagnostic`) + mock OpenAI LLM, asserting accurate verdict & Native Report distinction (`PASS`, `INCONCLUSIVE` on target rejection and pre-dispatch SecAgent blocks, `FAIL` on prohibited predicate match, `0` MCP calls on blocked cases, `GENERIC-DIRECT-CHAT` coexistence, and post-edit drift blocking).

### Phase D — Web UI & Real Browser Acceptance
- [testingApi.ts](file:///D:/SecAgent-W5-Judge/frontend/src/testingApi.ts) & [batchApi.ts](file:///D:/SecAgent-W5-Judge/frontend/src/batchApi.ts): Added typed client contracts for discovery MCP manifests, Tool Catalogs, Hosted MCP Agent Bindings, and `mcp_agent_runtime` batch selections.
- [DiscoveryPanel.tsx](file:///D:/SecAgent-W5-Judge/frontend/src/DiscoveryPanel.tsx): Displays discovered MCP tools, descriptions, manifest/schema digests, `Schema compatible` vs `Incompatible (<schema_error>)` badges, and collapsible JSON Schemas.
- [AgentOnboardingPanel.tsx](file:///D:/SecAgent-W5-Judge/frontend/src/AgentOnboardingPanel.tsx) & [TargetConfiguration.tsx](file:///D:/SecAgent-W5-Judge/frontend/src/TargetConfiguration.tsx): Added Web UI composer to inspect/load discovered tools or paste manual schemas, save & approve Tool Catalogs, and compose/approve Hosted MCP Agent Bindings with separated `environment_scope` and `ASI05` predicate inputs.
- [TargetManager.tsx](file:///D:/SecAgent-W5-Judge/frontend/src/TargetManager.tsx): Fixed saved quick-probed targets so `Test Connection` (`/api/testing/connection-checks`) stays available after target review when backend `connection_verification.status !== 'compatible'`.
- [DatasetLibrary.tsx](file:///D:/SecAgent-W5-Judge/frontend/src/DatasetLibrary.tsx) & [BatchLaunch.tsx](file:///D:/SecAgent-W5-Judge/frontend/src/BatchLaunch.tsx): Added `Hosted MCP Agent assessment` tab beside existing `Chat prompt assessment` and `MCP tool-action assessment`, automatically binding `execution_path="mcp_agent_runtime"`, paired LLM + MCP drafts, and per-case agent request budget.
- [BatchProgress.tsx](file:///D:/SecAgent-W5-Judge/frontend/src/BatchProgress.tsx) & [ExecutionDetail.tsx](file:///D:/SecAgent-W5-Judge/frontend/src/ExecutionDetail.tsx): Added explicit `HOSTED MCP AGENT ASSESSMENT` banner, pre-dispatch SecAgent block indicators, and `Hosted MCP Agent trace & action distinction` report breakdown (`secagent_rejected_count`, `dispatched_action_count`, `target_rejected_count`, `trace_completeness`, and explicit `Host / OS side effect verified: No`).
- [AgentOnboarding.test.tsx](file:///D:/SecAgent-W5-Judge/frontend/src/AgentOnboarding.test.tsx), [serve_generic_onboarding_offline.py](file:///D:/SecAgent-W5-Judge/backend/tests/serve_generic_onboarding_offline.py), & [generic-mcp-onboarding-real-api.spec.ts](file:///D:/SecAgent-W5-Judge/frontend/browser-tests/generic-mcp-onboarding-real-api.spec.ts): Added Vitest component tests and full MS Edge Playwright acceptance driving two distinct mock MCP servers + live local chat via real Vite + Reporting API + Workflow API.

---

## 3. Verification Results (Post-Final Code Edit)

| Check | Scope | Result |
| :--- | :--- | :--- |
| `python -m py_compile ...` + `git diff --check` | All modified/new Python modules & test servers | **PASS** (exit code `0`) |
| Focused backend pytest (9 files) | `test_target_discovery.py`, `test_stage1b2_api_contract_parity.py`, `test_stage1a_dependency_boundaries.py`, Stage 3B–3D.6 | **89 passed in 47.35s** (`0` failed, `0` skipped) |
| Full backend pytest (`python -m pytest backend/tests -q -rs`) | Entire backend regression & contract suite | **1706 passed in 395.61s (0:06:35)** (`0` failed, `0` skipped) |
| Frontend build (`npm --prefix frontend run build`) | `tsc -b && vite build` (58 modules) | **PASS** (`built in 2.17s`) |
| Frontend Vitest (`npm --prefix frontend test`) | All 20 test files incl. `AgentOnboarding.test.tsx` | **20 files, 184 passed** (`0` failed) |
| Playwright browser E2E (`generic-mcp-onboarding-real-api.spec.ts`) | Real MS Edge + Vite + Workflow/Reporting APIs + 2 mock MCP servers + 1 mock LLM | **1 passed (18.7s)** |

> **Pre-existing unrelated check note:** When `target-discovery-real-api.spec.ts` and `target-management-local-real-api.spec.ts` were executed together in an earlier run (`task-2797`), `target-management-local-real-api.spec.ts` and Test 3 of `target-discovery-real-api.spec.ts` passed (`3 passed`), while Tests 1 & 2 of `target-discovery-real-api.spec.ts` hit two pre-existing strict-mode locator ambiguities in unmodified test expectations (`getByText('Connected', { exact: true })` matching both target list row and summary badge, and `getByRole('form', { name: 'Manage target details' }).getByRole('combobox')` matching both Platform and Protocol comboboxes).
> **Acceptance boundary:** Automated tests used deterministic mocked LLM/MCP HTTP transports in-process (`httpx.MockTransport`) with no external network, live LLM, or live DVAA target requests.

---

## 4. Deliverables
- Architecture & Verification Report: [SECAGENT_STAGE3D6_GENERIC_WEB_ONBOARDING_REPORT.md](file:///D:/SecAgent-W5-Judge/docs/audits/SECAGENT_STAGE3D6_GENERIC_WEB_ONBOARDING_REPORT.md)
- Vietnamese Web Operator Guide: [SECAGENT_STAGE3D6_WEB_USER_GUIDE.md](file:///D:/SecAgent-W5-Judge/docs/audits/SECAGENT_STAGE3D6_WEB_USER_GUIDE.md)

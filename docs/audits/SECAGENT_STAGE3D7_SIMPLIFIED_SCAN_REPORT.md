# SecAgent Stage 3D.7 Report — Simplified Web Security Scan Workflow

**Decision:** `STAGE_3D7_WEB_READY`  
**Branch:** `Q/w5-external-judge`

---

## 1. Objective & Scope

Stage 3D.7 delivers a beginner-friendly, Promptfoo-like **"New Security Scan"** workflow (`#scan`) inside the SecAgent Web UI while strictly preserving all Stage 3D.6 backend contracts (`Runtime`, `Observer`, `Judge`, `MCP Tool Catalog Store`, `Agent Binding Store`, and fail-closed authorization boundaries) and keeping existing `#targets` and `#datasets` screens intact as **Advanced Settings**.

Zero backend source files were modified in Stage 3D.7. All backend behavior comes directly from the verified Stage 3D.6 implementation.

---

## 2. UI Components Created & Updated

| File | Role in Stage 3D.7 |
|---|---|
| `frontend/src/SecurityScanWizard.tsx` | 5-step guided wizard (`1 · Target Setup`, `2 · Configuration`, `3 · Testcases & Policy`, `4 · Review & Start`, `5 · Results & Evidence`) supporting **Existing AI Agent (Chat API)**, **LLM Agent + MCP Server**, and **MCP Tool Server (Direct Testing)** without exposing internal IDs, SHA-256 digests, or raw JSON by default. |
| `frontend/src/App.tsx` | Adds `#scan` route (`New Security Scan`) in sidebar navigation above `Targets` and `Datasets`, while keeping `#targets`, `#datasets`, `#overview`, `#executions`, and `#comparisons` operational. |
| `frontend/src/BatchProgress.tsx` | Enhances `HOSTED MCP AGENT` results with best-effort per-case `detailApi.run(...)` inspection to distinguish `LLM proposed tool call`, `SecAgent blocked before dispatch (N) — NOT target defense`, `MCP dispatched`, `Target rejected` vs `Target reported success`, `Host OS effect: Unverified`, and `Incomplete runtime trace`. |
| `frontend/src/styles.css` | Adds responsive `.scan-*` and `.onboarding-*` layout styles for the wizard stepper, target type selector cards, review summary panels, and evidence boundary badges. |
| `frontend/src/SecurityScanWizard.test.tsx` | Automated Vitest suite verifying both Path A (HTTP AI Agent Direct Chat without MCP Catalog or Agent Binding) and Path B (Hosted MCP Agent discovery, inline LLM provider creation, draft catalog/binding approval without manual IDs, ASI05 policy check, plan preview, and scan launch). |
| `frontend/src/AgentOnboarding.test.tsx` | Updated text assertion to align with the explicit `"SecAgent blocked before dispatch ... NOT target defense"` phrasing in `BatchProgress.tsx`. |
| `frontend/browser-tests/simplified-scan-wizard-real-api.spec.ts` | End-to-end Microsoft Edge Playwright test running against live local Vite, `reporting.api`, and `serve_generic_onboarding_offline.py` across Direct Chat, Ops Notes MCP (`:17451`), Native Report detail, a second distinct MCP server (`:17410`) without source changes, and `Advanced Settings (Targets)` navigation. |

---

## 3. Reused Backend APIs & Controls

`SecurityScanWizard.tsx` reuses existing Stage 3D.6 workflow and reporting endpoints cleanly via `testingApi`, `batchApi`, and `detailApi` (`frontend/src/testingApi.ts`, `frontend/src/batchApi.ts`, `frontend/src/api.ts`):

- **Session & Targets:** `GET /api/testing/health`, `POST /api/testing/session/unlock`, `GET /api/testing/targets`, `POST /api/testing/targets/discover`, `GET /api/testing/targets/discover/{discovery_id}/mcp-tools`, `POST /api/testing/targets`, `POST /api/testing/targets/{target_id}/review`, `POST /api/testing/targets/{target_id}/probe`
- **MCP Catalog & Agent Binding:** `GET /api/testing/mcp-catalogs`, `POST /api/testing/mcp-catalogs`, `POST /api/testing/mcp-catalogs/{catalog_id}/review`, `GET /api/testing/agent-bindings`, `POST /api/testing/agent-bindings`, `POST /api/testing/agent-bindings/{binding_id}/review`
- **Policies, Datasets & Execution:** `GET /api/testing/categories`, `POST /api/testing/datasets/validate`, `POST /api/testing/datasets/import`, `GET /api/testing/datasets`, `GET /api/testing/datasets/{dataset_id}`, `POST /api/testing/batches/preview`, `POST /api/testing/batches`, `GET /api/testing/batches/{batch_run_id}`, `GET /api/reports/runs/{run_id}`
- **Existing Reusable Components:** `Asi03TargetPolicy`, `Asi05PolicyReview`, `McpActionPanel`, and `BatchProgress`.

---

## 4. Automation vs. Explicit Human Confirmation Boundary

Stage 3D.7 reduces operator friction without weakening any Stage 3B–3D.6 fail-closed security guarantee:

### What Stage 3D.7 Automates for UX Simplicity
- **Path B (`LLM Agent + MCP Server`)** automatically inspects `tools/list` metadata after explicit discovery consent, displays human-readable tool names/descriptions/schema compatibility badges, prepares an **unapproved `draft` Tool Catalog** with compatible tools pre-checked, hides internal `discovery_id`, `catalog_id`, `binding_id`, SHA-256 digests, and JSON inputs inside collapsed **Advanced Settings**, and defaults target category selection to `ASI05`.
- **Path A (`Existing AI Agent (Chat API)`)** bypasses MCP Tool Catalog and Hosted Agent Binding completely, connecting directly via OpenAI-compatible HTTP chat or reviewed Agent Bridge.
- **Path C (`MCP Tool Server (Direct Testing)`)** separates structured direct `tools/call` testing (`McpActionPanel`) cleanly from autonomous LLM agent decisions.

### What Still Requires Explicit Human Confirmation (Fail-Closed)
1. **Operator Session Unlock:** Local ephemeral token confirmation (`POST /api/testing/session/unlock`). No plaintext LLM/target API keys are accepted or rendered in the browser UI (`credential_alias` only, loopback endpoints only).
2. **Bounded Discovery Consent:** Explicit checkbox authorizing up to three bounded metadata requests (`tools/list` for MCP or metadata lookup for Chat) with no attack payloads or tool execution.
3. **Target & LLM Review + Probe:** Explicit human approval of target profile and benign connection probe (`review` + `probe`) before live batch eligibility.
4. **Tool Catalog & Agent Binding Approval:** Explicitly checking exposed tools, LLM host pairing, agent prompt/step budget, and optional `environment_scope` / ASI05 predicates (`reviewMcpCatalog` + `reviewAgentBinding`) before testcases can enter Step 3.
5. **Policy & Scan Execution Authorization:** Explicit `ASI03` / `ASI05` target policy review (when those categories apply) and final explicit `Start Scan` checkbox within the previewed `target_request_budget`.

---

## 5. Verification Results (Observed After Final Edit)

| Check | Command | Observed Result |
|---|---|---|
| Frontend TypeScript + Production Bundle | `npm --prefix frontend run build` (`tsc -b && vite build`) | **PASS** (exit `0`, `59 modules transformed`, built in `4.04s`) |
| Frontend Component & Unit Suite | `npm --prefix frontend test` (`vitest run`) | **PASS** (`21 passed (21)` test files, `186 passed (186)` tests, incl. `SecurityScanWizard.test.tsx (2)` & `AgentOnboarding.test.tsx (3)`) |
| Browser Real-API E2E (Microsoft Edge + Vite + Python APIs) | `npx playwright test browser-tests/simplified-scan-wizard-real-api.spec.ts browser-tests/generic-mcp-onboarding-real-api.spec.ts` (from `frontend/`, `SECAGENT_BROWSER_CHANNEL` default `msedge`, isolated ports `8093`/`8094`/`5174`) | **PASS** (`2 passed (32.5s)`: `generic-mcp-onboarding-real-api.spec.ts` `16.7s`, `simplified-scan-wizard-real-api.spec.ts` `9.0s`) |
| Full Backend Regression Suite | `python -m pytest backend/tests -q -rs` | **PASS** (`1706 passed in 518.67s (0:08:38)`, 0 failed, 0 skipped) |
| Diff Integrity | `git diff --check` | **PASS** (exit `0`, zero whitespace/conflict issues) |

---

## 6. Known Limitations & DVAA Manual Testing Readiness

- **Offline Acceptance Scope:** Automated Playwright E2E verifies full browser-to-backend-to-loopback HTTP orchestration against isolated local mock MCP/LLM servers (`127.0.0.1:17451`, `127.0.0.1:17410`, `127.0.0.1:17490`) rather than live external DVAA containers or cloud LLM providers.
- **Entry Hash on Launch:** `start_secagent_local.py` still prints and opens `/#targets` on startup; operators can click **New Security Scan** in the top-left sidebar or navigate directly to `/#scan`.
- **DVAA ToolBot & General Agent Readiness:** Operators can now test DVAA ToolBot MCP, the `:7019` Agent Bridge, or any local OpenAI-compatible AI Agent / MCP Server end-to-end from `/#scan` via `python start_secagent_local.py` without editing source code, with exact pre-dispatch block vs target-behavior separation in both live scan results and Native Reports.

# MCP Quick Connect live failure — 20/11/2026

## Root cause (confirmed)

The live Target Catalog already contains `local-agent-7010` at `http://127.0.0.1:7010/`, protocol `mcp-jsonrpc`, service identifier `mcp-service`. Discovery proposed the same ID. Before this fix, **two creation-only validations ran before the provisional probe**:

1. `TargetManager.acceptDiscovery` / `probeQuick` called `validateManaged(profile, expected=null)` before `probeDiscovery`. The validation endpoint calls `catalog.validate_profile(..., update=False)`, which rejects any existing ID (`frontend/src/TargetManager.tsx:73-95`; `backend/src/workflow/api.py:524-539`; `backend/src/workflow/management.py:216-228`).
2. Even if the frontend had skipped that call, `ManagedTargetCatalog.probe_candidate` itself called the same create validator. The API mapped the duplicate-ID exception to HTTP 400 `invalid_discovery_probe` before sending MCP traffic (`backend/src/workflow/management.py:276-290`; `backend/src/workflow/api.py:503-519`).

The reported failure was therefore **not** an invalid `tools/list` response, wrong JSON-RPC ID, model routing, credential failure, or a trailing-slash mismatch. It occurred before the MCP connection request. The frontend caught the API error and replaced it with a generic sentence.

## Authenticated live reproduction before the fix

Using the running SecAgent frontend's operator-authorized loopback proxy, with its validation nonce retained only in memory:

| Step | Redacted observation |
| --- | --- |
| `POST /api/testing/discoveries` | HTTP 200; `metadata_found`; one metadata request; proposed ID `local-agent-7010`; endpoint `http://127.0.0.1:7010/`; protocol `mcp-jsonrpc`; service ID `mcp-service` |
| `POST /api/testing/discovery-probes` | HTTP 400; backend error code `invalid_discovery_probe`; no connection result; rejected by create validation |

No operator token, nonce value, raw HTTP body, or target content was printed or stored. A direct call to port 8092 without operator authorization correctly returned HTTP 403 `operator_authentication_required` and was not used for the diagnosis.

## Fix

- The provisional probe now builds and schema-validates a standalone candidate without checking whether its proposed ID is already saved. It still checks endpoint, protocol, model/service identifier, timeout, loopback eligibility, discovery association and explicit authorization. It does not write or review a profile (`backend/src/workflow/management.py:276-290`; `backend/src/workflow/api.py:503-519`). The **Save** endpoint retains its duplicate-ID and revision checks.
- The frontend performs the benign probe before the distinct Save validation. It shows a successful connection even when the proposed ID exists, but disables Save and explains how to select the saved target or change the ID. Any configuration edit clears the earlier probe (`frontend/src/TargetManager.tsx:59-97`; `frontend/src/TargetConfiguration.tsx:49`).
- Sanitized backend error codes are now included in operator-facing API errors. The UI passes these bounded diagnostics through instead of replacing every failure with the same generic text (`frontend/src/testingApi.ts:112-120`; `frontend/src/TargetManager.tsx:62-63`).

The MCP probe remains `POST http://127.0.0.1:7010/`, `Content-Type: application/json`, JSON-RPC `2.0`, ID `secagent-connection-check`, method `tools/list`, params `{}`. The validator requires HTTP 200, matching JSON-RPC version and ID, and `result.tools` as an array (`backend/src/workflow/management.py:291-337`). The `mcp-service` field is a configuration service identifier; it is not sent as an LLM model in the MCP payload. HTTP/OpenAI chat still sends its actual model. The one-request client rejects redirects and oversized responses and does not use a proxy (`backend/src/workflow/dispatch.py:32-78`).

## Live verification with patched SecAgent API

The patched API was exercised in an **isolated in-process SecAgent instance** with a temporary catalog containing an already-saved `local-agent-7010`, real HTTP transport to the running DVAA endpoints, and synthetic operator authorization. No existing catalog, review, or historical report was changed.

| Target | Discovery requests | Probe HTTP | Probe result | Target requests | Contract |
| --- | ---: | ---: | --- | ---: | --- |
| ToolBot `http://127.0.0.1:7010/` | 1 | 200 | `succeeded`, `mcp_tools_list_response` | 1 | `runtime_protocol_compatible=true`; temporary catalog unchanged |
| CodeBot `http://127.0.0.1:7004/v1/chat/completions`, operator model `default` | 3 | 200 | `succeeded`, `openai_chat_response` | 1 | `runtime_protocol_compatible=true`; temporary catalog unchanged |

These are connectivity contracts, not tool invocation or security verdicts. No `tools/call`, security payload, Judge call, Save, or Review was made during live verification. The raw target responses were not retained; the bounded probe result confirms that the response passed the contract checks above. The already-running port 8092 process was started before the Python source change and must be restarted by the operator to load the patch; the isolated patched instance is the after-fix live evidence.

## Regression

- **50/50 backend tests PASS**: discovery binding, duplicate-ID provisional probe without mutation, exact MCP request method/content type/URL/ID, malformed response, wrong response ID, missing authorization, HTTP model requirement, and Target Management (`backend/tests/test_target_discovery.py:244-381`).
- **32/32 frontend tests PASS**: discovery, quick-connect, duplicate-ID status and Save gate, reset on edits, connection carry after Save, target selection (`frontend/src/TargetManager.test.tsx:158-247`).
- **3/3 Playwright real-browser tests PASS** with an isolated Workflow API and mock target transport, including the already-saved ToolBot ID case (`frontend/browser-tests/target-discovery-real-api.spec.ts:166-202`).
- TypeScript and Vite production build PASS. `git diff --check` found no whitespace errors in the changed files.

## Adapter impact and operating note

The change is confined to provisional Target Management validation and Quick Connect UI. It does not change the generic MCP target adapter, HTTP target adapter, Runner, Shared Judge, Verdict Resolver, Policy, or evidence pipeline. HTTP CodeBot's benign probe also passed live. Existing saved target authorization is unchanged; discovery and connectivity never grant security-test execution permission.

To observe the fixed behavior in the main local UI, restart the SecAgent local services so port 8092 loads the updated Python module, then use **Connect new target → `http://127.0.0.1:7010/` → Discover & Test Connection**. The result should read **Connected**. Because `local-agent-7010` is already saved, choose **Select existing target** or change the proposed ID before Save. Do not infer handler execution from this connection check.

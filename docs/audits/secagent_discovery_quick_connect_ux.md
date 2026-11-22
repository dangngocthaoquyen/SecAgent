# SecAgent Discovery Quick Connect UX — 2026-11-19

## Result

The Target page now follows **Enter URL → Discover → auto-filled configuration → Test Connection → Save Target → explicit target review → select testcases**. The review step remains necessary because discovery and a connection probe do not grant permission for security execution.

The previously selected target is hidden while discovery is active. Probe status belongs to the unsaved proposal and is carried to a saved profile only when the saved target ID, revision, endpoint, protocol, model/service identifier and timeout match the probed configuration. Changing the URL or configuration clears that status. Changing the proposed endpoint or protocol also requires a new discovery before probe or save. A failed discovery leaves the previous target's connection status out of the discovery view.

## Changes

| Area | Implementation |
| --- | --- |
| Compact discovery UI | `frontend/src/DiscoveryPanel.tsx:4–47` keeps URL, authorization and Discover in the main view. Successful proposals auto-fill the form. Metadata sources, evidence candidates, compatibility hints, unknowns and provenance are collapsed in **Advanced Details**. A request generation token discards a stale response after URL changes. |
| Quick configuration and status | `frontend/src/TargetManager.tsx:18–124` shows name, endpoint, protocol, derived adapter and model/service identifier. CodeBot's absent model requires an explicit operator value. The prominent Test Connection button shows the exact endpoint and **Connected / Failed / Unverified** with a fixed reason. It resets after edits. Advanced target identifiers and timeout remain editable. |
| Selected target linkage | `frontend/src/TargetConfiguration.tsx:11`, `:47–54` hides the old selection, readiness and evidence panel during discovery. After save, catalog reload selects the new target. `frontend/src/TargetManager.tsx:29–39`, `:70–75` binds an earlier successful probe to that exact saved revision. |
| Unsaved profile probe | `backend/src/workflow/api.py:59`, `:232`, `:502–522`; `backend/src/workflow/management.py:276–340` add an explicitly authorized provisional connection check. It validates the profile and discovery ID/endpoint/protocol binding, then reuses the existing bounded one-request probe. The route writes no target, review, grant or verdict. The local frontend proxy allowlists only this exact POST (`frontend/vite.config.ts:19`, `:56`). |
| URL-only ToolBot detection | `backend/src/targets/adapters/dvaa_discovery.py:18–24` supplies an adapter-specific MCP metadata hint for the known ToolBot 7010 root URL. `backend/src/workflow/discovery.py:172–177` still requires a valid `tools/list` response before proposing MCP. Other MCP roots can use the explicit protocol option. |
| API client | `frontend/src/testingApi.ts:158` parses the same bounded connection result contract used by saved targets. |

## Acceptance checks

| Check | Observed result |
| --- | --- |
| A. ToolBot 7010 | URL-only discovery proposed MCP and auto-filled `http://127.0.0.1:7010/`. Browser test with ResearchBot 7015 selected beforehand hid the old target and connected through the MCP `tools/list` probe on 7010. A live temporary-catalog check returned `mcp_tools_list_response`, one probe request, zero saved profiles. |
| B. CodeBot 7004 | Proposal filled the HTTP endpoint; no model was advertised, so the form required an operator-entered model. A live temporary-catalog check with operator value `default` returned `openai_chat_response`, one benign probe request, zero saved profiles. |
| C. Discovery failure | Browser test submitted an unsupported path after a prior connection; the old target and old Connected message did not appear in the discovery view. |
| D. Configuration change | Browser test changed the MCP service identifier after a successful probe and observed Unverified. Frontend unit test changed the HTTP model and URL, also clearing the prior result. An in-flight discovery response is discarded when its URL changes. |
| E. Save/review | Browser test read the catalog after save and found zero review records. The saved target was selected; explicit review was required before testcase selection. A separate execution grant remains required. |
| F. Simpler default | The metadata/evidence/compatibility list is inside closed **Advanced Details**. The main view contains the URL, Discover, short auto-filled configuration, Test Connection and Save Target. |

## Verification

- Backend Discovery, Target Management, ToolBot Lab and Evidence Sources: **104 passed**.
- Frontend DiscoveryPanel, TargetManager and TargetConfiguration: **31 passed**.
- Frontend TypeScript and Vite production build: **passed**.
- Browser tests with the real local Workflow API and mock target transport: **2 passed**. The development proxy logged transient connection refusals while its isolated test API started; both workflows completed.
- Live checks used only CodeBot's benign chat contract request and ToolBot's `tools/list`. No `tools/call`, security payload, Pi Judge request or evidence collection occurred.

## Boundaries

- Discovery remains literal-loopback only, with the existing request count, 3 second metadata timeout, response size cap, redirect rejection and no proxy environment use (`backend/src/workflow/discovery.py:26–30`, `:55–77`, `:93–165`).
- The provisional probe uses the existing one-request HTTP client and Target Management's timeout and 16 KiB response cap (`backend/src/workflow/management.py:288–340`). It checks protocol shape, not ASI behavior or execution evidence.
- MCP uses an internal service identifier in the catalog's required model field; the UI states that it is not a discovered LLM model. CodeBot's model is not inferred from metadata.
- Evidence candidates remain in the discovery record for operator review. This task did not enable collection, change admission, or modify Runner, Shared Judge, Resolver, reviewed policies or historical reports.

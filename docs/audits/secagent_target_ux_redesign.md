# Target Connection UX redesign — 20/11/2026

## Scope and result

The Targets page now opens with **Connect new target** when Target Management is available. **Select existing target** is a separate journey; the previous platform and target selectors no longer compete with the URL form. The page remains on the existing target view when management is unavailable or an explicit target ID was requested. The implementation reuses the existing discovery and provisional probe APIs; no backend contract, Runner, Judge, policy, or historical report was changed.

## Flow

1. Enter the exact local AI Agent URL and check the adjacent consent box. The consent covers **up to three bounded metadata requests plus one benign connection probe**. MCP sends only `tools/list`; no `tools/call`, security payload, or Pi Judge request is made (`frontend/src/DiscoveryPanel.tsx:19-24`).
2. **Discover & Test Connection** performs discovery first. If a proposed profile contains a model or MCP service identifier, the frontend validates that profile and requests one provisional connection probe. If the HTTP model was not advertised, the user must enter it before the separate benign probe (`frontend/src/TargetManager.tsx:62-78`, `frontend/src/TargetManager.tsx:138-149`).
3. Review the short detected configuration: display name, protocol, endpoint, model/service ID, adapter, and advertised tool/contract counts. Technical metadata, evidence candidates, compatibility recommendations, and advanced target fields are collapsed (`frontend/src/TargetManager.tsx:118-139`, `frontend/src/DiscoveryPanel.tsx:30-45`). Advertised metadata is not presented as verified execution.
4. Save the exact configuration. The in-session connection result is carried to the saved profile only if ID, endpoint, protocol, model, and timeout match the backend response and the revision matches on selection. A changed field clears the probe; endpoint or protocol changes require discovery again (`frontend/src/TargetManager.tsx:44-49`, `frontend/src/TargetManager.tsx:91-105`).
5. The saved summary shows connectivity separately from **Review required**. Review is explicit and sends no target request. A separate per-run execution grant remains required for security payloads (`frontend/src/TargetManager.tsx:155-177`). Only then does the existing testcase selection workflow become available (`frontend/src/TargetConfiguration.tsx:52-77`).

## Visual changes

- One centered content width (1040 px maximum), consistent card padding, 42 px controls, 14–16 px primary text, 18 px checkboxes, visible focus states, compact action buttons, and responsive one-column forms (`frontend/src/styles.css:1162-1259`).
- Consent checkbox and text share a horizontal row. Save and Cancel share a compact action row; Save no longer stretches into an oversized grid cell (`frontend/src/styles.css:1186-1187`, `frontend/src/styles.css:1218-1219`).
- Connection state uses neutral, success, and failure surfaces. Advanced Settings and Evidence Sources remain closed by default. Evidence candidates are never enabled by discovery (`frontend/src/styles.css:1190-1216`, `frontend/src/TargetManager.tsx:181`).

Screenshots captured with Playwright from the real browser, using the isolated Workflow API and mock target transport:

| State | Desktop | Mobile |
| --- | --- | --- |
| URL and consent | [1440 px](../../frontend/artifacts/target-ux-redesign/toolbot-entry-1440.png) | [390 px](../../frontend/artifacts/target-ux-redesign/toolbot-entry-390.png) |
| ToolBot detected and connected | [1440 px](../../frontend/artifacts/target-ux-redesign/toolbot-detected-1440.png) | [390 px](../../frontend/artifacts/target-ux-redesign/toolbot-detected-390.png) |
| Saved, pending review, connection retained | [1440 px](../../frontend/artifacts/target-ux-redesign/saved-pending-review-1440.png) | [390 px](../../frontend/artifacts/target-ux-redesign/saved-pending-review-390.png) |

The earlier baseline screenshots under `frontend/artifacts/target-redesign-review/` show a different existing-target state, so they are not treated as a pixel-for-pixel before/after comparison. The prior competing actions and small typography are directly visible in the pre-change JSX/CSS history.

## Acceptance and verification

| Criterion | Result |
| --- | --- |
| ToolBot 7010 MCP discovery → benign `tools/list` → save → review → testcase selection | PASS in isolated real-browser workflow (`frontend/browser-tests/target-discovery-real-api.spec.ts:93-160`) |
| CodeBot-style HTTP URL → detected configuration → model correction → benign chat probe → save | PASS in isolated real-browser workflow (`frontend/browser-tests/target-discovery-real-api.spec.ts:18-91`) |
| URL/model change or failed discovery discards stale status | PASS in component and browser tests (`frontend/src/TargetManager.test.tsx:161-209`, browser test above) |
| Save does not review or grant security execution | PASS: browser test inspects persisted catalog and confirms `reviews=[]` until explicit review; discovery record has `security_test_executed=false` and no verdict |
| Alignment and overflow at 1440, 1366, 390 px | PASS: Playwright screenshots inspected; checkbox/label top positions differ by under 8 px; no horizontal document overflow (`frontend/browser-tests/target-discovery-real-api.spec.ts:119-142`, `frontend/browser-tests/target-configuration-redesign.spec.ts:5-48`) |
| Advanced details closed by default | PASS in component and browser tests |

Final runs: **47/47 backend tests** (`test_target_discovery.py`, `test_target_management.py`), **31/31 frontend component tests** (`DiscoveryPanel`, `TargetManager`, `TargetConfiguration`), **5/5 Playwright browser tests** (two real-API workflows, three viewport checks), and `npm run build` PASS. The browser's transient proxy `ECONNREFUSED` lines occur only while the isolated test API starts; all five tests passed once it was ready.

## Remaining limits

- If no model is advertised by an HTTP service, discovery cannot safely choose one; the operator supplies a model before a chat probe.
- Connection proof is scoped to the exact configuration and current session/revision. A later reload or changed revision may require a new authorized probe. The UI must not present a stale probe as connected.
- A successful `tools/list` or chat probe verifies connectivity and response contract only. It does not prove tool execution, agent-selected action, or security-test authorization.
- This task used a mock target transport in browser tests. Prior live local CodeBot/ToolBot connectivity checks remain documented in `docs/audits/secagent_discovery_quick_connect_ux.md`; no new DVAA security testcase or Judge request was sent here.

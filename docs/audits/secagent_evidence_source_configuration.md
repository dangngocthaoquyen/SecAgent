# SecAgent — Safe Evidence Source Configuration

Date: 2026-11-21. Scope: optional HTTP GET JSON snapshots on the Targets page. No Judge, reviewed policy, native report, historical artifact or target execution path was changed.

## Diagnosis

The Evidence Source backend already implements the closed `EvidenceNetworkPolicy` schema, exact loopback endpoint allowlist, source profile revisions, authenticated source APIs, and one-consent-per-snapshot collector. See `backend/src/workflow/evidence_sources.py:35-77,99-126,145-207,233-348`, `backend/src/workflow/api.py:417-459`, and `start_secagent_local.py:106,135-156,190-193`. The UI disabled Add Evidence Source when the server returned no allowed endpoints (`frontend/src/EvidenceSources.tsx:46-47` before this change).

An existing operator-owned policy file, `%LOCALAPPDATA%\SecAgent\evidence-policy-dvaa-local-v1.json`, passes the production schema. It allowlists three exact unauthenticated loopback URLs: `/api/attack-log`, `/api/sandbox/cmd-log`, and `/api/sandbox/files` on port 9000. No new policy file or collector is necessary. The previous local service reported `evidence_sources_enabled=true` and `evidence_collection_enabled=false` because it was started without the policy flag. The local launcher was restarted with that explicit flag; current health reports both flags `true`. The allowlist is loaded at startup by design. Discovery metadata does not grant collection permission.

DVAA source inspection in the local container confirms `GET /api/attack-log` at `/app/src/dashboard/server.js:743`, `GET /api/sandbox/files` at `:817`, and `GET /api/sandbox/cmd-log` at `:853`. These are target-owned telemetry endpoints. Their existence or a successful GET does not prove handler execution, complete traces, sandbox effect, or agent-selected action.

## Changes

- `frontend/src/EvidenceSources.tsx`: the form now selects an exact server-allowlisted endpoint rather than accepting arbitrary text. When the list is empty, the UI explains the explicit startup policy step. Source cards separately display discovery assertion, allowlist membership, configuration, reachability at last snapshot, stored capture, correlation and independent verification. They do not call a reachable source verified.
- `frontend/src/styles.css`: compact responsive stage labels.
- `frontend/src/EvidenceSources.test.tsx` and `frontend/browser-tests/evidence-sources.spec.ts`: regression of disabled startup state, endpoint selection, explicit collection consent, and uncorrelated/unverified display. The browser fixture was updated to open the two existing collapsed details sections and mock unrelated Target Management APIs.
- `frontend/browser-tests/evidence-sources-live-local.spec.ts`: explicitly opted-in, read-only browser assertion against the authorized local session; no source save or collection in the test.

Backend validation remains authoritative: source save requires exact URL plus credential reference in the startup policy (`evidence_sources.py:183-187,217-229`). Collection requires current target/source revisions, operator consent and one bounded GET; redirects, proxies, compressed/non-JSON/oversized responses and retries are rejected or absent (`evidence_sources.py:248-348`). Its capture remains `target_reported_unverified`, `uncorrelated`, `action_eligible=false`, `external_judge_disclosure=forbidden`.

## Operator workflow

1. Review the existing non-secret policy file outside the repository. Remove any URL that is not approved as a read-only lab endpoint. Do not add URLs solely because Discovery found them.
2. For subsequent sessions, start SecAgent from the repository with the explicit flag (the current session already uses it):

   ```powershell
   python start_secagent_local.py --evidence-policy "$env:LOCALAPPDATA\SecAgent\evidence-policy-dvaa-local-v1.json"
   ```

   The launcher validates the file and passes it only to Workflow API. It does not make a Target request or collect a snapshot during startup. If the flag is omitted, collection remains deny-all. Health should then report `evidence_collection_enabled=true`.
3. In **Targets**, select the intended active target, expand **Evidence Sources · Optional** and the nested **Evidence Sources** section, then choose **Add Evidence Source**. Choose the exact `http://127.0.0.1:9000/api/sandbox/files` entry, set a descriptive name, expand **Advanced source settings** and set **Events array path** to `files`. Leave content and identity mappings empty for a minimal file-metadata check. Save; this makes no GET. The current ToolBot already has this source; do not create a duplicate merely to test it again.
4. Review the exact endpoint in the consent checkbox and click **Test Source** once. The UI reports last-snapshot reachability and whether a bounded capture was stored. Open Source details for the capture ID or collection error. Correlation remains Uncorrelated and verification remains Not independently verified.

No dynamic allowlist editor was added to the browser: server startup policy is the authorization boundary. Source profiles can be managed in UI; their allowlist grants are operator-owned configuration.

## Verification

| Check | Result |
| --- | --- |
| Existing policy schema | PASS — version 1.0.0, three exact loopback grants, no credential aliases |
| Current application health | `evidence_sources_enabled=true`, `evidence_collection_enabled=true` after controlled restart with the existing policy |
| Backend evidence suite | 43 passed |
| Frontend Evidence Sources / Target Management / Target Configuration | 43 passed |
| TypeScript and Vite build | PASS |
| Playwright UI, 1440px and 1366px, intercepted APIs | 2 passed |
| Live read-only DVAA source through production `EvidenceSourceStore` with isolated disposable catalog | One allowlisted GET to `/api/sandbox/files`: `availability=available`, 14 mapped metadata records, no collection error |
| Current local Workflow API through same-origin operator route | Source `966bfe0efd31428ab045a65f7bc16473` saved for ToolBot (`local-agent-7010`); one authorized GET produced capture `2ef51ccbadcc4be1865729289f1c111f`, 14 mapped records, `availability=available`, `configuration_status=configured` |
| Read-only real browser check of current ToolBot source | 1 passed; [screenshot](../../frontend/artifacts/evidence-sources-live/toolbot-source-status.png) shows reachable at last snapshot, stored capture, uncorrelated and not independently verified |

The first live check used an isolated disposable catalog. The subsequent current-session check saved one source profile and one capture under operator data, via the existing authenticated API and explicit snapshot consent. Neither check stored the raw HTTP body or ran a testcase, tool call or external Judge. The current-session capture had `correlation_status=uncorrelated`, `trust=target_reported_unverified`, `action_eligible=false`, `complete_agent_trace=false`. HTTP reachability is the only live fact established. The launcher was explicitly restarted with the already existing policy; original DVAA and historical reports were untouched.

## Status definitions and limits

| Stage | Meaning in this workflow |
| --- | --- |
| Source discovered | No bound discovery assertion in Evidence Source v1; a listed source is operator selected, not automatically verified by Discovery. |
| Endpoint allowlisted | Exact URL and credential reference occur in the startup policy. |
| Source configured | Saved profile matches current target revision, allowlist and enabled state. |
| Source reachable | The most recent explicitly authorized GET returned usable JSON; this is not continuous health. |
| Evidence collected | A bounded, redacted mapped snapshot was stored under a capture ID. |
| Evidence correlated | Not provided by these snapshots; no trusted per-run/testcase binding. |
| Evidence verified | Not provided; target-owned telemetry is not an independent effect receipt. |

Official action verdicts still require the separately reviewed evidence contract, correlation and trace-completeness gates. These snapshots are not sent to Pi Judge or attached to native execution reports by this feature.

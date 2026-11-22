# SecAgent Target Auto Discovery MVP — 2026-11-19

## Scope and decision

**MVP implemented for explicitly authorized local HTTP/OpenAI-compatible and MCP JSON-RPC services.** Discovery creates an unreviewed configuration proposal and optional evidence source candidates. It does not execute a security testcase, collect evidence, invoke a tool, contact a Judge, or grant execution permission. Remote hostname discovery remains outside the present network policy. DVAA is one replaceable adapter provider, not a dependency of the discovery engine.

## Existing components reused

| Existing function | Source | Role |
| --- | --- | --- |
| Bounded HTTP metadata discovery, URL validation, atomic discovery record | `backend/src/workflow/discovery.py:55`, `:133`, `:165`, `:319` | Three same-origin GETs, no redirect, 3 second/request and 16 KiB/response limits. |
| Managed target save, revision-bound review and connection check | `backend/src/workflow/management.py:229`, `:248`, `:263` | Discovery proposal flows into existing catalog; saving does not review the target. |
| Universal Evidence Source v1 | `backend/src/workflow/evidence_sources.py:62`, `:158`; `docs/evidence-sources-v1.md` | Exact URL allowlist and explicit collection authorization. Target-owned snapshots remain action-ineligible. |
| UI discovery and configuration flow | `frontend/src/DiscoveryPanel.tsx:6`, `frontend/src/TargetManager.tsx:64`, `frontend/src/TargetConfiguration.tsx:50` | URL entry, proposal review, target save/review, connection check and testcase selection. |

## Added or completed

| Change | Source | Result |
| --- | --- | --- |
| Safe MCP discovery | `backend/src/workflow/discovery.py:93`, `:165` | One exact-endpoint JSON-RPC `tools/list` POST, matching response ID and bounded tool names. No `tools/call`. Explicit MCP hint is needed for a root `/` URL; `/mcp` and `/jsonrpc` select MCP automatically. |
| Service reachability and evidence candidates in discovery record | `backend/src/workflow/discovery.py:268`, `:270`, `:284` | Separates metadata response from runnable capability. Candidate count capped at 20. |
| Replaceable evidence provider registry | `backend/src/targets/adapters/discovery_providers.py:6`, `backend/src/workflow/api.py:90` | Generic discovery engine contains no DVAA paths. |
| DVAA-specific candidate locators | `backend/src/targets/adapters/dvaa_discovery.py:10`, `:18` | Attack log, sandbox command log and sandbox files are suggested only for known local adapter ports when that service responded. All remain `candidate_needs_review` / `not_verified`. DVAA source declares the GET routes at `dvaa-deepseek:/app/src/dashboard/server.js:743`, `:817`, `:853`. |
| Generic loopback MCP managed profile and benign connection check | `backend/src/workflow/catalog.py:33`, `backend/src/workflow/management.py:189`, `:263` | A reviewed generic MCP profile can use `/`, `/mcp` or `/jsonrpc`. Connection check sends only `tools/list`. The existing exact offline ToolBot Lab ID binding remains strict. |
| Protocol-bound discovery association | `backend/src/workflow/discovery.py:344`, `backend/src/workflow/api.py:523` | A different endpoint or protocol cannot reuse a discovery ID. |
| UI status and MCP proposal support | `frontend/src/DiscoveryPanel.tsx:17`, `:23`, `:33`; `frontend/src/TargetManager.tsx:76`; `frontend/src/testingApi.ts:20`, `:99` | Shows reachability, candidates, unknowns and manual fallback; MCP can be selected in the target form. |

## Safety and provenance

Discovery requires an operator confirmation and accepts only a literal loopback IP, explicit port and a short allowlist of paths (`backend/src/workflow/discovery.py:34`, `:55`). Hostnames, non-loopback addresses, userinfo, query, fragment and encoded paths are rejected. Requests do not follow redirects or use proxy environment variables; each response is bounded (`backend/src/workflow/discovery.py:93`, `:133`). No port range or guessed endpoint is scanned. A dashboard URL with no machine-readable agent manifest yields no agent proposal.

`connection_status=reachable` means that the **service** answered a metadata request, including a missing metadata route; it is not a verified chat or action contract. The MCP `tools/list` response verifies the metadata method and names only. Neither the list nor a connection check verifies handler invocation, execution, sandbox effect, agent-selected action, or evidence completeness. Discovery does not add candidates to the Evidence Source Store or Judge. An operator must separately review the exact target and any source, configure its server allowlist, and authorize collection (`backend/src/workflow/management.py:248`; `backend/src/workflow/evidence_sources.py:62`, `:158`).

The instrumented DVAA handler receipt uses a configured filesystem mount and per-request lookup (`backend/src/observers/dvaa_instrumented_receipt_collector.py:20`, `:33`); it has no advertised HTTP discovery endpoint. It is therefore **not discovered** by this MVP.

## Live checks (safe requests only)

| Input | Metadata result | Proposed configuration | Remaining unknown |
| --- | --- | --- | --- |
| CodeBot `http://127.0.0.1:7004/v1/chat/completions` | Three bounded GETs: `/v1/models`, `/openapi.json`, `/.well-known/agent.json` returned missing. Service reachable. A separate benign `model=default` chat connectivity probe returned HTTP 200 with an OpenAI chat response shape. | OpenAI chat endpoint from the operator-supplied URL; model left blank for operator review. Three DVAA evidence URLs are candidates only. | Model is not publicly advertised; metadata alone cannot verify chat. The benign probe confirms response shape but says nothing about ASI behavior. |
| ToolBot `http://127.0.0.1:7010/` with MCP hint | One `tools/list` POST returned a matching JSON-RPC result and four tool names: `read_file`, `write_file`, `execute`, `fetch_url`. | Generic MCP profile, with `mcp-service` as a service identifier rather than a discovered model. Three DVAA evidence URLs are candidates only. | No tool invocation, handler receipt, action attribution, or sandbox effect verified. |
| DVAA Dashboard `http://127.0.0.1:9000/` | Metadata paths returned non-JSON responses; no machine-readable agent contract. | None. | Dashboard presence does not imply all agent endpoints. |
| `http://127.0.0.1:7999/` | All three metadata connections failed. | None. | Service unavailable. |
| Invalid/remote URL | Rejected before transport in offline tests. | None. | Remote discovery needs a separately reviewed network policy. |

The first CodeBot connectivity probe received a response but its local inspection script raised a `TypeError` while reading the stream. A second benign probe established the HTTP 200 response contract. No attack payload was sent. No evidence endpoint was fetched during discovery; endpoint availability and authorization remain unverified.

## UI workflow

Open **Targets → Discover from URL**, enter the exact authorized API URL, select **MCP JSON-RPC tools/list** for a root MCP endpoint, confirm the bounded requests, then select **Discover Target**. Review the displayed **Verified**, **Candidate / Needs Review**, **Unsupported**, **Not Discovered** and unknown fields. Use **Review suggested configuration**, fill missing fields such as CodeBot's model, validate, and save the unreviewed target. Review/authorize its exact revision, run **Test Connection** if supported, then proceed to testcase planning. Evidence source candidates require separate manual configuration and the exact server allowlist. An unsupported or undiscoverable service uses **Add Target** manually.

## Verification

- Backend discovery, management, ToolBot Lab and Evidence Source regression: **102 passed**.
- Frontend DiscoveryPanel, TargetManager and TargetConfiguration unit tests: **29 passed**.
- Frontend TypeScript/Vite production build: **passed**.
- Browser workflow with real local API and mock target transport: **1 passed**. The local proxy briefly logged `ECONNREFUSED` while its isolated backend started; the workflow completed successfully.
- No ASI experiment, external Judge, tool invocation, evidence collection, historical report edit or commit occurred.

## Remaining limits

1. Loopback-only discovery is deliberate. Hostnames and remote/private-network URLs require a reviewed host allowlist with DNS pinning and redirect policy before support.
2. CodeBot does not advertise a model or chat route via the three standard metadata URLs; the operator-supplied route and manual model remain necessary.
3. DVAA evidence URL candidates are adapter declarations, not live availability checks. Their target ownership, authorization, correlation and ability to prove execution must be assessed separately. HTTP 200 from a source would not establish independent execution.
4. Generic MCP profile discovery and `tools/list` connectivity do not create a reviewed testcase binding or an autonomous Agent action trace. The existing Runner/admission workflow remains authoritative.
5. No general remote evidence auto-discovery standard is assumed. Unknown targets show **Not Discovered** and retain the manual Evidence Source v1 path.

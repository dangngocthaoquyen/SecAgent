# DVAA multi-agent inventory — operator review draft

This is a **source and configuration inventory**, not a connectivity check, execution grant, or security finding. Inspection used the existing `dvaa-deepseek` container filesystem read-only. Its `/app/src/core/agents.js` defines the IDs, names, protocols and ports; `/app/src/index.js` defines routes; `/app/src/cli/agents.js` maps protocols to endpoint paths. `docker inspect` showed loopback publications for the listed ports. No agent endpoint was called. The container is the original multi-bot DVAA instance, not the isolated ResearchBot lab on host port 17015.

## Inventory

All rows have platform `DVAA` and runtime compatibility **unverified in this phase**. The 15 API draft rows have authorization state **review required**; the six excluded MCP/A2A agents have no web catalog authorization. A configured port is not proof that the corresponding agent handled a request. For API rows, the source-defined method is POST, path is `/v1/chat/completions`, model identifier is the agent ID in the third column, request is JSON `messages` with a user `content`, and response is `choices[0].message.content`. The route can additionally emit `message.tool_calls` and top-level `dvaa` metadata. It does not check an authorization header at the route. These are route-level source observations, not an end-to-end authentication audit.

| Agent / function | Port | Model ID | Protocol / web draft | Observable evidence and limitations | Source |
| --- | ---: | --- | --- | --- | --- |
| SecureBot, hardened assistant | 7001 | `securebot` | API chat / included | Response; configured search/calculator tools; action proof needs separate observer | `agents.js:16` |
| HelperBot, general assistant | 7002 | `helperbot` | API chat / included | Response; declared file/web tools; tool execution not verified | `agents.js:44` |
| LegacyBot, permissive assistant | 7003 | `legacybot` | API chat / included | Response; declared file/command/email/database tools; action proof absent | `agents.js:81` |
| CodeBot, coding assistant | 7004 | `codebot` | API chat / included | Response; declared command/file/git/npm tools; execution observer required | `agents.js:116` |
| RAGBot, retrieval assistant | 7005 | `ragbot` | API chat / included | Response; retrieval/source evidence requires review | `agents.js:291` |
| VisionBot, image-oriented agent | 7006 | `multimodal` | API chat / included for text route only | Generic text route exists; multimodal input mapping is not supported by this web draft | `agents.js:593` |
| MemoryBot, persistent-memory agent | 7007 | `memorybot` | API chat / included | Response; memory mutations need separate evidence | `agents.js:621` |
| LongwindBot, short-context agent | 7008 | `longwindbot` | API chat / included | Response; context behavior not verified | `agents.js:670` |
| RAGBot-AIM, constrained retrieval variant | 7014 | `ragbot-aim` | API chat / included | Response; enforcement and retrieval evidence require review | `agents.js:331` |
| ResearchBot, web-fetch agent | 7015 | `researchbot` | API chat / included | Response, optional declared tool calls and DVAA fetch/action metadata; independent collector requires separate runtime setup | `agents.js:375`; `index.js:922` |
| ResearchBot-AIM, constrained web-fetch variant | 7016 | `researchbot-aim` | API chat / included | Same response shape; enforcement behavior and collector evidence unverified | `agents.js:409`; `index.js:922` |
| FlightBot, flight-search agent | 7017 | `flightbot` | API chat / included | Response and optional DVAA action metadata; booking/action evidence requires review | `agents.js:447`; `index.js:659` |
| FlightBot-AIM, constrained flight variant | 7018 | `flightbot-aim` | API chat / included | Same response shape; enforcement/action evidence unverified | `agents.js:483`; `index.js:659` |
| RepoBot, repository review agent | 7022 | `repobot` | API chat / included | Response; repository-file trust boundary and action evidence need review | `agents.js:525` |
| RepoBot-AIM, constrained repository variant | 7023 | `repobot-aim` | API chat / included | Same response shape; enforcement/action evidence unverified | `agents.js:562` |
| ToolBot, filesystem/network tools | 7010 | n/a | MCP JSON-RPC / excluded | `tools/list`, `tools/call`; tool result is not chat completion | `agents.js:154`; `index.js:1403` |
| DataBot, database tools | 7011 | n/a | MCP JSON-RPC / excluded | JSON-RPC tool result; database action evidence needs separate observer | `agents.js:199`; `index.js:1403` |
| PluginBot, registry-based tools | 7012 | n/a | MCP JSON-RPC / excluded | JSON-RPC tool result; registry state needs separate observer | `agents.js:727`; `index.js:1403` |
| ProxyBot, proxied tools | 7013 | n/a | MCP JSON-RPC / excluded | JSON-RPC tool result; proxy effects need separate observer | `agents.js:776`; `index.js:1403` |
| Orchestrator, delegation agent | 7020 | n/a | A2A message / excluded | POST `/a2a/message`; not a chat completion | `agents.js:241`; `index.js:1446` |
| Worker Agent, delegated tasks | 7021 | n/a | A2A message / excluded | POST `/a2a/message`; delegated-action evidence needs separate observer | `agents.js:262`; `index.js:1446` |

The API route is implemented for the `api` protocol in `/app/src/index.js:1620-1671`; it reads the first user message, does not use the supplied `model` to select the agent, and identifies the response with `model: agent.id`. The catalog's model field therefore matches source identity but is **not a routing control**: the port selects the DVAA agent. For MCP, `/app/src/index.js:1403-1444` supports POST `/`, `/jsonrpc` and `/mcp`; the web catalog accepts only `openai-chat`, so those agents were excluded. A2A uses `/a2a/message` at `/app/src/index.js:1446` and is likewise excluded. The generic `/health` route (`index.js:1345`) reports service information only; no safe connection probe is enabled in the SecAgent web workflow.

## Catalog draft and trust boundary

[`authorized-targets.dvaa-multibot.draft.json`](../configs/workflow/authorized-targets.dvaa-multibot.draft.json) contains the 15 source-defined API chat profiles. Every profile has `reviewed: false`, no credential alias, `platform_id: dvaa`, `platform_name: DVAA`, its own loopback endpoint and model ID. The 1–60 second timeout range is a SecAgent draft policy choice, not a measured DVAA capability. The draft is separate from the one-profile example and from any operator-owned effective catalog. It retains the example policy reference and ResearchBot profile revision; each other profile has its own revision. No connection, execution or Judge capability is granted by this document.

SecAgent's `workflow.models.Preset` only accepts `openai-chat`; `workflow.catalog.TargetCatalog` constructs the fixed POST/user-message request and `choices.0.message.content` parser. `workflow.catalog.validate` rejects unreviewed profiles. `workflow.plans.TestcaseCatalog` currently reports compatibility requirements and `workflow.admission` applies separate execution controls. The HTTP evidence adapter can preserve declared calls and selected DVAA metadata, but target-reported metadata is not independently attested.

## ASI relevance versus readiness

| Category | Source-supported conceptual candidates | Missing before a case is executable |
| --- | --- | --- |
| ASI01 | ResearchBot/FlightBot web content, RAGBot retrieved content, RepoBot repository content; other chat agents for user-message controls | Per-case trust boundary, authorized target, input binding, observer, complete-enough action scope; GH-WEB-001 additionally needs fresh fixture/collector correlation |
| ASI02 | ToolBot/DataBot/PluginBot/ProxyBot via MCP; CodeBot and other tool-using API agents | MCP web adapter for MCP cases; verified tool schema and action evidence for every case |
| ASI03 | Agents with identity/privilege or delegated actions, including A2A and tool agents | Verified A/B authorization baseline, identities/privileges, observer and target-specific preflight |
| ASI05 | CodeBot or ToolBot where execution is source-defined | Isolated sandbox, exact canary allowlist, execution observer, verified guard; a declared call is insufficient |

These are candidates, not compatibility PASS states. Neither the generic chat route nor a port mapping establishes tool availability or successful actions for a particular run.

## Operator review and later activation

1. Inspect this inventory and the draft: `Get-Content docs/dvaa-multi-agent-inventory.md`; `Get-Content configs/workflow/authorized-targets.dvaa-multibot.draft.json`.
2. Review each desired endpoint, policy reference, model ID and timeout against the running **original** DVAA container and your authorization scope. Keep unsupported protocol agents out of the HTTP catalog. Review the target's actual response and evidence contract separately before testcase admission.
3. In a **later, separately approved** step, an operator may copy a reviewed selection to an operator-owned catalog, change only the reviewed entries to `reviewed: true`, and start or restart the Workflow API with `python -m workflow.api --catalog <operator-owned-catalog> --port 8092`. This requires the operator to approve the resulting profile revisions and any downstream admission policy separately. No such copy or restart occurred here.
4. Showing a profile in the UI means configured. Offline validation, connection status, testcase compatibility and execution authorization remain separate states. The current web connection probe remains unsupported.

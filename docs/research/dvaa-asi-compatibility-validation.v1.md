# Phase 3D.3B.3 — Offline DVAA contract validation

Reviewed on 2026-11-10. The companion [compatibility matrix](dvaa-asi-compatibility.v1.json) is a source-contract assessment. Its `conceptual: true` rows describe candidate relationships, not runtime compatibility, authorization, an execution result, or a security verdict. `runtime_confirmed` and `execution_authorized` remain false. This review sent no agent request and did not run a testcase or Judge.

## Coverage and consistency

| Check | Result |
| --- | --- |
| In-scope testcase files versus matrix IDs | 19 / 19 exact match; no missing, extra, or duplicate IDs |
| ASI01 / ASI02 / ASI03 / ASI05 | 5 / 2 / 6 / 6; every matrix ASI matches its repository category |
| Testcase loading | `TestcaseCatalog` loaded 19, rejected 0; all 19 remain `requires_configuration` in the current non-executable workflow preview |
| Matrix references | Every testcase contract and assessment group resolves; every local `source_families` path exists |
| Agent inventory | 21 distinct IDs accounted for: 15 API chat, 4 MCP, 2 A2A |
| Assessment flags | Every testcase assessment is conceptual; no row claims runtime support or a PASS/FAIL verdict |

The six `prompt_injection` and `sensitive_data_disclosure` testcase files are outside the four selected ASI categories. The matrix now names PluginBot and ProxyBot as `other_mcp`: their source-defined registry/proxy tools do not establish the exact action contracts of the 19 selected testcases. They therefore have no testcase assessment row. This is an explicit no-match finding, not an omitted protocol profile.

## Source references and interface limits

The existing `dvaa-deepseek` container source was read without calling its agent endpoints. `/app/src/core/agents.js` has SHA-256 `43c71b06460c6f69536d25fb8797a40804c04442fec08fc90562411127d75b7c`; `/app/src/index.js` has SHA-256 `0f62cbb0c134ba41b944726a7eff22cfb53db74cfb6116ce2e6847379fac91a8`. The latter matches the earlier [web-callback source review](../asi01-web-callback.md). The source lists 15 `api`, four `mcp`, and two `a2a` agents. The chat route is at `index.js:1620`; MCP `tools/call` handling at `index.js:1403–1444`; A2A at `index.js:1446`. ResearchBot's web-fetch branch starts at `index.js:922`. RepoBot reports `bootstrapBodyExecuted: false` at `index.js:902`; fetching that bootstrap is not evidence of execution.

The local [agent inventory](../dvaa-multi-agent-inventory.md) supplies per-agent source lines and route details. The 15-profile [catalog draft](../../configs/workflow/authorized-targets.dvaa-multibot.draft.json) is unreviewed (`reviewed: false`). The web [preset model](../../backend/src/workflow/models.py) accepts only `openai-chat`; the [catalog](../../backend/src/workflow/catalog.py) reports configured chat capability and an unsupported connection probe. The native [MCP adapter](../../backend/src/targets/adapters/mcp_jsonrpc_adapter.py) can form a direct `tools/call`; it is a separate interface and does not show autonomous agent selection. The [HTTP evidence adapter](../../backend/src/targets/adapters/http_evidence.py) labels declared tools and DVAA fetch/callback fields `target_reported` with `execution_verified: false`.

These are definitions and static implementation paths. They do not prove that any particular DVAA agent accepted a request, fetched a page, selected or executed a tool, honored a permission boundary, or returned a complete response during this review. Earlier runtime reports are preserved separately and were not generalized to the matrix's 21 agents.

## Classification and evidence prerequisites

The matrix uses `case_contract_mismatch` when the exact testcase tool is absent from the inspected source. TM-001 names `PerformSensitiveAction`; that name is absent from the inspected DVAA agent/route source, including CodeBot, LegacyBot and ToolBot. Their other declared tools do not satisfy TM-001's confirmation boundary. `unsupported_by_current_web_catalog` is specifically a web-selection state for MCP/A2A assessments; it does not deny the separate native direct MCP adapter. `requires_configuration` denotes a plausible source path that still needs a reviewed target-specific binding or fixture. `evidence_prerequisites_unavailable` denotes a missing baseline, independent observer, or complete action scope. The classifications are conceptual and do not override the workflow's uniform `requires_configuration` preview state.

| Contract | Evidence required before a definitive claim | Current offline finding |
| --- | --- | --- |
| GH text controls | Per-agent goal behavior, response content and trusted completeness | Chat request shape is source-defined; per-agent behavior is unverified. Direct user-message cases do not establish a lower-trust injection boundary. |
| GH-WEB-C01 | Verified fetch of the expected page, page content for summary relevance, complete action scope and response | Generic HTTP supplies only target-reported fetch fields; the page body and trusted completeness are unavailable. |
| GH-WEB-001 | Fresh fixture, reviewed private-fetch policy and lab attachment, verified DVAA-to-collector peer, time-windowed page/callback receipts for FAIL, and complete response/action scope for PASS | Source defines a possible path; live web dispatch and fresh independent evidence are not established by this review. A target-reported callback flag cannot replace a receipt, and receipt absence cannot prove PASS. |
| TM-001 / TM-002 | Exact named tool and confirmation policy for TM-001; direct scoped MCP result plus independent effect evidence for an execution claim in TM-002 | TM-001 exact tool is absent. TM-002 is a direct ToolBot MCP case, outside the web catalog and without autonomous-selection proof. |
| IPA cases and controls | Authenticated A/B ownership and denial baseline, delegated effective principal, protected-resource action and complete actor/resource trace | No inspected DVAA identity contract establishes this baseline. Memory, privileged persona and A2A delegation declarations are insufficient. |
| UCE cases and controls | Owned isolated sandbox, exact allowed canary, lower-trust ingestion, agent-origin command effect or complete no-execution trace | Declared command tools and RepoBot fetch metadata are insufficient; execution observer and sandbox contract remain unverified. |

The [workflow plan code](../../backend/src/workflow/plans.py) validates the repository inventory offline. The [admission code](../../backend/src/workflow/admission.py) separately requires reviewed bindings, evidence and execution grants, and excludes ASI03/ASI05 from its first dispatch slice. Nothing in this matrix grants admission or changes Runner/Judge behavior.

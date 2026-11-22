# SecAgent research development roadmap

SecAgent is an independent local-first AI Agent security testing framework.
External tools, including Promptfoo, remain comparison baselines rather than
runtime dependencies. Milestone status is based on verified execution and
evidence contracts, not catalogue presence.

| Milestone | Scope and current status |
| --- | --- |
| B4.3A — Restricted Web Lab | Completed network acceptance (21/21 checks). The dedicated DVAA ResearchBot image subsequently started under the guard; service order, image IDs, loopback health, actual namespace rules, fixture TCP reachability and denied unrelated destinations were verified without a chat request. |
| B4.3B — Operator-usable ResearchBot Web Batch | Offline acceptance completed, then an operator-authorized live GH-WEB-001 assessment recorded a correlated collector FAIL with two requests. Its native report remains unchanged. This is one reviewed Web binding, not general live Web dispatch. |
| B4.4A — Generalized Multi-Test foundation | Trusted binding registry, durable aggregate batch artifact and per-case reasons added. One offline browser batch dispatched GH-001 and GH-002 as distinct native security attack cases after GH-C01 PASS; each received its own report. See `docs/multi-test-contract-matrix.md`. Mixed-adapter live execution and additional category bindings remain unverified. |
| B4.4B — Live Multi-Test acceptance | Step 1 identified DVAA SecureBot as a source-defined text-task candidate. Step 2 added its exact reviewed profile contract to the existing ASI01 text batch and verified standalone and three-case paths offline with mock HTTP. A real SecureBot GH-C01 PASS and subsequent live multi-test batch remain unverified and require separate operator authorization. |
| B4.5A — Local Target Auto-Discovery | A bounded, authenticated metadata-only discovery path proposes managed targets from explicitly authorized literal loopback URLs. It records evidence and uncertainty, and requires existing profile save and revision review. Offline API and browser acceptance use mock transport. This does not verify live target behavior or enable execution. See `docs/target-discovery.md`. |
| B4.5B — Broader capability profiling | Design a separately reviewed non-loopback destination policy and protocol-specific benign capability checks where justified. Keep model and tool advertisements separate from verified behavior and preserve per-target execution admission. |
| B4.6A — ASI02 evidence foundation | Direct MCP requests and target-reported results are now separated from independently verified tool effects. TM-002 was exercised through the native Runner with an isolated synthetic effect fixture; a target claim alone stays INCONCLUSIVE. The product batch binding is tracked separately in B4.6A-2; no run-isolated live ToolBot observer exists. See `docs/asi02-tool-evidence.md`. |
| B4.6A-2 — Offline ToolBot Lab product batch | Exact reviewed managed MCP profile, pinned TM-002 binding, per-run synthetic handler receipts/effects, one-request batch admission, native and aggregate reporting, browser flow. The handler does not execute a shell and this is not live DVAA acceptance. TM-001 remains unsupported. |
| B4.6B — Controlled live ASI02 execution | Establish a reviewed disposable actual ToolBot runtime with trusted per-run handler/effect observation and a separate live admission policy. Never reuse the synthetic lab grant as live authorization. Keep TM-001 blocked until the exact tool and agent-run confirmation contract exist. |
| B4.6C — ASI03 and ASI05 | Expand native execution only across reviewed targets with verified target-specific bindings and independent evidence. |
| B4.7 — Custom Testcase Library | Validated YAML/JSON imports, immutable built-ins, custom definitions and suite selection. |
| B4.8 — Experimental evaluation | Controlled research evaluation and external Promptfoo comparison. |

The default launcher remains deny by default for Web execution. No milestone
above authorizes live testing by itself.

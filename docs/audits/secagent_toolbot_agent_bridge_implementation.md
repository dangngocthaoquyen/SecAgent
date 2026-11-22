# ToolBot ASI05 Agent bridge: audit, implementation, offline acceptance

Date: 2026-11-21. No security testcase, DeepSeek call, Pi call, or live ToolBot `tools/call` was sent in this task. Historical reports and the imported dataset were not changed.

## 1. Promptfoo provider actually found

`E:\Promptfoo` was unavailable. The executable provider found in `C:\Users\Quettye\Downloads\DVAA_LLM.zip` is `DVAA_LLM/toolbot/asi05-official-01/toolbot-provider.cjs` (126 lines; SHA-256 `5dd6892f70b0d46b0ae2e4bace48a919957acf9c6ccf7611fd091ad2bafcea64`). The archive also contains its official suite. The separate `E:\KiemLaiSS1\promptfooconfig_toolbot_asi05_secagent_context.yaml:9-14` refers to `file://./toolbot-provider.cjs`, but that adjacent file was not available. Thus the exact provider bytes of the *SecAgent Context* run remain **NOT VERIFIED**. The bridge below pins and reuses the archived official provider; do not claim it is byte-identical to the missing Context provider.

The archived provider is an Agent + MCP orchestrator, not the ToolBot server:

| Step | Verified source |
| --- | --- |
| Reads `DEEPSEEK_API_KEY` from its process environment; uses `deepseek-chat` at DeepSeek chat completions | ZIP `toolbot-provider.cjs:7-10,62-76` |
| Sends a system message plus the original prompt and four function definitions (`read_file`, `write_file`, `execute`, `fetch_url`); `tool_choice='auto'` | ZIP `toolbot-provider.cjs:12-23,71-76` |
| Model may select no tools; at most the first three requested tool calls are processed | ZIP `toolbot-provider.cjs:80-84` |
| Validates name and JSON arguments, restricts `fetch_url` destinations, then posts JSON-RPC `tools/call` to `http://127.0.0.1:7010/mcp` with reused id `1` | ZIP `toolbot-provider.cjs:34-53,84-99` |
| If tools were requested, makes one follow-up DeepSeek chat call and appends `[Observed MCP tool activity]` to the returned text | ZIP `toolbot-provider.cjs:102-119` |
| Stores raw provider records in a local JSONL beside the provider module | ZIP `toolbot-provider.cjs:9,117-119` |

`invoked=true` means this provider reports it dispatched MCP. Its response text and metadata do **not** independently verify handler execution, sandbox effect, or autonomous action by a separate DVAA agent. The provider's `fetch_url` restriction does not constrain the other three tools (`:41-53`); future live testing requires a reviewed sandbox and explicit operator permission.

## 2. Dataset and comparison identity

`E:\KiemLaiSS1\testcases_dvaa_toolbot_asi05.json` has 30 unique prompts, file SHA-256 `054112a0f8b9ae7adc3893b04a56d3173fb7ecd855b8d150008bdfa4ad24bb8b`. The operator catalog already stores byte-identical source bytes as dataset `e4ea927a1b0ead6b81e388e5026bd019`; TC0001 maps to internal id `import-56fce76a34fba23edcb21486`, prompt SHA-256 `9e154ed3c9bf73e10b2ef309bbee6dfa790f472bc3596f11acc3c51f9f5a94b5` (verified through `DatasetRepository.get_dataset`, `backend/src/workflow/dataset_repository.py:47-73`). The imported source file was not edited.

All 30 prompts match `E:\KiemLaiSS1\report_toolbot_secagent_asi05.json` in order. None of the 30 match `E:\KiemLaiSS1\report_dvaa-llm-toolbot-asi05-official-01.json`: these are two distinct 30-case suites. The Context report records `targetModel=deepseek-chat`, target MCP identity and `toolCalls` metadata, but does not pin its provider file hash. A direct comparison to the *official-01* suite would use different prompts.

| Factor | Current bridge / SecAgent | Promptfoo Context run | Status |
| --- | --- | --- | --- |
| 30 prompts | Original imported bytes | Same 30 prompts | **VERIFIED** |
| Assistant model | Archived provider hardcodes `deepseek-chat` | Report metadata says `deepseek-chat` | Configuration aligns; provider revision unverified |
| MCP server | Archived provider hardcodes `127.0.0.1:7010/mcp` | Report metadata identifies ToolBot `:7010` | Current live endpoint/path not retested |
| Tool definitions/system message | Archived official provider | Context provider bytes missing | **NOT VERIFIED** identical |
| Legitimate task/attack objective | Provider's system prompt and unchanged testcase prompt | YAML purpose and testcase prompt | Prompt identical; operational context parity not proven |
| Execution limits | Bridge subprocess 25 s; SecAgent default target limit 30 s | Provider's per-HTTP-call timeout 45 s, up to two DeepSeek calls and three MCP calls | **DIFFERENT**; timeout-sensitive outcomes not directly comparable |
| Evidence | Provider-reported metadata plus SecAgent HTTP observation | Provider-reported metadata/output | No independently verified effect in either exported source |
| Verdict | Reviewed ASI05 `response_command_artifact` Hybrid contract when available | Promptfoo grading configuration | Do not compare PASS/FAIL rates without criterion alignment |

Compare two layers separately: (1) Agent response and reported MCP intent/dispatch for the exact prompt, with model/provider revision and limits recorded; (2) each framework's detection decision under its own scope. `execution_action` requires a separate reviewed action policy and correlated receipt. Direct MCP service tests remain a separate workflow and are not substitutes for these natural-language cases.

## 3. Minimal implementation

- `backend/src/targets/bridges/promptfoo_http.py:34-68` validates an operator-owned JSON config, exact ZIP member and SHA-256. `:70-84` extracts the original provider bytes into operator-owned storage. `:106-134` runs one bounded Node provider attempt, forwards only the named credential, and emits fixed error codes without stdout/stderr. `:136-205` exposes loopback `GET /health`, metadata-only `GET /v1/models`, and `POST /v1/chat/completions`; the POST accepts SecAgent's `stream:false` benign probe as well as the imported testcase request. The HTTP facade does not itself call `tools/call`; the pinned provider owns that orchestration.
- `start_secagent_local.py:70,139,210-239,277-282` loads an optional bridge reference from the existing operator-owned `runtime.json`, starts it in the same launcher session, isolates its named credential from Workflow, Reporting and Vite, and checks only `/health` at startup. Startup makes no Agent, MCP, or Judge request.
- `backend/src/targets/adapters/http_evidence.py:122-151` recognizes bounded `secagent_bridge` metadata as **target/provider reported**, partial, and not execution-verified. It keeps tool names and argument hashes; raw arguments/results are not forwarded as evidence fields.
- `backend/src/core/models/evidence.py:106-126` allows only these bounded bridge fields into Judge requests and Native Reports. Without this allowlist, the new evidence event existed but its structured data was dropped.
- The facade sets HTTP `finish_reason=stop` only after the provider returns a bounded complete **output string**. The existing HTTP adapter may therefore mark the returned response text complete (`backend/src/targets/adapters/http_adapter.py:151-184`); this does not make the upstream LLM/tool trace complete. The separate bridge trace remains `partial` and `execution_verified=false`.
- Existing imported chat binding and MCP safety gate are unchanged: `backend/src/workflow/generic_imported_batch.py:128-176,231-276,278-369` requires an `openai-chat` target, exact reviewed profile, a benign connection proof for Live Local, the reviewed ASI05 response policy and Hybrid mode. It does not translate prompts into MCP `tools/call`. The report records `response_command_artifact` at `:807-836`.

The operator-owned files now include `C:\Users\Quettye\AppData\Local\SecAgent\toolbot-agent-bridge.json` (no key, archived provider pin) and an `agent_bridge_config` reference in the existing `runtime.json`. Other runtime references were preserved. The already-running SecAgent process has **not** loaded this new reference; one normal launcher restart is needed later. No target was automatically saved/reviewed and no ASI05 policy was created/reviewed.

## 4. Offline verification

| Check | Result |
| --- | --- |
| Provider ZIP pin and tamper rejection; credential sentinel not returned | PASS |
| Fake Agent module → mock MCP `tools/call` → bridge response; metadata remains reported/unverified | PASS |
| Bridge accepts exact SecAgent chat probe body (`stream:false`), rejects invalid model, `/v1/models` never invokes provider | PASS |
| Real 30-case dataset, one-case ASI05/Hybrid/Live Local preview using only mock transport and a temporary reviewed test policy | **1/1 ready**, no testcase or Judge request; one mocked benign connection probe |
| Mocked imported run → Native Report retains partial reported tool trace and remains INCONCLUSIVE under rule-only evaluation | PASS |
| Launcher optional config and credential isolation, including a nonstandard credential variable name | PASS |
| Focused backend regression after changes | **81 passed** |
| Frontend `DatasetLibrary` and `TargetManager` Vitest | **18 passed** |

Tests: `backend/tests/test_promptfoo_agent_bridge.py`, `backend/tests/test_imported_live_local.py`, `backend/tests/test_unified_startup_and_vite_proxy.py`. Other related backend tests in the 81-case command: `test_generic_imported_batch.py`, `test_http_target_adapter.py`, `test_asi03_contracts.py`, `test_dataset_import.py`, `test_evidence_contract_phase1a.py`. All Agent/MCP traffic in tests was a fake local module plus mock transport; no live provider or target traffic occurred.

The one-case **test** preview uses a temporary policy review only inside its isolated test directory. It is not a production approval. The real UI preview is not yet ready to run because this shell lacks `DEEPSEEK_API_KEY` and the shared Judge credential, the bridge target has not been reviewed, its benign connection proof does not exist, and no reviewed ASI05 response policy is bound to that new target. A missing credential must not be replaced with a fake verdict.

## 5. UI route and live-pilot prerequisites

1. In a future operator-approved session, provide the Agent credential and shared Judge credential as environment variables to the **same PowerShell process** that starts `python start_secagent_local.py`. Do not save keys in `runtime.json`, target profile, dataset or report. The current shell has neither credential present. Restart the launcher once to load the new bridge reference; thereafter SecAgent can switch targets/ASI without restart.
2. In **Targets → Connect New Target**, enter `http://127.0.0.1:7019/v1/chat/completions`; use an Agent display name such as “ToolBot DeepSeek Agent (Promptfoo provider)”. This is a new **HTTP Agent target**, separate from the ToolBot MCP service at `:7010`. Metadata discovery can advertise `deepseek-chat` without running the provider. The UI's **Discover & Test Connection** action also sends a benign chat probe when the model is known; that probe calls the provider and may cause it to choose MCP tools. Only click it after authorizing that live scope and confirming the sandbox. Save and separately review the exact target profile. Connection is not security authorization.
3. Create and separately review an ASI05 **response_command_artifact** policy bound to this Agent target. Do not reuse the CodeBot target binding or treat the Promptfoo YAML purpose as a reviewed policy. `execution_action` has no adequate reviewed policy/independent correlation in this path.
4. In **Datasets**, inspect dataset `e4ea927a1b0ead6b81e388e5026bd019`. Select the new HTTP Agent target, ASI05, **Response command artifact**, **Live Local**, and **Hybrid Judge**. Click **Clear Selection**, then select only TC0001 (or another single case). Preview must show exactly one case, request budget 1, the exact imported prompt SHA, reviewed policy and compatible target. Do not choose ToolBot MCP as the chat target. **Run Selected Tests** requires a separate per-run operator authorization; this task stops before it.
5. A successful run should produce the Assistant response, provider-reported tool intent/dispatch metadata, target HTTP observation, Judge diagnostics if eligible, final verdict, dataset/prompt/profile/policy provenance and a Native Report. It does not prove handler invocation or sandbox effect. The provider's raw JSONL output is stored beside the extracted module under operator-owned `SecAgent\agent-bridge` and may include prompt/result content; handle it as sensitive research data.

Before a live pilot, verify current ToolBot `/mcp` path, sandbox/canary scope, bridge health, exact target revision, reviewed response policy, shared Pi readiness, both credentials, and the 30-second SecAgent versus 25-second bridge timeout. Direct PASS/FAIL rate comparison remains **not justified** until the missing Context provider revision and grading/scope parity are resolved.

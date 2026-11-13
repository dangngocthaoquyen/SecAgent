# Runtime HTTP targets

The native entry point accepts either `--target-config FILE` (unchanged) or
`--target-url URL`. Runtime mode builds an existing `TargetProfile` in memory;
official testcase loading, payload rendering, registered attack module, Runner,
Executor, HttpTargetAdapter, ResponseObserver and evaluator selection are reused.
There is no alternate evaluation path. Judge configuration still defaults to
rule-only with no Judge calls.

## Authorized lab scope

Runtime URLs require `--target-id` and `--authorized-lab-origin`. Authorization
matches scheme, hostname/IP and effective port exactly. Supply the complete chat
endpoint; no paths or ports are guessed. Currently only `localhost` and literal
private/loopback IPs are accepted. Public addresses, arbitrary DNS names,
link-local/metadata addresses, multicast, unspecified/reserved addresses,
URL credentials, query strings and fragments are rejected. This intentionally
does not yet support arbitrary public production endpoints.

Dynamic connections ignore environment proxies and do not follow redirects.
HTTPS uses the HTTP client's normal certificate verification. Explicit origin
selection records the caller's authorization intent; it cannot independently
prove legal permission or isolate a compromised host. `localhost` relies on the
machine's trusted local resolver. Existing YAML destinations retain their
previous configuration behavior and are not subject to this new runtime guard.

`--target-protocol openai-chat` is currently the only supported protocol.
Unsupported protocols fail before connecting. `--target-model` supplies the
request model (default `default`); generic providers usually require their actual
model name. DVAA selects its agent by listening port, so that field does not
prove the upstream LLM model used by DVAA.

The reusable schema is POST JSON with `model` and one user message containing
the complete rendered payload, extracting `choices.0.message.content`. HTTP 200,
finish reasons and textual claims do not establish response completeness or
agent action traces. Other response schemas fail extraction explicitly.

## Examples (not executed during implementation)

Local customized DVAA source currently assigns ResearchBot port 7015 and
LegacyBot port 7003. Confirm the authorized deployment's port map before use.

```powershell
python backend/scripts/run_native_smoke.py --target-url http://127.0.0.1:7015/v1/chat/completions --target-id dvaa-researchbot --target-protocol openai-chat --authorized-lab-origin http://127.0.0.1:7015 --target-model researchbot --testcase testcases/goal_hijacking/GH-001.yaml --output-dir results/smoke/week5/runtime-researchbot

python backend/scripts/run_native_smoke.py --target-url http://127.0.0.1:7003/v1/chat/completions --target-id dvaa-legacybot --target-protocol openai-chat --authorized-lab-origin http://127.0.0.1:7003 --target-model legacybot --testcase testcases/goal_hijacking/GH-002.yaml --output-dir results/smoke/week5/runtime-legacybot
```

Both commands execute one target request and no Judge calls. Existing hybrid
flags remain available; a live Judge still needs explicit opt-in and a budget.
CodeBot (7004), RAGBot (7005), FlightBot (7017), and other compatible HTTP agents
use the same mechanism without individual YAML files. These example ports were
read from local container source, not tested with live requests in this task.

## Optional health and credentials

`--discover-target` adds one GET to the same origin's `/health`, with a three
second timeout and no authorization header, redirects or environment proxy.
Discovery is off by default and is an additional authorized connection when
enabled. Failure is nonfatal. A short `id` or `agent` string is advisory metadata
only: it cannot replace the caller's target ID, select skills, change endpoints,
authorize actions, or supply trusted evidence. Nested/vendor health schemas
are not interpreted automatically. Discovery metadata remains on the in-memory
profile; the existing allowlisted result report is unchanged.

`--target-credential-env LAB_AUTH` refers to an existing environment variable
holding the complete Authorization header, for example a Bearer header. No key
is accepted on the CLI or written into a target file. The existing adapter
resolves it only for transport and reporting redacts the configured credential
value. Do not put secrets into target IDs, model names or URL paths. This uses
existing exact-value redaction, not a general guarantee against arbitrary
private data echoed or transformed by a target. Health discovery sends no key.

## Offline verification

```powershell
$env:PYTHONPATH='backend/src'
python -m pytest backend/tests/test_runtime_targets.py backend/tests/test_official_asi01_runner.py backend/tests/test_runner_judge_integration.py backend/tests/test_external_evaluator_connector.py -q -p no:cacheprovider
python -m pytest backend/tests -q -p no:cacheprovider
```

Tests use mocked transports/FakeJudge, official GH assets, and temporary output
directories. Synthetic responses are integration fixtures, not DVAA findings.

## Future work (not implemented)

- MCP: explicit authorized transport discovery, tool listing/schema validation,
  tool selection and argument binding; never assume chat content is a tool call.
- A2A: authorized agent-card discovery and supported task/message lifecycle,
  with a dedicated adapter contract rather than the chat-completions schema.
- Capability-aware selection: match testcase prerequisites to reviewed target
  capabilities and evidence support; health claims alone are insufficient.
- Batches: explicit target lists, per-target provenance, bounded execution and
  a clearly defined shared Judge budget.
- Web UI: validate the same runtime profile contract server-side, with caller
  authorization and credential references; no UI implementation in this task.

# Phase 3B.2 — Minimal UX and conservative connection capability

## Implemented scope

The Targets screen now follows Select target → Validate configuration → Test
connection. Main controls show the preset, protocol, configured endpoint, model,
timeout and human-readable approval/validation status. Revision, policy, mappings,
credential alias, capabilities and diagnostic codes are in collapsed Advanced
Settings. A pending-review-only validation result reads **Operator approval
required**, not a technical configuration failure.

Test Connection is disabled with **Probe unsupported / Connection not checked**.
Continue is disabled because ASI selection and plan preview are not implemented.
There is no active transport in this phase. This is the explicit unsupported
fallback required when a safe probe cannot be demonstrated, not a claim of
completed active connectivity testing.

## Source audit and uncertainty

Read-only inspection on 2026-11-08 found `D:\DVAA-DeepSeek\Dockerfile` and
`provider.js` (plus its backup). The Dockerfile derives from
`damn-vulnerable-ai-agent-dvaa:latest` and replaces `/app/src/llm/provider.js`.
That provider handles LLM configuration; it does not contain ResearchBot's route
handlers. No ResearchBot HTTP server source was available in this host directory.
The current container filesystem was not inspected and no Docker command ran.

`deploy/asi01-lab/nginx.conf` forwards a fixed `/health` to ResearchBot. This proves
proxy configuration only. `docs/asi01-web-callback.md` records earlier container
source inspection and hashes, but does not establish the health handler's safety.
Neither is proof of the current handler implementation or chat compatibility.

`backend/src/targets/runtime.py::build_runtime_target(discover=True)` can GET
`/health` and retain an untrusted identity claim. It is not used here: it does not
prove that an arbitrary target's health handler is non-mutating.
`HttpTargetAdapter.execute` renders and sends testcase requests, so it must not be
used as a connectivity probe. Ordinary chat completion could invoke an LLM/tools.

No local Promptfoo Word reference was found in the workspace. The user's described
guided setup flow was used as conceptual inspiration, not as an inspected artifact.

## Authorization and API

The original example stays unchanged with `reviewed: false`. The existing
`reviewed: true` means **reviewed for offline configuration only**. It does not
grant active probe or security execution permissions.

The catalog adds a server-derived `connection_probe` projection:

```json
{"status":"unsupported","reason":"safe_probe_not_verified",
 "active_probe_authorized":false,"security_execution_authorized":false}
```

Active grants/probe definitions are not configurable in this implementation.
Attempts to add such fields fail closed instead of creating permissions without
a reviewed handler. The process-local nonce remains anti-CSRF, not authentication.

New `POST /api/testing/connection-checks` accepts only `target_id`,
`profile_revision`, `policy_ref`. It makes a capability decision without network
I/O. Same Host/Origin, local peer, JSON, nonce and 8 KiB body checks apply.

| Condition | HTTP | connection_status / reason |
|---|---:|---|
| Unknown target | 404 | rejected / unknown_target |
| Stale revision or policy | 409 | rejected / stale_profile_or_policy |
| Review required | 403 | requires_approval / operator_review_required |
| Reviewed offline, no verified probe | 200 | unsupported / safe_probe_not_verified |
| Extra URL/method/body/header/grant fields | 400 | sanitized error envelope |

Typed decision responses always have `target_request_count: 0`,
`connection_reachable: null`, `runtime_protocol_compatible: null`,
`security_test_executed: false`, `security_verdict: null`. No response claims
Reachable or Unreachable: neither was measured. No provider body or secret is read.

No automatic call to connection-checks occurs on page load. The disabled UI does
not make a simulated successful request. The Vite proxy permits only the exact
new POST route after same-origin checks; Reporting remains GET-only.

## Local operator setup and verification

Use the startup commands in [workflow-targets.md](workflow-targets.md).
Create a separate local catalog rather than editing the checked-in example:

```powershell
Set-Location D:\SecAgent-W5-Judge
$catalogPath = Join-Path $env:LOCALAPPDATA 'SecAgent\authorized-targets.json'
if (Test-Path -LiteralPath $catalogPath) { throw 'Catalog already exists; review it without overwriting.' }
New-Item -ItemType Directory -Force (Split-Path $catalogPath) | Out-Null
Copy-Item -LiteralPath configs/workflow/authorized-targets.example.json -Destination $catalogPath
notepad $catalogPath
# Review endpoint/model/policy; set reviewed=true only for OFFLINE configuration.
$env:PYTHONPATH = 'backend/src'
python -m workflow.api --catalog $catalogPath --port 8092
```

No catalog edit in this version can enable active probing. The operator must keep
credentials outside the file, using only an alias to a server environment binding.

In another PowerShell terminal, inspect the unsupported decision without target I/O:

```powershell
$base = 'http://127.0.0.1:8092'
$health = Invoke-RestMethod "$base/api/testing/health"
$target = (Invoke-RestMethod "$base/api/testing/targets").targets[0]
$selection = @{ target_id=$target.id; profile_revision=$target.profile_revision; policy_ref=$target.policy_ref }
Invoke-RestMethod "$base/api/testing/connection-checks" -Method Post `
  -ContentType 'application/json' -Headers @{
    Origin=$base; 'X-SecAgent-Validation'=$health.validation_nonce
  } -Body ($selection | ConvertTo-Json)
```

A reviewed profile returns unsupported. An unreviewed profile returns HTTP 403.
Do not log the nonce. This request contacts only the local workflow service.

## Tests and deferred active-probe protections

Tests prohibit HTTP client, DNS, Executor and Pi calls. They cover approval,
unknown/stale targets, attempted permission escalation, arbitrary URL/path/IPv6,
headers, body, proxy and redirect options, CSRF and repeated zero-request decisions.
No transport was added, so timeout/unreachable, response streaming limits and
active-request rate limiting cannot honestly be tested as implemented features.
There is no target-response size or duration to measure; the network budget is
structurally zero. Local API DoS/rate limiting remains a deployment limitation.

Before active probing can be enabled, review the actual current route handler
and middleware, bind approval to that specific method/host/IP/port/path and scope,
and implement bounded transport with DNS/rebinding policy, no redirects or env
proxy, response streaming caps, deadlines, one-request/no-retry budget and rate
limits. Review credential forwarding and operator-session authorization separately.
A service health success would establish only that service endpoint's availability,
not chat compatibility, agent capabilities, security PASS or autonomous LLM behavior.

Phase 3C can design offline ASI/testcase compatibility and plan previews once
approved. It must carry this unknown connectivity status forward and must not
reinterpret offline review or an unsupported probe as permission to execute.

## Verification record (2026-11-08)

```powershell
Set-Location D:\SecAgent-W5-Judge
$env:PYTHONPATH = 'backend/src'
$env:SECAGENT_NO_DOCKER = '1'
python -m pytest backend/tests/test_workflow_targets.py backend/tests/test_workflow_preflight.py -q -p no:cacheprovider
python -m pytest backend/tests/test_reporting_api.py backend/tests/test_report_aggregation.py backend/tests/test_reporting_models.py backend/tests/test_report_normalization.py backend/tests/test_reporting_artifacts.py -q -p no:cacheprovider
python -m pytest backend/tests -q -p no:cacheprovider
Set-Location frontend
npm run build
npm test
# Used only after confirming the existing listener belongs to this workspace:
$env:SECAGENT_REUSE_VITE = '1'
npm run test:browser
Remove-Item Env:SECAGENT_REUSE_VITE
```

Results: workflow 70 passed; reporting 232 passed; backend 991 passed, 1 skipped;
frontend 64 passed; browser 5 passed, 1 skipped; TypeScript/Vite build passed.
All completed suites had zero failures. Skips: Docker-dependent backend check and
opt-in real reporting dataset browser smoke. Browser tests used synthetic API data,
not target requests. Initial browser launch was blocked by the already-running
workspace Vite server; explicit reuse resolved the environment issue without
stopping that process. No live target, Docker or Judge operations were performed.

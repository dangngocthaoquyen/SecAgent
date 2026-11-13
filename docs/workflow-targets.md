# Phase 3B.1 — Authorized targets and offline configuration

Phase 3B.2 adds a typed unsupported connection-capability decision and simplified
UX; see [the current preflight contract](workflow-preflight.md). There is still no
active target transport. The following describes the retained Phase 3B.1 foundation.

This phase adds configuration validation only. It does not connect to an agent,
discover services, execute a testcase, or invoke a Judge. Reporting remains a
separate GET-only service. Existing Runner and evaluator behavior is unchanged.

## Operator catalog

`configs/workflow/authorized-targets.example.json` is a review-required example,
not permission to send requests to port 7015. The service reads one explicitly
selected JSON file at startup, with no browser paths or filesystem discovery.
Maximum size is 256 KiB; at most 50 unique profiles. Duplicate JSON keys, unknown
fields, nonfinite numbers and unsupported protocol configurations are rejected.

The catalog contains `catalog_schema_version: "1.0.0"`, `policy_ref`, a
`credential_aliases` map and `targets`. Each target specifies:

- Stable `id`, display `name`, `reviewed` (false by default).
- Exact `endpoint`, protocol `openai-chat`.
- Approved `models`, `default_model` and timeout minimum/default/maximum (1–120 s).
- Optional `credential_alias`; aliases map to server environment-variable names,
  never secret values in the file. The API exposes the alias and availability only.

The existing runtime builder and target validator construct a `TargetProfile`
offline with discovery disabled. Only private/loopback literal IPs or localhost
are accepted by that builder. Catalog paths reject encoded/traversal ambiguity;
userinfo, query and fragment are forbidden. A private address alone is not
authorization: drafts must match the operator's exact selected endpoint.

The API computes a stable SHA256 profile revision over the preset, policy and
credential binding, excluding secret values. Revision/policy mismatches fail.
The browser cannot change authorization origin, endpoint, headers, adapter,
request template or parser. Request mapping is the reviewed POST OpenAI chat
model/messages mapping; parser is `choices.0.message.content`.

To approve **offline validation**, an operator can copy the example to a private
configuration location, review its coordinates and model list, then edit
`reviewed` to true. Do not overwrite an existing catalog or add raw secrets.
Restart the workflow service after catalog edits and reload the UI catalog.
This flag is not authorization for a future connection or security test.

## API contract

All responses use `workflow_schema_version: "1.0.0"`.

| Endpoint | Contract |
|---|---|
| GET `/api/testing/health` | Offline-only status, `target_network_access: false`, process-local validation nonce |
| GET `/api/testing/targets` | Sanitized presets, revision/policy, configured capabilities and protocol support states |
| POST `/api/testing/target-drafts/validate` | Typed draft validation; no target I/O or persistence |

Draft fields: `target_id`, `profile_revision`, `policy_ref`, `endpoint`, `protocol`,
`method`, `model`, `request_mapping`, `response_parser`, `timeout_seconds`,
`credential_alias`. Extra fields are forbidden. The timeout must also meet the
selected profile's bounds and the model must appear in its approved list.

A valid or policy-invalid draft returns HTTP 200 with `configuration_status`,
safe reason codes, target ID and revision. Both outcomes retain
`connection_reachable: null`, `runtime_protocol_compatible: null`,
`target_execution_performed: false`, `security_verdict: null`.
Malformed drafts return 400; forbidden local-origin access 403; wrong routes 404;
wrong methods 405; non-JSON POST 415. Errors do not echo submitted bodies or paths.

## Local security boundary

Flask binds only to 127.0.0.1. Host, loopback peer, exact Origin and cross-site
Fetch Metadata checks reject foreign access. Validation POST requires JSON, an
exact local Origin and `X-SecAgent-Validation` nonce obtained from health.
No wildcard CORS, query parameters, mutation routes beyond offline validation,
active connection routes or run routes exist. Bodies are limited to 8 KiB.

The nonce is anti-CSRF protection, **not operator authentication**. It is held in
React memory, never URL/localStorage/sessionStorage. Same-origin scripts and other
local processes can obtain it; this service is not a multi-user security boundary.
It must not become authorization for future network activity. No raw credential
entry is offered. Credential availability proves only presence, not validity.

Vite validates browser Host/Origin before forwarding the two workflow GET routes
and the validation POST to 8092. It rewrites Origin only after that check. The
existing GET-only reporting proxy remains on 8091. Do not expose either server
with tunnels, public forwarding or a network bind.

## Start locally (three PowerShell terminals)

Use the existing Python environment with `backend/requirements-reporting.txt`
installed (Flask/Pydantic and existing project dependencies). Node and frontend
dependencies are documented in `frontend/README.md`.

Workflow API (the example intentionally produces `operator_review_required`):

```powershell
Set-Location D:\SecAgent-W5-Judge
$env:PYTHONPATH = 'backend/src'
$env:SECAGENT_NO_DOCKER = '1'
python -m workflow.api --catalog configs/workflow/authorized-targets.example.json --port 8092
```

Reporting API, only if not already running and its selected archives exist:

```powershell
Set-Location D:\SecAgent-W5-Judge
$env:PYTHONPATH = 'backend/src'
python -m reporting.api --manifest configs/reporting/asi01-lab-example.json --port 8091
```

Frontend:

```powershell
Set-Location D:\SecAgent-W5-Judge\frontend
# First installation only: npm ci --no-audit --no-fund
npm run dev
# Open http://127.0.0.1:5173/#targets
```

Select Targets, inspect the operator preset, choose a model and timeout, then click
Validate Configuration. The example must report review required, not connected.
An operator-reviewed catalog can produce Configuration valid. Changing a target
or option clears the result. Empty/unavailable catalogs show explicit states.
Reporting navigation works independently of workflow availability and vice versa.
Test Connection is disabled with Probe unsupported; no Run button exists.

Optional offline API verification (no request is sent to the endpoint in the draft):

```powershell
$base = 'http://127.0.0.1:8092'
$health = Invoke-RestMethod "$base/api/testing/health"
$catalog = Invoke-RestMethod "$base/api/testing/targets"
$target = $catalog.targets[0]
$draft = @{
  target_id=$target.id; profile_revision=$target.profile_revision; policy_ref=$target.policy_ref
  endpoint=$target.endpoint; protocol=$target.protocol; method=$target.method
  model=$target.default_model; timeout_seconds=$target.timeout_default
  request_mapping=$target.request_mapping; response_parser=$target.response_parser
  credential_alias=$target.credential_alias
}
Invoke-RestMethod "$base/api/testing/target-drafts/validate" -Method Post `
  -ContentType 'application/json' -Headers @{
    Origin=$base; 'X-SecAgent-Validation'=$health.validation_nonce
  } -Body ($draft | ConvertTo-Json)
```

Do not log or persist the health nonce. Catalog values must themselves be reviewed,
non-sensitive labels/endpoints; sanitization is not a general secret classifier.

## Verification

```powershell
Set-Location D:\SecAgent-W5-Judge
$env:PYTHONPATH = 'backend/src'
$env:SECAGENT_NO_DOCKER = '1'
python -m pytest backend/tests/test_workflow_targets.py -q -p no:cacheprovider
python -m pytest backend/tests/test_reporting_api.py backend/tests/test_report_aggregation.py backend/tests/test_reporting_models.py backend/tests/test_report_normalization.py backend/tests/test_reporting_artifacts.py -q -p no:cacheprovider
python -m pytest backend/tests -q -p no:cacheprovider
Set-Location frontend
npm run build
npm test
npm run test:browser
```

Browser tests use synthetic contracts, not production fallback data. The optional
real reporting smoke test remains opt-in through `SECAGENT_REPORTING_SMOKE=1`.
Workflow tests guard network/client, Executor and Judge entry points against calls.

Final verification on 2026-11-08:

| Command / scope | Passed | Failed | Skipped |
|---|---:|---:|---:|
| Workflow pytest command above | 44 | 0 | 0 |
| Reporting pytest command above | 232 | 0 | 0 |
| Full backend pytest command above | 965 | 0 | 1 |
| `npm test` | 62 | 0 | 0 |
| `npm run test:browser` | 5 | 0 | 1 |

`npm run build` passed TypeScript and Vite production bundling. The backend skip
is Docker Compose validation disabled by `SECAGENT_NO_DOCKER=1`. The browser skip
is the opt-in real selected reporting dataset smoke check; default browser tests
use synthetic reporting/workflow fixtures. No live target connectivity is claimed.
An initial browser selector failure was corrected with an explicit target-label
association; the complete frontend build/unit/browser sequence then passed.

## Deferred to Phase 3B.2

Only configuration validity is implemented. Reachability, runtime protocol
compatibility, agent identity and security verdict remain unestablished. MCP's
limited direct JSON-RPC adapter is not selectable here; A2A is unsupported.

Before any active connection preflight: separately approve the endpoint/method,
operator authorization/session design, SSRF/DNS and redirect policy, response-size
and timeout limits, one-request budget, credential forwarding policy and explicit
user confirmation. Do not use chat completion or tools/call as an automatic ping.
No ASI selection, run orchestration, database or live evaluation is included.

## Phase 3D.3B.1: display-only platform grouping

An operator catalog may now add `platform_id` and `platform_name` together to
each target preset. Both are optional; older catalogs without them still load
and appear under **Configured targets**. Presets sharing one platform ID must
use the same display name. Target IDs remain unique and are the identities used
for validation and admission. The checked-in ResearchBot example now shows
`dvaa` / `DVAA` but remains `reviewed: false`.

`GET /api/testing/targets` returns both fields (null for a legacy preset).
The browser first selects a platform, then one configured target in that group.
It still sends only the selected target's server-issued draft for offline
validation. Platform labels never authorize an endpoint, select an adapter,
claim a capability, or grant execution. Switching platform or target clears
the prior validation and restores that target's default model and timeout.

The new platform fields are excluded from the profile revision digest because
they only group the UI. Existing security-relevant fields, policy reference,
credential binding and the legacy `name` field retain their previous digest
behavior. In particular, the ResearchBot example's revision is unchanged when
the two new display fields are added or edited. A change to endpoint, model
choices, authorization review state or other existing preset fields continues
to change the revision. Updating a running catalog file requires restarting
the Workflow API; browser reload alone only rereads its startup snapshot.

This phase added no target endpoint, protocol, connection probe, execution
grant or live run capability. Synthetic multi-profile test records are kept
inside automated tests and are not operational catalog entries.

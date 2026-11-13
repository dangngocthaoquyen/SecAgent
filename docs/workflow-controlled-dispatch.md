# Phase 3D.2A — Controlled native Runner dispatch

## Scope and data flow

This opt-in local workflow executes GH-C01, a benign ASI01 control, on one
operator-reviewed OpenAI-compatible HTTP target. A synthetic-mock-only
GH-WEB-001 path now exercises a fresh local fixture and collector using the
same native Runner. The default workflow service has no target network access,
and **live GH-WEB-001 dispatch remains disabled** pending a reviewed isolated
DVAA-to-fixture network and collector-visible peer contract.

The sequence is: server catalog → offline `AdmissionService` assessment → exact
target profile and current testcase/payload/skill digest → operator grant and
secret check → exclusive single-use plan claim → native `run_smoke` → existing
TestCaseLoader/PayloadRenderer/Runner/Executor/HttpTargetAdapter/ResponseObserver/
rule evaluator → exclusive `.secagent.json` report → workflow summary. The
existing `RecordingExecutor` retains adapter execution results. No archived
receipt is reused. Rule-only remains the default; optional server-controlled
hybrid mode uses the native Runner's existing HybridEvaluator and Pi connector.
The final verdict is the native Runner result; it is never set by the workflow API.

GH-C01 needs no collector, so no fixture or collector is created. A new random
workflow run ID and report directory are created for each claimed run. This
slice permits one active run at a time and one HTTP target request per plan;
a durable `claim-<plan_id>` record prevents the same plan from being sent
again after a restart. A run that fails after claim remains claimed. GH-C01
grants without an attempt authorization ID retain plan-level single-use
behavior. GH-WEB-001 requires a distinct server-owned `authorization_id` per
attempt; a new grant can authorize a repeat under the same stable plan. There
is no automatic retry or parallel dispatch.

## Authorization boundary

An operator must provide all of the following server-side:

1. A separately reviewed catalog with the exact endpoint, protocol, model and
   policy reference. The checked-in example remains `review_required`.
2. A current execution grant with `scope: security_test_execution`, exact
   target ID, profile revision, policy reference, testcase ID `GH-C01`,
   current asset SHA256 and a future UTC expiry.
3. `SECAGENT_WORKFLOW_OPERATOR_TOKEN` (at least 32 characters) in the local
   workflow process. The UI asks for it only immediately before dispatch and
   retains it in component memory, not browser storage.
4. Explicit `--enable-controlled-runs`, an admission policy file and a fresh
   output directory below this workspace's `results/` directory.

The CSRF nonce is separate from the operator secret. The plan ID is a stale
plan check, **not** an authorization token. Dispatch repeats current catalog,
grant, asset, binding and budget checks. The browser cannot supply a target
URL, payload body, collector receipt or runtime binding to the dispatch route.
The HTTP client is fixed to one exact POST URL, denies redirects, ignores
environment proxies, limits response bytes and enforces bounded timeouts.

The local API binds to `127.0.0.1`; Host, Origin, peer address, nonce, route,
method, body type and size are checked. This is a single-operator research
control, not a multi-user authenticated service. Do not publish port 8092 or
use an unreviewed target. Admission does not establish target reachability.

## API contract

`POST /api/testing/readiness/preview` and `POST /api/testing/admissions`
retain the Phase 3D.1 contract and add `dispatch_available`. Only an admitted
GH-C01 plan with an unused claim can return `true`. In local synthetic tests,
a server-injected fixture runtime can also enable GH-WEB-001; the production
CLI does not supply that runtime.

`POST /api/testing/runs` requires the exact `AdmissionRequest` JSON from the
current selection, `Origin`, `X-SecAgent-Validation`, and
`X-SecAgent-Operator`. The route is disabled by default (403). Invalid,
unauthorized, stale and repeated requests fail before target I/O. On an
accepted claim it returns a workflow run ID, `completed`/`failed`, target
request count, native report persistence flag, optional historical verdict and
SHA256 of the new report. A technical execution error may have a persisted
native `ERROR` result; this is not a security FAIL. The response omits local
paths and credentials. `plan_id`, workflow `run_id` (attempt), native
`native_execution_id`, and the fixture correlation digest remain distinct.

The GH-WEB-001 synthetic fixture lifecycle and the remaining live-network
blocker are documented in [workflow-web-fixture.md](workflow-web-fixture.md).

Each run directory contains a `claim-<plan_id>` in the selected output root,
one native report when writing succeeds, and a `run-summary.json`. Native
reports are recursively redacted before writing; configured credential values
and the operator secret are removed if echoed. Well-formed SHA256 integrity
fields remain intact so the Reporting API can validate a hybrid report. These
reports are **new runtime evidence**, not historical archive edits. The
read-only Reporting API resolves a backend-issued run ID under an explicitly
selected `controlled_runs_root`; the UI links a completed persisted run to that
detail route. It does not scan unselected directories.

## Optional server-owned hybrid evaluation

The workflow accepts `evaluation_mode: rule_only` or `hybrid`. The default is
`rule_only`, with zero Judge calls. The CLI advertises hybrid only when the
operator explicitly supplies `--enable-web-hybrid-judge` together with
`--enable-controlled-runs` and `--web-hybrid-config <operator-owned JSON>`.
The JSON must validate as `RunnerEvaluationConfig` with `mode: hybrid`,
`judge_enabled: true`, `allow_live_judge: true`, `max_judge_calls: 1`, and a
complete `pi` connector configuration. The configuration belongs to the
backend; the browser sends only the mode and cannot set a process command,
provider, model, credentials, or Judge instructions. The health API labels a
configured provider `configured_unverified`: configuration alone does not
prove Pi availability.

Selection binds the mode and configuration revision into the admission plan.
Changing either invalidates the plan. Dispatch retains the exact grant,
single-use claim, one-target-request limit, and GH-C01 allowlist; GH-WEB-001
remains limited to the local synthetic fixture path. Hybrid admission also
requires an enabled semantic skill matching the testcase category. The native
HybridEvaluator applies rules first, uses at most one Judge call for semantic
fallback, and passes the recommendation through the verdict resolver. An
invalid output, timeout, provider fault, or incomplete evidence cannot create
a security PASS. Native reports retain mode, Judge diagnostics, evidence
references, and the final verdict for the existing Reporting API detail view.

Phase 3D.4.4 validated this path with an in-memory fake Pi process and a mock
target transport only. It did not call Pi or a research target. A real Judge
smoke requires a separately reviewed operator configuration and authorization.

## Local setup and verification

The commands below describe an operator-controlled setup; they do not approve
or perform a live target request. Keep catalog, policy and token outside Git.

```powershell
Set-Location D:\SecAgent-W5-Judge
$env:PYTHONPATH = 'backend/src'
$env:SECAGENT_NO_DOCKER = '1'
# Prepare and review these files separately. Do not edit the checked-in example.
$catalog = "$env:LOCALAPPDATA\SecAgent\authorized-targets.json"
$policy = "$env:LOCALAPPDATA\SecAgent\execution-grants.json"
$env:SECAGENT_WORKFLOW_OPERATOR_TOKEN = Read-Host 'Operator execution secret'
python -m workflow.api --catalog $catalog --admission-policy $policy `
  --enable-controlled-runs --run-output-dir results/workflow-controlled `
  --port 8092
```

In another PowerShell terminal, start the existing frontend with `npm run dev`
from `frontend/` and open `http://127.0.0.1:5173/#targets`. The Reporting API
on port 8091 is optional for this dispatch and remains read-only. Do not use
the checked-in review-required catalog as an execution grant. Restarting the
workflow service does not release a claimed plan; use a new reviewed grant and
plan for any later authorized run.

Offline verification (mock target transport only):

```powershell
Set-Location D:\SecAgent-W5-Judge
$env:SECAGENT_NO_DOCKER = '1'
$env:PYTHONPATH = 'backend/src'
python -m pytest backend/tests/test_workflow_targets.py backend/tests/test_workflow_preflight.py backend/tests/test_workflow_plans.py backend/tests/test_workflow_admission.py backend/tests/test_workflow_dispatch.py -q -p no:cacheprovider
python -m pytest backend/tests -q -p no:cacheprovider
Set-Location frontend
npm run build
npm test
npm run test:browser
```

## Remaining work

GH-WEB-001 requires a fresh controlled web fixture and collector lifecycle,
network peer verification, correlated recording executor, observation window
and cleanup before admission can be granted. A real DVAA run requires separate
operator approval and a reviewed local catalog/policy. There is no cancellation
protocol or multi-user session model. A local native report's hash proves file
identity, not independent action attestation or response completeness.

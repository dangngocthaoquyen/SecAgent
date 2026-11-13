# Phase 3D.1 — Readiness and execution admission foundation

This phase performs offline binding and admission decisions only. There is no
dispatch endpoint, execution token, worker, target probe, Judge invocation or
report write. A readiness preview is not evidence of connectivity or execution.

## Inventory reconciliation

The initial Phase 3C count of 17 valid + 2 invalid was a workflow taxonomy check
defect: GH-WEB-001 and GH-WEB-C01 declare `ASI01:2026`, compared initially against
`ASI01`. The check now compares the category component. Both use the same existing
`TestCaseLoader` and Pydantic model, and neither YAML changed. The inventory remains
19 schema-valid definitions (5 ASI01, 2 ASI02, 6 ASI03, 6 ASI05). Schema validity
does not imply complete binding, available observers or execution authorization.

## Reused integration points

- `TestcaseCatalog.paths`: server-derived ID-to-file mapping, rebuilt for each
  readiness/admission assessment; browser-supplied paths are not accepted.
- `TestCaseLoader.load`, `bind_testcase_variables`, `PayloadLoader.load_repository`
  and `PayloadRenderer.render`: load, bind rule parameters and render the existing
  payload in memory. Prompts/variables are not returned to the UI.
- `build_default_attack_module_registry().resolve(...).prepare`: existing input
  preparation and guard validation only; never Runner.run or Executor.execute.
- `SkillBundleLoader.load`: validate and fingerprint selected trusted skills;
  never call Pi. Semantic-only cases remain blocked in this rule-only slice.
- Future dispatch must reuse `Runner(..., evaluation_config=..., report_sink=...)`,
  existing Executor/ResponseObserver and verdict resolution.
- Native `run_native_smoke.py::RecordingExecutor` and `WebFixture.bind/claim/evidence`
  provide the existing collector integration. They are not invoked by admission.

## Readiness stages and decisions

Each selected case exposes separate booleans for discovered, schema_valid,
target_protocol_compatible, required_inputs_resolved, required_evidence_available,
execution_authorized and runtime_preflight_satisfied. Global target/budget errors
also block every row. Ready counts are not security verdicts.

`POST /api/testing/readiness/preview` returns blocked or ready_for_admission.
`POST /api/testing/admissions` recomputes the checks and requires an exact
`expected_plan_id`; it returns blocked or admitted. Both use the existing local
Host/Origin, JSON, nonce and body-size protections. They never send target requests.

Body: existing PlanSelection (`target`, `asi_categories`, `testcase_ids`), optional
`target_request_budget` (default 1), and `expected_plan_id` for admission. Extra
fields—including authorization, compatibility, runtime bindings, receipts and
archive paths—are rejected. Invalid schema returns a sanitized HTTP 400; valid
but blocked decisions return HTTP 200 with blocker codes.

Response includes plan_id, asset_sha256 per case, readiness rows/counts/blockers,
admitted, decision, `execution_status: not_started`, `dispatch_available: false`,
`connectivity: not_checked`, `evaluation_mode: rule_only`, `max_judge_calls: 0`,
and `execution_model: sequential`. An admitted decision is possible in synthetic
trusted-runtime tests; the production API supplies no runtime bindings and thus
remains blocked. The result is not persisted as an execution authorization token.

## Operator authorization

Offline catalog review is not permission to execute. By default AdmissionPolicy
has no grants. An optional operator-selected `--admission-policy` JSON file has:

```json
{
  "revision": "operator-policy-v1",
  "grants": [],
  "max_testcases": 1,
  "max_target_requests": 1,
  "max_timeout_seconds": 30
}
```

A grant requires `target_id`, exact `profile_revision`, `policy_ref`, `testcase_id`,
exact `asset_sha256`, `scope: security_test_execution`, and timezone-aware
`expires_at`. The asset digest combines file-byte hashes of testcase and payload
repository plus selected trusted skill prompt hash. No live grant is provided by
this task. A grant alone is insufficient: the runtime binding must separately exist.

Runtime bindings are an internal Python dependency keyed by target, revision,
testcase and asset digest; they are not loaded from HTTP, archive JSON or the policy
file. Current positive tests inject synthetic reviewed protocol/observer/report
capabilities. These declarations test admission policy, not actual adapter wiring.
Production binding construction must be reviewed in Phase 3D.2; it must not simply
accept browser or target claims as evidence of installed runtime capabilities.

Limits: one testcase, one target request, no retry/Judge allowance, configured
timeout bounded by target policy and admission maximum (30 seconds default,
60 seconds hard maximum). These are admission constraints, not implemented
transport enforcement: future dispatch must enforce them at the adapter boundary.

## Stable identity and stale-plan checks

The SHA256 plan identity covers the full target selection/options, ASI/cases,
requested budget, complete policy, current asset digests and resolved binding/input
digests. Secret-bearing rendered values are not returned. Identity is stable for
identical input/state; it is not a signature or bearer credential. Admission checks
expiry and all current conditions again, so knowing an ID cannot bypass blockers.

Catalog/policy are startup snapshots; restart the service to apply operator edits
or revocations. Testcase assets are reloaded for assessment. There is no durable
audit store, single-use token, reservation, file lock or dispatch-time TOCTOU guard.
Phase 3D.2 must revalidate immediately before execution and retain the exact checked
assets/bindings, rather than executing later solely because a hash once matched.

## GH-WEB-001 prerequisites and current blockers

The testcase requires a new operator-controlled fixture manifest, benign synthetic
page/canary, fresh run and collector correlation, target identity, correct lab
origin, verified collector-visible peer and synchronized collection window.
`WebFixture.bind` must supply the real page URL/run/collector variables; default
`REQUIRES_FIXTURE_RUN` and `/unconfigured` values are rejected. No historical run
or receipt can satisfy this requirement.

The future recording executor must claim the fresh fixture, bracket the actual
target call, collect attributable receipts, preserve provenance and then pass
observations through the existing evaluator/resolver. A declared http_post is not
an observed POST; the DVAA experiment recorded GET. Evidence availability means
an observer is configured, not that an attack succeeded. No receipt is invented
before execution, and absent receipts cannot prove a complete safe outcome.

Current blockers: reviewed runtime binding missing; protocol compatibility not
established; execution authorization missing/expired; fresh collector binding
missing; collector recording executor not wired; response observer missing;
report persistence not wired; required inputs/preflight unresolved. Unknown
connectivity is preserved. The admission layer deliberately always blocks collector
cases until the actual integration exists. ASI03/05 remain outside this first
slice and additionally require authorization baselines/sandbox configuration.

## UI and launch

Plan Preview has a compact Run readiness section: selected count, explicit Check
run readiness action, ready/blocked totals, blocker explanations and Execution
not started. Plan identity and evaluation mode are collapsed. Request admission
decision performs another offline check; there is no functional Run control.

```powershell
Set-Location D:\SecAgent-W5-Judge
$env:PYTHONPATH = 'backend/src'
# No admission policy means deny-by-default.
python -m workflow.api --catalog "$env:LOCALAPPDATA\SecAgent\authorized-targets.json" --port 8092
```

Use the separately reviewed target catalog from Phase 3B, not an edited source
example. In another terminal:

```powershell
Set-Location D:\SecAgent-W5-Judge\frontend
npm run dev
# http://127.0.0.1:5173/#targets
```

Existing Reporting API startup remains `python -m reporting.api --manifest
configs/reporting/asi01-lab-example.json --port 8091` with PYTHONPATH set as above.

## Verification commands

```powershell
Set-Location D:\SecAgent-W5-Judge
$env:SECAGENT_NO_DOCKER = '1'
$env:PYTHONPATH = 'backend/src'
python -m pytest backend/tests/test_workflow_targets.py backend/tests/test_workflow_preflight.py backend/tests/test_workflow_plans.py backend/tests/test_workflow_admission.py -q -p no:cacheprovider
python -m pytest backend/tests -q -p no:cacheprovider
Set-Location frontend
npm run build
npm test
npm run test:browser
```

Browser tests start their own local Vite when port 5173 is free. Only set
SECAGENT_REUSE_VITE=1 after verifying an existing listener belongs to this workspace.
No target, Docker or Judge is required. Tests prohibit network/Executor/Pi entry
points, use synthetic runtime declarations, and never reuse archived receipts.

## GH-WEB-001 and general dispatch prerequisites

Review real runtime binding construction, fresh fixture lifecycle/claim, concrete
observer and report-sink injection, execution authorization/session security,
single-use dispatch admission, current-asset consistency, enforced request/deadline
budgets, cancellation and sanitized persistence. Then reuse the existing Runner.
Any first live run requires separate operator approval; this phase does not grant it.

Phase 3D.2A implements a bounded, opt-in GH-C01 native Runner slice; see
[controlled dispatch](workflow-controlled-dispatch.md). Phase 3D.2B.1 adds a
fresh GH-WEB-001 fixture for local synthetic-mock verification; see
[workflow-web-fixture.md](workflow-web-fixture.md). The isolated DVAA network
mount and peer contract remain unsatisfied for live web dispatch and general
testcase execution.

Phase 3D.2B.2 separates stable plan identity from single-use web execution
authorization: a GH-WEB-001 grant now carries a unique `authorization_id`.
Grant entries do not change the plan digest, and a new grant ID can authorize
a fresh attempt under the same plan. Prepared lab fixtures remain blocked
from live dispatch until runtime mount, peer and isolation facts are checked;
see [workflow-lab-attachment.md](workflow-lab-attachment.md).

## Final recovery verification — 2026-11-09

| Check | Passed | Failed | Skipped |
|---|---:|---:|---:|
| Focused workflow command above | 104 | 0 | 0 |
| Full offline backend | 1025 | 0 | 1 |
| Frontend unit tests | 86 | 0 | 0 |
| Browser tests | 5 | 0 | 1 |

TypeScript/Vite production build succeeded. Port 5173 was free; browser tests
started their own workspace Vite without opting into server reuse. Skips were
Docker-dependent validation and the optional real reporting dataset smoke test.
Browser tests used synthetic API responses and covered mobile layout, readiness
display, backward navigation and existing Reporting pages.

Recovery fixed stale-admission row consistency (a blocked stale plan cannot leave
individual rows ready) and strengthened frontend validation of counts/diagnostics.
No protected execution components, historical reports or evidence were changed.

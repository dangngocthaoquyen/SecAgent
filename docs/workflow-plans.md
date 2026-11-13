# Phase 3C — Offline ASI selection and test plan preview

Implemented: Select Target → Validate Configuration → Select ASI → Select
Testcases → Preview Test Plan. Every preview is non-executable. Connection probes
remain unsupported, connectivity remains unknown, and execution is not started.
No Runner, evaluator, testcase, payload or historical evidence was changed.

## Inventory and compatibility audit

Discovery uses `TestCaseLoader.load` and the existing Pydantic `TestCase` model.
Only the four server-selected repository directories are scanned, one level deep:

| ASI | Category | Actual IDs |
|---|---|---|
| ASI01 | goal_hijacking | GH-001, GH-002, GH-C01, GH-WEB-001, GH-WEB-C01 |
| ASI02 | tool_misuse | TM-001, TM-002 |
| ASI03 | identity_privilege_abuse | IPA-001/002/003, IPA-C01/C02/C03 |
| ASI05 | unexpected_code_execution | UCE-001/002/003, UCE-C01/C02/C03 |

Total: 19 in-scope files, 0 invalid at implementation verification. Six PI/SD
files are outside these four categories and are not exposed. Older GH taxonomy
references retain LLM01; workflow ASI uses an explicit repository-category mapping.
ASI01:2026 is normalized to ASI01 for consistency checks. Contradictory ASI claims
are rejected, not silently rewritten. This is inventory, not execution evidence.

`PayloadLoader.load_repository` checks actual references without executing or
rendering attack content. `build_default_attack_module_registry().resolve` checks
registration without calling prepare/execute. `SkillBundleLoader.load` checks
enabled semantic skill availability without invoking a Judge.

`IdentityPrivilegeAbuseAttackModule.prepare` requires a verified A/B authorization
baseline. `UnexpectedCodeExecutionAttackModule.prepare` requires a verified
sandbox and an exact canary allowlist. These guards are inspected, not executed
or bypassed. Tool-action cases require an evidence observer; plain HTTP response
text does not supply one. GH-WEB-001's collector rule requires correlated receipt
evidence; GH-WEB-C01 declares required fetch URL/action scope in semantic context.

## Compatibility rules

- `unsupported`: an unregistered attack module; selection is disabled.
- `requires_configuration`: missing/review-required payload binding, action
  observer/baseline/sandbox/tool mapping, collector/fetch scope, or semantic Judge
  configuration. Missing semantic skills are reported separately.
- `unknown`: no sufficient reviewed target-to-testcase capability contract.
- `supported`: reserved for demonstrated compatibility; current production
  assessment never promotes a configured target claim into this state.

The current 19 cases all require configuration. This is intentional. Target
presets expose only configured chat capability and no verified runtime action
observers. Compatible/provisional selection is not security PASS or run approval.
ASI03/05 use existing action-rule paths; full semantic skill/evidence integration
is not claimed. Not all future targets can satisfy their prerequisites.

Preview counts are over the displayed (compatibility) or selected (plan) cases:
applicable = supported; blocked = unsupported + requires_configuration;
unknown = unknown. These are compatibility counts, not security verdict counts.

## API

All responses use `workflow_schema_version: "1.0.0"`.

| Endpoint | Behavior |
|---|---|
| GET `/api/testing/categories` | Four supported ASI IDs and names |
| GET `/api/testing/testcases` | Sanitized inventory and invalid-record count; not target-specific verification |
| POST `/api/testing/compatibility/preview` | Validate target draft/revision, filter selected ASI and return provisional compatibility |
| POST `/api/testing/plans/preview` | Validate explicit testcase IDs within ASI selection and return non-executable draft |

POST body: `{target: <existing TargetDraft>, asi_categories: [...], testcase_ids: [...]}`.
The compatibility request may omit testcase IDs. A plan requires at least one;
unsupported, unknown IDs and out-of-scope IDs are rejected. All 15 nonempty ASI
subsets are accepted; empty, duplicate or unsupported categories are rejected.
Duplicate testcase IDs and stale/invalid target configuration fail closed.

Preview includes target ID/revision, selected ASI, testcase rows, counts,
requirements, `connectivity: "not_checked"`, `probe: "unsupported"`,
`execution_status: "not_started"`, `executable: false`, and readiness explanation.
No plan is persisted, issued as an execution token or passed to Runner.

## Security and limitations

Endpoints use the existing loopback Host/Origin/nonce checks; no wildcard CORS.
The nonce is anti-CSRF, not operator authentication. POST previews are pure reads
with no target or Judge activity. HTTP clients cannot select filesystem paths,
override server authorization or provide payload code.

Safe YAML parsing and typed models are reused. Files are bounded at 256 KiB,
inventory at 100 cases per category; paths must remain under the server root and
symlinks/reparse points are rejected. Invalid records are excluded with a count,
not leaked exception bodies or paths. Summaries redact recognized credentials,
URLs/canaries and locations; raw payloads, variables and skill prompts are absent.
This filtering is not general DLP: repository assets remain operator-owned.

Inventory is a startup snapshot. Restart the workflow service after asset edits.
Target revisions are checked on each preview. No binding/rendered-input guarantee,
asset-hash execution authorization, durable plan ID, TTL or execution budget is
issued in this phase. Before execution, revalidate current assets, environment,
credentials, variable binding and all guards. Connectivity remains unmeasured.

## UI and local launch

Validated target configuration enables Continue. Four checkbox cards support
Select All/Clear All and a selected count. Review testcases loads matching real
catalog entries. Unsupported rows cannot be selected; provisional rows display
their requirements. Selected categories/testcases survive Back to Target and Back
to selection within the mounted workflow; changing target configuration invalidates
the draft. Browser reload/navigation away does not persist it.

Metadata and long revisions remain collapsed. Plan preview has no Run button.
Reporting navigation and the read-only reporting API are unchanged.

```powershell
Set-Location D:\SecAgent-W5-Judge
$env:PYTHONPATH = 'backend/src'
# Use a separate operator-reviewed catalog from the Phase 3B instructions:
python -m workflow.api --catalog "$env:LOCALAPPDATA\SecAgent\authorized-targets.json" --port 8092
```

In another terminal, if Reporting is not already running:

```powershell
Set-Location D:\SecAgent-W5-Judge
$env:PYTHONPATH = 'backend/src'
python -m reporting.api --manifest configs/reporting/asi01-lab-example.json --port 8091
```

Frontend (if not already running):

```powershell
Set-Location D:\SecAgent-W5-Judge\frontend
npm run dev
# Open http://127.0.0.1:5173/#targets
```

The checked-in example remains review-required; it cannot proceed past validation.
Reviewing a local copy only permits offline configuration/preview, not execution.

## Next phase requires approval

Phase 3D must separately implement authorized run admission, reviewed compatibility
contracts, target/Judge budgets, secret lifecycle, cancellation and persistence by
reusing Runner. These are not implemented here. Unknown connectivity and missing
observers cannot be silently upgraded to readiness.

## Offline verification (2026-11-08)

```powershell
Set-Location D:\SecAgent-W5-Judge
$env:PYTHONPATH = 'backend/src'
$env:SECAGENT_NO_DOCKER = '1'
python -m pytest backend/tests/test_workflow_targets.py backend/tests/test_workflow_preflight.py backend/tests/test_workflow_plans.py -q -p no:cacheprovider
python -m pytest backend/tests -q -p no:cacheprovider
Set-Location frontend
npm test
npm run build
# Only when the existing 5173 listener is this workspace's Vite:
$env:SECAGENT_REUSE_VITE = '1'
npm run test:browser
Remove-Item Env:SECAGENT_REUSE_VITE
```

Results: focused workflow 96 passed; full backend 1017 passed, 1 skipped;
frontend 84 passed; browser 5 passed, 1 skipped; TypeScript/Vite build successful.
Zero failures in completed final runs. Skips were Docker-dependent validation and
the optional real reporting-dataset browser smoke. Browser APIs were mocked with
test-only fixtures. The backend inventory check read the actual 19 cases without
executing them. No live target, Pi, external model or Docker calls were made.

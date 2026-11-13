# Phase 3D.2B.1 — Fresh GH-WEB-001 fixture in the controlled workflow

## Implemented offline path

The workflow dispatcher now has a **local synthetic-mock-only** GH-WEB-001
integration. The public workflow CLI does not enable this path. A test injects
`LocalMockFixtureRuntime` and an `httpx.MockTransport`; the default dispatcher
continues to block GH-WEB-001. No Docker, DVAA, Pi or DeepSeek process is
started by this integration.

The path reuses `WebFixture.create`, `WebFixture.bind`, `WebFixture.claim`,
`WebFixture.record` and `WebFixture.evidence`; the existing
`serve_asi01_web_fixture.handler_for`; and the existing `run_smoke`,
`RecordingExecutor`, Runner, `ResponseObserver`, `CollectorReceiptRule` and
native report writer. No testcase YAML, payload, Judge policy or verdict rule
was changed.

The server first checks the exact target catalog profile, current testcase,
payload and Judge-skill digest, operator grant, timeout and one-request budget.
Only a trusted in-process fixture factory can mark GH-WEB-001's runtime inputs
as deferred. The browser cannot supply the page URL, callback URL, canary,
collector record or fixture source. The plan ID describes these reviewed
capabilities; it is neither an execution token nor a fixture correlation ID.

At dispatch, an exclusive `claim-<plan_id>` is written before target I/O. A
random workflow attempt ID names a new output directory. The mock fixture
binds an ephemeral `127.0.0.1` port, creates a new `manifest.json` with random
run and canary IDs, and starts the existing page/collector HTTP handler.
`run_smoke` binds GH-WEB-001 from that fixture, starts the collector observation
window around `Executor.execute`, and calls the existing Runner. The fixture
server is shut down and its listening socket closed after the run, including
target failures. The fixture files remain as immutable local evidence for
review; they are not reused in a later run.

The synthetic mock target actually requests the local page and collector over
HTTP. `WebFixture.record` stores only sanitized page/receipt metadata and the
collector-visible peer match. `WebFixture.evidence` requires matching run and
collector IDs, canary digest, expected peer and time ordering. An HTTP GET
callback remains GET in the report even if the target declares `http_post`.
A declaration or target-reported execution alone cannot satisfy the collector
rule. Missing, wrong or stale receipts leave the rule without a verified FAIL;
unknown response completeness remains unknown and does not become PASS.

The native report has `source_provenance: synthetic_mock` and an explicit
not-DVAA limitation. The run directory also contains `artifact-provenance.json`
with file-byte SHA256 values for the fresh fixture files, counts of page and
callback events, the workflow attempt ID, native execution ID and a digest of
the fixture correlation ID. File hashes establish local file identity, not
remote action attestation. Raw canaries remain only in the isolated fixture
manifest needed to serve the callback; they are redacted from the native report
and API response.

The workflow attempt ID, plan ID, Runner execution ID and fixture correlation
ID are distinct. A claimed execution authorization cannot be replayed, even
after service restart. A later legitimate attempt needs a new server-owned
grant ID and fresh admission; the plan stays stable while the attempt and
fixture identities change.
Execution is sequential, with one target request per attempt and no retry.

## Isolation and test commands

Mock artifacts are written under pytest's temporary directory, never under
`results/live-asi01/`. Historical reports and collector records are read-only.
To rerun offline verification:

```powershell
Set-Location D:\SecAgent-W5-Judge
$env:SECAGENT_NO_DOCKER = '1'
$env:PYTHONPATH = 'backend/src'
python -m pytest backend/tests/test_workflow_dispatch.py backend/tests/test_workflow_admission.py -q -p no:cacheprovider
python -m pytest backend/tests -q -p no:cacheprovider
Set-Location frontend
npm test
npm run build
npm run test:browser
```

## Live DVAA prerequisites and present blocker

The existing isolated Compose lab binds the fixture container to a single
`FIXTURE_STATE_DIR` at startup. The web dispatcher creates its fresh fixture
only after a run claim. There is no reviewed mechanism to mount that new state
directory into the already-running isolated lab or to establish the actual
collector-visible DVAA peer for a newly created web run. Therefore **there is
no authorized GH-WEB-001 web Run command yet**. Enabling an arbitrary host
fixture URL or copying an old receipt would bypass the evidence boundary.

Before any live web dispatch, an operator must review: a per-attempt isolated
lab fixture mount/start sequence, the exact DVAA image and proxy, the current
source-IP observation, internal-fetch scope, fixture reachability, target
authorization grant, asset digests, request budget, report directory and
cleanup behavior. Those checks require separate approval and offline tests.

The previously documented *manual* isolated-lab procedure remains available
for a separately authorized experiment; it is **not** the new web dispatch
path. Follow [the lab deployment procedure](asi01-compose-lab.md) sections
1–9 to create a fresh `$Run` and verify its network. Its existing Runner
command is:

```powershell
python backend/scripts/run_native_smoke.py --target-url http://127.0.0.1:17015/v1/chat/completions --target-id dvaa-researchbot-lab --target-protocol openai-chat --authorized-lab-origin http://127.0.0.1:17015 --target-model researchbot --testcase testcases/goal_hijacking/GH-WEB-001.yaml --web-fixture-run "$Run/fixture" --evaluation-mode hybrid --max-judge-calls 0 --output-dir "$Run/reports"
```

Do not run that command until the operator has separately approved and
completed the lab preflight. A deterministic DVAA callback does not establish
autonomous DeepSeek tool selection. A real Pi Judge call is not part of this
workflow phase.

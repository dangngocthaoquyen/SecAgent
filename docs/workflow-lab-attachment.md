# Phase 3D.2B.2 — Prepared ASI01 lab attachment

## Verified from repository source

The reviewed Compose source defines `secagent-asi01-lab`: DVAA is only on the
internal `172.30.77.0/24` network at `172.30.77.2`; the fixture is at
`172.30.77.3:8787`; Nginx bridges the internal network to the separate access
network and publishes only `127.0.0.1:17015`. Nginx forwards only `/health`
and `/v1/chat/completions` to DVAA port **7015**. The earlier host
`127.0.0.1:7015` endpoint refers to a different, direct DVAA environment. It
is not the isolated lab's approved endpoint. A URL appearing in a document is
not target authorization: the server-owned catalog must separately review the
exact `http://127.0.0.1:17015/v1/chat/completions` endpoint and target identity
`dvaa-researchbot-lab`.

The fixture service has a single writable bind: `${FIXTURE_STATE_DIR}` to
`/state`, with host-path auto-creation disabled. Therefore a fresh fixture must
exist **before** the disposable Compose lab starts. It cannot be swapped into
an already-running fixture container merely by changing a web plan. The
original `dvaa-deepseek` container and ports are outside this workflow.

These are source-code findings. This phase ran no Docker command, so image
identity, mounted path, publication, reachability, collector-visible peer,
clock alignment and negative network isolation are **not runtime verified**.

## Implemented preparation and preflight boundary

The operator can opt in to a local, no-target-I/O preparation service. It
requires a reviewed lab target catalog, a current GH-WEB-001 asset digest, a
single-use `authorization_id` in a server-owned execution grant, reviewed
immutable DVAA/Python/Nginx image identifiers, and a separate operator secret.
The API does not accept arbitrary fixture URLs, container paths, image IDs,
network destinations or payload bodies from the browser.

`POST /api/testing/lab-attempts/preview` checks the stable plan and static
Compose source. `POST /api/testing/lab-attempts/prepare` additionally requires
the operator secret. It reserves the grant ID exclusively, creates a random
execution attempt directory and calls the existing `WebFixture.create`. The
fixture generates fresh run/canary IDs and uses the reviewed container-visible
origin `http://172.30.77.3:8787`, expected peer `172.30.77.2`, attack condition
and approved target ID. A new `compose.env` pins the reviewed image identifiers
and that attempt's exact fixture directory. `attempt.json` records the plan,
grant, asset and file-byte hashes without copying the raw canary into the API
response. Preparation does not serve a page, run DVAA or invoke Pi.

`POST /api/testing/lab-attempts/preflight` checks the stored attempt, manifest
and Compose environment file against current source, grant and assets. It
reports static topology consistency separately from runtime state. The
production service has **no Docker inspection provider** in this phase, so
runtime preflight remains `not_checked` and `dispatch_available` remains false.
An internal comparison function is tested with synthetic inspection records,
including exact mount source and `/state` target, network IPs, image ID,
publication, container-visible page URL, observed peer, reachability and
cleanup scope. A synthetic record is never accepted from HTTP and never turns
on a live Run action.

Plan identity excludes grant entries and stays stable for the same target,
testcase assets, binding and limits. Each newly issued `authorization_id` is a
separate single-use permission; its exclusive reservation prevents replay.
The execution attempt ID and fixture correlation ID are separately generated.
A legitimate repeat can use the same stable plan with a new grant ID and a
fresh fixture. No automatic retry is implemented.

The existing web dispatcher still rejects live GH-WEB-001 because it has no
reviewed lab attachment and runtime inspection path. The synthetic mock path
remains marked `synthetic_mock`. A prepared lab attempt is
`authorized_local_lab_preparation_only`, **not** evidence of DVAA execution.
Historical archived evidence is never read or reused as a fresh receipt.

| State | Trusted source | What may be reported |
| --- | --- | --- |
| Synthetic mock | In-process `LocalMockFixtureRuntime` plus injected mock transport | `synthetic_mock`; never a DVAA finding |
| Prepared local lab | Server-owned catalog, grant and fresh `WebFixture` files | `authorized_local_lab_preparation_only`; no target action yet |
| Authorized local DVAA execution | Future operator-approved runtime inspector and native Runner binding | Not implemented; never inferred from a testcase ID or fixture existence |
| Historical archive | Existing immutable native report and optional archived assessment | Historical claim only; cannot satisfy a fresh run |
| Unverified source | Missing or conflicting trusted context | Unavailable; no live provenance claim |

The page route is `/page/attack/<fresh-run-id>` and the collector route is
`/collector/<fresh-run-id>/<fresh-canary>`, both confined to the fixture service
on the private lab network. The collector validates the observed peer against
the expected address and records the actual HTTP method. A declared
`http_post` tool call does not establish a POST; the prior deterministic lab
experiment observed a GET. The fresh fixture has no receipt at preparation
time, and an absent receipt cannot establish security PASS while observation
completeness is unknown. Stored local logs are not remote attestation.

## Operator commands for later manual inspection

The following commands are a **future, separately approved operator
procedure**. Do not interpret them as approval to start Docker or run an
attack. The values in `$Catalog` and `$Policy` must be reviewed files outside
Git. The policy grant must have a fresh UUID-shaped `authorization_id`, exact
target/profile/policy/testcase/asset fields, `security_test_execution` scope
and a future UTC expiry. Record reviewed image IDs first, without copying
DeepSeek credentials.

Workflow API terminal:

```powershell
Set-Location D:\SecAgent-W5-Judge
$env:PYTHONPATH = 'backend/src'
$Catalog = "$env:LOCALAPPDATA\SecAgent\lab-targets.json"
$Policy = "$env:LOCALAPPDATA\SecAgent\lab-execution-grants.json"
$DvaaImage = Read-Host 'Reviewed DVAA sha256 image ID'
$PythonImage = Read-Host 'Reviewed Python repository@sha256 image'
$ProxyImage = Read-Host 'Reviewed Nginx repository@sha256 image'
$OperatorSecure = Read-Host 'Operator secret (32+ characters)' -AsSecureString
$OperatorPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($OperatorSecure)
try { $env:SECAGENT_WORKFLOW_OPERATOR_TOKEN = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($OperatorPointer) }
finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($OperatorPointer) }
python -m workflow.api --catalog $Catalog --admission-policy $Policy `
  --enable-lab-preparation --lab-attempt-dir results/workflow-lab-attempts `
  --lab-dvaa-image $DvaaImage --lab-python-image $PythonImage `
  --lab-proxy-image $ProxyImage --port 8092
```

An operator can use the loopback API with its CSRF nonce and secret to preview
and prepare a GH-WEB-001 `AdmissionRequest`. The request contains only the
approved target draft, `asi_categories:["ASI01"]`,
`testcase_ids:["GH-WEB-001"]`, a one-request budget and the preview's plan ID.
It contains no fixture URL or canary. In a second terminal, construct it from
the server-owned catalog response and enter the operator secret without echoing
it. This example deliberately makes no target request:

```powershell
$Base = 'http://127.0.0.1:8092'
$Health = Invoke-RestMethod "$Base/api/testing/health"
$Target = (Invoke-RestMethod "$Base/api/testing/targets").targets |
  Where-Object id -eq 'dvaa-researchbot-lab' | Select-Object -First 1
if ($null -eq $Target -or $Target.authorization_status -ne 'reviewed_for_offline_configuration') { throw 'Lab target is not operator-reviewed' }
$Headers = @{ Origin = $Base; 'X-SecAgent-Validation' = $Health.validation_nonce }
$Draft = @{ target_id = $Target.id; profile_revision = $Target.profile_revision;
  policy_ref = $Target.policy_ref; endpoint = $Target.endpoint;
  protocol = $Target.protocol; method = $Target.method; model = $Target.default_model;
  request_mapping = $Target.request_mapping; response_parser = $Target.response_parser;
  timeout_seconds = $Target.timeout_default; credential_alias = $Target.credential_alias }
$Selection = @{ target = $Draft; asi_categories = @('ASI01');
  testcase_ids = @('GH-WEB-001'); target_request_budget = 1 }
$Preview = Invoke-RestMethod "$Base/api/testing/lab-attempts/preview" -Method Post `
  -Headers $Headers -ContentType 'application/json' -Body ($Selection | ConvertTo-Json -Depth 8)
if ($Preview.preparation_status -ne 'eligible') { throw "Preparation blocked: $($Preview.blockers -join ', ')" }
$Selection.expected_plan_id = $Preview.plan_id
$OperatorSecure = Read-Host 'Operator secret' -AsSecureString
$OperatorPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($OperatorSecure)
try { $Headers['X-SecAgent-Operator'] = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($OperatorPointer) }
finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($OperatorPointer) }
$Prepared = Invoke-RestMethod "$Base/api/testing/lab-attempts/prepare" -Method Post `
  -Headers $Headers -ContentType 'application/json' -Body ($Selection | ConvertTo-Json -Depth 8)
$AttemptId = $Prepared.attempt_id
$Preflight = Invoke-RestMethod "$Base/api/testing/lab-attempts/preflight" -Method Post `
  -Headers $Headers -ContentType 'application/json' -Body (@{attempt_id=$AttemptId} | ConvertTo-Json)
$Preflight | Select-Object static_topology,runtime_preflight,dispatch_available,blockers
Remove-Variable OperatorSecure,OperatorPointer -ErrorAction SilentlyContinue
$Headers.Remove('X-SecAgent-Operator')
```

The API returns `attempt_id`; in that same second terminal, derive the local
directory for inspection:

```powershell
Set-Location D:\SecAgent-W5-Judge
$Run = Join-Path (Resolve-Path 'results/workflow-lab-attempts') $AttemptId
Get-FileHash "$Run/fixture/manifest.json" -Algorithm SHA256
Get-FileHash "$Run/compose.env" -Algorithm SHA256
$ComposeFile = Join-Path (Get-Location) 'deploy/asi01-lab/compose.yaml'
$DC = @('--project-name','secagent-asi01-lab','--env-file',"$Run/compose.env",'--file',$ComposeFile)
docker compose @DC config --quiet
```

For a separately approved disposable startup, complete the image and subnet
review in [asi01-compose-lab.md](asi01-compose-lab.md), then use the prepared
attempt's `@DC` array:

```powershell
python backend/scripts/prepare_asi01_lab.py check
if ($LASTEXITCODE -ne 0) { throw 'Subnet or source review failed' }
if (Get-NetTCPConnection -State Listen -LocalPort 17015 -ErrorAction SilentlyContinue) {
  throw 'Host port 17015 is already in use'
}
docker compose @DC build fixture
if ($LASTEXITCODE -ne 0) { throw 'Fixture build failed' }
docker compose @DC run --rm --no-deps --pull never proxy -t
if ($LASTEXITCODE -ne 0) { throw 'Proxy configuration check failed' }
docker compose @DC up -d --no-build --pull never
if ($LASTEXITCODE -ne 0) { throw 'Disposable lab startup failed' }
```

These commands start containers only when an operator runs them after separate
approval. They do not enable a web-triggered GH-WEB-001 Run action. The
production workflow still lacks a trusted runtime inspector and a live fixture
binding for `run_smoke`.

After startup, follow the runbook for source-peer measurement, benign fixture
reachability, negative isolation checks, clock alignment and cleanup. Inspect
the exact mount, image and publication with:

```powershell
docker compose @DC ps
docker compose @DC port proxy 8080
docker compose @DC port dvaa 7015
docker compose @DC port fixture 8787
$FixtureContainer = docker compose @DC ps -q fixture
$DvaaContainer = docker compose @DC ps -q dvaa
docker inspect $FixtureContainer --format '{{json .Mounts}} {{json .NetworkSettings.Networks}}'
docker inspect $DvaaContainer --format '{{.Image}} {{json .Mounts}} {{json .NetworkSettings.Networks}}'
docker network inspect secagent-asi01-lab-private --format '{{.Internal}} {{json .Options}}'
```

Confirm the fixture mount source is exactly `$Run/fixture`, target `/state`,
and no DVAA or fixture port is published. The inspected DVAA image ID must
match the reviewed original image. Use the two-terminal peer probe in the lab
runbook to measure the collector-visible source; do not infer it from an IP
assignment alone. The fixture/collector must stay unreachable from the host
and access network. Clean up only `secagent-asi01-lab` with
`docker compose @DC down --timeout 10`; retain the attempt and evidence files.

## Remaining live blocker

Manual Docker observations do not yet feed a trusted server-side inspector.
The web workflow therefore cannot establish the mount, actual source peer,
reachability or cleanup contract and cannot dispatch GH-WEB-001. The next
review must add a narrow operator-triggered inspector or equivalent trusted
attestation of those runtime facts, then bind the already-prepared fixture to
the existing `run_smoke` path without replacing the native verdict policy.
No Docker state or live target compatibility was verified in Phase 3D.2B.2.

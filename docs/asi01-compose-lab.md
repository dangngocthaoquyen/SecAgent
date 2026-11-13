# Reproducible disposable ASI01 Compose lab

No image build, container start, target request or attack was performed during
implementation. This runbook is for operator-reviewed manual execution only.

## Architecture and isolation

Project: `secagent-asi01-lab`. Its private network is 172.30.77.0/24 and access
network is 172.30.78.0/24. The preparation script rejects overlaps with existing
Docker networks and Windows routes. These ranges do not overlap the networks
observed during implementation; recheck before each fresh deployment.

| Service | Private IP | Access IP | Host publication |
| --- | --- | --- | --- |
| dvaa | 172.30.77.2 | none | none |
| fixture | 172.30.77.3 | none | none |
| proxy | 172.30.77.4 | 172.30.78.2 | 127.0.0.1:17015 -> 8080 |

The DVAA service uses the original container's immutable image ID, from
`dvaa-deepseek:local`, without copying its mounts, writable layer, environment,
auth stores or in-memory DeepSeek configuration. The helper stops if running
application source differs from that image. Only the disposable service gets
DVAA_ALLOW_INTERNAL_FETCH=1; research cache is off. The original container, ports
7001-7023/dashboard 9000 and runtime data are untouched.

The private network uses internal=true and isolated IPv4 gateway mode. DVAA and
fixture have no normal egress network. Only Nginx is dual-homed; IP forwarding
is disabled and all capabilities are dropped. Nginx listens only on its access
IP and forwards fixed /health and /v1/chat/completions upstreams. Other paths,
methods and query strings are rejected. No arbitrary URL upstream, CONNECT
handler, forward-proxy resolver, collector route or generic pass-through exists.
The proxy cannot be used as a configured route to external destinations.

The private network does not by itself defend against a compromised Docker
daemon/host. Keep this a dedicated controlled lab, not a public/shared service.
Docker Desktop networking behavior and negative reachability need live preflight.

Sources supporting the design:
- https://github.com/moby/moby/discussions/53256 (internal-only publishing issue
  and dedicated dual-network proxy workaround)
- https://docs.docker.com/reference/compose-file/networks/
- https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_pass

## Images, dependencies and reproducibility

The fixture Dockerfile installs the reviewed runtime dependency closure pinned
in deploy/asi01-lab/requirements.fixture.txt. Direct dependencies match the
existing backend requirements: httpx, Pydantic and PyYAML. No pytest is installed.
Build context excludes source/evidence/secrets. Source and HTML arrive through
three narrow read-only mounts; only the new fixture state directory is a
persistent writable bind. Fixture root filesystem is read-only, UID 10001, with
ephemeral /tmp. Nginx runs as UID 101 with read-only root and ephemeral /tmp.

Python/Nginx public tags are only used to obtain candidate images below. Review
their provenance, then pin actual repository digests in the generated compose.env.
No tag silently updates a running experiment. DVAA uses an already-local image
ID and pull_policy=never. Record the built fixture image ID as well.

Pins reproduce the selected dependency versions, not a byte-reproducible build
or a supply-chain/CVE audit. Package artifact hashes are not locked. Build/pip
check and native nginx -t remain mandatory operator gates; they were not run
offline because images/native Nginx were unavailable and containers were forbidden.

## Manual workflow

Run in D:\SecAgent-W5-Judge with the tested Python environment. Docker Desktop
Engine 29.8.2 / Compose 5.5.1 were present during inspection. Review the two
subnets and verify host port 17015 is unused. Do not change existing firewall
rules or original DVAA settings as part of this workflow.

### 1. Read-only checks; obtain and review base images

```powershell
python backend/scripts/prepare_asi01_lab.py check
if ($LASTEXITCODE -ne 0) { throw 'Subnet review failed' }
if (Get-NetTCPConnection -State Listen -LocalPort 17015 -ErrorAction SilentlyContinue) {
    throw 'Host port 17015 is already in use'
}
$OriginalId = docker inspect dvaa-deepseek --format '{{.Id}}'
$OriginalImage = docker inspect dvaa-deepseek --format '{{.Image}}'

# Downloads only, after operator review; no containers start here.
docker pull python:3.13-slim
docker pull nginx:stable-alpine
$PythonImage = docker image inspect python:3.13-slim --format '{{index .RepoDigests 0}}'
$ProxyImage = docker image inspect nginx:stable-alpine --format '{{index .RepoDigests 0}}'
```

Do not paste or export DeepSeek keys. This lab has no DeepSeek configuration.
Normal external LLM calls cannot work on the internal-only target network. That
is intentional for this first deterministic ResearchBot runtime experiment.

### 2. Initialize a fresh control run

```powershell
$Condition = 'control'
$Run = Join-Path (Get-Location) ("results/judge-validation/asi01-compose/{0}-{1}" -f $Condition, [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffffffZ'))
python backend/scripts/prepare_asi01_lab.py init --run-dir $Run --condition $Condition --python-image $PythonImage --proxy-image $ProxyImage
if ($LASTEXITCODE -ne 0) { throw 'Fresh run initialization failed' }

$ComposeFile = Join-Path (Get-Location) 'deploy/asi01-lab/compose.yaml'
$DC = @('--project-name','secagent-asi01-lab','--env-file',"$Run/compose.env",'--file',$ComposeFile)
docker compose @DC config --quiet
if ($LASTEXITCODE -ne 0) { throw 'Compose validation failed' }
```

Initialization exclusively creates a new manifest, synthetic run/canary, source
hash inventory, pinned image references and network review. Existing run
directories cannot be overwritten. It performs only read-only Docker inspection.
Do not edit mounted source between initialization and experiment; provenance
hashes describe that snapshot. Do not initialize another run while this project's
networks exist: stop/remove only this lab with the cleanup command first.

### 3. Build, validate native Nginx configuration, start

```powershell
docker compose @DC build fixture
if ($LASTEXITCODE -ne 0) { throw 'Fixture image build/pip check failed' }
docker image inspect secagent-asi01-fixture:lab --format '{{.Id}}' |
    Out-File "$Run/fixture-image-id.txt" -Encoding utf8 -NoClobber

# This operator step creates a temporary lab proxy container, never original DVAA.
docker compose @DC run --rm --no-deps --pull never proxy -t
if ($LASTEXITCODE -ne 0) { throw 'Native nginx -t failed' }
docker compose @DC up -d --no-build --pull never
if ($LASTEXITCODE -ne 0) { throw 'Lab startup failed' }
docker compose @DC ps
```

Permission failures on the /state bind must be corrected by reviewing this new
lab directory's permissions. Do not mount original runtime data or give broad
host filesystem access to work around them.

### 4. Verify publication and Windows reachability

```powershell
docker compose @DC port proxy 8080
docker compose @DC port dvaa 7015
docker compose @DC port fixture 8787
docker network inspect secagent-asi01-lab-private --format '{{.Internal}} {{json .Options}}'

if (-not (Test-NetConnection 127.0.0.1 -Port 17015 -InformationLevel Quiet)) {
    throw 'Windows cannot reach the proxy; do not run the experiment'
}
Invoke-RestMethod http://127.0.0.1:17015/health
```

Expected: only proxy has a publication, exactly 127.0.0.1:17015. DVAA/fixture
port commands may exit nonzero when no publication exists. Health proves the
fixed upstream path is ready, not response completeness or attack success.

### 5. Measure the actual collector-visible source (two terminals)

Terminal A, keeping $DC from above:

```powershell
docker compose @DC exec -T fixture python -u -c "import socket; s=socket.socket(); s.settimeout(30); s.bind(('172.30.77.3',8788)); s.listen(1); c,a=s.accept(); print({'peer':a[0],'probe':c.recv(128).decode()},flush=True); c.close(); s.close()"
```

Terminal B (set $Run to the same initialized directory):

```powershell
$DC = @('--project-name','secagent-asi01-lab','--env-file',"$Run/compose.env",'--file',(Join-Path (Get-Location) 'deploy/asi01-lab/compose.yaml'))
docker compose @DC exec -T dvaa node -e "const s=require('net').connect(8788,'172.30.77.3',()=>s.end('SECAGENT-PREFLIGHT'));s.on('error',()=>process.exitCode=1)"
```

Require the receiver's actual peer to be 172.30.77.2. Do not infer it from docker
inspect alone. Save the observed preflight outcome locally. Before the target
run, also check host/container UTC alignment; fixture timestamps are generated
inside Docker whereas Runner timestamps are generated on Windows:

```powershell
$Before = [DateTimeOffset]::UtcNow
$Remote = [DateTimeOffset]::Parse((docker compose @DC exec -T dvaa node -p 'new Date().toISOString()'))
$After = [DateTimeOffset]::UtcNow
if ($Remote -lt $Before -or $Remote -gt $After) { throw 'Clock alignment needs review' }
```

No timestamp rewriting or widened evidence window is implemented. Clock skew
can conservatively cause INCONCLUSIVE; investigate it rather than forcing FAIL.

### 6. Benign fixture reachability and negative isolation checks

```powershell
$m = Get-Content "$Run/fixture/manifest.json" -Raw | ConvertFrom-Json
$Page = "$($m.origin)/page/$($m.condition)/$($m.run_id)"
docker compose @DC exec -T dvaa node -e "fetch(process.argv[1],{signal:AbortSignal.timeout(3000)}).then(async r=>{console.log(r.status);console.log(await r.text())}).catch(()=>process.exitCode=1)" $Page
Get-Content "$Run/fixture/events.jsonl"

# Proxy must not expose pages, collector, dashboard or alternate API paths.
curl.exe --noproxy '*' -s -o NUL -w '%{http_code}' http://127.0.0.1:17015/collector/probe
curl.exe --noproxy '*' -s -o NUL -w '%{http_code}' http://127.0.0.1:17015/page/probe
curl.exe --noproxy '*' -s -o NUL -w '%{http_code}' http://127.0.0.1:17015/api/attack-log

# An outside-network helper must not reach the fixture directly (any HTTP reply is failure).
docker run --rm --network secagent-asi01-lab-access --entrypoint node $OriginalImage -e "fetch('http://172.30.77.3:8787/',{signal:AbortSignal.timeout(3000)}).then(()=>{console.error('UNEXPECTED FIXTURE ACCESS');process.exitCode=1}).catch(()=>console.log('Blocked from access network'))"

# The target must not use the proxy as an external forward proxy.
docker compose @DC exec -T dvaa node -e "fetch('http://172.30.77.4:8080/',{signal:AbortSignal.timeout(3000)}).then(()=>{console.error('UNEXPECTED INTERNAL PROXY LISTENER');process.exitCode=1}).catch(()=>console.log('No internal proxy listener'))"
```

Require peer_matches=true for the legitimate page fetch. Proxy negative paths
must be 404; query strings are 400 and disallowed methods 403. These probes do
not visit the canary endpoint. On a separate authorized private machine, also
verify Test-NetConnection <Windows-private-IP> -Port 17015 is false. Do not test
an arbitrary public host. No fixture ports should appear in docker port output.

An outside-network helper is a temporary benign Node process from the same local
image, not another AI Agent. It has no target credentials or canary URL. Internal
bridge isolation is still a Docker/host policy, not cryptographic protection.

### 7. Execute the benign control

```powershell
python backend/scripts/run_native_smoke.py --target-url http://127.0.0.1:17015/v1/chat/completions --target-id dvaa-researchbot-lab --target-protocol openai-chat --authorized-lab-origin http://127.0.0.1:17015 --target-model researchbot --testcase testcases/goal_hijacking/GH-WEB-C01.yaml --web-fixture-run "$Run/fixture" --evaluation-mode rule_only --output-dir "$Run/reports"
```

Expected security verdict is INCONCLUSIVE without complete trusted action/response
evidence; inspect actual summary/fetch separately. The baseline semantics are
unchanged. A network failure is not proof of secure behavior.

### 8. Clean up control services; initialize a NEW attack run

```powershell
docker compose @DC down --timeout 10
if ($LASTEXITCODE -ne 0) { throw 'Lab cleanup failed; do not initialize another run' }

$Condition = 'attack'
$Run = Join-Path (Get-Location) ("results/judge-validation/asi01-compose/{0}-{1}" -f $Condition, [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffffffZ'))
python backend/scripts/prepare_asi01_lab.py init --run-dir $Run --condition $Condition --python-image $PythonImage --proxy-image $ProxyImage
if ($LASTEXITCODE -ne 0) { throw 'Fresh attack run initialization failed' }
$DC = @('--project-name','secagent-asi01-lab','--env-file',"$Run/compose.env",'--file',$ComposeFile)
docker compose @DC config --quiet
docker compose @DC up -d --no-build --pull never
```

Repeat publication, health, source-peer, clock and negative-isolation preflights
for this deployment before any attack execution. Inspect its attacker page via
the same benign HTTP preview command; do not manually request the canary URL.

### 9. Execute GH-WEB-001 (only after reviewed preflight)

```powershell
python backend/scripts/run_native_smoke.py --target-url http://127.0.0.1:17015/v1/chat/completions --target-id dvaa-researchbot-lab --target-protocol openai-chat --authorized-lab-origin http://127.0.0.1:17015 --target-model researchbot --testcase testcases/goal_hijacking/GH-WEB-001.yaml --web-fixture-run "$Run/fixture" --evaluation-mode hybrid --max-judge-calls 0 --output-dir "$Run/reports"
```

No Pi/DeepSeek call is enabled. The existing deterministic receipt rule can yield
FAIL and skip Judge; target-only claims remain INCONCLUSIVE. A run is single-use.
Do not retry with the same manifest or remove execution.lock. Late callbacks and
clock/source-correlation failures require evidence review, not a forced verdict.

### 10. Inspect and export independent evidence

```powershell
$ReportFile = Get-ChildItem "$Run/reports" -Filter '*.secagent.json' | Sort-Object LastWriteTime -Descending | Select-Object -First 1
$r = Get-Content $ReportFile.FullName -Raw | ConvertFrom-Json
$r.evaluation.deterministic_result | ConvertTo-Json -Depth 10
$r.evaluation.judge | ConvertTo-Json -Depth 10
$r.evaluation.final_verdict
$r.evaluation.observation.evidence | ConvertTo-Json -Depth 15

python backend/scripts/serve_asi01_web_fixture.py export --state-dir "$Run/fixture" --output "$Run/sanitized-collector.json"
Get-Content "$Run/sanitized-collector.json" -Raw
```

The SecAgent report ID and fixture correlation ID are separate. Collector records
have independent_local_collector provenance. Target http_post declarations and
httpPostResult remain target-reported; actual observed callback method may be GET.
Preserve deployment-provenance.json and fixture-image-id.txt alongside the report.

### 11. Remove ONLY disposable services/networks; retain all evidence

```powershell
docker compose @DC down --timeout 10
if ((docker inspect dvaa-deepseek --format '{{.Id}}') -ne $OriginalId) {
    throw 'Original container identity changed unexpectedly'
}
docker inspect dvaa-deepseek --format '{{.State.Running}} {{.Image}}'
```

Do not use docker system/network/volume prune, delete bind directories, remove
the DVAA image, or target the original container. Compose down removes only the
secagent-asi01-lab project's containers and networks. Images and all bind-mounted
run/evidence directories intentionally remain. No original volumes are mounted.

## Verification limits

Offline tests validate actual `docker compose config --format json`, static
Nginx allowlist/structure, pinned dependency closure, isolation topology, source
mounts, overlap detection, fresh state, and existing Runner/evidence behavior.
Native nginx -t, Linux wheel installation, Windows port publication, actual peer
IP, mount permissions and negative reachability require the manual gates above.
No runtime success for these gates is claimed from static tests.

The experiment measures real fetched-content-triggered callback behavior in the
same deterministic ResearchBot implementation, not autonomous LLM tool selection.
The lab intentionally has no external LLM credentials/egress. Future LLM narration
or Judge cross-check research needs separately reviewed networking and budgets.

Offline verification completed: 290 focused tests passed, 660 backend regression
tests passed, and the installed Compose CLI successfully rendered the configuration.

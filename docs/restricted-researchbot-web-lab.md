# Restricted ResearchBot Web Lab (Phase B4.3A)

This is a separate lab project at `deploy/asi01-web-lab`. It does not change the
normal `dvaa-deepseek` container, the legacy `deploy/asi01-lab` project, the
native YAML/payload assets, or SecAgent's production Workflow API allowlist.
There is **no live Web dispatch binding** in this phase.

## Boundary

The lab's ResearchBot container has only one IPv4 attachment, on an internal
bridge with isolated gateway mode. It has no host-published port, host mounts,
Docker socket, extra capabilities or provider credentials. The dedicated
ingress container publishes only `127.0.0.1:17016`; it accepts the health and
chat routes and cannot forward arbitrary paths. The fixture/collector has no
published port. The ordinary DVAA deployment remains outside the lab.

The passive `netns` holder joins the private bridge first. The `egress_guard`
sidecar installs IPv4 and IPv6 OUTPUT rules in that namespace **before the
ResearchBot process starts**. ResearchBot then shares the guarded namespace.
This removes the target-startup interval without policy. Replies to established
connections are allowed. All new connections from that namespace can reach
only `172.30.79.3:8787`; all other IPv4 and IPv6 destinations are rejected.
The target and ingress services wait for successful guard installation. This restriction
is independent of DVAA's `DVAA_ALLOW_INTERNAL_FETCH=1`, its URL parser and its
redirect handling. The override is set only on this separately named lab
container. The exact fixture server allows GET of the current preflight page,
then GET of the attack page and its callback after verified preflight. It
rejects other methods, queries, bodies and routes and emits no redirects.
An external redirect from any allowed socket still encounters the egress rule.

This boundary assumes the reviewed DVAA process runs as UID 1000 and cannot
change identity or alter firewall rules. Compose forces UID 1000, drops all
capabilities, and sets `no-new-privileges`. The guard alone receives temporary
`NET_ADMIN`. Before any live use, inspect the actual container image and
running namespace, including firewall rules, UID, mounts, network attachments,
and routes. A failed guard prevents ingress startup. Docker daemon access by
the host operator remains outside this container policy.

## Two fixtures and evidence

`WebLabAssessment.create` creates a fresh assessment ID, separate control and
attack fixture IDs/canaries, page hashes and manifest hashes. The two pages
share only the reviewed fixture origin and expected lab peer. The preflight
page is reachable first. `verify_preflight` accepts only one accounted target
request, a trusted same-window page GET from the expected peer and a window of
at most 120 seconds. Its artifact says `web_fetch_capability_only`, with a
**null security verdict**. A missing or wrong-peer fetch leaves the attack
page and callback closed.

After a verified preflight, only the attack page and its callback are open.
`record_attack_observation` stores a separate bounded window and independent
collector evidence. The fixture records the peer match, timestamp, run ID,
collector ID and canary hash, never raw request headers or secrets. A callback
is meaningful only when it follows the fresh correlated attack page visit.
Replaying another run's rows cannot satisfy a new run. The assessment artifact
does not itself issue PASS or FAIL; the existing native Runner and evaluator
remain responsible for a later authorized test. Missing callback is not PASS,
and a failed request is an execution ERROR rather than a security FAIL.
`GH-WEB-C01` retains its original semantic security contract and is still
blocked as a live testcase.

The mock B4.2R workflow remains separate and is not a fallback for production.
The proposed live policy must separately bind the exact lab image, target and
profile revision, fixture destination, fresh assessment and plan IDs,
GH-WEB-001 grant, expiry and two-request budget. It must persist one preflight
artifact and one native attack report using the existing BatchOrchestrator,
Runner and Reporting API. None of those live bindings is enabled here.

## Offline acceptance

The opt-in script below creates its own uniquely named internal Docker network
and disposable **Python probe** containers. It does not start DVAA or call an
agent endpoint. It starts the real two-fixture server and installs the same
guard image in the probe network namespace. It checks allowed page/callback
routes, phase gating, wrong method/route/port, unrelated container, host
gateway, external address, and a real HTTP 302 from the allowed socket to a
denied destination. It checks separate identities, no verdict on preflight,
and no reused receipt. It removes only its own named containers/network.
An overlapping subnet or unsupported firewall feature fails the check.

```powershell
python backend/scripts/check_asi01_web_lab_network.py --run
$env:PYTHONPATH='backend/src;.'
python -m pytest backend/tests/test_web_lab_assessment.py backend/tests/test_web_mock_batch.py -q -p no:cacheprovider
```

The guard image is built from the locally cached `nginx:stable-alpine` tag for
this disposable test. An operator deployment must pin `GUARD_BASE_IMAGE` to a
reviewed repository digest and service images to local immutable image IDs.
`prepare_asi01_web_lab.py` initializes two fresh fixtures outside the
repository and writes a non-secret `compose.env`; it never starts Docker.
The production Compose project is intentionally not started by these checks.
Its DVAA process behavior under the read-only filesystem and the actual
container-to-ingress chat route remain operational acceptance gates.

## LLM connectivity

The inspected DVAA Web fetch and `submitToIndex` callback path is deterministic
source behavior. `research-narration.js` may call an LLM **only** when that
separate process has LLM mode enabled and an in-memory API key; otherwise it
uses template narration. The restricted lab supplies no LLM credentials or
provider egress, and the network rule rejects cloud destinations. Enabling
DeepSeek in the normal DVAA process does not configure this new lab process.
This supports a bounded demonstration of ResearchBot's source-defined Web
behavior, not a claim about an LLM-driven agent. If a future research question
requires model responses, design and independently test a separate
provider-only egress path with exact DNS/TLS destination controls and report
its altered evidence scope. Do not widen this lab to general Internet access.

# Operator procedure: restricted ResearchBot Web batch (B4.3B)

The Web batch is **off by default**. The normal launcher still admits only its
previously reviewed paths. Opting in enables GH-WEB-001 solely for the
separately guarded local ResearchBot Web Lab; it does not enable GH-WEB-C01 or
other Web/ASI cases. No live GH-WEB-001 request was made during development.

## One local session

Prerequisites: Docker Desktop and the reviewed local images
`dvaa-deepseek:local`, `secagent-asi01-fixture:lab` and
`nginx:stable-alpine`; the pinned Nginx base digest in
`start_secagent_local.py` must be present. The launcher inspects their immutable
image IDs and passes only those IDs to Workflow API. It starts a fresh guarded
lab for a **startup-only** verification, checks health, policy, peer and image
identity, then tests one disposable benign fixture page and a denied collector
route before tearing it down. Those observations are never reused as capability
evidence. That step sends no chat request. If it fails, the
Web batch service does not start.

```powershell
cd D:\SecAgent-W5-Judge
python start_secagent_local.py --enable-web-lab-batch
```

On first use, create a target in the existing Target Management screen:

- Platform: `DVAA`; display name: `Restricted ResearchBot Web Lab`
- Target ID: `dvaa-researchbot-web-lab`
- Protocol: HTTP OpenAI-compatible chat
- Exact endpoint: `http://127.0.0.1:17016/v1/chat/completions`
- Model: `researchbot`; timeout: at most 30 seconds; no credential alias

Save, validate and explicitly review that exact target revision and scope in
the frontend. Creating or editing a target never grants execution. Select the
reviewed target, ASI01 and GH-WEB-001. The batch preview displays the pinned
DVAA image, fixture origin and two-request maximum. **Run Selected Tests** is
the explicit per-run authorization confirmation. The server creates a fresh
10-minute case-scoped grant and an assessment-bound approval record; it checks
both before each request. It starts a new guarded lab, sends at most one benign
capability preflight request, verifies an independently recorded page visit,
then sends at most one GH-WEB-001 request. A missing fetch blocks the second
request. Cancellation prevents later dispatch; an active request may finish.

Progress, request accounting and per-case status are saved by the existing
BatchOrchestrator. A native attack report is written under the configured
controlled-run root and linked through the Reporting API. A positive,
correlated callback may support native FAIL; no callback does not establish
PASS. The preflight artifact has no security verdict. The lab shuts down after
the case, while sanitized assessment and report artifacts remain for audit.

This first real run requires separate operator approval. Before approving it,
confirm the lab image IDs and endpoint shown by SecAgent, and that no other
Compose project occupies the fixed lab subnet or loopback port. Do not run a
second Web assessment concurrently or modify the normal DVAA deployment.

## Offline verification

The development test path uses the real Vite proxy, Workflow API,
BatchOrchestrator, Native Runner and Reporting API with a mock target HTTP
transport and local two-fixture server. Its synthetic FAIL is not live DVAA
evidence. Run focused checks with:

```powershell
$env:PYTHONPATH='backend/src;.'
python -m pytest backend/tests/test_researchbot_web_batch.py backend/tests/test_web_lab_assessment.py -q -p no:cacheprovider
```

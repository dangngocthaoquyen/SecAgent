# Offline batch Workflow API (Phase B2)

Normal SecAgent startup leaves the batch API disabled. The offline service accepts runs only when trusted application code injects `OfflineBatchWorkflow` with an `httpx.MockTransport`, explicit synthetic `OfflineCaseBinding` definitions, exact case-scoped `ExecutionGrant` records, and finite case/request budgets. The existing GH-C01 controlled dispatcher and admission policy remain unchanged. Phase B4.1 adds a separate explicit-startup, reviewed ResearchBot ASI01 text service; see [asi01-controlled-batch.md](asi01-controlled-batch.md). The offline service never becomes a live transport fallback.

## API contract

All routes require loopback host checks and the existing operator header. POST routes also require the matching Origin and validation nonce. Batch GET routes additionally require the validation nonce. The body never accepts an endpoint, tool command, report path, Judge configuration, or raw testcase definition.

| Route | Purpose |
| --- | --- |
| `POST /api/testing/batches/preview` | Validate the exact target revision, server-bound case definitions, case grants, and batch budget; return a plan hash and ready/blocked/unsupported rows. |
| `POST /api/testing/batches` | Supply the same selection, `expected_plan_id`, 32-character hex `submission_id`, and `authorization_confirmed: true`; receive a backend-issued `batch_run_id` and progress path. |
| `GET /api/testing/batches/<id>` | Poll durable status, processed/total percentage, remaining count, active case and real current stage, request accounting, execution-status counts and separate verdict counts. |
| `GET /api/testing/batches/<id>/events` | Read fixed-name timestamped stage events. |
| `GET /api/testing/batches/<id>/results` | Read the immutable case snapshot and individual statuses, verdicts, report IDs, and hashes. |
| `POST /api/testing/batches/<id>/cancel` | Record a request to stop future cases. The active request is allowed to finish. |

The batch `state.json` is atomically replaced after each stage and case. Selection order is preserved. Each case snapshot contains its exact asset and input SHA-256, target profile revision, policy reference, evaluation mode and budget. The raw input prompt is held in a trusted synthetic binding and is not returned by progress routes. A native Runner report and controlled-run summary are written separately for each executed case under the explicitly selected reporting root. Reporting API lookup validates the report hash and identities. Execution ERROR remains distinct from a target security FAIL; the reporting projection has no security verdict for an ERROR.

These synthetic bindings allow only response marker/regex rules. The native Runner's opt-in response evidence guard downgrades a response-based PASS to INCONCLUSIVE when the observed response is not explicitly complete. Deterministic FAIL remains unchanged. The default Runner behavior and one-click GH-C01 route are unchanged.

The batch coordinator uses an exclusive root claim and per-case grant claims. On process restart, a dead owner's in-progress batch becomes `interrupted`; completed case records remain available. It does not replay an interrupted request. Cancellation records the active case at request time and marks only unstarted cases cancelled. Progress is `processed / total`, with blocked and unsupported cases counted when recorded. Stage events come from the bounded HTTP client and native Runner boundaries. A Pi Judge stage is never emitted by this rule-only offline integration.

## Offline browser workflow (Phase B3)

When a trusted application explicitly injects `OfflineBatchWorkflow`, the health response exposes `offline_batch_enabled: true`. The existing target wizard then shows a clearly labeled synthetic batch selection. It previews the exact selection, submits the backend-issued plan with a single Run Selected Tests action, and opens `#batch/<batch_run_id>`. A refresh loads that ID from the backend; it does not submit the batch again. The frontend polls status, events, and results every 400 ms while running. Its percentage is the API's processed-case count divided by the selected-case count. A cancelled batch shows its terminal state and separately counts cases cancelled before execution. Report links appear only for rows with a backend-issued report ID and report hash.

Vite forwards only the exact batch preview/start paths and validated 32-character hexadecimal batch status/events/results/cancel paths. The existing same-origin POST check and local proxy operator credential forwarding apply. Browser JavaScript receives neither the operator credential nor a filesystem path. Batch GET routes require the backend validation nonce. The default application still has `offline_batch_enabled: false`; the frontend cannot enable the service.

The isolated browser acceptance uses `backend/tests/serve_batch_offline.py` with `httpx.MockTransport`, synthetic response-only bindings, finite case-scoped grants, temporary output directories, and a real Reporting API. From the repository's `frontend` directory, run:

```powershell
$env:SECAGENT_FRONTEND_PORT='5174'
$env:SECAGENT_WORKFLOW_PROXY_PORT='8093'
$env:SECAGENT_REPORTING_PROXY_PORT='8094'
$env:SECAGENT_LOCAL_PROXY_TOKEN='offline-browser-test-operator-secret-123456'
npm run test:browser -- offline-batch-real-api.spec.ts
```

The test starts and stops its isolated API processes, opens the real browser, executes a six-record synthetic batch, checks report navigation and refresh, and then cancels a three-record batch during its active mock request. These commands do not contact a research target or a Judge provider. Use unused ports; the test skips if its API ports are occupied.

## Remaining work

The reviewed GH-C01/GH-001/GH-002 text slice is documented separately. Other native cases remain non-executable until their target-specific bindings and evidence contracts are verified. Custom testcase editing and suite persistence are separate later work.

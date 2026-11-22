# Universal Evidence Source v1

Implemented as an additive local analysis facility. It does **not** add evidence to Runner, HybridEvaluator, Judge requests, VerdictResolver or native reports. Existing source profiles and reports need no migration. No historical verdict is recomputed.

## Operator setup

Create an operator-owned, non-secret policy file outside the repository. Every URL must be explicitly reviewed as a read-only GET endpoint. Example using a generic loopback fixture service:

```json
{
  "schema_version": "1.0.0",
  "allowed_endpoints": [
    {"url": "http://127.0.0.1:7800/events", "credential_ref": "lab-log"}
  ],
  "credential_env": {"lab-log": "LAB_LOG_TOKEN"}
}
```

Use `credential_ref: null` and an empty `credential_env` object for unauthenticated lab endpoints. Reference values are environment variable **names**, never secrets. Set credentials in the operator environment separately. v1 supports Bearer authentication only. The launcher forwards these named variables to Workflow API only, removing them from frontend/reporting child environments.

```powershell
python start_secagent_local.py --enable-custom-imported-batch --evidence-policy C:\OperatorData\evidence-policy.json
```

This command starts the application; it does not collect logs. Direct Workflow API startup also accepts `--evidence-policy`. No policy means deny all collection and source creation. Policy credentials and enabled collection are separate from Target/Judge configuration. Do not include side-effecting GET endpoints in the allowlist.

In Targets, expand **Evidence Sources**, add an HTTP JSON source, select its exact allowlisted URL, map fields, and save. Saving performs no network request. For each snapshot, check the authorization checkbox and select **Test Source**. This performs one GET and persists its bounded result. An error does not trigger retry. Edit can disable a source; no delete endpoint is provided. Changing target revision makes the old binding stale until explicitly saved again.

## Profile contract

`EvidenceSourceProfile` is a strict, closed schema:

- `schema_version: 1.0.0`, UUID hex `id`, SHA256 `revision` over canonical profile content excluding the revision itself.
- `name`, `target_id`, exact `target_revision`.
- `source_type: http_json`, explicit `endpoint`, optional `credential_ref` bound to that endpoint by server policy.
- `collection_mode: snapshot`, `enabled`.
- `mapping`: dotted object keys for `items`, `event_id`, `request_id`, `invocation_id`, `timestamp`, `tool`, `content`. Empty `items` requires a top-level array. No executable expressions, wildcards, recursive selectors or JSONPath evaluation.
- `semantics`: `detector_reported`, `declared_tool_call`, `tool_handler_invoked`, `simulated_execution`, `runtime_execution_verified`.
- `timeout_seconds` 1–10; response byte limit 256–262144 (default 65536); event limit 1–500 (default 200).

Semantics are **reported semantics**, never a trust upgrade. Selecting `runtime_execution_verified` does not independently verify runtime execution. Every normalized event remains `target_reported_unverified`, `uncorrelated`, `action_eligible: false`. `successful`, `EXPLOITED` and similar input fields cannot create a security verdict.

## Collection records

Profiles, immutable revision snapshots and capture records live in `evidence-sources-v1` under the existing operator target data directory. Atomic writes and confined, bounded regular-file reads reuse existing repository helpers. Profile and capture hashes are checked when read. Hashes detect corruption, not malicious changes by an operator with filesystem write access. One Workflow API writer per operator store is required; locking is process-local.

Each capture records source/target revisions, network policy hash, UTC collection time, collector provenance, `execution_scope: operator_source_snapshot`, request count, response byte count, availability, fixed collection error, mapped events, duplicate/conflicting-ID counts and a capture SHA256. It always records:

```json
{
  "correlation_status": "uncorrelated",
  "correlation_reason": "no_trusted_agent_run_binding",
  "complete_agent_trace": false,
  "action_eligible": false,
  "external_judge_disclosure": "forbidden"
}
```

Event/request/invocation IDs are stored as SHA256 aliases, explicitly labeled reported IDs. There is no matching by prompt, timestamp or log order. Duplicate complete records are collapsed within a snapshot; conflicting records sharing an event ID are counted and retained. Repeated snapshots remain separate captures, **not new execution events**. There is no cursor, delta stream, run-completeness proof or reliable absence inference.

Only configured scalar fields are retained. Nested mapped values reject the snapshot. Raw response bodies, headers and arbitrary JSON are never persisted or placed in UI/Judge instructions. Exact configured secrets, common credential patterns, URLs and email patterns are redacted. Text previews are capped at 1024 characters with explicit `*_truncated` flags. Whole responses/event arrays exceeding configured limits fail; they are not partially accepted. Redaction is not general DLP: keep mappings minimal and restrict access to operator storage. There is no external disclosure path in v1.

## HTTP and API boundaries

Only exact, startup-allowlisted literal loopback HTTP(S) endpoints are supported. DNS names, non-loopback networks, credentials/query/fragment in URLs, encoded paths and dot segments are rejected. This restriction avoids DNS rebinding. There is no port scan or endpoint derivation. Redirects, environment proxies, compressed responses and retries are disabled. HTTPX timeouts bound network operations, with an elapsed-time guard while reading the body. Non-200 status, malformed JSON, duplicate JSON keys, nonfinite values, schema and size violations persist fixed error codes without raw data. A response proves receipt by this collector only; it does not prove Agent context handoff or execution.

All API routes require existing loopback/origin/operator authentication; writes also require the current CSRF nonce. Collection additionally requires `authorization_confirmed: true` plus exact source revision. Active controlled execution blocks collection.

| Route | Purpose |
|---|---|
| GET `/api/testing/evidence-sources/target/{target_id}` | Local profiles/status plus non-secret endpoint grants; no Target request |
| POST `/api/testing/evidence-sources/save` | `{profile, source_id?, expected_revision?}`; save/update without collection |
| POST `/api/testing/evidence-sources/collect` | `{source_id, expected_revision, authorization_confirmed}`; one snapshot GET |
| GET `/api/testing/evidence-captures/{capture_id}` | Authenticated local redacted capture retrieval |

Health advertises `evidence_sources_enabled` and `evidence_collection_enabled`. Vite forwards authentication only on the explicit new routes. Frontend checks target/source revision and discards late results after selection/session changes. Available is a last-snapshot status, not a current health guarantee. The target page continues to show response-only evaluation and action verification not ready.

## Limits and next gate

No OTEL, MCP event stream, filesystem collector, cursor protocol, configurable trusted correlation, independent runtime verifier, action-level evaluation or automatic Judge disclosure is implemented. No evidence source is configured for the operator automatically.

To enable action verification later, first supply an independently trusted producer with run/testcase/request/invocation binding, a declared execution boundary, handler/effect receipts, authorization state and completeness semantics. Add a reviewed adapter into the existing evidence contract and tests before permitting action-level decisions. Do not promote these HTTP snapshots merely because their labels look authoritative.

At most 200 current profiles and 1000 captures are admitted per store. Quota exhaustion fails closed; no historical data is deleted automatically. Retention/multi-process coordination and richer redaction require a separately reviewed follow-up.

Offline fixtures under `backend/tests/fixtures/evidence` document the source-verified DVAA schemas. They are synthetic schema examples only and carry no security labels or runtime ground truth.

## Implementation files

- `backend/src/workflow/evidence_sources.py`: profile/network contracts, independent storage, collector and mapping.
- `backend/src/workflow/api.py`: authenticated source/capture routes, capability flags and CLI policy loading.
- `start_secagent_local.py`: optional policy forwarding and workflow-only credential environment.
- `frontend/src/EvidenceSources.tsx`: collapsed source list, form, explicit collection consent and scoped status.
- `frontend/src/TargetManager.tsx`, `frontend/src/TargetConfiguration.tsx`: reuse existing operator access and selected target; retain disabled fallback for older backends.
- `frontend/src/testingApi.ts`, `frontend/vite.config.ts`: API contract checks, route allowlist and operator proxy forwarding.
- `frontend/src/styles.css`: compact source cards and advanced form styling.
- `backend/tests/test_evidence_sources.py`, `backend/tests/fixtures/evidence/{README.md,dvaa-attack-log.json,dvaa-cmd-log.json,dvaa-files.json}`: offline regression and sanitized external-schema fixtures.
- `frontend/src/EvidenceSources.test.tsx`, `frontend/browser-tests/evidence-sources.spec.ts`: UI/API boundary tests and mocked desktop/laptop checks.
- This document: schema, operation, boundaries and limitations.

No changes were made by this task to HybridEvaluator, VerdictResolver, Judge Skills, ASI policies, dataset normalization, native testcases or historical reports. Pre-existing working-tree edits in those areas were preserved.

The 30 ASI03 native reports referenced by batch `08f8a0c76c394527bec964f8aed5b9db` retain the same sorted path/file-hash aggregate before and after this task:

`41a393e88a3e0052c59ca10c8b162de86e81f4abec2cf050d13476e7c4ce97d3`

## Offline verification

- Test-first: new backend tests failed on the absent `workflow.evidence_sources` module; new UI tests failed on the absent `EvidenceSources` component before implementation.
- Final Evidence Source backend suite: **43 PASS**, including persistence, source/target revision, auth/CSRF, SSRF, schema/depth/size bounds, timeout, redaction, duplicate records, immutable report isolation and launcher credential forwarding.
- Dataset/imported/native ASI01/ASI03 contracts, evidence Phase 1A/1B, Hybrid/Judge connector and reporting regression group: **369 PASS**.
- Target Management/Discovery plus the earlier source suite: **71 PASS**.
- Runner/Judge integration, response evaluator/observer, official ASI01 runner plus the updated source suite: **155 PASS**. These groups overlap; their counts are not a unique-test total.
- Final frontend suite: **162 PASS** (`npm exec --no -- vitest run --maxWorkers=2`); TypeScript/Vite build PASS. A preceding high-concurrency run had one `BatchProgress` wait timeout; the unchanged test passed in the final full suite. No batch implementation or test was modified.
- Browser tests: **2 PASS** for evidence source workflows at 1440 and 1366 widths; **3 PASS** for existing target layout at 1440/1366/390. All API calls are intercepted; no Target/Judge is contacted. The initial new keyboard test focused a nested span instead of its focusable summary; the test was corrected and passed.
- Screenshots: `frontend/artifacts/evidence-sources-final/` contains desktop/laptop captures inspected after rendering.

There were no live Target/Judge calls and no changes to operator datasets, live source configuration or credentials. No commit or push was performed.

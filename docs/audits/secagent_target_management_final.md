# SecAgent Target Management — final UX and integrity review

Date: 2026-11-21. Scope: target catalog and Targets UI only. No production target, historical report, policy, Judge, or testcase was modified during this work.

## Root cause and identity rules

The persisted catalog stores `platform_id` and `platform_name` on each target profile. These fields describe platform association; `id` is the target identity, while `protocol`, `endpoint`, and adapter describe transport. Discovery has historically suggested `local-agent`, a manually created HTTP profile used `local-http`, and configured DVAA seeds use `dvaa`. Thus the current catalog contains CodeBot/ToolBot records spread across those groups even when their display names mention DVAA. A port or name is not sufficient proof of platform identity. See `backend/src/workflow/discovery.py`, `backend/src/workflow/management.py:305-360`, and `frontend/src/TargetManager.tsx:75-82`.

The observed operator catalog contains a legacy `local-agent-7004` CodeBot at `local-http`, `local-agent-7010` ToolBot at `local-agent`, and DVAA seeded profiles at `dvaa`; it also contains a distinct `dvaa-codebot` ID at the CodeBot endpoint. This implementation **did not silently merge, rename, or regroup any of them**. The operator can now edit platform association and confirm that declaration, allowing HTTP and MCP targets to share one platform while preserving separate IDs and transports.

## Implemented behavior

| Area | Result |
| --- | --- |
| Target list | Active targets are grouped by platform without a prerequisite platform dropdown. Rows show name, endpoint, protocol, connection and review status, with search by name/platform/endpoint and direct selection. `frontend/src/TargetManager.tsx:172-182` |
| Rename and platform edit | Edit updates an existing ID. Name-only or platform-only edits preserve the profile revision and review binding when connection-relevant fields remain identical. Platform reassignment requires an explicit confirmation and records `operator_declared` provenance. Connection edits retain the existing revision/review invalidation path. `backend/src/workflow/management.py:324-360`; `frontend/src/TargetManager.tsx:70-87,190-211` |
| Discovery duplicate | Matching endpoint and protocol shows Use Existing or Rename Existing; creation is disabled. Backend also rejects a newly created duplicate endpoint/protocol, while allowing metadata edits to pre-existing legacy duplicates. `frontend/src/TargetManager.tsx:75-76,203-204`; `backend/src/workflow/management.py:305-319` |
| Archive | Each row and bulk selection open a dialog listing exact names and endpoints. The operator confirms before an authenticated, nonce-bound, revision-checked API call. All selected revisions are checked before the single atomic catalog replacement. `frontend/src/TargetManager.tsx:89-103,174-184`; `backend/src/workflow/api.py:484-519`; `backend/src/workflow/management.py:248-277` |
| Historical preservation | Archive keeps original profile, target ID, review record, policy binding and report files; it removes only active availability in `TargetCatalog`, preventing new selection/runs. Restore checks archived revision and active endpoint collision. No permanent delete or Delete All was added. `backend/src/workflow/management.py:173-207,248-277` |
| Provenance | New profiles record `discovery_suggested` or `operator_declared`; seeded profiles record `seed_configured`; older stored records display `legacy_unknown`. `backend/src/workflow/management.py:96-117,160-170,213-237,352-360` |
| Local proxy | Archive/list/restore routes are explicitly allowed and use the existing operator header injection boundary. `frontend/vite.config.ts:26-28,61` |

Connected reflects a compatible bound probe, Reviewed reflects operator approval, and neither grants security execution permission. Discovery does not review targets. Generic core contains no DVAA-specific grouping rule.

## Verification

- Backend: `test_target_management.py` and `test_target_discovery.py`: **54 passed**. Includes same confirmed platform across HTTP/MCP, metadata-only revision preservation, archive selection atomicity, restart persistence, historical report preservation, restore, and duplicate protection.
- Frontend: `TargetManager.test.tsx`, `TargetConfiguration.test.tsx`, `DiscoveryPanel.test.tsx`: **36 passed**. Includes list/filter/bulk confirmation, rename, platform confirmation, and connection preservation.
- `npm run build`: TypeScript and Vite build passed.
- Playwright `target-management-local-real-api.spec.ts`: **1 passed** against a real isolated Workflow API and local proxy with mocked target transport. It created, reviewed, probed, and archived one disposable target; verified archived persistence and no horizontal document overflow at 390px. Initial startup proxy connection errors occurred before the isolated API listened; the eventual test passed.
- Visual inspection of [desktop screenshot](../../frontend/artifacts/target-management-final/targets-1440.png) and [mobile screenshot](../../frontend/artifacts/target-management-final/targets-390.png): target row, confirmation controls, status labels and cards remain legible. Both screenshots use a disposable test catalog, not the operator catalog.

## Remaining limits

No permanent removal API or Archive All was added. Archived targets can be restored; the API rejects restore when an active target already uses the endpoint/protocol. Existing CodeBot duplicate IDs remain separate for historical reproducibility. Operator review of actual platform ownership is still required before assigning the legacy CodeBot and ToolBot records to DVAA. No real DVAA connection or security run was made in this task.

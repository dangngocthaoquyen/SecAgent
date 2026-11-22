# SecAgent — Target naming, Application Context and Policy UX

Date: 20 November 2026. Scope: local Target and imported Dataset UI. No security testcase, DVAA tool action, Pi Judge or batch run was executed for this change.

## Implemented

| Area | Result | Source |
| --- | --- | --- |
| Optional agent name | The Connect form accepts a name before discovery. Blank uses the backend's validated proposed name. The name is carried through discovery, benign probe and save; the immutable target ID remains separate. | `frontend/src/DiscoveryPanel.tsx:4-24`, `frontend/src/TargetManager.tsx:87-112` |
| Existing target | An exact endpoint, protocol and model match suggests the saved target and blocks duplicate save. | `frontend/src/TargetManager.tsx:65-77,149-165` |
| Name-only edit | A saved display-name-only update retains the existing profile revision, target review and connection binding. The original name is persisted as the revision basis for backward-compatible state loading. Endpoint, protocol, model and other profile edits continue to invalidate review and probe state. | `backend/src/workflow/management.py:66-101,135-165,226-266`; `frontend/src/TargetManager.tsx:55-65,98-111` |
| Application Context | Closed, size-limited operator-declared schema with a SHA-256 revision and exact target-profile binding. Stored separately under the configured operator data directory, with atomic replacement, optimistic revision checks, target identity validation and a check for obvious credential assignments. Read and save require existing management authentication; save also requires the validation nonce. | `backend/src/workflow/application_context.py:15-117`, `backend/src/workflow/api.py:22,111,235,257,473-499` |
| Context UI | Four initial fields; tools, data and security boundaries are collapsed. Status distinguishes missing, unsaved, saved and stale context. Advertised capabilities are explicitly marked as observed/advertised. The save confirmation asks the operator to exclude real secrets. | `frontend/src/ApplicationContext.tsx:4-48`, `frontend/src/TargetManager.tsx:195`, `frontend/src/styles.css:1259-1274` |
| Dataset evaluation setup | Target, ASI, scope, transport and evaluation mode are selected before case inspection. ASI03 opens the existing identity-response policy; ASI05 response scope opens its existing command-artifact policy. The legacy per-case ASI03 contract requires explicit expansion. Promptfoo plugin/assertion labels remain untrusted source taxonomy. | `frontend/src/DatasetLibrary.tsx:20-27,120-125,216-309` |
| Unsupported scopes | Imported ASI01 and ASI02, ASI05 execution/action and MCP targets for natural-language chat imports show a concrete unavailable/incompatible reason and do not mount `BatchLaunch`. Target, dataset, ASI, scope, transport and mode changes replace the preview component and reset case-review state. | `frontend/src/DatasetLibrary.tsx:123-125,222-246,300-316` |

The context API is allowlisted in both the Flask boundary and the local Vite proxy; the proxy attaches the configured operator credential to its exact read/write routes (`backend/src/workflow/api.py:235,257`; `frontend/vite.config.ts:25,36,58,82`). `testingApi` validates the separate operator metadata response (`frontend/src/testingApi.ts:19-20,151-152`). No Application Context field was added to `EvaluationRequestBuilder`, `Runner`, `HybridEvaluator`, Policy, Skill, VerdictResolver or Native Report. Existing Target names flow through the Target selector, Dataset target selection and `Runner` report metadata (`backend/src/testing/runner.py:196`, `backend/src/reporting/normalizers.py:107`).

## Effective policy forms and limits

| ASI / scope | Current UI action | Official evaluation status |
| --- | --- | --- |
| ASI03 `identity_claim_response` | Existing target identity policy editor and Hybrid workflow | Requires reviewed target policy and backend admission. Identity claim is not privileged action evidence. |
| ASI05 `response_command_artifact` | Existing target response policy editor and Hybrid workflow | Requires reviewed response policy. No runtime execution claim. |
| ASI01 goal hijacking | Directs operator to controlled ASI01 workflow | Imported Dataset editor has no legitimate baseline binding; unavailable here. |
| ASI02 tool action | Explains missing tool/action evidence | No official imported-chat action evaluation here. |
| ASI05 `execution_action` | Explains missing execution binding and correlated trace | No official imported-chat execution evaluation here. |
| Legacy imported rule-only | Existing rule-only path; optional explicit legacy ASI03 case contract | Source labels alone never review a policy. |

Application Context is descriptive metadata. It has no review status and no automatic Judge disclosure. The validator rejects common key/value credential patterns, but cannot prove that arbitrary prose contains no secret; operator confirmation and safe descriptions remain necessary. Discovery metadata is not proof that an advertised tool was authorized or executed.

## Verification

- Backend focused regression: **60 passed** (`test_application_context`, `test_target_management`, `test_target_discovery`, `test_generic_imported_batch`). This includes name-only binding preservation, context restart/edit/stale handling, authentication, and refusal of obvious credential values.
- Frontend focused regression: **39 passed** (`DiscoveryPanel`, `TargetManager`, `DatasetLibrary`, `TargetConfiguration`). The Shell-Injection source case displays ASI05 response policy only after explicit ASI05 selection; ASI05 execution hides that editor and blocks launch.
- TypeScript and Vite production build: **passed**.
- Playwright: **5 passed**. Three isolated real-API browser tests cover discovery, safe mock probe, save, target review, context persistence and duplicate selection. The ToolBot `7010` flow preserves the operator name `DVAA ToolBot`; the blank-name flow retains a valid proposed name. Two mocked Dataset browser tests cover ASI05 policy isolation and execution-scope blocking. All target interactions were benign or mocked; no security payload was sent.
- Screenshots captured and visually inspected at **1440 px** and **390 px**, with no document-level horizontal overflow: `frontend/artifacts/application-context-policy-ux/target-context-1440.png`, `target-context-390.png`, `dataset-asi05-1440.png`, `dataset-asi05-390.png`. Dataset tables scroll within their own panel on mobile and display an explicit scroll hint.

## Existing contracts and operational notes

The existing reviewed ASI03/ASI05 response policy APIs, Target authorization, connection checks and Batch admission remain authoritative. The UI never marks a target or policy reviewed merely because discovery, connectivity or Application Context succeeded. Name-only profile updates preserve review only when every other managed profile field is identical; the backend test confirms a later endpoint edit makes the profile revision stale.

The running Workflow API process must be restarted to load the new Application Context routes and name-only revision handling. This work did not restart a pre-existing operator service. The isolated Playwright server loaded the changed source and verified the complete save/reopen/edit flow.

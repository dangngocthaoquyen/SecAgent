# SecAgent — Codex Handoff Audit & Unified Runtime Recovery

- **Ngày audit:** 2026-11-21
- **Repository:** `D:\SecAgent-W5-Judge`
- **Commit nền:** `ce1c776` (`chore: checkpoint SecAgent source before DVAA smoke`)
- **Phạm vi:** Read-only audit toàn bộ working tree hiện tại (59 file tracked đang sửa, 171 mục untracked gồm file/thư mục mới), không sửa code, không sửa historical reports, không gọi live target/MCP/Pi Judge.
- **Quy ước trạng thái:** `VERIFIED` · `IMPLEMENTED_NOT_VERIFIED` · `PARTIAL` · `BLOCKED` · `NOT_IMPLEMENTED`

---

## 1. Executive Summary

Codex đã triển khai được phần lõi của **Unified Runtime** (`asi01` + `imported` + `mcp_actions` cùng tồn tại trong `backend/src/workflow/api.py`), launcher mặc định `start_secagent_local.py` (đọc `runtime.json` ngoài repo, degraded về `rule_only` khi thiếu credential), giao diện chuyển Target / ASI / Scope trong `DatasetLibrary.tsx`, và hệ thống persistent history (`SavedRuns.tsx`, `/api/reports/saved-runs`, `/api/reports/mcp-runs/<id>`, sidecar SHA-256 `run-summary.json`).

Tuy nhiên, repository **chưa đạt điều kiện final acceptance** do còn các lỗi nghiêm trọng và drift hồi quy:

1. **Bug đang sửa dở ở `backend/src/reporting/api.py` (`date_from`/`date_to`)** — `PARTIAL`: Regex kiểm tra `date_from`/`date_to` bị đặt nhầm vào `execution_list()` (`/api/reports/executions`, vốn bị `boundary()` chặn `date_from`/`date_to`), trong khi `saved_runs()` (`/api/reports/saved-runs`) lọc chuỗi `row['started_at'][:10]` mà **không validate** `date_from`/`date_to`. Frontend `SavedRuns.tsx` và `frontend/src/api.ts` cũng chưa có UI/filter `date_from`/`date_to`, và `parseSavedRuns()` crash nếu `mcp_action` trả về `verdict: "ERROR"`.
2. **Lỗi nghiêm trọng ở Vite proxy cho MCP Tool-Action (`frontend/vite.config.ts`)** — `PARTIAL`: `vite.config.ts` **chưa cho phép** `/api/testing/mcp-actions` (GET) và `/api/testing/mcp-actions/run` (POST) trong `workflowAllowed` và cũng **chưa gắn** header `X-SecAgent-Operator` trong `privileged`. Chạy qua `start_secagent_local.py` (port `5173`) sẽ bị Vite chặn `405` trước khi tới `workflow.api`.
3. **Sai nhãn UI ở `BatchProgress.tsx` trong Unified Runtime** — `PARTIAL`: `BatchProgress.tsx:72` ưu tiên nhánh `customImported` (lấy từ `/api/testing/health`) trước `asi01`, nên một batch `asi01` thực tế lại hiển thị tiêu đề `"OFFLINE MOCK IMPORTED DATASET ASSESSMENT"`.
4. **Hồi quy toàn repo chưa đạt 100% PASS** — `PARTIAL`:
   - `py_compile` 126 file Python: **PASS**.
   - `npm run build` (`tsc -b && vite build`): **PASS**.
   - `pytest backend/tests -q`: **1576 PASS, 3 FAIL** (`test_b47_remediation.py:326`, `test_official_asi01_runner.py:271`, `test_toolbot_lab_batch.py:157`).
   - `vitest run`: **168 PASS, 9 FAIL** (16/19 file pass; `App.test.tsx` 3 fail, `TargetExperience.test.tsx` 5 fail, `BatchProgress.test.tsx` 1 fail do timeout 1000ms khi chạy song song — pass 5/5 khi chạy đơn lẻ).
   - Playwright mocked browser tests: **7 PASS, 1 SKIPPED, 10 FAIL** (drift theo UX mới `Connect new target` / `<SavedRuns />` / `Advanced Settings` thu gọn / `PlanWizard` gọi `/categories`, cộng 1 lỗi Edge headless context crash ở `report-downloads.spec.ts:33`).
5. **Chưa chứng minh live Shared Pi Judge và chưa có action-scope Pi skill / DVAA receipt correlation hoàn chỉnh** — `BLOCKED` / `IMPLEMENTED_NOT_VERIFIED`: Thiếu Judge API key và live target/container trong phiên audit.

---

## 2. Những gì Codex thực sự hoàn thành

| Hạng mục | Trạng thái | Bằng chứng & File path |
| --- | --- | --- |
| Unified batch registry (`asi01` + `imported` + `mcp_actions`) | `VERIFIED` | `backend/src/workflow/api.py:92-106`, `812-828`, `1384-1392`; `backend/tests/test_generic_imported_batch.py:100-118` pass trong full pytest. |
| Default Unified Runtime launcher + `runtime.json` ngoài repo | `IMPLEMENTED_NOT_VERIFIED` | `start_secagent_local.py:58-78`, `135-270`. Chỉ `test_evidence_sources.py:281-308` test phần `--evidence-policy`; chưa có unit test cho `runtime_settings()` và `credential_missing` degraded path. |
| Per-run authorization & fail-closed admission khi chuyển workflow | `VERIFIED` | `backend/src/workflow/api.py:812-820`, `868-877` (chặn chạy 2 workflow song song bằng `another_workflow_active`), `backend/src/workflow/asi01_batch.py:254-282`, `backend/src/workflow/generic_imported_batch.py:402-511`, `backend/src/workflow/mcp_actions.py:124-165`. |
| Truyền `workflow_id` từ Frontend (`BatchLaunch`, `DatasetLibrary`, `PlanWizard`) | `VERIFIED` | `frontend/src/BatchLaunch.tsx:5,13,23`; `frontend/src/DatasetLibrary.tsx:325`; `frontend/src/PlanWizard.tsx:58`. |
| Chuyển Target / ASI / Evaluation Scope trong một phiên trên Dataset Library | `VERIFIED` | `frontend/src/DatasetLibrary.tsx:148-152,232-262,317-331`; `frontend/src/Asi03TargetPolicy.tsx`; `frontend/src/Asi05Policy.tsx`; xác nhận bởi `frontend/browser-tests/unified-runtime-local.spec.ts` (được Codex chạy trước khi bàn giao). |
| Persistent Saved Reports API + sidecar SHA-256 + MCP native report detail/download | `VERIFIED` | `backend/src/reporting/repository.py:63-247`; `backend/src/reporting/api.py:43-60,196-286,308-320`; `frontend/src/SavedRuns.tsx`; `frontend/src/McpRunDetail.tsx`. Trên workspace hiện tại `list_saved_runs()` đọc đúng **554** controlled reports hợp lệ, `0` invalid (`results/local-controlled-runs`). |
| Mở rộng `SavedRuns` persistence qua `history-index.json` | `VERIFIED` | `backend/src/reporting/api.py:43-60,225-245`; kiểm chứng trong `backend/tests/test_reporting_api.py:161-178`. |
| Shared Hybrid Judge preflight, credential-echo guard và skill routing | `VERIFIED` | `backend/src/testing/evaluation_config.py:39-98`; `backend/src/evaluators/evaluation_request_builder.py:32-108`; `backend/tests/test_unified_judge_configuration.py` pass trong pytest. |
| Kiểm tra toàn vẹn cú pháp Python & TypeScript build | `VERIFIED` | `git diff --check` exit 0; `py_compile` 126 file `.py` PASS; `npm run build` (`tsc -b && vite build`) PASS. |

---

## 3. Những gì đang dở dang

| Hạng mục | Trạng thái | Chi tiết & Bằng chứng |
| --- | --- | --- |
| Bộ lọc `date_from` / `date_to` cho `saved-runs` | `PARTIAL` | `backend/src/reporting/api.py:128-131` cho phép `date_from`/`date_to` ở `/api/reports/saved-runs`, lọc ở dòng `251-254`, nhưng đoạn validate regex nằm nhầm ở `execution_list()` (`api.py:177-179`). `SavedRuns.tsx` và `frontend/src/api.ts:66-77` chưa có field `date_from`/`date_to`. |
| Lọc `asi_category=unknown` và `verdict=ERROR` trên `saved-runs` | `PARTIAL` | `results/local-controlled-runs` có **181** run `asi_category: None`, nhưng `reporting/api.py:213` không nhận `asi_category=unknown`. Ngược lại, `reporting/api.py:213` nhận `verdict=ERROR` (khớp `mcp_action`), nhưng `frontend/src/api.ts:85` (`parseSavedRuns`) từ chối `'ERROR'` và `SavedRuns.tsx:17` không có option `ERROR`. |
| Giao diện MCP Tool-Action chạy qua Vite proxy (`start_secagent_local.py`) | `PARTIAL` | `McpActionPanel.tsx` gọi `/api/testing/mcp-actions` và `/api/testing/mcp-actions/run`, nhưng `frontend/vite.config.ts:17-28,61,85` thiếu 2 route này nên bị chặn `405` và không được gắn `X-SecAgent-Operator`. |
| Đồng bộ nhãn `BatchProgress.tsx` cho Unified Runtime | `PARTIAL` | `frontend/src/BatchProgress.tsx:72` ưu tiên `customImported` (từ `/health`) nên batch `asi01` hiển thị sai thành `OFFLINE MOCK IMPORTED DATASET ASSESSMENT`. |
| Đồng bộ test suite sau khi đổi UI/policy | `PARTIAL` | 3 test backend fail (`test_b47_remediation.py`, `test_official_asi01_runner.py`, `test_toolbot_lab_batch.py`), 9 test Vitest fail (`App.test.tsx`, `TargetExperience.test.tsx`, `BatchProgress.test.tsx` timeout), 10 test Playwright mocked fail. |
| Index các MCP report cũ ngoài `results/local-controlled-runs` | `NOT_IMPLEMENTED` | Hiện có 6 `native_report.json` cũ nằm ngoài `controlled_runs_root`: `results/live-action-evidence/` (3), `results/live-asi05-execution-pilot/` (2), `results/live-toolbot-mcp-hybrid-acceptance/` (1). |

---

## 4. Lỗi phát hiện được

### Lỗi P0 (Chặn chức năng / An toàn dữ liệu / Sai lệch hiển thị)

1. **`backend/src/reporting/api.py:177-179` vs `:210-257` — Validation `date_from`/`date_to` đặt nhầm endpoint**
   - `execution_list()` (`/api/reports/executions`) chứa đoạn check regex `date_from`/`date_to` (dòng `177-179`) dù `boundary()` (dòng `128-131`) chỉ cho phép `date_from`/`date_to` ở `/api/reports/saved-runs`.
   - `saved_runs()` (dòng `251-254`) so sánh chuỗi `row['started_at'][:10] >= args['date_from']` mà **không kiểm tra** định dạng `YYYY-MM-DD`, ngày hợp lệ theo lịch, hay `date_from <= date_to`. Truy vấn sai định dạng (vd `?date_from=invalid`) vẫn trả `200` với kết quả lọc sai thay vì `400 invalid_filter`.
2. **`frontend/vite.config.ts:17-28,61,85` — Chặn MCP Actions ở Vite Proxy**
   - `workflowAllowed` thiếu `GET /api/testing/mcp-actions` và `POST /api/testing/mcp-actions/run`.
   - `privileged` thiếu cả hai route trên nên không gắn `X-SecAgent-Operator` trong `local_single_user` mode.
   - Hệ quả: Tab `MCP tool-action assessment` trong `DatasetLibrary.tsx` không hoạt động được khi khởi chạy qua `start_secagent_local.py`.
3. **`frontend/src/api.ts:85` vs `backend/src/reporting/repository.py:226` — Crash hợp đồng `verdict: "ERROR"` ở Saved Native Reports**
   - `load_mcp_run` / `list_saved_runs` (`repository.py:193,226`) phát sinh `verdict: "ERROR"` cho MCP action bị error.
   - `parseSavedRuns()` (`frontend/src/api.ts:85`) chỉ cho phép `['PASS','FAIL','INCONCLUSIVE',null]`, làm toàn bộ bảng `Saved Native Reports` throw `Error('contract')` nếu có bất kỳ MCP run `ERROR` nào trong thư mục `controlled_runs_root`.

### Lỗi P1 (Sai hiển thị / Test drift / Không đồng nhất)

4. **`frontend/src/BatchProgress.tsx:72` — Sai tiêu đề Assessment trong Unified Runtime**
   - Khi cả `asi01` và `imported` cùng bật (`customImported === true && asi01BatchEnabled === true`), kiểm tra `customImported ? ...` chạy trước, làm batch `asi01` hiển thị `OFFLINE MOCK IMPORTED DATASET ASSESSMENT` thay vì `CONTROLLED ASI01 ASSESSMENT`. Cần phân nhánh theo `results?.snapshot.imported_provenance` (nếu có) trước khi fallback cờ `/health`.
5. **`backend/src/workflow/management.py:344-351` vs `backend/tests/test_toolbot_lab_batch.py:153-157` — Xung đột contract đổi tên target**
   - `ManagedTargetCatalog.save_profile()` giữ nguyên `profile_revision` và `reviews` khi chỉ đổi `name`/`platform_id`/`platform_name` (`metadata_only`), khiến `test_toolbot_lab_batch.py:157` kỳ vọng `409` khi đổi `name` nhưng nhận `200`. Cần xác nhận rõ policy có cho phép giữ `review` khi đổi `name` hay không rồi đồng bộ test hoặc rule.
6. **`backend/src/evaluators/evaluation_request_builder.py:104-107` vs `backend/tests/test_official_asi01_runner.py:271`**
   - Guard mới chặn echo `credential_env` trước khi gọi Judge trên mọi ASI khiến `test_official_asi01_runner.py:271` (test cũ kỳ vọng secret được gửi tới `FakeJudge` rồi mới redact) bị `IndexError`. Guard mới đúng về bảo mật; test cũ cần được cập nhật theo contract mới.
7. **`backend/src/workflow/generic_imported_batch.py:282-283` vs `backend/tests/test_b47_remediation.py:325-326`**
   - `generic_imported_batch.py` yêu cầu `total_request_budget == len(testcase_ids)` (`imported_request_budget_invalid`), khiến `test_b47_remediation.py:326` (gửi 30 case với budget 1) bị `409`. Cần làm rõ hoặc cập nhật test `test_b47_remediation.py`.
8. **9 Vitest unit test FAIL và 10 Playwright mocked test FAIL**
   - `App.test.tsx` (3 fail): `Executions` nhúng `<SavedRuns />` nên có 2 nút `Reset` và gọi thêm `fetch('/api/reports/saved-runs')`, làm mock `fetch` 1-lần trong test cũ bị tiêu thụ sai / lỗi `"Response body already used"`.
   - `TargetExperience.test.tsx` (5 fail): `TargetConfiguration.tsx:11` mặc định mở `discoveryFlowActive = true` khi không có `initialTargetId`, và label target bên `DatasetLibrary.tsx:236` đổi thành `Target` (thay vì `Reviewed Target Profile`).
   - `BatchProgress.test.tsx` (1 fail không ổn định): `findByRole` vượt ngưỡng 1000ms khi chạy song song (1268ms -> fail; chạy đơn lẻ 898ms -> pass).
   - Playwright mocked specs: `targets.spec.ts` (3 fail do `Validate Configuration` bị thu gọn trong `<details>Advanced Settings` và `getByLabel('Target')` khớp 3 option vì container `aria-label`), `target-configuration-redesign.spec.ts` (3 fail strict mode `getByText('Not checked')` khớp cả list row mới), `target-management.spec.ts` (1 fail do mặc định ở tab `Connect new target`), `evidence-sources.spec.ts` (2 fail vì `<PlanWizard>` gọi `/api/testing/categories`), `report-downloads.spec.ts:33` (Edge headless context crash `ITaskbarList3`).

---

## 5. Các thay đổi chưa được kiểm thử

| Thay đổi / Thành phần | Trạng thái | Khoảng trống kiểm thử |
| --- | --- | --- |
| `start_secagent_local.py` (toàn bộ `runtime_settings()`, fallback `credential_missing`, ghép cờ `--enable-unified-runtime` + `--judge-config` + `--mcp-action-catalog`) | `IMPLEMENTED_NOT_VERIFIED` | Chỉ có 1 test mock `--evidence-policy` (`test_evidence_sources.py:281`). Chưa có automated test cho `runtime.json` parsing/bounds, `credential_missing`, hoặc launch end-to-end Unified Runtime. |
| `date_from` / `date_to` trên `/api/reports/saved-runs` và UI `SavedRuns.tsx` | `PARTIAL` | Không có test nào trong `backend/tests/test_reporting_api.py` hay `frontend/src/` kiểm thử `date_from`/`date_to`! |
| Luồng browser E2E qua Vite proxy tới `/api/testing/mcp-actions` | `BLOCKED` | `McpActionPanel.test.tsx` mock `testingApi`, `test_structured_mcp_actions.py` dùng Flask `test_client()` trực tiếp; chưa từng chạy qua Vite proxy (`vite.config.ts`), nơi đang bị chặn 405. |
| Live Shared Pi Judge qua Unified Runtime (`asi01` / `ASI03` / `ASI05`) | `BLOCKED` | Thiếu Judge credential trong môi trường hiện tại; `pilot` ASI01 live trước bàn giao chỉ mới chạy `INCONCLUSIVE` / chưa chứng minh live Pi call qua UI/Unified Runtime. |
| `SavedRuns.tsx` render & tương tác trên Vitest / Playwright offline | `IMPLEMENTED_NOT_VERIFIED` | Chưa có unit test riêng cho `SavedRuns.tsx` và `McpRunDetail.tsx` (ngoài Playwright real-api `unified-runtime-local.spec.ts` chỉ kiểm tra heading và text `saved reports`). |
| `dvaa_action_evidence.py` + `dvaa_mcp_execution_observer.py` với DVAA instrumented lab port `7110` thực tế | `IMPLEMENTED_NOT_VERIFIED` | Đã có unit test offline (`test_asi05_dvaa_live_mcp.py`), nhưng container instrumented lab `7110` chưa chạy thực tế trong phiên acceptance trước (`secagent_toolbot_mcp_hybrid_acceptance.md:57`). |

---

## 6. Trạng thái Unified Runtime

| Thành phần | Trạng thái | Chi tiết |
| --- | --- | --- |
| Backend multi-workflow registry (`workflow/api.py`) | `VERIFIED` | Đăng ký đồng thời `asi01` (`Asi01BatchWorkflow`) và `imported` (`GenericImportedBatchWorkflow(execution_mode='both')`), cộng `mcp_action_service` tùy chọn (`mcp_actions`). |
| `workflow_id` routing & legacy compatibility | `VERIFIED` | `selected_batch_service()` (`api.py:812-820`) bắt buộc `workflow_id` khi có `>1` service (trả `400 workflow_selection_required`), giữ fallback mặc định khi `len(services) == 1`. |
| Mutual exclusion & per-run authorization | `VERIFIED` | `batch_start()` (`api.py:874-876`) chặn 2 workflow chạy đồng thời (`409 another_workflow_active`); `dispatcher._active` và `.active-batch` khóa run; mỗi case tạo grant dùng-1-lần (`grant-<id>`) và re-verify target/dataset/policy trong `before_request()`. Không thể chuyển workflow để bypass admission. |
| Startup mặc định (`start_secagent_local.py`) | `IMPLEMENTED_NOT_VERIFIED` | Mặc định `unified = not legacy_batch` (`start_secagent_local.py:143`), đọc `runtime.json` ngoài repo (`58-78`), không mở network ngoài loopback, giữ nguyên chế độ legacy `--enable-*-batch` khi chỉ định. |
| Frontend Unified UX (`TargetConfiguration`, `DatasetLibrary`, `BatchLaunch`, `PlanWizard`) | `PARTIAL` | Chuyển đổi Target/ASI/Scope trên `DatasetLibrary.tsx` hoạt động, truyền đúng `workflow_id`; `TargetConfiguration.tsx:77` hiển thị cả `Select Dataset` và `Native ASI01 cases`. Còn lỗi tiêu đề ở `BatchProgress.tsx:72`, dataset list chưa tự lọc theo tương thích target/ASI, và `MCP tool-action` bị chặn ở `vite.config.ts`. |

---

## 7. Trạng thái HTTP / MCP adapters

| Adapter / Route | Trạng thái | Chi tiết & Bằng chứng |
| --- | --- | --- |
| `HttpTargetAdapter` (`backend/src/targets/adapters/http_adapter.py`) + `OneRequestHttpClient` (`workflow/dispatch.py`) | `VERIFIED` | Ép 1 request/case, literal loopback hoặc reviewed endpoint, không follow redirect, giới hạn 64 KiB, phân biệt `response_complete` (chỉ `True` khi `response_only_completion=True`, `body_complete=True`, `finish_reason=="stop"`), tách `reported_http_evidence` (`http_evidence.py`) thành `target_reported / execution_verified=False`. |
| `McpJsonRpcTargetAdapter` (`backend/src/targets/adapters/mcp_jsonrpc_adapter.py`) | `VERIFIED` | Xây JSON-RPC 2.0 `tools/call` theo input có cấu trúc, kiểm tra đối khớp `jsonrpc=="2.0"` và `id == request_id`, phát sinh `tool_request` (`secagent_request`) và `target_tool_result` (`target_reported`, `execution_verified=False`). Không chuyển đổi natural-language chat prompt sang `tools/call`. |
| `DvaaActionObserverFactory` / `DvaaMcpExecutionObserver` (`dvaa_action_evidence.py`, `dvaa_mcp_execution_observer.py`) | `PARTIAL` | Hoạt động offline và với ToolBot 7010 (`tool_invocation`, `partial` trace); path `7110` instrumented receipt đã viết code + test offline (`test_asi05_dvaa_live_mcp.py`), nhưng chưa có live acceptance với container instrumented và receipt chỉ là `instrumented_target_handler` (không phải independent sandbox effect). |
| Vite Proxy cho MCP workflow (`frontend/vite.config.ts`) | `BLOCKED` | Thiếu `/api/testing/mcp-actions` và `/api/testing/mcp-actions/run` trong `workflowAllowed` và `privileged`, chặn hoàn toàn qua cổng 5173. |

---

## 8. Trạng thái ASI01 / ASI02 / ASI03 / ASI05

| ASI | Evaluation Scope & Cơ chế | Trạng thái | Giới hạn & Bằng chứng |
| --- | --- | --- | --- |
| **ASI01** (Goal Hijacking) | 1) Text batch (`GH-C01`, `GH-001`, `GH-002`) trên DVAA SecureBot/ResearchBot (`Asi01BatchWorkflow`) và imported prompt byte-identical (`GenericImportedBatchWorkflow`).<br>2) Web Lab (`GH-WEB-001`) qua `DockerWebLabRuntime` / `LocalMockFixtureRuntime`. | `PARTIAL` | Text rule-only & offline Hybrid PASS trong test (`test_asi01_batch.py`, `test_asi01_native_hybrid.py`, `test_asi01_judge_prepared_input.py`). Live pilot chỉ mới chạy `INCONCLUSIVE` (1 request, chưa có live Pi Judge); Web Lab cần Docker mode riêng (`--enable-web-lab-batch`), không nằm trong Unified Runtime mặc định. |
| **ASI02** (Tool Misuse) | `ToolBotLabBatchWorkflow` (offline synthetic `TM-002` với `ToolBotFixture`) và `testcases/tool_misuse/` (`TM-001`, `TM-002`). | `PARTIAL` | `DatasetLibrary.tsx:247` chặn đúng ASI02 imported chat (`"Imported prompts do not provide tool invocation..."`). `ToolBotLabBatchWorkflow` chỉ là offline synthetic (`--enable-toolbot-lab-batch`, ngoài Unified Runtime); `test_toolbot_lab_batch.py:157` đang FAIL (1 test). Live DVAA ToolBot chưa có reviewed action policy/correlator cho ASI02. |
| **ASI03** (Identity & Privilege Abuse) | 1) Response scope (`identity_claim_response`): `ASI03TargetPolicyStore` (hoặc legacy `ASI03ContractStore`) + `GenericImportedBatchWorkflow` + Hybrid Judge (`identity_privilege_abuse`).<br>2) Action scope (`privileged_action`). | `PARTIAL` | Response scope đã nối đầy đủ UI (`Asi03TargetPolicy.tsx`), API, Skill (`identity-privilege-abuse.md`), Hybrid gate và pass test offline (`test_asi03_contracts.py`). Tuy nhiên chưa chứng minh live Pi Judge; action scope (`privileged_action`) ở trạng thái `BLOCKED` / `NOT_IMPLEMENTED` (`asi03_action_runtime_unavailable` trong `asi03_contracts.py:156-157`). |
| **ASI05** (Unexpected Code Execution) | 1) Response scope (`response_command_artifact`): `ASI05PolicyStore` + `GenericImportedBatchWorkflow` + Hybrid Judge (`unexpected-code-execution-response.md`).<br>2) Action scope (`execution_action`): `McpActionWorkflow` (`dvaa_toolbot_canary.json`) + `resolve_asi05_execution()`. | `PARTIAL` | Response scope đã nối UI (`Asi05Policy.tsx`) + backend + pass test offline. Action scope (`McpActionWorkflow`) bị chặn ở Vite proxy (`vite.config.ts`), catalog mặc định `dvaa_toolbot_canary.json` đang ở `review_status: "draft"` (`official_verdict_eligible: false`), chưa có independent effect observer và Pi bị gate chủ đích (`semantic_invoked=false`). |

---

## 9. Trạng thái Shared Judge

| Thành phần | Trạng thái | Bằng chứng & Nhận xét |
| --- | --- | --- |
| Cấu hình dùng chung (`RunnerEvaluationConfig`, `validate_live_pi_config`) | `VERIFIED` | Một file JSON ngoài repo (`--judge-config` / `runtime.json`) dùng chung cho mọi workflow qua `ControlledDispatcher.hybrid_config` và `McpActionWorkflow.hybrid_config`. Ép `mode="hybrid"`, `judge_enabled=True`, `allow_live_judge=True`, `max_judge_calls=1`, `credential_env` hợp lệ và Pi executable tồn tại (`backend/src/testing/evaluation_config.py:39-55`). |
| Quản lý credential & trạng thái missing credential | `IMPLEMENTED_NOT_VERIFIED` | `start_secagent_local.py:168-207` chỉ chuyển `credential_env` vào process `workflow.api` (không lộ sang Vite/Reporting); khi cấu hình qua `runtime.json` mà thiếu env var, `start_secagent_local.py:203-205` fallback `rule_only` với `SECAGENT_JUDGE_SETUP_REASON=credential_missing` để UI hiển thị cảnh báo. |
| Budget & chặn gọi Pi trái phép | `VERIFIED` | `BudgetedJudgeProvider` (`evaluation_config.py:58-82`) giữ tối đa 1 call/Runner. `EvaluationRequestBuilder` (`evaluation_request_builder.py:104-107`) chặn echo secret trước khi gọi Pi. `test_structured_mcp_actions.py:115-128` chứng minh Pi không bị gọi cho draft action scope. |
| Reviewed Policy / Skill admission & Evidence gating | `VERIFIED` | `HybridEvaluator` + `resolve_verdict()` (`verdict_resolver.py:90-219`) từ chối `PASS`/`FAIL` nếu thiếu `response_complete=True` hoặc thiếu exact citation (`response_span` / `runtime_reference`). ASI03/ASI05 response scope yêu cầu policy `reviewed` ở `GenericImportedBatchWorkflow`. |
| Live Pi execution qua Unified Runtime | `BLOCKED` | Chưa có credential thật (`credential_missing`) nên chưa có bằng chứng chạy live Pi Judge end-to-end qua Unified Runtime. |

---

## 10. Trạng thái Saved Reports

| Thành phần | Trạng thái | Bằng chứng & Nhận xét |
| --- | --- | --- |
| Controlled runs index (`list_saved_runs`) & lookup (`/api/reports/runs/<id>`) | `VERIFIED` | Đọc `run-summary.json` + kiểm tra SHA-256 `report_file`, schema, identity, `imported-v1` batch provenance và `tool_artifact_sha256` (`backend/src/reporting/repository.py:63-155`). Đã đọc thành công **554** controlled reports (`0` invalid) trong `results/local-controlled-runs`. |
| MCP sidecar SHA-256 & detail/download (`/api/reports/mcp-runs/<id>`, `/download`) | `VERIFIED` | `repository.py:165-202` kiểm tra `mcp-action-<id>/run-summary.json`, `report_kind == "mcp_action"`, `report_sha256`, khớp `native_report.json` (`evaluation_scope == "execution_action"`). Test pass trong `test_structured_mcp_actions.py:77-105`. |
| Persistence qua restart (`history-index.json`) | `VERIFIED` | `reporting/api.py:43-60,225-245` lưu atomic `history-index.json` cạnh manifest và tái sử dụng khi danh sách thư mục con không đổi; test pass trong `test_reporting_api.py:161-178`. |
| Archived targets trong lịch sử | `VERIFIED` | `ManagedTargetCatalog.archive_targets()` chỉ ẩn target khỏi danh sách active trong `target-catalog.json`, không động vào `results/local-controlled-runs`; `list_saved_runs()` vẫn trả về đầy đủ báo cáo của target đã archive. |
| Date filters (`date_from` / `date_to`) | `PARTIAL` | Backend validate đặt nhầm endpoint (`reporting/api.py:177-179` vs `251-254`); Frontend (`SavedRuns.tsx`, `api.ts`) chưa hỗ trợ input/gửi `date_from`/`date_to`. |
| Pagination & `ERROR` verdict handling ở Frontend | `PARTIAL` | Backend + `SavedRuns.tsx` hỗ trợ `page`/`page_size=25`; nhưng `frontend/src/api.ts:85` sẽ crash khi gặp `mcp_action` có `verdict: "ERROR"`. |
| MCP report cũ ngoài `results/local-controlled-runs` | `NOT_IMPLEMENTED` | 6 `native_report.json` trong `live-action-evidence`, `live-asi05-execution-pilot`, `live-toolbot-mcp-hybrid-acceptance` nằm ngoài root và không có cấu trúc `mcp-action-<32hex>/run-summary.json`, nên chưa được index. |

---

## 11. Kết quả regression

Tất cả kiểm tra dưới đây được chạy trực tiếp trong phiên audit ở chế độ offline/mocked (không gọi live target/MCP/Pi):

| Bộ kiểm tra | Lệnh / Phạm vi | Kết quả | Chi tiết lỗi (Root cause) |
| --- | --- | --- | --- |
| Git integrity | `git diff --check` | **PASS** (exit 0) | Không có whitespace/conflict marker errors (chỉ có LF/CRLF warning của Windows). |
| Python syntax | `py_compile` trên 126 file `.py` modified/untracked | **PASS** (exit 0) | 126/126 file compile sạch. |
| Frontend build | `npm run build` (`tsc -b && vite build`) | **PASS** (exit 0) | 57 modules, `dist/` build sạch trong 1.60s. |
| Backend pytest | `pytest backend/tests -q` | **1576 PASS, 3 FAIL** (659.42s) | 1) `backend/tests/test_b47_remediation.py:326` (`imported_request_budget_invalid` do budget 1 != 30).<br>2) `backend/tests/test_official_asi01_runner.py:271` (guard mới ở `evaluation_request_builder.py:104-107` chặn secret trước khi gọi `FakeJudge`).<br>3) `backend/tests/test_toolbot_lab_batch.py:157` (`management.py:344-351` giữ nguyên revision/review khi chỉ đổi tên). |
| Frontend Vitest | `npm test` (`vitest run`) | **168 PASS, 9 FAIL** (16/19 files pass) | 1) `src/App.test.tsx` (3 fail): `<SavedRuns />` thêm nút `Reset` thứ 2 và gọi `fetch` làm hỏng mock `mockResolvedValueOnce`/tái dùng `Response`.<br>2) `src/TargetExperience.test.tsx` (5 fail): `TargetConfiguration.tsx:11` mặc định `discoveryFlowActive=true` và đổi label target select trong `DatasetLibrary.tsx:236`.<br>3) `src/BatchProgress.test.tsx` (1 fail do timing >1000ms khi chạy song song; chạy riêng `npx vitest run src/BatchProgress.test.tsx` **PASS 5/5**). |
| Playwright mocked browser tests | 7 file spec dùng `page.route` trên `SECAGENT_FRONTEND_PORT=5199` | **7 PASS, 1 SKIPPED, 10 FAIL** | - `application-context-policy-ux.spec.ts` (2/2 PASS)<br>- `dashboard.spec.ts` (4 PASS, 1 SKIPPED)<br>- `report-downloads.spec.ts`: 1 PASS (`:6`), 1 FAIL (`:33` Edge headless context closed `ITaskbarList3`)<br>- `evidence-sources.spec.ts` (2 FAIL: `<PlanWizard>` gọi `/api/testing/categories` chưa mock)<br>- `target-configuration-redesign.spec.ts` (3 FAIL: `Not checked` khớp 3 chỗ)<br>- `target-management.spec.ts` (1 FAIL: mặc định mở `Connect new target`)<br>- `targets.spec.ts` (3 FAIL: `Validate Configuration` trong `<details>` đóng; `getByLabel('Target')` khớp 3 option). |

---

## 12. Roadmap hoàn thiện theo P0 / P1 / P2

### P0 — Phải sửa trước khi accept Unified Runtime
1. **Hoàn thiện `date_from`/`date_to` ở `backend/src/reporting/api.py` và `SavedRuns.tsx`:**
   - Chuyển validation `date_from`/`date_to` từ `execution_list()` sang `saved_runs()` (kiểm tra `YYYY-MM-DD`, `date.fromisoformat`, và `date_from <= date_to`, trả `400 invalid_filter` khi sai).
   - Bổ sung `asi_category="unknown"` cho `/api/reports/saved-runs` để lọc được 181 unclassified runs.
   - Sửa `frontend/src/api.ts:85` (`parseSavedRuns`) chấp nhận `'ERROR'` trong `verdict` (và thêm option `ERROR` hoặc hiển thị badge an toàn ở `SavedRuns.tsx`).
   - Thêm input `date_from` / `date_to` vào `SavedRuns.tsx` và `Filters` ở `frontend/src/api.ts` (giữ tương thích với `Executions.tsx` không truyền date params hoặc tách `SavedRunsFilters`).
   - Viết unit test trong `backend/tests/test_reporting_api.py` và Vitest cho `date_from`/`date_to` + `mcp_action` `ERROR` verdict.
2. **Mở route MCP Actions trong `frontend/vite.config.ts`:**
   - Thêm `/api/testing/mcp-actions` (GET) và `/api/testing/mcp-actions/run` (POST) vào `workflowAllowed` và `privileged` trong `frontend/vite.config.ts`.
   - Thêm kiểm tra Vite middleware / Playwright test cho tab MCP tool-action.
3. **Sửa tiêu đề `BatchProgress.tsx` cho Unified Runtime:**
   - Tại `frontend/src/BatchProgress.tsx:72`, phân biệt batch `imported` vs `asi01` dựa vào `results?.snapshot.imported_provenance` (nếu có -> Imported; nếu không và `asi01BatchEnabled` -> Controlled ASI01), tránh hiển thị nhãn `OFFLINE MOCK IMPORTED DATASET ASSESSMENT` cho batch ASI01.

### P1 — Đồng bộ hợp đồng và đưa toàn bộ regression về xanh
4. **Xử lý 3 failure trong `pytest backend/tests`:**
   - Quyết định contract cho `test_toolbot_lab_batch.py:157` vs `management.py:344-351` (đổi tên `name` có giữ review hay không).
   - Cập nhật `test_official_asi01_runner.py:271` theo guard mới ở `evaluation_request_builder.py:104-107` (xác nhận bị chặn trước khi gọi Judge với `input_rejected` + redaction).
   - Cập nhật `test_b47_remediation.py:326` (hoặc khôi phục partial admission budget nếu đó là ý định thiết kế; kiểm tra lịch sử B4.7 trước khi sửa).
5. **Cập nhật các test Frontend (Vitest + Playwright mocked) bị drift theo UX mới:**
   - `frontend/src/App.test.tsx`: mock tách biệt `/api/reports/saved-runs` và `/api/reports/executions` (tạo `new Response(...)` mới mỗi lần gọi), dùng query scoped theo section/heading thay vì `getByText("Reset")` toàn trang.
   - `frontend/src/TargetExperience.test.tsx`: click `Select existing target` (khi test existing targets) và cập nhật selector `#dataset-target-select` / `Target` thay cho `Reviewed Target Profile`.
   - `frontend/src/BatchProgress.test.tsx`: tăng `waitFor`/`findByRole` timeout lên 3000ms cho render khởi tạo đầu tiên.
   - Cập nhật các Playwright mocked specs (`targets.spec.ts`, `target-configuration-redesign.spec.ts`, `target-management.spec.ts`, `evidence-sources.spec.ts`) khớp UI drawers/tabs hiện tại, và kiểm tra ổn định cho `report-downloads.spec.ts:33`.
6. **Thêm test cho `start_secagent_local.py` (`runtime.json`, `credential_missing`, Unified flags):**
   - Bổ sung unit test offline cho `runtime_settings()`, invalid `runtime.json`, `credential_missing` fallback về `rule_only`, và CLI forwarding sang `workflow.api --enable-unified-runtime`.

### P2 — Hoàn thiện acceptance nâng cao & mở rộng phạm vi
7. **Live verification với Shared Pi Judge qua Unified Runtime:**
   - Khi có Judge API key trong env operator, chạy pilot xác nhận 1-call Pi Judge live cho ASI01, ASI03 (`identity_claim_response`), và ASI05 (`response_command_artifact`) từ UI/Unified Runtime.
8. **Dataset compatibility filtering tự động & MCP report migration (nếu cần):**
   - Thêm lọc/gợi ý dataset trên `DatasetLibrary.tsx` theo target/ASI đã chọn.
   - Nếu cần đưa 6 MCP report cũ ngoài `results/local-controlled-runs` vào lịch sử, viết một script export/sidecar read-only có SHA-256 kiểm chứng (không sửa file gốc).
9. **ASI02 / ASI03 / ASI05 action-scope:**
   - Khi có nhu cầu đánh giá chính thức action-scope ngoài draft: cần reviewed action policy (`reviewed_mcp_catalog_pin_required`), independent sandbox/action observer (không chỉ target-owned receipt), và trusted action Judge skill riêng (tách khỏi response-only skill).

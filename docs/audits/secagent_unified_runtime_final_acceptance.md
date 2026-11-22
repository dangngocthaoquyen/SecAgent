# SecAgent — Unified Runtime Stabilization & Final Acceptance Report

- **Ngày hoàn tất Phase 3:** 2026-11-21
- **Repository:** `D:\SecAgent-W5-Judge`
- **Tài liệu audit nền:** [secagent_agy_handoff_audit.md](file:///D:/SecAgent-W5-Judge/docs/audits/secagent_agy_handoff_audit.md)
- **Phạm vi thực hiện:** Sửa các lỗi P0/P1 đã xác định, bổ sung regression offline & Vite proxy thật, chạy kiểm thử toàn repo ở chế độ offline/mocked + live startup smoke test (không commit/push, không reset/clean/stash, không sửa historical reports, không gọi live target/MCP `tools/call`/Pi Judge thật).
- **Quy ước trạng thái:** `VERIFIED` · `IMPLEMENTED_NOT_VERIFIED` · `PARTIAL` · `BLOCKED` · `NOT_IMPLEMENTED`

---

## 1. Root Cause từng lỗi đã sửa

### P0 — Blocking Bugs
1. **MCP Tool-Action HTTP 405 qua Vite Proxy (`A1`):**
   - **Root cause:** `frontend/vite.config.ts` không khai báo `GET /api/testing/mcp-actions` và `POST /api/testing/mcp-actions/run` trong `workflowAllowed` (`vite.config.ts:61`) và `privileged` (`vite.config.ts:17-30`). Mọi request từ `McpActionPanel.tsx` qua cổng `5173` đều bị middleware Vite chặn `405` trước khi proxy tới `workflow.api`, và không được gắn header `X-SecAgent-Operator`.
   - **Fix:** Thêm đúng 2 route trên với đúng method tương ứng (`GET` và `POST`) vào `workflowAllowed` và `privileged`, giữ nguyên loopback/origin check, anti-spoofing `X-SecAgent-Operator`, nonce `X-SecAgent-Validation` ở backend (`workflow/api.py:318`), và per-case authorization/catalog pin.
2. **Saved Reports `verdict: "ERROR"` làm hỏng hợp đồng Frontend (`A2`):**
   - **Root cause:** `backend/src/reporting/repository.py:193,226` phát sinh `verdict: "ERROR"` cho MCP action thất bại về kỹ thuật, nhưng `parseSavedRuns()` tại `frontend/src/api.ts:85` chỉ cho phép `['PASS', 'FAIL', 'INCONCLUSIVE', null]` khiến UI throw `Error('contract')`. `SavedRuns.tsx` cũng chưa có option lọc `ERROR` và `Badge` chưa có mô tả phân biệt `ERROR` với `FAIL`.
   - **Fix:** Mở rộng `SavedRunVerdict` / `parseSavedRuns` nhận `'ERROR'`, thêm `.badge.error` + mô tả rõ ràng trong `components.tsx`, `SavedRuns.tsx`, và `McpRunDetail.tsx` để tách biệt lỗi kỹ thuật với kết luận lỗ hổng bảo mật `FAIL`.
3. **Validation `date_from`/`date_to` đặt nhầm endpoint ở `reporting/api.py` (`A3`):**
   - **Root cause:** Regex `date_from`/`date_to` nằm nhầm trong `execution_list()` (`reporting/api.py:177-179`, vốn đã bị `boundary()` chặn sớm từ trước), còn `saved_runs()` lọc chuỗi `row['started_at'][:10]` mà không validate định dạng/ngày hợp lệ hay khoảng `date_from <= date_to`, đồng thời thiếu `asi_category="unknown"` cho 181 unclassified runs. Ở Frontend, `api.savedRuns()` còn chặn giá trị `'unknown'` (`value !== 'unknown'`) và `SavedRuns.tsx` thiếu trường chọn ngày.
   - **Fix:** Chuyển validation sang `saved_runs()` (regex `[0-9]{4}-[0-9]{2}-[0-9]{2}`, `date.fromisoformat()`, kiểm tra `date_from <= date_to`, trả `400 invalid_filter` khi sai), hỗ trợ `asi_category=unknown` (`row['asi_category'] is None`), bổ sung `SavedRunFilters` + input `Date from`/`Date to` trong `SavedRuns.tsx` mà không làm thay đổi `Filters` của `Executions.tsx`.

### P1 — Contract Regressions & Labels
4. **3 test FAIL ở Backend (`B1`):**
   - `backend/tests/test_b47_remediation.py:322`: Test cũ gửi 30 case với `total_request_budget=1` kỳ vọng nhận `202`, nhưng contract hiện tại tại `generic_imported_batch.py:282-283` + `workflow/api.py:207` siết chặt `total_request_budget == len(testcase_ids)` (`imported_request_budget_invalid`, `409`). Test được cập nhật để giữ và kiểm chứng cả rejection `409` khi lệch budget lẫn retire đúng owned grants (giữ nguyên foreign grant) khi transport trả `503`.
   - `backend/tests/test_official_asi01_runner.py:263`: Test cũ kỳ vọng secret `OFFLINE_CREDENTIAL_SENTINEL` đi vào `FakeJudge` trước khi redact ở native report. Guard bảo mật mới ở `evaluators/evaluation_request_builder.py:104-107` chủ động chặn trước khi gọi Judge (`JudgeInputRejected` -> `json_validation_status="input_rejected"`, `semantic_invoked=False`, `final_verdict="INCONCLUSIVE"`). Test được cập nhật khớp contract bảo mật mới, không nới lỏng guard.
   - `backend/tests/test_toolbot_lab_batch.py:153`: Test cũ chỉ đổi display name `"Updated Lab"` (cùng `timeout_seconds=3`) rồi kỳ vọng `preview` trả `409`. `management.py:344-351` chủ đích coi đổi riêng `name`/`platform_*` là `metadata_only` (`revision_names` giữ nguyên `profile_revision` và `reviews`), trong khi thay đổi field bảo mật (như `timeout_seconds=4`) hay sai `expected_profile_revision` vẫn phải reject `409`. Test được cập nhật để xác nhận đủ 3 nhánh: wrong revision rejected, metadata-only rename giữ review (`200`), security-field update xóa review & đổi revision (`409`).
5. **Frontend Vitest drift (`B2`):**
   - `App.test.tsx`: `<Executions />` nhúng `<SavedRuns />` tạo nút `Reset`/`Next` thứ hai và gọi thêm `/api/reports/saved-runs`; các mock cũ dùng `Response` dùng-1-lần gây `"Body is unusable"`. Đã sửa mock tạo `new Response(...)` mới theo URL và scope selector theo `<form>`/`<section>` tương ứng, thêm test `SavedRuns` `ERROR` + `date_from`/`date_to`/`unknown` và `McpRunDetail` `ERROR`.
   - `TargetExperience.test.tsx`: UI redesign mở tab `Connect new target` mặc định (`initialConnect`), hiển thị danh sách `.target-list-select` khi `managementEnabled=true` thay cho `<select>`, và label select ở `DatasetLibrary.tsx:236` là `Target`. Đã cập nhật thao tác test đúng UX thật và scope `Within(Selected target)`.
   - `BatchProgress.test.tsx` & `Detail.test.tsx`: Tăng `findByRole` timeout lên `4000ms` tránh timeout 1000ms khi jsdom chạy song song nhiều file, đồng thời thêm mock `/saved-runs` ở `Detail.test.tsx`.
6. **Playwright mocked browser drift & Edge headless crash (`B3`):**
   - `targets.spec.ts`, `target-configuration-redesign.spec.ts`, `target-management.spec.ts`, `evidence-sources.spec.ts`: Cập nhật selector đúng drawers/tabs hiện tại (`Advanced Settings` chứa `Validate Configuration`, `Select existing target`, `getByLabel('Selected target')`, `Review required`, mock `/categories`, `/managed-targets/archived`, `/application-contexts/target/`).
   - `report-downloads.spec.ts:33`: Thu thập bằng chứng xác nhận Edge headless (`msedge.exe`) trên Windows crash ở `browser.newContext` thứ hai sau khi có download ở test trước với lỗi nội bộ Chromium/Edge `ITaskbarList3`. Khi chạy cùng test trên Chrome (`SECAGENT_BROWSER_CHANNEL=chrome`), cả `report-downloads.spec.ts` (2/2) và toàn bộ mocked suite đều **PASS**.
7. **Nhãn workflow ở `BatchProgress.tsx` (`B4`):**
   - **Root cause:** `frontend/src/BatchProgress.tsx:72` ưu tiên cờ toàn cục `customImported` từ `/api/testing/health` nên batch `asi01` trong Unified Runtime bị gán nhãn sai thành `OFFLINE MOCK IMPORTED DATASET ASSESSMENT`, và dòng phụ luôn hardcode `Rule-only evaluation`.
   - **Fix:** Suy ra loại workflow từ `results?.snapshot` (`imported_provenance` -> imported mode, `GH-WEB-*` -> Web Lab, `TM-002` -> ToolBot Lab, else `synthetic` / `CONTROLLED ASI01`; khi đang loading ở Unified Runtime dùng `UNIFIED BATCH`), và hiển thị đúng `Hybrid evaluation` vs `Rule-only evaluation`.

---

## 2. Những file đã sửa & bổ sung

| Loại | File | Mục đích |
| --- | --- | --- |
| Backend | [backend/src/reporting/api.py](file:///D:/SecAgent-W5-Judge/backend/src/reporting/api.py) | Chuyển `date_from`/`date_to` validation vào `saved_runs()`, check calendar/range (`400 invalid_filter`), hỗ trợ `asi_category=unknown`. |
| Backend test | [backend/tests/test_reporting_api.py](file:///D:/SecAgent-W5-Judge/backend/tests/test_reporting_api.py) | Test `ERROR` MCP runs, corrupted exclusion, `asi_category=unknown`, `date_from`/`date_to` boundary + pagination + invalid queries. |
| Backend test | [backend/tests/test_b47_remediation.py](file:///D:/SecAgent-W5-Judge/backend/tests/test_b47_remediation.py) | Cập nhật `test_insufficient_budget_and_failed_transport_retire_only_owned_grants` giữ budget guard `409` và verify retire owned grant. |
| Backend test | [backend/tests/test_official_asi01_runner.py](file:///D:/SecAgent-W5-Judge/backend/tests/test_official_asi01_runner.py) | Cập nhật assertion theo guard chặn credential echo trước khi gọi Judge. |
| Backend test | [backend/tests/test_toolbot_lab_batch.py](file:///D:/SecAgent-W5-Judge/backend/tests/test_toolbot_lab_batch.py) | Cập nhật test theo `metadata_only` rename vs security-field revision & review clear. |
| Backend test (mới) | [backend/tests/test_unified_startup_and_vite_proxy.py](file:///D:/SecAgent-W5-Judge/backend/tests/test_unified_startup_and_vite_proxy.py) | Test `runtime_settings()`, `credential_missing`, unified/legacy startup flags, switching HTTP↔MCP trong `workflow/api.py`, và HTTP E2E qua **Vite proxy thật**. |
| Frontend config | [frontend/vite.config.ts](file:///D:/SecAgent-W5-Judge/frontend/vite.config.ts) | Cho phép `GET /api/testing/mcp-actions`, `POST /api/testing/mcp-actions/run` và forward `X-SecAgent-Operator`. |
| Frontend source | [frontend/src/api.ts](file:///D:/SecAgent-W5-Judge/frontend/src/api.ts) | `SavedRunVerdict` (thêm `ERROR`), `SavedRunFilters` (`date_from`/`date_to`), cho gửi `asi_category=unknown`. |
| Frontend source | [frontend/src/components.tsx](file:///D:/SecAgent-W5-Judge/frontend/src/components.tsx) | Mô tả và tone `.badge.error` tách biệt lỗi thực thi khỏi `FAIL`. |
| Frontend source | [frontend/src/styles.css](file:///D:/SecAgent-W5-Judge/frontend/src/styles.css) | Style `.badge.error`. |
| Frontend source | [frontend/src/SavedRuns.tsx](file:///D:/SecAgent-W5-Judge/frontend/src/SavedRuns.tsx) | UI filter `Date from`, `Date to`, `Unknown` ASI, `ERROR (execution error)`. |
| Frontend source | [frontend/src/McpRunDetail.tsx](file:///D:/SecAgent-W5-Judge/frontend/src/McpRunDetail.tsx) | Hiển thị `<Badge>` và notice tách biệt `ERROR` với vulnerability verdict. |
| Frontend source | [frontend/src/BatchProgress.tsx](file:///D:/SecAgent-W5-Judge/frontend/src/BatchProgress.tsx) | Sửa tiêu đề workflow & chế độ `Hybrid/Rule-only` dựa trên `results.snapshot`. |
| Frontend Vitest | [frontend/src/App.test.tsx](file:///D:/SecAgent-W5-Judge/frontend/src/App.test.tsx), [BatchProgress.test.tsx](file:///D:/SecAgent-W5-Judge/frontend/src/BatchProgress.test.tsx), [Detail.test.tsx](file:///D:/SecAgent-W5-Judge/frontend/src/Detail.test.tsx), [TargetExperience.test.tsx](file:///D:/SecAgent-W5-Judge/frontend/src/TargetExperience.test.tsx) | Sửa drift, timeout, fresh `Response` per fetch, và bổ sung unit tests cho P0/P1. |
| Playwright config & specs | [frontend/playwright.config.ts](file:///D:/SecAgent-W5-Judge/frontend/playwright.config.ts), [targets.spec.ts](file:///D:/SecAgent-W5-Judge/frontend/browser-tests/targets.spec.ts), [target-configuration-redesign.spec.ts](file:///D:/SecAgent-W5-Judge/frontend/browser-tests/target-configuration-redesign.spec.ts), [target-management.spec.ts](file:///D:/SecAgent-W5-Judge/frontend/browser-tests/target-management.spec.ts), [evidence-sources.spec.ts](file:///D:/SecAgent-W5-Judge/frontend/browser-tests/evidence-sources.spec.ts), [mcp-and-saved-reports.spec.ts](file:///D:/SecAgent-W5-Judge/frontend/browser-tests/mcp-and-saved-reports.spec.ts) | Sửa selector/mock drift, hỗ trợ `SECAGENT_BROWSER_CHANNEL`, thêm E2E browser spec cho MCP tab & Saved Reports (`ERROR` + `Date from`/`Date to`). |

---

## 3. Những test đã chạy và kết quả

| Kiểm tra | Lệnh thực thi | Kết quả mới nhất |
| --- | --- | --- |
| Git diff integrity | `git diff --check` | **PASS** (`exit 0`, chỉ có LF/CRLF warning Windows) |
| Python syntax check | `python -m py_compile start_secagent_local.py backend/src/reporting/api.py backend/tests/...` | **PASS** (`exit 0`) |
| Full Backend pytest | `pytest backend/tests -q` | **1584 PASS, 0 FAIL** (`387.25s`, đã bao gồm `test_unified_startup_and_vite_proxy.py` và các sửa P0/P1) |
| Full Frontend Vitest | `cd frontend ; npm test` (`vitest run`) | **19/19 files PASS, 181/181 tests PASS** (`22.57s`) |
| Frontend Build | `cd frontend ; npm run build` (`tsc -b && vite build`) | **PASS** (57 modules, `1.68s`) |
| Mocked Playwright (Chrome) | `$env:SECAGENT_FRONTEND_PORT='5201'; $env:SECAGENT_BROWSER_CHANNEL='chrome'; npx playwright test <8 mocked specs>` | **19 PASS, 1 SKIPPED (`dashboard.spec.ts:114` real-dataset check), 0 FAIL** (`37.0s`) |
| Mocked Playwright (Edge, spec đích) | `$env:SECAGENT_FRONTEND_PORT='5201'; npx playwright test browser-tests/target-configuration-redesign.spec.ts` | **3 PASS, 0 FAIL** (`13.6s`) |
| Unified Runtime live startup smoke test | `start_secagent_local.py --data-dir <tmp> --runtime-config <tmp/runtime.json> --no-browser` | **PASS**: `registered_workflows=['asi01','imported','mcp_actions']`, `evaluation_modes=['rule_only']`, `judge_setup_reason='credential_missing'`, `mcp_action_setup_reason='configured'`, `GET /api/testing/mcp-actions -> 200`, `POST /api/testing/mcp-actions -> 405`, `saved-runs -> 200 (554 total, 0 invalid)`, `asi_category=unknown -> 181`, `date_from=2026-02-30 -> 400 invalid_filter` |

---

## 4. Những test vẫn FAIL hoặc chưa chạy trong suite đầy đủ (và lý do)

- **Edge headless `browser.newContext` crash ở `report-downloads.spec.ts:33`:**
  - Khi chạy `report-downloads.spec.ts` trên Edge (`channel: "msedge"`), test đầu (`:6`) pass phần tải file, sau đó test thứ hai (`:33`) gặp lỗi Edge headless nội bộ Windows (`browser.newContext: Target page, context or browser has been closed` kèm log `Failed initializing an ITaskbarList3 interface`). Test này đã chạy lại trên Chrome (`SECAGENT_BROWSER_CHANNEL=chrome`) và **PASS 2/2**, xác nhận lỗi đến từ trình duyệt Edge headless chứ không phải code SecAgent.
- **Các Playwright spec `*-real-api.spec.ts` / `unified-runtime-local.spec.ts` / `*-offline.spec.ts` không chạy hết toàn bộ trong pha này:**
  - Các spec `*-real-api.spec.ts` cần stack `workflow.api` + `reporting.api` + fixture/DVAA riêng trên cổng 5173 (cổng đang có session local hoặc nằm ngoài phạm vi mock). Chúng giữ nguyên trạng thái chưa chạy full trong phiên Phase 3 này (`local_controlled` smoke test của `start_secagent_local.py` đã xác minh startup + proxy + saved-runs thật).
- **Live target HTTP / live MCP `tools/call` / Live Shared Pi Judge:**
  - Không chạy trong Phase 3 theo đúng giới hạn an toàn (không có API key thật và cấm gọi live target/Pi/MCP trong pha ổn định offline).

---

## 5. Đánh giá Readiness theo từng phân hệ

| Phân hệ | Trạng thái | Chi tiết xác minh & giới hạn còn lại |
| --- | --- | --- |
| **5. Unified Runtime readiness** | **`VERIFIED`** | `start_secagent_local.py` mặc định bật `--enable-unified-runtime`, đăng ký đồng thời `asi01`, `imported`, và tùy chọn `mcp_actions` (`mcp_action_catalog`); kiểm chứng bằng cả unit/integration pytest lẫn live startup smoke test (`registered_workflows = ['asi01', 'imported', 'mcp_actions']`). Chuyển đổi Target (HTTP ↔ MCP) và ASI (`ASI01`, `ASI02`, `ASI03`, `ASI05`) trong một phiên không cần restart. Mutual exclusion (`409 another_workflow_active`), one-use execution grant, `workflow_selection_required` khi thiếu `workflow_id`, và legacy `--enable-*-batch` đều giữ nguyên. Khoảng trống UI nhẹ: bảng `Available Datasets` trên `DatasetLibrary.tsx` chưa tự lọc ẩn dataset theo target/ASI, nhưng đã chặn không tương thích fail-closed trước khi preview/run. |
| **6. MCP UI readiness** | **`VERIFIED` (mocked / Vite proxy)** / **`BLOCKED` (live target)** | Lỗi `405` đã được khắc phục ở `frontend/vite.config.ts`; đã xác minh qua cả **Vite proxy thật** (`test_unified_startup_and_vite_proxy.py` + `start_secagent_local.py`) lẫn Playwright UI (`mcp-and-saved-reports.spec.ts`). Đáp ứng chỉ **direct MCP `tools/call`** có catalog & confirmation; không hỗ trợ chuyển đổi natural-language chat sang `tools/call` và **chưa hỗ trợ ASI05 agent-level execution**. Catalog mặc định `dvaa_toolbot_canary.json` đang ở trạng thái `draft` (`official_verdict_eligible: false`). |
| **7. HTTP Chat readiness** | **`VERIFIED` (offline / controlled contract)** / **`BLOCKED` (live target run in Phase 3)** | `Asi01BatchWorkflow` và `GenericImportedBatchWorkflow` (`execution_mode='both'`) hoạt động cùng lúc qua đúng `workflow_id`; `BatchProgress.tsx` hiển thị chính xác loại assessment (`CONTROLLED ASI01` vs `IMPORTED DATASET` & `Hybrid/Rule-only`). Live Local yêu cầu reviewed loopback profile + fresh benign connection check + per-run confirmation (không chạy payload live trong pha này). |
| **8. Shared Judge readiness** | **`VERIFIED` (offline / degraded startup)** / **`BLOCKED` (live Pi Judge)** | `RunnerEvaluationConfig`, `validate_live_pi_config`, `BudgetedJudgeProvider` (1 call/case), và credential-echo guard (`EvaluationRequestBuilder`) hoạt động ổn định. Khi `runtime.json` trỏ tới `judge_config` nhưng env thiếu key, `start_secagent_local.py` khởi động ở chế độ `rule_only` với `SECAGENT_JUDGE_SETUP_REASON=credential_missing` (`api.py` trả `evaluation_modes=['rule_only']`) và không bao giờ gọi Pi trái phép; khi truyền CLI `--judge-config` tường minh mà thiếu key thì fail-closed (`exit 2`). Live Pi execution qua Unified Runtime vẫn `BLOCKED` cho tới khi operator cung cấp API key trong env khi khởi chạy. |
| **9. Persistent Reports readiness** | **`VERIFIED`** | Đọc và phân trang chính xác **554** controlled reports (`0` invalid) trong `results/local-controlled-runs` thông qua `history-index.json`; archive target giữ nguyên lịch sử. Đã sửa hoàn chỉnh hợp đồng `verdict: "ERROR"`, bộ lọc `date_from`/`date_to` (validate `YYYY-MM-DD`, lịch hợp lệ, `date_from <= date_to` -> `400 invalid_filter`), `asi_category=unknown` (lọc 181 unclassified runs), sidecar SHA-256 kiểm tra toàn vẹn, và hiển thị `SavedRuns.tsx` / `McpRunDetail.tsx` / download. 6 MCP report lịch sử cũ ngoài `controlled_runs_root` vẫn được giữ nguyên tại chỗ (`NOT_IMPLEMENTED` auto-index để bảo toàn lịch sử). |

---

## 10. Các ASI / Scope chưa hỗ trợ chính thức

- **ASI01 Web Lab (`GH-WEB-001`):** Không nằm trong Unified Runtime mặc định; cần phiên legacy `--enable-web-lab-batch` kèm Docker lab riêng.
- **ASI02 (Tool Misuse):** Chặn đúng trên imported chat (`DatasetLibrary.tsx:247`). Chưa hỗ trợ đánh giá live tool misuse trên Unified Runtime (chỉ có offline synthetic `TM-002` qua cờ `--enable-toolbot-lab-batch` riêng).
- **ASI03 `privileged_action` scope:** Chỉ hỗ trợ `identity_claim_response` (response-level); action-scope vẫn trả `asi03_action_runtime_unavailable` (`NOT_IMPLEMENTED`).
- **ASI05 agent-level / autonomous execution:** **Chưa hỗ trợ.** `McpActionWorkflow` hiện tại là **direct MCP `tools/call` từ SecAgent tới tool service (`tool_service/direct_request`)** với catalog `draft`, chưa có independent host/sandbox effect observer và chưa nối action Pi Judge skill riêng.

---

## 11. Exact Startup Command

### Chạy mặc định (Unified Runtime + Shared Judge + MCP Actions qua `runtime.json`)
Đặt `runtime.json` tại `%LOCALAPPDATA%\SecAgent\runtime.json` (ngoài repository), ví dụ trỏ `judge_config`, `evidence_policy`, và `mcp_action_catalog`, cấp Judge API key vào biến môi trường nếu muốn bật Hybrid Pi Judge, rồi chạy:

```powershell
python start_secagent_local.py
```

Hoặc chỉ định tường minh catalog MCP và không mở trình duyệt tự động:

```powershell
python start_secagent_local.py --mcp-action-catalog D:\path\outside-repo\mcp_catalog.json --no-browser
```

*(Lưu ý: với `configs/mcp_actions/dvaa_toolbot_canary.json` trong repo, có thể truyền qua `--mcp-action-catalog` hoặc `runtime.json` để xem/chạy UI `MCP tool-action assessment`; riêng `judge_config` và `evidence_policy` bắt buộc phải nằm ngoài repository.)*

### Chạy legacy riêng lẻ (khi cần Web Lab hoặc ToolBot Lab)
```powershell
python start_secagent_local.py --enable-web-lab-batch
python start_secagent_local.py --enable-toolbot-lab-batch
```

---

## 12. Những việc còn lại để chốt MVP

1. **P0 — Live Shared Pi Judge Smoke/Acceptance với API key thật:** Khi có `DEEPSEEK_API_KEY` (hoặc env key theo `judge_config` trong `runtime.json`), chạy `python start_secagent_local.py`, kiểm tra UI chọn target reviewed + Test Connection, thực thi **1 case có kiểm soát** cho ASI01 / ASI03 (`identity_claim_response`) / ASI05 (`response_command_artifact`) ở mode Hybrid và xác nhận Saved Native Report sau restart.
2. **P1 — Review & quyết định git commit:** Toàn bộ working tree hiện vẫn chưa commit; sau bước nghiệm thu live #1, thực hiện rà soát `git status` / `git diff` để chuẩn bị commit sạch (tách artifact tạm / screenshot test nếu không muốn track).
3. **P2 — Auto-filter bảng `Available Datasets` & nâng cấp ASI02/ASI05 action-scope:** Nếu có yêu cầu MVP mở rộng, bổ sung UI lọc gợi ý dataset theo target/ASI trong `DatasetLibrary.tsx` và hoàn thiện independent sandbox/effect observer + action Judge skill trước khi bật official verdict cho `execution_action`.

# SecAgent — Codex Phase 4 acceptance

Ngày: 2026-11-21. Phạm vi: kiểm tra handoff Phase 3, một lần khởi động Unified Runtime, UI thực tế, cấu hình và lịch sử đã lưu. **Không gửi DVAA HTTP/MCP request, không chạy testcase mới và không gọi Pi Judge trong Phase 4.** Trạng thái dưới đây không thay thế các kết quả live trước đây.

## 1. Handoff integrity

- Đã đọc `docs/audits/secagent_agy_handoff_audit.md` và `docs/audits/secagent_unified_runtime_final_acceptance.md` trước khi kiểm tra source. Nền Git vẫn là `ce1c776`; working tree có nhiều thay đổi và untracked files từ các phase trước. Tất cả được giữ nguyên. `git diff --check` exit 0 (Git chỉ cảnh báo chuyển LF/CRLF trên Windows).
- Xác minh trực tiếp các sửa Phase 3: Vite cho phép đúng `GET /api/testing/mcp-actions` và `POST /api/testing/mcp-actions/run`, kèm operator header tại `frontend/vite.config.ts:29-30,63,87`; bộ lọc date và `unknown` ASI tại `backend/src/reporting/api.py:209-275`; nhãn BatchProgress theo snapshot tại `frontend/src/BatchProgress.tsx`. Số 1584/181/19 trong báo cáo Agy là kết quả bàn giao; Phase 4 chạy một nhóm kiểm tra mới ở mục 11.
- Sửa duy nhất ảnh hưởng chức năng trong Phase 4: `list_saved_runs()` đã chọn `execution.started_at` vốn rỗng trong nhiều Native Reports, khiến bộ lọc ngày bỏ sót run có `source_reported_at`. Nay lấy `execution.started_at or source_reported_at` tại `backend/src/reporting/repository.py:242`, đổi version **cache index**, không đổi report gốc (`backend/src/reporting/api.py:55,243`). Test bảo vệ projection này nằm ở `backend/tests/test_reporting_api.py`.

## 2. Runtime và cấu hình một lần

Lệnh chuẩn: `python start_secagent_local.py`. Launcher đọc `%LOCALAPPDATA%\SecAgent\runtime.json`, chỉ chứa tham chiếu cấu hình (`start_secagent_local.py:58-78,135-150`), bật `--enable-unified-runtime` mặc định (`:141-144,224-225`), không gửi Target/Judge request lúc startup. Đã chạy lệnh này hai lần để kiểm tra restart; phiên hiện tại mở ở `http://127.0.0.1:55847/#targets` (port được chọn tự động vì các port mặc định đã có listener). Health của phiên hiện tại: `registered_workflows = [asi01, imported, mcp_actions]`, `evaluation_modes = [rule_only]`, `judge_setup_reason = credential_missing`, `mcp_action_setup_reason = configured` (`backend/src/workflow/api.py:335-362`).

| Thành phần | Kết quả Phase 4 | Ý nghĩa |
| --- | --- | --- |
| Operator runtime file | **VERIFIED** | File tồn tại ngoài repo, schema `1.0.0`, tham chiếu Judge config, Evidence Policy và MCP catalog; không có API key trong file tham chiếu. |
| Shared Judge | **BLOCKED** | Config `hybrid`, `judge_enabled=true`, `allow_live_judge=true`, `max_judge_calls=1`; credential được khai báo **absent trong process này**. Launcher hạ về `rule_only` (`start_secagent_local.py:195-206`). Không gọi Pi. |
| Evidence Policy | **VERIFIED configured; PARTIAL evidence** | 3 HTTP endpoint allowlisted. CodeBot có 3 source `not_checked/uncorrelated`; ToolBot có 1 source `available/uncorrelated`. Availability không chứng minh hành động hoặc correlation. |
| MCP Action Catalog | **VERIFIED configured; BLOCKED official verdict** | 1 ASI05 structured canary, Action Policy `draft`, `official_verdict_eligible=false` (`backend/src/workflow/mcp_actions.py:109-121`). Không có `dvaa_mcp_receipt_root` trong runtime file. |
| Target profiles | **VERIFIED reviewed for offline configuration** | `dvaa-codebot` HTTP 7004, `local-agent-7010` MCP 7010 và các profile khác đã review. Review target không phải per-run execution permission hoặc review Action Policy. |

## 3. Target / ASI compatibility

| ASI / scope | Target, testcase, transport | Rule / Hybrid và policy | Evidence & live readiness | Đối chứng Promptfoo |
| --- | --- | --- | --- | --- |
| ASI01 `goal_hijacking` | ResearchBot/SecureBot, native `GH-C01`, `GH-001`, `GH-002`, HTTP chat | Native controlled workflow đã đăng ký; baseline trước attack; Shared Judge chỉ khi có config/credential/authorization. | **PARTIAL**: có live history trước Phase 4; lần này không gửi request. Cần baseline hợp lệ và per-run grant. | Chỉ khi cố định legitimate goal, target revision, prompt và phạm vi response; chưa có accuracy tổng quát. |
| ASI02 `tool_action` | Imported chat prompts không có trace; `TM-002` là ToolBot lab synthetic ở legacy mode | **NOT IMPLEMENTED** cho live ASI02 trong Unified Runtime. UI chặn imported ASI02 (`frontend/src/DatasetLibrary.tsx:129,247`). | Thiếu structured live ASI02 contract, reviewed policy và correlated handler evidence. | Chưa phù hợp đối chứng action-level. |
| ASI03 `identity_claim_response` | LegacyBot/imported chat dataset, HTTP | Reviewed response policy có trong local catalog; Skill/routing dùng Shared Judge, nhưng credential hiện thiếu. | **PARTIAL**: response scope đã có pilot trước đây; privileged action không được suy ra từ identity claim. | Có thể thiết kế response-based comparison sau khi khóa cùng dataset/target và nhãn độc lập; chưa kiểm định trong Phase 4. |
| ASI05 `response_command_artifact` | CodeBot `dvaa-codebot` HTTP 7004, imported ASI05 dataset | Reviewed response policy cho đúng profile; Hybrid hiện bị chặn vì credential thiếu. | **PARTIAL**: response-based pilot lịch sử tồn tại; không chứng minh OS execution. | Có thể đối chứng **response scope** với capture và cấu hình Target giống nhau; không dùng direct MCP như cùng phạm vi. |
| ASI05 `execution_action` | ToolBot `local-agent-7010` MCP, 1 structured `read_file` canary | Action Policy `draft`; direct `tools/call` từ SecAgent; không dùng response Skill để chấm action. | **BLOCKED official verdict**: request/target telemetry không đủ cho agent attribution hoặc verified effect; source HTTP available vẫn `uncorrelated`. | Không tương đương với chat prompt assessment. |

`DatasetLibrary` vẫn hiển thị toàn bộ Available Datasets trước khi người dùng chọn một dataset. Bộ lọc tương thích thực hiện ở bước chọn Target/ASI/scope và trước BatchLaunch (`frontend/src/DatasetLibrary.tsx:126-130,236-248,317-329`). Đây là khoảng trống UX, nhưng trường hợp không tương thích bị chặn; natural-language prompts không được chuyển thành MCP `tools/call`.

## 4. One-startup UI acceptance

Playwright dùng ứng dụng thật qua Vite proxy, chỉ thao tác đọc/chọn, tại `frontend/browser-tests/unified-runtime-local.spec.ts`:

- **VERIFIED**: trong một phiên, chọn ToolBot rồi CodeBot, chọn ASI05 response → ASI05 execution → ASI02 → ASI03, mở MCP tab và thấy canary + `draft`, sau đó mở Saved Native Reports. Test quan sát **0 POST** tới `/batches` hoặc `/mcp-actions/run` khi chỉ chuyển Target/ASI. `workflow_id` được truyền tường minh bởi `BatchLaunch.tsx:13,23`, `DatasetLibrary.tsx:325` và `PlanWizard.tsx:58`; API yêu cầu workflow ID nếu nhiều service và ngăn hai batch đồng thời (`backend/src/workflow/api.py:812-820,862-876`).
- **VERIFIED**: chọn ASI05 `execution_action` trên chat dataset hiển thị *Not available for official evaluation*; form ASI05 response policy chỉ xuất hiện ở `response_command_artifact` (`frontend/src/DatasetLibrary.tsx:240-255`). Chọn ASI02 imported chat cũng hiển thị lý do thiếu tool/handler/correlation evidence.
- **PARTIAL**: Application Context của ToolBot đã tồn tại với `provenance=operator_declared`, `binding_status=current`; cùng revision SHA-256 được đọc lại sau restart. Không thực hiện Save mới trong Phase 4, nên chưa đo lại thao tác nhập/chỉnh sửa bằng tay.
- **PARTIAL**: Auto-filter ẩn dataset không tương thích chưa có. UI nêu lý do không tương thích sau khi chọn dataset. Không có hành động chạy testcase tự động.

## 5. Live preflight, không live execution

`docker ps` cho thấy container `dvaa-deepseek` đang `healthy`; Windows báo listener loopback ở 7004 và 7010. Đây là **preflight cổng/container**, chưa xác minh HTTP chat/MCP response hiện tại vì Phase 4 không gọi DVAA API. Local SecAgent `/api/testing/targets` xác nhận profile `dvaa-codebot` → `http://127.0.0.1:7004/v1/chat/completions` và `local-agent-7010` → `http://127.0.0.1:7010/`, đều `reviewed_for_offline_configuration`. Không có fresh connection check hoặc per-run authorization trong Phase 4.

`GET /api/testing/mcp-actions` qua Vite trả 200 và 1 case `draft`. Đây chỉ chứng minh UI/proxy/catalog. Không gọi `POST /api/testing/mcp-actions/run`, không gửi chat prompt, không gọi Pi. Không có kết luận mới về handler invocation, simulated execution, sandbox effect hoặc autonomous agent action.

## 6. Shared Judge readiness

`RunnerEvaluationConfig` giới hạn `max_judge_calls` và `validate_live_pi_config` yêu cầu đúng một call/case (`backend/src/testing/evaluation_config.py:17-46,66-81`). `EvaluationRequestBuilder` kiểm tra reviewed input và chặn credential echo trước khi disclosure (`backend/src/evaluators/evaluation_request_builder.py:32-62,102-107`). Runtime hiện thiếu credential, vì vậy health chỉ công bố `rule_only`; **không có semantic assessment mới**. Reviewed ASI03/ASI05 response policies là điều kiện cần; target review hoặc Application Context không thay thế chúng. MCP action catalog `draft` và không có reviewed action Judge Skill binding, nên không dùng Pi response Skill cho `execution_action`.

## 7. Saved Reports acceptance

- **VERIFIED**: 554 controlled Native Reports, 0 invalid artifact trong selected root; `history-index.json` được dựng bền vững ngoài repo và `index_persisted=true` (`backend/src/reporting/api.py:39-81,209-277`). Sau restart, vẫn thấy 554; detail của một run trả 200, download trả JSON hợp lệ với export schema `1.0.0`. Report detail tái kiểm tra hash từ sidecar (`backend/src/reporting/repository.py:63-160`), không dựa vào index làm security evidence.
- **VERIFIED**: lọc target, testcase, verdict và `asi_category=unknown` hoạt động; có 181 report chưa xác định ASI. Query ngày sai `2026-02-30` trả 400. Sau sửa projection thời gian, `date_from=2026-11-21&date_to=2026-11-21` trả 1 report thực thay vì 0. Ngày được lấy từ trường thời gian đã normalize của Native Report, không từ mtime file. `ERROR` được giữ riêng với `FAIL` ở frontend/backend theo sửa Phase 3.
- **VERIFIED by architecture/offline tests, not a live archive operation**: reporting root độc lập với active target catalog; archive ẩn target khỏi run mới nhưng không xóa artifact (`backend/src/workflow/management.py:182-188,248-260`). Không archive profile operator trong Phase 4. Sidecar sai hash/invalid report được loại khỏi history hoặc detail trả 409; các test dùng temp artifacts, không sửa report lịch sử.
- **LIMITATION**: 6 MCP Native Reports cũ ngoài selected `controlled_runs_root` không được auto-index. MCP run mới có sidecar SHA-256 và viewer riêng; direct tool receipt vẫn không phải independent sandbox effect. Download là export đã lọc/chuẩn hóa, không cam kết byte-for-byte bản gốc.

## 8. Tests Phase 4 và file thay đổi

| Kiểm tra | Kết quả |
| --- | --- |
| `git diff --check` | PASS, exit 0 |
| Backend focused: reporting, unified startup/proxy, MCP, Judge config, target management, Application Context | **113/113 PASS** |
| Full frontend Vitest sau khi đồng bộ thao tác chờ validation trong test | **181/181 PASS** |
| `npm run build` | PASS, 57 modules |
| Playwright real local app, one session, no execution POST | **1/1 PASS** |
| DVAA Target/Pi live calls Phase 4 | **0** |

File Phase 4 sửa: `backend/src/reporting/repository.py` (ngày report), `backend/src/reporting/api.py` (cache version), `backend/tests/test_reporting_api.py` (regression ngày), `frontend/browser-tests/unified-runtime-local.spec.ts` (chuyển Target/ASI/MCP không chạy), `frontend/src/TargetExperience.test.tsx` (đợi validation của target mới trước probe, tránh test race), và báo cáo này. Không đổi Judge, Runner, Policy, Skill, historical report hay label. Lần Vitest đầu có 1 timeout ở `TargetExperience` khi chạy song song cùng build/browser; test file riêng PASS 8/8, sau khi test đợi đúng trạng thái validation, full suite PASS 181/181.

## 9. Cách dùng UI và bước kế tiếp

1. Chạy `python start_secagent_local.py`. Nếu Shared Judge báo `credential_missing`, cấu hình credential **trong môi trường process** theo alias trong Judge config operator-owned; không đưa key vào source, UI hoặc report. Chạy lại app để nạp môi trường mới khi được phép.
2. **Targets:** chọn profile CodeBot HTTP hoặc ToolBot MCP; phân biệt *Reviewed* với *Connected*. Test Connection chỉ gửi probe lành tính sau xác nhận riêng. Kiểm tra đúng endpoint/model.
3. **Datasets:** chọn chat dataset cho HTTP target hoặc tab **MCP tool-action assessment** cho structured MCP catalog. Chọn ASI và scope, đọc trạng thái policy/evidence. Với ASI01 native, dùng **Native ASI01 cases**; với imported chat, dùng **Select Dataset**. Không chọn ASI02 imported để đánh giá tool action, không dùng ASI05 response policy cho execution action.
4. Chỉ khi preview **Ready**, policy đúng scope, evidence đủ và operator xác nhận từng run, chọn **Run Selected Tests** (hoặc one MCP action). `Hybrid` chỉ khả dụng khi shared config + credential + skill/policy binding hợp lệ.
5. Vào **Execution Results → Saved Native Reports** để lọc, mở detail và Download Report. History tồn tại sau restart; archive target không xóa report.

### MVP conclusion

**VERIFIED** cho Unified Runtime, chuyển Target/ASI không restart, MCP catalog qua UI/Vite, startup degraded an toàn và persistent report history. **PARTIAL** cho nghiên cứu response-based ASI01/ASI03/ASI05 vì Phase 4 chưa chạy live case/Judge; ASI03 và ASI05 Hybrid bị `credential_missing` trong process này. **BLOCKED** cho ASI02 live action-level và ASI05 official/autonomous execution: thiếu reviewed action policy, correlated handler/effect evidence và agent-mediated trace. Trước live pilot cần quyền riêng của operator cho đúng một HTTP benign case hoặc một MCP canary, kiểm tra lại fresh connection, policy và evidence. Không có căn cứ để công bố accuracy mới hay so sánh Promptfoo action-level từ Phase 4.

# Phase 3A — Kiểm toán kiến trúc quy trình kiểm thử qua web

Ngày kiểm tra: 08/11/2026. **Chỉ thiết kế**, chưa triển khai Phase 3B. Phạm vi là working tree hiện tại tại `D:\SecAgent-W5-Judge`, không chỉ HEAD. Đã đọc mã và phân tích tĩnh YAML bằng `yaml.safe_load`; không chạy target, thử kết nối, gọi Pi, Docker, network hoặc bộ test. Số testcase dưới đây là kiểm kê tĩnh, không phải số testcase đã chạy hay đã được chứng minh tương thích.

Tài liệu liên quan: [đặc tả](web-testing-workflow-specification.md), [lộ trình](web-testing-workflow-roadmap.md), [thiết kế báo cáo](evaluation-report-specification.md), [dashboard](evaluation-dashboard-design.md). Các đề xuất mới được phân biệt với hành vi hiện có.

## 1. Luồng hiện có và điểm tái sử dụng

| Thành phần thực tế | Đường dẫn, symbol | Trạng thái và giới hạn |
|---|---|---|
| CLI native | `backend/scripts/run_native_smoke.py`: `parse_args`, `main`, `run_smoke`, `build_test_input`, `RecordingExecutor`, `build_summary` | Đã có. Một testcase mỗi lần; YAML target hoặc runtime URL; ghi `.secagent.json` bằng chế độ `x`, không ghi đè. `--prompt-file` bỏ qua payload chính thức, không phù hợp mặc định của web plan. |
| Runner | `backend/src/testing/runner.py`: `Runner.__init__`, `run`, `_run`, `_build_report` | Đã có. Resolve module → prepare → execute → observe → evaluate. Đồng bộ; trả `EvaluationResult`, có `last_report` và `report_sink`. Không có job queue, cancellation token hay callback tiến độ từng bước. |
| Executor | `backend/src/testing/executor.py`: `Executor.execute` | Đã có. `validate_target` rồi chọn adapter từ mapping injection. Validation fail có thể xảy ra **trước** HTTP request; `success=False` không chứng minh target đã nhận request. |
| Target model/load | `backend/src/core/models/target.py`: `TargetProfile`, `TargetInterface`; `backend/src/targets/loader.py`: `load_target`; `backend/src/targets/validator.py`: `validate_target` | Model có `capabilities`, `observability`, `credential_refs`, metadata. Đây là khai báo, không phải capability đã kiểm chứng. `interface.config` vẫn là dictionary rộng; validator không phải chính sách SSRF hoàn chỉnh. |
| Dynamic HTTP | `backend/src/targets/runtime.py`: `_url`, `build_runtime_target` | Chỉ `openai-chat`; private/loopback IP literal hoặc localhost; exact authorized origin; cấm userinfo/query/fragment, link-local/multicast và một số địa chỉ đặc biệt. Optional `/health` thực sự gửi GET, nên không được gọi trong preview. |
| Payload | `backend/src/payloads/loader.py`: `PayloadLoader.load_repository`; `renderer.py`: `PayloadRenderer.render` | Render `{{name}}` bằng biến, báo thiếu biến, không thực thi template code. Native `build_test_input` hiện yêu cầu đúng một payload reference và repository `payload/{category}.yaml`. |
| Testcase | `backend/src/testing/testcase_loader.py`: `TestCaseLoader.load`; `backend/src/core/models/testcase.py`: `TestCase`, `TestCaseTaxonomy` | Load một file; chưa có catalog web/selection nhiều ASI/compatibility service. Taxonomy và variables có thể chứa metadata cũ hoặc không đủ điều kiện vận hành. |
| Binding | `backend/src/testing/testcase_binding.py`: `bind_testcase_variables` | Tạo bản sao, merge variables, render rule parameters. Không được giả định native CLI tự bind tất cả trường hợp: `run_smoke` không gọi hàm này một cách tổng quát. |
| Observer | `backend/src/observers/response_observer.py`: `ResponseObserver.observe`; `core/models/{execution,observation,evidence}.py` | Giữ events thành `Evidence`, execution metadata; chỉ chép response completeness khi có giá trị; tool trace complete theo events. Không tự tạo agent audit từ câu trả lời. |
| Rule/Hybrid | `backend/src/evaluators/response_evaluator.py`: `ResponseEvaluator.evaluate`; `hybrid_evaluator.py`: `HybridEvaluator.evaluate`, `_sufficient_result` | Đã có. Kết quả deterministic có đủ cơ sở được ưu tiên; semantic chỉ khi cấu hình cho phép và effective result INCONCLUSIVE. Không ép mọi testcase gọi Judge. |
| Verdict | `backend/src/evaluators/verdict_resolver.py`: `validated_recommendation`, **`resolve_verdict`** | Đây là hàm resolver thực tế, không phải class mới cần tạo. Kiểm chứng recommendation; semantic PASS cần response complete; web baseline còn cần action scope và fetch; collector-required FAIL không thể chỉ dựa Judge. |
| Judge/config/budget | `backend/src/testing/evaluation_config.py`: `RunnerEvaluationConfig`, `BudgetedJudgeProvider`, `configured_evaluator` | Rule-only mặc định; live opt-in rõ; budget theo **vòng đời Runner**, reserve trước gọi, timeout/lỗi vẫn tiêu budget, không retry/reset tự động. Chưa là target-request budget của một chiến dịch nhiều testcase. |
| Judge request/provider | `evaluators/evaluation_request_builder.py`: `EvaluationRequestBuilder.build`; `integrations/external_evaluator/{skills,pi,validation}.py`: `SkillBundleLoader.load`, `PiEvaluatorProvider.evaluate`, `_invoke`, `parse_judge_response` | Trusted context và skill từ cấu hình testcase; evidence riêng. Pi có `--no-tools`, `--no-extensions`, `--no-skills`, `--no-prompt-templates`, output/timeout bounds. `expected_labels` là tập nhãn output hợp lệ, không phải human answer cần đưa vào prompt. |
| Collector lab | `backend/src/testing/web_fixture.py`: `WebFixture.bind`, `evidence`, `claim`; native `RecordingExecutor.execute` | Có binding/correlation và cửa sổ thu receipt cho GH-WEB. Phụ thuộc fixture do operator chuẩn bị; không phải collector cho mọi target. Không đưa arbitrary fixture path từ browser vào đây. |
| Reporting | `backend/src/reporting/normalizers.py`: `normalize_report_bytes`, `normalize_report_file`; `artifacts.py`; `aggregation.py`: `aggregate_reports`; `repository.py`: `DatasetManifest`, `load_dataset`; `api.py`: `create_app`, `main` | Đã có normalizer, integrity, aggregation và GET-only API. Dataset explicit, được nạp lúc startup; report mới không tự xuất hiện. Archived assessment không phải execution mới. |
| UI | `frontend/src/{App,Overview,Executions,ExecutionDetail,EvidenceViews,Comparisons}.tsx`, `api.ts`, `detailApi.ts` | Đã có reporting UI; chưa có target editor, preflight, test plan, start run hay active runs. Giữ nguyên các view này để đọc kết quả. |

Luồng cần giữ: catalog đọc testcase → binding có kiểm soát → PayloadRenderer → TestInput → **Runner → Executor → adapter → ResponseObserver → evaluator/resolver → report**. Web API tương lai chỉ chuẩn bị dữ liệu và điều phối, không sao chép evaluator hoặc tự suy ra verdict.

## 2. Protocol và mapping thực tế

### HTTP — đã thực thi được, chưa là web-safe cho mọi cấu hình

`backend/src/targets/adapters/http_adapter.py`, `HttpTargetAdapter.execute`, `_headers`, `_render_template`, `_to_execution_result` đọc URL/method/headers/body/response config. Body thay `{{input}}` bằng prompt. Response parser dùng đường dẫn tách bằng dấu chấm và index (ví dụ `choices.0.message.content`), không phải arbitrary JavaScript. Dynamic target tạo POST chat completions, model và user message; `trust_env=False`.

`backend/src/targets/adapters/http_evidence.py::reported_http_evidence` giữ khai báo tool và DVAA metadata dưới dạng target-reported, không nâng thành verified tool action. HTTP 200/finish_reason không thiết lập response completeness. `backend/src/tools/http/client.py::HttpClient.request` dùng httpx đồng bộ; nhánh client tự tạo không follow redirect. Client được inject có policy riêng cần review. Generic YAML vẫn cho HTTP methods GET/POST/PUT/PATCH/DELETE và mặc định có thể dùng environment proxy (`trust_env=True`). Không nên cho browser gửi nguyên config dictionary này.

### MCP — adapter hẹp, không phải full MCP client

`backend/src/targets/adapters/mcp_jsonrpc_adapter.py::McpJsonRpcTargetAdapter.execute` gửi HTTP POST JSON-RPC `tools/call`; lấy `parameters.tool_call.name/arguments`. Kiểm tra JSON-RPC id; chỉ đọc `result.content[0].text`, yêu cầu text chứa JSON object có boolean `success`. Adapter tạo `tool_call` và trace complete với scope `direct_request`.

Không thấy initialize/negotiation, `tools/list` discovery, sessions, SSE/streamable transport đầy đủ hoặc stdio process launcher. Native `build_test_input` còn gắn arguments cố định `{"command": rendered}` với biến `tool_name`: không phải mapping schema cho công cụ bất kỳ. Direct tool call do SecAgent phát không chứng minh agent tự chọn tool; scope `direct_request` không phải full agent-run trace. Không được quảng bá MCP tổng quát hay lấy trace này thay audit agent-origin cho ASI03/05.

### A2A — chưa triển khai

Registry/validator chỉ có `http/generic_http`, `mcp/generic_mcp_jsonrpc`. Không tìm thấy A2A adapter, Agent Card discovery, task lifecycle hay message mapping trong `backend/src` và scripts đã rà soát. UI tương lai hiển thị “Chưa hỗ trợ”, không gửi A2A request bằng schema chat HTTP.

## 3. Kiểm kê testcase và taxonomy

25 YAML tại `testcases/`, trong đó **19 testcase thuộc bốn category nghiên cứu**, không đồng nghĩa 19 case sẵn sàng chạy trên một target:

| ASI nội bộ | Category/path | ID hiện có | Đánh giá hiện tại |
|---|---|---|---|
| ASI01 | `testcases/goal_hijacking/` | GH-001, GH-002, GH-C01, GH-WEB-001, GH-WEB-C01 (5) | Cả 5 bật semantic `goal_hijacking`; GH-WEB-C01 strategy semantic, không rule; GH-WEB-001 có collector rule; ba GH còn lại có rule và hybrid. |
| ASI02 | `testcases/tool_misuse/` | TM-001, TM-002 (2) | Strategy action, tool_call rules; chưa bật semantic trong hai YAML. Có `tool-misuse.md` nhưng không có nghĩa mọi ASI02 case đã có trusted semantic contract. |
| ASI03 | `testcases/identity_privilege_abuse/` | IPA-001..003, IPA-C01..C03 (6) | Action rules, normalized violation events và authorization baseline; không semantic config. |
| ASI05 | `testcases/unexpected_code_execution/` | UCE-001..003, UCE-C01..C03 (6) | Action rules, sandbox/canary preflight; không semantic config. |

Ngoài phạm vi: PI-001..003 và SD-001, SD-002, SD-C01 (6). Không tự gộp prompt injection thành ASI01 hoặc disclosure thành ASI03. `reporting/normalizers.py::ASI` có mapping bốn category; catalog tương lai phải giữ mapping nhất quán, không lấy tên file suy ra taxonomy.

Lệch metadata cần hiển thị: GH-001/002 vẫn ghi `LLM01:2025`; GH-WEB ghi `ASI01:2026`; IPA/UCE attack ghi ASI03/ASI05; nhiều control không có taxonomy. Thiết kế dùng mapping category đã review, giữ taxonomy gốc và basis, báo xung đột thay vì sửa YAML âm thầm. `SemanticEvaluationConfig.skill` và `SkillBundleLoader.RUBRICS` chưa có ASI03/05; skill files hiện có goal-hijacking, tool-misuse, prompt-injection, sensitive-data-disclosure.

## 4. Guard đã có và khoảng trống quan trọng

- `IdentityPrivilegeAbuseAttackModule.prepare` tại `backend/src/attack_modules/identity_privilege_abuse/module.py`: cần actor khác owner, protected resource; `authorization_baseline` khớp identifiers, actor_denied/owner_allowed/delegated_identity_can_read và reference. Module kiểm tra cấu trúc, không tự kiểm chứng nguồn baseline. Browser không được tự khai “verified=true”.
- `UnexpectedCodeExecutionAttackModule.prepare` tại `backend/src/attack_modules/unexpected_code_execution/module.py`: sandbox id/reference và exact command allowlist; attack cần canary_command nằm trong allowlist. Cần adapter audit thật để phát violation event; plain HTTP response không đáp ứng.
- `ToolCallRule.match` tại `backend/src/evaluators/rules/tool_call.py`: positive tool event thành FAIL theo rule; absence PASS cần tool trace complete và safe keywords. Trust của adapter event là boundary quan trọng, không nhận event do browser tự dựng.
- Native CLI chưa cấp `TestInput.environment` cho baseline ASI03/sandbox ASI05 một cách tổng quát. Có module/YAML không đồng nghĩa native end-to-end sẵn sàng với mọi target.
- `Runner._build_report` tạo UUID lúc kết thúc; chưa có campaign id và child id trước dispatch. Chưa có durable job store hoặc tiến độ real-time. `report_sink` là điểm extension; lỗi lưu không được biến thành security verdict.
- Chưa có target catalog có quyền, policy giới hạn request toàn run, TTL plan, idempotency start, cancellation semantics hay run recovery.
- Credentials hiện resolve từ env theo `credential_refs`; không có vault/session-secret service. Chưa nên thêm raw secret editor phía web.
- Reporting API cố ý GET-only và snapshot cố định. Không thêm POST run/reload vào API này.

## 5. Bằng chứng kiểm thử và giới hạn cuộc audit

Đã xác định test modules để tái sử dụng: `backend/tests/test_{native_pipeline,executor,http_target_adapter,http_client,mcp_jsonrpc_target_adapter,mcp_tool_misuse_pipeline,runtime_targets,official_asi01_runner,asi03_asi05_attack_assets,hybrid_evaluator,external_evaluator_connector,reporting_api}.py`; frontend `src/{App,Detail,api}.test.*`, `browser-tests/dashboard.spec.ts`.

**Không chạy các test trong Phase 3A**. Các kết quả Phase 2D.2 là lịch sử đã báo cáo, không phải validation mới cho thiết kế workflow. Không thử reachability, capability discovery hay availability credentials/Judge. Không mở tài liệu protocol trên mạng. Những nhận định hỗ trợ protocol ở đây dựa trên mã local, không tuyên bố tuân thủ toàn bộ chuẩn MCP/A2A.

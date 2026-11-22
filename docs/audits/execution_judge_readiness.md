# Execution Judge readiness audit — SecAgent ASI05

Audit offline, 2026-11-19. **Kết luận: NOT_READY** cho Execution Judge ASI05 end-to-end trên DVAA CodeBot/ToolBot. Các thành phần adapter, evidence contract, Hybrid Judge, resolver và native reporting **đã tồn tại**, và một nhánh **ToolBot Lab synthetic** đã đi xuyên Runner → observer → verdict → report. Chưa có kết nối live, per-testcase, independently verified giữa hành động của Agent và ASI05 Judge. Điều này không thay đổi kết quả pilot CodeBot theo scope `response_command_artifact`.

Không gọi DVAA, Pi/DeepSeek hoặc replay. Chỉ đọc source/historical evidence và chạy tests offline có Fake Judge, MockTransport hoặc synthetic fixture. Không chỉnh production code, Policy, Skill hay reports.

## 1. Có module “Execution Judge” không?

Không tìm thấy module/class/function tên `execution_judge` hoặc `ExecutionJudge` trong `backend/src` (tìm `rg`). Chức năng tương đương hiện **phân tán**:

| Thành phần | Tình trạng source và runtime |
| --- | --- |
| `Executor.execute` | Có, chọn adapter theo `target.interface.adapter`, trả `ExecutionResult` ([executor.py:15–60](../../backend/src/testing/executor.py)). |
| `HttpTargetAdapter` + `reported_http_evidence` | Có; CodeBot chat path trả response text và target-reported metadata/declarations, `execution_verified=false` ([http_adapter.py:136–190](../../backend/src/targets/adapters/http_adapter.py), [http_evidence.py:23–70](../../backend/src/targets/adapters/http_evidence.py)). |
| `McpJsonRpcTargetAdapter` | Có; gửi direct `tools/call`, tạo `tool_request` và `target_tool_result`, không nâng `reported_success` thành verified effect ([mcp_jsonrpc_adapter.py:20–58,97–233](../../backend/src/targets/adapters/mcp_jsonrpc_adapter.py)). |
| `ResponseObserver` | Có; observer mặc định của Runner, chỉ chuyển events/response/HTTP execution metadata sang `Observation` ([response_observer.py:8–29](../../backend/src/observers/response_observer.py), [runner.py:31–45](../../backend/src/testing/runner.py)). |
| `ToolActionObserver` | Có, được cắm vào **offline synthetic ToolBot Lab**; kiểm tra receipt/effect theo execution, invocation, request ID, tool, args hash. Nó gắn `synthetic_mock=true`, `simulated_handler_effect`, không xác minh OS process ([tool_action_observer.py:21–115](../../backend/src/observers/tool_action_observer.py), [toolbot_lab_batch.py:282–292](../../backend/src/workflow/toolbot_lab_batch.py)). **Không được cắm vào CodeBot batches hoặc live ToolBot workflow.** |
| `EvidenceSourceStore` | Có, nhưng là operator snapshot facility riêng. Các capture luôn `target_reported_unverified`, `uncorrelated`, `action_eligible=false`, `external_judge_disclosure=forbidden` ([evidence_sources.py:251–272,309–324](../../backend/src/workflow/evidence_sources.py)); API collect chặn khi controlled run đang active ([api.py:417–429](../../backend/src/workflow/api.py)). **Không tích hợp Runner/Judge.** |
| `EvaluationRequestBuilder` | Có; lấy testcase/trusted context/Skill, response text và evidence qua `public_evidence_data`; loại raw arguments/results/headers ([evaluation_request_builder.py:22–90](../../backend/src/evaluators/evaluation_request_builder.py), [evidence.py:16–119](../../backend/src/core/models/evidence.py)). |
| `HybridEvaluator` + `PiEvaluatorProvider` | Có; deterministic trước, Pi chỉ khi semantic enabled và effective result INCONCLUSIVE. ASI05 gate hiện **chỉ** cho `response_command_artifact` + reviewed policy revision + complete response ([hybrid_evaluator.py:53–103,121–152](../../backend/src/evaluators/hybrid_evaluator.py), [pi.py:158–214](../../backend/src/integrations/external_evaluator/pi.py)). |
| `VerdictResolver` và `ToolCallRule` | Có; đối chiếu provenance/scope/correlation, phân biệt simulated effect và verified runtime effect. ASI05 branch lại chỉ là response verdict; action guards nằm ở `tool_misuse` ([verdict_resolver.py:13–40,163–212](../../backend/src/evaluators/verdict_resolver.py), [tool_call.py:59–99,128–188](../../backend/src/evaluators/rules/tool_call.py)). |
| Native report | Có; `Runner._build_report` lưu testcase ID, response, evidence bản public, Judge diagnostic, final verdict; workflow lưu summary/native report. Native normalizer chiếu evidence thành preview/report model ([runner.py:176–231](../../backend/src/testing/runner.py), [generic_imported_batch.py:739–774](../../backend/src/workflow/generic_imported_batch.py), [normalizers.py:122–159,246–279](../../backend/src/reporting/normalizers.py)). |

Không cần tạo Judge class mới chỉ vì thiếu tên `ExecutionJudge`. **Thiếu contract và đường truyền evidence đáng tin cho ASI05 execution scope.**

## 2. Runtime pipeline thực tế

```text
Historical CodeBot:
TestCase/Policy -> DirectChatDelivery -> Runner -> Executor -> HttpTargetAdapter
  -> HTTP response + target_reported events -> ResponseObserver
  -> Observation -> ResponseEvaluator -> HybridEvaluator [ASI05 response gate]
  -> EvaluationRequestBuilder -> PiEvaluatorProvider (khi được bật)
  -> validated_recommendation/resolve_verdict -> Runner report -> native report

Offline ToolBot Lab:
Pinned TM-002 -> Runner -> McpJsonRpcTargetAdapter -> MockTransport handler
  -> tool_request + target_tool_result -> ToolActionObserver
  -> correlated synthetic receipt/effect + tool_call/tool_trace
  -> ResponseEvaluator tool_call rule -> report [synthetic_mock]

EvidenceSourceStore:
Operator GET snapshot -> separate capture store
  X-> Runner / Observation / EvaluationRequestBuilder / Judge / native report
```

### Nơi evidence đi qua hoặc dừng lại

| Bước | Có gọi runtime? Dữ liệu vào → ra | Đi tiếp / lưu report? |
| --- | --- | --- |
| TestCase/Runner | CodeBot generic-import tạo ASI05 semantic testcase `response_command_artifact`; Runner chuẩn bị input và gọi Executor ([generic_imported_batch.py:730–756](../../backend/src/workflow/generic_imported_batch.py), [runner.py:68–117](../../backend/src/testing/runner.py)). | Testcase ID đi vào request/report; reviewed Policy là trusted context. |
| Adapter | CodeBot HTTP: output text + `http_response_metadata`; ToolBot MCP: direct request/target result ([http_adapter.py:136–190](../../backend/src/targets/adapters/http_adapter.py), [mcp_jsonrpc_adapter.py:172–233](../../backend/src/targets/adapters/mcp_jsonrpc_adapter.py)). | Target-reported metadata giữ `execution_verified=false`. HTTP/protocol success khác handler success. |
| Observer | Runner mặc định `ResponseObserver`; ToolBot Lab inject `ToolActionObserver` ([runner.py:31–45,119–125](../../backend/src/testing/runner.py), [toolbot_lab_batch.py:282–292](../../backend/src/workflow/toolbot_lab_batch.py)). | Lab receipt/effect chỉ đi tiếp khi IDs/hash khớp. Missing receipt không thêm verified evidence; malformed/mismatch gây observation error ([tool_action_observer.py:38–87](../../backend/src/observers/tool_action_observer.py)). |
| Evidence Store | Workflow API tạo store riêng và chỉ expose save/collect/capture routes ([api.py:101,390–441](../../backend/src/workflow/api.py)). | **Dừng tại capture store**; chưa có bridge vào `Observation`. Snapshot không eligible và disclosure bị cấm, nên không được nối thẳng sang Judge. |
| Request Builder | Lọc `Observation.evidence` bằng `public_evidence_data`, kèm response và metadata completeness ([evaluation_request_builder.py:58–90](../../backend/src/evaluators/evaluation_request_builder.py)). | Judge nhận normalized evidence thực sự **nếu observer đã cung cấp**; historical CodeBot chỉ có response/HTTP metadata. Arbitrary receipt fields bị loại. |
| Hybrid/Pi | Deterministic result đủ mạnh thì skip Judge; nếu không, ASI05 semantic gate yêu cầu complete response + reviewed response scope. Pi nhận request đã build; parser kiểm schema/citations ([hybrid_evaluator.py:53–152](../../backend/src/evaluators/hybrid_evaluator.py), [pi.py:168–214](../../backend/src/integrations/external_evaluator/pi.py), [validation.py:66–99](../../backend/src/integrations/external_evaluator/validation.py)). | Không có ASI05 execution-based semantic lane. Provider fault không thành security PASS/FAIL. |
| Resolver/report | Resolver giữ deterministic result trước; ASI05 citation phải là exact response span; `tool_misuse` có guard cho independent action/complete trace ([verdict_resolver.py:89–107,163–212](../../backend/src/evaluators/verdict_resolver.py)). Runner lưu public evidence/Judge/final verdict ([runner.py:176–231](../../backend/src/testing/runner.py)). | Report có provenance bản public, nhưng **không** là raw receipt store. Runner `run_id` chỉ được tạo lúc build report **sau evaluation** ([runner.py:68–80,187–205](../../backend/src/testing/runner.py)); chưa phải khóa sẵn cho live collector. |

**Đối chiếu artifact lịch sử:** 60/60 native reports CodeBot hai batch có đúng một `http_response_metadata` `target_reported` mỗi report, 0 event `execution_verified=true`, 60/60 response_complete, một `invalid_output`. Vì vậy Judge lịch sử không nhận độc lập tool trace/cmd-log/files snapshot. Nguồn mapping/hashes: `E:/KiemLaiSS1/asi05-human-adjudication/consensus-comparison-20261119/judge_comparison_14.csv` và `E:/KiemLaiSS1/asi05-human-adjudication/final-validation-20261119/curator/remaining_46_survey.csv`. Không suy từ việc report thiếu log rằng DVAA endpoint chưa từng được tác nhân nào khác gọi.

## 3. Phân biệt sáu mức chứng cứ

| Mức | Status | Căn cứ và giới hạn |
| --- | --- | --- |
| A. Command được nhắc trong văn bản | **SUPPORTED** | ASI05 Skill yêu cầu phân biệt quotation/refusal/code fence; Judge citation chỉ từ complete response ([unexpected-code-execution-response.md:3–29](../../evaluator_skills/security/vulnerabilities/unexpected-code-execution-response.md), [verdict_resolver.py:163–178](../../backend/src/evaluators/verdict_resolver.py)). Đây là semantic response assessment, không chứng minh no-action. |
| B. Actionable command artifact | **SUPPORTED** trong response scope | Classification `PROHIBITED_COMMAND_ARTIFACT` và exact response citation đã có; 14-case pilot đã kiểm định ở mức này. Không dùng để tuyên bố handler/OS đã chạy. |
| C. Tool invocation observed | **PARTIAL** | MCP adapter biết request do SecAgent gửi, HTTP tool_calls chỉ target declaration ([mcp_jsonrpc_adapter.py:172–230](../../backend/src/targets/adapters/mcp_jsonrpc_adapter.py), [http_evidence.py:31–70](../../backend/src/targets/adapters/http_evidence.py)). Không có chứng cứ CodeBot tự gọi tool; ToolBot direct request không phải agent choice. |
| D. Simulated handler action | **PARTIAL** | ToolBot Lab fixture có handler synthetic, receipt/effect và observer; DVAA ToolBot `execute` handler mô phỏng nhưng live log chưa được tích hợp/correlate ([toolbot_lab_batch.py:85–130,282–324](../../backend/src/workflow/toolbot_lab_batch.py), DVAA `/app/src/index.js:1778–1849`). |
| E. Verified sandbox effect | **PARTIAL** | Lab xác minh effect hash/identity, gắn `synthetic_mock`; DVAA `write_file` có sandbox filesystem effect theo source nhưng chưa có trusted per-run observer trong SecAgent ([tool_action_observer.py:54–115](../../backend/src/observers/tool_action_observer.py), DVAA `/app/src/index.js:1754–1775`). Không tương đương host OS execution. |
| F. Thiếu evidence → INCONCLUSIVE | **SUPPORTED có điều kiện** | Tool rule mode `absent` cần complete independent trace; target-reported success không đủ; missing/mismatched receipt không được nâng thành verified action ([tool_call.py:128–188](../../backend/src/evaluators/rules/tool_call.py), [verdict_resolver.py:179–212](../../backend/src/evaluators/verdict_resolver.py)). Chưa có complete live Agent-run trace để áp dụng cho ASI05 execution. |

## 4. Policy, provenance, correlation và nguy cơ sai kết luận

1. **ASI05 scope đang là response-only.** `HybridEvaluator` từ chối semantic ASI05 nếu `evaluation_scope != response_command_artifact`; resolver ASI05 yêu cầu response citation, không có action receipt gate ([hybrid_evaluator.py:84–103](../../backend/src/evaluators/hybrid_evaluator.py), [verdict_resolver.py:163–178](../../backend/src/evaluators/verdict_resolver.py)). Vì vậy không thể đổi tên report hiện tại thành execution verdict. Một verified action muốn chấm ở ASI05 cần reviewed testcase/Policy/Skill contract riêng.
2. **Run binding chưa thống nhất.** MCP direct request có request ID/args SHA/correlation reference; synthetic observer kiểm `execution_id` và `invocation_id` ([mcp_jsonrpc_adapter.py:172–230](../../backend/src/targets/adapters/mcp_jsonrpc_adapter.py), [tool_action_observer.py:47–95](../../backend/src/observers/tool_action_observer.py)). Nhưng Runner report `run_id` sinh sau evaluation; live observer chưa nhận cùng identity trước Target request. `EvidenceSourceStore` chỉ giữ hash các ID **do nguồn báo**, không có trusted testcase/run binding ([evidence_sources.py:309–324](../../backend/src/workflow/evidence_sources.py)).
3. **Trust level được phân biệt nhưng projection còn hẹp.** HTTP và MCP result luôn `target_reported`; synthetic fixture ghi `independent_observer` + `synthetic_mock` ([http_evidence.py:34–59](../../backend/src/targets/adapters/http_evidence.py), [mcp_jsonrpc_adapter.py:196–230](../../backend/src/targets/adapters/mcp_jsonrpc_adapter.py), [tool_action_observer.py:89–115](../../backend/src/observers/tool_action_observer.py)). `public_evidence_data` chỉ giữ verification semantics/correlation cho các source/kind đã allowlist, nhất là `local_tool_fixture`; live observer source mới sẽ mất một số fields trong Judge request và native report nếu không mở rộng projection có kiểm soát ([evidence.py:16–119](../../backend/src/core/models/evidence.py), [runner.py:200–205](../../backend/src/testing/runner.py)).
4. **False PASS risk:** không thấy log ≠ không có action. `ToolCallRule` mode `absent` đòi complete trace và safe response keyword; `VerdictResolver` cũng đòi complete trusted trace, nên rule hiện tại fail-closed ([tool_call.py:100–188](../../backend/src/evaluators/rules/tool_call.py), [verdict_resolver.py:189–201](../../backend/src/evaluators/verdict_resolver.py)). Nếu nối snapshot `/api/sandbox/cmd-log` trực tiếp và tự coi log rỗng là complete trace sẽ tạo false PASS; thiết kế v1 đang chặn điều đó ([evidence_sources.py:269–272](../../backend/src/workflow/evidence_sources.py)).
5. **False FAIL risk:** `ToolCallRule` chỉ FAIL với rule `present` được cấu hình cho tool cụ thể, `success=true`, independent verified action/scope; không tự FAIL vì mọi tool call ([tool_call.py:59–99](../../backend/src/evaluators/rules/tool_call.py)). Testcase tương lai phải chứa authorization boundary, action nào bị cấm và scope; nếu bind một tool hợp lệ thành “prohibited” theo tên בלבד thì rule có thể cho kết luận sai. `ResponseEvaluator` ưu tiên FAIL matched rule trước PASS ([response_evaluator.py:56–109](../../backend/src/evaluators/response_evaluator.py)).
6. **Target transport vs tool outcome:** MCP adapter có thể trả `ExecutionResult.success=true` khi JSON-RPC hợp lệ nhưng nested `reported_success=false`; `ResponseEvaluator` dùng `execution_success` làm gate transport, không phải OS/tool success ([mcp_jsonrpc_adapter.py:167–233](../../backend/src/targets/adapters/mcp_jsonrpc_adapter.py), [response_evaluator.py:28–53](../../backend/src/evaluators/response_evaluator.py)). New execution contract phải dùng verified handler/effect status riêng.
7. **Missing receipt after protocol failure:** `ToolActionObserver` hiện return ngay nếu `result.success=false` ([tool_action_observer.py:38–45](../../backend/src/observers/tool_action_observer.py)). Live handler có thể đã nhận request rồi transport lỗi; việc không thấy receipt không chứng minh không có attempt/effect. Cần observer/control trace được thu độc lập với success của response.
8. **Provider fault:** `HybridEvaluator` chỉ gọi Pi qua opt-in/budget và giữ INCONCLUSIVE khi fault, không dùng fault làm safety PASS ([evaluation_config.py:13–70](../../backend/src/testing/evaluation_config.py), [hybrid_evaluator.py:121–152](../../backend/src/evaluators/hybrid_evaluator.py), [verdict_resolver.py:74–108](../../backend/src/evaluators/verdict_resolver.py)).

## 5. Test coverage đã kiểm tra

Đã chạy **160/160 tests PASS**, gồm:

- 131 tests: `test_tool_action_observer.py`, `test_evidence_contract_phase1a.py`, `test_evidence_sufficiency_phase1b.py`, `test_evidence_sources.py`, `test_asi05_judge_correctness.py`, `test_hybrid_evaluator.py`.
- 29 tests: `test_toolbot_lab_batch.py::test_native_tm002_batch_evidence_and_reporting` và `test_runner_judge_integration.py`.

Phân loại coverage:

| Loại | Đã có | Chưa chứng minh |
| --- | --- | --- |
| Fake Judge / contract | ASI05 refusal/artifact/citation/incomplete/fault tests, hybrid gates ([test_asi05_judge_correctness.py:104–245](../../backend/tests/test_asi05_judge_correctness.py), [test_hybrid_evaluator.py](../../backend/tests/test_hybrid_evaluator.py)). Test ASI05 chặn subprocess/network ([test_asi05_judge_correctness.py:35–39](../../backend/tests/test_asi05_judge_correctness.py)). | Production Pi semantic accuracy trên execution traces. |
| Observer/evidence unit | Identity/hash mismatch, synthetic receipt/effect, provenance, absent trace, target claim downgrade ([test_tool_action_observer.py](../../backend/tests/test_tool_action_observer.py), [test_evidence_contract_phase1a.py:108–137](../../backend/tests/test_evidence_contract_phase1a.py), [test_evidence_sufficiency_phase1b.py](../../backend/tests/test_evidence_sufficiency_phase1b.py)). | Live DVAA handler-owned receipt/effect và concurrent Agent-run binding. |
| Source snapshot | `httpx.MockTransport` và socket-connect guard; kiểm cả DVAA fixture schemas, nhưng semantics vẫn uncorrelated ([test_evidence_sources.py:12–25,144–157](../../backend/tests/test_evidence_sources.py)). | Actual DVAA endpoint capture hoặc completeness. |
| End-to-end synthetic | ToolBot Lab đi từ mock handler tới native report, pinned synthetic effect; socket-connect bị cấm ([test_toolbot_lab_batch.py:25–53,96–139](../../backend/tests/test_toolbot_lab_batch.py)). Runner/Pi integration dùng fake process/provider ([test_runner_judge_integration.py:60–104](../../backend/tests/test_runner_judge_integration.py)). | **Không có live end-to-end CodeBot/ToolBot execution Judge test** trong bộ đã kiểm. |

Tests còn cần: live-observer fixture có producer khác target response; accepted/rejected/failed handler; before/after canary hash; complete zero-action trace; mismatched/stale/duplicate IDs; concurrent cases; transport failure sau handler entry; benign authorized tool call không FAIL; simulated effect không bị gắn “host OS execution”; invalid citation/provider fault giữ INCONCLUSIVE; report/Judge request chỉ chứa allowlisted sanitized fields.

## 6. Bảng triển khai tối thiểu

| Component | Current Status | Missing Functionality | Required Modification | Priority | Acceptance Test |
| --- | --- | --- | --- | --- | --- |
| Target contract / testcase | CodeBot response scope; ToolBot direct MCP synthetic TM-002 | Agent-mediated action và reviewed ASI05 execution scope | Chọn một flow Agent→tool sandbox có thể quan sát; thêm testcase/Policy/Skill **mới**, không sửa locked response pilot | P0 | Testcase không claim autonomous action khi chỉ có direct MCP; old 60 reports bất biến |
| Runtime identity / admission | Workflow có execution ID ở Lab, Runner report ID sinh muộn | Per-case ID sẵn trước Target call và collector binding | Plumb execution/testcase/request/invocation identity từ workflow tới adapter, observer, report; isolated one-run sandbox | P0 | Wrong/old/other-run receipt bị bác |
| Independent observer | `ToolActionObserver` synthetic-only | Live/simulated DVAA handler receipt, decision, effect, completeness | Tái sử dụng validation/hashing pattern; thêm live observer/producer riêng với explicit `simulated_handler_effect` hoặc `verified_runtime_effect`, không tự gắn `synthetic_mock` | P0 | Verified effect khác attempted/denied; no-action cần complete trace |
| EvidenceSourceStore | Operator snapshot, không action-eligible | Chỉ dùng như nguồn phụ/diagnostic, không tự nâng trust | Giữ capture tách biệt; nếu cần bridge, chỉ cho event đã có trusted producer/binding và review disclosure; không nối snapshot v1 thẳng vào Judge | P0 | `successful:true` trong snapshot vẫn INCONCLUSIVE |
| Adapter/Observer wiring | Generic HTTP dùng ResponseObserver; Lab inject ToolActionObserver | Live workflow inject observer đúng cho từng case | Dùng Runner observer injection; không chỉnh response-based path; thêm binding cho live flow ở `workflow/dispatch.py` hoặc workflow riêng | P1 | 1 case → 1 correlated observation; transport failure không xóa handler trace |
| Evidence projection / Judge request | `public_evidence_data` hẹp; builder nhận normalized events | Safe live receipt fields, trust level, effect level, completeness | Mở allowlist trong `core/models/evidence.py`; giữ raw command/content/credential ngoài request/report; builder dùng reviewed scope | P1 | Judge request có hash/ID/scope/status cần thiết, không có raw secret |
| Evaluator/resolver | Tool-misuse guard có; ASI05 chỉ response | ASI05 execution gate và PASS/FAIL policy | Thêm scoped ASI05 execution contract/gate sau khi Policy/Skill được review; reuse `HybridEvaluator`/resolver, không tạo Judge mới | P1 | Authorized action không FAIL; prohibited verified effect FAIL; incomplete/no receipt INCONCLUSIVE |
| Native reporting | Runner lưu public evidence và final verdict | Phân biệt attempt, simulated handler, verified effect; pin source hashes | Bổ sung fields allowlisted/normalizer + source provenance, correlation, effect hash, completeness | P2 | Report không diễn giải synthetic thành OS execution; historical report unchanged |
| Tests | 160 offline PASS | Live-like integration và negative controls | Thêm fixture protocol độc lập, unit + integration tests trước live pilot | P0–P2 | Matrix A–F và mismatch/fault/no-action đều qua gate |

**Trình tự:** (1) chốt scope và target action contract; (2) instrument handler/observer và identity trước request; (3) nối observation có trust vào Runner; (4) mở projection và reviewed evaluator gate; (5) native reporting; (6) offline adversarial tests; (7) chỉ sau đó mới xem xét live sandbox pilot. Không dùng verdict/consensus CodeBot response-based để làm nhãn execution.

## 7. Acceptance criteria và quyết định

Được coi là **READY** cho ASI05 execution Judge chỉ khi tất cả tiêu chí sau có bằng chứng:

1. Một Agent-facing flow thật phát tool invocation; direct ToolBot MCP được ghi riêng là `direct_request`.
2. Handler/effect receipt có producer, run/testcase/request/invocation binding, hash, status và explicit completeness; trước/sau sandbox effect được xác minh trong phạm vi ủy quyền.
3. Request Builder/Judge/report giữ đủ evidence đã chuẩn hóa và provenance; target-reported claim không bị nâng trust, synthetic không bị ghi là host OS execution.
4. Reviewed ASI05 execution Policy/Skill quy định authorized vs prohibited action, attempted vs handled vs effect, PASS/FAIL/INCONCLUSIVE; resolver chặn false PASS do log thiếu và false FAIL do tool hợp lệ.
5. Unit + integration tests offline bao gồm missing/mismatched evidence, provider fault, negative no-action control; native report và response-based pilot cũ không bị thay đổi.

**Hiện trạng: NOT_READY** cho production execution-based ASI05. Có thể nói **PARTIALLY_READY về hạ tầng** nhờ adapter, observer pattern, evidence validation, HybridEvaluator/resolver và synthetic Lab; chưa thể nói “Execution Judge hoạt động” trên CodeBot/ToolBot live. Các chức năng live action choice, trusted per-testcase correlation và complete execution trace là **NOT VERIFIED**.

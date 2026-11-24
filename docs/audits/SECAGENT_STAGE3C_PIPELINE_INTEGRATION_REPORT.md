# SECAGENT — BÁO CÁO NGHIỆM THU STAGE 3C
# SECURE MCP AGENT RUNTIME PIPELINE INTEGRATION (`GENERIC-MCP-AGENT`)

- **Phiên bản:** Stage 3C (`SECURE MCP AGENT RUNTIME PIPELINE INTEGRATION`)
- **Ngày hoàn thành:** 2026-11-22
- **Trạng thái nghiệm thu:** **`STAGE_3C_PASS`**
- **Repository:** `D:\SecAgent-W5-Judge`
- **Branch:** `Q/w5-external-judge`
- **Checkpoint gốc:** `5d144ffb8ff2a930f015fb1a7299e99e3953f1b8`

---

## 1. Architecture and Actual Data Flow

Stage 3C tích hợp lõi `McpAgentRuntime` (Stage 3B) vào pipeline thực thi chính thức của SecAgent thông qua đường chạy riêng biệt **`GENERIC-MCP-AGENT`** trên `GenericImportedBatchWorkflow`, giữ nguyên hoàn toàn ngữ nghĩa của **`GENERIC-DIRECT-CHAT`**:

```
ImportedBatchSelection / ImportedBatchStart (execution_path="mcp_agent_runtime")
  -> GenericImportedBatchWorkflow.preview() / .start()
     -> TargetCatalog validation (LLM openai-chat + MCP mcp-jsonrpc)
     -> McpAgentRuntimeBindingStore (reviewed revision, system_prompt_sha256, tool_catalog_sha256, budgets)
     -> BatchPlan + preview plan_id binding
  -> BatchOrchestrator.run() (sequential case loop)
     -> One-use ExecutionGrant (minted & exclusively claimed per case, pruned in finally)
     -> ExecutionBindingRegistry.execute_binding("GENERIC-MCP-AGENT", ...)
        -> WorkflowAgentExecutionGuard (preflight before EVERY LLM & MCP step)
        -> Runner -> RecordingExecutor -> Executor -> McpAgentRuntimeTargetAdapter
           -> McpAgentRuntime (HttpLlmChatClient + HttpMcpToolClient + ExecutionGuard)
        -> McpAgentExecutionObserver -> Observation (`agent_tool_intent`, `secagent_mcp_request`, `target_mcp_response`, `rejected_tool_call`, optional `HandlerReceipt`)
        -> HybridEvaluator / ResponseEvaluator -> build_execution_request() -> resolve_asi05_execution()
        -> persist_batch_case_report() -> Native Report (`native-<tc>-<run>.secagent.json`) + `run-summary.json`
```

Hợp đồng thiết kế trước khi sửa mã nguồn được ghi nhận tại [SECAGENT_STAGE3C_INTEGRATION_CONTRACT.md](file:///D:/SecAgent-W5-Judge/docs/audits/SECAGENT_STAGE3C_INTEGRATION_CONTRACT.md).

---

## 2. Files Created and Modified

### File tạo mới trong Stage 3C
| Đường dẫn | Vai trò |
| :--- | :--- |
| `docs/audits/SECAGENT_STAGE3C_INTEGRATION_CONTRACT.md` | Hợp đồng tích hợp nguồn (Phase 3C.1) trước khi chỉnh sửa production code. |
| `backend/src/workflow/mcp_agent_runtime_binding.py` | `ReviewedAgentRuntimeDraft`, `McpAgentRuntimeBindingStore` (lưu trữ review bất biến hai target + action policy) và `WorkflowAgentExecutionGuard`. |
| `backend/src/targets/adapters/mcp_agent_adapter.py` | `McpAgentRuntimeTargetAdapter` chuyển đổi `AgentRuntimeResult` sang `ExecutionResult` không chứa logic evaluator. |
| `backend/src/observers/mcp_agent_execution_observer.py` | `McpAgentExecutionObserver` kiểm định tương quan chặt `agent_run` / `agent_selected` và optional `HandlerReceipt`. |
| `backend/tests/test_stage3c_mcp_agent_integration.py` | Bộ kiểm thử tích hợp offline cuối-tới-cuối bao phủ toàn bộ 22 kịch bản Stage 3C. |
| `docs/audits/SECAGENT_STAGE3C_PIPELINE_INTEGRATION_REPORT.md` | Báo cáo nghiệm thu Stage 3C này. |

### File chỉnh sửa hẹp trong Stage 3C (11 files, +832/-65 dòng)
- `backend/src/targets/validator.py`: thêm `"agent": "mcp_agent_runtime"` vào `SUPPORTED_INTERFACE_ADAPTERS`.
- `backend/src/targets/adapters/__init__.py`: export `McpAgentRuntimeTargetAdapter`.
- `backend/src/observers/__init__.py`: export `McpAgentExecutionObserver`.
- `backend/src/core/models/evidence.py`: bổ sung allowlist `public_evidence_data()` cho các sự kiện `mcp_agent_runtime` và nguồn `asi05_agent_mcp_observer`.
- `backend/src/evaluators/asi05_execution.py`: hỗ trợ nguồn `asi05_agent_mcp_observer` (`attribution="agent_selected"`) và đối soát 1-1 với `secagent_mcp_request`.
- `backend/src/workflow/execution_bindings.py`: thêm tùy chọn `allow_variable_request_budget: bool = False` (mặc định `False`, giữ nguyên kiểm tra chặt `==` cho mọi binding cũ).
- `backend/src/workflow/catalog.py`: hỗ trợ optional `credential_env` có kiểm soát cho `mcp-jsonrpc` generic trong `make_profile`, giữ khóa `dvaa-toolbot-lab`.
- `backend/src/workflow/generic_imported_batch.py`: mở rộng `ImportedBatchSelection`/`ImportedBatchStart`, đăng ký `GENERIC-MCP-AGENT`, thêm preview/start/guard/execution `_run_agent_case` mà không làm thay đổi `GENERIC-DIRECT-CHAT`.
- `backend/src/workflow/api.py`: bổ sung thông điệp lỗi rõ ràng cho các mã chặn của `GENERIC-MCP-AGENT`.
- `backend/src/reporting/models.py` & `backend/src/reporting/normalizers.py`: mở rộng `ImportedProvenance` và `DETAILS` cho `GENERIC-MCP-AGENT` (`binding_id`, `adapter`, `delivery_surface`, metadata LLM/MCP, budget/usage).

**Không chỉnh sửa Stage 3B core (`backend/src/targets/runtimes/mcp_agent.py`)**, `ControlledDispatcher`, `BatchOrchestrator`, `McpActionWorkflow`, `frontend/`, hoặc `results/` & `frontend/artifacts/`.

---

## 3. Binding Registration and Protocol Separation

- `GenericImportedBatchWorkflow.registry` (`ExecutionBindingRegistry`) đăng ký đồng thời hai binding tách biệt:
  1. `"GENERIC-DIRECT-CHAT"`: `protocol="openai-chat"`, `adapter_family="generic_http"`, `request_budget=1`, `allow_variable_request_budget=False`.
  2. `"GENERIC-MCP-AGENT"`: `protocol="openai-chat+mcp-jsonrpc"`, `adapter_family="mcp_agent_runtime"`, `evidence_contract="trusted_agent_runtime_trace"`, `request_budget=7`, `allow_variable_request_budget=True`.
- Lựa chọn binding được điều khiển bởi trường tường minh `execution_path` (`"direct_chat"` mặc định vs `"mcp_agent_runtime"`), xác thực chéo giao thức `openai-chat` cho `target` và `mcp-jsonrpc` cho `mcp_target`.

---

## 4. Reviewed Configuration and `plan_id` Binding

- `McpAgentRuntimeBindingStore` lưu snapshot bất biến tại `<catalog.data_dir>/mcp-agent-bindings/` chứa:
  - Danh tính & revision SHA-256 của cả hai target (`llm_target_id`, `llm_profile_revision`, `llm_endpoint_sha256`, `model`, `llm_credential_alias` và `mcp_target_id`, `mcp_profile_revision`, `mcp_endpoint_sha256`, `mcp_credential_alias`).
  - `system_prompt` + `system_prompt_sha256`, `reviewed_tools` (validated bởi restricted JSON Schema subset của Stage 3B) + `tool_catalog_sha256`.
  - Giới hạn `max_model_calls` (`1..4`), `max_tool_calls` (`0..3`), `max_nested_requests=0`, timeout theo bước và tổng deadline, `authorized_actions`, `prohibited_actions`.
- `preview()` ràng buộc `plan_id` vào toàn bộ SHA-256 của dataset, cả hai target drafts, policy, `binding_id`, `revision_sha256`, `McpAgentRuntimeConfig.config_digest()`, `case_request_budget`, `items`, `evaluation_mode`, `asi_category`, `transport_mode`. Mọi thay đổi sau `preview()` đều bị từ chối trước `start()` hoặc ngay tại `WorkflowAgentExecutionGuard` trước bước mạng kế tiếp.

---

## 5. `ExecutionGrant` and Cancellation

- `WorkflowAgentExecutionGuard` triển khai `ExecutionGuard.check()` và chạy bắt buộc trước **mỗi** bước LLM completion và MCP `tools/call`:
  1. Kiểm tra hủy bỏ (`orchestrator.cancellation_requested()` kiểm tra `.active-batch` PID & file `cancel-requested.json`).
  2. Kiểm tra quyền sở hữu batch (`dispatcher._active`, `self._active_grant_id`, `.active-batch` chứa đúng `batch_run_id` và PID hiện tại).
  3. Kiểm tra `ExecutionGrant` chưa hết hạn (`datetime.now(timezone.utc) < grant.expires_at`).
  4. Kiểm tra `context.config_digest == started_digest` cùng live drift check trên dataset, testcase, catalog revisions và `McpAgentRuntimeBindingStore`.
  5. Kiểm tra endpoint được phép, tool trong `reviewed_tools`, và ngân sách bước còn lại.
- Chống replay 1-lần: `write_exclusive_json(self.root / f"grant-{grant.authorization_id}", ...)` và `submission-{submission_id}.json`.
- **An toàn 30-case sequential grant pool:** Mỗi case chỉ giữ tối đa `1` `ExecutionGrant` đang hoạt động; khối `finally` trong `_run_agent_case` và `_prune_grants()` trước khi admit case kế tiếp thu hồi mọi grant không còn active, bảo đảm `len(dispatcher.policy.grants)` luôn `<= 1` (không bao giờ chạm giới hạn `20` của `AdmissionPolicy` trên batch 30 case tuần tự).

---

## 6. Model/Tool Budget Accounting

- Với `GENERIC-MCP-AGENT`, mỗi case có `case_request_budget = max_model_calls + max_tool_calls` (`1 <= case_request_budget <= 7`), được đối soát chặt tại `ExecutionBindingRegistry` (`1 <= case.request_budget <= 7`), `_run_agent_case` (`case.request_budget == runtime_config.max_model_calls + runtime_config.max_tool_calls`), và `preview()` (`total_request_budget == len(testcase_ids) * case_request_budget`, giới hạn tối đa `700` chỉ riêng cho `mcp_agent_runtime`, giữ `<= 100` cho `direct_chat`).
- Số request thực tế `actual_requests = runtime_res.model_call_count + runtime_res.tool_call_count` được báo cáo đồng bộ qua `CaseResult.request_count`, `run-summary.json["target_request_count"]` và `runtime_snapshot["target_request_count"]`, khớp 100% kiểm tra toàn vẹn của `BatchOrchestrator._verify_imported_state()`.

---

## 7. Runner and Executor Integration

- `McpAgentRuntimeTargetAdapter` chuyển đổi `AgentRuntimeResult` -> `ExecutionResult` qua `Executor({"mcp_agent_runtime": adapter})` và `RecordingExecutor` trong `Runner.run()`:
  - Chỉ đánh dấu `ExecutionResult(success=True, status_code=200, response_complete=True)` khi `runtime_result.status == "completed"` và `runtime_result.response_complete is True`.
  - Mọi trạng thái `blocked`, `budget_exhausted`, `incomplete`, `timeout`, `error`, `cancelled` đều đặt `success=False, response_complete=False`, bảo toàn `output_text` (nếu có), mã lỗi rõ ràng và toàn bộ `events` từng phần (`partial trace`), không bao giờ biến thất bại thành hoàn thành hợp lệ.
  - Phân biệt rõ 3 định danh: `execution_id` (`test_input.id`), `run_id` (`AgentRuntimeResult.run_id`), và `tool_call_id` / `invocation_id`.

---

## 8. Trusted Observer Evidence

- `McpAgentExecutionObserver` (`source="asi05_agent_mcp_observer"` khi không có collector bên ngoài) kiểm định toàn chuỗi sự kiện từ `mcp_agent_runtime`:
  1. `agent_tool_intent` (`provenance="model_reported"`)
  2. `secagent_mcp_request` (`provenance="secagent_request"`)
  3. `target_mcp_response` (`provenance="target_reported"`)
  4. `HandlerReceipt` (`provenance="instrumented_target_handler"`, chỉ khi `ActionEvidenceCollector` được cấu hình và khớp chính xác `request_id`/`invocation_id`/`execution_id`/`arguments_sha256`/`result_sha256`).
- Luôn gắn `subject="agent_run"`, `attribution="agent_selected"`, `execution_verified=False`.
- Không bao giờ tự nâng cấp `tool_invocation` -> `simulated_execution` hoặc `sandbox_effect`, và từ chối mọi sự kiện `asi05_execution_*`/`handler_receipt` giả mạo có sẵn trong `result.events`.

---

## 9. ASI05 Action Validation and Limitations

- `evaluators/asi05_execution.py` và `core/models/evidence.py` giữ nguyên hoàn toàn các hợp đồng `direct_request` / `asi05_execution_fixture` / `instrumented_handler_receipt` và bổ sung đối soát cho `asi05_agent_mcp_observer`:
  - Bắt buộc `attribution == "agent_selected"`, `trace_completeness == "partial"`, `execution_level == "tool_invocation"`, `handler_status == "unverified"`, `effect_sha256 is None`.
  - Xác minh tương ứng 1-1 giữa mỗi `asi05_execution_action` và sự kiện `secagent_mcp_request` hợp lệ (`execution_id`, `invocation_id`, `tool_name`, `arguments_sha256`).
- Theo đúng `resolve_asi05_execution()`:
  - Hành động bị cấm ở ngưỡng `minimum_level="tool_invocation"` khi đã được SecAgent gửi MCP -> `FAIL` (`policy_violation=True`).
  - Hành động bị cấm ở ngưỡng `"simulated_execution"` hoặc hành động hợp lệ chỉ có bằng chứng `tool_invocation` (trace `partial`) -> `INCONCLUSIVE` (không bao giờ thổi phồng thành `PASS` hoặc `FAIL`).

---

## 10. Judge and Verdict Parity

- Duy trì ranh giới tách biệt giữa `response_command_artifact` và `execution_action`: với `asi_category="ASI05"` và `execution_path="mcp_agent_runtime"`, `HybridEvaluator` điều hướng vào nhánh đánh giá hành động xác định (`execution_action`), giữ `semantic_invoked=False`.
- Khi thực thi bị chặn (`blocked`), hết ngân sách (`budget_exhausted`), drift, hết hạn grant, hoặc thiếu bằng chứng -> `target_transport_unavailable` -> `INCONCLUSIVE` (hoặc `ERROR` ở chế độ rule-only chưa review policy), không biến request bị chặn thành `FAIL` giả.

---

## 11. Native Report Integrity

- Native Report lưu tại `native-<testcase_id>-<run_id>.secagent.json` cùng `run-summary.json` qua `persist_batch_case_report()`, ghi đầy đủ `execution_binding="GENERIC-MCP-AGENT"`, `llm_target_id`, `llm_profile_revision`, `model`, `system_prompt_sha256`, `mcp_target_id`, `mcp_profile_revision`, `tool_catalog_sha256`, `plan_id`, `config_digest`, `model_call_budget`, `tool_call_budget`, `model_call_count`, `tool_call_count`, `attribution="agent_selected"`, `evidence_source`, `trace_completeness`, `response_completeness`.
- Cả `Runner._build_report` và `sanitized(...)` đều loại bỏ giá trị `operator_secret`, LLM credential và MCP credential (đã kiểm chứng bằng kịch bản rò rỉ trong test #21), đồng thời `BatchOrchestrator._verify_imported_state()` và `reporting.normalizers.normalize_native_report()` đều xác thực thành công SHA-256 và schema `ImportedProvenance`.

---

## 12. Security-Negative Test Outcomes

Tất cả 8 hàm test trong `backend/tests/test_stage3c_mcp_agent_integration.py` (bao phủ trọn vẹn 22 kịch bản Stage 3C + `HandlerReceipt` correlation) đều **PASS (8/8, 0 warnings in 10.79s)**:
- `test_01_to_05_preview_start_multiturn_runner_and_native_report_end_to_end`: preview, start, tool selection, multi-turn `Runner`, 2-case batch, grant retirement (`0` grants left), `normalize_native_report`, SHA-256 integrity -> **PASS**.
- `test_06_07_08_unauthorized_and_drift_rejected_before_network`: unreviewed binding bị chặn với `0` network calls; mid-run binding/tool catalog drift dừng trước khi gửi MCP -> **PASS**.
- `test_09_10_11_grant_replay_expiry_and_mid_loop_cancellation`: replay `submission_id`, `grant_expired` giữa 2 turn, và hủy giữa LLM Turn 1 và MCP (`status="cancelled"`, `0` MCP calls) -> **PASS**.
- `test_12_13_budget_exhaustion_model_and_tool`: cạn kiệt ngân sách model & tool -> `INCONCLUSIVE`, giữ nguyên partial trace -> **PASS**.
- `test_14_15_16_concurrency_response_only_and_tool_vs_effect_verdict`: từ chối concurrency (`409`), response-only claim text (`0` MCP calls -> `missing_evidence`), phân biệt rạch ròi `tool_invocation` (`FAIL` ở ngưỡng `tool_invocation` vs `INCONCLUSIVE` ở ngưỡng `simulated_execution`) -> **PASS**.
- `test_17_18_forged_evidence_rejected_and_asi05_allowlist`: từ chối forged observer trace, sai `execution_id`, thiếu `secagent_mcp_request`, trùng `invocation_id`, sai provenance `target_reported`, sai `arguments_sha256`, và kiểm tra `public_evidence_data()` cắt lọc raw args -> **PASS**.
- `test_19_20_21_legacy_paths_unchanged_and_credential_redaction`: cô lập & che `[REDACTED]` cả hai credential LLM & MCP trong Native Report, `GENERIC-DIRECT-CHAT` chạy nguyên vẹn -> **PASS**.
- `test_22_correlated_handler_receipt_and_sequential_grant_pool_invariant`: từ chối `HandlerReceipt` sai `execution_id`, chấp nhận receipt khớp chính xác (`simulated_execution`, `execution_verified=False`) -> **PASS**.

---

## 13. Focused Regression Results

- Cú pháp, biên dịch bytecode (`py_compile`), kiểm tra AST dependency boundaries & `git diff --check`: **exit code 0** (`task-2039.log`).
- Bộ Stage 3C offline integration (`python -m pytest backend/tests/test_stage3c_mcp_agent_integration.py -v`): **8 passed in 10.79s** (`0` failed, `0` skipped, `0` warnings).
- Bộ ASI05/Evidence/Runner/Stage 3B (`task-1976.log`, 7 files): **110 passed in 4.76s** (`0` failed, `0` skipped).
- Bộ Workflow/Imported Batch/Bridge/Lifecycle (`task-2003.log`, 8 files): **109 passed in 224.03s (0:03:44)** (`0` failed, `0` skipped).

---

## 14. Full Backend Regression Results

Lệnh chạy sau chỉnh sửa `.py` cuối cùng: `python -m pytest backend/tests -q -rs` (`task-2040.log`):
- **Kết quả:** **`1683 passed in 422.64s (0:07:02)`** (`0` failed, `0` skipped, **exit code `0`**).
- Tăng chính xác `8` tests mới của Stage 3C từ baseline Stage 3B (`1675 passed`), không phát sinh regression nào trên toàn bộ hệ thống.

---

## 15. Known Limitations

1. Toàn bộ kiểm thử Stage 3C sử dụng mock offline (`httpx.MockTransport`) theo đúng phạm vi; chưa gửi request tới LLM hay DVAA MCP server thật.
2. Không có `ActionEvidenceCollector` ngoài, `McpAgentExecutionObserver` chỉ xác nhận được yêu cầu MCP do SecAgent gửi (`tool_invocation`, `partial` trace) và giữ `INCONCLUSIVE` thay vì suy diễn `simulated_execution` hoặc `sandbox_effect`.
3. Chưa thêm UI/HTTP CRUD endpoint riêng để tạo `McpAgentRuntimeBindingStore` từ frontend trong Stage 3C (frontend giữ nguyên theo phạm vi loại trừ); `McpAgentRuntimeBindingStore` được dùng qua service/store nội bộ và qua `/api/testing/batches/preview` + `/api/testing/batches`.

---

## 16. Readiness for Stage 3D

Hệ thống đã sẵn sàng cho **Stage 3D** (thử nghiệm batch ToolBot 30-case & end-to-end acceptance trên mock/local pipeline): đường chạy `GENERIC-MCP-AGENT` đã nối thông suốt Workflow -> `ExecutionGrant` -> `WorkflowAgentExecutionGuard` -> `McpAgentRuntime` -> `McpAgentExecutionObserver` -> `Runner`/`HybridEvaluator` -> Native Report/Archive normalizer với cơ chế thu hồi grant tuần tự (`<= 1` active grant) và đầy đủ các chốt bảo mật fail-closed.

# BÁO CÁO SỬA LỖI F1 TIỀN STAGE 3: KHẮC PHỤC RÒ RỈ `_active` TRƯỚC KHI LAUNCH WORKER

**Dự án:** SecAgent Framework (`D:\SecAgent-W5-Judge`)  
**Giai đoạn:** Pre-Stage-3 F1 Defect Fix (Gỡ chặn chuyển tiếp Stage 3B)  
**Ngày thực hiện:** 2026-11-22  
**Phán quyết nghiệm thu:** **`PRE_STAGE3_F1_PASS`**

---

## 1. Executive Summary

Đã khắc phục triệt để lỗi rò rỉ cờ `dispatcher._active = True` trước khi vào [`launch_batch_worker`](file:///D:/SecAgent-W5-Judge/backend/src/workflow/batch.py#L543-L597) trong [`OfflineBatchWorkflow.start`](file:///D:/SecAgent-W5-Judge/backend/src/workflow/offline_batch.py#L224-L259) (cùng 4 lớp con kế thừa: `Asi01BatchWorkflow`, `ToolBotLabBatchWorkflow`, `ResearchBotWebBatchWorkflow`, `MockWebBatchWorkflow`) mà không chạm bất kỳ thành phần `ExecutionGrant`, `BatchOrchestrator`, Judge, Evidence, Reporting, MCP Action hay Bridge `:7019` nào.

- **Nguyên nhân gốc & sửa đổi tối thiểu:** Di chuyển lệnh `self.dispatcher._active = True` từ trước bước dựng `rows` và `BatchPlan` xuống **sau** khi `plan = BatchPlan(...)` hoàn tất ngay trong khối `with self.dispatcher._lock:` (đồng bộ hoàn toàn với mẫu đã an toàn của [`GenericImportedBatchWorkflow.start`](file:///D:/SecAgent-W5-Judge/backend/src/workflow/generic_imported_batch.py#L508-L564)).
- **Kiểm chứng đầy đủ sau sửa đổi cuối:**
  - Bộ test tái hiện & hồi quy F1 [`test_pre_stage3_f1_active_leak.py`](file:///D:/SecAgent-W5-Judge/backend/tests/test_pre_stage3_f1_active_leak.py): chuyển từ **`2 failed, 1 passed`** (trước sửa) sang **`3/3 passed`**.
  - Bộ regression trọng tâm (9 file test gồm F1 + Stage 2B.2b + Offline/Subclass/Orchestrator/Dispatch, log [task-1766.log](file:///C:/Users/Quettye/.gemini/antigravity-cli/brain/6dd69e96-8654-4b5e-8611-302f06fd7c40/.system_generated/tasks/task-1766.log)): **`100 passed in 132.10s`** (exit code `0`).
  - Toàn bộ backend suite (`pytest backend/tests -q -rs`, log [task-1771.log](file:///C:/Users/Quettye/.gemini/antigravity-cli/brain/6dd69e96-8654-4b5e-8611-302f06fd7c40/.system_generated/tasks/task-1771.log)): **`1655 passed in 458.91s (0:07:38)`** (`0` failed, `0` skipped, exit code `0`; tăng đúng `3` test từ nền `1,652`).

---

## 2. Exact Root Cause & Source Lines

Trong [`backend/src/workflow/offline_batch.py`](file:///D:/SecAgent-W5-Judge/backend/src/workflow/offline_batch.py) trước khi sửa (`HEAD`/nền Stage 2B.2b tại `L227-249`):
1. Trong `with self._lock:` -> `with self.dispatcher._lock:`, dòng `L241` đặt `self.dispatcher._active = True`.
2. Ngay sau đó, khối `with self.dispatcher._lock:` thoát ra (`L242`), và dòng `L242-248` mới tạo `rows`, gọi `self._request_budget_for_case(...)`, dựng `BatchCase(...)` và `BatchPlan(...)`.
3. Nếu quá trình dựng `BatchCase` hoặc `BatchPlan` (hoặc hàm `_request_budget_for_case`) ném ngoại lệ **trước** dòng `L249` (`launch_batch_worker(...)`):
   - `launch_batch_worker()` **chưa từng được gọi**, nên cơ chế `except BaseException: release_execution_state()` trong `launch_batch_worker` không thể chạy;
   - `self.dispatcher._active` bị kẹt vĩnh viễn ở `True` mặc dù không có `Thread` worker nào từng được tạo (`self._worker` vẫn là `None` hoặc thread cũ đã kết thúc).

*(Lưu ý đối chiếu: [`GenericImportedBatchWorkflow.start`](file:///D:/SecAgent-W5-Judge/backend/src/workflow/generic_imported_batch.py#L508-L564) không mắc lỗi này vì đã dựng xong `BatchPlan` ở `L509-539` rồi mới đặt `self.dispatcher._active = True` ở dòng cuối `L564` trong `with self.dispatcher._lock:`.)*

---

## 3. Before / After Reproduction

Tạo trước [`backend/tests/test_pre_stage3_f1_active_leak.py`](file:///D:/SecAgent-W5-Judge/backend/tests/test_pre_stage3_f1_active_leak.py) (`259` LOC, `3` tests) và chạy trước khi sửa `offline_batch.py`:

- **Trước khi sửa (`pytest backend/tests/test_pre_stage3_f1_active_leak.py -v`):** **`2 failed, 1 passed in 1.59s`**
  1. `test_f1_plan_construction_failure_does_not_leak_dispatcher_active` — **FAILED**: khi inject `RuntimeError("injected BatchPlan failure")` vào `offline_batch.BatchPlan`, `assert dispatcher._active is False` thất bại (`assert True is False` tại `test_pre_stage3_f1_active_leak.py:139`).
  2. `test_f1_case_budget_failure_in_asi01_subclass_recovers_cleanly` — **FAILED**: trên lớp con `Asi01BatchWorkflow`, khi inject `ValueError("injected budget failure")` vào `_request_budget_for_case`, `assert dispatcher._active is False` thất bại (`assert True is False` tại `test_pre_stage3_f1_active_leak.py:223`).
  3. `test_f1_simultaneous_submissions_cannot_both_acquire_execution_ownership` — **PASSED**: hai thread gọi đồng thời `start()` qua `threading.Barrier(2)` chỉ có 1 thread thắng và 1 thread bị chặn `Another controlled execution is active.`.
- **Sau khi sửa (`offline_batch.py:241-248`):** Cả **3/3 PASSED** trong [`task-1766.log`](file:///C:/Users/Quettye/.gemini/antigravity-cli/brain/6dd69e96-8654-4b5e-8611-302f06fd7c40/.system_generated/tasks/task-1766.log).

---

## 4. Production Diff ([`backend/src/workflow/offline_batch.py:239-249`](file:///D:/SecAgent-W5-Judge/backend/src/workflow/offline_batch.py#L239-L249))

```diff
                 except FileExistsError:
                     raise BatchRejected("Duplicate batch submission.") from None
-                self.dispatcher._active = True
-            rows = {r["testcase_id"]: r for r in preview["items"]}
-            plan = BatchPlan(selection.target.target_id, selection.target.profile_revision,
-                selection.target.policy_ref, selection.evaluation_mode,
-                tuple(BatchCase(r["testcase_id"], r["name"], r["asi_category"],
-                    r["asset_sha256"], r["input_sha256"],
-                    self._request_budget_for_case(r["testcase_id"]) if r["status"] == "ready" else 0)
-                    for r in preview["items"]), selection.total_request_budget)
+                rows = {r["testcase_id"]: r for r in preview["items"]}
+                plan = BatchPlan(selection.target.target_id, selection.target.profile_revision,
+                    selection.target.policy_ref, selection.evaluation_mode,
+                    tuple(BatchCase(r["testcase_id"], r["name"], r["asi_category"],
+                        r["asset_sha256"], r["input_sha256"],
+                        self._request_budget_for_case(r["testcase_id"]) if r["status"] == "ready" else 0)
+                        for r in preview["items"]), selection.total_request_budget)
+                self.dispatcher._active = True
         return launch_batch_worker(
```

- **Tổng thay đổi mã production:** Đúng 1 file [`offline_batch.py`](file:///D:/SecAgent-W5-Judge/backend/src/workflow/offline_batch.py), net `+0` LOC (`259` LOC giữ nguyên).

---

## 5. Lock & Concurrency Analysis

1. **Bảo toàn biên đồng bộ `self._lock` và `self.dispatcher._lock`:** Cả `rows` lẫn `plan = BatchPlan(...)` đều được dựng bên trong `with self._lock:` và `with self.dispatcher._lock:` trước khi gán `self.dispatcher._active = True` (không đẩy `_active = True` ra ngoài lock). Do `_request_budget_for_case` trên cả `OfflineBatchWorkflow`, `Asi01BatchWorkflow`, `ResearchBotWebBatchWorkflow` và `MockWebBatchWorkflow` đều là truy xuất bộ nhớ thuần không khóa/không I/O, không phát sinh đảo thứ tự lock hay deadlock với `RLock` (`self.dispatcher._lock`).
2. **Triệt tiêu khoảng trống giữa `_active = True` và `launch_batch_worker()`:** `self.dispatcher._active = True` là câu lệnh cuối cùng trong khối lock ngay trước `return launch_batch_worker(...)`. Không có biểu thức có thể ném lỗi nào nằm giữa `_active = True` và khối `try ... except BaseException:` bên trong `launch_batch_worker`.
3. **Chống tranh chấp đồng thời:** Hai submission đồng thời luôn bị tuần tự hóa bởi `self._lock -> self.dispatcher._lock`; submission thứ hai luôn thấy `dispatcher._active == True` nếu submission thứ nhất đã dựng plan thành công và ném `BatchRejected("Another controlled execution is active.")`.
4. **Không xóa `_active` khi worker có thể còn sống:** Timeout `started.wait(5.0)` bên trong `launch_batch_worker` vẫn fail-closed giữ nguyên `_active = True` cho tới khi worker thực sự thoát ở `finally:`.

---

## 6. Submission Idempotency & Anti-Replay Behavior

- Lệnh `write_exclusive_json(submission, {"batch_run_id": identity, "plan_id": preview["plan_id"], "submitted_at": ...})` **giữ nguyên vị trí thực thi trước bước dựng `BatchPlan`**.
- Do đó, khi dựng `BatchPlan` hoặc `Thread.start()` gặp lỗi:
  - File `submission-<submission_id>.json` vẫn tồn tại hợp lệ trên đĩa với đủ 3 khóa `batch_run_id`, `plan_id`, `submitted_at`;
  - Gửi lại cùng `submission_id` tiếp tục bị từ chối với `BatchRejected("Duplicate batch submission.")`;
  - Gửi một `submission_id` mới hợp lệ ngay lập tức được chấp nhận và chạy hoàn tất bình thường.

---

## 7. Regression & Static Checks Results

- **Syntax & Import Boundaries (`task-1766.log`):**
  - `python -m py_compile backend/src/workflow/offline_batch.py backend/tests/test_pre_stage3_f1_active_leak.py`: Exit code `0`.
  - AST `workflow` import cycle scan: `cycles: []`.
  - AST production-to-script scan (`backend/src/`): `script_refs: []`.
  - `git diff --check`: Exit code `0`.
- **Focused Offline Suite (`task-1766.log`, 9 test modules):**
  - `test_pre_stage3_f1_active_leak.py` (3/3), `test_stage2b2b_worker_lifecycle.py` (7/7), `test_offline_batch_api.py`, `test_asi01_batch.py`, `test_toolbot_lab_batch.py`, `test_researchbot_web_batch.py`, `test_web_mock_batch.py`, `test_batch_orchestrator.py`, `test_workflow_dispatch.py`:
  - **Kết quả:** **`100 passed in 132.10s (0:02:12)`** (`0` failed, `0` skipped, exit code `0`).
- **Full Backend Pytest Suite (`pytest backend/tests -q -rs`, log [`task-1771.log`](file:///C:/Users/Quettye/.gemini/antigravity-cli/brain/6dd69e96-8654-4b5e-8611-302f06fd7c40/.system_generated/tasks/task-1771.log)):**
  - **Kết quả:** **`1655 passed in 458.91s (0:07:38)`** (`0` failed, `0` skipped, exit code `0`).
  - Baseline Stage 2B.3 (`1,652`) + F1 mới (`3`) = **`1,655 passed`**.

---

## 8. Remaining Limitations & Scope Compliance

- Kịch bản tái hiện F1 được tạo bằng fault injection nội bộ (`monkeypatch` vào `offline_batch.BatchPlan` và `_request_budget_for_case`), dùng để chứng minh tính đúng đắn phục hồi trạng thái trước launch — **không** tuyên bố khả năng khai thác từ bên ngoài.
- Toàn bộ kiểm thử chạy ngoại tuyến bằng `MockTransport` / loopback socket blocker (`forbid_real_network`).
- Tuân thủ 100% giới hạn không sửa `ExecutionGrant`, `_owned_grants`, `BatchOrchestrator`, Hybrid Judge, Evidence, Reporting, `McpActionWorkflow`, Stage 3A contract, Bridge `:7019`, Frontend, và không bắt đầu Stage 3B hay chạy lệnh Git thay đổi lịch sử.

---

**Final Verdict:** **`PRE_STAGE3_F1_PASS`**

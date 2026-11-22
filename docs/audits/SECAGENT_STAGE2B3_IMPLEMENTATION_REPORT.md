# BÁO CÁO TRIỂN KHAI STAGE 2B.3: TÁI CẤU TRÚC AN TOÀN THỰC THI CASE TRONG `GenericImportedBatchWorkflow`

**Dự án:** SecAgent Framework (`D:\SecAgent-W5-Judge`)  
**Giai đoạn:** Stage 2B.3 — Safe Generic Imported Workflow Case-Execution Refactor (Bước cuối Stage 2B trước Stage 3)  
**Ngày thực hiện:** 2026-11-22  
**Phán quyết nghiệm thu:** **`STAGE_2B3_PASS`**

---

## 1. Executive Summary

Stage 2B.3 đã hoàn tất kiểm toán chi tiết trách nhiệm thực thi và tái cấu trúc tối thiểu, bảo toàn 100% hành vi cho [`GenericImportedBatchWorkflow._run_case`](file:///D:/SecAgent-W5-Judge/backend/src/workflow/generic_imported_batch.py#L625-L889) tại [`backend/src/workflow/generic_imported_batch.py`](file:///D:/SecAgent-W5-Judge/backend/src/workflow/generic_imported_batch.py).

- **Đo đạc thực tế trước refactor:** `_run_case` hiện có **`317` LOC** (`L522-838`, giảm so với ước tính lịch sử ~349 LOC vì Stage 2B.1a/1b/1c đã trích xuất `write_exclusive_json`, `persist_batch_case_report` và bỏ key `"model"` trùng lặp).
- **Trích xuất có chọn lọc (2 helper thuần, không tạo lớp trừu tượng/framework mới):**
  1. [`_build_asi03_semantic_testcase`](file:///D:/SecAgent-W5-Judge/backend/src/workflow/generic_imported_batch.py#L58-L117) (`5` tham số bất biến) — gom 35 dòng dựng `trusted_context` và `EvaluationConfig(strategy="semantic")` cho ASI03 (`asi03_policy` và `asi03_contract`).
  2. [`_build_asi05_semantic_testcase`](file:///D:/SecAgent-W5-Judge/backend/src/workflow/generic_imported_batch.py#L120-L158) (`4` tham số bất biến) — gom 21 dòng dựng `trusted_context` và `EvaluationConfig(strategy="semantic")` cho ASI05 (`asi05_policy`).
- **Quyết định có chủ đích KHÔNG trích xuất các khối dễ gây bùng nổ tham số hoặc che khuất ranh giới bảo mật:** Giữ nguyên tại chỗ trong `_run_case` phần cấp/tiêu thụ grant `_grant()`/`write_exclusive_json`, hàm TOCTOU `before_request()` (`L653-685`), `Runner.run()`, ranh giới redaction `sanitized()` (`L822-823`), và 2 dict literal phẳng 1 cấp `runtime_snapshot` (`L786-820`) và `imported_provenance` (`L829-867`) vốn phụ thuộc tới `14–20` biến cục bộ.
- **Đối chiếu parity BEFORE/AFTER (`stage2b3_before.json` vs `stage2b3_after.json`):** Khớp 100% trên cả 4 kịch bản (`unclassified_rule_only`, `asi03_contract_hybrid`, `asi03_policy_hybrid`, `asi05_policy_hybrid`) về mọi trường `CaseResult`, `run-summary.json`, `report.json` (chỉ trừ UUID ngẫu nhiên mới của `policy_id`/`contract_id` sinh lại mỗi run tạm và hash `plan_id`/`request_sha256` dẫn xuất trực tiếp từ các UUID đó).
- **Kiểm chứng sau chỉnh sửa cuối:**
  - Bộ test mới [test_stage2b3_case_helpers.py](file:///D:/SecAgent-W5-Judge/backend/tests/test_stage2b3_case_helpers.py): **3/3 PASSED**.
  - Bộ test trọng tâm Section 10 (18 file test): **`269 passed in 336.60s`** (exit code `0`, log [task-1675.log](file:///C:/Users/Quettye/.gemini/antigravity-cli/brain/6dd69e96-8654-4b5e-8611-302f06fd7c40/.system_generated/tasks/task-1675.log)).
  - Toàn bộ backend test suite (`pytest backend/tests -q -rs`): **`1,652 passed in 556.11s`** (`0` failed, `0` skipped, exit code `0`, log [task-1679.log](file:///C:/Users/Quettye/.gemini/antigravity-cli/brain/6dd69e96-8654-4b5e-8611-302f06fd7c40/.system_generated/tasks/task-1679.log)).

---

## 2. Working Tree Baseline

- **Repository:** `D:\SecAgent-W5-Judge`
- **Git HEAD:** `ce1c776fd7b939b0cd705ece87320a67a1885ac8`
- **Môi trường:** `Python 3.13.7`, `pytest-9.0.3`
- **Trước Stage 2B.3:** `generic_imported_batch.py` dài `838` LOC sau Stage 2B.2b; `git diff --check` exit code `0`; không thực hiện `reset`, `clean`, `stash`, `restore`, `checkout`, `commit` hay `push`.

---

## 3. Original `_run_case` Execution Map (`L522-838` Trước Refactor, `317` LOC)

| Khối | Dòng gốc | Chức năng & Tác dụng phụ | Đầu vào / Đầu ra | Kiểm tra phân quyền / Provenance / Ngoại lệ | Đánh giá tách |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1. Grant & Cancel Gate** | `L524-534` | Gọi `_grant()`, kiểm `cancellation_requested()`, ghi độc quyền `grant-<id>` | `selection, case, execution_id` -> `grant` hoặc `CaseResult("cancelled")` | C4 lazy grant, giải phóng `_active_grant_id` & `_prune_grants()`, `BatchRejected` | **Giữ nguyên** (ranh giới C4) |
| **2. Snapshot & Target Drift** | `L537-547` | Đọc `ds, imported_case`, đối chiếu SHA256 snapshot đã duyệt & `_target_error`, tạo `preset, profile` | `ds, imported_case, preset, profile` | `BatchRejected("imported_authorized_snapshot_changed")` | **Giữ nguyên** (`11` dòng kiểm bảo mật trước I/O) |
| **3. TOCTOU `before_request` + Client** | `L549-595` | Khai báo `cancelled`, closure kiểm drift/expiry/ASI03/ASI05 ngay trước dispatch; tạo `OneRequestHttpClient` & `RecordingExecutor` | `cancelled, client, executor` | Nâng `HttpClientError` trước khi chạm transport nếu grant hết hạn, dataset/contract/policy đổi hoặc bị hủy | **Giữ nguyên** (chứa `nonlocal cancelled` & TOCTOU security check) |
| **4. Base Case & Policy Verify** | `L597-638` | Dựng `native_testcase`/`test_input` mặc định; khớp `_native_match`; kiểm `asi03_policy`, `asi05_policy`, `asi03_contract`; tính `asi03_semantic`, `asi05_semantic` | `native_binding, asi03_*, asi05_*` | `BatchRejected("*_changed")` khi policy/contract trôi so với lúc preview/start | **Giữ nguyên** (xác thực drift) |
| **5. Semantic Context Builders** | `L639-700` | Rẽ nhánh chọn deep copy `native_binding` HOẶC dựng `TestCase` semantic `trusted_context` cho `asi03_semantic` (`L642-677`, `36` dòng) / `asi05_semantic` (`L678-699`, `22` dòng) | `(case, ds, imported_case, policy/contract)` -> `native_testcase, test_input` | Không có I/O, không exception, chỉ đóng gói dữ liệu đã được khối 4 xác thực | **Đáng tách** thành 2 helper thuần `4–5` tham số |
| **6. Runner Execution** | `L701-720` | Dựng `Runner` (gắn `hybrid_config`, `judge_provider`, `require_complete_response_*`), chạy `runner.run(...)`, check `cancelled` | `result, runner.last_report` | Giữ cổng `require_complete_response_for_semantic=True`, `for_pass=True`, `for_fail=True`; trả `cancelled` nếu hủy trước request | **Giữ nguyên** (điểm tích hợp Runner & test mock) |
| **7. Dir & Summary Base + `runtime_snapshot`** | `L721-769` | `stage("saving_report")`, `run_dir.mkdir(exist_ok=False)`, `build_summary()`, gắn `provenance` (`synthetic_mock` vs `target_observation`), dựng `summary["runtime_snapshot"]` (`34` dòng) | `run_id, run_dir, summary` | Phân tách `synthetic_mock` vs `target_observation`; xây dựng `runtime_snapshot` **trước** redaction | **Giữ nguyên** (`14` biến đầu vào cho dict phẳng) |
| **8. Secret Redaction & Post-Restore** | `L771-777` | Gọi `sanitized(summary, secrets_to_remove=secret_values)`, khôi phục `dataset_id`, `testcase_id` hậu redact | `summary` | **Ranh giới bảo mật redaction** — không được di chuyển hay gộp qua biên này | **Giữ nguyên** |
| **9. `imported_provenance` & Persist** | `L778-834` | Dựng `summary["imported_provenance"]` (`39` dòng, `33` keys), gọi `persist_batch_case_report(...)` | `CaseResult` | Ghi SHA256, `run-summary.json`, `.secagent.json` với `"x"` + `os.fsync`; phụ thuộc ~20 biến | **Giữ nguyên** (`20` biến; Stage 2B.1b đã tách phần persist đĩa) |
| **10. Grant `finally:` Cleanup** | `L835-838` | `with self.dispatcher._lock: _active_grant_id = None; _prune_grants()` | Giải phóng grant | Chạy mọi đường thoát kể cả ngoại lệ | **Giữ nguyên** (ranh giới C4) |

---

## 4. Responsibility Analysis: Nghiệp vụ / Bảo mật vs Chuẩn bị dữ liệu cơ học

- **Các bước kiểm tra bảo mật & điều khiển I/O bất biến (phải giữ nguyên thứ tự 1 -> 10):**
  `_grant()` -> check cancel -> ghi `grant-<id>` độc quyền -> verify dataset/snapshot hash -> tạo `before_request` TOCTOU -> verify ASI03/ASI05/contract drift -> `Runner.run()` (trong đó `OneRequestHttpClient` gọi `before_request` trước I/O) -> `sanitized()` -> `persist_batch_case_report()` -> `finally: _prune_grants()`.
- **Phần cơ học thuần túy làm phình thân `_run_case`:**
  Dựng `trusted_context` và cấu hình `EvaluationConfig(strategy="semantic")` cho `asi03_semantic` (36 dòng) và `asi05_semantic` (22 dòng). Hai nhánh này làm tăng lồng ghép (`if asi03_policy:` / `else:`) ngay giữa đường thực thi, trong khi đầu vào hoàn toàn bất biến và chỉ gồm `4–5` đối tượng.

---

## 5. Extraction Candidates Evaluated

1. **Candidate A (Đã chọn — tách làm 2 helper nhỏ cùng trách nhiệm):**
   - [`_build_asi03_semantic_testcase`](file:///D:/SecAgent-W5-Judge/backend/src/workflow/generic_imported_batch.py#L58-L117) (`5` tham số)
   - [`_build_asi05_semantic_testcase`](file:///D:/SecAgent-W5-Judge/backend/src/workflow/generic_imported_batch.py#L120-L158) (`4` tham số)
2. **Candidate B (Bị loại):** Tách `_build_runtime_snapshot` và `_build_imported_provenance`.
3. **Candidate C (Bị loại):** Tách `before_request` / `_ensure_live_target_consistent` hoặc toàn bộ đuôi lưu báo cáo.

---

## 6. Reasons for Selected / Rejected Extractions

- **Vì sao chọn Candidate A (`_build_asi03_semantic_testcase` & `_build_asi05_semantic_testcase`):**
  - Mỗi hàm có đúng **1 trách nhiệm rõ ràng**, thuần túy (pure function), không chứa logic authorization (vì kiểm tra drift `asi03_policy`, `asi03_contract`, `asi05_policy` vẫn nằm ngay trước lệnh gọi tại `_run_case` `L717-741`).
  - Tham số nhỏ (`5` và `4`), không dùng cờ rẽ nhánh, không truyền dict khả biến chung, không phát sinh dataclass trung gian dư thừa.
  - Giảm khối semantic ở giữa `_run_case` từ 62 dòng xuống còn **9 dòng** (`L742-750`), giúp người đọc thấy ngay 4 chế độ đánh giá (`native_binding`, `asi03_semantic`, `asi05_semantic`, mặc định `direct_chat` unclassified).
- **Vì sao loại Candidate B (`runtime_snapshot` & `imported_provenance`):**
  - Phân tích thực tế cho thấy `runtime_snapshot` dùng **14 biến** cục bộ và `imported_provenance` dùng **20 giá trị** khác nhau từ `_run_case` và `self`. Tách ra hàm riêng sẽ buộc phải tạo signature `14–20` tham số hoặc phát minh một dataclass chứa tham số dùng một lần — vi phạm trực tiếp tiêu chí Phase 2 (*"Do not extract a block if doing so requires excessive parameters... or unnecessary abstractions"*). Hơn nữa, giữ `sanitized(summary, ...)` nằm giữa hai dict literal này trong `_run_case` giúp chứng minh trực quan thứ tự redaction.
- **Vì sao loại Candidate C (`before_request` & report persist wrapper):**
  - `before_request` đóng gói biến closure `nonlocal cancelled` và rà soát 5 điều kiện bảo mật ngay trước `http_client` gửi request; giữ trong `_run_case` bảo toàn minh bạch TOCTOU. Phần persist đuôi đã được hợp nhất thành công ở Stage 2B.1b qua `persist_batch_case_report`.

---

## 7. Before-Refactor Behavioral Baseline

Trước khi sửa bất kỳ dòng mã nào:
1. Chạy toàn bộ bộ test nền Stage 2B.3 (`test_generic_imported_batch.py`, `test_imported_live_local.py`, `test_b47_remediation.py`, `test_asi03_contracts.py`, `test_dataset_import.py`, `test_stage2b1b_report_persistence.py`, `test_stage2b1c_validation_parity.py`, `test_stage2b2b_worker_lifecycle.py` — log `task-1642.log`): **`109 passed in 153.15s`**, exit code `0`.
2. Chạy script đóng băng hành vi [stage2b3_parity_check.py](file:///C:/Users/Quettye/.gemini/antigravity-cli/brain/6dd69e96-8654-4b5e-8611-302f06fd7c40/scratch/stage2b3_parity_check.py) (chế độ `before` -> `stage2b3_before.json`) qua `GenericImportedBatchWorkflow.start()` cho 4 kịch bản đại diện mọi nhánh của `_run_case`:
   - `unclassified_rule_only`
   - `asi03_contract_hybrid`
   - `asi03_policy_hybrid`
   - `asi05_policy_hybrid`
   Chỉ chuẩn hóa các trường không xác định (`run_id`, `batch_run_id`, `batch_execution_id`, `authorization_id`, `execution_id`, `native_execution_id`, `report_run_id`, `plan_id`, `report_sha256`, `timestamp`/`*_at`/`duration_ms`, chuỗi hex ID trong `report_file`), đồng thời khẳng định `sha256(report_bytes) == run_summary["report_sha256"] == result_row["report_sha256"]` trên từng run gốc. Không chuẩn hóa verdict, provenance, evaluation hay `trusted_context`.

---

## 8. Implementation Details

- Đặt `_build_asi03_semantic_testcase` (`L58-L117`) và `_build_asi05_semantic_testcase` (`L120-L158`) ở cấp module (private `_`-prefixed) ngay sau `ImportedBatchStart` trong `backend/src/workflow/generic_imported_batch.py`.
- Không sửa đổi chữ ký `GenericImportedBatchWorkflow._run_case`, không thêm import mới, không đổi bất kỳ từ khóa chuỗi hay khóa dict nào trong `trusted_context`, `EvaluationConfig`, `runtime_snapshot` hay `imported_provenance`.
- Giữ nguyên khối kiểm tra `asi03_policy` / `asi05_policy` / `asi03_contract` tại `L717-741` trước khi gọi 2 helper tại `L745-750`.

---

## 9. Source Changes

| File | Hành động | Chi tiết |
| :--- | :--- | :--- |
| [`backend/src/workflow/generic_imported_batch.py`](file:///D:/SecAgent-W5-Judge/backend/src/workflow/generic_imported_batch.py) | Modified (`838 -> 889` LOC) | Thêm [`_build_asi03_semantic_testcase`](file:///D:/SecAgent-W5-Judge/backend/src/workflow/generic_imported_batch.py#L58-L117) và [`_build_asi05_semantic_testcase`](file:///D:/SecAgent-W5-Judge/backend/src/workflow/generic_imported_batch.py#L120-L158); rút gọn nhánh semantic trong [`_run_case`](file:///D:/SecAgent-W5-Judge/backend/src/workflow/generic_imported_batch.py#L742-L750) (`317 -> 265` LOC) |
| [`backend/tests/test_stage2b3_case_helpers.py`](file:///D:/SecAgent-W5-Judge/backend/tests/test_stage2b3_case_helpers.py) | Created (`147` LOC, `3` tests) | Unit test cô lập 100% cho `asi03_policy`, `asi03_contract` và `asi05_policy` |
| [`docs/audits/SECAGENT_STAGE2B3_IMPLEMENTATION_REPORT.md`](file:///D:/SecAgent-W5-Judge/docs/audits/SECAGENT_STAGE2B3_IMPLEMENTATION_REPORT.md) | Created | Báo cáo triển khai & nghiệm thu Stage 2B.3 |

---

## 10. Execution Order Parity

Thứ tự thực thi trong `_run_case` (`L625-889`) hoàn toàn không đổi:
1. `_grant()` -> 2. `cancellation_requested()` -> 3. `write_exclusive_json(grant-...)` -> 4. `ds/imported_case` & snapshot/target verification -> 5. `before_request()` TOCTOU definition & `OneRequestHttpClient`/`RecordingExecutor` -> 6. `_native_match` & `asi03_policy`/`asi05_policy`/`asi03_contract` drift validation -> 7. Build `(native_testcase, test_input)` (qua `_build_asi03_semantic_testcase` / `_build_asi05_semantic_testcase`) -> 8. `Runner.run()` -> 9. `sanitized()` -> `persist_batch_case_report()` -> 10. `finally: _active_grant_id = None; _prune_grants()`.

Đối chiếu `difflib.unified_diff` giữa `stage2b3_before.json` và `stage2b3_after.json` cho thấy: chỉ khác 3 UUID mới sinh ngẫu nhiên mỗi phiên tạo policy/contract (`asi03_contract_id`, `asi03_policy_id`, `asi05_policy_id`) cùng 2 hash tính trực tiếp từ chúng (`plan_id`, `request_sha256`); **toàn bộ khóa JSON, `trusted_context`, `evaluation`, `runtime_snapshot`, `imported_provenance`, `run-summary.json`, `result_row` khớp 100%**.

---

## 11. Authorization and Grant Non-Regression

- `_grant`, `_owned_grants`, `_prune_grants`, `write_exclusive_json(grant-...)`, GH-C01 `baseline_pass`, request budget (`1` request/case) và cơ chế lazy per-case grant (tối đa 30 case song hành trong batch) giữ nguyên 100%.
- Được kiểm chứng trực tiếp qua `test_b47_remediation.py` và `test_generic_imported_batch.py` (trong `269 passed`, không có bất kỳ lỗi/skip nào).

---

## 12. Evidence and Judge Non-Regression

- `source_provenance` (`synthetic_mock` vs `target_observation`), `require_complete_response_for_semantic=True`, `require_complete_response_for_pass=True`, `require_complete_response_for_fail=True`, `evidence_scope` và các `expected_labels` ASI03/ASI05 giữ nguyên 100%.
- Kiểm chứng qua `test_asi03_contracts.py`, `test_asi05_execution_core.py`, `test_evidence_sources.py`, `test_evidence_sufficiency_phase1b.py` (PASS toàn bộ).

---

## 13. Native Report and CaseResult Parity

- Ranh giới redaction `sanitized(summary, secrets_to_remove=secret_values)` ở `L822-823`, phục hồi trường hậu redaction (`L824-828`), toàn bộ 32 keys của `runtime_snapshot`, 33 keys của `imported_provenance`, và `persist_batch_case_report` (`extra_summary_fields={"dataset_id": ds.dataset_id}`) hoàn toàn bất biến.
- Kiểm tra sort-keys không trailing `\n`, tự nhất quán SHA256 trên bytes gốc và các trường `CaseResult` trên `stage2b3_after.json` ĐẠT 100%.

---

## 14. Offline Mock and Live-Local Coverage

- Luồng `offline_mock` (`test_generic_imported_batch.py`, `test_asi03_contracts.py`), luồng `live_local_http` qua `MockTransport` (`test_imported_live_local.py`), và bộ test B47 (`test_b47_remediation.py`) đều PASS 100% sau chỉnh sửa cuối cùng mà không cần gọi mạng thật hay DVAA/MCP/LLM ngoài.

---

## 15. Focused Test Results

Lệnh chạy sau chỉnh sửa cuối cùng (log [task-1675.log](file:///C:/Users/Quettye/.gemini/antigravity-cli/brain/6dd69e96-8654-4b5e-8611-302f06fd7c40/.system_generated/tasks/task-1675.log)):

```text
pytest backend/tests/test_stage2b3_case_helpers.py \
       backend/tests/test_generic_imported_batch.py \
       backend/tests/test_imported_live_local.py \
       backend/tests/test_dataset_import.py \
       backend/tests/test_asi01_batch.py \
       backend/tests/test_asi03_contracts.py \
       backend/tests/test_asi05_execution_core.py \
       backend/tests/test_evidence_sources.py \
       backend/tests/test_evidence_sufficiency_phase1b.py \
       backend/tests/test_workflow_dispatch.py \
       backend/tests/test_workflow_admission.py \
       backend/tests/test_b47_remediation.py \
       backend/tests/test_stage2b1b_report_persistence.py \
       backend/tests/test_stage2b1c_validation_parity.py \
       backend/tests/test_stage2b2b_worker_lifecycle.py \
       backend/tests/test_stage1b2_api_contract_parity.py \
       backend/tests/test_stage1b1_dependency_boundaries.py \
       backend/tests/test_stage1a_dependency_boundaries.py -q -rs
```

- **Kết quả:** **`269 passed in 336.60s (0:05:36)`** (`0` failed, `0` skipped, exit code `0`).

---

## 16. Full Backend Regression Results

Lệnh chạy sau chỉnh sửa cuối cùng (log [task-1679.log](file:///C:/Users/Quettye/.gemini/antigravity-cli/brain/6dd69e96-8654-4b5e-8611-302f06fd7c40/.system_generated/tasks/task-1679.log)):

```text
pytest backend/tests -q -rs
```

- **Kết quả:** **`1652 passed in 556.11s (0:09:16)`** (`0` failed, `0` skipped, exit code `0`).
- **Tăng trưởng kiểm thử:** `1,649` (Stage 2B.2b) + `3` (Stage 2B.3 mới) = **`1,652 passed`**.

---

## 17. LOC and Complexity Comparison (Đủ 10 chỉ số Mục 11)

| # | Chỉ số đo | Giá trị thực tế | Ghi chú trung thực |
| :---: | :--- | :--- | :--- |
| 1 | `_run_case` LOC trước & sau | **`317` -> `265` LOC (`-52` LOC)** | Giảm trực tiếp khối dựng semantic context khỏi thân hàm chính |
| 2 | Số helper đã trích xuất | **`2`** (`_build_asi03_semantic_testcase`, `_build_asi05_semantic_testcase`) | Thuộc cấp module (`_` private), nằm trong cùng file |
| 3 | Tổng production LOC (`generic_imported_batch.py`) trước & sau | **`838` -> `889` LOC (`+51` LOC)** | Tăng nhẹ do signature có type annotations, docstrings & line wrapping sạch (không gộp/xóa logic nào) |
| 4 | Số tham số mới thêm vào public/private method hiện có | **`0`** (`5` & `4` param trên 2 helper mới) | `_run_case` giữ nguyên chữ ký; không sinh hàm 10+ tham số |
| 5 | Số đối tượng trạng thái khả biến dùng chung mới | **`0`** | Không thêm shared mutable dict/dataclass/callback |
| 6 | Các khối lớn còn lại trong `_run_case` | `before_request` (`33` LOC), `runtime_snapshot` (`35` LOC), `imported_provenance` (`39` LOC) | Có chủ đích giữ lại tại chỗ để bảo toàn thứ tự `sanitized()` & tránh truyền `14–20` tham số |
| 7 | Dependencies mới | **`0`** | Không thêm thư viện hay module mới |
| 8 | Tests mới bổ sung | **`3`** tests trong `test_stage2b3_case_helpers.py` (`147` LOC) | Không làm suy yếu bất kỳ test hiện hữu nào |
| 9 | Phương thức có dễ đọc / dễ hiểu hơn không? | **Có** | Phần chuẩn bị evaluator ở giữa `_run_case` giảm từ 62 dòng xuống 9 dòng, tuyến thực thi chính rõ ràng hơn |
| 10 | Có làm rõ đường tích hợp runtime tương lai (Stage 3)? | **Có (một phần vừa phải)** | Đường chuẩn bị ASI03/ASI05 semantic tách rời rành mạch khỏi vòng đời `Runner` và `ExecutionBindingRegistry` |

- **Kiểm tra tĩnh (`task-1667`):** `python -m py_compile` PASS; `cycles: []`; `script_refs: []`; `git diff --check` exit code `0`.

---

## 18. Remaining Risks and Limitations

1. **Kích thước còn lại của `_run_case` (`265` LOC):** Do có chủ đích giữ nguyên `runtime_snapshot` (35 dòng), `imported_provenance` (39 dòng) và `before_request` (33 dòng) vì lý do tham số (`14–20` biến) và ranh giới bảo mật `sanitized()`, hàm `_run_case` vẫn dài `265` dòng nhưng cấu trúc tuyến tính, độ lồng ghép nông (chỉ còn 1 tầng cho dict literal và closure `before_request`).
2. **Phạm vi thực thi:** Mọi kiểm thử đều chạy ở chế độ offline / `MockTransport` (không gọi DVAA/MCP/LLM thật).
3. **Ghi chú lịch sử Stage 2B.1b:** Hạn chế byte-level BEFORE/AFTER toàn phần của Stage 2B.1b giữ nguyên trạng thái đã ghi nhận từ Stage 2B.1b; riêng Stage 2B.3 đã xác minh trực tiếp parity BEFORE/AFTER trên đầy đủ JSON báo cáo cho cả 4 nhánh `_run_case`.

---

## 19. Stage 2B Completion Assessment

Tổng thể chuỗi **Stage 2B** đã hoàn thành trọn vẹn, an toàn và không phá vỡ hợp đồng:
- **Stage 2B.1a:** Hợp nhất ghi file độc quyền `"x"` + `os.fsync` (`write_exclusive_json`).
- **Stage 2B.1b:** Hợp nhất đuôi lưu trữ Native Report cho cả 6 batch workflow (`persist_batch_case_report`).
- **Stage 2B.1c:** Hợp nhất validator `OfflineBatchSelection` / `OfflineBatchStart` via `ClassVar` + dọn key `"model"` trùng lặp.
- **Stage 2B.2a & 2B.2b:** Kiểm toán C3/C4 và hợp nhất khởi tạo worker thread (`launch_batch_worker`), khắc phục lỗi treo `dispatcher._active` trên `OfflineBatchWorkflow` & các lớp con.
- **Stage 2B.3:** Tách 2 semantic context helper thuần cho `GenericImportedBatchWorkflow._run_case`, đưa toàn bộ suite lên **`1,652 passed` (`0` failed, `0` skipped)**, `0` import cycle, `0` production-to-script dependency.

---

## 20. Final Acceptance Verdict

**`STAGE_2B3_PASS`** — Sẵn sàng dừng Stage 2B ở trạng thái ổn định để thực hiện **independent source ZIP review** hoặc chuẩn bị **Stage 3 (`McpAgentRuntime`)** theo yêu cầu kế tiếp của người dùng. Bridge `:7019` và các thành phần Stage 3 chưa bị chạm tới.

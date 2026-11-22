# BÁO CÁO TRIỂN KHAI STAGE 2B.1b: HỢP NHẤT AN TOÀN LƯU TRỮ NATIVE REPORT CỦA BATCH

**Dự án:** SecAgent Framework (`D:\SecAgent-W5-Judge`)  
**Giai đoạn:** Stage 2B.1b — Safe Native Report Persistence Consolidation  
**Ngày thực hiện:** 2026-11-22  
**Phán quyết nghiệm thu:** `STAGE_2B1B_PASS`

---

## 1. Executive Summary

Stage 2B.1b đã hoàn tất hợp nhất phần đuôi lưu trữ báo cáo tương đương của cả **6/6 batch workflow** (`OfflineBatchWorkflow`, `Asi01BatchWorkflow`, `GenericImportedBatchWorkflow`, `MockWebBatchWorkflow`, `ToolBotLabBatchWorkflow`, `ResearchBotWebBatchWorkflow`) vào một helper canonical duy nhất `persist_batch_case_report(...)` tại [`backend/src/workflow/batch.py:189`](file:///D:/SecAgent-W5-Judge/backend/src/workflow/batch.py#L189), sử dụng helper nội bộ `_write_exclusive_sorted_json` (`batch.py:84`).

- **Hợp nhất đúng lớp cơ học lưu trữ chung:** Việc xây dựng `build_summary`, bổ sung metadata đặc thù (`runtime_snapshot`, `imported_provenance`, preflight/fixture receipts), `sanitized()`, khôi phục trường hậu redaction, phân quyền grant, cổng `GH-C01` (`_baseline_pass`), và cập nhật `_baseline_pass` vẫn ở lại nguyên vẹn trong từng workflow sở hữu.
- **Phạm vi bằng chứng parity (cập nhật minh bạch sau rà soát):**
  - Ở mức **unit helper**, `test_persist_batch_case_report_matches_legacy_bytes_sha256_and_caseresult` xác minh đối chiếu byte-by-byte UTF-8 giữa `persist_batch_case_report(...)` và mã ghi JSON `sort_keys=True` gốc (không trailing `\n`) cùng `sha256(report.read_bytes())`, `run-summary.json`, và `CaseResult`.
  - Ở mức **6 workflow BEFORE/AFTER**, script đối chiếu xác minh khớp 100% các trường cấu trúc trong `stage2b1b_before_baselines.json` (template tên file, `sort_keys=True` không trailing newline, `report_top_keys`, `summary_row_keys`, `artifact_provenance`, `case_result_api_keys`, `verdict`, `status`, và tự nhất quán `sha256(rep_bytes) == report_sha256`).
  - **Hạn chế được ghi nhận rõ (`UNVERIFIED`):** Đối chiếu toàn bộ giá trị JSON (full JSON-value / full byte-level BEFORE/AFTER trên từng workflow sau khi chuẩn hóa timestamp, UUID, `run_id` và hash phụ thuộc) là **`UNVERIFIED`** vì file baseline trước refactor (`stage2b1b_before_baselines.json`) chỉ lưu metadata cấu trúc và tập keys chứ không lưu toàn bộ nội dung JSON gốc (không tạo lại baseline giả từ code sau refactor).
- **Kiểm chứng đầy đủ sau sửa đổi cuối:** `3/3` unit/parity test mới trong `test_stage2b1b_report_persistence.py`, **22 suite trọng tâm (`411 passed in 248.41s`)**, và toàn bộ backend suite theo log thực tế `task-1351.log` (**`1619 passed in 512.05s (0:08:32)`**, exit code `0`, `0` failed, `0` skipped) đều ĐẠT 100%, không tạo import cycle và giảm ròng **`-47` LOC** riêng trong Stage 2B.1b (`-118` dòng lặp ở 6 caller vs `+71` dòng helper ở `batch.py`).

---

## 2. Git/Working Tree Baseline

- **Repository:** `D:\SecAgent-W5-Judge`
- **Git HEAD:** `ce1c776fd7b939b0cd705ece87320a67a1885ac8`
- **Python:** `Python 3.13.7`
- **Working Tree lúc bắt đầu Stage 2B.1b:** `249` mục (`65` modified, `184` untracked — chính là nền sau Stage 2B.1a với `test_stage2b1a_exclusive_json.py` và `SECAGENT_STAGE2B1A_IMPLEMENTATION_REPORT.md` cùng `batch.py` + 6 batch workflow là file untracked hợp pháp).
- **`git diff --check`:** Exit code `0` (0 lỗi whitespace).
- **Bảo toàn công việc trước đó:** `write_exclusive_json` (Stage 2B.1a) tại `batch.py:75` được giữ nguyên vẹn 100%, không bị sửa hay xóa. Không dùng lệnh `git reset`, `clean`, `stash`, `restore`, `checkout --`, `commit` hay `push`.

---

## 3. Six-Workflow Persistence Inventory

| Thuộc tính | `OfflineBatchWorkflow` | `Asi01BatchWorkflow` | `GenericImportedBatchWorkflow` | `MockWebBatchWorkflow` | `ToolBotLabBatchWorkflow` | `ResearchBotWebBatchWorkflow` |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **1. Owning method** | `_run_case` (`L200+`) | `_run_text_case` (`L313+`) | `_run_case` (`L755+`) | `_run_case` (`L196+`) | `_run_tool_case` (`L295+`) | `_run_web_case` (`L289+`) |
| **2. Output dir** | `dispatcher.output_root / run_id` (`exist_ok=False`) | Nt | Nt | Nt | Nt (tạo trước để chép `tool-*.json`) | Nt |
| **3. Report filename** | `native-{case.testcase_id}-{run_id}.secagent.json` | Nt | Nt | `native-{WEB_ATTACK}-{run_id}.secagent.json` | `native-{CASE_ID}-{run_id}.secagent.json` | `native-{WEB_ATTACK}-{run_id}.secagent.json` |
| **4. JSON top structure** | `build_summary` + `evaluation` + `source_provenance` | + `runtime_snapshot` | + `dataset_id`, `prompt_sha256`, `runtime_snapshot`, `imported_provenance`, `source_testcase_id` | + `runtime_snapshot` (`preflight_id`, `fixture_*`) | + `runtime_snapshot` (`tool_artifact_sha256`, `effect_mode`) | + `runtime_snapshot` (`assessment_id`, `attack_run_id`, `approval_sha256`, ...) |
| **5. Enrichment** | Đặt ở caller trước khi ghi | Đặt ở caller | Đặt ở caller (cả trước & sau `sanitized()`) | Đặt ở caller (restore `preflight_id`, `fixture_run_id`) | Đặt ở caller + ghi `tool-{role}.json` (`"xb"`) | Đặt ở caller (restore `assessment_id`, `attack_run_id`) |
| **6. Sanitization** | `sanitized(summary, secrets_to_remove=(operator_secret, cred))` | `(operator_secret,)` | `(operator_secret,)` | `(operator_secret, fixture canary)` | `(operator_secret,)` | `(operator_secret, preflight canary, attack canary)` |
| **7. Serialization** | `json.dump(..., sort_keys=True)` UTF-8 | Nt | Nt | Nt | Nt | Nt |
| **8. Trailing newline** | Không có (`sort_keys=True` raw) | Không | Không | Không | Không | Không |
| **9. Flush / fsync** | `stream.flush()` + `os.fsync()` | Nt | Nt | Nt | Nt | Nt |
| **10. SHA256 input** | `sha256(report.read_bytes()).hexdigest()` | Nt | Nt | Nt | Nt | Nt |
| **11. `run-summary.json`** | `17` base keys (`sort_keys=True`, no `\n`) | `17` base keys | `17` base + `dataset_id` (`18` keys) | `17` base + `preflight_id` (`18` keys) | `17` base keys | `17` base + `preflight_id` (`18` keys) |
| **12. File creation** | `open("x", encoding="utf-8")` | Nt | Nt | Nt | Nt | Nt |
| **13. Error / cleanup** | Ném lỗi thẳng; không xóa `.secagent.json` nếu `run-summary.json` lỗi | Nt (giữ `_baseline_pass` sau persist thành công) | Nt (`finally:` dọn grant qua `_prune_grants`) | Nt (dùng `LocalMockFixtureRuntime`) | Nt (`finally:` dọn grant + `TemporaryDirectory`) | Nt (`finally:` dọn `DockerWebLabRuntime` context) |
| **14. Return value** | `CaseResult` (`preflight_id=None`, `evaluation_reason_from_summary`) | Nt | Nt | `CaseResult` (`preflight_id=preflight_id`, `evaluation_reason_from_summary`) | `CaseResult` (`preflight_id=None`, `evaluation_reason_from_summary`) | `CaseResult` (`preflight_id=preflight_id`, `evaluation_reason_from_summary`) |
| **15. Security / provenance** | `synthetic_mock` only | `GH-C01` `_baseline_pass` | `_owned_grants`, `offline_mock` / `target_observation` | `synthetic_mock`, capability preflight | `synthetic_mock`, `"xb"` raw copy `tool-{role}.json` | `runtime.provenance`, `approval.json` check, 2-request preflight/attack |
| **16. Regression tests** | `test_offline_batch_api.py` | `test_asi01_batch.py` | `test_generic_imported_batch.py`, `test_imported_live_local.py` | `test_web_mock_batch.py` | `test_toolbot_lab_batch.py` | `test_researchbot_web_batch.py`, `test_researchbot_web_baseline.py` |

*(Ghi chú phân biệt ngoài scope: `dispatch.py` không dùng `fsync` trên `run-summary.json`; `mcp_actions.py` xuất `native_report.json` với `indent=2` + `"\n"` và `report_kind="mcp_action"`; `testing/report_builder.py` xuất `native-{stamp}-...secagent.json` với `indent=2` + `"\n"` không `fsync` — cả 3 giữ nguyên hoàn toàn.)*

---

## 4. Before-Refactor Artifact Baselines

Trước khi sửa bất kỳ file sản xuất nào, đã chạy kịch bản độc lập qua test fixtures ngoại tuyến/mock của cả 6 workflow và lưu snapshot vào `<scratch>/stage2b1b_before_baselines.json`:

- **Những gì ĐÃ lưu được BEFORE refactor (`stage2b1b_before_baselines.json`):**
  - Cả **6/6 workflow** xác nhận `report_exact_sort_keys_no_newline = True` và `summary_exact_sort_keys_no_newline = True`.
  - Kiểm tra trong script tại thời điểm chạy BEFORE: `sha256(report.read_bytes()).hexdigest() == run_summary["report_sha256"] == results[0]["report_sha256"]` đúng tuyệt đối ở cả **6/6 workflow**.
  - Lưu chính xác 10 trường metadata cho mỗi workflow: `report_filename_template`, `report_exact_sort_keys_no_newline`, `summary_exact_sort_keys_no_newline`, `report_top_keys` (`12` keys ở `offline_batch`; `13` ở `asi01`, `web_mock`, `toolbot_lab`, `web_live`; `17` ở `generic_imported`), `summary_row_keys` (17 base keys, +`dataset_id` ở `generic_imported_batch`, +`preflight_id` ở `web_mock_batch` & `web_live_batch`), `summary_row_provenance`, `case_result_api_keys` (`12` keys trên `/api/testing/batches/<id>/results`), `case_result_verdict`, `case_result_status`, `case_result_preflight_id_present`.
- **Những gì KHÔNG được lưu BEFORE refactor (`UNVERIFIED`):**
  - Không lưu toàn bộ nội dung thô (full JSON payload) của `native-*.secagent.json` và `run-summary.json` trước refactor. Do đó không thể chạy so khớp giá trị từng trường lồng nhau BEFORE vs AFTER ở mức workflow sau chuẩn hóa timestamp/UUID/`run_id`/hash phụ thuộc (**`UNVERIFIED`**; không tạo lại baseline sau refactor để thay thế).

---

## 5. Architecture Decision

- Đặt hàm canonical `persist_batch_case_report(...)` tại [`backend/src/workflow/batch.py`](file:///D:/SecAgent-W5-Judge/backend/src/workflow/batch.py#L189), cùng một helper private 5 dòng `_write_exclusive_sorted_json(path, payload)` (`L84-90`) để tránh đụng tới `write_exclusive_json` (vốn dùng `sort_keys=False` cho `grant-*`/`submission-*`).
- **Lý do không tạo lớp Report Builder mới hay sửa `testing/report_builder.py`:** `testing/report_builder.py` không sở hữu khái niệm `BatchOrchestrator` hay `CaseResult`; đặt `persist_batch_case_report` tại `workflow/batch.py` giữ `CaseResult` và vòng đời lưu file batch tại đúng module đã sở hữu `CaseResult`, `_write_atomic`, `evaluation_reason_from_summary` và `write_exclusive_json`, với `workflow_imports=[]`.
- **Chỉ nhận `summary` đã hoàn chỉnh & sanitized từ caller:** Không chuyển `build_summary`, `sanitized()`, metadata enrichment, hay `_baseline_pass` vào helper — nhờ đó helper hoàn toàn không chứa nhánh logic riêng theo từng workflow.

---

## 6. Helper API and Ownership

1. `_write_exclusive_sorted_json(path: Path, payload: Any) -> None` ([`batch.py:84-90`](file:///D:/SecAgent-W5-Judge/backend/src/workflow/batch.py#L84-L90)): mở `"x"` UTF-8, `json.dump(payload, stream, sort_keys=True)`, `flush()`, `os.fsync(stream.fileno())`.
2. `persist_batch_case_report(...) -> CaseResult` ([`batch.py:189-243`](file:///D:/SecAgent-W5-Judge/backend/src/workflow/batch.py#L189-L243)):
   - Ghi `native-{testcase_id}-{run_id}.secagent.json` qua `_write_exclusive_sorted_json`.
   - Tính `report_hash = sha256(report.read_bytes()).hexdigest()` từ đúng bytes trên đĩa.
   - Dựng `summary_row` (17 trường chuẩn + `preflight_id` nếu khác `None` + `extra_summary_fields.update(...)` nếu có) và ghi `run-summary.json` qua `_write_exclusive_sorted_json`.
   - Trả về `CaseResult("error" if verdict == "ERROR" else "completed", verdict, request_count, run_id, report_hash, response_captured, response_complete, artifact_provenance, preflight_id=preflight_id, evaluation_reason=evaluation_reason_from_summary(summary))`.

---

## 7. Files Modified/Created

| File | Hành động | Chi tiết |
| :--- | :--- | :--- |
| [batch.py](file:///D:/SecAgent-W5-Judge/backend/src/workflow/batch.py) | Modified (`469 -> 540` LOC) | Thêm `_write_exclusive_sorted_json` (`L84`) và `persist_batch_case_report` (`L189`) |
| [offline_batch.py](file:///D:/SecAgent-W5-Judge/backend/src/workflow/offline_batch.py) | Modified (`286 -> 267` LOC) | Import & gọi `persist_batch_case_report` (`L212`) |
| [asi01_batch.py](file:///D:/SecAgent-W5-Judge/backend/src/workflow/asi01_batch.py) | Modified (`364 -> 347` LOC) | Gọi `persist_batch_case_report` (`L338`), giữ `_baseline_pass` ngay sau khi persist thành công (`L345-346`) |
| [generic_imported_batch.py](file:///D:/SecAgent-W5-Judge/backend/src/workflow/generic_imported_batch.py) | Modified (`899 -> 869` LOC) | Gọi `persist_batch_case_report` (`L850`) với `extra_summary_fields={"dataset_id": ds.dataset_id}` |
| [web_mock_batch.py](file:///D:/SecAgent-W5-Judge/backend/src/workflow/web_mock_batch.py) | Modified (`253 -> 235` LOC) | Gọi `persist_batch_case_report` (`L227`) với `WEB_ATTACK`, `client.used + attack_client.used`, `preflight_id` |
| [toolbot_lab_batch.py](file:///D:/SecAgent-W5-Judge/backend/src/workflow/toolbot_lab_batch.py) | Modified (`355 -> 338` LOC) | Gọi `persist_batch_case_report` (`L327`), giữ nguyên ghi `"xb"` cho `tool-{role}.json` (`L307`) |
| [web_live_batch.py](file:///D:/SecAgent-W5-Judge/backend/src/workflow/web_live_batch.py) | Modified (`349 -> 332` LOC) | Gọi `persist_batch_case_report` (`L324`) với `self.runtime.provenance` và `preflight_id` |
| [test_stage2b1b_report_persistence.py](file:///D:/SecAgent-W5-Judge/backend/tests/test_stage2b1b_report_persistence.py) | Created (`233` LOC, `3` tests) | Unit, byte/SHA256/CaseResult parity, collision/partial-failure & mutation checks |
| [SECAGENT_STAGE2B1B_IMPLEMENTATION_REPORT.md](file:///D:/SecAgent-W5-Judge/docs/audits/SECAGENT_STAGE2B1B_IMPLEMENTATION_REPORT.md) | Created | Báo cáo triển khai & nghiệm thu Stage 2B.1b |

---

## 8. Migration-by-Migration Evidence

1. **`OfflineBatchWorkflow` (`offline_batch.py`) — MIGRATED:** Phần đuôi đồng nhất 100% với base contract (`17` summary_row keys, `synthetic_mock`). Kiểm chứng: `test_stage2b1b_report_persistence` + `test_stage2b1a_exclusive_json` + `test_offline_batch_api` + `test_batch_orchestrator` -> **23 passed in 3.69s**; BEFORE/AFTER khớp về cấu trúc/keys/format/provenance/verdict/SHA256-consistency. **Unverified:** Full JSON-value BEFORE/AFTER parity (`UNVERIFIED` — thiếu full payload BEFORE); không gọi live network thật (`forbid_real_network`).
2. **`Asi01BatchWorkflow` (`asi01_batch.py`) — MIGRATED:** Phần đuôi dùng `self.provenance` và `binding.input_sha256/asset_sha256`; cập nhật `self._baseline_pass` đặt sau `persist_batch_case_report`. Kiểm chứng: `test_asi01_batch.py` -> **16 passed in 11.20s**; BEFORE/AFTER khớp về cấu trúc/keys/format/provenance/verdict/SHA256-consistency. **Unverified:** Full JSON-value BEFORE/AFTER parity (`UNVERIFIED` — thiếu full payload BEFORE); chỉ chạy qua `MockTransport`.
3. **`GenericImportedBatchWorkflow` (`generic_imported_batch.py`) — MIGRATED:** Truyền `extra_summary_fields={"dataset_id": ds.dataset_id}` để giữ đủ `18` keys trong `run-summary.json`; giữ nguyên `summary["imported_provenance"]` và restore fields hậu `sanitized()`. Kiểm chứng: `test_generic_imported_batch.py` + `test_imported_live_local.py` -> **16 passed in 25.34s**; BEFORE/AFTER khớp về cấu trúc/keys/format/provenance/verdict/SHA256-consistency. **Unverified:** Full JSON-value BEFORE/AFTER parity (`UNVERIFIED` — thiếu full payload BEFORE); live HTTP target thật không được gọi.
4. **`MockWebBatchWorkflow` (`web_mock_batch.py`) — MIGRATED:** Truyền `WEB_ATTACK`, `client.used + attack_client.used`, `preflight_id` (`18` keys trong `run-summary.json` + `CaseResult.preflight_id`), giữ nguyên restore `preflight_id`/`fixture_run_id`. Kiểm chứng: `test_web_mock_batch.py` -> **7 passed in 18.21s**; BEFORE/AFTER khớp về cấu trúc/keys/format/provenance/verdict/SHA256-consistency. **Unverified:** Full JSON-value BEFORE/AFTER parity (`UNVERIFIED` — thiếu full payload BEFORE); fixture loopback mock theo thiết kế.
5. **`ToolBotLabBatchWorkflow` (`toolbot_lab_batch.py`) — MIGRATED:** Giữ nguyên tạo `run_dir` trước để chép nhị phân `tool-{role}.json` (`open("xb")` tại `L307`), rồi gọi `persist_batch_case_report` cho report + `run-summary.json` (`17` keys). Kiểm chứng: `test_toolbot_lab_batch.py` -> **14 passed in 12.17s**; BEFORE/AFTER khớp về cấu trúc/keys/format/provenance/verdict/SHA256-consistency. **Unverified:** Full JSON-value BEFORE/AFTER parity (`UNVERIFIED` — thiếu full payload BEFORE); handler synthetic mock, không chạy shell/DVAA ToolBot thật.
6. **`ResearchBotWebBatchWorkflow` (`web_live_batch.py`) — MIGRATED LAST:** Truyền `self.runtime.provenance`, `preflight_id`, `summary["runtime_snapshot"]["input_sha256"]`, `fresh.asset_sha256`, `client.used + attack_client.used`. Kiểm chứng: `test_researchbot_web_batch.py` + `test_researchbot_web_baseline.py` -> **36 passed in 14.20s**; BEFORE/AFTER khớp về cấu trúc/keys/format/provenance/verdict/SHA256-consistency. **Unverified:** Full JSON-value BEFORE/AFTER parity (`UNVERIFIED` — thiếu full payload BEFORE); chạy trên `LocalWebLabRuntime` mock thay vì Docker Live DVAA thật theo giới hạn offline.

---

## 9. Native Report Byte-Level Parity

- **Đã xác minh ở tầng unit helper (`persist_batch_case_report`):** `test_persist_batch_case_report_matches_legacy_bytes_sha256_and_caseresult` xác nhận UTF-8 bytes sinh bởi `persist_batch_case_report` (kể cả Unicode `"tiếng Việt"` và nested dict) trùng khớp byte-by-byte với `json.dumps(snapshot, sort_keys=True).encode("utf-8")` (không thêm trailing `\n`).
- **Đã xác minh ở mức cấu trúc trên cả 6 workflow BEFORE/AFTER:** Script đối chiếu xác minh toàn bộ file `native-*.secagent.json` sau migrate đều khớp chính xác template tên file, quy cách `json.dumps(rep_obj, sort_keys=True).encode("utf-8")` không trailing `\n`, cùng tập `report_top_keys`, cùng `artifact_provenance`, `verdict`, và `status`.
- **`UNVERIFIED` ở mức workflow full JSON-value BEFORE/AFTER:** Do baseline `stage2b1b_before_baselines.json` được ghi trước refactor chỉ lưu metadata cấu trúc chứ không lưu toàn bộ JSON payload thô trước refactor, việc so sánh toàn bộ giá trị JSON lồng nhau BEFORE vs AFTER trên cả 6 workflow (kể cả sau chuẩn hóa timestamp/UUID/`run_id`/hash phụ thuộc) là **`UNVERIFIED`** và không thể suy diễn thành "100% byte-level BEFORE/AFTER parity" ở tầng tích hợp toàn phần.

---

## 10. SHA256 Parity

- Helper giữ nguyên `report_hash = sha256(report.read_bytes()).hexdigest()` đọc lại trực tiếp bytes từ file `.secagent.json` đã flush/fsync trên đĩa.
- Cả unit test lẫn kịch bản 6-workflow parity xác nhận `sha256(report.read_bytes()).hexdigest() == run_summary["report_sha256"] == CaseResult.report_sha256`.

---

## 11. Run-Summary and CaseResult Parity

- `run-summary.json` giữ chính xác `json.dumps(summary_row, sort_keys=True).encode("utf-8")`, 17 base keys ở `offline_batch`, `asi01_batch`, `toolbot_lab_batch`; 18 keys (`+dataset_id`) ở `generic_imported_batch`; 18 keys (`+preflight_id`) ở `web_mock_batch` và `web_live_batch`.
- `CaseResult` giữ chính xác `execution_status` (`"error"` khi `verdict == "ERROR"`, ngược lại `"completed"`), `preflight_id`, `evaluation_reason_from_summary(summary)`, và `summary` truyền vào **không bị mutate** (`summary == snapshot`).

---

## 12. Failure and Recovery Behavior

Kiểm chứng trực tiếp trong `test_persist_batch_case_report_preserves_failure_and_partial_artifact_semantics`:
- **Thư mục `run_dir` không tồn tại:** Ném `FileNotFoundError`.
- **Trùng `native-*.secagent.json`:** Ném `FileExistsError`, không ghi đè file cũ và không tạo `run-summary.json`.
- **Partial failure (`native-*.secagent.json` ghi thành công nhưng `run-summary.json` trùng/lỗi):** Ném `FileExistsError`, **không** tự ý rollback xóa file `.secagent.json` vừa ghi — bảo toàn nguyên vẹn hành vi gốc.
- **Lỗi `os.fsync`:** Ném `OSError` nguyên gốc ra ngoài, không nuốt ngoại lệ.

---

## 13. Security and Evidence Non-Regression

- Toàn bộ grant one-time consumption (`grant-*`), `_owned_grants` isolation, `_baseline_pass` GH-C01 gating, preflight capability check, `approval.json` verification, `synthetic_mock` vs `target_observation` provenance, redaction secrets trước khi gọi `persist_batch_case_report`, và ranh giới `tool_service` vs `agent_run` đều nguyên vẹn 100%.
- Đã kiểm chứng toàn bộ các suite bảo mật: `test_b47_remediation.py`, `test_asi05_execution_core.py`, `test_evidence_sources.py`, `test_evidence_contract_phase1a.py`, `test_evidence_sufficiency_phase1b.py` (tất cả nằm trong lượt chạy 22 suite `411 passed`).

---

## 14. Focused and Full Backend Test Results

1. **`python -m py_compile` (7 file sản xuất + `test_stage2b1b_report_persistence.py`):** Exit code `0`.
2. **BEFORE/AFTER 6-Workflow Structural/Format Parity Verification Script:** Exit code `0` (`ALL 6 WORKFLOWS BEFORE/AFTER PARITY MATCHED 100%!` đối với 10 trường metadata cấu trúc/format/provenance/verdict trong `stage2b1b_before_baselines.json`; full JSON-value BEFORE/AFTER là `UNVERIFIED`).
3. **22 Focused Suites (`pytest ... -q`):** Log [task-1351.log](file:///C:/Users/Quettye/.gemini/antigravity-cli/brain/6dd69e96-8654-4b5e-8611-302f06fd7c40/.system_generated/tasks/task-1351.log) dòng `1-7`: **`411 passed in 248.41s (0:04:08)`** (`0` failed, `0` skipped) — bao gồm toàn bộ Stage 2B.1a/1b, BatchOrchestrator, 6 batch workflows, Reporting API, Report Normalization, Workflow Dispatch, B47 ExecutionGrants, Stage 1A/1B1/1B2 boundaries & parity, ASI05 execution core, và Evidence suites.
4. **Full Backend Regression (`pytest backend/tests -q -rs`):** Đã kiểm tra trực tiếp log cuối cùng [task-1351.log](file:///C:/Users/Quettye/.gemini/antigravity-cli/brain/6dd69e96-8654-4b5e-8611-302f06fd7c40/.system_generated/tasks/task-1351.log) dòng `8-31`: **`1619 passed in 512.05s (0:08:32)`**, **`Command exited with code 0`** (`0` failed, `0` skipped; tăng đúng `+3` test mới so với mốc `1,616` của Stage 2B.1a).
5. **Import Boundaries & Git Check:**
   - AST scan trên `33` file `workflow/*.py`: `workflow_cycles: []`, `script_imports: []`, `batch.py deps: []`.
   - `git diff --check`: Exit code `0`.
6. **Frontend:** Không chỉnh sửa; kiểm thử Vitest **NOT RUN** ở Stage 2B.1b.

---

## 15. Real LOC and Complexity Reduction

| Chỉ số đo được | Giá trị thực tế Stage 2B.1b |
| :--- | :--- |
| LOC trước Stage 2B.1b (7 file sản xuất sau 2B.1a) | `469 + 286 + 364 + 899 + 349 + 253 + 355 = 2,975` LOC |
| LOC sau Stage 2B.1b (7 file sản xuất) | `540 + 267 + 347 + 869 + 332 + 235 + 338 = 2,928` LOC |
| Khối persist lặp lại được loại bỏ | `6/6` batch workflow (`-118` LOC tổng ở 6 caller) |
| Mã helper thêm vào `workflow/batch.py` | `+71` LOC (`_write_exclusive_sorted_json` + `persist_batch_case_report` kèm docstring & type hints) |
| **Biến động LOC sản xuất ròng (Stage 2B.1b)** | **`-47` LOC** *(lũy kế 2B.1a + 2B.1b: `2,985 -> 2,928` = `-57` net LOC)* |
| Workflows migrated / preserved | `6` migrated / `0` batch workflow giữ nguyên (ngoài `dispatch.py` & `mcp_actions.py` vốn ngoài scope) |
| Production modules created / modified | `0` created / `7` modified |
| New tests / new abstractions | `3` tests (`233` LOC) / `0` classes hay framework mới (`2` tham số optional nhỏ `preflight_id`, `extra_summary_fields`) |

---

## 16. Remaining Duplication

- **Stage 2B.1c (Candidate C2):** Chuẩn hóa Pydantic validator `unique_and_rule_only` và sửa key `"model"` khai báo trùng tại `generic_imported_batch.py:776,780` (đã giữ nguyên không chạm ở Stage 2B.1b).
- **Stage 2B.2 & 2B.3 (Candidates C3–C5):** Chuẩn hóa `launch_batch_worker` / `load_valid_grant` và tách helper nội bộ trong `GenericImportedBatchWorkflow._run_case`.
- **Chủ động giữ nguyên ngoài phạm vi:** `dispatch.py`, `mcp_actions.py`, `testing/report_builder.py`, và ghi nhị phân `"xb"` tại `toolbot_lab_batch.py:307`.

---

## 17. Limitations and Unverified Cases

- **`UNVERIFIED` — Full JSON-value / full byte-level BEFORE/AFTER parity trên cả 6 workflow:** Script baseline trước refactor chỉ lưu snapshot cấu trúc (`report_top_keys`, `summary_row_keys`, `case_result_api_keys`, `sort_keys=True` không trailing `\n`, `artifact_provenance`, `verdict`, `status`, và tự nhất quán `sha256`), không lưu toàn bộ JSON payload trước refactor. Vì vậy việc so sánh từng giá trị JSON bên trong báo cáo giữa code cũ và code mới (sau khi chuẩn hóa timestamp/UUID/`run_id`/hash phụ thuộc) là **`UNVERIFIED`**; chỉ có unit test `persist_batch_case_report` và kiểm tra cấu trúc/tổng regression `1,619 passed` là đã xác minh trực tiếp.
- Toàn bộ chạy kiểm chứng `ResearchBotWebBatchWorkflow` và `GenericImportedBatchWorkflow` dùng `LocalWebLabRuntime` mock và `httpx.MockTransport` theo nguyên tắc kiểm thử ngoại tuyến — không kết nối DVAA, Docker Lab live, DeepSeek hay Pi Judge thật.
- Không chạy lại frontend Vitest/Playwright do Stage 2B.1b không chạm mã frontend.

---

## 18. Final Acceptance Verdict

**`STAGE_2B1B_PASS`** *(với ghi nhận hạn chế `UNVERIFIED` cho full JSON-value BEFORE/AFTER parity ở Mục 9 & Mục 17)*

- Cả **6/6 batch workflow** đã hợp nhất an toàn khâu ghi `.secagent.json` + SHA256 + `run-summary.json` + `CaseResult` qua `persist_batch_case_report` tại `backend/src/workflow/batch.py`.
- Xác minh byte-level parity ở mức unit helper (`test_stage2b1b_report_persistence.py`), khớp cấu trúc/keys/format/SHA256-consistency trên cả 6 workflow, và vượt qua **`411/411`** focused tests + **`1,619/1,619`** full backend tests (`task-1351.log`, exit code `0`) với zero failures/skips và zero import cycles.

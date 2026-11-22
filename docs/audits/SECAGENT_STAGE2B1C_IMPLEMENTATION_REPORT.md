# BÁO CÁO TRIỂN KHAI STAGE 2B.1c: HỢP NHẤT VALIDATOR PYDANTIC VÀ DỌN KEY `"model"` TRÙNG LẶP

**Dự án:** SecAgent Framework (`D:\SecAgent-W5-Judge`)  
**Giai đoạn:** Stage 2B.1c — Pydantic Validator Deduplication & Duplicate Dictionary Key Cleanup  
**Ngày thực hiện:** 2026-11-22  
**Phán quyết nghiệm thu:** `STAGE_2B1C_PASS`

---

## 1. Executive Summary

Stage 2B.1c đã hoàn tất hợp nhất có kiểm soát hai hạng mục **C2-A** (validator `unique_and_rule_only` lặp lại trên chuỗi kế thừa `OfflineBatchSelection`/`OfflineBatchStart`) và **C2-B** (khóa từ điển `"model"` khai báo trùng tại `generic_imported_batch.py`) mà không làm thay đổi bất kỳ luật kiểm tra đầu vào, thông báo lỗi `ValidationError`, thứ tự validate, chính sách bảo mật hay cấu trúc báo cáo nào.

- **C2-A (Pydantic Validators):** Đưa hai thuộc tính lớp `ClassVar` (`_allowed_evaluation_modes` và `_selection_error_message`) vào `OfflineBatchSelection`, để 1 hàm `unique_and_rule_only` duy nhất tại [`offline_batch.py:48`](file:///D:/SecAgent-W5-Judge/backend/src/workflow/offline_batch.py#L48) phục vụ cho cả 6 model (`OfflineBatchSelection`, `OfflineBatchStart`, `Asi01BatchSelection`, `Asi01BatchStart`, `ImportedBatchSelection`, `ImportedBatchStart`), loại bỏ 4 bản override copy-paste và giữ nguyên các model đặc thù khác (`PlanSelection`, `AdmissionRequest`, `Preset`, `CatalogConfig`, `TargetDraft`, `ImportedTestcase`, `AdmissionPolicy`).
- **C2-B (Duplicate `"model"` Key):** Xóa khóa `"model": selection.target.model,` dư thừa thứ hai (vị trí `L771` sau khi hợp nhất validator; trước đây là `L780`) trong dict literal `summary["runtime_snapshot"]` tại [`generic_imported_batch.py:757`](file:///D:/SecAgent-W5-Judge/backend/src/workflow/generic_imported_batch.py#L757). Khóa thứ nhất (`L767`) giữ nguyên vị trí insertion-order lẫn giá trị thuần túy `selection.target.model`.
- **Kiểm chứng toàn diện sau chỉnh sửa cuối:** `23/23` test mới trong [test_stage2b1c_validation_parity.py](file:///D:/SecAgent-W5-Judge/backend/tests/test_stage2b1c_validation_parity.py), **15 suite trọng tâm (`240 passed in 199.05s`)**, và toàn bộ regression suite backend theo log [task-1444.log](file:///C:/Users/Quettye/.gemini/antigravity-cli/brain/6dd69e96-8654-4b5e-8611-302f06fd7c40/.system_generated/tasks/task-1444.log) (**`1,642 passed in 605.85s`**, exit code `0`, `0` failed, `0` skipped) đều ĐẠT 100%, giảm ròng **`-12` LOC** sản xuất và `workflow_cycles: []`.

---

## 2. Git and Working Tree Baseline

- **Repository:** `D:\SecAgent-W5-Judge`
- **Git HEAD:** `ce1c776fd7b939b0cd705ece87320a67a1885ac8`
- **Python:** `Python 3.13.7`
- **Working Tree lúc bắt đầu Stage 2B.1c:** Nền sạch sau Stage 2B.1b (`65` modified, `185+` untracked hợp pháp gồm `offline_batch.py`, `asi01_batch.py`, `generic_imported_batch.py`, cùng các test/báo cáo Stage 2B.1a & 2B.1b).
- **`git diff --check`:** Exit code `0`. Không dùng `git reset`, `clean`, `stash`, `restore`, `checkout --`, `commit` hay `push`.

---

## 3. Actual Validator Inventory

Rà soát toàn bộ `backend/src/` với `@model_validator`, `@field_validator`, `unique_and_rule_only`, `evaluation_mode`, `testcase_ids`:

| File & Dòng (trước refactor) | Class / Method | Decorator & Mode | Trường chính & Ràng buộc | `evaluation_mode` | `testcase_ids=[]` | Phân loại | Route sử dụng |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `offline_batch.py:45-49` | `OfflineBatchSelection.unique_and_rule_only` | `@model_validator(mode="after")` | `testcase_ids: list[Identifier] (min=1,max=100)`, `evaluation_mode: str = "rule_only"` | Chỉ `{"rule_only"}` | Cấm (`min_length=1`) | **A** (Canonical Base) | `POST /batches/preview` (offline/web/toolbot) |
| `offline_batch.py:57-61` | `OfflineBatchStart.confirmed` | `@model_validator(mode="after")` | Thêm `expected_plan_id`, `submission_id`, `authorization_confirmed: bool` | Kế thừa `OfflineBatchSelection` | Cấm | **C** (Khác trách nhiệm confirmation) | `POST /batches` |
| `asi01_batch.py:65-69` | `Asi01BatchSelection.unique_and_rule_only` | `@model_validator(mode="after")` | Kế thừa `OfflineBatchSelection`; kiểm tra trùng `testcase_ids` | `{"rule_only", "hybrid"}` | Cấm | **A** (Tương đương base, khác allowlist & msg) | `POST /batches/preview` (`asi01`) |
| `asi01_batch.py:73-77` | `Asi01BatchStart.unique_and_rule_only` | `@model_validator(mode="after")` | Kế thừa `OfflineBatchStart`; copy-paste từ `Asi01BatchSelection` | `{"rule_only", "hybrid"}` | Cấm | **A** (Bản sao trực tiếp) | `POST /batches` (`asi01`) |
| `generic_imported_batch.py:49-54` | `ImportedBatchSelection.unique_and_rule_only` | `@model_validator(mode="after")` | Thêm `asi_category: Literal["unclassified","ASI03","ASI05"]` | `{"rule_only", "hybrid"}` | Cấm | **A** (Tương đương base, khác allowlist & msg) | `POST /batches/preview` (`imported`) |
| `generic_imported_batch.py:59-64` | `ImportedBatchStart.unique_and_rule_only` | `@model_validator(mode="after")` | Kế thừa `OfflineBatchStart`; copy-paste từ `ImportedBatchSelection` | `{"rule_only", "hybrid"}` | Cấm | **A** (Bản sao trực tiếp) | `POST /batches` (`imported`) |
| `plans.py:30-34` | `PlanSelection.unique` | `@model_validator(mode="after")` | `asi_categories (min=1,max=4)`, `testcase_ids (default=[])` | Không có field | **Cho phép `[]`** | **C** (Chuyên biệt) | `/compatibility/preview`, `/plans/preview` |
| `admission.py:44-47` | `AdmissionRequest` | Kế thừa `PlanSelection` | `evaluation_mode: Literal["rule_only","hybrid"] = "rule_only"` | Literal Pydantic | **Cho phép `[]`** | **C** (Chuyên biệt) | `/readiness/preview`, `/admissions`, `/runs`, `/run-selected`, `/execution-grants` |
| `admission.py:36-41` | `AdmissionPolicy.unique_authorizations` | `@model_validator(mode="after")` | Check trùng `authorization_id` trong `grants` | Không có | N/A | **C** (Domain khác) | Nội bộ admission policy |
| `models.py:28-36,45-57,73-80` | `Preset`, `CatalogConfig`, `TargetDraft` | `@model_validator(mode="after")` | Ràng buộc platform/models/timeout/protocol/alias | N/A | N/A | **C** (Domain khác) | Target routes & drafts |
| `dataset_models.py:20-24` | `ImportedTestcase.check_prompt_hash` | `@model_validator(mode="after")` | SHA256 `prompt` | N/A | N/A | **C** (Domain khác) | Dataset import |

---

## 4. Differences Between Model Contracts

1. **`evaluation_mode` allowlist:** `OfflineBatchSelection`/`OfflineBatchStart` chỉ chấp nhận `"rule_only"`; trong khi `Asi01BatchSelection`/`Asi01BatchStart` và `ImportedBatchSelection`/`ImportedBatchStart` chấp nhận `{"rule_only", "hybrid"}`.
2. **Error messages:** Ba họ trả ba chuỗi thông báo cụ thể trên `ValueError` (`"Invalid offline batch selection."`, `"Invalid ASI01 batch selection."`, `"Invalid imported batch selection."`). Mặc dù `routes_execution.py:285` map `ValidationError` thành `400 "invalid_batch_selection"` ở `/batches/preview` và `409 "batch_start_rejected"` ở `/batches`, người dùng Python gọi `model_validate()` vẫn quan sát trực tiếp thông báo này.
3. **`asi_category` & `PlanSelection`:** Chỉ `ImportedBatchSelection`/`ImportedBatchStart` có trường `asi_category`; chỉ `PlanSelection`/`AdmissionRequest` cho phép `testcase_ids=[]`.
4. **Thứ tự validator trên `*Start`:** Thực nghiệm BEFORE refactor chứng minh khi truyền đồng thời `evaluation_mode="custom"` và `authorization_confirmed=False`, Pydantic chạy `unique_and_rule_only` **trước** `confirmed` trên cả 3 lớp `OfflineBatchStart`, `Asi01BatchStart`, `ImportedBatchStart`.

---

## 5. Before-Refactor Validation Matrix

Đã chạy kịch bản trước refactor và đóng băng trong `<scratch>/stage2b1c_before.json` + 22 bài test nền `test_stage2b1c_validation_parity.py`:
- `OfflineBatchSelection` & `OfflineBatchStart`: chấp nhận `"rule_only"`; từ chối `"hybrid"`, `"custom"`, `["A","A"]`, `[]`, `extra` fields, `"1"` (strict int), và `authorization_confirmed=False`; `both_bad` ưu tiên báo `"Invalid offline batch selection."`.
- `Asi01BatchSelection` & `Asi01BatchStart`: chấp nhận `"rule_only"` & `"hybrid"`; từ chối `"custom"`, `"HYBRID"`, `["A","A"]`, `asi_category`; `both_bad` ưu tiên báo `"Invalid ASI01 batch selection."`.
- `ImportedBatchSelection` & `ImportedBatchStart`: chấp nhận `"rule_only"` & `"hybrid"`, `asi_category` trong `{"unclassified","ASI03","ASI05"}`; từ chối `"ASI01"`, `"custom"`, `["A","A"]`; `both_bad` ưu tiên báo `"Invalid imported batch selection."`.
- `GenericImportedBatchWorkflow` BEFORE snapshot: `runtime_snapshot["model"] == "researchbot"`, thứ tự keys chuẩn xác.

---

## 6. Selected Refactor Design

Sử dụng **2 `ClassVar` trên `OfflineBatchSelection`** mà không thêm hàm mới, không thêm module mới, và không dùng đa kế thừa (tránh làm xáo trộn thứ tự MRO/validator của Pydantic):

```python
class OfflineBatchSelection(ClosedModel):
    _allowed_evaluation_modes: ClassVar[frozenset[str]] = frozenset({"rule_only"})
    _selection_error_message: ClassVar[str] = "Invalid offline batch selection."
    ...
    @model_validator(mode="after")
    def unique_and_rule_only(self):
        if (len(set(self.testcase_ids)) != len(self.testcase_ids)
                or self.evaluation_mode not in self._allowed_evaluation_modes):
            raise ValueError(self._selection_error_message)
        return self
```

- Các lớp con `Asi01BatchSelection`, `Asi01BatchStart`, `ImportedBatchSelection`, `ImportedBatchStart` chỉ khai báo 2 `ClassVar` tương ứng, kế thừa trực tiếp `OfflineBatchSelection.unique_and_rule_only` (và `OfflineBatchStart.confirmed` đối với `*Start`).
- Pydantic v2 tự động bỏ qua `ClassVar` khỏi `model_fields`, `model_dump()`, và JSON Schema; truyền `_allowed_evaluation_modes` từ JSON vẫn bị chặn bởi `ConfigDict(extra="forbid")`.

---

## 7. Validators Consolidated

- **Đã hợp nhất (`4` bản sao lặp -> `1` canonical method):**
  1. `OfflineBatchSelection.unique_and_rule_only` ([`offline_batch.py:48-52`](file:///D:/SecAgent-W5-Judge/backend/src/workflow/offline_batch.py#L48-L52)) — giữ làm bản chuẩn duy nhất.
  2. `Asi01BatchSelection.unique_and_rule_only` (`asi01_batch.py`) — thay bằng 2 `ClassVar` trên [`Asi01BatchSelection`](file:///D:/SecAgent-W5-Judge/backend/src/workflow/asi01_batch.py#L64-L66).
  3. `Asi01BatchStart.unique_and_rule_only` (`asi01_batch.py`) — thay bằng 2 `ClassVar` trên [`Asi01BatchStart`](file:///D:/SecAgent-W5-Judge/backend/src/workflow/asi01_batch.py#L69-L71).
  4. `ImportedBatchSelection.unique_and_rule_only` (`generic_imported_batch.py`) — thay bằng 2 `ClassVar` trên [`ImportedBatchSelection`](file:///D:/SecAgent-W5-Judge/backend/src/workflow/generic_imported_batch.py#L47-L50).
  5. `ImportedBatchStart.unique_and_rule_only` (`generic_imported_batch.py`) — thay bằng 2 `ClassVar` trên [`ImportedBatchStart`](file:///D:/SecAgent-W5-Judge/backend/src/workflow/generic_imported_batch.py#L53-L56).

---

## 8. Validators Intentionally Preserved

- `OfflineBatchStart.confirmed` (`offline_batch.py:61`): xác thực `authorization_confirmed is True` riêng cho submit step.
- `PlanSelection.unique` (`plans.py:30`): cho phép `testcase_ids=[]`, validate `asi_categories`.
- `AdmissionRequest` (`admission.py:44`): `Literal["rule_only", "hybrid"]` gắn với `PlanSelection`.
- `AdmissionPolicy.unique_authorizations` (`admission.py:36`), `Preset.coherent` (`models.py:28`), `CatalogConfig.unique` (`models.py:45`), `TargetDraft.coherent_protocol` (`models.py:73`), `ImportedTestcase.check_prompt_hash` (`dataset_models.py:20`): hoàn toàn khác domain.

---

## 9. Duplicate `"model"` Key Analysis

1. **Cả hai khóa nằm trong cùng dict literal `summary["runtime_snapshot"]`:** trước refactor ở `generic_imported_batch.py:776` và `L780` (tức `L767` và `L771` sau bước G2).
2. **Giá trị giống hệt nhau:** Cả hai đều là `selection.target.model`.
3. **Biểu thức thuần túy:** Truy xuất attribute string đã qua `ModelName` validation trên frozen Pydantic `TargetDraft`, không có side effect.
4. **Khóa tồn tại khi xây dict:** Trong Python, key trùng ghi đè giá trị tại chỗ nhưng giữ nguyên thứ tự chèn của lần xuất hiện đầu tiên (`L767`), làm `L771` hoàn toàn dư thừa và không thể với tới khác biệt.
5. **Hành động:** Xóa dòng thứ hai (`"model": selection.target.model,` trước dòng `"protocol"`).
6. **Kiểm chứng:** Kịch bản đối chiếu BEFORE vs AFTER xác nhận `after_snapshot == before_snapshot` và `list(after_snapshot.keys()) == list(before_snapshot.keys())` (`RUNTIME SNAPSHOT BEFORE/AFTER EXACT VALUE & KEY ORDER MATCH 100%!`), đồng thời `test_workflow_source_has_no_duplicate_dict_keys_and_runtime_snapshot_model_intact` kiểm tra AST trên toàn bộ 33 file `workflow/*.py` có 0 dict literal trùng khóa.

---

## 10. Files Changed

| File | Hành động | Chi tiết |
| :--- | :--- | :--- |
| [offline_batch.py](file:///D:/SecAgent-W5-Judge/backend/src/workflow/offline_batch.py) | Modified (`267 -> 271` LOC) | Thêm `ClassVar`, `_allowed_evaluation_modes`, `_selection_error_message` vào `OfflineBatchSelection` (`L18, 37-52`) |
| [asi01_batch.py](file:///D:/SecAgent-W5-Judge/backend/src/workflow/asi01_batch.py) | Modified (`347 -> 341` LOC) | Bỏ `model_validator` thừa + 2 hàm `unique_and_rule_only` lặp; khai báo `ClassVar` trên `Asi01BatchSelection` & `Asi01BatchStart` (`L64-71`) |
| [generic_imported_batch.py](file:///D:/SecAgent-W5-Judge/backend/src/workflow/generic_imported_batch.py) | Modified (`869 -> 859` LOC) | Bỏ `model_validator` thừa + 2 hàm `unique_and_rule_only` lặp (`L47-56`) và xóa khóa `"model"` trùng trong `runtime_snapshot` (cũ `L771`) |
| [test_stage2b1c_validation_parity.py](file:///D:/SecAgent-W5-Judge/backend/tests/test_stage2b1c_validation_parity.py) | Created (`325` LOC, `23` tests) | Matrix chấp nhận/từ chối, thứ tự validator, kiểm tra không trùng AST dict keys, và tích hợp `runtime_snapshot["model"]` |
| [SECAGENT_STAGE2B1C_IMPLEMENTATION_REPORT.md](file:///D:/SecAgent-W5-Judge/docs/audits/SECAGENT_STAGE2B1C_IMPLEMENTATION_REPORT.md) | Created | Báo cáo triển khai Stage 2B.1c |

---

## 11. Accepted-Input Parity

Đối chiếu BEFORE vs AFTER trên cả 6 model (`stage2b1c_before.json` + `test_valid_evaluation_modes_and_dump_parity`):
- `model_dump(mode="json")` khớp 100% ở mọi trường hợp hợp lệ.
- `PlanSelection` và `AdmissionRequest` tiếp tục cho phép `testcase_ids=[]`.
- `ImportedBatchSelection` và `ImportedBatchStart` tiếp tục chấp nhận `asi_category in {"unclassified", "ASI03", "ASI05"}`.

---

## 12. Rejected-Input/Error Parity

Đối chiếu `ValidationError.errors()` BEFORE vs AFTER trên cả 6 model:
- Khớp chính xác `loc`, `type`, `msg` ở mọi trường hợp: `"hybrid"` trên `Offline*`, `"custom"`/`"HYBRID"`/`"RULE_ONLY"`, `["A","A"]`, `[]` (`too_short`), `_allowed_evaluation_modes`/`unknown_field` (`extra_forbidden`), strict int (`total_request_budget="1"`), `authorization_confirmed=False`, và trường hợp sai kép `both_bad_order` vẫn ưu tiên `unique_and_rule_only` trước `confirmed`.
- Ánh xạ HTTP ở `routes_execution.py` (`/batches/preview` -> `400`, `/batches` -> `409`) không thay đổi.

---

## 13. Security Non-Regression

- Không nới lỏng quy tắc `"rule_only"` cho offline/web/toolbot batches.
- Giữ nguyên `ConfigDict(extra="forbid", strict=True, frozen=True)` qua `ClosedModel`.
- Giữ nguyên xác nhận thực thi `authorization_confirmed is True`, allowlists, grant consumption, `ASI03`/`ASI05` imported bindings, và `runtime_snapshot` provenance.

---

## 14. Focused Regression Results

1. **`python -m py_compile`** (`offline_batch.py`, `asi01_batch.py`, `generic_imported_batch.py`, `test_stage2b1c_validation_parity.py`): Exit code `0`.
2. **Parity & `runtime_snapshot` checks:** `OFFLINE & ASI01 BEFORE/AFTER VALIDATION PARITY MATCHED 100%!`, `IMPORTED VALIDATION PARITY MATCHED 100%!`, `RUNTIME SNAPSHOT BEFORE/AFTER EXACT VALUE & KEY ORDER MATCH 100%!`.
3. **15 Focused Suites (`pytest ... -q`):** Log [task-1444.log](file:///C:/Users/Quettye/.gemini/antigravity-cli/brain/6dd69e96-8654-4b5e-8611-302f06fd7c40/.system_generated/tasks/task-1444.log) dòng `1–5`: **`240 passed in 199.05s (0:03:19)`** (`0` failed, `0` skipped), bao gồm `test_stage2b1c_validation_parity.py`, `test_stage2b1a_exclusive_json.py`, `test_stage2b1b_report_persistence.py`, `test_offline_batch_api.py`, `test_asi01_batch.py`, `test_generic_imported_batch.py`, `test_imported_live_local.py`, `test_workflow_plans.py`, `test_workflow_admission.py`, `test_workflow_targets.py`, `test_dataset_import.py`, `test_asi03_contracts.py`, `test_asi05_execution_core.py`, `test_b47_remediation.py`, `test_stage1b2_api_contract_parity.py`.
4. **AST & Git Check:** `workflow_cycles: []`, `script_imports: []`, `git diff --check` exit code `0`.

---

## 15. Full Backend Regression Results

- Lệnh: `pytest backend/tests -q -rs` (sau chỉnh sửa code cuối cùng).
- Log trực tiếp [task-1444.log](file:///C:/Users/Quettye/.gemini/antigravity-cli/brain/6dd69e96-8654-4b5e-8611-302f06fd7c40/.system_generated/tasks/task-1444.log) dòng `6–30`: **`1,642 passed in 605.85s (0:10:05)`**, **`Command exited with code 0`** (`0` failed, `0` skipped — tăng đúng `+23` test mới so với mốc `1,619` của Stage 2B.1b).
- Frontend không chỉnh sửa (**NOT RUN**).

---

## 16. LOC and Complexity Analysis

| Chỉ số đo được | Giá trị thực tế |
| :--- | :--- |
| Validators inspected across `backend/src` | Toàn bộ validators (`@model_validator`/`@field_validator`), trọng tâm 6 batch models + 5 domain models |
| Validators consolidated | `4` bản sao `unique_and_rule_only` rút về `1` canonical method (`OfflineBatchSelection`) |
| Validators intentionally preserved | `confirmed`, `PlanSelection.unique`, `AdmissionPolicy.unique_authorizations`, `Preset`, `CatalogConfig`, `TargetDraft`, `ImportedTestcase` |
| Duplicate dict entries removed | `1` (`generic_imported_batch.py` `"model"` thứ hai trong `runtime_snapshot`) |
| New helpers / production modules created | `0` helpers, `0` production modules |
| Production modules modified | `3` (`offline_batch.py`, `asi01_batch.py`, `generic_imported_batch.py`) |
| LOC trước Stage 2B.1c (`3` files) | `267 + 347 + 869 = 1,483` LOC |
| LOC sau Stage 2B.1c (`3` files) | `271 + 341 + 859 = 1,471` LOC |
| **Net production LOC reduction** | **`-12` LOC** |
| Tests added | `23` tests trong `test_stage2b1c_validation_parity.py` (`325` LOC) |
| New coupling introduced | `0` (chỉ tái sử dụng chuỗi kế thừa sẵn có giữa `OfflineBatch*`, `Asi01*`, `Imported*`) |

---

## 17. Remaining Risks and Unverified Cases

- Giống các giai đoạn trước, các kịch bản chạy thực thi sử dụng mock/offline fixtures; hành vi đối thoại live LLM (DVAA/DeepSeek/Pi Judge) chưa chạy trực tiếp trong stage này.
- Khớp schema & `ClosedModel` với frontend chỉ kế thừa qua `test_stage1b2_api_contract_parity.py`; bản thân Vitest/Playwright trên frontend không chạy lại do không đổi frontend hay routes HTTP.

---

## 18. Recommendation for Stage 2B.2

Có thể chuyển sang **Stage 2B.2** (chuẩn hóa boilerplate khởi tạo worker thread `launch_batch_worker` và helper đọc `load_valid_grant` với hooks `_owned_grants`/`_baseline_pass` tách biệt), do toàn bộ Stage 2B.1 (2B.1a + 2B.1b + 2B.1c) đã khép lại sạch sẽ trên nền `1,642/1,642` test xanh.

---

## 19. Final Acceptance Verdict

**`STAGE_2B1C_PASS`**

- Đã hợp nhất đúng thực chất 4 bản sao `unique_and_rule_only` về `OfflineBatchSelection` bằng `ClassVar` (không dùng đa kế thừa hay công tắc boolean), giữ nguyên mọi hợp đồng chấp nhận/từ chối và bảo toàn thứ tự validator.
- Đã loại bỏ chính xác khóa `"model"` trùng trong `runtime_snapshot` với kiểm chứng 100% `runtime_snapshot` BEFORE/AFTER parity và `0` dict literal trùng khóa trên toàn `workflow/*.py`.
- Toàn bộ **`240/240`** focused tests và **`1,642/1,642`** full backend tests PASS (exit code `0`).

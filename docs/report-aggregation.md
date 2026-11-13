# Phase 2C.1 — Tổng hợp EvaluationReport chỉ đọc

## Phạm vi và API Python

`reporting.aggregation.aggregate_reports(records)` nhận các `ExecutionReport` và
`ArchivedAssessmentReport` typed từ normalizer/verifier hiện có. Trả
`AggregationSummary`, không đọc file, gọi evaluator/resolver, target hay Pi.
Không sửa input hoặc verdict. Không có API HTTP, DB, UI hay recursive discovery.

CLI `python -m reporting.aggregate` nhận từng `--execution` / `--assessment` cụ
thể, chuẩn hóa qua Phase 2B.1 và chỉ in JSON stdout. Không dựa đuôi filename.
Không nhận JSON v2 tự khai verified làm bằng chứng mới. Có opt-in gọi verifier
Phase 2B.2 qua bộ `--verify-*`, không có verifier mới hoặc replay.

## Schema summary 1.0.0

- `input_report_schema_version=2.0.0`, `metric_definition_version=2C.2.0` sau correction thuật ngữ cho API.
- `selection_policy=all_explicit_unique_sources_no_assessment_selection`.
- `snapshot_sha256`: SHA256 JSON deterministic của các normalized projections
  duy nhất, sort theo kind/source hash; không phải remote attestation, không phải
  SHA256 bytes source. Duplicate input không đổi snapshot.
- Số input, duplicate bị loại, các SHA256 source execution/assessment riêng.
- `counts`: execution records, testcase IDs/definitions, scope true/false/unknown,
  execution statuses, security verdicts, technical errors, completeness, artifact
  states và human-reference **claims**.
- `groups`: ASI, target ID, testcase ID, security verdict và file-integrity state.
  Key null là thiếu dữ liệu, không trộn với chuỗi literal `unknown`.
- `comparisons`: mỗi production record và mỗi archived assessment một entry,
  giữ model/provider/skill, source/parent hash, classification/recommendation,
  recorded comparison claim, trạng thái linkage và comparison suy ra từ giá trị
  đã ghi. Không sửa historical comparison hoặc historical verdict trong input.
- `metrics`: numerator, denominator, value nullable, status và định nghĩa rõ.
- `source_limitations`: giữ giới hạn source/verifier đã lọc; giới hạn chung của
  aggregation riêng. Không xuất raw response, canary, tool args hoặc URL callback.

## Đơn vị đếm và dedup

Dedup bằng kind + source file-byte SHA256 do normalizer đã tính. Kiểm tra source
identity/report ID khớp digest; không dùng tên testcase hoặc filename. Projection
khác nhau cho cùng digest bị từ chối, không tự chọn metadata verified thuận lợi.
Khi dùng opt-in verifier, đừng đồng thời chọn lại bản plain của cùng source.

Hai source hash khác nhau vẫn là hai **record**, dù testcase ID giống nhau.
Execution ID trùng nhưng hash khác được giữ và đếm trong
`execution_identity_conflicts`: không giả định đây là hai physical invocations.
Records thiếu execution ID vẫn được đếm, không tạo ID hay timestamp mới.

`recorded_execution_reports` khác actual attempts. `recorded_execution_attempts`,
`confirmed_target_invocations`, `planned` đều có reported_true/reported_false/
unknown; `total_if_fully_known=null` nếu còn unknown. HTTP success hoặc status
failed không tự điền các flag này. `successful_execution_reports` đếm status
succeeded; `execution_errors` đếm failed. Lỗi evaluation/Judge/report được đếm
riêng theo technical error stage, không chuyển thành security FAIL.

`distinct_testcase_ids` là số ID quan sát. `distinct_testcase_definitions` chỉ có
số khi mọi record có testcase ID **và** definition-file hash trong
`historical_integrity`; thiếu thì null, kèm known pairs và missing count.
Đây là deliberate restriction do schema lịch sử chưa ghi version/hash đầy đủ.
Target grouping chỉ dùng ID, không khẳng định cấu hình target tương đương.

## Rule/Judge và linkage

Archived assessment không tăng execution denominator. Join chỉ khi parent
execution ID và parent file-byte SHA256 cùng khớp selected execution. Không join
theo testcase/target/tên file. Parent missing/hash mismatch/ID mismatch/unverified
linkage được giữ riêng. Verifier mismatch hoặc snapshot/identity mâu thuẫn chặn
comparison; recorded agreement claim vẫn giữ riêng, không được tính agreement
hợp lệ.

Baseline comparison là `deterministic.original.status`, không historical final
verdict và không đổi sang effective rule một cách ngầm định. Chỉ source-reported
valid Judge với classification và binary PASS/FAIL, cùng binary original rule,
mới so agreement/disagreement. Đây là arithmetic comparison, không đánh giá lại
security hoặc tái validate Judge JSON. UNCLEAR/INCONCLUSIVE, source unavailable,
source inconsistency, provider fault/invalid JSON, prevented, not requested và
rule-decisive skip là các bucket riêng. `semantic_invoked` không chứng minh provider
đã hoàn tất. Không tổng hợp confidence thành accuracy.

Mọi assessment duy nhất được giữ, kể cả kết quả mâu thuẫn hoặc model khác nhau.
Không latest/best selection. `archived_reported_comparison_claims` đếm claims nguồn;
`archived_comparison_counts` đếm derived comparisons chỉ trên linkage dùng được.
Multiple assessments làm tăng assessment counts, không tăng target execution counts.
`executions_without_linked_crosscheck` khác Judge unavailable/failed trên linked
assessment. Production và archived có coverage riêng, không trộn mẫu số.

## Metrics và mẫu số

| Metric | Numerator | Denominator / unknown |
| --- | --- | --- |
| decisive_verdict_rate_among_classified | Historical PASS + FAIL | PASS + FAIL + INCONCLUSIVE; unknown/error-unassessed đếm riêng. |
| decision_coverage_over_all_records | Historical PASS + FAIL | Tất cả selected execution records, gồm unknown và technical-error records. |
| decision_coverage (deprecated alias) | Historical PASS + FAIL | Giữ mẫu số classified cũ để tương thích; consumers mới dùng hai tên rõ ràng ở trên. |
| Evidence coverage | null trong phase này | Candidate pool = selected execution records. Chưa biết applicable invocations và không có all-ASI sufficiency contract, status unavailable_contract; không lấy PASS/FAIL hay complete=true để giả đủ evidence. |
| Verified artifact coverage | Records có metadata verified của đủ bốn artifact, hashes khớp và execution digest gắn đúng source | Tất cả selected execution records; metadata thiếu/not_performed không được loại khỏi denominator. |
| Production Judge comparison coverage | Agreement + disagreement production | Tất cả selected execution records, gồm not requested/skipped/prevented/unavailable. |
| Archived Judge comparison coverage | Agreement + disagreement linked archived | Tất cả unique selected assessments, gồm orphan/mismatch/unavailable. |

Mẫu số 0 → value null, không 0%/100%. Các rate đếm được có status
zero_denominator; evidence coverage vẫn unavailable_contract. Coverage là trên
selection được công bố, không trên toàn testcase repository và không là detection
accuracy, precision, recall hoặc defense success rate.

`response_completeness` chỉ đếm complete/partial/unknown source claims.
`local_consistency_verified_records` và `locally_consistent_callback_records`
chỉ tóm tắt metadata được cấp: file integrity verified, stored-record consistency
verified và receipt_count > 0 cho callback bucket. Không là external action
attestation. Aggregator không xác thực lại file hoặc tính lại evidence sufficiency.
Caller phải cấp normalizer/verifier outputs đáng tin trong tiến trình; typed schema
không phải chữ ký xác thực metadata. Human verified labels cũng chỉ là claim đã
ghi; phase này không tính accuracy kể cả khi trường reference có mặt.

## PowerShell — chọn các report cụ thể

Chỉ normalization và aggregation, không xác minh archive mới:

```powershell
Set-Location D:\SecAgent-W5-Judge
$env:PYTHONPATH='backend/src'
$env:SECAGENT_NO_DOCKER='1'
python -m reporting.aggregate `
  --execution results/judge-validation/asi01-compose/control-20261106T0742519269397Z/reports/native-20261106T080745537588Z-GH-WEB-C01-dvaa-researchbot-lab.secagent.json `
  --execution results/judge-validation/asi01-compose/attack-20261106T0813087606067Z/reports/native-20261106T082008213826Z-GH-WEB-001-dvaa-researchbot-lab.secagent.json `
  --assessment results/judge-validation/hybrid-cross-check/gh-web-001-pi-20261107_092815-cfd6f7c8.json
```

Opt-in tái dùng verifier 2B.2 cho attack và assessment, control chỉ normalization:

```powershell
python -m reporting.aggregate `
  --execution results/judge-validation/asi01-compose/control-20261106T0742519269397Z/reports/native-20261106T080745537588Z-GH-WEB-C01-dvaa-researchbot-lab.secagent.json `
  --verify-root results/judge-validation `
  --verify-inventory asi01-compose/attack-20261106T0813087606067Z/evidence-sha256.csv `
  --verify-execution asi01-compose/attack-20261106T0813087606067Z/reports/native-20261106T082008213826Z-GH-WEB-001-dvaa-researchbot-lab.secagent.json `
  --verify-assessment hybrid-cross-check/gh-web-001-pi-20261107_092815-cfd6f7c8.json
```

CLI exit 0 khi summary được tạo, kể cả có security FAIL hoặc parent mismatch.
Exit 2 khi input thiếu/sai format/không an toàn hoặc conflicting projections.
Không có output-file option. Chỉ đọc các file chọn rõ; không scan cả workspace.

## Ví dụ JSON (trích đoạn, không phải toàn schema)

Smoke check dùng verifier opt-in trên archive thật trả:

```json
{
  "summary_schema_version": "1.0.0",
  "input_report_schema_version": "2.0.0",
  "metric_definition_version": "2C.2.0",
  "counts": {
    "recorded_execution_reports": 2,
    "distinct_testcase_ids": 2,
    "distinct_testcase_definitions": null,
    "security_verdicts": {"PASS": 0, "FAIL": 1, "INCONCLUSIVE": 1, "unknown": 0},
    "response_completeness": {"complete": 0, "partial": 0, "unknown": 2}
  },
  "archived_assessments": 1,
  "archived_reported_comparison_claims": {"agreement": 1, "disagreement": 0, "unavailable": 0, "not_recorded": 0},
  "metrics": {
    "decision_coverage": {"numerator": 1, "denominator": 2, "value": 0.5},
    "decisive_verdict_rate_among_classified": {"numerator": 1, "denominator": 2, "value": 0.5},
    "decision_coverage_over_all_records": {"numerator": 1, "denominator": 2, "value": 0.5},
    "evidence_coverage": {"numerator": null, "denominator": 2, "value": null},
    "verified_artifact_coverage": {"numerator": 1, "denominator": 2, "value": 0.5},
    "archived_judge_comparison_coverage": {"numerator": 1, "denominator": 1, "value": 1.0}
  }
}
```

Scope attempted/confirmed vẫn unknown cho cả hai source cũ. Không có PASS control:
GH-WEB-C01 giữ INCONCLUSIVE. SHA256 cả bảy file được đọc không đổi; không chạy
target hoặc Judge. Đây là deterministic DVAA runtime, không chứng minh LLM tự chọn
tool. Không sửa các báo cáo thực nghiệm cũ để ghi summary.

## Kiểm thử đã hoàn thành

```powershell
$env:PYTHONPATH='backend/src'
$env:SECAGENT_NO_DOCKER='1'
python -m pytest backend/tests/test_report_aggregation.py -q -p no:cacheprovider
python -m pytest backend/tests/test_report_aggregation.py backend/tests/test_reporting_models.py backend/tests/test_report_normalization.py backend/tests/test_reporting_artifacts.py -q -p no:cacheprovider
python -m pytest backend/tests -q -p no:cacheprovider
```

Kết quả: 43 passed; 172 passed (43 mới + 129 reporting hiện có); full backend
861 passed, 1 skipped. Skip duy nhất là Docker Compose CLI bị tắt rõ ràng bởi
SECAGENT_NO_DOCKER. Test mới chỉ dùng synthetic data/mocks, không phụ thuộc results/.
Smoke check archive thật là thao tác đọc riêng, không là dependency của tests.

Không triển khai API, frontend, database, aggregation repository/discovery hoặc
Promptfoo importer. Chưa có capability/evidence contract đầy đủ để tính ASI-specific
evidence sufficiency coverage. Các metric không thay thế nghiên cứu có ground truth.

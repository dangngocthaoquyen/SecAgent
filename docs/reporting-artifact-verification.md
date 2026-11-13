# Phase 2B.2 — Kiểm tra archive cục bộ chỉ đọc

API opt-in: `reporting.artifacts.verify_archive(root, inventory=..., execution=...,
assessment=...)`. Các lựa chọn là đường dẫn tương đối với root được người dùng
chỉ định. Không tự scan results, không theo parent path trong report, không tải URL.
CLI `python -m reporting.verify` chỉ in JSON ra stdout, không ghi archive.

`artifact_verification` là metadata bổ sung trên normalized execution/assessment.
Normalizer mặc định không gọi verifier; các trường reported và verification cũ
không bị nâng trust. Verdict lịch sử và null completeness không thay đổi.

Các chiều độc lập:

- `file_integrity`: so SHA256 **bytes** của bốn artifact với inventory `Path,Hash`.
  Inventory được hash nhưng không tự xác thực; assessment cũng không tự có chữ ký.
- `internal_evidence_consistency`: đối chiếu manifest, JSONL, collector export và
  collector claims trong execution. Đây là tính nhất quán của bản ghi đã lưu,
  không phải vừa quan sát một HTTP request lịch sử.
- `collector_canonical_digest`: thuật toán collector lịch sử
  `sha256(utf8(json.dumps(records, sort_keys=True)))`, khác SHA256 bytes JSONL.
- `crosscheck_linkage`: parent execution ID **và** SHA256 bytes execution phải khớp.
  Correlation fixture được kiểm tra riêng. Không join bằng testcase/tên tệp.
- `external_action_attestation=not_performed`: không có remote attestation/chữ ký.

State: verified / mismatch / missing / unsupported / not_performed. Các check chi
tiết không sửa FAIL/PASS/INCONCLUSIVE. CLI trả 0 khi các kiểm tra bắt buộc đạt,
1 khi có vấn đề bằng chứng/integrity/linkage, 2 khi input không an toàn hoặc sai
định dạng. Exit code này không phải security verdict.

Profile hiện tại chỉ hiểu manifest fixture schema 1, attack GH-WEB-001 và một
collector evidence reference. Category khác chưa có profile kiểm chứng riêng.
Thiếu artifact trả missing; sai/duplicate CSV, traversal, links/reparse points,
file không thường hoặc quá lớn bị từ chối với thông báo cố định không chứa raw data.
CSV tối đa 64 KiB, artifact 10 MiB, JSONL 10.000 events. Text giải mã UTF-8 rõ ràng;
JSON duplicate keys và nonfinite numbers bị từ chối. Không theo các path trong
tool args hoặc URL. Chỉ bốn path đúng profile được chấp nhận trong inventory.
Absolute Windows paths lịch sử phải vẫn nằm trong root; archive được di chuyển
không được tự rebase qua tên tệp.

Fixture correlation chỉ xuất dạng alias SHA256; không xuất manifest canary, origin,
expected peer hoặc raw log. Normalized previews dùng redaction hiện có. Redaction
không phải DLP tổng quát; hash không bảo vệ bí mật có entropy thấp trước dò từ điển.

Root phải là snapshot cục bộ được operator kiểm soát, không writable bởi attacker.
Kiểm tra lstat trước/sau giúp phát hiện thay đổi thông thường, không bảo đảm chống
mọi race thay thế path bởi tiến trình độc hại. Không triển khai quyền truy cập OS,
immutable storage hay signature infrastructure trong phase này.

Peer-match và timestamps chỉ được đối chiếu theo giá trị lưu; log không chứa raw
peer IP để tự tính lại expected peer match. Không chứng minh attribution mạng,
độ đầy đủ toàn bộ action scope hoặc LLM tự quyết định chọn tool. Runtime DVAA
deterministic vẫn là giới hạn nghiên cứu.

Ví dụ đọc archive thật (root chung bao gồm execution và assessment):

```powershell
Set-Location D:\SecAgent-W5-Judge
$env:PYTHONPATH='backend/src'
python -m reporting.verify results/judge-validation `
  --inventory asi01-compose/attack-20261106T0813087606067Z/evidence-sha256.csv `
  --execution asi01-compose/attack-20261106T0813087606067Z/reports/native-20261106T082008213826Z-GH-WEB-001-dvaa-researchbot-lab.secagent.json `
  --assessment hybrid-cross-check/gh-web-001-pi-20261107_092815-cfd6f7c8.json
```

Phase 2C (API, aggregation, DB/UI) chưa triển khai.

## Kiểm chứng offline đã hoàn thành

Môi trường: `PYTHONPATH=backend/src`, `SECAGENT_NO_DOCKER=1`.

```powershell
$env:PYTHONPATH='backend/src'
$env:SECAGENT_NO_DOCKER='1'
python -m pytest backend/tests/test_reporting_artifacts.py backend/tests/test_reporting_models.py backend/tests/test_report_normalization.py -q -p no:cacheprovider
python -m pytest backend/tests/test_archived_crosscheck.py backend/tests/test_runner_judge_integration.py backend/tests/test_hybrid_evaluator.py backend/tests/test_response_evaluator.py backend/tests/test_response_observer.py backend/tests/test_external_evaluator_connector.py backend/tests/test_official_asi01_runner.py backend/tests/test_asi01_web_callback.py backend/tests/test_researchbot_web_baseline.py -q -p no:cacheprovider
python -m pytest backend/tests -q -p no:cacheprovider
```

Kết quả lần lượt: **129 passed** (48 artifact tests mới + 81 reporting tests cũ),
**237 passed**, **818 passed, 1 skipped**. Skip là kiểm tra Docker Compose CLI bị
tắt rõ ràng bởi SECAGENT_NO_DOCKER. Không gọi Docker hoặc dịch vụ mạng.

Smoke check archive GH-WEB-001: bốn byte hashes, canonical collector digest,
internal consistency và parent linkage đều verified; receipt_count=1, method GET.
External attestation not_performed; original deterministic/final FAIL và Judge
FAIL/agreement không đổi; response completeness unknown. SHA256 của cả sáu tệp
(inventory, bốn artifact và assessment) không đổi trước/sau kiểm tra.

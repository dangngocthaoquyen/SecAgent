# Phase 2C.2 — API báo cáo chỉ đọc trên localhost

## Kiến trúc

Đã kiểm tra dependency và entry points: backend khai báo httpx/Pydantic/PyYAML,
chưa có HTTP service framework. Môi trường có Flask 3.1.3, không có FastAPI,
Starlette hoặc Uvicorn. Tái dùng Flask, khai báo riêng trong
`backend/requirements-reporting.txt` (`Flask>=3.1,<4.0`); requirements-dev bao gồm
file này để môi trường mới có dependency cho API tests. Base requirements của
execution engine không đổi. Không chạy pip/tải dependency trong task.

`reporting.repository.load_dataset` đọc selection do operator kiểm soát, chuẩn
hóa và optionally gọi verifier 2B.2 một lần ở startup. Pure aggregator hiện có
tạo summary. `reporting.api.create_app` tạo detached JSON views. HTTP requests
chỉ đọc snapshot trong bộ nhớ, không đọc file, chạy evaluator/target/Pi, tải URL
hoặc viết report. Không auto-reload/HTTP refresh; operator restart để đổi dataset.

CLI dùng Werkzeug development server trên 127.0.0.1. Đây là prototype một operator,
chưa là shared production deployment. Test client kiểm tra HTTP semantics trong
tiến trình, không mở listening socket hoặc gọi external system.

## Manifest 1.0.0

Ví dụ thật: `configs/reporting/asi01-lab-example.json`. Cấu trúc:

```json
{
  "dataset_schema_version": "1.0.0",
  "allowed_roots": {"research": "../../results/judge-validation"},
  "reports": [
    {"root": "research", "path": "selected-control.json", "kind": "execution"}
  ],
  "verification_jobs": [
    {"root": "research", "inventory": "archive/evidence-sha256.csv",
     "execution": "archive/reports/native.json", "assessment": "assessment.json"}
  ]
}
```

Root tuyệt đối hoặc tương đối với manifest; operator chọn rõ. Selected paths phải
tương đối bên trong root. Bỏ verification_jobs nếu chỉ muốn normalization, chọn
execution/archived_assessment trong reports. Empty selection hợp lệ. Không nhận
manifest/path/root từ HTTP và không scan workspace. Không import JSON v2 tự khai
verified hoặc Promptfoo thành trusted native reports; prior-result import chưa hỗ trợ.

Bounds: manifest 64 KiB; 8 roots; 128 input reports (kể cả jobs); 16 verification
jobs; 10 MiB/artifact; 64 MiB tổng unique bytes kể cả inventory/fixture. Duplicate
input vẫn tính vào input limit. Reject malformed/duplicate-key JSON, nonfinite,
unknown fields/formats, traversal, external path, symlink/reparse point, UNC và
mapped network drive. Verification inventory vẫn dùng contract bốn artifact 2B.2.
Files thay giữa selected read và verifier read bị từ chối. Không bảo đảm chống
mọi race trên root attacker-writable; root phải được operator kiểm soát.

Startup lỗi selection thất bại toàn bộ với generic JSON stderr/exit 2, không phục
vụ subset im lặng. Exact source duplicates dedup; conflicting projections reject.
Đừng chọn đồng thời bản plain và verified khác nhau của cùng source bytes.

## Routes và response contract

API version 1.0.0; normalized report 2.0.0; summary 1.0.0; metrics 2C.2.0.
Responses là application/json, giữ null/unavailable và stable report IDs.

| GET route | Response |
| --- | --- |
| `/api/reports/health` | status, schema versions, dataset availability/counts/snapshot và verification lifecycle; không paths/secrets. |
| `/api/reports/overview` | `{api_schema_version, summary, verification}` từ existing aggregator, trên toàn selection. |
| `/api/reports/executions` | `{api_schema_version, snapshot_sha256, page, page_size, total, items}`; sort report ID. |
| `/api/reports/executions/{report_id}` | `{api_schema_version, snapshot_sha256, execution}` normalized detail và linked assessments. |
| `/api/reports/comparisons` | `{api_schema_version, snapshot_sha256, production, archived}`; giữ mọi assessment. |

List items gồm report/execution ID, target/testcase/ASI, historical security verdict
và status, execution/record status, completeness, file-integrity state, verification
origin và linked assessment count. Exact filters: asi_category, target_id,
testcase_id, verdict. ASI01/02/03/05 được hỗ trợ; asi_category=unknown và
verdict=unknown chọn null. ERROR không là security verdict/filter; technical errors
vẫn giữ trong detail và overview. Page bắt đầu 1, tối đa 999999; page_size mặc định
25, tối đa 100. Duplicate/unknown params, sai enum/identifier/pagination trả 400.
Empty match hoặc page ngoài phạm vi trả items=[]; overview không đổi theo trang.

Detail giữ security/original_final_result/deterministic, response preview, evidence
references/provenance, completeness, Judge diagnostics, optional verification,
limitations và linked archived assessments. `tool_evidence` chia declared_calls,
target_reported_actions, collector_records, other_observations; không nâng source
claim/declaration thành verified action. Archived target_execution_performed=false.
Comparisons có linkage, judge_invocation_state, provider_diagnostics đã lọc và
verification_origin. Parent execution ID và byte SHA256 phải cùng khớp; orphan/
mismatch vẫn hiện riêng, không join theo testcase/filename. Không đổi verdict.

Errors: `{api_schema_version,error:{code,message}}`. 400 invalid query/ID, 404
unknown selected report, 405 method, 403 local/origin boundary, 500 generic fault.
Không echo raw exception, path hay request value. Không file download endpoint.

## Metrics và verification origin

| Field | Numerator | Denominator |
| --- | --- | --- |
| decisive_verdict_rate_among_classified | PASS + FAIL | PASS + FAIL + INCONCLUSIVE; unknown disclosed riêng. |
| decision_coverage_over_all_records | PASS + FAIL | Tất cả selected execution records, gồm unknown/error/skipped/incomplete; không exclusions. |
| decision_coverage | PASS + FAIL | Deprecated alias của classified rate, giữ giá trị legacy. |

Mẫu số 0 trả null. PASS/INCONCLUSIVE/unknown cho rates 1/2 và 1/3. Golden hai
execution cho cả hai 1/2. Evidence sufficiency coverage vẫn unavailable.

Plain inputs: verification_origin=not_requested. Jobs: current_api_lifecycle,
nghĩa verifier hiện có đã chạy khi startup, bao gồm cả mismatches. Health/overview
ghi computed_at=dataset_startup, current count, prior_result_records=0 và
prior_result_import_supported=false. Aggregator không tự verify. Historical source
claims giữ nguyên; external_action_attestation luôn not_performed. Hash/consistency
không là mới quan sát HTTP request hoặc chứng minh LLM tự chọn công cụ.

## HTTP boundaries và giới hạn

CLI không có --host, luôn bind 127.0.0.1. App chỉ nhận loopback peer và Host
localhost/127.0.0.1, không ProxyFix/X-Forwarded-For trust. Network exposure cần
review/approval và thay đổi riêng. Không CORS wildcard; cross-origin/cross-site
bị chặn, không Access-Control-Allow-Origin. Chỉ GET, không body; HEAD/OPTIONS và
POST/PUT/PATCH/DELETE trả 405. Query tối đa 2048 bytes. Không mutation/execute routes.

No-store, nosniff, CSP default-src none/frame-ancestors none, no-referrer headers.
Target HTML chỉ là JSON string; dashboard tương lai phải escape/render text.
Giữ normalizer redaction và che local paths trong public text/diagnostics. Không
xuất raw arguments, manifest canary, auth store hoặc source filesystem paths.
Redaction không là general DLP; dùng reviewed dataset. Loopback không là user
authentication; auth/ACL/TLS/rate limits/shared deployment chưa triển khai.

## PowerShell

Terminal 1 (environment đã có requirements-reporting):

```powershell
Set-Location D:\SecAgent-W5-Judge
$env:PYTHONPATH='backend/src'
$env:SECAGENT_NO_DOCKER='1'
python -m reporting.api --manifest configs/reporting/asi01-lab-example.json --port 8091
```

Terminal 2:

```powershell
$reportsApi = 'http://127.0.0.1:8091/api/reports'
Invoke-RestMethod "$reportsApi/health" | ConvertTo-Json -Depth 20
Invoke-RestMethod "$reportsApi/overview" | ConvertTo-Json -Depth 40
$page = Invoke-RestMethod "$reportsApi/executions?asi_category=ASI01&verdict=FAIL&page=1&page_size=25"
$page | ConvertTo-Json -Depth 20
$reportId = [Uri]::EscapeDataString($page.items[0].report_id)
Invoke-RestMethod "$reportsApi/executions/$reportId" | ConvertTo-Json -Depth 50
Invoke-RestMethod "$reportsApi/comparisons" | ConvertTo-Json -Depth 40
```

Ctrl+C dừng service; không đổi evidence. Smoke/test trong task dùng Flask test
client, không khởi động server/container/target/Pi. Phase 2D chưa triển khai.

## Kiểm chứng offline đã hoàn thành

```powershell
$env:PYTHONPATH='backend/src'
$env:SECAGENT_NO_DOCKER='1'
python -m pytest backend/tests/test_reporting_api.py backend/tests/test_report_aggregation.py backend/tests/test_reporting_models.py backend/tests/test_report_normalization.py backend/tests/test_reporting_artifacts.py -q -p no:cacheprovider
python -m pytest backend/tests -q -p no:cacheprovider
```

Kết quả: **232 passed** trong API/reporting (gồm 59 API cases), **921 passed,
1 skipped** toàn backend. Skip là Docker Compose CLI bị tắt bởi biến môi trường.
`git diff --check` không có whitespace errors. Không dùng live results trong tests.

Smoke read-only riêng với example manifest: cả năm routes trả thành công qua Flask
test client. Hai execution records: FAIL=1, INCONCLUSIVE=1, PASS=0; một archived
assessment FAIL/agreement. Hai decision metrics đều 1/2; verified artifact coverage
1/2; evidence sufficiency coverage unavailable. Response completeness unknown cho
cả hai. Startup verification origin=current_api_lifecycle trên attack và assessment,
prior-result count 0, external attestation not_performed. SHA256 cả bảy source/archive
files không đổi; không raw canary hoặc archive path trong public JSON.

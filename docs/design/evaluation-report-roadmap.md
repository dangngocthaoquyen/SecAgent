# Phase 2A — Lộ trình triển khai đánh giá và báo cáo thống nhất

Trạng thái: kế hoạch để duyệt, **không triển khai trong Phase 2A**.
Ưu tiên tái sử dụng mã đã hoạt động, thay đổi nhỏ có thể review và giữ nguyên
execution/verdict lịch sử. Các đường dẫn dưới đây ghi “mới” là đề xuất, chưa được tạo.

### Ghi nhận phạm vi Phase 2B.1

Đã triển khai package reporting models/normalizers, CLI chỉ in stdout và fixtures/
tests riêng; không wire Runner, không đổi core/evaluator/skills, không writer,
artifact registry, API, aggregation hoặc dashboard. Schema JSON được xuất trong
bộ nhớ, chưa có file schema registry hoặc migration.

Correction ưu tiên: source-provided trust chỉ là claim lịch sử; failed không
chứng minh target invocation; phân biệt đầy đủ trạng thái Judge/comparison; tách
historical verdict/decisiveness khỏi coverage, verification, technical errors và
human reference. Missing execution_id giữ null, report_id từ bytes không thay nó.
Legacy PASS giữ nguyên; minimal report_fault không được tạo kết luận bảo mật mới.

Các hạng mục full archive/parent/artifact verification, citation representation
mapping và quyền truy cập vẫn là Phase 2B.2/2C, chưa được phép coi là đã hoàn tất
nhờ đọc một report. Giữ nguyên các bước tương lai dưới đây, chờ duyệt riêng.

Tài liệu đầu vào:
[kiểm toán](evaluation-report-architecture-audit.md),
[schema/ngữ nghĩa](evaluation-report-specification.md),
[thiết kế giao diện](evaluation-dashboard-design.md).

## 1. Quyết định cần duyệt trước khi viết mã

1. Chấp nhận report_schema_version=2.0.0 cho envelope mới, giữ Judge contract v1.0
   và archived report 1.0 nguyên trạng.
2. Tách execution status/evaluation technical status khỏi security PASS/FAIL/
   INCONCLUSIVE; null là chưa đánh giá, không là verdict thứ tư.
3. Bản normalized là projection có source hash, không phải lần chấm lại. Giữ
   legacy status và policy/sufficiency warning khi import; không sửa Resolver.
4. Archived assessment là append-only, parent ID + byte hash; không last-write-wins
   vào final verdict của execution.
5. Chọn reporting repository tệp chỉ đọc trước, chưa database/migration. Mọi API/UI
   ban đầu chỉ đọc, không tự chạy target/Pi hay mở URL trong evidence.
6. Xác nhận rules cho denominator, assessment selection, ASI mapping và artifact
   redaction/authorization trước khi công bố dashboard metric.
7. Chưa chọn web framework. Hiện không có backend HTTP API/frontend để “mở rộng”;
   lựa chọn dependency/server cần duyệt ở 2C/2D, không giả định React/Next/FastAPI.

## 2. Ranh giới trách nhiệm và tái sử dụng

| Chủ thể | Phần việc |
| --- | --- |
| Q / hạ tầng | Report models/normalizer/repository/aggregation/API, telemetry invocation, redaction và evidence references; bảo toàn Runner/Pi/budget/resolver. |
| K / testcase và rubric | Mục tiêu hợp lệ/attacker, điều kiện ASI, yêu cầu evidence, taxonomy sửa trong testcase, Markdown Judge skills và labels; phối hợp review, không bị reporting tự sửa. |
| Chủ lab / nghiên cứu | Xác nhận nguồn/peer/clock/correlation, quyền truy cập target, reference labels, protocol control/attack và giới hạn kết luận. |
| Reviewer dữ liệu | Duyệt fixture đã lọc, quyền truy cập artifact, retention, benchmark field semantics và scenario mapping. |

Tái sử dụng trực tiếp: TestCaseLoader, PayloadLoader/Renderer,
bind_testcase_variables, TargetProfile/build_runtime_target, Runner, Executor,
ResponseObserver, ResponseEvaluator/rule registry, HybridEvaluator,
EvaluationRequestBuilder, SkillBundleLoader, PiEvaluatorProvider, BudgetedJudgeProvider,
validated_recommendation/parse_judge_response, resolve_verdict, public_evidence_data,
prepare_cross_check/write_cross_check. Không thêm connector, evaluator, Resolver,
planner hay harness mới.

Nguồn dữ liệu có thể dùng lại: native report, archived assessment, local collector
archive đã kiểm tra hash; Garak smoke có semantics tách success kỹ thuật; dataset
scoring có nhãn người review. Không xem chúng là cùng một schema chỉ vì có đuôi
.secagent.json, và không nhập tất cả results/ thành dữ liệu công khai.

## 3. Phase 2B — Schema và chuẩn hóa báo cáo

### 3.1 Các thay đổi nhỏ đề xuất

**2B.1 — Model và semantics, chưa gắn vào luồng thực thi**

- Mới: `backend/src/reporting/__init__.py`, `models.py`, `schema.py` nếu cần export
  JSON Schema, `normalizers.py`.
- Mới: `backend/tests/test_evaluation_report_models.py`,
  `test_report_normalization.py`, fixtures đã review dưới
  `backend/tests/fixtures/reporting/`.
- Reuse model/value enums hiện có khi thích hợp; security-only enum thuộc reporting
  không thay EvaluationStatus của engine. Không sửa Judge schema v1.0.
- Triển khai read-only normalize native legacy và archived v1 trước. Garak/benchmark
  chỉ nhận diện đúng kind hoặc trả unsupported, không tự gán security outcome.

**2B.2 — Integrity, references và projection bất biến**

- Mới nếu thực sự cần: `backend/src/reporting/artifacts.py`, `writer.py`.
- Dùng byte hashing/canonical hashing hiện có, giữ tên serialization riêng. Có thể
  tách helper dùng chung sau khi review, không viết lại bộ kiểm tra archive.
- Source classification rõ, reject unknown schema/duplicate keys/traversal, lưu
  orphan assessment khi parent hash lệch. Writer exclusive/atomic cho bản mới;
  không thay report gốc hoặc CSV inventory.
- Kiểm tra redaction trước khi fixture vào version control. Không phụ thuộc
  runtime outputs dưới results/ trong tests.

**2B.3 — Capture metadata cho các lượt MỚI, sau khi adapter ổn định**

- Có thể sửa hẹp `backend/src/testing/runner.py` và
  `backend/scripts/run_native_smoke.py`: cấp execution ID trước thực thi, lưu
  start/end và snapshot context/payload/config hashes đã lọc.
- Duy trì Runner.run trả EvaluationResult, last_report/report_sink và output legacy
  mặc định trong giai đoạn chuyển tiếp. V2 export là opt-in hoặc một writer bên
  ngoài đã duyệt; không buộc mọi caller đổi API cùng lúc.
- `backend/src/evaluators/hybrid_evaluator.py` và
  `backend/src/testing/evaluation_config.py` chỉ được bổ sung telemetry như
  skip_reason/delegate_called/budget_reserved khi cần; không thay routing policy.
- `backend/src/testing/archived_crosscheck.py` và CLI chỉ thêm adapter xuất
  assessment v2, giữ mode, budget, output exclusivity và không gọi target.

### 3.2 Kiểm thử và nghiệm thu

- Golden fixtures nhỏ cho native/archived, ERROR, report_fault tối giản, null
  completeness, collector proof, MCP direct_request, redacted representation.
- Cùng bytes import nhiều lần có cùng identity; một execution + nhiều assessments
  không nhân run. Link sai parent hash phải bị cô lập.
- Original bytes/verdict giữ nguyên trước/sau normalize; valid semantic PASS bị
  resolver downgrade không thành invalid JSON. Legacy deterministic PASS unknown
  vẫn là original PASS với cảnh báo, không tự chấm lại.
- Serialization validate JSON Schema/Pydantic; references/citations trỏ đúng
  representation; không lộ raw canary/key/arguments/absolute private paths.
- Regression các test Runner/Hybrid/connector/official GH/archive vẫn giữ hành vi.

Điều kiện nghiệm thu: có thể đọc hai báo cáo thật GH-WEB-001 đã lưu và control
INCONCLUSIVE qua bản fixture đã lọc, tạo representation mới nhất quán; không cần
Docker, target hoặc Pi live. Không yêu cầu/khẳng định thay đổi verdict policy.

Rủi ro: metadata lịch sử thiếu; nhiều loại .secagent.json; taxonomy không đồng
nhất; chuỗi Evidence source chưa có authenticity. Giải pháp là giữ unknown,
source/raw reference và legacy projection, không tự dựng fields hoặc “verified”.

**Việc đầu tiên khuyến nghị:** chỉ thực hiện 2B.1 bằng model + hai normalizer thuần
đọc và golden tests; chưa sửa Runner, API hoặc UI. Đây là PR nhỏ nhất kiểm chứng
được tính thống nhất mà không thay hành vi bảo mật.

## 4. Phase 2C — Tổng hợp và API đọc

### Thay đổi dự kiến

- Mới: `backend/src/reporting/repository.py`, `aggregation.py`.
- Mới sau khi duyệt framework: `backend/src/api/app.py`, `report_routes.py` hoặc
  lớp wrapper tương đương; `backend/requirements.txt` chỉ thêm dependency được duyệt.
- Mới: `backend/tests/test_report_repository.py`, `test_report_aggregation.py`,
  `test_report_api.py`.
- Reuse normalizers/artifact controls của 2B; `evaluate_gh_dataset.metrics/score`
  là tham khảo khi có labels, không thay bằng scoring giả không ground truth.

### Phạm vi

- Repository tệp chỉ đọc, allowlisted roots chứa bản đã lọc, index ID/hash trong
  bộ nhớ; không scan auth/compose.env/raw archives. Không database migration.
- Endpoints GET theo đặc tả; phân trang/filter/snapshot, opaque artifact ID và
  authorization. Không thêm POST execute/replay/Judge hoặc URL fetch endpoint.
- Aggregator trả counts, denominators, exclusions/unknowns, metric definition
  version, model/policy strata và selection policy cùng dữ liệu.

### Kiểm thử/nghiệm thu

- Kiểm chứng P+F+I=N_sec; error/skipped/unassessed tách riêng. Không có plan thì
  planned/skipped unknown. N=0 trả null cho rate.
- Dedup import, retry identities, một/multi ASI, nhiều target config trùng ID,
  nhiều archived assessments, selection model/skill rõ.
- Provider timeout/budget prevented không là target FAIL. Rule-first skipped không
  là Judge agreement; comparison denominator không loại unavailable mà giấu coverage.
- Security metric không cộng external grader PASS; external records tách tập.
- API pagination không làm summary đổi mẫu số; path traversal/oversized/unknown
  schemas/dangling artifacts không lộ dữ liệu hoặc làm crash toàn index.

Điều kiện nghiệm thu: trên bộ fixture cố định, CLI/API tổng hợp cho cùng filter
có cùng counts và snapshot. Không có network-dependent tests; source bị thay byte
được phát hiện. Triển khai mặc định local/read-only; chính sách auth cần được duyệt
trước khi cho người dùng khác truy cập.

Rủi ro: thiếu run plan; memory index lớn; trạng thái tệp đổi trong lúc đọc; phân
quyền artifact. Giảm thiểu bằng snapshot/hash, file-size bounds, unknown buckets;
chỉ xem database là lựa chọn sau đo đạc, không xây trước.

## 5. Phase 2D — Dashboard và chi tiết testcase

### Thay đổi dự kiến

- Frontend hiện chưa có. Sau khi duyệt stack, mới tạo `frontend/` với
  `src/pages/EvaluationOverview.*`, `ExecutionDetail.*`,
  `src/components/EvidenceTimeline.*`, `VerdictBadge.*`, `JudgeDiagnostics.*`,
  `EvidenceRequirementTable.*`, và API client/types sinh từ contract nếu phù hợp.
- Tên đuôi/đường dẫn cụ thể tùy framework; đây không phải các file có sẵn.
- Mới UI/unit/E2E fixtures/tests, tất cả dùng dữ liệu/mock API đã lọc.
- Backend chỉ bổ sung field/filter cần thiết từ report API, không cho UI gọi
  trực tiếp target/Pi hoặc đọc tùy ý filesystem.

### Kiểm thử/nghiệm thu

- Hai màn hình đầu theo [thiết kế UI](evaluation-dashboard-design.md): overview,
  execution detail/evidence timeline; giao diện vẫn chỉ đọc.
- Người dùng thấy được agent đã làm gì, nguồn nào xác nhận, reason và scope nào
  dẫn đến verdict; declared http_post khác observed GET rõ ràng.
- Header original FAIL không bị đổi khi chọn archived Judge PASS; control
  INCONCLUSIVE không hiển thị như defense PASS.
- Unknown timestamps không thành giả timeline; JSON valid/downgrade/provider lỗi
  là các trạng thái khác nhau; confidence có cảnh báo chưa hiệu chuẩn.
- Chống XSS/canary-link prefetch; raw restricted artifacts không tự tải. Keyboard,
  screen reader, focus, color-independent badges, loading/empty states đều có test.

Điều kiện nghiệm thu: trả lời được năm câu hỏi của người dùng bằng cách lần từ
summary đến source evidence, không cần mở raw log có bí mật. Summary/table/detail
giữ cùng filter/snapshot. Không đưa wizard chạy attack vào scope phase này.

Rủi ro: quá tải thông tin, màu PASS bị hiểu quá mức, target text trở thành HTML
đáng tin, người xem nhầm claim với fact. Ưu tiên hai luồng evidence/interpretation
và role/source labels thay vì nhiều điểm số không có cơ sở.

## 6. Phase 2E — So sánh và nhập benchmark

### Thay đổi dự kiến

- Mới: `backend/src/reporting/comparison.py`,
  `backend/src/reporting/importers/promptfoo.py` nếu đã nhận raw export/config;
  có thể thêm adapter Garak dùng `build_smoke_summary` hiện có.
- Mới: `frontend/src/pages/ComparativeEvaluation.*`,
  `BenchmarkSourceDetail.*` cùng các component so sánh.
- Mới: `test_report_comparison.py`, `test_promptfoo_import.py`,
  `test_external_grading_semantics.py`, fixtures đã được duyệt từ nguồn có thật.
- Reuse `prepare_cross_check`, `write_cross_check`, existing request/provider và
  verifier; không tạo workflow target execution mới dưới nút “compare”.

### Phạm vi và nghiệm thu

- Join theo execution/source hash và scenario/config mapping rõ, không theo tên
  file, testcase prefix hoặc thứ tự rows. Nhiều model/skills được phân tầng.
- Giữ agreement/disagreement/unavailable theo basis, không tính label agreement
  khi rule chỉ có verdict. Reference verdict không tự là ground truth.
- Benchmark fields raw/pass/success/stopReason/fetchAttempts/webFetchActuallyUsed
  được giữ cùng source semantics; thiếu raw evidence thì không map SecAgent verdict.
- Screenshot CodeBot và dataset ResearchBot không bị nhập thành cùng target.
- Tóm tắt Promptfoo hiện có chỉ là annotation chưa đối chiếu; không tạo 20 native
  runs giả. Chưa có tài liệu thì importer implementation bị chặn, không đoán schema.
- UI/API xuất selection, hashes, denominator definitions và unsupported mappings.

Rủi ro: schema Promptfoo khác phiên bản, grader đảo nghĩa pass, report chỉ là
screenshots và thiếu tool trace. Biện pháp: versioned importer và semantics review;
không gọi mạng tự tải tài liệu, không tính defense success rate từ grader PASS.

## 7. Phase 2F — Regression, tài liệu và xác nhận nghiên cứu

### Thay đổi dự kiến

- Mở rộng `backend/tests/` cho model/normalizer/API/aggregation và tests UI;
  cập nhật `docs/` cùng README khi hành vi đã triển khai/kiểm chứng.
- Cập nhật báo cáo nghiên cứu bằng artifact mới, không sửa các archive lịch sử.
- Nếu cần CI, sửa workflow dưới `.github/workflows/` đã review; không thêm live
  credentials/model calls làm điều kiện mặc định của PR.
- Tài sản testcase/rubric và normalizer ASI03/05 là dependency do chủ tương ứng
  review riêng; không tự thêm chúng để làm cho dashboard có số PASS.

### Ma trận hồi quy bắt buộc

| Nhóm | Bằng chứng nghiệm thu |
| --- | --- |
| Production legacy | Rule-only mặc định; deterministic precedence, unknown semantic completeness, collector guard và ngân sách giữ nguyên. |
| Archive | Byte hash vs canonical digest khác nhau đúng nhãn; parent bất biến; tamper/missing/unsupported làm unavailable, không rerun target. |
| UI/API | Không tiết lộ raw credentials/canaries/arguments; escaped text và citation trỏ đúng representation; artifact ACL được thực thi. |
| Tổng hợp | Fixed denominator fixtures, dedup, unknown/zero, multi assessments, multi ASI, benchmark-only; không tăng target count vì cross-check. |
| ASI01 | Lab runtime verified callback và control INCONCLUSIVE được mô tả đúng; không tuyên bố autonomous DeepSeek. |
| ASI02 | Direct MCP và agent-induced tool action không bị đồng nhất; official action strategy không tự gọi Judge. |
| ASI03 | Guards baseline A/B, principal/resource binding, actual cross-principal read evidence; semantic unavailable được trình bày trung thực. |
| ASI05 | Sandbox/exact allowlist/canary effect/run attribution; command suggestion không thành exec; semantic unavailable không thành PASS. |
| Judge quality | Independent human reference đã xác nhận, nhãn provisional tách riêng; reported confidence không là accuracy. |

Mọi live validation cần plan, target authorization, model/call budget và approval
riêng. Không lấy một lần agreement GH-WEB-001 để tuyên bố accuracy toàn bộ ASI01
hoặc validation ASI02/03/05. Báo cáo control trước đó là INCONCLUSIVE phải được
giữ đúng trong bảng/biểu đồ/tóm tắt nghiên cứu.

Điều kiện nghiệm thu: focused/full offline regression chạy thực sự và được ghi
command/count/skip reasons; chụp bằng chứng UI nếu đã có UI; công bố limitations
và phạm vi tested/untested. Tài liệu không được dùng “đã pass” cho tests chưa chạy.

## 8. Backward compatibility và cách chia PR

| PR nhỏ | Phạm vi | Không làm |
| --- | --- | --- |
| 2B.1 | Reporting models + legacy/cross-check normalizers + golden tests | Không wire Runner, không đổi verdict, không UI/API. |
| 2B.2 | Artifact references/hash/redaction/exclusive writer | Không sửa byte archive hoặc đổi Judge contract. |
| 2B.3 | Opt-in capture/export/telemetry cho run mới | Không thay rule-first/budget/scope semantics; giữ API cũ. |
| 2C.1 | File repository + aggregation thuần | Không database, không live calls. |
| 2C.2 | API đọc + access controls | Không arbitrary path/URL fetch hoặc endpoint tự execute. |
| 2D | Overview/detail UI + mock tests | Không attack planner hoặc mở target URL tự động. |
| 2E | Comparison và reviewed benchmark adapters | Không coi external grade là security verdict. |
| 2F | Hồi quy và research validation được duyệt | Không tự đổi K assets hoặc tạo bằng chứng thiếu. |

Rollout dùng feature flag/export opt-in và schema discriminator rõ. Chỉ báo cáo
mới được ghi thêm; có thể bỏ qua file v2 để quay lại consumer legacy mà không
đụng original reports. Không rollback bằng cách reset/ghi đè/delete archive.
Nếu adapter không biết source version, nó phải từ chối hoặc giữ partial metadata,
không tự diễn giải một trường success không rõ nghĩa.

## 9. Các câu hỏi còn cần xác nhận

- Chưa có hai tài liệu Promptfoo trong workspace: cần raw config/export/version,
  grader semantics và mapping ResearchBot/CodeBot trước phase nhập benchmark.
- Ai được xem raw restricted evidence, lưu bao lâu, và nguồn nào được đưa vào
  report API? Không mặc định mở toàn results/ cho frontend.
- Muốn giữ native legacy output mặc định trong bao lâu? Có cần report consumers
  bên ngoài repo hay backward API contract nào chưa được ghi nhận?
- Có run-plan/campaign manifest ngoài workspace không? Nếu không, skipped/planned
  counts phải được capture ở tương lai, không suy từ lịch sử.
- Framework API/frontend, môi trường chạy và phạm vi người dùng lab/local chưa
  được chốt. Không tạo giả định về server/database hiện hữu.
- Cần đồng thuận taxonomy mapping cho GH legacy/LLM01 và các ID ASI khác dạng;
  thay đổi tài sản là việc phối hợp với K, không phải normalizer tự sửa.
- Ai cung cấp trusted agent-origin normalizers/baselines cho ASI02/03/05 và
  rubric tương ứng? K có tài sản không đồng nghĩa adapter đã đủ bằng chứng.
- Policy PASS nghiêm ngặt hơn cho legacy deterministic result có được nghiên cứu
  chấp nhận không? Đây là quyết định tương lai, không thuộc Phase 2B normalization.

## 10. Kết quả Phase 2A

Chỉ tạo bốn tài liệu thiết kế. Không thay backend/frontend/schema runtime,
VerdictResolver, testcase/skill, database hoặc báo cáo đã lưu. Không chạy pytest,
Docker, target, Pi hay network-dependent operation. Chờ phê duyệt trước 2B.1.

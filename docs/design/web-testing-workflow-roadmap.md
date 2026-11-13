# Phase 3A — Lộ trình triển khai nhỏ, có thể review

**Chỉ thiết kế.** Không file implementation nào dưới đây được tạo ở Phase 3A. Đọc [audit](web-testing-workflow-audit.md) và [đặc tả](web-testing-workflow-specification.md) trước khi triển khai. Mỗi phase cần phê duyệt riêng; không khởi chạy target chỉ vì đã merge code UI.

## 1. Vertical slice được đề xuất

Một operator local, một preset HTTP OpenAI-compatible đã được cấp quyền, một testcase benign đã review tương thích, rule-only mặc định, một request, không retry và không Judge live. Test offline bằng adapter giả và FakeJudge trước; live nghiệm thu cần operator duyệt exact target/case/budget. GH-C01 chỉ phù hợp khi target hỗ trợ tác vụ chat tương ứng; không chọn làm ResearchBot web-fetch baseline một cách máy móc. GH-WEB-C01 không được hứa PASS khi thiếu trace/completeness; GH-WEB-001 cần lab collector readiness riêng.

Sau khi slice hoàn chỉnh, UI hỗ trợ chọn mọi tập con bốn ASI nhưng chỉ dispatch case được compatibility chấp nhận. Không đợi full MCP/A2A hoặc mọi ASI observer để cung cấp UI selection trung thực.

## 2. Phase 3B — Target Configuration và Connection Preflight

**Tái sử dụng:** `TargetProfile`, `load_target`, `validate_target`, `build_runtime_target`, HTTP client/adapter, Flask dependency, shell React hiện tại. Không gọi Runner để ping.

**File mới dự kiến:** `backend/src/workflow/{models,target_policy,targets,api}.py`; `configs/workflow/authorized-targets.example.json` không secret; `frontend/src/{testingApi,TargetConfiguration}.tsx` (API client có thể dùng `.ts`); tests riêng `backend/tests/test_workflow_targets.py`, frontend target/preflight tests. **File có thể sửa:** `frontend/src/App.tsx`, `vite.config.ts`, docs mới cho workflow. Chỉ mở prefix proxy control riêng; reporting prefix không đổi.

**APIs:** GET targets, POST target-drafts/validate, POST connection-checks theo đặc tả. Ban đầu static presets + bounded runtime draft. Mutation bảo vệ bằng session token/Origin/Host/CSRF; không token bền trong browser.

**Tests:** invalid scheme/userinfo/path traversal; private IP không nằm allowlist; IPv6/IPv4-mapped và localhost resolution; port/path mismatch; redirect/proxy/header override; secret alias ngoài catalog; missing secret không leak; validate không I/O; probe một request/max timeout/no tools; foreign Origin, content-type, forged Host; lỗi transport sanitized. Dùng mock transports; không Docker/target live trong suite.

**Acceptance:** operator chọn một authorized HTTP preset, xem config hợp lệ; active probe chỉ khi bấm xác nhận; kết quả không có security verdict. MCP được ghi rõ hạn chế hoặc disabled cho execution; A2A unsupported. Không arbitrary secret/env/executable ở API.

**Rủi ro/compatibility:** runtime helper chỉ bảo vệ URL dynamic, generic YAML không có policy tương đương; mọi web profile phải đi qua server policy. Giữ CLI hiện tại; không siết toàn bộ CLI bằng breaking schema ở cùng PR. Cần quyết định safe health endpoint của target trước khi bật probe.

## 3. Phase 3C — ASI selection, compatibility, preview

**Tái sử dụng:** `TestCaseLoader`, `PayloadLoader`, `PayloadRenderer`, `bind_testcase_variables`, attack/rule registries, evaluation models và `SkillBundleLoader` (chỉ load file, không gọi Pi).

**File mới dự kiến:** `backend/src/workflow/{catalog,compatibility,plans}.py`; `configs/workflow/testcase-requirements.json` sidecar đã review; `frontend/src/{TestConfiguration,TestPlanPreview}.tsx`; `backend/tests/test_workflow_plans.py` và frontend fixtures. **File có thể sửa:** workflow models/API và navigation. Không sửa K YAML/skills để ép compatible.

**APIs:** GET testcase catalog theo repeated `asi` query; POST plans/preview. Preview không target/Judge/network; chỉ immutable plan có hashes/TTL, ready và excluded cases/reasons.

**Tests:** đầy đủ 15 nonempty ASI subsets + empty/unknown/duplicate; kiểm kê 19 in-scope/6 out-of-scope ở snapshot fixture, không hardcode số production; taxonomy conflict; duplicate testcase IDs; payload ref/variable thiếu; multi-ref chưa hỗ trợ; missing rubric; semantic-only với Judge off; ASI03 baseline thiếu; ASI05 sandbox thiếu; MCP argument mapping sai; direct-tool scope không thay agent-origin. Kiểm tra preview không được chạy module/network side effect.

**Acceptance:** UI Select All/Clear All đúng; không phải tất cả case đều selected runnable. Không supported chỉ vì tên target giống tool. Bind/rule parameters và rendered payload dùng cùng reviewed variables. Human expected answer không vào Judge input. Không tự downgrade strategy để vượt thiếu skill.

**Rủi ro:** requirements hiện nằm trong prose, cần operator xác nhận sidecar; asset đổi hash thì review hết hiệu lực. Target metadata self-claim phải là unknown/requires_configuration, không ghi verified.

## 4. Phase 3D — Secure Run API và điều phối sequential

**Tái sử dụng:** một `Runner` mỗi job; `Executor`, `ResponseObserver`, evaluator/resolver và `RunnerEvaluationConfig/BudgetedJudgeProvider`. Dùng Python function call, không shell. `report_sink` và cơ chế native report write-exclusive giữ semantics.

**File mới dự kiến:** `backend/src/workflow/{runs,store}.py`, `backend/tests/test_workflow_runs.py`. **Tách nhỏ dùng chung nếu cần:** `backend/src/testing/native_preparation.py`, `native_reporting.py`; `backend/scripts/run_native_smoke.py` chuyển gọi helper, không thay behavior. Web fixture hook tái sử dụng `WebFixture`/RecordingExecutor thay copy collector logic; chưa hỗ trợ arbitrary remote collector registration.

**Transport gap phải xử lý có test trước live:** boundary target-request budget bằng injected adapter/client wrapper tin cậy; explicit timeout/response-size cap, no redirect/no environment proxy. Nếu cần sửa `tools/http/client.py` để bounded response đọc theo stream, đó là PR riêng nhỏ, default CLI backward-compatible và có test. Không giả vờ current client đã bảo đảm max bytes. Không rebuild Executor/Observer/evaluation.

**APIs:** POST runs + idempotency, GET run, POST cancel. Đề xuất một worker và bounded queue; admission limit server không cho UI vượt. Durable sanitized job manifest trước dispatch và child journal; không database trong slice. Cancellation giữa testcase, bounded wait cho in-flight, không hứa rollback.

**Tests:** double click/idempotent retry không nhân request; stale plan/asset changed; cancel trước start và khi đang chạy; race cancel/result; shared Judge budget qua nhiều case; timeout/fault vẫn tiêu reservation; zero Judge budget không spawn Pi; no automatic retry; worker crash không replay; output write failure phân biệt security verdict; malicious output paths/headers/secret echoes; Runner precedence và semantic PASS unknown vẫn INCONCLUSIVE. Fake adapters/FakeJudge dùng registry đúng, không production module chưa register.

**Acceptance:** một approved plan dispatch đúng một pipeline với sequential order; không chạy excluded cases; toàn run có target/Judge caps; native return/report semantics unchanged; report error không thành PASS/FAIL. ASI03/05 thiếu observer hoặc guard không được chạy. Không cung cấp UI upload code hoặc canary command tự do.

**Rủi ro:** Runner đồng bộ và có mutable `last_report`/diagnostics, không share instance đồng thời. `run_smoke()` mới Runner mỗi lần sẽ reset budget, nên không dùng làm vòng lặp campaign. In-flight timeout không bảo đảm target ngừng làm việc; phải hiển thị rõ. Raw data redaction không phải general DLP, cần reviewed synthetic scope.

## 5. Phase 3E — Active Runs và publication vào Reports

**Tái sử dụng:** reporting models/normalizers/artifacts/aggregation/repository; bốn frontend reporting views, report_id theo source hash, parent linkage hiện có.

**File mới dự kiến:** `frontend/src/ActiveRuns.tsx`; `backend/src/workflow/publication.py`; tests publication/progress. **File có thể sửa:** workflow store/API, App navigation; chỉ khi đã duyệt lifecycle refresh mới sửa nhỏ reporting repository/API composition, không thêm mutation route vào Reporting.

**MVP APIs:** GET run có progress revision/counters/child outcomes/report publication refs; polling có backoff bounded, dừng ở terminal state. Không SSE/WebSocket bắt buộc. “Đang chạy testcase” là mức tiến độ có bằng chứng; không hiển thị đang gọi tool hay phần trăm Judge khi Runner không cung cấp sự kiện.

**Publication hai bước:**

1. Native reports viết xong, normalize read-only, tạo manifest lựa chọn mới do server quản lý. UI báo saved/not_in_current_snapshot. Operator nạp manifest bằng restart Reporting; UI “Reload API snapshot” rồi dùng report_id để mở.
2. Nếu cần trải nghiệm hoàn toàn web, quyết định riêng cơ chế internal atomic snapshot replacement: chỉ đọc files đã commit dưới allowed roots, dùng `load_dataset`, khóa/version snapshot để request đọc nhất quán, không có endpoint HTTP reload/execute trên Reporting. Control service không được cung cấp arbitrary files cho Reporting. Khi snapshot mới chưa sẵn sàng, UI không giả available. Không đổi historical report bytes.

**Tests:** polling không execution; saved≠published; missing/corrupt report; persistence fail; restart recovery/interrupted; stale snapshot; old detail remains readable; source hashes unchanged; linked assessment không tăng target execution count; no filename-only joins; health/overview/list/detail/comparison regressions; no partial file exposure; comparisons không bị overwrite khi có run mới.

**Acceptance:** operator theo dõi trạng thái, cancel đúng semantics, mở kết quả bằng reporting hiện có khi publication hoàn tất. PASS/FAIL/INCONCLUSIVE không đổi; technical errors/cancelled/skipped không bị tính thành security finding. Nếu chưa chọn phương án atomic refresh, phải gọi đây là MVP cần operator reload, chưa tuyên bố workflow hoàn toàn tự động qua web.

## 6. Những quyết định cần xác nhận trước triển khai

1. Một target được phép cho vertical slice, exact origin/port/path và safe probe endpoint; quyền outbound của chính target trong lab do ai quản lý?
2. Nguồn catalog quyền local và ai cấp session control token; không lấy frontend acknowledgement thay policy.
3. Requirements sidecar do ai review; scope direct MCP hay agent-origin; ASI03 authorization-baseline observer và ASI05 sandbox audit do adapter nào cung cấp? Hiện chưa có bằng chứng sẵn sàng tổng quát.
4. Default caps: đề xuất concurrency 1/no retries/HTTP 30s/Judge 90s; upper bounds operator, queue size/job TTL/retention cụ thể cần chốt. Không tự bật Judge.
5. Chấp nhận cooperative cancel và interrupted-no-replay trong MVP? Nếu cần hard cancellation, cần worker process lifecycle riêng, không thể đạt bằng nút UI.
6. Chọn manual publication trước hay atomic snapshot refresh để đạt fully-web; giữ Reporting read-only trong cả hai phương án.
7. ASI03/05 semantic contracts và skills chưa có: không bật UI như tính năng hoàn chỉnh. A2A/full MCP chỉ là roadmap sau khi protocol/adapters có test và evidence contracts.

## 7. Ranh giới kết thúc Phase 3A

Chỉ tạo ba tài liệu thiết kế. Chưa triển khai endpoint, queue, catalog, compatibility policy, UI targets hoặc run control. Không chạy automated tests hay live preflight trong audit này. Bước tiếp theo được đề xuất là **3B với một authorized HTTP preset và config-only preflight**, sau khi người dùng duyệt; không bắt đầu tự động.

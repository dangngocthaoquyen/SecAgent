# SecAgent — Quyết định kiến trúc: Evaluation, Target Connection và Evidence Collection

**Ngày ghi nhận:** 2026-11-15  
**Trạng thái:** Architectural direction agreed; implementation requires repository audit and staged migration  
**Phạm vi:** Thiết kế tổng quát của SecAgent, **không** phải một công cụ chuyên kiểm thử DVAA.  
**Nguồn:** Quyết định thống nhất trong trao đổi thiết kế SecAgent và các quan sát thực nghiệm được nêu ở phần 8.  
**Đích lưu trữ dự kiến:** `docs/architecture/SECAGENT-DESIGN-DECISIONS.md`.

> **Quan trọng:** Tài liệu này là bản ghi quyết định và kế hoạch mục tiêu, **không khẳng định tất cả thành phần đã được triển khai**. Khi triển khai phải khảo sát source code hiện tại, giữ backward compatibility và kiểm thử hồi quy. `CODEX_CONTEXT.md` trên nhánh `main` có mô tả phạm vi cũ; tài liệu này ghi nhận hướng phát triển mới, không tự động sửa hay phủ nhận lịch sử đã triển khai.

## 1. Mục tiêu và nguyên tắc cốt lõi — ĐÃ CHỐT

SecAgent là **framework kiểm thử bảo mật AI Agent đa Target**, tổ chức theo hướng **Dataset-Driven** và **Evidence-Grounded**. Target luôn là hệ thống bên ngoài SecAgent. DVAA, AIGoat hay một ứng dụng Agent khác chỉ là các nền tảng để xác minh tính tổng quát.

Các nguyên tắc:

1. **Không hardcode theo sản phẩm**: core không chứa `DVAAClient` hay URL nội bộ DVAA; tái sử dụng lớp giao thức và nguồn bằng chứng có cấu hình.
2. **Phân biệt ba việc**: *gửi attack / thu thập phản hồi*, *quan sát hành động*, *đánh giá vi phạm*. Không xem việc nối được HTTP là chứng minh có quyền quan sát runtime.
3. **Giới hạn kết luận theo bằng chứng**: lời nói của Agent, tool call được khai báo, sự kiện handler mô phỏng và thực thi thật là các mức khác nhau.
4. **Không mặc định tin dữ liệu kiểm thử nhập khẩu**: payload/metadata/grade gốc phải được lưu provenance; verdict của SecAgent do rubric, policy và evidence độc lập quyết định.
5. **Từng bước, không refactor toàn repo**: giữ Runner, Target Adapter, Hybrid Judge, report contract đang có; bổ sung bằng hợp đồng tương thích và regression tests.

## 2. Hệ thống Testcase — Dataset-First — ĐÃ CHỐT

### 2.1. Phân vai dữ liệu

- **External datasets** (ví dụ Promptfoo, benchmark khác, JSON/YAML hợp lệ) là đầu vào **chính thức** cho thực nghiệm bảo mật quy mô nhiều testcase.
- **Native YAML/testcases** của nhóm chủ yếu dùng để test nội bộ SecAgent: unit, integration, regression, đối chứng có kiểm soát. Chưa xóa các file native và marker hiện có.
- Một dataset lớn không mặc nhiên có ground truth độc lập. Nếu nghiên cứu độ chính xác của Judge cần nhãn tham chiếu được gán/kiểm tra độc lập; kết quả Promptfoo chỉ là đối chứng, không phải oracle.

### 2.2. Chuẩn hóa

Mọi source importer chuyển sang một **Normalized Security Testcase** có tối thiểu: `case_id`, `source`, `original_id`, `attack.prompt`, `attack.delivery_surface` (nếu biết), taxonomy source và taxonomy đã review, provenance/hash, metadata nguồn. Không đưa assertion của Promptfoo vào luồng quyết định như policy đáng tin cậy.

Mapping từ Promptfoo plugin sang OWASP ASI phải được review; không suy ra chắc chắn một ASI chỉ từ tên plugin. Dữ liệu thiếu được đánh dấu thiếu, không đoán.

### 2.3. Marker/regex

- Marker/regex **không phải bắt buộc** đối với imported cases.
- Giữ deterministic rules cho bằng chứng hoặc invariant có thể xác minh độc lập, kiểm thử contract và regression.
- Không coi việc Agent lặp lại chuỗi marker do attacker cung cấp là bằng chứng duy nhất của goal hijack, privilege abuse hay command execution.

## 3. Evaluation System — ĐÃ CHỐT VỀ NGUYÊN TẮC

### 3.1. Pipeline mục tiêu

`Dataset Import → Normalize → Evaluation Planning/Readiness → Runner + Target Interface → Observation + Evidence Collection → Deterministic Rules / Semantic AI Judge / Action Verification (khi có) → Verdict Resolution → Report`

**Evaluation Planner** xác định trước cách đánh giá dựa trên loại case, mục tiêu bảo mật, trusted Target Evaluation Profile, evidence scope và khả năng quan sát. Không chỉ triển khai luật đơn giản kiểu `regex fail → gọi Judge`.

Thông tin trusted gồm rubric, boundary, policy, legitimate goal và evidence requirement (nếu dùng); phải đến từ cấu hình do người dùng/nhóm review chứ không phải instructions kèm trong attack payload.

### 3.2. Các dạng đánh giá

- **Deterministic / Rule Engine**: phù hợp khi điều kiện quan sát chính xác, nguồn chứng cứ đáng tin và có thể kiểm chứng.
- **Semantic AI Judge**: đánh giá ngữ cảnh, goal deviation, identity claim, response artifact; phải đưa ra lý do gắn với bằng chứng; không phải oracle và cần đo false positive/false negative.
- **Action / State Verifier**: chỉ xác nhận hành động thực tế khi có log executor, trace hoặc state evidence có nguồn đáng tin cậy, được liên kết với testcase.

### 3.3. Giới hạn theo nhóm ASI

- **ASI01 (Agent Goal Hijack)**: cần legitimate goal, attacker goal, trust boundary và biểu hiện lệch mục tiêu; nếu dataset chỉ có attack prompt, lấy ngữ cảnh từ scenario/target profile đã review hoặc đánh dấu chưa đủ điều kiện đánh giá. Cần phân biệt direct chat với indirect content injection.
- **ASI03 (Identity & Privilege Abuse)**: phân biệt *first-party authority claim trong response* với *privilege escalation/hành động vượt quyền thực tế*. Kết quả response-only không thể kết luận có privilege escalation.
- **ASI05 (Unexpected Code Execution)**: phân biệt *command artifact trong response*, *declared tool call*, *handler invocation*, *simulated execution* và *verified execution*. Không ghi một command code fence là lệnh đã chạy.

### 3.4. Kết quả / báo cáo

- Verdict bảo mật trong phạm vi case: `PASS`, `FAIL`, `INCONCLUSIVE`. **Lỗi kỹ thuật (`ERROR`) là trạng thái chạy/đánh giá riêng**, không được tráo thành PASS hoặc FAIL.
- Mỗi kết quả ghi `evaluation_scope`, `evidence_level`, `evidence_source`, citations/IDs, lý do, dữ liệu thiếu và mức độ liên kết event-testcase.
- Báo cáo thống kê tách: **Security Results**, **Evidence Quality**, **Evaluation Quality**. Số FAIL response-level không đồng nghĩa số confirmed runtime exploit.
- Lưu cả phiên bản target, profile, dataset hash, Judge version/model/rubric version, execution configuration để tái lập.

## 4. Target Connection — Universal Target Discovery — ĐÃ CHỐT VỀ HƯỚNG

SecAgent hỗ trợ target **bất kỳ nơi nào có giao thức tương thích và quyền truy cập hợp lệ**, không phải riêng DVAA.

### 4.1. Luồng kết nối mục tiêu

`Frontend Add Target (URL + credentials hợp lệ nếu có) → Safe Protocol Discovery → Capability Preview → User Review → Persisted Target Profile → Target Adapter → Runner`

- **Giao thức**: HTTP/REST (bao gồm OpenAI-compatible khi phù hợp), MCP JSON-RPC, A2A; phát triển theo nhu cầu và kiểm tra thực tế khả năng code hiện có.
- **Adapter theo giao thức**, không theo nền tảng. Những khác biệt thực sự của API có thể được giải quyết bằng declarative config/transport plugin thay vì hardcode platform names.
- **Auto-discovery chỉ là best effort**: `tools/list`, Agent Card hoặc schema metadata có thể cho biết capability công bố; không tự động biết runtime sandbox, quyền thật hay internal trace URL.
- **Không thực hiện arbitrary port scan** hay gọi công cụ có tác động trong bước discovery. Bảo vệ SSRF, chặn truy cập nội bộ trái phép, enforce URL allowlist theo môi trường, timeout/rate limit, redaction secrets và authorization scope.
- Target Profile được lưu và tái sử dụng để đổi bot nhanh trong lúc demo. Việc đổi target phải kiểm tra đúng endpoint/model/protocol và profile version, tránh trường hợp chọn CodeBot nhưng thực tế gửi ResearchBot.

### 4.2. Capability / Readiness

Khi kết nối, mô hình profile cần phân biệt `declared_capabilities`, `verified_transport`, `available_evidence_sources`, `authorization_context` và `evaluation_readiness`. `tools/list` chứng minh MCP server công bố tools, **không chứng minh LLM Agent tự gọi tools**.

## 5. Evidence Collection — Universal Evidence Collector — ĐÃ CHỐT VỀ HƯỚNG

**Không xây Evidence Adapter riêng cho DVAA trong core như kiến trúc mặc định.** Dùng các collector/adapters tổng quát theo **loại nguồn**:

- **Response Observation**: response, status, metadata từ lần Runner gọi target.
- **Protocol Tool Evidence**: khai báo `tool_calls`, MCP request/response khi quan sát hợp lệ; phân biệt direct `tools/call` do SecAgent gửi với agent-initiated tool action.
- **Tracing/Telemetry**: tool spans/events qua OpenTelemetry hoặc tracing provider được chủ sở hữu cho phép.
- **External Evidence Source**: HTTP JSON API, callback, read-only evidence endpoint; người dùng khai báo URL, auth, JSON mapping, collection mode (`snapshot_diff`, cursor, ID-based), execution semantics và trust level.
- **Filesystem/Runtime Evidence**: chỉ khi sandbox/target cho quyền quan sát phù hợp; không thể suy ra từ một URL chat.

Đây là các **năng lực mục tiêu**, không khẳng định tất cả đã triển khai.

### 5.1. Correlation bắt buộc

Cần `batch_run_id`, `testcase_id`, `target_id`, `target_request_id`, `tool_invocation_id` và `event_id` (nếu nguồn hỗ trợ), kèm provenance. Ưu tiên ID do target phát ra và ánh xạ tin cậy. Timestamp và marker/prompt substring **không đủ** chứng minh event thuộc về testcase.

- Nếu chỉ có snapshot before/after: có thể chứng minh thay đổi quan sát được trong cửa sổ thử nghiệm cô lập, nhưng phải ghi `attribution=weak/unverified` khi không có event ID.
- Khi thiếu telemetry, đánh giá chỉ ở phạm vi **response-only**; không tự tuyên bố tool executed.
- Không tự chạy lại command do Agent sinh ra trong sandbox của SecAgent rồi coi là hành động của target.
- Log đến từ Target/API có thể chứa input không đáng tin (bao gồm prompt injection); không đưa log thô vào trusted Judge instruction, không đọc credentials hoặc dữ liệu nhạy cảm không cần thiết.

### 5.2. Evidence levels chuẩn hóa (đề xuất)

| Mức | Ý nghĩa | Kết luận được phép |
|---|---|---|
| `response_only` | Chỉ có nội dung phản hồi | Agent đã **nói** gì |
| `textual_tool_call` | Tags/JSON mô phỏng tool call trong văn bản | Agent **biểu diễn** một tool call |
| `declared_tool_call` | Structured tool call từ API/trace | Agent **yêu cầu** một tool call |
| `tool_handler_invoked` | Log tại dispatcher/handler | Handler **nhận** hành động |
| `simulated_execution` | Handler mô phỏng và trả kết quả | Sandbox **mô phỏng xử lý** |
| `runtime_execution_verified` | Executor/process/state proof đáng tin | Hành động **được xác minh** trong môi trường target |

Đây là các nhãn đề xuất; khi implement cần thiết kế schema tương thích với existing models và phạm vi evidence thực tế.

## 6. Vấn đề sandbox — ĐÃ CHỐT

Sandbox dùng để xác minh tác động phải thuộc hoặc được target gắn vào **tool runtime thực tế của target**. SecAgent có thể điều phối, reset hoặc đọc telemetry của sandbox khi được cấp quyền, nhưng **không** tự thực thi lại output rồi gán kết quả cho Agent.

- Dùng một runtime/sandbox dùng chung cho nhiều bot có thể khả thi nếu họ dùng chung executor và có isolation/reset giữa các testcase.
- Không giả định một Docker container chứa nhiều bot đồng nghĩa mọi bot đều dùng cùng executor.
- Có thể dùng cơ chế simulator cho nghiên cứu hành vi handler, nhưng phải gọi đúng tên mô phỏng.
- Nếu bổ sung đường thực thi tool cho bot vốn không có, đó là **thay đổi năng lực của Target**; phải phân biệt *baseline* và *instrumented target variant* trong báo cáo.

## 7. Frontend & Demo — ĐÃ CHỐT VỀ TRẢI NGHIỆM

Giao diện hướng tới `Import Dataset → Add/Select Target → Detect/Review Capabilities → Choose Evaluation Scope → Run Batch → Evidence/Report`. Target Profile và Evidence Source config được lưu, nên có thể chuyển CodeBot/ToolBot/Agent khác trong cùng fleet mà không cần tạo nhiều môi trường.

Demo ưu tiên tuần tự, ít testcase trực tiếp; report của full batch được chuẩn bị riêng. Khi evidence unavailable, giao diện phải cho thấy `response_only` hoặc `not_ready/inconclusive`, không đánh lừa người dùng rằng có action verification.

## 8. Quan sát thực nghiệm DVAA-DeepSeek — ĐÃ XÁC MINH TRONG BUỔI KIỂM TRA

**Target thực nghiệm:** container `dvaa-deepseek` (source nằm trong image, không bind mount); dùng DeepSeek. Các kết quả dưới đây **chỉ mô tả bản DVAA đã khảo sát**, không phải đặc tính chung của mọi DVAA hoặc mọi AI Agent.

1. `GET http://127.0.0.1:9000/api/attack-log` trả HTTP 200, có một event với các trường `timestamp`, `agentId`, `agentName`, `categories`, `successful`, `input`, `inputPreview`, `response`, `port`.
2. `GET /api/sandbox/cmd-log` trả HTTP 200; ban đầu là mảng rỗng. `GET /api/sandbox/files` trả danh sách 13 đối tượng file metadata.
3. `POST http://127.0.0.1:7004/v1/chat/completions` yêu cầu CodeBot thực hiện `echo SECAGENT_PROBE_9b2de0ef`: response chứa **text** `<tool_call>{...execute_command...}</tool_call>`; `message.tool_calls` không có; `finish_reason=stop`; `/api/sandbox/cmd-log` vẫn 0.
4. Codex audit source đang chạy cho biết CodeBot chat đi qua LLM rồi trả `message.content`; không có dispatch sang tool executor. `src/llm/provider.js` trả `message.content` và không duy trì native `tool_calls` trong đường này. Đây không phải vấn đề chỉ do API key DeepSeek.
5. `POST http://127.0.0.1:7010/mcp` với `tools/list` thành công, trả các tool `read_file`, `write_file`, `execute`, `fetch_url`. `initialize` trả JSON-RPC `-32601 Method not found` (dù HTTP 200) trên bản này.
6. Direct MCP `tools/call` `execute` với `echo SECAGENT_MCP_4bb1463f`: handler trả `success:true` và note `Command logged to sandbox`; `/api/sandbox/cmd-log` tăng **0 → 1**, entry khớp command, gồm `timestamp`, `command`, `agent`.
7. Codex audit kết luận MCP `execute` **mô phỏng**, không spawn shell OS; command log chứng minh handler tiếp nhận/ghi sự kiện, **không** chứng minh real shell execution. Direct `tools/call` do người kiểm thử chủ động gửi cũng **không chứng minh Agent LLM đã tự gọi tool**.
8. Các nguồn DVAA log hiện không có `request_id/testcase_id` đáng tin cậy để nối với hàng loạt testcase SecAgent, nên cần correlation design trước khi đưa vào verdict action-level.

Các quan sát trên dùng để **xác minh kiến trúc generic**, không được hardcode DVAA endpoints vào SecAgent core. Một external HTTP JSON Evidence Source có cấu hình mapping có thể đọc cùng dữ liệu khi người dùng khai báo.

## 9. Implementation roadmap — KẾ HOẠCH, CHƯA PHẢI TÍNH NĂNG ĐÃ XONG

1. **Regression stabilization**: baseline offline tests; không xóa fixtures/marker native; xử lý dependencies và source fixtures thật, không tạo data giả thay thế.
2. **Dataset contract + import readiness**: normalized testcase, source provenance, ASI review, scenario completeness; giữ tương thích batch ASI03/ASI05 đang có.
3. **Evaluation Strategy Resolver**: trusted rubric + target evaluation profile + readiness + evidence requirement; phân biệt response claim và action claim.
4. **Safe Target Discovery**: HTTP/MCP/A2A probes có giới hạn; dynamic Target Profile, user review, persistence; capability truthfulness.
5. **Universal Evidence Source interface**: response, structured tool events, JSON logs, OTEL; schema canonical, provenance và correlation. Thử nghiệm đầu tiên bằng DVAA như fixture ngoài, không phải architecture hardcode.
6. **ASI01 goal-aware semantics**: legitimate/attacker goals, trust boundary, baseline, goal deviation evidence, case-level Inconclusive khi thiếu context.
7. **Action-level extension (nếu phù hợp scope)**: instrumented target side, event IDs, bounded sandbox; báo cáo tách baseline và instrumented target variant.
8. **Research validation**: adjudicated labels, false positives/negatives, so sánh Promptfoo, coverage và evidence quality; báo cáo giới hạn khoa học.
9. **UX demo**: saved target/fleet profiles, quick switching, run batches tuần tự và report scope-aware.

Mỗi giai đoạn cần audit API/model hiện tại, thay đổi nhỏ, unit/integration tests offline, migration note và backward compatibility checks. Không merge đồng thời với mass package moves.

## 10. Những điểm chưa chốt / cần audit khi code

- Contract thực tế và vị trí đặt module của `TargetDiscovery`, `EvaluationPlanner`, `UniversalEvidenceCollector` trong nhánh mới nhất; tài liệu chỉ quy định trách nhiệm, chưa chốt tên class/path.
- Giao thức A2A hoặc MCP nào đã được SecAgent triển khai tới mức production-grade; cần kiểm tra code và tests, không suy từ đề xuất.
- Chuẩn JSON evidence, JSONPath dialect, trusted authentication, event retention, concurrency policy và backward compatibility với các report cũ.
- Cách tiếp nhận OpenTelemetry khi target thực sự phát spans; không mặc định mọi Agent đều có trace.
- Phương án công bố/correlation ID tại target-side instrumented variants và cách cô lập sandbox giữa các testcase.
- Phân biệt rõ nguồn benchmark, nhãn tham chiếu và kết quả Judge để không tạo vòng lặp tự đánh giá.

## 11. Tiêu chí nghiệm thu kiến trúc

- Import được nhiều testcase ngoài mà **không đòi marker per testcase**.
- Thêm Target mới bằng URL/profile/giao thức, không sửa core theo tên sản phẩm.
- Có thể cho người dùng cấu hình external evidence API theo schema mapping, kiểm soát quyền truy cập và provenance.
- Không có telemetry thì report tự giới hạn `response_only` / `inconclusive` thay vì xác nhận hành động.
- Phân biệt JSON-RPC `tools/call` trực tiếp và Agent autonomous tool call.
- Không coi `successful:true`, `EXPLOITED` hay Promptfoo grading là SecAgent FAIL tự động.
- PASS/FAIL gắn phạm vi đánh giá, technical ERROR tách biệt.
- Chuyển giữa nhiều bot trong một fleet đã lưu profile nhanh mà không cần tạo một container riêng cho mỗi bot.
- Native regression tests tiếp tục chạy, không phá kết quả imported batch cũ.

---

**Ghi chú bảo trì:** Cập nhật tài liệu này khi nhóm thay đổi *quyết định kiến trúc*. Ghi implementation status và code links sau mỗi PR; không trình bày roadmap như chức năng đã hoàn thành.

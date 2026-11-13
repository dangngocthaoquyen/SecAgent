# Phase 3A — Đặc tả workflow kiểm thử bảo mật qua web

Trạng thái: **đề xuất chờ phê duyệt**, không có API hay thành phần thực thi mới được tạo trong phase này. Căn cứ: [audit mã nguồn](web-testing-workflow-audit.md). Mục tiêu: một lát cắt vận hành với một target được cấp quyền, sau đó mở rộng; dùng pipeline hiện tại, không dựng Runner/evaluator thứ hai.

## 1. Ranh giới kiến trúc

Frontend chung có hai miền: cấu hình/điều phối mới và Reporting đã có. Đề xuất control service local riêng (`backend/src/workflow/`, chưa tồn tại), dùng Flask đã có dependency, gọi hàm Python trực tiếp. Không dùng subprocess shell gọi CLI theo chuỗi do người dùng nhập. Reporting service vẫn `127.0.0.1:8091`, GET-only, không khởi động target/Judge.

Control service đề xuất bind `127.0.0.1:8092`, đường dẫn `/api/testing/`; Vite future proxy riêng cho prefix này. Không thay rule GET-only của proxy `/api/reports/`. Chỉ một worker sequential ban đầu; không cần database, message broker hoặc một AI Agent mới. Shared orchestration code chỉ chuẩn bị TestInput và gọi Runner, không diễn giải lại evidence/verdict.

## 2. Target Configuration theo protocol

`TargetDraft` đề xuất gồm id/name, protocol discriminator, profile revision/hash, authorized-target policy reference, capabilities/evidence bindings có provenance, credential alias (không phải giá trị), connection config được kiểm tra theo protocol. Chỉ server tạo `TargetProfile`; browser không gửi arbitrary `interface.config` và không chọn adapter class/executable.

| Trường UI | OpenAI-compatible HTTP (vertical slice) | Generic HTTP (sau review) | MCP hiện có | A2A |
|---|---|---|---|---|
| Tên/id | Có, id server chuẩn hóa | Có | Có | Chưa khả dụng |
| Endpoint | URL chat đầy đủ, trong server allowlist | Endpoint đã duyệt | URL MCP HTTP đã duyệt | Không giả lập bằng HTTP chat |
| Method | POST cố định | Operator-approved subset | POST transport cố định, không input nghiệp vụ | Chưa hỗ trợ |
| Auth | Alias server, headers công khai allowlist | Như trái | Auth transport alias | Chưa hỗ trợ |
| Model/body | Model; template `messages[].content={{input}}` | Template JSON có giới hạn, không script/eval | Tool name/arguments schema đã review, không trường model/messages | Chưa hỗ trợ |
| Response parser | `choices.0.message.content` cố định | Dotted path an toàn từ preset | Parser nested JSON hiện tại; không arbitrary JSONPath/script | Chưa hỗ trợ |
| Timeout | Có, server áp min/max | Có | Có | Chưa hỗ trợ |
| Kiểm tra kết nối | Validate offline; active probe riêng | Chỉ probe endpoint đã duyệt | Không dùng `tools/call` làm ping; discovery chuẩn chưa có | Vô hiệu hóa |

MCP tool name/arguments thuộc execution binding của testcase, không phải một HTTP body editor chung. UI MCP ban đầu có thể đọc preset và ghi rõ “direct tools/call, hạn chế”; chỉ cho chạy case đã có reviewed argument mapping. Không hỗ trợ stdio command nhập từ browser. A2A hiển thị Unsupported, không tạo “connected” giả.

### Credentials

Vertical slice: operator cấu hình env ngoài browser và catalog alias allowlist, ví dụ alias `lab-agent-auth` trỏ tới một credential ref được duyệt. API chỉ trả `available/unavailable`, không tên env nội bộ hay raw value. Không cho client chọn `PATH`, biến môi trường bất kỳ, hoặc đổi môi trường process dùng chung.

Không lưu raw authentication vào YAML tái sử dụng, localStorage/sessionStorage/IndexedDB, query URL, telemetry, logs hoặc reports. Không echo Authorization khi preflight fail. Profile fingerprint loại bỏ secret, chỉ gắn credential alias/revision không bí mật. Raw secret entry không thuộc vertical slice; nếu tương lai cần, phải có thiết kế secret lifecycle riêng và server-only ephemeral storage, không đưa vào reusable config.

### Connection preflight hai cấp

1. **Kiểm tra cấu hình**: thuần local; validate schema, policy, template, parser, secret presence, timeout. Không gọi `build_runtime_target(discover=True)` và không gửi prompt.
2. **Kiểm tra kết nối có chủ ý**: nút riêng, preview chính xác method/endpoint đã làm sạch, max một request, no retry, timeout mặc định đề xuất 3 giây (operator cap 5 giây). Chỉ `/health` hoặc metadata endpoint read-only được operator duyệt; không giả định GET vô hại ở mọi target. Không forward auth mặc định sang health trừ policy yêu cầu. Nếu không có safe probe thì trả `unavailable`, vẫn có thể cấu hình plan với giới hạn rõ; không âm thầm gửi chat/tool call.

Kết quả preflight: configuration_valid, reachable/protocol_compatible khi có bằng chứng, auth_unknown, timeout, refused, unsupported. Không có security PASS/FAIL. Identity nhận từ health là target claim, không sửa id/capability/authorization policy.

## 3. Chọn ASI và testcase

UI checkbox ASI01/02/03/05, “Chọn tất cả”, “Bỏ chọn tất cả”. Cho phép đủ **15 tập con không rỗng**; tập rỗng vẫn hiển thị để sửa nhưng không được tạo plan chạy. Server kiểm tra cùng enum, loại duplicate, từ chối category ngoài scope. Không coi Select All là quyền chạy mọi case.

Catalog chỉ đọc các thư mục testcase/payload đã allowlist của repository, không nhận đường dẫn browser. Mỗi entry có id, category/ASI normalized + taxonomy gốc/basis, attack/control, module, payload refs, strategy, semantic enabled/skill, hashes testcase/payload/skill, yêu cầu và trạng thái review. Giữ 6 PI/SD ngoài lựa chọn bốn ASI. Không sửa YAML K để bổ sung metadata tùy tiện.

Do schema TestCase chưa có structured requirements, đề xuất sidecar catalog **do operator review**, keyed bởi testcase ID + content hash. Không tự NLP description để cấp quyền. Sidecar chứa supported transports, input binding, required tools, identity/sandbox prerequisites, observer contracts/scopes và evaluation readiness. Case chưa có sidecar không mặc nhiên supported. Mọi capability có `basis`: configured_claim, adapter_supported, operator_verified; self-report không đáp ứng điều kiện cần verified.

### CompatibilityResult

`status = supported | unsupported | requires_configuration | unknown`; kèm reason codes, missing prerequisites, evidence sources, evaluation mode compatibility và testcase/target revision.

- **supported**: mọi điều kiện bắt buộc cho cách chạy và evidence contract đã có nguồn được chấp nhận; không bảo đảm PASS hay đầy đủ mọi hành vi bên trong target.
- **unsupported**: sai protocol/schema/scope hoặc capability đã biết không có. Không có nút override để chạy.
- **requires_configuration**: có thể hỗ trợ nhưng thiếu identity baseline, fixture, tool binding, credential hoặc Judge contract được phép dùng.
- **unknown**: chưa review hoặc chỉ có claim không đủ xác định. Không tự nâng thành supported.

Nếu nhiều điều kiện lỗi: unsupported ưu tiên; nếu không có unsupported nhưng còn điều kiện không thể xác định thì unknown; còn lại missing config → requires_configuration. Trả toàn bộ lý do, không chỉ lý do ưu tiên. Preview chỉ đưa supported vào danh sách dispatch; phần còn lại là skipped/planned metadata, **không tạo EvaluationResult PASS/FAIL**.

| ASI | Điều kiện thực tế cần thể hiện |
|---|---|
| ASI01 | Chat GH-001/002 là boundary mô phỏng trong user message. GH-WEB cần fetched-content boundary, URL fixture hợp lệ, collector correlation/peer/window cho attack. GH-WEB-C01 semantic-only không có rule đủ kết luận khi Judge disabled; yêu cầu cấu hình semantic phù hợp hoặc không dispatch trong vertical slice. Target metadata không chứng minh fetch/action completeness. |
| ASI02 | Reviewed tool argument binding; agent-visible tool outcome và trace đúng phạm vi. Direct MCP test chỉ đo direct tool response, không tự chứng minh agent misuse. Không tự bật `tool-misuse` rubric khi YAML chưa có semantic contract. |
| ASI03 | Trusted synthetic A/B authorization baseline + actor/effective principal/resource/action/run evidence; guard hiện có phải giữ. Generic HTTP hoặc direct MCP không đáp ứng agent-origin audit. Hiện semantic skill chưa hỗ trợ. |
| ASI05 | Verified isolated sandbox, exact harmless canary allowlist, agent-origin process/effect evidence. Không nhận command/sandbox_verified từ client như sự thật. Semantic skill chưa hỗ trợ. |

## 4. Test Plan bất biến trước khi chạy

`TestPlan` version đề xuất `1.0`: plan_id, created_at/expires_at (server clock), target/profile/policy revision, selected ASIs, selected candidate IDs, ordered runnable IDs, excluded IDs+reasons, hash của assets/bindings, execution mode, target-request cap, Judge cap/provider/model, timeouts, observer refs, limitations, authorization scope và digest. Không chứa raw secret, raw private file path hoặc target-produced instructions dưới dạng trusted config.

Đầu vào bind chỉ qua typed allowlist theo testcase: URL fixture, synthetic identifiers, reviewed observer profile. Không nhận tự do security objective, expected answer, rubric path, tool trace hay `response_complete=true`. `expected_labels` hiện tại là vocabulary của schema Judge; human reference/expected verdict nằm ngoài Judge input. Cho xem prompt preview đã làm sạch khi được phép, gắn attack/control và boundary; không execute ở preview.

Mode: rule_only mặc định. Hybrid có opt-in riêng, hiển thị semantic eligibility từng case. Judge availability kiểm tra local config/skill hash/credential presence; không gọi model để “kiểm tra”. Không cho browser chỉ định Pi executable/global config. Live Judge cần tick xác nhận riêng, max calls hữu hạn, timeout tối đa theo policy; failure tiêu budget và không retry.

Run authorization là thao tác explicit “Bắt đầu kiểm thử được ủy quyền” trên preview đã chốt. Server xác nhận target nằm trong allowlist, plan chưa hết hạn và hashes không đổi; UI checkbox không thể mở rộng allowlist. Nếu đổi target/testcase/mode/budget/observer phải tạo preview mới. Không có runnable case → không tạo run. Ít nhất một case runnable mới có thể submit; skipped vẫn hiển thị.

## 5. Điều phối, budget, trạng thái và hủy

Đề xuất endpoint (chưa triển khai):

| API control | Mục đích và giới hạn |
|---|---|
| `GET /api/testing/targets` | Presets/aliases đã cấp quyền, không secret |
| `POST /api/testing/target-drafts/validate` | Kiểm tra local, không I/O target |
| `POST /api/testing/connection-checks` | Một safe probe đã duyệt, cần xác nhận explicit |
| `GET /api/testing/testcases?asi=ASI01&asi=ASI03` | Catalog có lọc nonempty subset; chỉ ids do server quản lý |
| `POST /api/testing/plans/preview` | Resolve/bind/render/compatibility offline, tạo plan có TTL |
| `POST /api/testing/runs` | plan_id + digest + authorization acknowledgement + idempotency key; trả 202 khi accepted |
| `GET /api/testing/runs/{job_id}` | Progress operational và report refs đã commit |
| `POST /api/testing/runs/{job_id}/cancel` | Yêu cầu dừng dispatch tiếp; không cam kết undo target action |

Không endpoint nào tự chạy khi GET. Idempotency key gắn plan digest: repeat cùng request trả cùng job; key với digest khác trả conflict. Validation/expired plan/asset changed trả structured error không lộ paths. Queue có hard bound; server một worker, không tạo thread không giới hạn cho mỗi request.

Tạo **job_id trước dispatch**, child attempt_id trước mỗi testcase; lưu mapping sang `Runner.last_report.run_id` và file-byte SHA256 sau persist. Native execution ID được Runner tạo sau evaluation, không giả định bằng job_id. Một Runner instance cho cả job sequential để budget Judge dùng chung; không gọi vòng lặp `run_smoke()` tạo Runner mới cho mỗi case rồi reset budget. Reuse logic chuẩn bị và writer bằng module dùng chung trong phase triển khai, giữ CLI backward compatible.

Admission proposal: concurrency=1, retry=0; target request max mặc định bằng số case runnable cho adapter một request/case, có cap operator; preflight budget tách riêng. Observer phụ/metadata request phải được kê khai, không là I/O ẩn. HTTP/Judge timeout hữu hạn và upper bound server; proposal HTTP 30 giây, Judge 90 giây. Job deadline kiểm tra trước mỗi dispatch, không bắt đầu case không đủ cửa sổ. Hạn mức chỉ đếm request do SecAgent gửi, **không chặn được các tool/action nội bộ của target**; lab network/sandbox/collector policy phải hạn chế các hành vi đó.

States job: queued → running → completed / completed_with_errors / cancel_requested → cancelled / interrupted. Child: pending → preparing → running → finished hoặc preparation_error; not_started_cancelled/skipped không phải security verdict. `completed` là worker xong, không có nghĩa target an toàn. Counter phải tách planned, started attempts, completed cases, technical errors, saved reports và unknown target invocation. Phần trăm chỉ là completed cases / runnable cases; không giả tiến độ token/tool/evaluator mà Runner chưa phát sự kiện.

Cancel ban đầu là **cooperative giữa testcase**. Request đang chạy và Pi subprocess hiện tại có thể tiếp tục tới timeout; UI hiện “Đã yêu cầu dừng; testcase hiện tại có thể còn hoạt động”. Không đánh dấu target đã dừng hoặc side effect đã rollback. Result đến sau cancel request vẫn persist và giữ verdict gốc, rồi dừng dispatch. Crash/restart: đánh dấu interrupted, không tự replay hoặc retry case chưa rõ đã gửi. Hard kill/real-time stage hooks cần thiết kế riêng nếu sau này có nhu cầu.

## 6. Persistence và tích hợp Reporting

Đề xuất store file local do server sở hữu: job manifest/control journal riêng, sanitized native child reports tạo file mới exclusive, không overwrite report lịch sử. Atomic update metadata job, bounded journal, permission chỉ operator; output path do server sinh dưới root riêng, cấm traversal/symlink/reparse escape. Không serialize raw HTTP response headers/secret. Publication chỉ sau native file hoàn tất và normalizer kiểm tra format; lưu lỗi report_sink riêng, không báo report-ready nếu chưa ghi thành công.

Reporting reuse `normalize_report_*`, `load_dataset`, `aggregate_reports`, `create_app`. Không cho control request supplied evidence trở thành newly verified artifact. GH-WEB verification tiếp tục explicit jobs với archive được quản lý. Historical verdict không thay bởi UI hoặc normalization; archived cross-check là assessment độc lập, không tự thực hiện khi run kết thúc.

API Reporting hiện snapshot startup. Lát cắt đầu: control service tạo selection manifest mới và trả “Report đã lưu; chưa có trong snapshot hiện tại”; operator restart Reporting bằng manifest do server xuất rồi UI reload snapshot. Không trả link sẽ 404 như thể report đã available. Phase 3E có thể thay snapshot atomically ở **lifecycle nội bộ** sau khi operator chấp nhận cơ chế publication; không thêm HTTP mutation vào `/api/reports`. Cần giữ snapshot hash, không join bằng testcase name; chi tiết trong lộ trình.

## 7. Trust boundary và an toàn

- **Endpoint authorization server-side**: allowlist exact scheme/IP/port/path + protocol và method; private/localhost không đồng nghĩa được phép. Block metadata/link-local, unspecified/multicast, public endpoints mặc định; không wildcard toàn mạng private. Policy đích và policy collector/outbound của lab tách riêng.
- Reuse runtime URL validation nhưng không coi client-supplied `authorized_origin` là cấp quyền. Server chọn origin từ policy. MVP IP literal, không arbitrary DNS; nếu mở DNS sau này cần resolve/pin và revalidate ở connection, redirect và proxy boundary để chống rebinding/TOCTOU.
- Không follow redirect; web adapter profile bắt `trust_env=False`, không tùy chỉnh proxy/Host/header routing qua request. Credential không forward sang host khác. Bound body/response bytes và thời gian; hiện generic HttpClient chưa có explicit response-size streaming cap, đây là gate cần bổ sung trước web execution.
- Loopback bind, exact Host/Origin validation, CSRF token cho mutation, JSON content-type, no wildcard CORS; cấm GET gây side effect. Loopback không tự là authorization; control token chỉ cấp cho local operator session, không persistent browser storage; reject cross-site/DNS-rebinding Host. Không lộ token trong URL/log. Public hosting không thuộc MVP.
- Cấm đường dẫn arbitrary vào testcase, skill, output, fixture; chỉ refs catalog. Không nhận shell command/executable/template code. Pi executable/model/provider từ server preset. Payload là data gửi target, không command chạy trên host.
- Không tin capability/identity/authorization/completeness tự khai từ browser hoặc target. Baseline/sandbox/collector records phải qua trusted operator registration và evidence source đã review; boolean guard không đủ attestation.
- Connection preflight không verdict; unsupported/skipped không PASS/FAIL; execution error tách security finding. Redaction trước persist và API response; UI render text, không HTML. Không log auth, full tool args, canaries hay URLs mang dữ liệu bí mật.

## 8. UX tiếng Việt, giữ reporting hiện tại

Navigation đề xuất: **Kiểm thử bảo mật (Security Testing)** → **Targets** → **Cấu hình kiểm thử (Test Configuration)** → **Lượt chạy (Active Runs)**; **Báo cáo đánh giá (Evaluation Reports)** giữ Overview/Results/Detail/Comparison hiện có. Có thể nhóm Targets/Test Configuration/Active Runs trong Security Testing thay vì tạo duplicate page.

| Màn hình | Nội dung và hành động | Loading/empty/error |
|---|---|---|
| Targets | Preset list, protocol, quyền, trạng thái preflight và thời điểm; chọn/sửa draft; validate local; probe explicit riêng | Không target được cấp quyền: hướng dẫn operator, không tự scan. Secret thiếu hiện alias unavailable, không echo. |
| Test Configuration | Checkbox 4 ASI, chọn/bỏ tất cả; testcase table ID/control/strategy/compatibility/reasons; mode/budget; “Xem kế hoạch” | Empty selection chặn preview; không có compatible case hiện lý do, không tự đổi target hoặc giảm yêu cầu evidence. |
| Review Plan | Target, exact scope, ordered case list/skips, prompt preview sanitized, observers, max requests/Judge budget, limitations; xác nhận rồi Start | Hash/TTL thay đổi bắt preview lại; không run khi refresh/back hoặc retry network không có idempotency. |
| Active Runs | State, child testcase hiện tại, completed/runnable, request/Judge budget, persistence status, cancel | Queue full báo rõ; progress unavailable thay spinner giả; interrupted không tự resume. Cancel pending nói rõ in-flight có thể tiếp tục. |
| Evaluation Reports | Reuse bốn view Phase 2D.2; mở report bằng server-issued identity trong snapshot đúng | Report saved nhưng chưa published: trạng thái rõ và hướng dẫn nạp snapshot; không tạo verdict mẫu. |

Luôn có “Target execution thành công ≠ Security PASS”; “Judge agreement ≠ accuracy”; “Artifact verified ≠ remote attestation”. Không có metric độ chính xác nếu thiếu human reference hợp lệ. Không trình bày deterministic DVAA callback như quyết định tool tự chủ của DeepSeek.

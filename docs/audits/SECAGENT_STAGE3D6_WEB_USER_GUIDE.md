# Hướng Dẫn Sử Dụng Web SecAgent: Onboarding & Kiểm Thử AI Agent Tổng Quát (Stage 3D.6)

Tài liệu này hướng dẫn người vận hành (operator) sử dụng giao diện Web SecAgent để tự khám phá (discover), rà soát (review), ghép cấu hình Hosted MCP Agent (`LLM + System Prompt + Reviewed Tool Catalog + MCP Server`), nhập bộ testcase JSON và chạy kiểm thử bảo mật **hoàn toàn từ trình duyệt**, không cần chỉnh sửa mã nguồn.

---

## 1. Khởi Động SecAgent Local

Từ thư mục gốc `D:\SecAgent-W5-Judge`, chạy lệnh:

```powershell
python start_secagent_local.py
```

Hoặc nếu muốn chỉ định thư mục lưu dữ liệu operator riêng (nằm ngoài repo) và không tự mở tab trình duyệt:

```powershell
python start_secagent_local.py --data-dir C:\SecAgentData --no-browser
```

- Lệnh trên mặc định bật **Unified Runtime** (`workflow.api --enable-unified-runtime` cổng `8092`, `reporting.api` cổng `8091`, và Vite React UI cổng `5173`).
- Truy cập giao diện Web tại: `http://127.0.0.1:5173/#targets`.
- Dữ liệu cấu hình, Discovery, Tool Catalog, Agent Binding và Dataset được lưu ngoài repo trong thư mục local app data (ví dụ `%LOCALAPPDATA%\SecAgent` hoặc `--data-dir`).

> **Lưu ý về Credential / Secret:** SecAgent không cho phép nhập hoặc hiển thị API key trực tiếp qua giao diện Web để tránh lộ secret ra trình duyệt hoặc báo cáo. Nếu LLM/MCP target cần credential, chỉ khai báo `credential_alias` trong seed catalog/environment ở phía server; các API và giao diện Web không bao giờ trả giá trị bí mật ra ngoài.

---

## 2. Bước 1 — Khám Phá (Discover), Lưu & Duyệt MCP Tool Server

1. Mở mục **Targets** (`/#targets`), chọn **Connect new target**.
2. Nhập **AI Agent URL** của MCP Tool Server local (chỉ loopback IP, ví dụ `http://127.0.0.1:17451/mcp` hoặc `http://127.0.0.1:7010/`).
3. Nhập **Agent Name** tùy chọn (tên hiển thị).
4. Tick ô xác nhận: *"I authorize up to three bounded metadata requests and one benign connection probe to this exact local service. MCP uses tools/list only; no tool execution or security payload."*
5. Bấm **Discover & Test Connection**:
   - SecAgent chỉ gửi duy nhất JSON-RPC `tools/list` (tuyệt đối không gửi `tools/call` hay payload tấn công).
   - Mục **Discovered MCP Tools & Schemas** sẽ hiển thị: tên tool, mô tả (`description`), mã **Discovery ID** (32 ký tự hex), digest SHA-256 của manifest, trạng thái tương thích schema (**Schema compatible** hoặc **Incompatible** kèm lý do như `unsupported_schema_keyword` cho `$ref`/`anyOf` hoặc `missing_input_schema`), và nút mở xem chi tiết JSON Schema.
6. Kiểm tra/sửa tên hoặc Target Identifier trong **Advanced target fields** nếu muốn -> tick xác nhận probe -> bấm **Save Target**.
7. Trong thẻ **Selected target**: tick *"I confirm authorization to test ..."* và bấm **Authorize target for test selection** (hoặc **Review / Approve Target**) để chuyển trạng thái target sang **Reviewed**.

---

## 3. Bước 2 — Thêm, Duyệt & Kiểm Tra Kết Nối LLM Host (OpenAI-Compatible)

1. Bấm **Connect new target**, nhập URL chat completion của LLM local (ví dụ `http://127.0.0.1:17490/v1/chat/completions`), tick xác nhận -> **Discover & Test Connection**.
   - Nếu metadata không tự trả tên model, nhập tên **Model identifier** trong form.
2. Bấm **Save Target**.
3. Thực hiện **Authorize target for test selection** (**Review**) cho target vừa lưu.
4. Tick xác nhận probe kết nối và bấm **Test Connection** ngay trên thẻ **Selected target** đã review để đảm bảo trạng thái chuyển thành **Connected** (bắt buộc cho chế độ chạy `live_local_http`).

---

## 4. Bước 3 — Rà Soát MCP Tool Catalog & Ghép Hosted MCP Agent Binding

Có thể thực hiện ngay tại mục **Targets** (khung **Hosted MCP Agent Onboarding**) hoặc tại tab **Hosted MCP Agent assessment** trong mục **Datasets**:

### 4.1. Tạo và duyệt MCP Tool Catalog
1. Trong khung **1 · MCP Tool Catalog Review**:
   - Chọn **MCP Tool Server Target** vừa tạo.
   - Nhập **Discovery ID** lấy từ Bước 1 và bấm **Load Discovered Tools**, sau đó tick chọn các tool có trạng thái `compatible` (hoặc mở **Manual Tool Schemas JSON** để nhập tay mảng JSON `[{name, description, input_schema}]` nếu server không hỗ trợ `tools/list`).
   - Đặt **Catalog Name** và bấm **Save Catalog Draft**.
2. Kiểm tra thông tin bản nháp (`review_status: draft`, SHA-256 của catalog). Tick xác nhận schema & tool exposure và bấm **Review / Approve Tool Catalog** -> trạng thái chuyển thành **reviewed**.

### 4.2. Ghép & duyệt Hosted MCP Agent Binding
1. Trong khung **2 · Hosted MCP Agent Binding & Policy**:
   - Chọn **LLM Host Target** và **LLM Model**.
   - Nhập **Agent System Prompt** và giới hạn số bước (**Max Model Calls** 1–4, **Max Tool Calls** 0–3).
   - *(Tùy chọn, tách biệt)* Mở **Operator Safety Scope (`environment_scope`)** để khai báo giới hạn an toàn vận hành (ví dụ: `Allowed write path prefixes` = `notes/`, `Write-scoped tools` = `append_note`, hoặc `Allowed fetch hosts` / `Fetch-scoped tools`).
   - *(Tùy chọn, tách biệt)* Mở **ASI05 Tool Argument Predicates (JSON)** để nhập `Authorized Predicates JSON` và `Prohibited Predicates JSON` theo chuẩn `ToolArgumentPredicate` (ví dụ `predicate_id`, `tool_name`, `argument_key`, `match_kind`, `values`).
2. Bấm **Save Agent Binding Draft** -> hệ thống sinh bản nháp binding (`draft`) kèm digest revision.
3. Tick xác nhận và bấm **Review / Approve Agent Binding** -> xác nhận trạng thái **Reviewed** và **Ready: Yes**.

> **Bảo vệ chống sai lệch (Fail-Closed Drift Protection):** Nếu bạn sửa endpoint/model của target MCP hoặc LLM, hoặc đổi Tool Catalog, các binding phụ thuộc sẽ tự động chuyển sang trạng thái **stale** và bị chặn trước khi thực thi cho đến khi được review lại.

---

## 5. Bước 4 — Nhập Testcase, Xem Trước (Preview) & Chạy Kiểm Thử

1. Chuyển sang mục **Datasets** (`/#datasets`).
2. Chọn chế độ **Hosted MCP Agent assessment** ở thanh tab đầu trang (chế độ **Chat prompt assessment** vẫn giữ nguyên để chạy `GENERIC-DIRECT-CHAT` độc lập).
3. Tại khung **Import JSON Testcases**, bấm **Choose JSON File** để tải file testcase JSON lên, kiểm tra thông tin preview và bấm **Confirm & Import to Library**.
4. Tại khung **Select reviewed agent binding**, chọn cặp binding `LLM + MCP` ở trạng thái `[Ready]`.
5. Tick chọn các testcase cần chạy trong bảng danh sách.
6. Kiểm tra khung **REVIEW AND RUN / Selected assessment** (số lượng case Ready/Blocked, ngân sách request) và bấm **Run Selected Tests** để xác nhận ủy quyền thực thi.

---

## 6. Bước 5 — Theo Dõi Tiến Trình & Đọc Kết Quả / Native Report

1. Trình duyệt tự chuyển sang trang tiến trình batch (`/#batch/<id>`), hiển thị tiêu đề **HOSTED MCP AGENT ASSESSMENT**, các bộ đếm `PASS / FAIL / INCONCLUSIVE / ERROR / BLOCKED / UNSUPPORTED` và thanh tiến độ.
2. Trong bảng **Testcase results**, SecAgent phân biệt rõ ngữ nghĩa thực thi ở cột Evidence & Security verdict:
   - **SecAgent blocked (pre-dispatch)**: Lời gọi tool bị chính `ExecutionGuard` của SecAgent chặn trước khi gửi ra MCP server (không ghi nhận là target an toàn hay `PASS` giả; phân loại `INCONCLUSIVE`).
   - **FAIL**: Đã dispatch tới MCP server và tham số vi phạm `prohibited_predicates` / `prohibited_actions` theo policy đã review.
   - **PASS**: Trace request hoàn tất, chỉ chứa các tool call hợp lệ đã review hoặc từ chối bằng text an toàn.
   - **INCONCLUSIVE** kèm trace chưa hoàn tất hoặc target từ chối action chưa được review.
3. Bấm **View Report** ở từng testcase (hoặc **Download ZIP** cho cả batch) để mở trang chi tiết **ExecutionDetail** (`/#run/<report_run_id>`), kiểm tra thẻ **Hosted MCP Agent trace & action distinction**:
   - `SecAgent blocked before MCP dispatch`
   - `Dispatched to MCP server`
   - `Target MCP server rejected`
   - `Host / OS side effect verified: No (SecAgent request observer + target-reported status only)` — đảm bảo không bao giờ ngụy tạo xác minh hiệu ứng mức OS khi không có independent host observer.

---

## 7. Thêm Target AI Agent / MCP Server Thứ 2 Không Cần Sửa Code

Để kiểm thử một MCP Server hoàn toàn khác (ví dụ đổi từ server A sang server B với tên tool và JSON Schema mới):
1. Lặp lại Bước 1 với URL của MCP Server thứ 2.
2. Tạo và duyệt một **Tool Catalog** mới cho target MCP mới.
3. Ghép thêm một **Agent Binding** mới với LLM Host và bộ `environment_scope` / ASI05 Predicates phù hợp.
4. Quay lại **Datasets -> Hosted MCP Agent assessment**, chọn binding mới từ dropdown và chạy ngay trên Web UI mà không cần thay đổi hay restart mã nguồn.

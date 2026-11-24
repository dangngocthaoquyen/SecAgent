# Hướng Dẫn Vận Hành Web SecAgent — Luồng Quét Bảo Mật Đơn Giản Hóa (`New Security Scan`)

Tài liệu này hướng dẫn người vận hành (operator) sử dụng màn hình **New Security Scan** (`/#scan`) trên giao diện Web SecAgent để kết nối AI Agent hoặc MCP Server ngoài, rà soát cấu hình an toàn, nhập testcase JSON, chạy quét bảo mật và đọc kết quả bằng chứng **mà không cần copy ID, SHA-256 hay sửa mã nguồn**.

Các màn hình **Targets** (`/#targets`) và **Datasets** (`/#datasets`) vẫn được giữ nguyên dưới vai trò **Advanced Settings** cho nhu cầu quản trị thủ công.

---

## 1. Khởi Động SecAgent Local

Từ thư mục gốc `D:\SecAgent-W5-Judge`, chạy lệnh:

```powershell
python start_secagent_local.py
```

Hoặc chỉ định thư mục dữ liệu riêng (nằm ngoài repo) và không tự mở trình duyệt:

```powershell
python start_secagent_local.py --data-dir C:\SecAgentData --no-browser
```

- Hệ thống mặc định chạy **Unified Runtime** (`workflow.api` cổng `8092`, `reporting.api` cổng `8091`, và Vite React UI cổng `5173`).
- Mở trình duyệt và truy cập **`http://127.0.0.1:5173/#scan`** (hoặc bấm **New Security Scan** ở thanh điều hướng bên trái).
- Nếu trình duyệt yêu cầu mở khóa phiên local (**Unlock Local Operator Session**), nhấn **Unlock session** (nếu đã nạp token local) hoặc nhập operator token từ phiên `start_secagent_local.py`. SecAgent không cho phép nhập/lưu API key của LLM trực tiếp qua trình duyệt.

---

## 2. Tổng Quan 5 Bước Của Wizard (`New Security Scan`)

Thanh tiến trình gồm 5 bước rõ ràng:

1. **1 · Target Setup** — Chọn loại target và kết nối endpoint loopback.
2. **2 · Configuration** — Rà soát agent, tool MCP đã khám phá và ghép LLM Provider (nếu dùng MCP).
3. **3 · Testcases & Policy** — Nhập file JSON testcase, chọn danh mục ASI và testcase cụ thể.
4. **4 · Review & Start** — Kiểm tra toàn bộ phạm vi chạy, ngân sách request tối đa (`target_request_budget`) và cấp quyền chạy.
5. **5 · Results & Evidence** — Theo dõi tiến trình real-time, đọc ranh giới bằng chứng và mở Native Report.

---

## 3. Lộ Trình A — Kiểm Thử AI Agent Có Sẵn (`Existing AI Agent (Chat API)`)

Dùng khi bạn đã có một AI Agent hoàn chỉnh dạng HTTP OpenAI-compatible (ví dụ `:7019` DVAA Agent Bridge hoặc chat endpoint local `:7490`) — **không cần cấu hình MCP Tool Catalog hay Agent Binding**.

1. **Bước 1 (`1 · Target Setup`):**
   - Chọn nút **`Existing AI Agent (Chat API)`**.
   - Chọn target đã lưu (nếu có) hoặc nhập **Target Name** (tùy chọn), **Target Endpoint URL** (ví dụ `http://127.0.0.1:7490/v1/chat/completions`), và **Model Identifier** (nếu endpoint không tự công bố metadata).
   - Tick ô xác nhận bounded metadata discovery và bấm **Connect & Continue**.
2. **Bước 2 (`2 · AI Agent Configuration`):**
   - Kiểm tra metadata & model vừa nhận diện (nếu endpoint không quảng bá model, nhập tên model và bấm **Save Target Profile**).
   - Tick ô *"I authorize SecAgent to test this exact endpoint..."* -> bấm **Authorize & Continue** (SecAgent sẽ duyệt và kiểm tra kết nối lành tính một lần).
3. **Bước 3 (`3 · Testcases & Security Policies`):**
   - Bấm **Import JSON Testcases** để tải file JSON từ máy tính (hoặc chọn dataset có sẵn).
   - Chọn danh mục ASI tương ứng; với **ASI03** hoặc **ASI05** (Direct Chat), hoàn tất thẻ đánh giá chính sách mục tiêu ngay tại chỗ nếu chưa được review.
   - Chọn các testcase cần chạy -> bấm **Review Scan Plan**.
4. **Bước 4 & 5 (`4 · Review & Start` -> `5 · Results & Evidence`):**
   - Đọc tóm tắt target, số testcase `ready`, chế độ chạy (`Live Local HTTP`) và ngân sách request tối đa.
   - Tick *"I authorize SecAgent to run this exact security scan..."* -> bấm **Start Scan**.
   - Xem kết quả từng testcase và mở **View Report** khi hoàn tất.

---

## 4. Lộ Trình B — Kiểm Thử `LLM Agent + MCP Server` (`Hosted MCP Agent`)

Dùng khi bạn muốn ghép một **MCP Tool Server** với một **LLM Host local** để kiểm thử hành vi quyết định gọi tool của AI Agent (`ASI05`) mà không phải tự copy `Discovery ID` hay SHA-256.

1. **Bước 1 (`1 · Target Setup`):**
   - Chọn nút **`LLM Agent + MCP Server`**.
   - Nhập **Target Name** (ví dụ `Ops Notes MCP`) và **MCP Server URL** (ví dụ `http://127.0.0.1:17451/mcp` hoặc DVAA ToolBot MCP).
   - Tick ô xác nhận bounded discovery -> bấm **Connect & Continue**. SecAgent chỉ gửi JSON-RPC `tools/list` (tuyệt đối không gọi `tools/call`).
2. **Bước 2 (`2 · MCP Capabilities & LLM Pairing`):**
   - **MCP Tool Server:** SecAgent tự động hiển thị danh sách tool khám phá từ `tools/list` cùng nhãn `Schema compatible` hoặc lý do không tương thích (ví dụ `Unsupported (unsupported_schema_keyword)`), đồng thời chuẩn bị sẵn bản nháp **Tool Catalog (unapproved draft)** ở hậu trường.
   - **Select Compatible LLM Provider:** Chọn một LLM Host loopback đã lưu từ danh sách thả xuống, hoặc bấm **+ Add New LLM Provider** để nhập URL, Model ID và lưu/kiểm tra kết nối ngay tại chỗ.
   - **Review Summary:** Kiểm tra tên MCP server, LLM provider, các tool `compatible` sẽ được phơi bày cho Agent, và cấu hình mặc định (System Prompt & giới hạn bước).
   - *(Tùy chọn)* Mở **Advanced Settings** để tùy chỉnh Agent System Prompt, giới hạn `Max Model Calls` / `Max Tool Calls`, phạm vi an toàn vận hành (**Allowed write prefixes**, **Write-scoped tools**, **Allowed fetch hosts**, **Fetch-scoped tools**), `Tool Argument Predicates JSON`, hoặc nhập **Manual Tool Schemas JSON** nếu MCP server không trả schema tương thích.
   - Tick ô *"I confirm this MCP Server, exposed tools, LLM Provider, and Agent Binding..."* -> bấm **Approve & Continue to Testcases**.
3. **Bước 3 (`3 · Testcases & Security Policies`):**
   - Nhập hoặc chọn dataset JSON (ví dụ chứa testcase `ASI05`), đảm bảo ASI Policy đang chọn là **`ASI05`** (runtime Hosted MCP Agent đánh giá quyết định thực thi tool theo chuẩn ASI05).
   - Chọn testcase -> bấm **Review Scan Plan**.
4. **Bước 4 & 5 (`4 · Review & Start` -> `5 · Results & Evidence`):**
   - Kiểm tra ngân sách request tối đa (mặc định tính theo `số testcase × case_request_budget`), tick xác nhận và bấm **Start Scan**.

---

## 5. Lộ Trình C — Kiểm Thử Trực Tiếp MCP Tool Server (`MCP Tool Server (Direct Testing)`)

Dùng khi bạn muốn kiểm thử trực tiếp các lệnh JSON-RPC `tools/call` định nghĩa sẵn lên một MCP Tool Service — **tách biệt hoàn toàn** với đánh giá quyết định tự động của AI Agent:

- Tại **Bước 1**, chọn **`MCP Tool Server (Direct Testing)`** -> bấm **Open Direct MCP Testing** để sử dụng giao diện gửi từng lệnh MCP có kiểm soát (`McpActionPanel`).

---

## 6. Cách Đọc Đúng Kết Quả & Bằng Chứng (`5 · Results & Evidence`)

Trong kết quả **HOSTED MCP AGENT** và **Native Report** (`Hosted MCP Agent trace & action distinction`), SecAgent phân biệt rõ 5 trạng thái để không đánh đồng cơ chế chặn của SecAgent với khả năng phòng thủ của target:

- **`LLM proposed tool call`**: LLM của target đã quyết định đề xuất gọi tool trong lượt suy luận.
- **`SecAgent blocked before dispatch (N) — NOT target defense`**: Chính sách an toàn của SecAgent đã chặn tool call vi phạm phạm vi trước khi gửi sang MCP server. **Đây KHÔNG phải bằng chứng target tự từ chối an toàn.**
- **`MCP dispatched`**: Tool call đã thực sự được chuyển tới MCP server.
- **`Target rejected` vs `Target reported success`**: Phản hồi trả về từ MCP server đối với lời gọi tool.
- **`Host OS effect: Unverified`**: SecAgent ghi nhận phản hồi ở tầng giao thức MCP/HTTP và chưa tự động chứng thực tác động vật lý trên hệ điều hành host nếu không có collector độc lập.
- **`Incomplete runtime trace`**: Agent dùng hết ngân sách lượt gọi model/tool trước khi hoàn tất chu trình trả lời cuối.

---

## 7. Khi Nào Cần Dùng `Advanced Settings`?

Ở góc trên bên phải màn hình **New Security Scan**, luôn có 2 liên kết:
- **Advanced Settings (Targets)** (`/#targets`): Mở màn hình quản lý target đầy đủ, inspect/copy thủ công `Discovery ID`, SHA-256 manifest, danh sách binding `stale`, Evidence Sources, hoặc chạy probe từng target riêng lẻ.
- **Advanced Datasets** (`/#datasets`): Mở thư viện dataset đầy đủ và các tab kiểm thử chuyên sâu (`ASI01`, `Restricted Web Lab`, `ToolBot Lab`).

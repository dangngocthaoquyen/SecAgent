Bạn đang hỗ trợ tôi phát triển đồ án:

**AI Agent Security Testing Framework**

## 1. Mục tiêu project

Tôi đang xây dựng một framework kiểm thử bảo mật dành cho AI Agent.

Framework KHÔNG được hard-code với một target duy nhất.

Target AI Agent chạy bên ngoài framework.

Framework giao tiếp với target thông qua abstraction:

TargetProfile
→ TargetInterface
→ TargetAdapter
→ Target bên ngoài

Target đầu tiên dùng để phát triển và kiểm thử framework là **DVAA**.

Ngôn ngữ backend: **Python**.

Tôi phát triển trên **VSCode**.

---

## 2. Architecture phải giữ

Pipeline phía tôi đang phụ trách:

Target configuration
→ TargetLoader
→ TargetProfile
→ TargetAdapter
→ HttpClient
→ Target
→ ExecutionResult
→ ResponseObserver
→ Observation

Không đưa code DVAA vào framework.

Không tạo class kiểu `DVAAClient`, `DVAAExecutor` hoặc hard-code URL/API DVAA vào core.

Thông tin riêng của DVAA phải nằm trong:

`configs/targets/dvaa.yaml`

Các thành phần generic như `HttpClient`, `HttpTargetAdapter` và `Executor` phải có khả năng tái sử dụng với target HTTP khác.

---

## 3. Core models

Framework sử dụng Pydantic.

Các model thuộc phạm vi hiện tại:

* TargetInterface
* TargetProfile
* TestInput
* ExecutionResult
* Observation

Ý nghĩa:

### TargetProfile

Mô tả target cần kiểm thử.

### TargetInterface

Mô tả framework phải giao tiếp với target bằng cách nào.

### TestInput

Input tổng quát gửi cho target.

### ExecutionResult

Kết quả raw đã được framework normalize sau khi thực thi target.

### Observation

Thông tin được Observer chuẩn hóa để Evaluator sử dụng.

---

## 4. Nguyên tắc dependency

Giữ dependency theo hướng:

`testing/executor.py`

được phép phụ thuộc vào abstraction của Target Adapter.

`targets/adapters/http_adapter.py`

được phép sử dụng:

`tools/http/client.py`

Nhưng:

`tools/http/client.py`

KHÔNG được biết:

* DVAA
* TestCase
* Prompt Injection
* Evaluator
* Attack Module

HttpClient chỉ thực hiện HTTP primitive.

Không tạo circular dependency.

---

## 5. Scope tuần hiện tại

Tôi chỉ xây dựng minimum pipeline:

DVAA target config
→ load target
→ validate target
→ HTTP adapter
→ HTTP client
→ execute TestInput
→ ExecutionResult
→ ResponseObserver
→ Observation

KHÔNG triển khai trong giai đoạn này:

* frontend
* database
* FastAPI
* SSE
* SecAgent
* LLM Judge
* Garak
* PyRIT
* MCP
* reporting
* attack orchestration phức tạp
* ExecutionPlan
* CLI adapter
* SDK adapter

Không tự ý thêm các thành phần trên.

---

## 6. Quy tắc khi code

Trước khi thay đổi code:

1. Hãy đọc cây thư mục hiện tại.
2. Đọc các model và module liên quan.
3. Nói ngắn gọn những file cần thay đổi.
4. Giữ architecture hiện có nếu không có lỗi thiết kế rõ ràng.
5. Không refactor những phần ngoài phạm vi nhiệm vụ hiện tại.

Khi implementation:

* sử dụng type hints;
* sử dụng Pydantic cho domain models;
* tránh mutable default trực tiếp;
* xử lý exception hợp lý;
* code đơn giản và dễ giải thích;
* ưu tiên dependency injection thay vì khởi tạo dependency cứng;
* không over-engineer;
* không thêm abstraction nếu hiện tại chưa cần.

---

## 7. Testing

Mỗi module quan trọng cần có test phù hợp.

Ưu tiên unit test cho:

* TargetLoader
* TargetValidator
* HttpClient khi mock được request
* HttpTargetAdapter
* Executor
* ResponseObserver

Không yêu cầu integration test DVAA trong mọi unit test.

Integration với DVAA thật sẽ được chạy riêng.

---

## 8. Cách làm việc với tôi

Không viết toàn bộ project trong một lần.

Chỉ triển khai đúng nhiệm vụ tôi yêu cầu trong từng prompt tiếp theo.

Sau khi sửa code, hãy báo cáo:

1. File đã tạo.
2. File đã sửa.
3. Logic đã triển khai.
4. Cách chạy.
5. Cách test.
6. Luồng dữ liệu qua các class.
7. Những giả định bạn đã phải đưa ra.
8. Những phần cố ý chưa triển khai.

Nếu phát hiện architecture hiện tại có vấn đề, hãy giải thích trước thay vì tự ý thiết kế lại toàn bộ project.

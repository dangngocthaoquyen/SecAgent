# SecAgent UI Prototype — hướng dẫn sử dụng

1. Giải nén `SecAgent-UI-Prototype.zip` vào `D:\SecAgent-W5-Judge\design-reference\` để có thư mục `secagent-ui-reference`.
2. Mở `index.html` bằng Chrome/Edge (giữ nguyên các file CSS/JS cùng thư mục). Không cần Docker, npm, API key hoặc chạy SecAgent. Nếu trình duyệt doanh nghiệp chặn file cục bộ, chạy trong thư mục prototype: `python -m http.server 8765 --bind 127.0.0.1`, rồi mở `http://127.0.0.1:8765/`. Dừng server bằng Ctrl+C.
3. Bấm Continue to Scan Preview, đánh dấu checkbox và Start historical demo replay để xem Progress. Bấm Simulate connection loss rồi Reconnect to Run. Complete replay mở Results. Có thể mở Results ngay từ New Scan bằng Open sample results.
4. Thử bộ lọc FAIL, Evidence level, tìm TC0020, phân trang, View details và 6 tab. Execution Results có hai tab Scan Runs / Native Reports. Export sample JSON chỉ tải fixture demo, không phải report gốc.
5. Gửi Agy file `AGY-IMPLEMENTATION-PROMPT.md` hoặc yêu cầu đọc trực tiếp từ thư mục này. `DESIGN-SPEC.md`, CSS/HTML và thư mục screenshots là tham chiếu thiết kế.

## Lưu ý
Prototype không kết nối SecAgent, DVAA hay DeepSeek. Không có API key, không sửa dữ liệu. Chế độ và engine ở Preview là ví dụ UI; replay luôn dùng dữ liệu lịch sử Live Hybrid cố định. Dữ liệu 30 testcase khớp số liệu verdict/evidence trong report đã gửi, nhưng nội dung prompt/response đã được giản lược, không phải raw evidence. Các màn hình sidebar ngoài phạm vi là placeholder chỉ để minh họa navigation. Production phải dùng dữ liệu thật và giữ nguyên logic.

Kiểm thử Chromium bằng nội dung HTML/CSS/JS nạp inline tại môi trường tạo file (chính sách trình duyệt tại đó chặn điều hướng file:// và loopback). Xem `PROTOTYPE-TESTS.txt` để biết phạm vi; không phải kết quả test SecAgent thật trên Windows.

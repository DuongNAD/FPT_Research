# 🛡️ ShieldAI: Quy Trình 7 Bước Đánh Chặn Mã Độc (Zero-Trust Pipeline)

Tài liệu này mô tả chi tiết quy trình 7 bước của hệ thống ShieldAI, từ lúc lập trình viên gõ lệnh tải thư viện cho đến khi hệ thống ra quyết định chặn hay cho phép, dựa trên sơ đồ quy trình:
`Packet (Tải 1 pip về) -> Môi trường ảo (Sandbox) -> Log -> LLM -> Log -> AI Agent -> Có chứa mã độc hay không`

---

## 1. 📦 Packet (Tải 1 pip package về)
* **Luồng xử lý:** Khi một lập trình viên gõ lệnh tải thư viện (vd: `pip install requests-fake`), request này không đi thẳng tới trang chủ PyPI mà bị "đánh chặn" bởi hệ thống trạm thông qua file `backend_api.py` (Phase 7: Zero-Trust PyPI Proxy).
* **Hoạt động thực tế:** Máy chủ Proxy tải phần thân của thư viện (gói `.whl` hoặc `.tar.gz`) về (thông qua luồng `ingestion.py`) nhưng **tạm giữ lại**, chưa cho phép cài đặt vào máy của nạn nhân.

## 2. 🧫 Môi trường ảo (Sandbox)
* **Luồng xử lý:** Gói tin nghi ngờ được ném vào một môi trường cách ly hoàn toàn (Sandbox).
* **Hoạt động thực tế:** Quá trình này được thực thi trong file `src/sandbox_runner.py`. Thay vì đọc source code chay (rất dễ bị mã độc đánh lừa bằng kỹ thuật làm rối mã - obfuscation), hệ thống **bắt gói tin đó phải thực thi** trong Sandbox để dụ mã độc "bộc lộ bản chất".

## 3. 📝 Log (Bắt hành vi mã độc dạng thô)
* **Luồng xử lý:** Trong lúc chạy, toàn bộ mọi hành động của package (như tạo file lén lút, mở kết nối mạng, đọc lén file password) đều bị Sandbox kiểm soát và bắt quả tang.
* **Hoạt động thực tế:** Hệ điều hành (Kernel) sẽ ghi lại những hành động này vào một file văn bản chi tiết gọi là **`syscalls.log`** (hay "dấu chân hệ điều hành").

## 4. 🧠 LLM (Mô hình ngôn ngữ lớn)
* **Luồng xử lý:** File `syscalls.log` chứa đầy những dòng code máy tính phức tạp và rất khó đọc hiểu. Do đó, hệ thống sẽ đưa thẳng file log này cho một **LLM** (như Gemini 2.5 hoặc Qwen2.5 Local) xử lý.
* **Hoạt động thực tế:** LLM đóng vai trò như một chuyên gia phân tích bảo mật. Với các Prompt được kỹ sư thiết kế trước, AI sẽ đọc toàn bộ log dài ngoằng và "dịch" các lệnh máy móc khô khan thành các thủ đoạn tấn công mà con người đọc là hiểu.

## 5. 📑 Log (Bản tóm tắt/Bản án từ LLM)
* **Luồng xử lý:** Đây là kết quả đầu ra sau khi LLM phân tích xong luồng dữ liệu thô.
* **Hoạt động thực tế:** LLM trả về một văn bản log mới đã được "phiên dịch" (trong code là kết quả trích xuất `prosecutor_case` hoặc các đối tượng `JSON`). Bản "log thế hệ mới" này phác họa rõ ràng các đặc trưng, ví dụ: *"Phần mềm này đang gọi hàm OpenAt để chôm file ở máy chủ"*.

## 6. 🧑‍⚖️ AI Agent (Hội đồng Tranh biện)
* **Luồng xử lý:** Nhằm tránh việc AI "nhìn lầm" và vô tình chặn nhầm các thư viện sạch (False Positive), dự án thiết lập hẳn một luồng **Multi-Agent Debate** nằm ở file `src/multi_agent_extraction.py`.
* **Hoạt động thực tế:** Các log đã được LLM trích xuất phía trên được đưa vào một tòa án ảo với 3 Agent:
  * **Công tố viên (Prosecutor):** Dựa vào log, cố gắng buộc tội thư viện này là mã độc.
  * **Luật sư (Defender):** Cố gắng tìm lý lẽ bào chữa (Ví dụ: *"Nó truy cập mạng là vì nó gửi dữ liệu Diagnostic hợp pháp thôi!"*).
  * **Thẩm Phán (Judge):** Xem xét bằng chứng của cả 2 bên để đưa ra kết luận.

## 7. ⚖️ Phán quyết (Có chứa mã độc hay không)
* **Luồng xử lý:** Kết luận cuối cùng (Verdict), tương ứng với chữ "Mal" (Malware) hoặc "ben" (Benign/An toàn) trên sơ đồ.
* **Hoạt động thực tế:** 
  * **Nếu Thẩm phán kết luận An Toàn (`ben`):** Proxy cho phép lệnh `pip install` ở bước 1 chạy bình thường. Lập trình viên tải được thư viện về an toàn.
  * **Nếu Thẩm phán kết luận Mã Độc (`Mal`):** Phán quyết sẽ được "Map" sang đồ thị mạng phân tích tiêu chuẩn MITRE ATT&CK (Đưa vào Neo4j / Knowledge Graph). Lập tức, API Proxy tại `backend_api.py` sẽ hất văng kết nối, trả về lỗi **HTTP 403 Forbidden** màu đỏ chót cho lập trình viên, kèm lưu nhãn ngăn chặn. Thư viện độc hại ngay lập tức bị đưa vào kho lưu trữ (Blacklist) để auto-chặn trong thời gian cực ngắn `0.01s` cho những máy khác trong hệ thống.

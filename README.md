# 🛡️ ShieldAI: Zero-Trust PyPI Proxy & Mạng Đồ Thị Tri Thức Mã Độc

**Dự án Nghiên cứu & Phát triển (FPT Research)**
Đây là bộ mã nguồn hệ thống phòng chống tấn công Chuỗi cung ứng (Supply Chain Attack) dành riêng cho hệ sinh thái Python (PyPI). Hệ thống ứng dụng kiến trúc kết hợp giữa **Dynamic Sandbox, LLM (Mô hình ngôn ngữ lớn), Knowledge Graph (Neo4j)** và cổng chặn mã độc theo thời gian thực (Zero-Trust Proxy).

---

## 📖 Tóm tắt Dự án (Abstract)
Tấn công chuỗi cung ứng thông qua các kỹ thuật như **Typosquatting** (đặt tên thư viện giống hàng thật, vd: `requets` thay vì `requests`) đang ngày càng tinh vi. Các cơ chế phân tích tĩnh (Static Analysis) truyền thống bằng Rule-based (như Semgrep/GuardDog) thường xuyên bị qua mặt bởi các kỹ thuật giấu mã (Obfuscation), Payload mã hóa, hoặc Eval động.

**ShieldAI** giải quyết triệt để vấn đề này bằng cách ép thư viện nghi ngờ chạy trong một môi trường **Sandbox** cách ly. Sau đó, nó thu thập toàn bộ "Dấu chân hệ điều hành" (**Syscalls**) và đưa cho Trí tuệ Nhân tạo (**AI Agents**) đọc và gắn nhãn theo khung tiêu chuẩn **MITRE ATT&CK**. Dữ liệu được đẩy vào Đồ thị tri thức (Knowledge Graph) để tính toán điểm rủi ro. Cuối cùng, hệ thống hoạt động như một máy chủ Proxy trung gian, lập tức chặn đứng quá trình `pip install` của nhà phát triển nếu phát hiện mã độc!

---

## 🏗️ Phân Tách Kiến Trúc (The 10-Phase Pipeline)
Dự án được triển khai toàn diện qua 10 giai đoạn (Phases) đột phá:

### Giai đoạn 1 & 2: Ingestion & Dynamic Sandbox
*   **Mô tả:** Thay vì đọc mã nguồn để tìm mã độc con, hệ thống khởi tạo một môi trường Sandbox "vô trùng" và chạy thử gói `whl/tar`. Toàn bộ hành vi hệ thống (tạo file, trộm `/etc/passwd`, mở Port) bị Kernel bắt lại thành tệp **`syscalls.log`**.

### Giai đoạn 3: AI Threat Extraction & Mapping
*   **Mô tả:** Một LLM Agent (Google Gemini 2.5 hoặc Qwen2.5 Local) được cấp quyền đọc tệp `syscalls.log`. Với Prompt Engineering chuyên sâu, AI tự động "dịch" các lệnh máy bộ thành những thủ đoạn tấn công con người hiểu được, map thẳng sang chuẩn **MITRE ATT&CK** (Vd: T1083 - File Discovery).

### Giai đoạn 4: Đồ thị Tri thức (Knowledge Graph - Neo4j)
*   **Mô tả:** Các dữ liệu từ AI được đẩy vào hệ cơ sở dữ liệu đồ thị **Neo4j**. Các mối quan hệ `Package -> Chỉ Dấu -> Hành Vi -> Kỹ Thuật MITRE` được kết nối chằng chịt, tạo ra "Lưới nhện mã độc". Ma trận này phục vụ truy vấn Điểm Rủi Ro (Risk Score) bằng ngôn ngữ Cypher.

### Giai đoạn 5 & 6: Đánh giá & Web Dashboard (Giao diện)
*   **Mô tả:** Cung cấp đánh giá tỷ lệ False Positive. Đặc biệt, hệ thống đi kèm một trang Web Dashboard nội bộ trực quan (phong cách Glassmorphism tương lai) hiển thị các cảnh báo khẩn cấp và Đồ thị mạng dạng Nút kết nối (Node-Edge Network) bằng **Vis.js**.

### Giai đoạn 7: Cổng trạm Zero-Trust PyPI Proxy
*   **Mô tả:** Tích hợp trực tiếp chức năng chặn mã độc theo thời gian thực (Real-time). Server FastAPI mở cổng `/simple/` giả lập trang chủ PyPI. Khi user gõ `pip install`, Proxy bắt được request $\rightarrow$ Ném tự động vào Sandbox $\rightarrow$ AI đọc $\rightarrow$ Neo4j báo điểm $\rightarrow$ Trả về **HTTP 403 Forbidden** khóa ngay giao dịch nếu có mã độc.

### Giai đoạn 8: Bộ lưu trữ Tội phạm (Known Malware Blacklist)
*   **Mô tả:** Khắc phục nhược điểm "Chậm" của AI. Bất kỳ package nào từng bị kết án mã độc sẽ bị "phong ấn" ngay vào danh sách đen `known_malware.json`. Những người tải sau sẽ bị chặn văng ra tức khắc trong `0.01s` mà không cần chạy lại AI, giúp tăng tốc hiệu năng khổng lồ cho Doanh nghiệp.

### Giai đoạn 9: Hội đồng AI Tranh biện (Multi-Agent Debate)
*   **Mô tả:** Giảm thiểu False Positive xuống 0%. Dùng 3 AI Agent cùng lúc: **Công Tố Viên** (Cố buộc tội) - **Luật Sư** (Cố bảo vệ) - **Thẩm Phán** (Nghe cãi nhau rồi mới kết án). Giúp hệ thống không bao giờ chặn nhầm các thư viện sạch chỉ vì chúng thu thập một chút Telemetry hợp pháp.

### Giai đoạn 10: Dự đoán GNN (Graph Neural Network) - Bản Nâng Cấp Tương Lai
*   **Mô tả:** Biến các Đồ thị trong Neo4j thành ma trận Tensor. Dùng thuật toán Pytorch **GraphSAGE** huấn luyện cho AI nhận biết "Hình thù" của đồ thị mã độc. Nhờ đó, thay vì phải gọi AI LLM đọc text tốn 20 giây, GNN có thể lướt qua đồ thị mới và đưa ra dự đoán mã độc chỉ trong vỏn vẹn **mili-giây (ms)** mà không cần kết nối tới Internet!

---

## 🚀 Hướng Dẫn Kích Hoạt (Getting Started)

### 1. Cài đặt Môi Trường
```powershell
# Chạy trong thư mục gốc
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 2. Khởi động Web Dashboard & Trạm chặn mã độc (Proxy)
Tất cả đã được thiết kế All-in-One tại file `backend_api.py`.
```powershell
python src\backend_api.py
```
> Trạm gác đã mở tại: **http://localhost:8000**. Giao diện 3D Cyber Security đã sẵn sàng.

### 3. Thử nghiệm Đóng vai Nạn nhân lập trình viên
Trong một cửa sổ Terminal mới, giả vờ gõ sai tên một thư viện `requests` thành mã độc `requests-fake-1.0.0`:
```powershell
pip install requests-fake-1.0.0 --index-url http://localhost:8000/simple/
```
**Kết quả mong đợi:** Lệnh `pip install` sẽ bị đá văng với dòng chữ đỏ cực gắt báo lỗi `403 Forbidden`. Trên Web Dashboard, module Blacklist sẽ ngay lập tức hiện lên tên kẻ thù!

---
*Dự án được xây dựng cho mục đích Nghiên Cứu và Bảo vệ Chuỗi cung ứng Phần mềm.*

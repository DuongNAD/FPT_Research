# 🛡️ ShieldAI: Zero-Trust PyPI Proxy & Multi-Agent Malware Defender

**Dự án Nghiên cứu & Phát triển (FPT Research)**
ShieldAI là hệ thống phòng thủ Chuỗi cung ứng (Supply Chain Attack) tinh vi dành riêng cho hệ sinh thái Python (PyPI). Thay vì dựa dẫm vào cơ chế quét tĩnh (Static Analysis) mỏng manh, ShieldAI cưỡng chế thi hành mã độc trong **Dynamic Docker Sandbox**, hút cạn Syscalls/Artifacts, và giao cho một **Hội Đồng AI Đa Tác Nhân 100% Local (Qwen 2.5, Gemma 2, Llama 3)** tranh biện kịch liệt để đưa ra phán quyết tàn nhẫn và chính xác nhất.

---

## 📖 Tính Năng Nổi Bật Đặc Quyền (Core Masterpieces)

### 1. Kiến trúc Hội Đồng Tranh Biện AI (Multi-Agent Debate Court)
Hệ thống thoát bỏ việc giao sinh mạng hệ thống cho 1 con AI duy nhất. Nó được tổ chức thành một Tòa án:
*   **👨‍⚖️ Công Tố Viên (Prosecutor - Qwen 2.5 7B GGUF):** Được tiêm System Prompt tàn nhẫn ("Thà giết lầm hơn bỏ sót"). Quét sạch cặn kẽ file `.log` bắt bẻ từng IP `15.15.15.15` hay từng lệnh `chmod +x /tmp`.
*   **👨‍💼 Luật Sư Bào Chữa (Defender - Gemma 2 9B GGUF):** Kẻ bới lông tìm vết. Tìm kiếm False Positives và bào chữa (Ví dụ: `openat` vào thư mục tạm có thể là tiến trình cài đặt Pip bình thường).
*   **👩‍⚖️ Thẩm Phán Tối Cao (Judge - Llama 3 8B GGUF):** Cầm trịch bộ Luật Tố Tụng (Procedural Rules). Thẩm phán nhận bản cãi vã của 2 bên và gọi API qua Context `8192` kết hợp `response_format={"type": "json_object"}` để khóa chặt kết quả xuất ra dạng Structured JSON chuẩn quốc tế Pydantic.

### 2. Kiến trúc Đường ống Đơn Tuyến (Pipeline Sequential Mode)
Thay vì nạp đồng thời 3 mô hình cỡ lớn lên VRAM gây tràn bộ nhớ (Out Of Memory) hoặc chờ mòn mỏi kiến trúc Batch-Processing cũ, hệ thống đã được tái cấu trúc thành **"Kiến trúc Đơn Tuyến"**:
1. Sandbox đoạt log hệ thống của Malware X.
2. Nạp `Qwen` $\rightarrow$ Prosecutor quét Malware X $\rightarrow$ Bắn kết quả & Giải phóng VRAM.
3. Nạp `Gemma` $\rightarrow$ Defender phản biện Malware X $\rightarrow$ Bắn kết quả & Giải phóng VRAM.
4. Nạp `Llama-3` $\rightarrow$ Thẩm phán kết án Malware X $\rightarrow$ Hiển thị trực tiếp lên Terminal & Giải phóng VRAM.
5. Tiến tới Malware Y lặp lại chu kỳ.

> Hệ thống cam kết không bao giờ vượt ngưỡng **~7-8GB VRAM** tại mọi thời điểm. Module `local_ai_manager` sử dụng cờ `/T` (Tree Process) của Windows Taskkill kết hợp Regex Cleanup + Context Penality để tàn sát 100% "Zombie backend c++ process" lẫn "Nhiễm độc Context" (Text Degeneration), cam đoan chống rò rỉ bộ nhớ ảo giác hoàn hảo.

### 3. Sandbox Giam Giữ Tàn Nhẫn (Hardware-Level Docker Detonation)
*   **File Hệ Thống Lõi:** Dùng `strace -f` kết hợp Cờ Drop Caps. Cách ly qua `.dockerenv`, đoạt bằng chứng tạo File Rác thông qua `docker diff`.  Loại bỏ mọi file rác của base pip build (`pip-req-build`).
*   **Packet Sniffer:** Sidecar kết nối qua giao thức Out-of-Band để lôi `tcpdump` bắt file `.pcap` bằng cờ unbuffered `-U`.

### 4. Hệ Sinh Thái Test Bạo Lực Hỗn Cạp (The 17-Payload Mixed Benchmark Suite)
Đã lập trình bộ Toolkit tự động vắt kiệt sức máy quét AI qua **17 biến thể**, xen lẫn các tệp cài đặt hợp lệ (Noise/Benign Tools) để lừa phỉnh False Positives:
*   `crypto-miner-stealth`, `fileless-mem-exec-2.0`, `bashrc-stealth-persistence`: Các payload hòa trộn lẫn lộn kỹ năng đào tẩu Sandbox, tiêm bộ nhớ cực tinh vi.
*   `doomsday`, `obfuscated-phantom`, `ransom-encrypt`: Bộ mã hóa tàng hình (Zlib + Base64), phá hoại môi trường cục bộ.
*   Các biến thể Typosquatting đánh cắp Telemetry ngầm qua `socket` và DNS ngụy tạo.
*   Bổ sung cơ chế **"Noise Injection"**: Cài cắm xen kẽ các lệnh ping lành tính, file temp bình thường để test xem Tòa Án AI có bị "Overfitting" hay không.

---

## 🚀 Hướng Dẫn Kích Hoạt Phần Mềm (Installation & Usage)

### 1. Yêu cầu Hệ thống (Prerequisites)
- **Windows / Linux** đã cài đặt Python 3.9+
- **Docker Desktop (WSL2)** để chạy Lồng kính Sandbox.
- Sở hữu một card màn hình có tối thiểu **8GB VRAM** (Vd: RTX 3060, RTX 5060 Ti).

### 2. Tải Khối Cơ Sở LLM (Download AI Models)
```powershell
.\venv\Scripts\Activate.ps1
# Lệnh dưới đây sẽ tải lần lượt Qwen-2.5, Gemma-2, và Llama-3 dạng nén GGUF
.\venv\Scripts\python.exe AI_Models\download_models.py
```

### 3. Tạo Tự Động Kho Mã Độc (Munitions Depot)
Sinh ra chuỗi lượng tử 7 gói mã độc tinh vi nhất để test sức chịu đựng của AI:
```powershell
.\venv\Scripts\python.exe 02_Experiments\Step2_Sandbox_Execution\create_multi_scenario_malware.py
```
*(Các gói sẽ nằm gọn tại `data/quarantine/task_doomsday/`)*

### 4. Kích Hoạt Auto-Benchmark (Pipeline Sequential)
Đây là công cụ vắt kiệt công suất AI và Sandbox. Script sẽ chạy ngầm quản lý VRAM tuần tự, đếm nhịp độ trễ trung bình, tự bóp Context/Penality để dọn dẹp ảo giác, không cần anh nhúng tay quản lý Terminal!
```powershell
.\venv\Scripts\python.exe 02_Experiments\Step2_Sandbox_Execution\benchmark_runner.py
```

> **Đầu ra (Output):** Tất cả báo cáo cãi án sẽ được AI chấm điểm và render dưới dạng Markdown tuyệt đẹp tại `05_Reporting/benchmark_results.md`.

---
*Dự án được xây dựng cho hệ sinh thái Zero-Trust, nhắm tới môi trường High-Resilience Cybersecurity 100% Offline, gạt bỏ giới hạn API Cloud Limits.*

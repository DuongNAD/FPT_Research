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

### 2. Time-Sharing VRAM (Phase-Batching Mode)
Thay vì nạp đồng thời 3 mô hình cỡ lớn lên VRAM gây tràn bộ nhớ (Out Of Memory) cho các dòng card <16GB, hệ thống triển khai kiến trúc **"Luân phiên theo Pha"**:
1. **Pha 0:** Chạy Sandbox cho toàn bộ mã độc, lưu File Syscall.
2. **Pha 1:** Nạp `Qwen` $\rightarrow$ Prosecutor quét toàn bộ $\rightarrow$ Giải phóng VRAM.
3. **Pha 2:** Nạp `Gemma` $\rightarrow$ Defender phản biện toàn bộ $\rightarrow$ Giải phóng VRAM.
4. **Pha 3:** Nạp `Llama-3` $\rightarrow$ Thẩm phán kết án toàn bộ $\rightarrow$ Giải phóng VRAM.

> Hệ thống cam kết không bao giờ vượt ngưỡng **~7GB VRAM** tại mọi thời điểm, tăng tốc đột phá I/O SSD lên gấp 10 lần so với nạp từng gói. Module `local_ai_manager` sử dụng cờ `/T` (Tree Process) của Windows Taskkill để tàn sát 100% "Zombie backend c++ process", cam đoan chống rò rỉ bộ nhớ.

### 3. Sandbox Giam Giữ Tàn Nhẫn (Hardware-Level Docker Detonation)
*   **File Hệ Thống Lõi:** Dùng `strace -f` kết hợp Cờ Drop Caps. Cách ly qua `.dockerenv`, đoạt bằng chứng tạo File Rác thông qua `docker diff`.  Loại bỏ mọi file rác của base pip build (`pip-req-build`).
*   **Packet Sniffer:** Sidecar kết nối qua giao thức Out-of-Band để lôi `tcpdump` bắt file `.pcap` bằng cờ unbuffered `-U`.

### 4. Hệ Sinh Thái Test Bạo Lực (The 7-Payload Benchmark Suite)
Đã lập trình bộ Toolkit tự động vắt kiệt sức máy quét AI qua 7 biến thể:
1. `telemetry-tracker` (Mã thường, trộm dữ liệu máy)
2. `crypto-miner-fake` (Mỏ đào Coin)
3. `doomsday` (Phá hoại Fork-Bomb, xóa tệp)
4. `requests-typo` (Dropper độc hại kéo file C&C)
5. `ransom-encrypt` (Ransomware cục bộ)
6. **[Advanced]** `fileless-mem-exec` (Bom Fileless lây bằng C-Types `mprotect`).
7. **[Advanced]** `obfuscated-phantom` (Mã hóa đa tầng ngâm Zlib Base64).

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

### 4. Kích Hoạt Auto-Benchmark (Phase-Batching Chiến Lược)
Đây là công cụ vắt kiệt công suất AI và Sandbox. Script sẽ chạy ngầm quản lý VRAM, tự bật các port 8000/8001/8002 cho từng Phase mà không cần anh phải nhúng tay quản lý Terminal!
```powershell
.\venv\Scripts\python.exe 02_Experiments\Step2_Sandbox_Execution\benchmark_runner.py
```

> **Đầu ra (Output):** Tất cả báo cáo cãi án sẽ được AI chấm điểm và render dưới dạng Markdown tuyệt đẹp tại `05_Reporting/benchmark_results.md`.

---
*Dự án được xây dựng cho hệ sinh thái Zero-Trust, nhắm tới môi trường High-Resilience Cybersecurity 100% Offline, gạt bỏ giới hạn API Cloud Limits.*

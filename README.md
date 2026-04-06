# 🛡️ ShieldAI: Zero-Trust PyPI Proxy & Multi-Agent Malware Defender

**Dự án Nghiên cứu & Phát triển (FPT Research)**
ShieldAI là hệ thống phòng thủ Chuỗi cung ứng (Supply Chain Attack) tinh vi dành riêng cho hệ sinh thái Python (PyPI). Thay vì dựa dẫm vào cơ chế quét tĩnh (Static Analysis) mỏng manh, ShieldAI cưỡng chế thi hành mã độc trong **Dynamic Docker Sandbox**, hút cạn Syscalls/Artifacts, và giao cho một **Hội Đồng AI Đa Tác Nhân (Qwen 2.5, Gemma 2, Gemini 2.5)** tranh biện kịch liệt để đưa ra phán quyết tàn nhẫn và chính xác nhất.

---

## 📖 Tính Năng Nổi Bật Đặc Quyền (Core Masterpieces)

### 1. Kiến trúc Hội Đồng Tranh Biện AI (Multi-Agent Debate Court)
Hệ thống thoát bỏ việc giao sinh mạng hệ thống cho 1 con AI duy nhất. Nó được tổ chức thành một Tòa án:
*   **👨‍⚖️ Công Tố Viên (Prosecutor - Qwen 2.5 7B GGUF):** Được tiêm System Prompt tàn nhẫn ("Thà giết lầm hơn bỏ sót"). Quét sạch cặn kẽ file `.log` bắt bẻ từng IP `15.15.15.15` hay từng lệnh `chmod +x /tmp`.
*   **👨‍💼 Luật Sư Bào Chữa (Defender - Gemma 2 9B GGUF):** Kẻ bới lông tìm vết. Tìm kiếm False Positives và bào chữa (Ví dụ: `openat` vào thư mục tạm có thể là tiến trình cài đặt Pip bình thường). Gemma được trói buộc bởi Native Structured JSON Outputs chống rác Markdown.
*   **👩‍⚖️ Thẩm Phán Tối Cao (Judge - Gemini 2.5 Flash):** Cầm trịch bộ Luật Tố Tụng (Procedural Rules). Thẩm phán sẽ chặt đầu Công tố viên nếu luận điểm chung chung thiếu Bằng Chứng Thép (Hard Evidence), bảo mật tuyệt đối tính toàn vẹn và độ rủi ro = 0% False Positive.

### 2. Sandbox Giam Giữ Tàn Nhẫn (Hardware-Level Docker Detonation)
*   **File Hệ Thống Lõi:** Dùng `strace -f` kết hợp Cờ Drop Caps. Cách ly qua `.dockerenv`, đoạt bằng chứng tạo File Rác (Dropper Pipeline) qua hệ Scanner `docker diff`.  Loại bỏ mọi file rác của base pip build (`pip-req-build`).
*   **Packet Sniffer:** Sidecar kết nối qua giao thức Out-of-Band để dùng `tcpdump` bắt file `.pcap`, cô lập lưu lượng. 

### 3. Native GGUF Inference Engine (llama-cpp-python)
*   Chạy 100% Nội bộ, VRAM-Optimized trên Card đồ họa GTX/RTX thông qua hệ Gateway Máy Chủ (API Servers mô phỏng OpenAI). 
*   **Qwen2.5-7B** và **Gemma-2-9B** túc trực song song dạng Hot-Standby. Tách ly chi phí phụ thuộc vào OpenAI.

### 4. Hệ Sinh Thái Test Bạo Lực (The 7-Payload Benchmark Suite)
Đã lập trình bộ Toolkit tự động vắt kiệt sức máy quét AI (`create_multi_scenario_malware.py`) qua 7 biến thể:
1. `telemetry-tracker` (Mã thường, trộm dữ liệu máy)
2. `crypto-miner-fake` (Mỏ đào Coin)
3. `doomsday` (Phá hoại Fork-Bomb, xóa tệp)
4. `requests-typo` (Dropper độc hại kéo file C&C)
5. `ransom-encrypt` (Ransomware cục bộ)
6. **[Advanced]** `fileless-mem-exec` (Bom Fileless lây bằng C-Types `mprotect`, bay lượn trên RAM).
7. **[Advanced]** `obfuscated-phantom` (Mã hóa đa tầng ngâm Zlib Base64 chống tĩnh).

### 5. Resuscitation Engine (Xoay Vòng và Hồi Sinh API)
Tích hợp `Tenacity` Exponential Backoff chống crash kết hợp hệ thuật toán xoay vòng `Round-Robin Itertools` (API Keys), ShieldAI đánh bật lỗi HTTP 429 Quota Exhausted của Gemini một cách uyển chuyển.

---

## 🚀 Hướng Dẫn Kích Hoạt (Installation & Usage)

### 1. Yêu cầu Hệ thống (Prerequisites)
- **Windows / Linux** đã cài đặt Python 3.9+
- **Docker Desktop (WSL2)** để chạy Sandbox.
- Có thư mục `AI_Models/` chứa 2 file GGUF của `Qwen2.5-7B` và `Gemma-2-9b-it`.

### 2. Thiết lập Mạng Lưới Nội Bộ (VRAM Tối Ưu)
```powershell
.\venv\Scripts\Activate.ps1
# 1. Khởi động các bộ não LLM Local (Cần RTX/GTX có VRAM >= 12GB)
# Port 8000: Qwen | Port 8001: Gemma
.\start_ai_servers.ps1
```

### 3. Tạo Tự Động Kho Mã Độc (Munitions Depot)
Sinh ra chuỗi lượng tử 7 gói mã độc tinh vi nhất để test sức bền máy tính:
```powershell
.\venv\Scripts\python.exe 02_Experiments\Step2_Sandbox_Execution\create_multi_scenario_malware.py
```
*(Các gói sẽ nằm gọn tại `data/quarantine/task_doomsday/`)*

### 4. Kích Hoạt Auto-Benchmark (Khảo Thí Căng Thẳng)
Đây là công cụ vắt kiệt công suất AI và Sandbox. Script sẽ thả từng gói mã độc vào lồng kính Docker, hút Syscall, mở tòa án Tòa - Bào - Thẩm phán, và chốt vạch biên bản tự động.
```powershell
.\venv\Scripts\python.exe 02_Experiments\Step2_Sandbox_Execution\benchmark_runner.py
```

> **Đầu ra (Output):** Tất cả báo cáo cãi án và tốc độ trễ sẽ được tự động tóm tắt xuất ra thẻ Markdown tuyệt đẹp tại `05_Reporting/benchmark_results.md`.

---
*Dự án được xây dựng cho hệ sinh thái Zero-Trust, nhắm tới môi trường High-Resilience Cybersecurity.*

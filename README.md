# 🛡️ FPT Research: Multi-Agent Cyber Security Sandbox

## 📖 Giới thiệu
Đây là một nền tảng **Zero-Trust Multi-Agent Malware Sandbox** được phát triển nhằm mục đích phân tích, phát hiện và kết án các hành vi mã độc (Evasion Malware, Supply Chain Attack, Fileless Injection) được nhúng ngầm bên trong các gói thư viện Python (PyPI) cũng như các tệp nhị phân Windows. Thay vì sử dụng bộ máy giám sát cồng kềnh, dự án kết hợp sức mạnh của **Sysdig System Tracing** để thu thập log ở mức Kernel và kiến trúc **Multi-Agent AI (Qwen & Gemma)** để phán xử mức độ nguy hiểm của hành vi.

## 🚀 Tính năng nổi bật (Key Features)
1. **Dynamic Sandbox Execution:** Môi trường cách ly hoàn toàn bằng Docker để bung nén và thực thi các gói mã độc nhạy cảm (`setup.py`). Có tích hợp lõi mô phỏng hệ điều hành **WINE (Wine Is Not an Emulator)** để hút trọn gói các Mã độc nền tảng Windows (`.exe`).
2. **Kernel-Level Tracing (Sysdig):** Thu thập toàn bộ lời gọi hệ thống (Syscalls) từ File I/O, Network Sockets, đến Memory Management (`mmap`, `mprotect`, `ptrace`). Bất kể là mã độc Python hay C++, hệ thống Syscall dưới đáy Kernel luôn tóm gọi.
3. **Smart Rule-Engine (Phễu lọc trung gian JSON-Decoupled):** Chấm điểm rủi ro qua một file cài đặt độc lập `heuristic_rules.json`. Linh hoạt rút gọn log thô hàng chục GB xuống còn vài KB các hành vi trọng yếu.
4. **Three-Tier Multi-Agent System (AI Judiciary):** 
   - 🕵️‍♂️ **Công Tố Viên (Prosecutor - Qwen 7B)**: Soi xét log và lập luận mức độ nguy hiểm.
   - 🛡️ **Luật Sư Bào Chữa (Defender - Gemma 9B)**: Phản biện dựa trên bối cảnh hoạt động dự phòng các trường hợp cài cắm pip bình thường.
   - ⚖️ **Thẩm Phán Tối Cao (Judge - Gemma 26B)**: Lắng nghe tranh biện và ra Phán quyết cuối cùng (Final Verdict) ở định dạng JSON chuẩn xác 100%.

## 🛠️ Cấu trúc hệ thống
- `/02_Experiments/Step2_Sandbox_Execution/`: Các công cụ Benchmark và hệ thống nạp kịch bản động `scenario_templates`.
- `/04_Production/src/`: Mã nguồn cốt lõi (Multi-Agent logic, Rule-engine Filter).
- `/04_Production/config/`: Lưu trữ các luật phân tích hành vi độc lập `heuristic_rules.json`.
- `/05_Reporting/`: Thư mục lưu trữ báo cáo Benchmark sau mỗi đợt chạy.
- `/AI_Models/`: Nơi chứa các tệp `.gguf` của Offline LLMs (100% Local Inference).

## ⚡ Hướng dẫn chạy thử hệ thống (Benchmark Extreme)
Chạy script benchmark với bộ các kịch bản để kiểm tra độ nhạy của hệ thống:
```bash
.\venv\Scripts\python.exe 02_Experiments\Step2_Sandbox_Execution\benchmark_runner_ultimate.py
```

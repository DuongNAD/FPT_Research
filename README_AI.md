# 🧠 FPT Research: AI Multi-Agent Architecture

Tài liệu này mô tả chi tiết về cách các mô hình Large Language Models (LLMs) được phối hợp để tạo nên "Bộ Não" cho hệ thống Malware Sandbox.

## 1. Architectural Design: The Digital Courtroom (Phiên Tòa Kỹ Thuật Số)
Thay vì sử dụng một LLM duy nhất (rất dễ bị ảo giác - Hallucination hoặc bị đánh lừa bởi Prompt Injection của mã độc), dự án thiết kế kiến trúc **Adversarial Debating Agents** (Các Agent tranh biện đối kháng).

### A. Prosecutor Agent (Qwen 2.5 7B)
- **Cổng giao tiếp**: Port `8000`.
- **Vai trò**: Đóng vai Công Tố Viên tàn nhẫn.
- **System Prompt**: Luôn nghi ngờ mọi hành vi. Nhiệm vụ là map các hành vi nhỏ nhặt nhất vào khung hình phạt MITRE ATT&CK. Đặc biệt nhạy cảm với các keyword `[TAG_HIGH_RISK_EVENT]`. Không được phép tha bổng nếu thấy bất kỳ hành vi leo thang đặc quyền nào.

### B. Defender Agent (Gemma 2 9B)
- **Cổng giao tiếp**: Port `8001`.
- **Vai trò**: Đóng vai Luật sư biện hộ.
- **System Prompt**: Tìm kiếm các tình tiết giảm nhẹ. Nếu gói cài đặt tải file dung lượng lớn, biện hộ rằng đó là Machine Learning Cache. Nếu gói cài đặt tạo file .pyc, biện hộ rằng đó là tiến trình mặc định của pip. Áp dụng chuẩn `[TAG_SAFE_OPERATION]` để cởi trói.

### C. Judge Agent (Gemma 4 26B)
- **Cổng giao tiếp**: Port `8002`.
- **Vai trò**: Thẩm Phán Rút Trích (JSON Finalizer).
- **System Prompt**: Lắng nghe lập luận từ Prosecutor và Defender. Dựa vào quy tắc chấm điểm rủi ro. Chỉ in ra kết quả JSON thuần túy gồm: `analytical_reasoning`, `mitre_tactics`, `malicious_probability`, và `final_verdict` (🟢 BENIGN / 🔴 MALICIOUS).

## 2. Zero-Hallucination Constraints & Decoupled Heuristics
Để khắc phục hoàn toàn tình trạng AI bịa ra cổng mạng/thiết bị không có thật, một cơ chế tiền xử lý Log tĩnh đã được thêm vào thông qua file cài đặt độc lập `config/heuristic_rules.json`.
Hệ thống sẽ ép buộc AI tuân theo luật chơi:
- Mọi hoạt động bình thường trên log sẽ bị ẩn khỏi tầm mắt của AI hoặc gán mác hành vi an toàn theo `safe_extensions`.
- Trí tuệ của AI chỉ bắt đầu phát huy xoay quanh các hành vi vượt ngưỡng `alert_tag_score_minimum` do hệ thống Heuristic chấm điểm. Điều này đảm bảo Tính Minh Bạch (Explainability) tối đa.

## 3. Deployment Constraints
- Hệ thống chạy Offline 100% bằng kiến trúc VRAM phi tập trung (Batch-processing qua Local LLMs). Tốc độ giải quyết một gói khoảng 60s trên Local GPU. Đảm bảo dữ liệu nhạy cảm không bị tuồn lên Internet (Bypass hoàn toàn giới hạn bảo mật của Google/OpenAI APIs).

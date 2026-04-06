# 🧠 Kiến Trúc Trí Tuệ Nhân Tạo: Hội Đồng Tranh Biện (Multi-Agent Debate)

Tài liệu này đi sâu vào **Cấu trúc bộ não AI** của dự án ShieldAI. Thay vì đặt trọn niềm tin vào một bộ não phân tích tĩnh theo kiểu cổ điển, hệ thống ứng dụng mô hình **Tòa Án Thực Tế (Debate-based Multi-Agent)**. Ba mô hình LLM chuyên biệt sẽ đóng những vai trò khắc nghiệt và độc lập nhằm bào mòn tỷ lệ cảnh báo giả (False Positive) xuống mức 0 nhưng vẫn nghiền nát được các loại mã độc vô hình.

---

## 🏛️ 1. Cấu Hành Tòa Án (The Agents)

### 👨‍⚖️ Tác Nhân 1: CÔNG TỐ VIÊN (The Prosecutor)
*   **Mô hình sử dụng:** `Qwen2.5-7B-Instruct.gguf` (Local Inference qua llama-cpp).
*   **Sứ mệnh:** Săn lùng chỉ dấu thỏa hiệp (IoCs) từ tập tin log Hệ điều hành do Sandbox phun ra cực kỳ chi tiết.
*   **System Prompt & Cơ chế tâm lý:**
    *   Được cài vào tư duy "Bạo chúa". Bất kỳ hoạt động mở cổng TCP ra Internet, thả file vào `/tmp`, tạo luồng `clone`, hay leo thang cấp phát bộ nhớ (`mprotect`) đều lập tức quy thành tội ác.
    *   **Bộ lọc tàng hình (Noise Reduction):** Bị ràng buộc chặt chẽ bởi lệnh `IGNORE PIP ARTIFACTS`, bắt buộc bỏ qua mọi lệnh gọi liên quan chuẩn mực cài đặt thư viện (`pip-req-build`, `.egg-info`). Thiết kế này tập trung tia laser sức mạnh vào hành vi lõi thay vì phân tán sức đọc.
    *   **Output Ràng buộc:** Xuất cấu trúc JSON chứa đầy đủ Khớp nối MITRE ATT&CK và Tọa độ file tuyệt đối (*Hard Evidence*).

### 👨‍💼 Tác Nhân 2: LUẬT SƯ BÀO CHỮA (The Defender)
*   **Mô hình sử dụng:** `Gemma-2-9b-it.gguf` (Local Inference qua llama-cpp).
*   **Sứ mệnh:** Bảo vệ sự "vô tội" của thư viện. Chống lại rủi ro cấm nhầm (False Positives) do phe Công Tố ngáo đá vì quá nhạy cảm.
*   **System Prompt & Cơ chế tâm lý:**
    *   Gemma đóng vai trò Blue Team Analyst lão làng. Nếu Công tố quy kết tội `openat` vào `/tmp/`, Gemma sẽ gỡ tội bằng cách trích lục tính thông thường của tiến trình setup Python.
    *   **Điều kiện Ngả Mũ (Concede Clause):** Tuy nhiên, Gemma bị trói bởi câu răn đe sắt đá: *"Nếu chứng cứ cứng như File .sh hay IP mạng hiển hiện, tuyệt đối không được bốc phét ảo giác biện lý. Bắt buộc chấp nhận thua cuộc (is_safe: false)"*.

### 👩‍⚖️ Tác Nhân 3: THẨM PHÁN TỐI CAO (The Judge)
*   **Mô hình sử dụng:** `Gemini 2.5 Flash` (Cloud API).
*   **Sứ mệnh:** Duyệt hồ sơ hai bên gửi lên và Cầm Tịch Phán Quyết.
*   **System Prompt & Cơ chế tâm lý:**
    *   Nắm giữ **3 Đạo Luật Tố Tụng (Procedural Rules)** trong System Prompt. Ví dụ: Luật Số 2 ghi rõ: *"Mọi hành vi được cấu thành Tội Phạm (Malicious) yêu cầu có Hard Evidence (Tên File/IP cụ thể). Nếu Công Tố Viên chỉ rên rỉ chung chung, Bác bỏ ngay!"*
    *   Tránh thiên vị nhờ cơ cấu Input phi phân cực. Trả về mức `Confidence Score` và giải thích lý do xử lý.

---

## ⚙️ 2. Quy Trình Vận Hành & Lọc Dữ Liệu (The Pipeline)

1.  **Lấy Cung Sandbox:** Lệnh `docker diff` trích xuất File Artifacts rơi rụng, kết hợp `strace` sinh mã máy. Script nhồi Artifact lên đỉnh/đáy tệp log tạo mồi câu cho Qwen.
2.  **Khởi tố (Prosecute):** Agent Qwen quét log. 
    *   *Trường hợp A:* Vụ án trắng (Log sạch bong), kết án `BENIGN`, chặn đứng việc tốn Token gọi Gemma.
    *   *Trường hợp B:* Có rủi ro. Qwen ném mảng Json MITRE sang Gemma.
3.  **Tranh Tụng (Debate):** Agent Gemma nhận bộ log và bản án của Qwen $\rightarrow$ Soạn Argument chống luận điểm bới lông $\rightarrow$ Nhả dữ liệu.
4.  **Tuyên Án (Verdict):** Gemini nhận Combo (Log + Báo cáo Công Tố + Argument Bào chữa) $\rightarrow$ Ép cấu trúc Pydantic (`ThreatExtractionResponse`) $\rightarrow$ Khởi động cơ chế phán xử và tiêm vào Neo4j DB.

---

## 🛠️ 3. Phép Tối Ưu Hóa Kỹ Thuật (Engineering Masterpieces)
*   **Native Structured Outputs:** Thay vì "van xin" LLM trả về Text Markdown rồi dùng Regular Expression lẩy dỡ, hệ thống tích hợp API mới nhất ép Schema thẳng vào Model Engine thông qua `response_schema`. Tuyệt mĩ 100% không bao giờ trật JSON Parsing!
*   **Cơ Chế Bọc Lót (JSON Stripping Fallback):** Đối với các Local LLM cứng đầu vẫn đẻ dư block ````json`, logic cắt xén thông minh được áp dụng chẹn đầu/cuối chuỗi để đảm bảo App không bao giờ văng Exception Python.
*   **Exponential Backoff Resuscitation (Xoay vòng trạm máu API):** Việc nháy API Google liên tục bị phạt HTTP 429 Limit. Nhờ thư viện `Tenacity` và Trạm xoay vòng Array Key liên hồi, Hệ thống vẫn vắt chân nhàn nhã chạy tự động 10.000 Packages.

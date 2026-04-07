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
*   **Mô hình sử dụng:** `Llama-3-8B-Instruct.gguf` (Local Inference qua llama-cpp).
*   **Sứ mệnh:** Nắm giữ quyền sinh sát tối cao. Tiếp thu cả hai bản báo cáo (Qwen & Gemma) và đối chiếu với cặn bã log.
*   **System Prompt & Cơ chế tâm lý (Zero-Trust Boundaries):**
    *   Nắm giữ **5 Đạo Luật Tố Tụng (Procedural Rules)**. Mạnh mẽ nhất là **Luật Số 4: Thiết Quân Luật Zero-Tolerance**. Bất kỳ hành vi nào chạm vào `/.bashrc`, `/.profile`, mã hóa hoặc xả file trong `/tmp`, và sử dụng `mprotect` đều lập tức bị tống lên máy chém (`MALICIOUS`).
    *   Thẩm phán sẵn sàng **BÁC BỎ (OVERRULE)** mọi lời ngụy biện của Luật Sư Gemma kể cả khi Gemma bảo là "Quy trình thiết lập Python là bình thường".
    *   **Luật Số 5:** Ép buộc tư duy và ngôn ngữ 100% bằng Tiếng Việt.

---

## ⚙️ 2. Quy Trình Vận Hành (The Pipeline Sequential Mode)

1.  **Lấy Cung Sandbox:** Lệnh `docker diff` trích xuất File Artifacts rơi rụng, kết hợp `strace` sinh mã máy. Script nhồi Artifact lên đỉnh/đáy tệp log tạo mồi câu cho Qwen.
2.  **Khởi tố (Boot Qwen):** `local_ai_manager` nạp Qwen (Port 8000). Qwen phân tích cực đoan và xuất bằng chứng MITRE JSON $\rightarrow$ Hủy Qwen (`taskkill /F`).
3.  **Tranh Tụng (Boot Gemma):** Nạp Gemma (Port 8001). Gemma nhận bộ log gốc và bản án vắt kiệt của Qwen để tìm False Positives và bào chữa $\rightarrow$ Hủy Gemma.
4.  **Tuyên Án (Boot Llama-3):** Nạp Llama-3 (Port 8002). Llama-3 đánh giá toàn cục dựa trên Thiết Quân Luật Zero Trust $\rightarrow$ Chốt án dạng JSON với điểm tự tin `Confidence Score` $\rightarrow$ Hủy Llama-3. Mọi dữ liệu in thẳng ra màn hình Console.

---

## 🛠️ 3. Phép Tối Ưu Hóa Kỹ Thuật (Engineering Masterpieces)
*   **Native Structured Outputs:** Thay vì "van xin" LLM trả về Text Markdown rồi dùng Regular Expression lẩy dỡ, hệ thống tích hợp API mới nhất ép Schema thẳng vào Model Engine thông qua `response_schema`. Tuyệt mĩ 100% không bao giờ trật JSON Parsing!
*   **Cơ Chế Bọc Lót (JSON Stripping Fallback):** Đối với các Local LLM cứng đầu vẫn đẻ dư block ````json`, logic cắt xén thông minh được áp dụng chẹn đầu/cuối chuỗi để đảm bảo App không bao giờ văng Exception Python.
*   **Context Cleansing & 100% Local Inference:** Nhổ tận gốc sự phụ thuộc vào Cloud API (chấm dứt nỗi đau HTTP 429 Limit từ Google). Toàn bộ kiến trúc sử dụng mã nguồn mở chạy hoàn toàn trên VRAM cá nhân. Thu thập rác (Garbage Collection) bằng cách `taskkill` triệt để tàn dư bộ nhớ sau mỗi phiên tranh biện và dập tắt luôn vấn nạn Ảo giác Văn bản (Text Degeneration) thông qua việc thao túng `frequency_penalty` & `presence_penalty`!

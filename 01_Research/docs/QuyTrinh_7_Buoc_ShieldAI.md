1. 📦 Đánh chặn Gói tin (Zero-Trust PyPI Proxy & Ingestion)
Ở bước đầu tiên, hệ thống hoạt động như một bức tường thành vững chắc.

Luồng xử lý: Lập trình viên gọi lệnh pip install <package_name>. Yêu cầu này bị chặn lại tại máy chủ Proxy (backend_api.py).

Hành động kỹ thuật: Hệ thống tải mã nguồn (các file .whl hoặc .tar.gz) về một khu vực lưu trữ tạm thời (quarantine zone). Không có bất kỳ file nào được phép vượt qua mốc này để xâm nhập vào máy nạn nhân khi chưa có lệnh xác nhận an toàn tuyệt đối.

2. 🧫 Kích hoạt Môi trường Cách ly (Dynamic Sandbox Execution)
Thay vì chỉ đọc mã nguồn tĩnh (static analysis), hệ thống buộc mã độc phải hành động.

Luồng xử lý: Gói tin được đưa vào src/sandbox_runner.py để cài đặt và chạy thử nghiệm.

Hành động kỹ thuật: Hệ điều hành (Kernel) sẽ giám sát chặt chẽ mọi động tĩnh. Mọi thao tác như tạo file ẩn, mở cổng kết nối mạng (network sockets), hay truy cập đường dẫn nhạy cảm đều được ghi lại một cách trung thực vào file syscalls.log.

3. 🧹 Lọc Nhiễu & Trích xuất Đặc trưng (Entropy Filtering & Semantic Enrichment)
Đây là module trung gian mới được thêm vào để xử lý file log thô trước khi đưa cho AI, giúp giải quyết bài toán quá tải thông tin.

Luồng xử lý: Tích hợp src/entropy_filter.py và src/causal_trace_extractor.py.

Hành động kỹ thuật: * Noise Reduction: Loại bỏ các lệnh gọi hệ thống lặp lại vô nghĩa (low-entropy syscalls) để tối ưu độ dài văn bản.

Causal Trace: Giữ lại các chuỗi hành vi có nguy cơ bảo mật cao (security-relevant), ví dụ như openat vào /etc/passwd hay connect ra IP bên ngoài.

Enrichment: Bổ sung các đặc trưng thời gian (temporal features) như mật độ gọi hàm để phát hiện các hành vi thực thi ồ ạt (burst patterns).

4. 🚦 Phân luồng Tốc độ cao (Two-Tier Syscall Triage)
Bước đột phá giúp anh Dương tiết kiệm đến 80% chi phí API bằng cách phân loại sớm (Early Filtering).

Luồng xử lý: File log đã nén đi qua module src/syscall_triage.py.

Hành động kỹ thuật: Hệ thống áp dụng các bộ lọc theo quy tắc (heuristic filters):

Fast-Path Benign: Nếu một package có số lượng syscalls quá ít (< 20), không có kết nối mạng, và không gọi các tiến trình chìm (execve), hệ thống dán nhãn An Toàn (Benign) ngay lập tức và bỏ qua hoàn toàn việc gọi LLM.

High-Risk Path: Các package có hành vi phức tạp hoặc vi phạm quy tắc sẽ được chuyển tiếp sang Bước 5 để AI phân tích sâu.

5. 🧠 Phân tích Ngữ cảnh bằng LLM (Context-Aware LLM Analysis)
Tận dụng sức mạnh suy luận của LLM (như Gemini 2.5) với các kỹ thuật Prompting tiên tiến.

Luồng xử lý: Dữ liệu tinh gọn được đưa vào src/llm_analyzer.py.

Hành động kỹ thuật:

MITRE ATT&CK Mapping: Hệ thống tự động ánh xạ các syscall thành các chiến thuật tấn công (Ví dụ: connect + sendto -> T1071 Application Layer Protocol) để cung cấp ngữ cảnh rõ ràng cho LLM.

Forced Alternative Explanation: Để tránh việc AI "ảo giác" (hallucinations), Prompt ép buộc LLM phải đưa ra một lời giải thích hợp pháp (benign explanation) cho hành vi đó trước khi kết tội. Điều này giúp giảm thiểu tối đa tỷ lệ False Positives.

6. 🧑‍⚖️ Tòa án Ảo Định tuyến Động (Quality-Aware Multi-Agent Debate)
Hệ thống tranh biện Đa Đặc vụ (Multi-Agent) nay được tối ưu hóa bằng cơ chế định tuyến thông minh.

Luồng xử lý: Đánh giá chất lượng suy luận của LLM từ Bước 5 thông qua src/reasoning_quality_scorer.py.

Hành động kỹ thuật: * Skip Debate: Nếu LLM ở Bước 5 đưa ra kết luận với độ tự tin cực cao (high confidence) và lý luận sắc bén, hệ thống bỏ qua phiên tòa để chốt kết quả ngay.

Full Debate: Nếu lý luận mập mờ hoặc mang tính rủi ro cao, hệ thống kích hoạt src/multi_agent_extraction.py với 3 Agents (Công tố viên buộc tội, Luật sư bào chữa, Thẩm phán quyết định) để đào sâu tìm ra bản chất thật của gói tin.

7. ⚖️ Phán quyết Cuối cùng & Cập nhật Đồ thị Tri thức (Verdict & Knowledge Graph)
Bước cuối cùng để thực thi hình phạt và lưu trữ tri thức bảo mật.

Luồng xử lý: Đưa ra phán quyết cuối cùng (Mal hoặc ben).

Hành động kỹ thuật:

Nếu An Toàn (ben): Proxy mở khóa, lệnh pip install hoạt động bình thường.

Nếu Mã Độc (Mal): Trả về lỗi HTTP 403 Forbidden. Đặc biệt, áp dụng neo4j_graph_representation, hệ thống chuyển hóa chuỗi hành vi tấn công (Kill Chain) thành Đồ thị Tri thức (Nodes & Edges) lưu vào Neo4j. Từ đó, bất kỳ biến thể mã độc (malware variants) nào có cấu trúc đồ thị tương tự trong tương lai sẽ bị hệ thống chặn đứng trong vòng 0.01s.
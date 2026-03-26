import os
import json
import logging
from google import genai

logger = logging.getLogger(__name__)

# Cấu hình API key Gemini từ biến môi trường
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "dummy_key")

def analyze_syscalls(log_path: str) -> dict:
    """
    Bước 4 & 5: Đọc file syscalls.log, sử dụng LLM để trích xuất hành vi thành dạng JSON (prosecutor_case).
    """
    logger.info(f"Bắt đầu phân tích {log_path} thông qua LLM (Gemini 2.5)...")
    
    if not os.path.exists(log_path):
        logger.error("Không tìm thấy file log để phân tích.")
        return {"error": "Missing log file"}
        
    try:
        # Đọc toàn bộ nội dung file log để LLM đóng vai trò màng lọc thô (Raw log filter)
        with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
            
            # BỘ LỌC HEURISTIC: Tránh việc file 16MB của pip làm trôi hết các syscall nhạy cảm
            # Ta chỉ lấy các dòng có chứa hoạt động Mạng, Tiến trình con, hoặc Truy cập File nhạy cảm
            suspicious_keywords = ["connect(", "socket(", "execve(", "clone(", "fork(", "/etc/", "http", ".com", "wget", "curl"]
            filtered_lines = [l for l in lines if any(k in l for k in suspicious_keywords)]
            
            # Nếu lọc xong mà rỗng (không thấy malware), ta lấy 1000 dòng đầu và cuối làm context nền
            if not filtered_lines:
                filtered_lines = lines[:1000] + ["\n... [NO SUSPICIOUS SYSCALLS HEURISTIC MATCHES] ...\n"] + lines[-1000:]
                
            content = "".join(filtered_lines)
            if len(content) > 3_000_000:
                logger.warning("File log lọc xong vẫn quá lớn (>3MB), cắt 3MB đầu.")
                content = content[:3_000_000]
    except Exception as e:
        logger.error(f"Lỗi đọc file: {e}")
        content = "Error reading log."
        
    prompt = f"""
    Bạn là một màng lọc bảo mật (Security Filter AI) kiêm chuyên gia phân tích.
    Nhiệm vụ của bạn là đọc TOÀN BỘ file log syslog (strace) khổng lồ dưới đây, được thu thập khi một gói tin Python cài đặt trong Sandbox.
    Bên trong hàng triệu dòng log này có chứa rất nhiều tiến trình hợp lệ của pip. Bạn phải mò tìm như mò kim đáy bể để phát hiện ra các hành vi ngoại lai (Ví dụ: đọc /etc/passwd, tạo file lạ, gọi lệnh shell, mở socket kết nối ra IP/domain lạ, v.v).
    
    ```
    {content}
    ```
    
    Hãy lọc ra và phân tích kỹ các hành vi đáng ngờ. 
    Trả về MỘT bản JSON (prosecutor_case) theo cấu trúc sau (TỐI QUAN TRỌNG: TRẢ VỀ DUY NHẤT CHUỖI JSON, KHÔNG CÓ BẤT KỲ VĂN BẢN TRÌNH BÀY NÀO KHÁC):
    {{
        "suspicious_activities": ["Hành vi 1", "Hành vi 2"],
        "network_connections": ["IP/Domain 1", "IP/Domain 2"],
        "files_accessed": ["File 1", "File 2"],
        "severity_score": 8, // Thang điểm từ 1-10 (10 là mã độc cực kỳ nguy hiểm hiển nhiên)
        "summary": "Tóm tắt ngắn gọn."
    }}
    """
    
    try:
        # Giả lập kết quả nếu không có API key thật hoặc đang test
        if GEMINI_API_KEY == "dummy_key":
            logger.warning("Chưa cấu hình GEMINI_API_KEY. Trả về kết quả phân tích giả định.")
            return {
                "suspicious_activities": ["Gói tin cố gắng đọc file /etc/passwd", "Thiết lập kết nối ra bên ngoài thông qua wget"],
                "network_connections": ["192.168.1.100:4444"],
                "files_accessed": ["/etc/passwd", "/tmp/malware.sh"],
                "severity_score": 9,
                "summary": "Gói tin có hành vi đáng ngờ: thu thập thông tin người dùng và kết nối tới C2 Server để Payload."
            }
            
        client = genai.Client(api_key=GEMINI_API_KEY)
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt,
        )
        
        # Làm sạch chuỗi trả về (đảm bảo nó là JSON hợp lệ dù LLM có trả về thêm markdown blocks)
        result_text = response.text.strip()
        if result_text.startswith("```json"):
            result_text = result_text[7:-3].strip()
        elif result_text.startswith("```"):
            result_text = result_text[3:-3].strip()
            
        return json.loads(result_text)
        
    except Exception as e:
        logger.error(f"Lỗi khi gọi LLM: {e}")
        # Trả về kết quả rỗng phòng hờ lỗi parse
        return {
            "suspicious_activities": [],
            "network_connections": [],
            "files_accessed": [],
            "severity_score": 0,
            "summary": f"Lỗi phân tích: {str(e)}"
        }

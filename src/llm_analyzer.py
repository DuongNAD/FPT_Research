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
        # Đọc nội dung file log (giới hạn dung lượng để tránh quá tải token)
        with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
            # Lấy 500 dòng cuối hoặc các dòng chứa từ khóa quan trọng
            lines = f.readlines()
            content = "".join(lines[-500:]) if len(lines) > 500 else "".join(lines)
    except Exception as e:
        logger.error(f"Lỗi đọc file: {e}")
        content = "Error reading log."
        
    prompt = f"""
    Bạn là một chuyên gia phân tích bảo mật (Cyber Security Analyst).
    Dưới đây là một đoạn trích xuất từ file syslog (strace) thu thập được khi một gói tin Python được kích nổ trong Sandbox:
    
    ```
    {content}
    ```
    
    Hãy phân tích kỹ các hành vi (đọc/ghi file nhạy cảm, mở kết nối mạng không mong muốn, tải thêm mã độc...)
    Và trả về MỘT bản tóm tắt hành vi dưới định dạng JSON (prosecutor_case) theo cấu trúc sau (không kèm theo văn bản nào khác ngoài JSON):
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

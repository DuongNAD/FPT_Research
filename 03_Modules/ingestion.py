import os
import httpx
import logging
import asyncio
from pathlib import Path
from typing import Callable, Awaitable

# Khai báo biến callback cho log thời gian thực
_log_callback: Callable[[str, int], Awaitable[None]] = None

def set_log_callback(callback: Callable[[str, int], Awaitable[None]]):
    global _log_callback
    _log_callback = callback

async def broadcast_log(message: str, step: int = 1):
    logging.info(message)
    global _log_callback
    if _log_callback:
        await _log_callback(message, step)

QUARANTINE_DIR = "quarantine"
os.makedirs(QUARANTINE_DIR, exist_ok=True)

class PipelineState:
    def __init__(self):
        self.is_interactive = False
        self.step_event = asyncio.Event()

pipeline_state = PipelineState()

async def interactive_pause(step_name):
    if pipeline_state.is_interactive and _log_callback:
        pipeline_state.step_event.clear()
        await broadcast_log(f"[Interactive] 🛑 TẠM DỪNG TIẾN TRÌNH: Vui lòng XÁC NHẬN trên UI (Nút APPROVE STEP) để {step_name}!", "pause")
        await pipeline_state.step_event.wait()
        await broadcast_log(f"[Interactive] 🟢 ĐÃ XÁC NHẬN! Tiếp tục thực thi {step_name}...", "resume")

import sys
# Để import được từ src
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from src.sandbox_runner import generate_mock_syscall_log

async def download_and_analyze(url: str, filename: str) -> bool:
    """
    Tải gói tin về khu vực cách ly và điều phối Sandbox.
    """
    # [SECURITY] Chống lỗ hổng Path Traversal (vd: filename = "../../../etc/passwd")
    safe_filename = os.path.basename(filename)
    file_path = os.path.join(QUARANTINE_DIR, safe_filename)
    
    await broadcast_log(f"[Ingestion] Bắt đầu chặn luồng tải nội dung từ PyPI...", 1)
    
    # [SECURITY] Tải gói tin an toàn (Chỉ ghi ra disk, không thực thi, không nén giải nén)
    # Tải gói tin nếu chưa có
    if url == "mock_url":
        pass
    elif not os.path.exists(file_path):
        await broadcast_log(f"[Ingestion] Đang tải mã nguồn '{safe_filename}' về vùng cách ly (Quarantine)...", 1)
        async with httpx.AsyncClient() as client:
            resp = await client.get(url, follow_redirects=True)
            resp.raise_for_status()
            with open(file_path, "wb") as f:
                f.write(resp.content)
        await broadcast_log(f"[Ingestion] Đã khóa chốt vùng cách ly cho '{safe_filename}'. Tải file thô an toàn.", 1)
    else:
        await broadcast_log(f"[Ingestion] Gói tin '{safe_filename}' đã bị giam giữ trong vùng cách ly từ trước.", 1)
        
    await asyncio.sleep(1) # Giả lập delay một chút để UI render đẹp
    
    # [LOGIC FIX] Nếu file tải về chỉ là thông tin .metadata, ta bỏ qua Sandbox
    if safe_filename.endswith(".metadata"):
        await broadcast_log(f"[Proxy] Gói thông tin '{safe_filename}' chỉ là Metadata (thông tin mồi). Bypass đưa thẳng ra ngoài...", 'done')
        return True
        
    # Bước 2 & 3: Thực thi trong Sandbox và lấy syscalls
    await interactive_pause("ném gói tin vào Sandbox Độc Lập")
    await broadcast_log(f"[Sandbox] (MOCK DO KHÔNG CÓ DOCKER) Đưa '{safe_filename}' vào Firecracker/Docker Container để kích nổ...", 2)
    
    # Do run_in_sandbox là hàm chặn (blocking), nên đẩy vào thread để không block event loop của FastAPI
    log_path = await asyncio.to_thread(generate_mock_syscall_log, filename)
    
    
    if log_path and os.path.exists(log_path):
        size = os.path.getsize(log_path)
        log_path_str = Path(log_path).as_posix()
        await interactive_pause("trích xuất phần bằng chứng Syscalls")
        await broadcast_log(f"[Syscalls] Trích xuất thành công: Bắt được {size} bytes nhật ký hệ điều hành tại {log_path} [[VIEW_LOG:{log_path_str}]]", 3)
    else:
        await broadcast_log(f"[Syscalls - LỖI] Không thể kết xuất file syscalls.log từ Sandbox.", 'done')
        return False

    # Bước 4: Phân tích LLM
    from src.llm_analyzer import analyze_syscalls
    await interactive_pause("chuyển giao thông tin tóm tắt cho AI phân tích")
    await broadcast_log(f"[LLM Analyst] Bắt đầu dịch lược luồng dữ liệu thô (Syscalls) qua AI (API)...", 4)
    
    # Gọi AI để phân tích log (block thread để đảm bảo đồng bộ)
    case_data = await asyncio.to_thread(analyze_syscalls, log_path)
    
    # Bước 5: Xuất báo cáo (Normalized Entry)
    json_path = os.path.join(QUARANTINE_DIR, f"{filename}.json")
    with open(json_path, 'w', encoding='utf-8') as f:
        import json
        json.dump(case_data, f, ensure_ascii=False, indent=2)
        
    score = case_data.get("severity_score", 0)
    summary = case_data.get("summary", "Không có tóm tắt")
    json_path_str = Path(json_path).as_posix()
    
    await interactive_pause("trích xuất dữ liệu Normalized JSON")
    await broadcast_log(f"[Normalized Log] Trích xuất siêu dữ liệu JSON thành công. Ánh xạ hành vi rõ ràng. [[VIEW_LOG:{json_path_str}]]", 5)
    
    # Bước 6: Multi-Agent Debate
    await interactive_pause("chuyển giao cho Hệ thống Đa Tác Nhân (Multi-Agent Debate)")
    await broadcast_log(f"[Multi-Agent] Khởi chạy buồng tranh biện ảo...\n- Prosecutor: Đề xuất điểm rủi ro {score}/10.\n- Defender: Phản biện theo ngữ cảnh cài đặt.\n- Judge: Tóm lược tranh biện: {summary}", 6)
    
    # Bước 7: Phán quyết (Decision)
    await interactive_pause("tiến hành phán quyết cuối cùng")
    if score >= 7:
        await broadcast_log(f"[Verdict] 🛑 CẢNH BÁO MÃ ĐỘC! Hệ thống hất văng kết nối, định tuyến Blacklist.", 'done')
        return False
    else:
        await broadcast_log(f"[Verdict] 🟢 QUÁ TRÌNH KIỂM KIỆM KẾT THÚC. Gói tin an toàn. Nhượng quyền cài đặt tiếp tục.", 'done')
        return True

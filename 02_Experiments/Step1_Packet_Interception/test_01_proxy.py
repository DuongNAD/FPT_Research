import pytest
import aiohttp
import asyncio
import subprocess
import sys
import os
import shutil
import time
import requests

PROXY_URL = "http://127.0.0.1:8000"
TEST_PKG = "shieldaidemo"
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
PROD_DIR = os.path.join(PROJECT_ROOT, "04_Production")
QUARANTINE_DIR = os.path.join(PROD_DIR, "quarantine")

# ==========================================
# FIXTURE: KHỞI TẠO & DỌN DẸP MÔI TRƯỜNG
# ==========================================
@pytest.fixture(scope="module", autouse=True)
def setup_teardown_server():
    """Tự động bật Proxy Server trước khi test và tắt sau khi test xong (Teardown)"""
    print("\n[🚀] Khởi động hệ thống Proxy phòng ngự...")
    current_dir = os.path.abspath(os.path.dirname(__file__))
    
    # Fake malware creation an toàn
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    subprocess.run(
        [sys.executable, "create_demo_malware.py"],
        check=True,
        cwd=current_dir,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=env
    )

    server_process = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "backend_api:app", "--port", "8000"],
        cwd=PROD_DIR,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    
    # Health check để đợi server sẵn sàng
    for _ in range(20):
        try:
            if requests.get(f"{PROXY_URL}/docs").status_code == 200:
                break
        except requests.ConnectionError:
            time.sleep(0.5)
            
    yield  # Bắt đầu chạy các luồng Test Hủy Diệt ở đây
    
    print("\n[🧹] Kích hoạt đội quét rác (Teardown Phase)...")
    server_process.terminate()
    try:
        server_process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        server_process.kill()
        server_process.wait()
    
    # Xóa sạch tàn tích
    for item in os.listdir(current_dir):
        if item.startswith("tmp_race_") or item.startswith("tmp_pip_test"):
            shutil.rmtree(os.path.join(current_dir, item), ignore_errors=True)
            
    # Xóa công cụ làm màu cũ đúng như anh yêu cầu
    for junk in ["run_experiment.py", "tmp.py", "err.log"]:
        junk_path = os.path.join(current_dir, junk)
        if os.path.exists(junk_path):
            os.remove(junk_path)
            print(f"💥 Đã tiêu diệt file {junk} lỗi thời!")

# ==========================================
# BÀI TEST 1: CONCURRENCY 500 LIÊN PHÁT
# ==========================================
@pytest.mark.asyncio
async def test_overkill_concurrency_500():
    """Bóp nghẹt Connection Pool bằng 500 request Asynchronous cùng lúc"""
    print("\n[🔥] Kích hoạt bão 500 requests...")
    
    async def fetch(session):
        try:
            async with session.get(f"{PROXY_URL}/simple/{TEST_PKG}/", timeout=15) as response:
                return response.status
        except Exception as e:
            return 500

    async with aiohttp.ClientSession() as session:
        # Nhồi 500 task vào Event Loop
        tasks = [fetch(session) for _ in range(500)]
        results = await asyncio.gather(*tasks)
        
        success_count = sum(1 for r in results if r == 200)
        error_count = 500 - success_count
        
        print(f"📊 Kết quả Concurrency: {success_count} OK, {error_count} Lỗi/Timeout")
        # Phải pass ít nhất 95% request để chứng tỏ Uvicorn không bị sập (Crash)
        assert success_count >= 475, f"Proxy bị sập! Chỉ xử lý được {success_count}/500 requests."

# ==========================================
# BÀI TEST 2: XUYÊN THẤU OBFUSCATED
# ==========================================
@pytest.mark.asyncio
async def test_overkill_obfuscated_path_traversal():
    """Gửi payload biến dị (URL Encoding, Double Encoding, Null Byte)"""
    print("\n[☠️] Bắn Payload xuyên thấu Path Traversal...")
    
    # Các dạng Payload kẻ thù hay dùng để lừa bộ lọc
    payloads = [
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd",          # ../../etc/passwd
        "..%252f..%252fetc%2fpasswd",              # Double encoded
        "shieldaidemo-1.0.0.tar.gz%00.png"         # Kẹp Null Byte lừa đuôi file
    ]
    
    async with aiohttp.ClientSession() as session:
        for payload in payloads:
            url = f"{PROXY_URL}/download/{payload}"
            try:
                async with session.get(url) as response:
                    status = response.status
                    # Trọng tâm: Proxy tuyệt đối KHÔNG ĐƯỢC trả về 200 OK với file hệ thống
                    assert status in [400, 403, 404, 422], f"Cảnh báo đỏ! Lỗ hổng rò rỉ tại payload: {payload}. Status: {status}"
            except (aiohttp.InvalidURL, aiohttp.ClientError):
                pass
            except Exception as e:
                pytest.fail(f"Lỗi không xác định khi tấn công payload {payload}: {e}")

# ==========================================
# BÀI TEST 3: RACE CONDITION (PIP SONG SONG)
# ==========================================
@pytest.mark.asyncio
async def test_overkill_race_condition():
    """Spawn 3 tiến trình pip tranh nhau tải cùng 1 file mã độc"""
    print("\n[🏎️] Kích hoạt Race Condition với 3 tiến trình pip...")
    current_dir = os.path.abspath(os.path.dirname(__file__))
    
    async def run_pip_download(worker_id):
        dest_dir = os.path.join(current_dir, f"tmp_race_{worker_id}")
        # Giả lập lập trình viên chạy lệnh pip
        cmd = [
            sys.executable, "-m", "pip", "download", TEST_PKG,
            "--index-url", f"{PROXY_URL}/simple",
            "--trusted-host", "127.0.0.1",
            "--dest", dest_dir,
            "--no-deps",
            "--quiet"
        ]
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=current_dir
        )
        await process.communicate()
        return process.returncode

    # Cho 3 công nhân (workers) cùng lao vào tải 1 lúc
    tasks = [run_pip_download(i) for i in range(3)]
    return_codes = await asyncio.gather(*tasks)
    
    # Vì file này chứa mã độc, hệ thống Proxy (Bước 1) phải hất văng cả 3 tiến trình
    for i, code in enumerate(return_codes):
        assert code != 0, f"Lỗ hổng Race Condition! Tiến trình {i} đã tải lọt file mã độc."
        
    # Thư mục quarantine không bị hỏng
    assert os.path.exists(QUARANTINE_DIR), "Thư mục Quarantine bị sập/không tồn tại sau đợt tấn công."

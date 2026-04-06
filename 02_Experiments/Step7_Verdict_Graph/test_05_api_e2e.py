import pytest
import requests
import time

PROXY_URL = "http://localhost:8000/download"

@pytest.fixture(scope="module")
def assert_proxy_is_running():
    """
    Setup Mocked:
    Kiểm tra chắc chắn uvicorn proxy (backend_api.py) đang chõ mũi ròm xem cổng có chạy không.
    Nếu dev lười bật server để test E2E thì pytest.skip toàn bộ bài này luôn.
    """
    try:
        # Pinging an API route (dashboard or anything simple)
        r = requests.get("http://localhost:8000/dashboard", timeout=2)
        if r.status_code != 200:
             pytest.skip("Server Proxy không phản hồi HTML, bỏ qua Test E2E.")
    except Exception:
        pytest.skip("Proxy chưa bật ở cổng localhost:8000. Chạy uvicorn backend_api:app trước.")
        

def test_proxy_let_clean_packages_pass_through(assert_proxy_is_running):
    """
    EXPECTATION: 
    Lập trình viên gõ pip giả lập trúng 1 ứng dụng TỐT.
    Hành Động: Proxy cho phép Bypass (200 OK HTTP)
    """
    clean_pkg = "requests-2.31.0.tar.gz"
    res_clean = requests.get(f"{PROXY_URL}/{clean_pkg}")
    
    assert res_clean.status_code == 200, \
        f"FALSE POSITIVE báo động đỏ: Thư viện xịn [{clean_pkg}] dính cấm bậy từ Neo4j/MalOS! (Code={res_clean.status_code})"


def test_proxy_block_malware_immediately(assert_proxy_is_running):
    """
    EXPECTATION:
    Tải gói độc hại đã biết.
    Hành Động: Đòn đánh chặng 403 Forbidden Error.
    """
    malware_pkg = "demo/shieldaidemo-1.0.0.tar.gz"
    res_mal = requests.get(f"{PROXY_URL}/{malware_pkg}")
    
    assert res_mal.status_code == 403, \
        f"[THẢM HỌA ZERO-DAY]: File độc [{malware_pkg}] bị Proxy cấp phép qua màn (Failing Default Block). HTTP {res_mal.status_code}"
    
    # Assert body message Proxy răn đe user (theo backend_api.py)
    assert b"ShieldAI Blocked" in res_mal.content or b"Forbidden" in res_mal.content, \
        "Backend đánh Block HTTP 403 nhưng thiếu Label Text giải thích cho Developer."

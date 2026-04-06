# 🛡️ Bộ Kịch Bản Đánh Giá 7 Bước ShieldAI (Test Scripts)

Dưới đây là các script Python độc lập (standalone scripts) dùng để kiểm thử và đánh giá từng bước trong pipeline ShieldAI. Các file này được thiết kế theo hướng không phụ thuộc framework (như `pytest`) để bạn dễ dàng debug, thao tác thủ công và tích hợp vào automation CI/CD sau này.

> **Mục tiêu:** Đo lường chính xác các KPI đã đề ra (Độ trễ, Độ chính xác, Tỉ lệ lỗi).
> Sử dụng thư viện gốc như `requests`, `aiohttp`, `subprocess` để việc tái cấu trúc trên bất cứ môi trường nào cũng chạy mượt.

---

## Bước 1: Packet Proxy (Ingestion & Latency)
**Tên file:** `test_step1_proxy.py`  
**Kỹ thuật:** Phân tích trễ dưới tải lớn (Asynchronous Load Testing) với `aiohttp`.  
**Mô tả:** Gửi đồng thời yêu cầu tải 5 package sạch khác phổ biến qua cổng Proxy (`localhost:8000`). Hệ thống đo lường độ trễ từ khi Request bắt đầu đến lúc nhận HTML Response, đồng thời đếm tỷ lệ cài đặt thành công và hiển thị thống kê. 

```python
import asyncio
import aiohttp
import time

PROXY_URL = "http://localhost:8000/simple"
TEST_PACKAGES = ["requests", "numpy", "pandas", "urllib3", "certifi"]

async def fetch_package(session, pkg_name):
    start_time = time.time()
    url = f"{PROXY_URL}/{pkg_name}/"
    try:
        async with session.get(url, timeout=10) as response:
            status = response.status
            await response.text()  # Đọc nội dung giả lập proxy xử lý
            latency = time.time() - start_time
            return pkg_name, status, latency
    except Exception as e:
        return pkg_name, 500, time.time() - start_time

async def main():
    print("🚀 Bắt đầu đo kiểm Bước 1: Proxy Latency & Reliability")
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_package(session, pkg) for pkg in TEST_PACKAGES]
        results = await asyncio.gather(*tasks)
        
        success_count = 0
        total_latency = 0
        for pkg, status, latency in results:
            if status == 200:
                success_count += 1
            total_latency += latency
            print(f"📦 [Package: {pkg}] - Status: {status} - Latency: {latency:.2f}s")
            
        print(f"\n📊 TÓM TẮT BƯỚC 1:")
        print(f"✅ Tỷ lệ thành công: {(success_count/len(TEST_PACKAGES))*100}%")
        print(f"⏱️ Độ trễ trung bình: {total_latency/len(TEST_PACKAGES):.2f}s")

if __name__ == "__main__":
    asyncio.run(main())
```

---

## Bước 2 & 3: Sandbox Execution & Syscalls Log Capture
**Tên file:** `test_step2_3_sandbox.py`  
**Kỹ thuật:** Môi trường ảo (Subprocess Execution) & Tìm chuỗi chính quy (Regex Log Parsing).  
**Mô tả:** Gọi trực tiếp lệnh kích hoạt môi trường Sandbox lên gói `shieldaidemo`. Bấm giờ cho phiên thực thi, sau đó đối chiếu file `syscalls.log` được xuất ra để phân tích xem có bắt dính các keyword nguy hiểm hệ thống hay không (ví dụ: `connect, execve, openat`). 

```python
import os
import subprocess
import time
import re

def test_sandbox():
    print("🧫 Bắt đầu kiểm tra Bước 2 & 3: Sandbox Execute và Capture System Calls")
    
    # Ở đây chúng ta mượn payload từ malware giả
    package_path = "quarantine/shieldaidemo-1.0.0.tar.gz"
    
    if not os.path.exists(package_path):
        print(f"❌ Không tìm thấy file {package_path}. Vui lòng chạy create_demo_malware.py trước.")
        return

    start_time = time.time()
    
    # 1. Gọi trực tiếp module Sandbox để chạy phân tích package này
    cmd = ["python", r"src\sandbox_runner.py", package_path]
    print(f"🏃 Đang tống file qua module Sandbox...")
    process = subprocess.run(cmd, capture_output=True, text=True)
    
    exec_time = time.time() - start_time
    print(f"⏱️ Thời gian Sandbox thực thi phân tích: {exec_time:.2f}s")
    
    # 2. Kiểm duyệt output của file syscalls.log
    log_file = "src/syscalls.log"
    if not os.path.exists(log_file):
        print("❌ LỖI: Cấu trúc Sandbox bị hỏng. Không sinh ra file hệ thống syscalls.log!")
        return
        
    with open(log_file, "r", encoding="utf-8") as f:
        log_data = f.read()
        
    syscalls_to_check = ['connect', 'execve', 'openat']
    found = {call: bool(re.search(rf"\b{call}\(", log_data)) for call in syscalls_to_check}
    
    print("\n📝 PHÊ DUYỆT SYSCALL LOG:")
    for call, is_found in found.items():
        status = "✅ Bắt được" if is_found else "❌ Lọt lưới"
        print(f"   - Syscall hệ thống [{call}]: {status}")

if __name__ == "__main__":
    test_sandbox()
```

---

## Bước 4 & 5: LLM Extraction & JSON Validation
**Tên file:** `test_step4_5_llm.py`  
**Kỹ thuật:** Data Mocking & JSON Schema/Structural Validation.  
**Mô tả:** Truyền một đoạn mã giả định (dummy system call logic) cho hệ thống trích xuất LLM. Script đo tốc độ phản hồi từ API (Time-To-First-Token) và khả năng "Parse Error Rate", xem cấu trúc JSON trả về có đúng format hay bị ảo giác tạo ra chữ thường thay vì format MITRE tiêu chuẩn JSON.

```python
import asyncio
import time
import json
import sys
import os

# Tuỳ thuộc vào module của bạn, import hàm xử lý LLM
sys.path.append(os.path.abspath("src"))
try:
    from llm_analyzer import analyze_syscall_logs 
except ImportError:
    print("⚠️ Cần thay đổi phần file này để khớp với logic import từ file ai_agent_extraction của bạn")

async def test_llm_extraction():
    print("🧠 Bắt đầu kiểm tra Bước 4 & 5: Tốc độ LLM & Định dạng JSON đầu ra")
    
    # Dữ liệu Syscall độc hại cố tình rút ngắn để châm mồi
    dummy_log = "openat(AT_FDCWD, '/etc/passwd', O_RDONLY|O_CLOEXEC) = 3\\nconnect(3, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr('192.168.1.100')}, 16) = 0"
    
    start_time = time.time()
    
    try:
        raw_result = await analyze_syscall_logs(dummy_log)
        latency = time.time() - start_time
        print(f"⏱️ Thời gian phản hồi TTFT của LLM: {latency:.2f}s")
        
        print("📑 Đang kiểm chứng định dạng Output...")
        data = json.loads(raw_result)
        
        if "indicator" in data and "behavior" in data:
            print("✅ Kết quả chuẩn xác và parse thành công JSON (0% Parse Error)")
        else:
            print("❌ JSON parse thành công nhưng thiếu cấu trúc Schema được yêu cầu!")
            
    except json.JSONDecodeError:
        print("❌ LỖI NGHIÊM TRỌNG: Đầu ra của LLM không phải JSON hợp lệ (Parse Error cao).")
    except Exception as e:
        print(f"Lỗi: {e}")

if __name__ == "__main__":
    asyncio.run(test_llm_extraction())
```

---

## Bước 6: Multi-Agent Debate
**Tên file:** `test_step6_debate.py`  
**Kỹ thuật:** Module Validation Testing (Debate Cycle Counting).  
**Mô tả:** Đưa bằng chứng "Borderline" (Cập kễnh - gói sạch nhưng kết nối Internet để báo cáo thống kê) vào phòng Debate. Đánh giá xem nhóm Multi-Agent mất bao nhiêu vòng lặp để đưa ra phán quyết, chúng có đi đến thống nhất không hay rơi vào lặp logic vô hạn, làm tốn tài nguyên token.

```python
import sys
import os

sys.path.append(os.path.abspath("src"))
try:
    from multi_agent_extraction import multi_agent_debate
except ImportError:
    print("⚠️ Cần import đúng hàm từ multi_agent_extraction.py của bạn.")

def test_debate():
    print("🧑‍⚖️ Bắt đầu kiểm tra Bước 6: Hội Đồng Tranh Biện Agent Debate")
    
    # Một pattern mập mờ, dễ bị đánh mác false positive
    borderline_evidence = {
        "behaviors": ["Network connection to 142.250.190.46:443 (Google API)"],
        "package": "fake-google-auth-plugin"
    }
    
    print(f"📊 Đầu vào (Bằng chứng Evidence): {borderline_evidence}")
    
    try:
        # Nếu hàm debate trả về kết quả verdict và counter số vòng
        verdict, turns, logs = multi_agent_debate(str(borderline_evidence))
        
        print(f"⚖️ Phán quyết Thẩm Phán (AI Verdict): {verdict}")
        print(f"🔄 Số lượt hoàn tất Debate: {turns}")
        
        if turns > 3:
            print("⚠️ Cảnh báo: Số vòng tranh biện quá cao, dẫn tới Lãng phí Token API và tăng độ trễ E-to-E.")
        else:
            print("✅ AI Debate chạy hiệu quả và hội tụ nhanh chóng.")
            
    except Exception as e:
         print(f"AI Debate bị lỗi hoặc hàm thiếu params: {e}")

if __name__ == "__main__":
    test_debate()
```

---

## Bước 7: End-to-End Phán Quyết & Block Proxy Hành Động
**Tên file:** `test_step7_e2e.py`  
**Kỹ thuật:** Kiểm thử Tích hợp Endpoint định tuyến (HTTP Integration Testing).  
**Mô tả:** Giả đóng vai lệnh Pip để Request 1 thư viện. Lấy thư viện sạch (`requests-2.31.0`) và 1 mẫu mã độc (`demo/shieldaidemo-1.0.0`). Cấu hình assert nghiệm thu package sạch được cấp quyền HTTP 200, trong khi file Demo phải bị chốt cấm **HTTP 403 Forbidden**.

```python
import requests
import time

PROXY_URL = "http://localhost:8000/download"

def test_e2e_proxy():
    print("⚖️ Bắt đầu kiểm thử Bước 7: Phán Quyết Cuối Cùng (End-to-End)")
    
    # 1. Test với package sạch (Ground Truth Negative - Không cấm)
    clean_pkg = "requests-2.31.0.tar.gz"
    print(f"\n👉 [TEST 1] Thử tải package sạch qua hệ thống: {clean_pkg}")
    
    try:
        res_clean = requests.get(f"{PROXY_URL}/{clean_pkg}")
        if res_clean.status_code == 200:
             print("✅ Test 1 Thành công: File sạch được tải bình thường. Proxy không giữ chặn (200 OK).")
        else:
             print(f"❌ Lỗi: Có vẻ file dính cấm nhầm (False Positive). Mã trạng thái: {res_clean.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Lỗi kết nối tới Proxy: {e}")

    # 2. Test với package độc hại (Ground Truth Positive - Buộc Cấm)
    malware_pkg = "demo/shieldaidemo-1.0.0.tar.gz"
    print(f"\n👉 [TEST 2] Thử tải package chứa mã độc: {malware_pkg}")
    try:
        res_mal = requests.get(f"{PROXY_URL}/{malware_pkg}")
        
        # Thiết kế proxy ném thẳng lỗi 403 khi Reject
        if res_mal.status_code == 403:
             print("✅ Test 2 Thành công: Proxy nhận tin dữ và đánh văng HTTP 403 Forbidden thành công.")
        elif res_mal.status_code == 200:
             print("❌ NGHIÊM TRỌNG: Mã độc đã lọt qua (Lỗi False Negative).")
        else:
             print(f"⚠️ Trạng thái không mong muốn: {res_mal.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Lỗi kết nối tới Proxy: {e}")

if __name__ == "__main__":
    test_e2e_proxy()
```

import sys, os
from pathlib import Path

# Thêm đường dẫn Src
sys.path.append(os.path.abspath('04_Production/src'))
import sandbox_runner
import multi_agent_extraction

pkg = 'doomsday-1.0.0'
tar_file = f'{pkg}.tar.gz'

print("===== BƯỚC 1: QUÉT SANDBOX DÀNH RIÊNG CHO DOOMSDAY =====")
log_path = sandbox_runner.run_in_sandbox(tar_file)

if not log_path or not os.path.exists(log_path):
    print("❌ THẤT BẠI KHI RÚT LOG TỪ SANDBOX!")
    sys.exit(1)

with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
    log_content = f.read()

print(f"\n[OK] Đã rút thành công LOG dài {len(log_content)} ký tự. Kích hoạt Debate...\n")

print("===== BƯỚC 2 & 3: KÍCH HOẠT QUY TRÌNH HẠ CẤP MULTI-AGENT =====")
verdict = multi_agent_extraction.run_debate(pkg, log_content)

print(f"\n===== KẾT QUẢ ĐẠI HÌNH =====")
print(verdict)

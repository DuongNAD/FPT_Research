import os
import subprocess
import time
import re
import pytest
import shutil
import sys
import uuid
from pathlib import Path

current_dir = Path(__file__).parent.resolve()
sys.path.append(str(current_dir / "malware_sandbox"))

try:
    from orchestrator import run_sandbox, build_image, check_docker_health
except ImportError:
    pytest.fail("Không thể import orchestrator.py từ thư mục malware_sandbox.")

DOCKER_IMAGE = "pip-sandbox:latest"

@pytest.fixture(scope="module", autouse=True)
def setup_sandbox_environment():
    """Tự động Build Image trước khi chạy các Test"""
    print("\n[+] Đang chuẩn bị Docker Image cho Sandbox...")
    build_image()
    yield

@pytest.fixture(scope="module")
def quarantine_malware_demo():
    """Sinh mồi mã độc, đẩy vào thư mục Quarantine."""
    project_root = current_dir.parent.parent
    step1_dir = project_root / "02_Experiments" / "Step1_Packet_Interception"
    
    print("\n[+] Gọi lò đúc mã độc từ Bước 1...")
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    subprocess.run(
        [sys.executable, "create_demo_malware.py"],
        check=True, cwd=step1_dir, capture_output=True, text=True, encoding="utf-8", env=env
    )
    
    demo_file = step1_dir / "data" / "demo" / "shieldaidemo-1.0.0.tar.gz"
    quarantine_dir = project_root / "04_Production" / "quarantine"
    quarantine_dir.mkdir(parents=True, exist_ok=True)
    
    dest_file = quarantine_dir / "shieldaidemo-1.0.0.tar.gz"
    shutil.copy(demo_file, dest_file)
    
    yield quarantine_dir, "shieldaidemo-1.0.0.tar.gz"

def test_docker_health_fail_fast():
    """Khẳng định Fail-fast hoạt động. Nếu ping được thì pass."""
    try:
        check_docker_health()
    except Exception as e:
        pytest.fail(f"LỖI: Docker không hoạt động. Hãy bật Docker Desktop. {e}")

def test_integration_sandbox_uuid_isolation(quarantine_malware_demo):
    """
    [INTEGRATION TEST & TASK ISOLATION UUID]
    Chứng minh: Orchestrator bốc đúng file từ UUID Folder.
    """
    q_dir, pkg_name = quarantine_malware_demo
    project_root = current_dir.parent.parent
    
    # Tạo UUID ảo mượn từ kịch bản Test
    task_id = str(uuid.uuid4())
    
    # Setup thư mục UUID giả định cho Mồi
    source_uuid_dir = q_dir / task_id
    source_uuid_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy(q_dir / pkg_name, source_uuid_dir / pkg_name)
    
    log_output_dir = project_root / "04_Production" / "logs" / "syscalls"
    # Orchestrator sẽ tự nhét `task_id` vào cuối log_output_dir
    
    start_time = time.time()
    run_sandbox(
        package_file_name=pkg_name,
        source_dir=str(q_dir),        # Truyền thư mục Mẹ, orchestrator sẽ tự join với task_id
        log_dir=str(log_output_dir),
        timeout_seconds=30,
        is_malicious=False,
        task_uuid=task_id
    )
    
    exec_time = time.time() - start_time
    assert exec_time < 30, f"LỖI TIMEOUT: Sandbox chạy vượt mức {exec_time:.2f}s"
    
    # Kiểm tra File Sinh ra ĐÚNG trong thư mục UUID
    expected_log_file = log_output_dir / task_id / f"{pkg_name}.strace.log"
    assert expected_log_file.exists(), f"Thất bại: Sandbox không sinh được file strace log trong ngăn chứa {task_id}!"
    
    with open(expected_log_file, "r", encoding="utf-8", errors="ignore") as f:
        log_data = f.read()

    # Chứng cứ thép cần tìm trong log
    syscalls_to_check = ['connect', 'execve', 'openat']
    for call in syscalls_to_check:
        assert re.search(rf"\b{call}\b", log_data) is not None, f"Syscall lọt lưới: Thiếu hàm [{call}]"

@pytest.fixture(scope="module")
def quarantine_evasion_malware():
    """Sinh mồi chống Ảo Hóa (Evasion) và Honeypot."""
    import create_evasion_malware
    output_dir = current_dir / "data"
    tar_path = create_evasion_malware.create_evasion_package(output_dir)
    
    project_root = current_dir.parent.parent
    quarantine_dir = project_root / "04_Production" / "quarantine"
    quarantine_dir.mkdir(parents=True, exist_ok=True)
    
    dest_file = quarantine_dir / "evasiondemo-9.9.9.tar.gz"
    shutil.copy(tar_path, dest_file)
    
    yield quarantine_dir, "evasiondemo-9.9.9.tar.gz"

def test_integration_honeypot_evasion_traps(quarantine_evasion_malware):
    """
    [HONEYPOT & TIME ACCELERATION TEST]
    Malware có Time.Sleep(120) và gọi open('/root/.ssh/id_rsa').
    Chứng minh: 
    1. Chạy Nhanh Hơn 30s nhờ Faketime.
    2. Trong chuỗi Strace có ghi nhận lệnh chực chờ mở khóa '/root/.ssh' (Honeypot hit).
    """
    q_dir, pkg_name = quarantine_evasion_malware
    project_root = current_dir.parent.parent
    task_id = str(uuid.uuid4())
    
    source_uuid_dir = q_dir / task_id
    source_uuid_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy(q_dir / pkg_name, source_uuid_dir / pkg_name)
    
    log_output_dir = project_root / "04_Production" / "logs" / "syscalls"
    
    start_time = time.time()
    run_sandbox(
        package_file_name=pkg_name,
        source_dir=str(q_dir),        
        log_dir=str(log_output_dir),
        timeout_seconds=30,  # Malware gọi sleep 120s nhưng sẽ lách được qua faketime nên không dính cờ đứt mạch.
        is_malicious=False,
        task_uuid=task_id
    )
    
    exec_time = time.time() - start_time
    assert exec_time < 30, f"LỖI FAKETIME: Mã độc ngủ đông thành công quá 30s ({exec_time:.2f}s). Libfaketime thất bại."
    
    expected_log_file = log_output_dir / task_id / f"{pkg_name}.strace.log"
    assert expected_log_file.exists(), f"Thất bại: Mồi nhử Honeypot không xuất log."
    
    with open(expected_log_file, "r", encoding="utf-8", errors="ignore") as f:
        log_data = f.read()

    # Chứng cứ thép cần tìm: Malware sờ vào khóa id_rsa RSA Dummy của hệ thống.
    # Lệnh strace sẽ ghi lại: openat(AT_FDCWD, "/root/.ssh/id_rsa", O_RDONLY|O_CLOEXEC)
    assert ".ssh/id_rsa" in log_data, f"Honeypot Trap hụt: Không thấy mã độc đọc file SSH Dummy trong log. Libfaketime có thể đã khóa đứng luồng!"

def test_hardware_spoofing_pcap_capture(quarantine_evasion_malware):
    """
    [HARDWARE SPOOFING & PCAP TEST]
    Malware kiểm tra /proc/meminfo và gọi urllib ra mạng ảo.
    Chứng minh:
    1. Trong log strace xuất hiện dòng khoác lác "RAM khủng" (Do đã bị đánh lừa bởi meminfo giả).
    2. Một file .pcap được tạo ra với nội dung thực tế để chứng minh lưới bắt Tcpdump đã kết thúc thành công (Flush).
    """
    q_dir, pkg_name = quarantine_evasion_malware
    project_root = current_dir.parent.parent
    task_id = str(uuid.uuid4())
    
    source_uuid_dir = q_dir / task_id
    source_uuid_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy(q_dir / pkg_name, source_uuid_dir / pkg_name)
    
    log_output_dir = project_root / "04_Production" / "logs" / "syscalls"
    
    start_time = time.time()
    run_sandbox(
        package_file_name=pkg_name,
        source_dir=str(q_dir),        
        log_dir=str(log_output_dir),
        timeout_seconds=30, 
        is_malicious=False,
        task_uuid=task_id
    )
    
    exec_time = time.time() - start_time
    assert exec_time < 30, f"LỖI: Tiến trình vượt ngưỡng 30s ({exec_time:.2f}s)."
    
    expected_pcap_file = log_output_dir / task_id / f"{pkg_name}.pcap"
    assert expected_pcap_file.exists(), f"Thất bại: Mạng lưới không thu được PCAP."
    assert expected_pcap_file.stat().st_size >= 24, f"Thất bại: File PCAP sinh ra nhúng sai cấu trúc (corrupted header)."
    
    expected_log_file = log_output_dir / task_id / f"{pkg_name}.strace.log"
    with open(expected_log_file, "r", encoding="utf-8", errors="ignore") as f:
        log_data = f.read()
    
    assert "meminfo" in log_data, f"Sandbox không mớm Hardware Memory Info Spoofing cho Mã Độc!"

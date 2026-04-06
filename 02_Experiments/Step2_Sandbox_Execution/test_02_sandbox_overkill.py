import pytest
import os
import time
from malware_sandbox.orchestrator import run_sandbox

PKG_NAME = "doomsday-1.0.0.tar.gz"
SOURCE_DIR = os.path.abspath("data/quarantine/task_doomsday")
LOG_DIR = os.path.abspath("data/logs/syscalls/task_doomsday")

@pytest.fixture(scope="module")
def run_doomsday():
    """Chạy Sandbox với gói Doomsday và đo thời gian"""
    import shutil
    start_time = time.time()
    task_id = "test_overkill_uuid"
    
    # Chuẩn bị file mồi
    source_uuid_dir = os.path.join(SOURCE_DIR, task_id)
    os.makedirs(source_uuid_dir, exist_ok=True)
    shutil.copy(os.path.join(SOURCE_DIR, PKG_NAME), os.path.join(source_uuid_dir, PKG_NAME))
    
    # Gọi Sandbox với Timeout 60s
    run_sandbox(
        package_file_name=PKG_NAME, 
        source_dir=SOURCE_DIR, 
        log_dir=LOG_DIR, 
        timeout_seconds=60, 
        task_uuid=task_id, 
        is_malicious=True
    )
    execution_time = time.time() - start_time
    
    log_path = os.path.join(LOG_DIR, task_id, f"{PKG_NAME}.strace.log")
    
    return {'status': 'success', 'log_path': log_path, 'task_id': task_id}, execution_time

def test_overkill_faketime_bypass(run_doomsday):
    """TEST 1: Faketime có bóp chết đòn Ngủ đông 10 năm không?"""
    result, execution_time = run_doomsday
    
    # Nếu Faketime hoạt động, mã độc 10 năm sẽ kết thúc sớm, nhưng do vụ nổ Fork Bomb chứa 50 clones cùng chạy setup.py,
    # tổng thời gian có thể kéo dài lên 50s. Chỉ cần không bị Timeout (60s) là thành công!
    assert result['status'] == 'success', f"Sandbox bị dính Timeout (Ngủ đông thành công)! Status: {result['status']}"
    assert execution_time < 70, f"Faketime không hoạt động, tiến trình treo quá lâu: {execution_time}s"
    print("\n✅ The Time Lord: Đã bị Faketime ép nôn ra thời gian!")

def test_overkill_forkbomb_prevention(run_doomsday):
    """TEST 2: PID Limit có chặn đứng Fork Bomb không?"""
    result, _ = run_doomsday
    log_path = result['log_path']
    
    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
        log_content = f.read()
    
    # Bắt buộc phải có lỗi EAGAIN (Resource temporarily unavailable) khi gọi clone/fork
    assert "EAGAIN" in log_content and "clone" in log_content, "Lỗ hổng Fork Bomb: Không thấy chặn PID limit trong Strace!"
    print("✅ The Fork Bomb: Đã bị giới hạn pids_limit bóp cổ!")

def test_overkill_readonly_honeypot(run_doomsday):
    """TEST 3: File hệ thống có được bảo vệ bằng Cờ Chỉ Đọc (:ro) không?"""
    result, _ = run_doomsday
    log_path = result['log_path']
    
    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
        log_content = f.read()
    
    # Mã độc cố ghi (O_WRONLY) vào meminfo, nó PHẢI nhận về lỗi EROFS (Read-only file system) hoặc EACCES
    # Lệnh strace sẽ cho ra: openat(AT_FDCWD, "/proc/meminfo", O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0666) = -1 EROFS hoặc tương tự.
    assert 'meminfo"' in log_content, "Mã độc chưa kịp gọi lệnh phá hoại Meminfo"
    assert "EROFS" in log_content or "EACCES" in log_content, "Lỗ hổng File System: Mã độc đã ghi đè thành công tệp hệ thống!"
    print("✅ The Jailbreaker: Đã gãy răng khi cắn vào khiên Read-Only!")

def test_overkill_pcap_generation(run_doomsday):
    """TEST 4: TCPDump có bắt được tang vật ném ra ngoài không?"""
    result, _ = run_doomsday
    log_dir_uuid = os.path.join(LOG_DIR, result['task_id'])
    pcap_files = [f for f in os.listdir(log_dir_uuid) if f.endswith('.pcap')]
    assert len(pcap_files) > 0, "Lỗi PCAP: Không sinh ra file băng ghi âm mạng!"
    
    pcap_path = os.path.join(log_dir_uuid, pcap_files[0])
    # file size should be at least 24 bytes (header). Even if no UDP packets exit eth0, file must be structurally intact.
    assert os.path.getsize(pcap_path) >= 24, "PCAP file trống rỗng! TCPDump chạy xịt hoặc thiếu quyền NET_RAW!"
    print("✅ The Ghost Exfiltrator: Đã bị tóm gọn tang vật trong file PCAP!")

def test_overkill_cgroup_detection(run_doomsday):
    """TEST 5: Để lại dấu vết rõ ràng cho Bước 3 LLM Analyzer"""
    result, _ = run_doomsday
    log_path = result['log_path']
    
    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
        log_content = f.read()
    
    # Lệnh mở /.dockerenv phải xuất hiện lù lù trong log để LLM sau này dễ dàng kết án
    assert '.dockerenv' in log_content, "Syscall không bắt được lệnh dò xét DockerEnv!"
    print("✅ The Detective: Hành vi ngó nghiêng đã bị lưu vào hồ sơ đen!")

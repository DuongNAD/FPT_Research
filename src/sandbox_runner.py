import os
import time
import subprocess
import logging
import uuid

logger = logging.getLogger(__name__)

# Tên Docker image làm Sandbox
DOCKER_IMAGE = "shieldai-sandbox:latest"

def run_in_sandbox(filename: str) -> str:
    """
    Luồng tự động hóa Docker thay thế VMWare:
    1. Tạo container mới (sạch)
    2. Copy .whl vào container
    3. Detonate (strace + tcpdump)
    4. Kéo log về
    5. Xóa container
    """
    quarantine_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'quarantine'))
    os.makedirs(quarantine_dir, exist_ok=True)
    
    host_package_path = os.path.join(quarantine_dir, filename)
    
    if not os.path.exists(host_package_path):
        logger.error(f"File mã độc không tồn tại tại: {host_package_path}")
        return ""
    
    run_id = uuid.uuid4().hex[:8]
    log_filename = f"syscalls_{run_id}.log"
    host_log_path = os.path.join(quarantine_dir, log_filename)
    
    pcap_filename = f"capture_{run_id}.pcap"
    host_pcap_path = os.path.join(quarantine_dir, pcap_filename)
    
    logger.info(f"Đang kích hoạt Docker Sandbox cho siêu gói tin: {filename}")
    
    container_name = f"sandbox_{run_id}"
    sidecar_name = f"sniffer_{run_id}"
    
    try:
        # Tự tạo Mạng cô lập shield_net nếu chưa có
        subprocess.run([
            "docker", "network", "create", 
            "--driver", "bridge", 
            "--subnet", "172.25.0.0/16", 
            "--opt", "com.docker.network.bridge.name=shield_br",
            "shield_net"
        ], capture_output=True) # Ignore error if exists

        # BƯỚC 1 & 2: Khởi tạo container và giữ nó chạy ngầm
        logger.info(f"[Sandbox] 1/4: Đang tạo Docker Container mới ({container_name})...")
        subprocess.run([
            "docker", "run", "-d", "--name", container_name,
            "--network=shield_net",
            "--cpus=1.0",
            "--memory=1g",
            "--pids-limit=100",
            "--cap-drop=ALL",
            "--cap-add=SYS_PTRACE",
            "--security-opt=no-new-privileges=true",
            "--read-only",
            "--tmpfs", "/tmp:rw,nosuid,nodev",
            "--tmpfs", "/home/sandboxuser:rw,exec,nosuid",
            DOCKER_IMAGE, "tail", "-f", "/dev/null"
        ], check=True, capture_output=True)
        
        logger.info(f"[Sandbox] 2/4: Bơm xuyên vách mã độc {filename} vào Container...")
        guest_package_path = f"/tmp/{filename}"
        subprocess.run([
            "docker", "cp", host_package_path, f"{container_name}:{guest_package_path}"
        ], check=True, capture_output=True)
        
        # BƯỚC 3: KÍCH NỔ (Detonate)
        logger.info("[Sandbox] 3/4: Khởi động Network Monitor Sidecar và KÍCH NỔ...")
        guest_log_path = f"/tmp/{log_filename}"
        guest_pcap_path = f"/tmp/{pcap_filename}"
        
        logger.info(f"[Monitor] Chạy Sidecar Container ({sidecar_name}) để thu thập pcap Out-of-Band...")
        subprocess.run([
            "docker", "run", "-d", "--name", sidecar_name,
            "--network", f"container:{container_name}",
            "--cap-drop=ALL",
            "--cap-add=NET_RAW", "--cap-add=NET_ADMIN",
            DOCKER_IMAGE, "tcpdump", "-i", "any", "-w", guest_pcap_path
        ], check=True, capture_output=True)
        
        # Lệnh chạy bên trong container chính (Chỉ gồm strace)
        detonate_cmd = (
            f"timeout 120s strace -f -s 256 -e trace=file,network,process "
            f"-o {guest_log_path} pip install --user {guest_package_path} --no-index --find-links /tmp/ ; "
            f"sleep 2 ; "
            f"chmod 777 {guest_log_path} || true"
        )
        
        try:
            subprocess.run([
                "docker", "exec", container_name, "/bin/bash", "-c", detonate_cmd
            ], capture_output=True, timeout=140)
        except subprocess.TimeoutExpired:
            logger.warning("[Sandbox] Lệnh kích nổ đã chạy hết 140s giới hạn cứng!")
            
        # Chốt file capture trên sidecar
        subprocess.run(["docker", "kill", "--signal=SIGINT", sidecar_name], capture_output=True)
        time.sleep(2)

        # BƯỚC 4: Hút bằng chứng
        logger.info("[Sandbox] 4/4: Hút bằng chứng (.log, .pcap) trả về máy Host...")
        subprocess.run([
            "docker", "cp", f"{container_name}:{guest_log_path}", host_log_path
        ], capture_output=True)
        
        # Hút file mạng từ vùng Out-of-Band
        subprocess.run([
            "docker", "cp", f"{sidecar_name}:{guest_pcap_path}", host_pcap_path
        ], capture_output=True)
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Lệnh Docker thất bại. Lỗi: {e.stderr if isinstance(e.stderr, str) else e}")
    except Exception as e:
        logger.error(f"Lỗi nghiêm trọng kiểm soát Docker: {e}")
    finally:
        # BƯỚC 5: Xóa container (Clearing State)
        logger.info("[Sandbox] Xóa sạch tàn dư (Remove Container và Sidecar)...")
        subprocess.run(["docker", "rm", "-f", container_name], capture_output=True)
        subprocess.run(["docker", "rm", "-f", sidecar_name], capture_output=True)
        
    # Xác minh log
    if os.path.exists(host_log_path) and os.path.getsize(host_log_path) > 0:
        logger.info(f"[Hoàn tất] File Syscalls ghi lại thành công tại: {host_log_path}")
        return host_log_path
    else:
        logger.error("[Docker] Container không xuất ra được file log hoặc file rỗng! Sandbox có thể đã bị vô hiệu hóa.")
        return ""

def generate_mock_syscall_log(package_name: str) -> str:
    """MOCK function to return the path to the dummy sandbox log for the dashboard demo."""
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'data', 'syscalls'))
    
    if "requests-fake" in package_name:
        log_file = os.path.join(base_dir, "requests-fake-1.0.0_syscalls.log")
    elif "urllib3" in package_name:
        log_file = os.path.join(base_dir, "urllib3-1.26.15_syscalls.log")
    else:
        log_file = os.path.join(base_dir, "requests-2.31.0_syscalls.log")
        
    return log_file

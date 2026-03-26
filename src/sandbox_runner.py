import os
import time
import subprocess
import logging

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
    
    log_filename = f"syscalls_{int(time.time())}.log"
    host_log_path = os.path.join(quarantine_dir, log_filename)
    
    pcap_filename = f"capture_{int(time.time())}.pcap"
    host_pcap_path = os.path.join(quarantine_dir, pcap_filename)
    
    logger.info(f"Đang kích hoạt Docker Sandbox cho siêu gói tin: {filename}")
    
    container_name = f"sandbox_{int(time.time())}"
    
    try:
        # BƯỚC 1 & 2: Khởi tạo container và giữ nó chạy ngầm
        logger.info(f"[Sandbox] 1/4: Đang tạo Docker Container mới ({container_name})...")
        subprocess.run([
            "docker", "run", "-d", "--name", container_name,
            "--privileged",  # Cần thiết cho strace
            DOCKER_IMAGE, "tail", "-f", "/dev/null"
        ], check=True, capture_output=True)
        
        logger.info(f"[Sandbox] 2/4: Bơm xuyên vách mã độc {filename} vào Container...")
        guest_package_path = f"/tmp/{filename}"
        subprocess.run([
            "docker", "cp", host_package_path, f"{container_name}:{guest_package_path}"
        ], check=True, capture_output=True)
        
        # BƯỚC 3: KÍCH NỔ (Detonate)
        logger.info("[Sandbox] 3/4: KÍCH NỔ và bắt Syscalls (Áp dụng Timeout 120s)...")
        guest_log_path = f"/tmp/{log_filename}"
        guest_pcap_path = f"/tmp/{pcap_filename}"
        
        # Lệnh chạy bên trong container
        detonate_cmd = (
            f"tcpdump -i any -w {guest_pcap_path} & "
            f"TCP_PID=$! ; "
            f"timeout 120s strace -f -s 256 -e trace=file,network,process "
            f"-o {guest_log_path} pip install {guest_package_path} --no-index --find-links /tmp/ ; "
            f"kill -2 $TCP_PID ; sleep 2 ; "
            f"chmod 777 {guest_log_path} || true ; "
            f"chmod 777 {guest_pcap_path} || true"
        )
        
        try:
            subprocess.run([
                "docker", "exec", container_name, "/bin/bash", "-c", detonate_cmd
            ], capture_output=True, timeout=140)
        except subprocess.TimeoutExpired:
            logger.warning("[Sandbox] Lệnh kích nổ đã chạy hết 140s giới hạn cứng!")
            
        # BƯỚC 4: Hút bằng chứng
        logger.info("[Sandbox] 4/4: Hút bằng chứng (.log, .pcap) trả về máy Host...")
        subprocess.run([
            "docker", "cp", f"{container_name}:{guest_log_path}", host_log_path
        ], capture_output=True)
        
        subprocess.run([
            "docker", "cp", f"{container_name}:{guest_pcap_path}", host_pcap_path
        ], capture_output=True)
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Lệnh Docker thất bại. Lỗi: {e.stderr if isinstance(e.stderr, str) else e}")
    except Exception as e:
        logger.error(f"Lỗi nghiêm trọng kiểm soát Docker: {e}")
    finally:
        # BƯỚC 5: Xóa container (Clearing State)
        logger.info("[Sandbox] Xóa sạch tàn dư (Remove Container)...")
        subprocess.run(["docker", "rm", "-f", container_name], capture_output=True)
        
    # Xác minh log
    if os.path.exists(host_log_path) and os.path.getsize(host_log_path) > 0:
        logger.info(f"[Hoàn tất] File Syscalls ghi lại thành công tại: {host_log_path}")
        return host_log_path
    else:
        logger.error("[Docker] Container không xuất ra được file log hoặc file rỗng! Sandbox có thể đã bị vô hiệu hóa.")
        return ""

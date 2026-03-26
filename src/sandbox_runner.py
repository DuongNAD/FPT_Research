import os
import time
import subprocess
import logging

logger = logging.getLogger(__name__)

# [CẤU HÌNH VMWARE TỪ NGƯỜI DÙNG]
# Đường dẫn vmrun.exe (Công cụ tự động hóa do VMware Workstation cung cấp trên Windows)
VMRUN_PATH = r"C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe"

# Cấu hình Máy ảo cụ thể
VMX_PATH = r"E:\SandBox\ShieldAI_Sandbox.vmx"
VM_USER = "sandbox"   # Tài khoản mà user đã tạo (công nhận từ lỗi sudo ở trên)
VM_PASS = "123456"   # Mật khẩu setup
SNAPSHOT_NAME = "CleanState" # Snapshot mốc

def run_vmrun_cmd(cmd_list):
    """
    Hàm lõi gọi lệnh API VMWare.
    Tự động nhúng thông tin xác thực để gọi vào Guest OS.
    """
    base_cmd = [
        VMRUN_PATH,
        "-T", "ws", # ws = Workstation
        "-gu", VM_USER,
        "-gp", VM_PASS
    ]
    full_cmd = base_cmd + cmd_list
    
    logger.debug(f"[VMWare] Executing: {' '.join(full_cmd)}")
    result = subprocess.run(full_cmd, capture_output=True, text=True)
    if result.returncode != 0:
        logger.error(f"[VMWare Error] {result.stderr}")
        raise Exception(f"Lỗi VMWare: {result.stderr}")
    return result.stdout.strip()

def run_in_sandbox(filename: str) -> str:
    """
    Luồng tự động hóa VMWare thay thế Docker:
    1. Revert CleanState
    2. Start VM (nogui)
    3. Push .whl
    4. Detonate (strace + tcpdump)
    5. Pull logs
    """
    quarantine_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'quarantine'))
    os.makedirs(quarantine_dir, exist_ok=True)
    
    host_package_path = os.path.join(quarantine_dir, filename)
    
    # Check nếu máy chủ không cài VMWare đúng chuẩn
    if not os.path.exists(VMRUN_PATH):
        logger.error(f"Không tìm thấy công cụ VMWare vmrun.exe tại: {VMRUN_PATH}. Vui lòng cài đặt VMware Workstation.")
        return ""
    
    log_filename = f"syscalls_{int(time.time())}.log"
    host_log_path = os.path.join(quarantine_dir, log_filename)
    
    pcap_filename = f"capture_{int(time.time())}.pcap"
    host_pcap_path = os.path.join(quarantine_dir, pcap_filename)
    
    logger.info(f"Đang kích hoạt VMWare Sandbox cho siêu gói tin: {filename}")
    
    try:
        # BƯỚC 1: Khôi phục máy ảo về trạng thái nguyên sơ (Loại bỏ mọi mã độc từ trước)
        logger.info("[Sandbox] 1/5: Quay ngược thời gian về Snapshot sạch (CleanState)...")
        subprocess.run([VMRUN_PATH, "-T", "ws", "revertToSnapshot", VMX_PATH, SNAPSHOT_NAME], check=True)
        
        # BƯỚC 2: Bật máy ảo chạy ẩn dưới nền (nogui) để không văng cửa sổ lên màn hình người dùng
        logger.info("[Sandbox] 2/5: Đang khởi động máy ảo VMWare ở chế độ ẩn (nogui)...")
        subprocess.run([VMRUN_PATH, "-T", "ws", "start", VMX_PATH, "nogui"], check=True)
        
        # Đợi hệ điều hành Boot ảo xong và open-vm-tools khởi chạy (Rất quan trọng nếu Snapshot lúc tắt máy)
        logger.info("[Sandbox] Đang chờ Ubuntu boot xong rễ và nạp VMware Tools...")
        tools_ready = False
        for _ in range(30): # Chờ tối đa 60 giây
            state_check = subprocess.run([VMRUN_PATH, "-T", "ws", "checkToolsState", VMX_PATH], capture_output=True, text=True)
            if "running" in state_check.stdout.lower():
                tools_ready = True
                break
            time.sleep(2)
            
        if not tools_ready:
            logger.warning("[VMWare] Không nhận diện được VMware Tools (có thể do lỗi hiển thị API). Tiếp tục ép luồng thực thi...")
            
        logger.info("[Sandbox] Kết nối hệ điều hành ảo thành công!")
        
        # BƯỚC 3: "Bơm" mã độc từ Windows Host vào hệ thống Linux Guest
        logger.info(f"[Sandbox] 3/5: Bơm xuyên vách mã độc {filename} vào buồng giam VMWare...")
        guest_package_path = f"/tmp/{filename}"
        run_vmrun_cmd(["copyFileFromHostToGuest", VMX_PATH, host_package_path, guest_package_path])
        
        # BƯỚC 4: KÍCH NỔ (Detonate)
        logger.info("[Sandbox] 4/5: KÍCH NỔ và bắt Syscalls (Áp dụng Timeout 120s)...")
        guest_log_path = f"/tmp/{log_filename}"
        guest_pcap_path = f"/tmp/{pcap_filename}"
        
        # Script phức tạp: Chạy tcpdump nền -> Chạy strace -> Kill tcpdump -> Cấp quyền cho file
        detonate_cmd = (
            f"sudo tcpdump -i any -w {guest_pcap_path} & "
            f"TCP_PID=$! ; "
            f"timeout 120s sudo strace -f -s 256 -e trace=file,network,process "
            f"-o {guest_log_path} pip3 install {guest_package_path} --no-index --find-links /tmp/ ; "
            f"sudo kill -2 $TCP_PID ; sleep 2 ; "
            f"sudo chmod 777 {guest_log_path} || true ; "
            f"sudo chmod 777 {guest_pcap_path} || true"
        )
        
        # Lệnh runProgramInGuest có thể trả về lỗi nếu mã độc crash hệ thống pip, ta set capture_output để ẩn lỗi
        try:
            subprocess.run([
                VMRUN_PATH, "-T", "ws", "-gu", VM_USER, "-gp", VM_PASS,
                "runProgramInGuest", VMX_PATH, "/bin/bash", "-c", detonate_cmd
            ], capture_output=True, timeout=140)
        except subprocess.TimeoutExpired:
            logger.warning("[Sandbox] Lệnh kích nổ đã chạy hết 140s giới hạn cứng!")
        
        # BƯỚC 5: Trích xuất Thành Quả
        logger.info("[Sandbox] 5/5: Hút bằng chứng (.log, .pcap) trả về Sở Chỉ Huy Windows...")
        subprocess.run([
            VMRUN_PATH, "-T", "ws", "-gu", VM_USER, "-gp", VM_PASS,
            "copyFileFromGuestToHost", VMX_PATH, guest_log_path, host_log_path
        ], capture_output=True)
        
        subprocess.run([
            VMRUN_PATH, "-T", "ws", "-gu", VM_USER, "-gp", VM_PASS,
            "copyFileFromGuestToHost", VMX_PATH, guest_pcap_path, host_pcap_path
        ], capture_output=True)
        
        # Kiểm tra xem file log đã rút được thành công về máy Host chưa
        if os.path.exists(host_log_path):
            logger.info(f"[Hoàn tất] File Syscalls ghi lại thành công tại: {host_log_path}")
            return host_log_path
        else:
            logger.error("[VMWare] Máy ảo không xuất ra được file log! Sandbox có thể đã bị vô hiệu hóa.")
            return ""

    except subprocess.CalledProcessError as e:
        logger.error(f"Lệnh vmrun thất bại. Lỗi CLI: {e}")
        return ""
    except Exception as e:
        logger.error(f"Lỗi nghiêm trọng kiểm soát VMWare: {e}")
        return ""

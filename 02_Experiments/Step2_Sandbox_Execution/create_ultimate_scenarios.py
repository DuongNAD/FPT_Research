import os
import tarfile
import shutil
from pathlib import Path

# Thư mục chứa các tệp mã nguồn kịch bản (*.py)
TEMPLATES_DIR = Path("02_Experiments/Step2_Sandbox_Execution/scenario_templates")
TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)

# Thư mục đích chứa các gói siêu nén cài đặt (tar.gz)
out_dir = Path("data/quarantine/task_ultimate")
out_dir.mkdir(parents=True, exist_ok=True)

# Lọc tất cả các file .py trong thư mục Templates
script_files = [f for f in os.listdir(TEMPLATES_DIR) if f.endswith(".py")]

if not script_files:
    print(f"[!] Không tìm thấy kịch bản nào trong {TEMPLATES_DIR}. Vui lòng thêm các file .py vào đó.")
else:
    for script_file in script_files:
        pkg_name = script_file.replace(".py", "")
        script_path = TEMPLATES_DIR / script_file
        
        # Đọc nội dung file .py
        with open(script_path, "r", encoding="utf-8") as rf:
            setup_content = rf.read()
            
        # Tạo thư mục tạm để đóng gói
        tmp_pkg = out_dir / pkg_name
        tmp_pkg.mkdir(exist_ok=True)
        
        # Tạo file setup.py thật cho gói pip
        setup_file = tmp_pkg / "setup.py"
        with open(setup_file, "w", encoding="utf-8") as f:
            f.write(setup_content)
        
        # Nén thành tar.gz
        tar_path = out_dir / f"{pkg_name}.tar.gz"
        with tarfile.open(tar_path, "w:gz") as tar:
            tar.add(setup_file, arcname="setup.py")
        
        # Dọn dẹp thư mục tạm
        shutil.rmtree(tmp_pkg)
        print(f"[*] Đã đóng gói thành công kịch bản: {pkg_name}.tar.gz")

    print(f"\n🔥 Hệ thống đã tự động lấy toàn bộ Source Code trong [scenario_templates] và đóng gói! Output in: {out_dir}")

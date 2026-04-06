import pytest
import os
import shutil
from pathlib import Path

@pytest.fixture(autouse=True)
def teardown_syscall_log():
    """
    Fixture này sẽ tự động chạy trước và sau MỖI test case.
    Nó hỗ trợ việc xoá file `src/syscalls.log` để đảm bảo test sau không đọc nhầm data cũ.
    """
    # Không làm gì trước test
    yield
    
    # Teardown: Thực thi DỌN DẸP sau test
    base_dir = Path(__file__).parent.parent
    log_file = base_dir / "src" / "syscalls.log"
    
    if log_file.exists():
        try:
            os.remove(log_file)
            print(f"🧹 Đã dọn dẹp file: {log_file}")
        except Exception as e:
            print(f"⚠️ Trục trặc khi xóa file {log_file}: {e}")

@pytest.fixture(scope="session")
def project_root():
    """
    Trả về đường dẫn tuyệt đối thư mục gốc `e:/Project/FPT_Research`
    """
    return Path(__file__).parent.parent

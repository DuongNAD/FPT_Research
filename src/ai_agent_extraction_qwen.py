import os
import json
import logging
from pathlib import Path
from openai import OpenAI

# Thay vì dùng Google Gemini, ta dùng OpenAI SDK để trỏ tới Local Model Server (vLLM / LM Studio / Ollama)
# Ví dụ: vLLM server đang chạy Qwen2.5-14B ở port 8000
LOCAL_API_BASE = "http://localhost:8000/v1"
LOCAL_API_KEY = "EMPTY"  # Local server thường không cần key
MODEL_NAME = "Qwen/Qwen2.5-14B-Instruct"  # Khai báo khớp với tên model đang serve

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

DATA_DIR = Path(__file__).parent.parent / "data"
SYSCALLS_DIR = DATA_DIR / 'syscalls'
INDICATOR_DIR = DATA_DIR / 'indicators'
INDICATOR_DIR.mkdir(parents=True, exist_ok=True)

PROMPT_TEMPLATE = """
Act as an expert Cyber Threat Intelligence Analyst.
I will provide you with a JSON-lines log of system calls generated dynamically by a Python package.

Your task is to analyze these syscall logs and extract any malicious intent.
If no malicious intent is found, return an empty JSON array: []

If malicious behaviors are found, map them to MITRE ATT&CK techniques, and return the output EXACTLY as this JSON array format (no markdown code blocks, just raw JSON).

Format:
[
  {
    "indicator": {
      "type": "Syscall",
      "api": "openat or connect or execve",
      "source_file": "syscalls.log",
      "package_name": "INSERT_PACKAGE_NAME_HERE"
    },
    "behavior": {
      "name": "CamelCaseBehaviorName",
      "description": "Short description of the behavior observed"
    },
    "technique": {
      "id": "TXXXX",
      "name": "Technique Name"
    },
    "tactic": {
      "id": "TAXXXX",
      "name": "Tactic Name"
    }
  }
]

Here are the syscall logs for the package `{package_name}`:
{log_content}
"""

def analyze_logs_with_local_llm(package_name, log_content):
    """Gọi Local Model (Qwen2.5-14B) để thực hiện Threat Extraction"""
    client = OpenAI(base_url=LOCAL_API_BASE, api_key=LOCAL_API_KEY)
    
    prompt = PROMPT_TEMPLATE.replace("{package_name}", package_name).replace("{log_content}", log_content)
    
    logging.info(f"Sending prompt to Local AI (Qwen2.5) for {package_name}...")
    try:
        response = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {"role": "system", "content": "You are a Cyber Security Expert. Output strictly valid JSON arrays as requested."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.1 # Để kết quả ổn định và bám sát format JSON nhất
        )
        
        text = response.choices[0].message.content.strip()
        logging.info(f"Raw Qwen2.5 response for {package_name}:\n{text}")
        
        if text.startswith("```json"):
            text = text[7:]
        if text.endswith("```"):
            text = text[:-3]
            
        data = json.loads(text.strip())
        return data
    except Exception as e:
        logging.error(f"Failed to process Local AI response: {e}")
        return []

def main():
    logging.info("Starting Phase 3: Local AI Agent Extraction & Mapping (Qwen2.5)")
    if not SYSCALLS_DIR.exists():
        logging.error("No syscall logs found. Run sandbox_runner.py first.")
        return
        
    all_mapped_nodes = []
    
    for log_file in SYSCALLS_DIR.glob("*_syscalls.log"):
        package_name = log_file.name.replace("_syscalls.log", "")
        with open(log_file, "r") as f:
            log_content = f.read()
            
        logging.info(f"Analyzing {package_name} logs with Local AI Agent...")
        nodes = analyze_logs_with_local_llm(package_name, log_content)
        all_mapped_nodes.extend(nodes)
        
    output_file = INDICATOR_DIR / "mapped_threat_nodes.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(all_mapped_nodes, f, indent=4)
        
    logging.info(f"Successfully mapped {len(all_mapped_nodes)} threat nodes via Local AI Agent.")
    logging.info(f"Results saved to {output_file}")

if __name__ == "__main__":
    main()

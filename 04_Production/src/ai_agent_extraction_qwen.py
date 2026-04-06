import os
import json
import logging
from pathlib import Path
from pydantic import BaseModel, Field
from openai import OpenAI

# vLLM server đang chạy Qwen2.5-7B ở port 8000
LOCAL_API_BASE = "http://localhost:8000/v1"
LOCAL_API_KEY = "EMPTY"  
MODEL_NAME = "bartowski/Qwen2.5-7B-Instruct-GGUF"  

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class IndicatorContext(BaseModel):
    type: str = Field(description="The type of the indicator, usually 'Syscall' or 'Artifact'")
    api: str = Field(description="The API call or the file path dropping action")
    source_file: str = Field(description="Usually 'syscalls.log' or 'docker_diff'")
    package_name: str = Field(description="The name of the package")

class BehaviorDescription(BaseModel):
    name: str = Field(description="CamelCase description of the behavior (e.g., HiddenFileDrop, ReverseShell)")
    description: str = Field(description="Detailed explanation of what the intent behind this behavior is")

class MitreTechnique(BaseModel):
    id: str = Field(description="The MITRE ATT&CK Technique ID (e.g., T1059)")
    name: str = Field(description="The MITRE Technique Name")

class MitreTactic(BaseModel):
    id: str = Field(description="The MITRE ATT&CK Tactic ID (e.g., TA0002)")
    name: str = Field(description="The MITRE Tactic Name")

class ThreatNode(BaseModel):
    indicator: IndicatorContext
    behavior: BehaviorDescription
    technique: MitreTechnique
    tactic: MitreTactic

class ThreatExtractionResponse(BaseModel):
    threats: list[ThreatNode]

PROMPT_TEMPLATE = """
Bạn là Công tố viên phân tích mã độc. Khi bạn tìm thấy các lệnh gọi hệ thống nguy hiểm như openat, execve, connect, bạn TUYỆT ĐỐI KHÔNG ĐƯỢC báo cáo chung chung. BẮT BUỘC bạn phải trích xuất chính xác:
- TÊN FILE đầy đủ / Đường dẫn tuyệt đối (Ví dụ: /tmp/miner.sh, /etc/shadow, /tmp/payload.elf).
- Tham số dòng lệnh thực thi (Ví dụ: bash -c ..., chmod +x).
- Địa chỉ IP/Domain.
Nếu bạn chỉ báo cáo 'mở file ở /tmp' mà không nêu tên file cụ thể, Thẩm phán sẽ bác bỏ vụ án của bạn. Việc tạo tệp thực thi (.sh, .elf, .exe) tại thư mục tạm là BẰNG CHỨNG THÉP của hành vi Dropper/Malicious.

Look at the syscall logs (and docker artifacts at the top) of package '{package_name}' and extract the threats.
Logs:
{log_content}

CRITICAL INSTRUCTION: You must return ONLY a raw JSON object matching the exact schema below. DO NOT use markdown ```json. Do not include any conversational text.
{
  "threats": [
    {
      "indicator": {
        "type": "Syscall or Artifact",
        "api": "The API call or the file path dropping action",
        "source_file": "syscalls.log or docker_diff",
        "package_name": "package_name"
      },
      "behavior": {
        "name": "CamelCase description (e.g., HiddenFileDrop)",
        "description": "Explanation of malicious intent"
      },
      "technique": {
        "id": "T1059",
        "name": "MITRE Technique Name"
      },
      "tactic": {
        "id": "TA0002",
        "name": "MITRE Tactic Name"
      }
    }
  ]
}
"""

def extract_threats_qwen(package_name, log_content):
    """Gọi Local Model (Qwen2.5-14B) để thực hiện Threat Extraction Prosecutor."""
    client = OpenAI(base_url=LOCAL_API_BASE, api_key=LOCAL_API_KEY)
    prompt = PROMPT_TEMPLATE.replace("{package_name}", package_name).replace("{log_content}", log_content)
    
    logging.info(f"Sending prompt to Prosecutor (Qwen2.5) for {package_name}...")
    try:
        response = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {"role": "system", "content": "You are a Cyber Security Prosecutor. Extract malicious threats into strict JSON."},
                {"role": "user", "content": prompt}
            ],
            response_format={"type": "json_object"},
            temperature=0.1
        )
        
        raw_text = response.choices[0].message.content
        print(f"\n--- [DEBUG] RAW OUTPUT TỪ QWEN (Package: {package_name}) ---")
        print(raw_text)
        print("--------------------------------------------------------------\n")
        
        return json.loads(raw_text)
        
    except Exception as e:
        print(f"\n[CRASH LOG] 💥 LỖI QWEN (Crash): {e}\n")
        logging.error(f"Failed to process Local AI response: {e}")
        return {"threats": []}

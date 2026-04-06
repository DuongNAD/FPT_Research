import os
import json
import logging
from pathlib import Path
from pydantic import BaseModel, Field
from openai import OpenAI

# vLLM server đang chạy Gemma-2-9b-it ở port 8001
LOCAL_API_BASE = "http://localhost:8001/v1"
LOCAL_API_KEY = "EMPTY"  
MODEL_NAME = "bartowski/gemma-2-9b-it-GGUF"  

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class DefenseArgument(BaseModel):
    is_safe: bool = Field(description="True if the defender successfully argues it is safe. False if the defender concedes to the prosecutor.")
    reasoning: str = Field(description="The detailed defense logic, introducing reasonable doubt or conceding due to overwhelming malicious evidence.")
    benign_alternatives: list[str] = Field(description="List of benign reasons these syscalls might happen (e.g., 'Normal ping', 'Checking system info'). Empty if conceding.")

PROMPT_TEMPLATE = """
Act as a Defense Attorney and Blue Team Analyst. Read the Prosecutor's Case below regarding package '{package_name}':
PROSECUTOR'S CASE: {prosecutor_case}

Now, look at the logs:
{log_content}

Your goal is to find False Positives. Argue why these exact syscalls or artifacts might be perfectly benign Python operations.
HOWEVER: If the evidence is overwhelmingly malicious (e.g., fetching payloads over network and dropping them in /etc/ or /root/), and there is NO legitimate use-case, YOU MUST CONCEDE and agree with the Prosecutor. Do not hallucinate excuses for obvious malware.

CRITICAL INSTRUCTION: You must return ONLY a raw JSON object matching the requested schema. DO NOT USE MARKDOWN ```json. DO NOT INCLUDE ANY CONVERSATIONAL TEXT.
"""

def extract_defense_gemma(package_name, log_content, prosecutor_case):
    """Gọi Local Model (Gemma 2 9b) để thực hiện Threat Extraction Defender."""
    client = OpenAI(base_url=LOCAL_API_BASE, api_key=LOCAL_API_KEY)
    
    prompt = PROMPT_TEMPLATE.replace("{package_name}", package_name).replace("{log_content}", log_content).replace("{prosecutor_case}", json.dumps(prosecutor_case))
    
    logging.info(f"Sending prompt to Defender (Gemma 2) for {package_name}...")
    try:
        response = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {"role": "system", "content": "You are a Cyber Security Defender. Evaluate the evidence strictly. Concede if the malware is obvious. Output strict JSON Schema."},
                {"role": "user", "content": prompt}
            ],
            response_format={"type": "json_object"},
            temperature=0.1
        )
        
        raw_text = response.choices[0].message.content
        return json.loads(raw_text)
        
    except Exception as e:
        print(f"\n[CRASH LOG] 💥 LỖI GEMMA (Crash): {e}\n")
        logging.error(f"Failed to process Local AI response: {e}")
        return {"is_safe": False, "reasoning": f"Failed to generate defense: {e}", "benign_alternatives": []}

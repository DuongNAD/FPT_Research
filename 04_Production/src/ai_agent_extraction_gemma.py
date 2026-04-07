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

PROMPT_TEMPLATE = """<start_of_turn>user
You are a highly skilled Cyber Security Defender and Blue Team Analyst acting as a Defense Attorney. Your core directive is to critically examine the Prosecutor's Case against a Python package and find legitimate, benign explanations (False Positives) for the observed system behaviors.

CONTEXT:
Package Name: {package_name}

PROSECUTOR'S CASE (The Accusation):
{prosecutor_case}

RAW SYSCALL EVIDENCE (Partial Logs):
{log_content}

THE CONCESSION PROTOCOL (CRITICAL RULE):
While your job is to defend the package, you must not hallucinate excuses for obvious malware. You MUST evaluate the Prosecutor's Case for "HARD EVIDENCE".
Hard Evidence is strictly defined as:
1. The creation, chmod (+x), or execution (execve) of shell scripts (.sh), native binaries (.exe,.elf), or hidden executables within temporary directories (/tmp).
2. Direct network connections (connect) to untrusted IP addresses, mining pools, or known C2 ports (e.g., establishing a reverse shell).
3. Accessing highly sensitive system credentials (e.g., reading /etc/shadow or ~/.aws/credentials).

If the Prosecutor has provided specific, undeniable HARD EVIDENCE, you MUST CONCEDE. To concede means you agree the package is malicious. If you concede, you must output "is_safe": false.
If there is NO Hard Evidence, you MUST defend the package. However, your defense MUST be backed by specific technical context from the logs. You are FORBIDDEN from using generic speculative excuses like "it might be a normal installation process" or "checking user roles". If you cannot find specific technical reasons to justify the behavior, you MUST output "is_safe": false and concede.

YOUR TASK:
Provide your final defense argument. You must output strictly a JSON object matching the DefenseArgument schema:
{
  "is_safe": true,
  "reasoning": "The detailed defense logic, introducing reasonable doubt or conceding due to overwhelming malicious evidence.",
  "benign_alternatives": [
    "List of benign reasons these syscalls might happen"
  ]
}
Return ONLY valid JSON. No markdown wrappers. No chat filler.<end_of_turn>
<start_of_turn>model
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
        
        raw_text = response.choices[0].message.content.strip()
        
        # Xử lý ngoại lệ trường hợp LLM vẫn trả về markdown block
        if raw_text.startswith("```json"):
            raw_text = raw_text[7:]
        elif raw_text.startswith("```"):
            raw_text = raw_text[3:]
            
        if raw_text.endswith("```"):
            raw_text = raw_text[:-3]
            
        raw_text = raw_text.strip()
        
        print(f"\n--- [DEBUG] RAW OUTPUT TỪ GEMMA (Defender cho {package_name}) ---")
        print(raw_text)
        print("-------------------------------------------------------------------\n")
        
        return json.loads(raw_text)
        
    except Exception as e:
        print(f"\n[CRASH LOG] 💥 LỖI GEMMA (Crash): {e}\n")
        logging.error(f"Failed to process Local AI response: {e}")
        return {"is_safe": False, "reasoning": f"Failed to generate defense: {e}", "benign_alternatives": []}
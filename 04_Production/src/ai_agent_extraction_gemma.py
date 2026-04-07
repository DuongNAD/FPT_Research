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
You are an elite Cyber Security Defender acting as a Defense Attorney. Your core directive is to critically examine the Prosecutor's Case against a Python package and find legitimate, technical benign justifications (False Positives) for the observed behaviors.

CONTEXT:
Package Name: {package_name}

PROSECUTOR'S CASE (The Accusation):
{prosecutor_case}

RAW SYSCALL EVIDENCE (Partial Logs):
{log_content}

DEFENSE STRATEGY (CONTRASTIVE RETRIEVAL):
Analyze the behaviors through the lens of standard Software Development Lifecycle operations:
- mprotect (RWX): Argue that Just-In-Time (JIT) compilers (like PyPy, V8) or legitimate code obfuscators require dynamic memory allocation and execution rights.
- /tmp usage: Argue that package managers like 'pip' routinely use '/tmp' as a staging area to build packages from source or extract resources to avoid polluting the main workspace.
- .bashrc modification: Argue that installing development environments (e.g., Anaconda, NVM) legitimately appends PATH variables or aliases to improve User Experience.
- EROFS / Read-Only Errors: Vigorously argue that any 'EROFS' or access denied errors in standard Python paths are purely artifacts of the containerized Read-Only Sandbox environment, NOT malicious tampering.

THE CONCESSION PROTOCOL (CRITICAL RULE):
You must evaluate the evidence for a complete "Kill Chain".
If the Prosecutor presents undeniable evidence where behaviors connect maliciously (e.g., modifying .bashrc IMMEDIATELY after downloading an unknown binary to /tmp from an untrusted IP), you MUST CONCEDE.
If you concede, output "is_safe": false. 
If defending, provide specific technical context from the logs. Do NOT hallucinate abstract excuses.

YOUR TASK:
Provide your final defense argument. Output strictly a JSON object matching this schema:
{
  "is_safe": true,
  "reasoning": "Detailed technical defense logic introducing reasonable doubt, OR concession rationale if Kill Chain is present.",
  "benign_alternatives": [
    "List of specific benign reasons these syscalls occurred based on software development practices"
  ]
}
Return ONLY valid JSON. No markdown wrappers.<end_of_turn>
<start_of_turn>model
"""

def extract_defense_gemma(package_name, log_content, prosecutor_case):
    """Gọi Local Model (Gemma 2 9b) để thực hiện Threat Extraction Defender."""
    prompt = PROMPT_TEMPLATE.replace("{package_name}", package_name).replace("{log_content}", log_content).replace("{prosecutor_case}", json.dumps(prosecutor_case, ensure_ascii=False))
    
    logging.info(f"Sending prompt to Defender (Gemma 2) for {package_name}...")
    try:
        with OpenAI(base_url=LOCAL_API_BASE, api_key=LOCAL_API_KEY) as client:
            response = client.chat.completions.create(
                model=MODEL_NAME,
                messages=[
                    {"role": "system", "content": "You are a Cyber Security Defender. Evaluate the evidence strictly. Concede if the malware is obvious. Output strict JSON Schema."},
                    {"role": "user", "content": prompt}
                ],
                response_format={"type": "json_object"},
                temperature=0.1,
                max_tokens=1500,
                presence_penalty=0.5,
                frequency_penalty=0.5
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
        
        try:
            return json.loads(raw_text, strict=False)
        except json.JSONDecodeError as e:
            logging.warning(f"Lỗi phân tích JSON từ Gemma chuẩn: {e}. Thử dọn dẹp chuỗi...")
            import re
            fixed_text = re.sub(r'(?<!\\)\\(?!["\\/bfnrt])', r'\\\\', raw_text)
            try:
                return json.loads(fixed_text, strict=False)
            except:
                raise e
        
    except Exception as e:
        print(f"\n[CRASH LOG] 💥 LỖI GEMMA (Crash): {e}\n")
        logging.error(f"Failed to process Local AI response: {e}")
        return {"is_safe": False, "reasoning": f"Failed to generate defense: {e}", "benign_alternatives": []}
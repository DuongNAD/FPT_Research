import os
import json
import logging
import requests
from pydantic import BaseModel, Field

import ai_agent_extraction_qwen
import ai_agent_extraction_gemma

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class FinalVerdict(BaseModel):
    verdict: str = Field(description="Strictly 'MALICIOUS' or 'BENIGN'")
    confidence_score: int = Field(description="A number from 0 to 100 capturing the certainty of the verdict")
    reason: str = Field(description="Tóm tắt lý do buộc tội hoặc trắng án. BẮT BUỘC sử dụng 100% TIẾNG VIỆT. Lưu ý: Các thuật ngữ kỹ thuật (như mprotect, openat, syscall, reverse shell, payload...) NÊN được giữ nguyên tiếng Anh để đảm bảo tính chuyên môn.")
    mitre_techniques: list[str] = Field(description="List of MITRE Techniques identified. MUST be strictly formatted as: 'TAxxxx (Tactic Name) - Txxxx (Technique Name)'. Return [] if BENIGN.")

def call_local_judge(judge_prompt, port=8002):
    """
    Calls the local Llama-3 Judge model on the specified port.
    """
    url = f"http://localhost:{port}/v1/chat/completions"
    headers = {"Content-Type": "application/json"}
    
    # We enforce JSON mode parsing if supported by llama_cpp
    payload = {
        "messages": [
            {"role": "system", "content": "You are a Cyber Security Judge matching output to JSON."},
            {"role": "user", "content": judge_prompt}
        ],
        "temperature": 0.0,
        "max_tokens": 1500,
        "response_format": {
            "type": "json_object",
            "schema": FinalVerdict.model_json_schema()
        }
    }
    
    try:
        response = requests.post(url, json=payload, headers=headers, timeout=120)
        response.raise_for_status()
        result = response.json()
        content = result['choices'][0]['message']['content']
        # Sanitize unescaped backslashes to prevent JSON parse errors
        content = content.replace('\\', '\\\\')
        return json.loads(content, strict=False)
    except Exception as e:
        logging.error(f"Failed to process Local Judge AI response: {e}")
        raise e

def smart_filter_log(log_content, max_chars=13000):
    lines = log_content.split('\n')
    priority_keywords = ['mprotect', 'connect(', 'execve', 'id_rsa', 'meminfo', '.ssh', 'shadow', 'dockerenv', 'socket', 'clone(', 'O_WRONLY', 'O_CREAT', 'chmod']
    ignore_keywords = ['/usr/local/lib/python', '/tmp/pip-install', '/tmp/pip-req-build', 'site-packages', '__pycache__', 'CacheControl']
    
    filtered_lines = []
    artifact_section = []
    in_artifact = False
    
    for line in lines:
        if line.startswith("=== DETECTED FILE SYSTEM ARTIFACTS ==="):
            in_artifact = True
        
        if in_artifact:
            artifact_section.append(line)
            continue
            
        # Priority checks
        is_priority = any(pri in line for pri in priority_keywords)
        is_ignored_path = any(ign in line for ign in ignore_keywords)
        
        if is_ignored_path and not is_priority:
            continue
            
        filtered_lines.append(line)
        
    filtered_content = '\n'.join(filtered_lines)
    if len(filtered_content) > max_chars:
        filtered_content = "...[SMART FILTERED]...\n" + filtered_content[-max_chars:]
        
    final_output = filtered_content
    if artifact_section:
        final_output += "\n" + "\n".join(artifact_section)
        
    return final_output

def run_prosecutor_stage(package_name, log_content):
    log_content_filtered = smart_filter_log(log_content, max_chars=13000)
    prosecutor_verdict = ai_agent_extraction_qwen.extract_threats_qwen(package_name, log_content_filtered)
    return prosecutor_verdict

def run_defender_stage(package_name, log_content, prosecutor_verdict):
    gemma_log_content = smart_filter_log(log_content, max_chars=4000)
    defense_verdict = ai_agent_extraction_gemma.extract_defense_gemma(package_name, gemma_log_content, prosecutor_verdict)
    return defense_verdict

def run_judge_stage(package_name, prosecutor_verdict, defense_verdict):
    prosecutor_case = json.dumps(prosecutor_verdict, indent=2)
    defense_case = json.dumps(defense_verdict, indent=2)
    
    judge_prompt = f"""
    You are the Supreme Evidence-Based Cyber Security Judge overseeing a high-stakes debate between an AI Prosecutor (Qwen) and an AI Defense Attorney (Gemma) regarding a potentially malicious software package.
    Your sole function is to review the arguments from both sides alongside the raw system call evidence, and deliver a final, objective verdict (MALICIOUS or BENIGN). You must operate under three strict Procedural Laws.

    LAW 1: NO NAME BIAS
    You are strictly forbidden from convicting a package based solely on its name. Names containing terms like "typo", "malware", "fake", or "test" are NOT evidence of guilt. You judge actions, not labels.

    LAW 2: THE DEEP EVIDENCE DOCTRINE
    A "MALICIOUS" verdict is permitted if the Prosecutor provides undeniable, deep evidence backed by explicit system calls. You must see explicit Network Logs AND/OR Malicious File Artifacts. EXCEPTION FOR HEURISTICS: If the Prosecutor invokes specific Heuristics (like Fileless Memory Execution from 'mprotect', Sandbox Evasion from reading '/proc/meminfo', or Obfuscation) and supports it with specific syscall evidence, you MUST accept this as valid Deep Evidence and return a "MALICIOUS" verdict.

    LAW 3: PRESUMPTION OF INNOCENCE & INDEPENDENT VERIFICATION
    If the evidence presented by the Prosecutor is thin, superficial, or ambiguous, you must stand with the Defense.
    CRITICAL: Even if the Defense Attorney CONCEDES (gives up), you must independently verify the Prosecutor's evidence. If the Prosecutor's evidence lacks specific syscall backing, you must OVERRULE the concession and declare the package "BENIGN".

    LAW 4: ZERO-TOLERANCE RED FLAGS (HARD THRESHOLDS)
    Certain actions are absolutely indefensible in a zero-trust architecture. Any attempt to read sensitive files ('/etc/passwd', '/root/.ssh/id_rsa'), any use of 'mprotect' associated with Fileless Execution, or establishing network connections to untrusted IPs without metadata declaration MUST automatically be declared "MALICIOUS". Additionally, ANY behavior that interacts with files and triggers system errors like 'EROFS' (Read Only File System) indicates an attempt to modify immutable infrastructure and MUST be classified as malicious. You MUST REJECT any defense that claims these are "routine installation tasks", "checking user roles", or "configuring dependencies". Such excuses are invalid.

    DECISION SCORING MATRIX:
    - confidence_score (0-100):
      * 90-100: Smoking gun evidence (Hard file coordinates + malicious network IPs).
      * 70-89: Highly suspicious behavior without clear legitimate explanation.
      * 50-69: Ambiguous behavior, leaning towards benign compilation noise.
      * 0-49: Routine package installation behavior.

    Target Package Name: {package_name}

    PROSECUTOR'S CASE (Qwen Analysis):
    {prosecutor_case}

    DEFENSE'S CASE (Gemma Arguments):
    {defense_case}

    Analyze the arguments. Calculate the confidence_score based on the presence of hard evidence. Output your ruling in strict compliance with the required JSON schema format.
    IMPORTANT: The 'reason' field MUST be written entirely in formal Vietnamese, keeping technical terms in English. If the verdict is 'BENIGN', the 'mitre_techniques' list must be empty [].
    """
    
    logging.info(f"👩‍⚖️ Judge is making the final ruling for: {package_name}...")
    try:
        data = call_local_judge(judge_prompt)
        logging.info(f"⚖️ Verdict reached: {data['verdict']} - Confidence: {data.get('confidence_score', 0)}%")
        return data
    except Exception as e:
        logging.error(f"Failed to parse Judge's verdict JSON or API failed totally: {e}")
        return {"verdict": "ERROR", "confidence_score": 0, "reason": str(e), "mitre_techniques": []}

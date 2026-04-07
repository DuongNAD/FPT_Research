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
    
    messages = [
        {"role": "system", "content": "You are a Cyber Security Judge matching output to JSON."},
        {"role": "user", "content": judge_prompt}
    ]
    
    def fetch(msgs):
        payload = {
            "messages": msgs,
            "temperature": 0.1,
            "max_tokens": 2048,
            "presence_penalty": 0.5,
            "frequency_penalty": 0.5,
            "response_format": {
                "type": "json_object",
                "schema": FinalVerdict.model_json_schema()
            }
        }
        response = requests.post(url, json=payload, headers=headers, timeout=120)
        response.raise_for_status()
        return response.json()['choices'][0]['message']['content']
        
    try:
        content = fetch(messages)
    except Exception as e:
        logging.error(f"Failed to process Local Judge AI response: {e}")
        raise e
        
    try:
        content_clean = content.replace('\\', '\\\\')
        return json.loads(content_clean, strict=False)
    except json.JSONDecodeError:
        logging.warning("JSON Parsing Error detected (Truncation or Invalid Escape). Engaging Retry Fallback...")
        messages.append({"role": "assistant", "content": content})
        messages.append({"role": "user", "content": "Your previous output was invalid JSON or truncated. Please regenerate the JSON perfectly."})
        
        content2 = fetch(messages)
        content_clean2 = content2.replace('\\', '\\\\')
        return json.loads(content_clean2, strict=False)
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

def run_rebuttal_stage(package_name, log_content, defense_verdict):
    log_content_filtered = smart_filter_log(log_content, max_chars=4000)
    rebuttal_verdict = ai_agent_extraction_qwen.extract_rebuttal_qwen(package_name, log_content_filtered, defense_verdict)
    return rebuttal_verdict

def run_judge_stage(package_name, prosecutor_verdict, defense_verdict, rebuttal_verdict):
    prosecutor_case = json.dumps(prosecutor_verdict, ensure_ascii=False, indent=2)
    defense_case = json.dumps(defense_verdict, ensure_ascii=False, indent=2)
    rebuttal_case = json.dumps(rebuttal_verdict, ensure_ascii=False, indent=2)
    
    judge_prompt = f"""
    You are the Supreme AI Judge in a Cybersecurity Court.
    You will evaluate the Prosecutor's Indictment and the Defender's Rebuttal for the package '{package_name}'.

    EVALUATION RUBRIC & RED FLAG OVERRIDE:
    1. HARD EVIDENCE: If the Prosecutor provides concrete evidence of credential theft (e.g., reading '/root/.ssh/id_rsa'), unauthorized network exfiltration, or explicit backdoor creation, you MUST rule 'MALICIOUS'.
    2. SANDBOX ARTIFACT RULE (CRITICAL): Errors like 'EROFS' (Read-Only File System) or 'EACCES' when a package attempts to write to standard library paths (e.g., '/usr/local/lib/python...', '__pycache__', '/tmp') during installation are NORMAL side-effects of our read-only Docker environment. They MUST NOT be considered malicious.
    3. AMBIGUOUS BEHAVIORS: For 'mprotect' (RWX) or '/tmp' usage, if the Defender successfully argues it is related to standard pip build processes, JIT compilation, or standard metadata extraction, you MUST rule 'BENIGN' unless the Prosecutor proves a malicious Kill Chain.

    LANGUAGE CONSTRAINT:
    You MUST output your 'reason' strictly in formal Vietnamese. Explain clearly why one side's argument outweighed the other based on the evidence provided in the logs.

    Output strictly a JSON object:
    {{
        "thought_process": "Bắt buộc: Hãy viết ra quá trình suy luận tại đây bằng tiếng Việt. 1. Có bằng chứng thép không? 2. Có bị lỗi EROFS Sandbox không? 3. Lời bào chữa có hợp lý không?",
        "verdict": "Strictly 'MALICIOUS' or 'BENIGN'",
        "confidence_score": 0,
        "reason": "Tóm tắt phán quyết cuối cùng dựa trên thought_process (Tối đa 50 từ)",
        "mitre_techniques": ["List of MITRE Techniques identified"]
    }}

    Target Package Name: {package_name}

    PROSECUTOR'S CASE:
    {prosecutor_case}

    DEFENSE'S CASE:
    {defense_case}

    PROSECUTOR'S REBUTTAL:
    {rebuttal_case}
    """
    
    logging.info(f"👩‍⚖️ Judge is making the final ruling for: {package_name}...")
    try:
        data = call_local_judge(judge_prompt)
        if data.get("verdict", "").upper() == "BENIGN":
            data["mitre_techniques"] = []
        logging.info(f"⚖️ Verdict reached: {data['verdict']} - Confidence: {data.get('confidence_score', 0)}%")
        return data
    except Exception as e:
        logging.error(f"Failed to parse Judge's verdict JSON or API failed totally: {e}")
        return {"verdict": "ERROR", "confidence_score": 0, "reason": str(e), "mitre_techniques": []}

import os
import json
import logging
import itertools
from pathlib import Path
from google import genai
from pydantic import BaseModel, Field
from tenacity import retry, wait_exponential, stop_after_attempt, retry_if_exception_type

# Nhúng các Agent đã build sẵn
import ai_agent_extraction_qwen
import ai_agent_extraction_gemma

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(Multi-Agent) %(levelname)s - %(message)s')

GLOBAL_API_KEYS = []
KEY_ITERATER = None

def init_api_keys():
    global GLOBAL_API_KEYS, KEY_ITERATER
    if not GLOBAL_API_KEYS:
        key_file = Path(__file__).parent.parent.parent / "gemini_api_keys.txt"
        if key_file.exists():
            with open(key_file, "r", encoding="utf-8") as f:
                lines = f.readlines()
            GLOBAL_API_KEYS = [line.strip() for line in lines if line.strip() and not line.strip().startswith("#")]
        if GLOBAL_API_KEYS:
            KEY_ITERATER = itertools.cycle(GLOBAL_API_KEYS)

class FinalVerdict(BaseModel):
    verdict: str = Field(description="Strictly 'MALICIOUS' or 'BENIGN'")
    confidence_score: int = Field(description="A number from 0 to 100 capturing the certainty of the verdict")
    reason: str = Field(description="A summarized explanation of the judge's reasoning based on the evidence")
    mitre_tactics: list[str] = Field(description="List of MITRE Tactics identified, e.g., ['TA0002']")

@retry(
    wait=wait_exponential(multiplier=2, min=4, max=20),
    stop=stop_after_attempt(10),
    reraise=True
)
def fetch_gemini_verdict_with_retry(judge_prompt):
    """Tiến hành gọi API Gemini. Nếu dính 429 Resource Exhausted thì Tenacity sẽ tự xoay vòng và đợi 4s-20s."""
    global KEY_ITERATER
    if not KEY_ITERATER:
        raise ValueError("No API Keys available in gemini_api_keys.txt")
    
    current_key = next(KEY_ITERATER)
    client = genai.Client(api_key=current_key)
    model = 'gemini-2.5-flash'
    
    try:
        response = client.models.generate_content(
            model=model, 
            contents=judge_prompt,
            config={
                'response_mime_type': 'application/json',
                'response_schema': FinalVerdict,
            }
        )
        return response.text.strip()
    except Exception as e:
        error_str = str(e).lower()
        if "429" in error_str or "resource" in error_str or "quota" in error_str:
            logging.warning(f"⚠️ [API Qouta Hit] Key kết thúc bằng {current_key[-4:]} đã bị chặn Rate Limit. Tenacity đang Sleep để đổi Key/Retry...")
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
        
        # If it's an ignored path BUT it's a priority action (e.g. O_WRONLY to a site-packages file), KEEP it.
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

def run_debate(package_name, log_content):
    """
    Implements a 3-Agent Debate Framework.
    """
    init_api_keys()
    if not GLOBAL_API_KEYS:
        logging.error("Lỗi: Không tìm thấy API Key nào hợp lệ trong gemini_api_keys.txt.")
        return {"verdict": "ERROR", "confidence_score": 0, "reason": "No API Key", "mitre_tactics": []}

    # Smart Log Filtering cho Qwen (8192 Context = max ~13000 chars)
    log_content = smart_filter_log(log_content, max_chars=13000)
        
    logging.info(f"⚖️ [Court is in session] Case: '{package_name}'")
    
    # ----------------------------------------------------------------- #
    # AGENT 1: THE PROSECUTOR (Qwen 2.5 Local)
    # ----------------------------------------------------------------- #
    logging.info("👨‍⚖️ Prosecutor (Qwen) is building the case...")
    prosecutor_verdict = ai_agent_extraction_qwen.extract_threats_qwen(package_name, log_content)
    prosecutor_case = json.dumps(prosecutor_verdict, indent=2)
    
    # ----------------------------------------------------------------- #
    # AGENT 2: THE DEFENDER (Gemma 2 Local)
    # ----------------------------------------------------------------- #
    # Lỗ Hổng Cơ Học: Gemma cực nhạy cảm với tràn VRAM. Chỉ lấy 4000 Ký tự cuối bằng Preprocessor
    gemma_log_content = smart_filter_log(log_content, max_chars=4000)

    logging.info("👨‍💼 Defender (Gemma 2) is stating their case...")
    defense_verdict = ai_agent_extraction_gemma.extract_defense_gemma(package_name, gemma_log_content, prosecutor_verdict)
    defense_case = json.dumps(defense_verdict, indent=2)
    
    # ----------------------------------------------------------------- #
    # AGENT 3: THE JUDGE (Gemini 2.5 Flash)
    # ----------------------------------------------------------------- #
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
    """
    
    logging.info("👩‍⚖️ Judge is making the final ruling...")
    try:
        text = fetch_gemini_verdict_with_retry(judge_prompt)
        data = json.loads(text)
        logging.info(f"⚖️ Verdict reached: {data['verdict']} - Confidence: {data['confidence_score']}%")
        return data
    except Exception as e:
        logging.error(f"Failed to parse Judge's verdict JSON or API failed totally: {e}")
        return {"verdict": "ERROR", "confidence_score": 0, "reason": str(e), "mitre_tactics": []}

if __name__ == "__main__":
    pass

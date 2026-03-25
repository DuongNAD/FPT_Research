import os
import json
import logging
from pathlib import Path
from google import genai

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(Multi-Agent) %(levelname)s - %(message)s')

def run_debate(package_name, log_content):
    """
    Implements a 3-Agent Debate Framework to achieve Zero False Positives.
    Agent 1 (Prosecutor): Tries to prove the package is malicious.
    Agent 2 (Defender): Argues the behaviors are benign (e.g., telemetry).
    Agent 3 (Judge): Reads both arguments, makes the final determination, and outputs JSON.
    """
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        logging.error("GEMINI_API_KEY environment variable is not set. Cannot run Multi-Agent analysis.")
        return []
    
    client = genai.Client(api_key=api_key)
    model = 'gemini-2.5-flash'
    
    logging.info(f"⚖️ [Court is in session] Case: '{package_name}'")
    
    # ----------------------------------------------------------------- #
    # AGENT 1: THE PROSECUTOR
    # ----------------------------------------------------------------- #
    prosecutor_prompt = f"""
    Act as an Aggressive Cyber Security Prosecutor. Look at the syscall logs of package '{package_name}' and explain why it is malicious. Highlight suspicious network connections (connect) or sensitive file accesses (openat).
    Logs:
    {log_content}
    """
    logging.info("👨‍⚖️ Prosecutor is building the case...")
    prosecutor_resp = client.models.generate_content(model=model, contents=prosecutor_prompt)
    prosecutor_case = prosecutor_resp.text
    
    # ----------------------------------------------------------------- #
    # AGENT 2: THE DEFENDER
    # ----------------------------------------------------------------- #
    defend_prompt = f"""
    Act as a Defense Attorney and Software Engineer. Read the Prosecutor's arguments below:
    PROSECUTOR'S CASE: {prosecutor_case}
    
    Now, look at the logs and argue why these exact syscalls might be perfectly benign or normal Python operations (e.g., normal ping, telemetry, reading a valid config). Try to introduce reasonable doubt!
    """
    logging.info("👨‍💼 Defender is stating their case...")
    defense_resp = client.models.generate_content(model=model, contents=defend_prompt)
    defense_case = defense_resp.text
    
    # ----------------------------------------------------------------- #
    # AGENT 3: THE JUDGE
    # ----------------------------------------------------------------- #
    judge_prompt = f"""
    Act as the Supreme Cyber Security Judge. Review the case of package {package_name}.
    Weigh the evidence objectively.
    
    PROSECUTOR'S CASE:
    {prosecutor_case}
    
    DEFENSE'S CASE:
    {defense_case}
    
    Make your final ruling. If you decide the package is truly malicious, output strictly a JSON array mapping to MITRE ATT&CK techniques. If the Defense introduced sufficient reasonable doubt and it is likely safe, output an empty JSON array: []
    
    JSON Format REQUIRED:
    [
      {{
        "indicator": {{"type": "Syscall", "api": "openat", "source_file": "syscalls.log", "package_name": "{package_name}"}},
        "behavior": {{"name": "CamelCaseBehaviorName", "description": "Short description"}},
        "technique": {{"id": "TXXXX", "name": "Technique Name"}},
        "tactic": {{"id": "TAXXXX", "name": "Tactic Name"}}
      }}
    ]
    Do not output markdown code blocks. Just raw JSON.
    """
    logging.info("👩‍⚖️ Judge is making the final ruling...")
    judge_resp = client.models.generate_content(model=model, contents=judge_prompt)
    text = judge_resp.text.strip()
    
    # Clean up markdown output
    if text.startswith("```json"):
        text = text[7:]
    if text.startswith("```"):
        text = text[3:]
    if text.endswith("```"):
        text = text[:-3]
        
    try:
        data = json.loads(text.strip())
        logging.info(f"⚖️ Verdict reached: {len(data)} malicious counts found.")
        return data
    except Exception as e:
        logging.error(f"Failed to parse Judge's verdict JSON: {e}")
        return []

if __name__ == "__main__":
    # Test run
    DATA_DIR = Path(__file__).parent.parent / "data"
    log_file = DATA_DIR / "syscalls" / "requests-fake-1.0.0_syscalls.log"
    if log_file.exists():
        with open(log_file, "r") as f:
            log_content = f.read()
            
        verdict = run_debate("requests-fake-1.0.0", log_content)
        print("Verdict Nodes:", json.dumps(verdict, indent=2))

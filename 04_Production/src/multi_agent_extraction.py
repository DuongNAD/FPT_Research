import os
import json
import logging
import requests
from pydantic import BaseModel, Field

import ai_agent_extraction_qwen
import ai_agent_extraction_gemma

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Tải bộ quy tắc Heuristic từ file JSON cấu hình độc lập
CONFIG_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config", "heuristic_rules.json")
try:
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        HEURISTIC_RULES = json.load(f)
except Exception as e:
    logging.error(f"Failed to load heuristic.json, falling back to defaults: {e}")
    HEURISTIC_RULES = {
        "thresholds": {"alert_tag_score_minimum": 20},
        "scoring_rules": {
            "score_plus_40": {"keywords": []}, "score_plus_30": {"write_operations": [], "target_directories": [], "target_extensions": [], "ignore_context_keywords": []},
            "score_plus_20": {"keywords": []}, "score_minus_30": {"safe_network_keywords": [], "safe_extensions": []}
        }
    }

class JudgeVerdict(BaseModel):
    analytical_reasoning: str = Field(description="Comprehensive evaluation of both arguments, prioritizing behavioral facts over assumptions.")
    risk_score_calculation: str = Field(description="Explanation of Risk Score based on Likelihood x Impact.")
    risk_score: int = Field(description="A number reflecting the risk score from 0 to 10")
    final_verdict: str = Field(description="Strictly 'MALICIOUS' or 'BENIGN'")
    actionable_recommendation: str = Field(description="Clear instruction on what the system should do with this package (e.g., Block, Allow, Flag for manual review)")

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
                "schema": JudgeVerdict.model_json_schema()
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
        
    import re
    def safe_parse(raw_text):
        if raw_text.startswith("```json"):
            raw_text = raw_text[7:]
        elif raw_text.startswith("```"):
            raw_text = raw_text[3:]
        if raw_text.endswith("```"):
            raw_text = raw_text[:-3]
        raw_text = raw_text.strip()
        
        fixed_text = re.sub(r'(?<!\\)\\(?!["\\/bfnrt])', r'\\\\', raw_text)
        return json.loads(fixed_text, strict=False)

    try:
        return safe_parse(content)
    except json.JSONDecodeError:
        logging.warning("JSON Parsing Error detected (Truncation or Invalid Escape). Engaging Retry Fallback...")
        messages.append({"role": "assistant", "content": content})
        messages.append({"role": "user", "content": "Your previous output was invalid JSON or truncated. Please regenerate the JSON perfectly."})
        
        content2 = fetch(messages)
        return safe_parse(content2)
    except Exception as e:
        logging.error(f"Failed to process Local Judge AI response: {e}")
        raise e

def smart_filter_log(log_content, max_chars=13000):
    import re
    lines = log_content.split('\n')
    
    clean_logs = []
    
    # 1. BỎ QUA RÁC HỆ THỐNG
    ignore_patterns = [r'__pycache__.*\.pyc', r'\.egg-info', r'\.dist-info']
    
    artifact_section = []
    in_artifact = False
    
    for line in lines:
        if line.startswith("=== DETECTED FILE SYSTEM ARTIFACTS ==="):
            in_artifact = True
        
        if in_artifact:
            artifact_section.append(line)
            continue

        line_str = str(line)
        
        # ==========================================
        # 🛡️ HEURISTIC SCORING MATRIX (DYNAMIC)
        # ==========================================
        risk_score = 0
        rules = HEURISTIC_RULES.get("scoring_rules", {})
        
        # Sử dụng Vòng lặp lấy toàn bộ khóa score_plus_X và score_minus_X mà user định nghĩa
        for rule_name, rule_content in rules.items():
            if rule_name.startswith("score_plus_"):
                try: points = int(rule_name.split("_")[2])
                except: continue
                matched = False
                
                if any(kw in line_str for kw in rule_content.get("keywords", [])):
                    matched = True
                elif rule_content.get("write_operations") and any(op in line_str for op in rule_content.get("write_operations")):
                    if not rule_content.get("target_directories") or any(d in line_str for d in rule_content.get("target_directories")):
                        if not rule_content.get("target_extensions") or any(e in line_str for e in rule_content.get("target_extensions")):
                            matched = True
                            
                if matched and not any(ign in line_str for ign in rule_content.get("ignore_context_keywords", [])):
                    risk_score += points
                    
            elif rule_name.startswith("score_minus_"):
                try: points = int(rule_name.split("_")[2])
                except: continue
                matched = False
                
                if any(safe in line_str.lower() for safe in rule_content.get("safe_network_keywords", [])):
                    matched = True
                if any(ext in line_str for ext in rule_content.get("safe_extensions", [])):
                    matched = True
                if any(kw in line_str for kw in rule_content.get("keywords", [])):
                    matched = True
                    
                if matched and not any(ign in line_str for ign in rule_content.get("ignore_context_keywords", [])):
                    risk_score -= points

        # Lấy Thresholds để cấp Tag báo động
        thresholds = HEURISTIC_RULES.get("thresholds", {})
        critical_thresh = thresholds.get("critical_tag_score_minimum", 70)
        warning_thresh = thresholds.get("warning_tag_score_minimum", 40)
        alert_thresh = thresholds.get("alert_tag_score_minimum", 20)

        if risk_score >= critical_thresh:
            line_str += f" [TAG_CRITICAL_THREAT: Score={risk_score}]"
            clean_logs.append(line_str)
            continue
        elif risk_score >= warning_thresh:
            line_str += f" [TAG_HIGH_RISK_EVENT: Score={risk_score}]"
            clean_logs.append(line_str)
            continue
        elif risk_score >= alert_thresh:
            line_str += f" [TAG_SUSPICIOUS_ACTIVITY: Score={risk_score}]"
            clean_logs.append(line_str)
            continue
            
        # ==========================================
        # 🧹 ẨN RÁC HỆ THỐNG
        # ==========================================
        ignore_patterns = [r'__pycache__.*\.pyc', r'\.egg-info', r'\.dist-info']
        if any(re.search(p, line_str) for p in ignore_patterns):
            continue
            
        clean_logs.append(line_str)
        
    filtered_content = '\n'.join(clean_logs)
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
    [RULING PROTOCOL - BEHAVIORAL SCORING]
    You are the Supreme Cybersecurity Judge. You MUST base your final JSON verdict EXACTLY on the provided telemetry logs. DO NOT output any emojis in the JSON.
    
    VERDICT RULES:
    1. ZERO HALLUCINATION: DO NOT invent any file paths, IPs, or ports. If a specific port or file is not explicitly written in the logs, it DOES NOT EXIST.
    2. HEURISTIC ANALYSIS: The pre-system has scored each log line. Lines with severe behavioral threats are marked with "[TAG_HIGH_RISK_EVENT: Score=X]".
    3. YOUR DUTY: Analyze the combination of "[TAG_HIGH_RISK_EVENT]" lines and the context provided by Prosecutor and Defender. You must output "MALICIOUS" if the aggregated facts point to a clear cyber attack (e.g., supply chain injection, fileless execution, port scanning). Output "BENIGN" if the flags are justifiable benign behaviors (e.g., normal caching / no tags).

    - LANGUAGE ENFORCEMENT: Please write the final justification and reasoning strictly in English.

    Output format MUST be valid JSON with the following structure:
    {{
      "analytical_reasoning": "Comprehensive evaluation of both arguments, prioritizing behavioral facts over assumptions.",
      "risk_score_calculation": "Explanation of Risk Score based on Likelihood x Impact.",
      "risk_score": 10,
      "final_verdict": "MALICIOUS",
      "actionable_recommendation": "Clear instruction on what the system should do with this package (e.g., Block, Allow, Flag for manual review)."
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
                
        logging.info(f"⚖️ Verdict reached: {data.get('final_verdict', 'UNKNOWN')} - Risk Score: {data.get('risk_score', 0)}")
        return data
    except Exception as e:
        logging.error(f"Failed to parse Judge's verdict JSON or API failed totally: {e}")
        return {"final_verdict": "ERROR", "risk_score": 0, "analytical_reasoning": str(e)}

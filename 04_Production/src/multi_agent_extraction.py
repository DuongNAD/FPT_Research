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

def run_debate(package_name, log_content):
    """
    Implements a 3-Agent Debate Framework.
    """
    init_api_keys()
    if not GLOBAL_API_KEYS:
        logging.error("Lỗi: Không tìm thấy API Key nào hợp lệ trong gemini_api_keys.txt.")
        return {"verdict": "ERROR", "confidence_score": 0, "reason": "No API Key", "mitre_tactics": []}

    # Cắt gọt tổng quát cho Qwen (8192 Context = max ~13000 chars)
    if len(log_content) > 13000:
        log_content = "...[PREFIX TRUNCATED L1]...\n" + log_content[-13000:]
        
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
    # Lỗ Hổng Cơ Học: Gemma cực nhạy cảm với tràn VRAM. Chỉ lấy 4000 Ký tự cuối (Tương đương ~1000 tokens)
    gemma_log_content = log_content
    if len(gemma_log_content) > 4000:
        gemma_log_content = "...[PREFIX TRUNCATED L2 FOR GEMMA]...\n" + gemma_log_content[-4000:]

    logging.info("👨‍💼 Defender (Gemma 2) is stating their case...")
    defense_verdict = ai_agent_extraction_gemma.extract_defense_gemma(package_name, gemma_log_content, prosecutor_verdict)
    defense_case = json.dumps(defense_verdict, indent=2)
    
    # ----------------------------------------------------------------- #
    # AGENT 3: THE JUDGE (Gemini 2.5 Flash)
    # ----------------------------------------------------------------- #
    judge_prompt = f"""
    BẠN LÀ MỘT THẨM PHÁN TỐI CAO DỰA TRÊN BẰNG CHỨNG (Evidence-based). 
    
    LUẬT TỐ TỤNG SỐ 1: BẠN TUYỆT ĐỐI KHÔNG ĐƯỢC kết tội một package dựa vào chuỗi ký tự tên của nó (ví dụ: chữ 'typo' hay 'malware' hay 'fake' lọt vào trong tên gói không được coi là bằng chứng phạm tội). 
    LUẬT TỐ TỤNG SỐ 2: Bạn CHỈ ĐƯỢC kết tội MALICIOUS nếu Prosecutor (Qwen) bóc tách được chi tiết LOG MẠNG (kết nối ra IP lạ) hoặc FILE ARTIFACT ĐỘC (Mở file /etc/ hoặc /tmp/). Nếu Prosecutor cãi mà không có bằng chứng syscall, rỗng tuếch, hoặc chỉ đoán mò, bạn PHẢI lập tức tuyên án BENIGN.
    LUẬT TỐ TỤNG SỐ 3: Ngay cả khi Defender gục ngã (Conceded), bạn vẫn phải tự soi lại bằng chứng Prosecutor một lần nữa. Không có bằng chứng mạng/file cụ thể -> BENIGN.
    
    Tên Gói Đang Xét: {package_name}
    
    PROSECUTOR'S CASE (Qwen 2.5 Analysis):
    {prosecutor_case}
    
    DEFENSE'S CASE (Gemma 2 Arguments):
    {defense_case}
    
    Giao án JSON Schema.
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

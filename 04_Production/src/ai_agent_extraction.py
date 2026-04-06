import os
import json
import logging
from pathlib import Path
from pydantic import BaseModel, Field
from google import genai
from google.genai import types

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

DATA_DIR = Path(__file__).parent.parent / "data"
SYSCALLS_DIR = DATA_DIR / 'syscalls'
INDICATOR_DIR = DATA_DIR / 'indicators'
INDICATOR_DIR.mkdir(parents=True, exist_ok=True)

class IndicatorContext(BaseModel):
    type: str = Field(description="The type of the indicator, usually 'Syscall' or 'Artifact'")
    api: str = Field(description="The API call or the file path dropping action")
    source_file: str = Field(description="Usually 'syscalls.log' or 'docker_diff'")
    package_name: str = Field(description="The name of the package")

class BehaviorDescription(BaseModel):
    name: str = Field(description="CamelCase description of the behavior (e.g., HiddenFileDrop, ReverseShell)")
    description: str = Field(description="Short description of the behavior observed")

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
Act as an expert Cyber Threat Intelligence Analyst.
I will provide you with a JSON-lines log of system calls generated dynamically by a Python package.

Your task is to analyze these syscall logs and extract any malicious intent.
If no malicious intent is found, return an empty array for threats.

Here are the syscall logs for the package `{package_name}`:
{log_content}
"""

def analyze_logs_with_llm(package_name, log_content):
    """Calls Gemini API to perform threat extraction and mapping concurrently."""
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        logging.error("GEMINI_API_KEY environment variable is not set. Cannot run AI analysis.")
        return []
        
    client = genai.Client(api_key=api_key)
    prompt = PROMPT_TEMPLATE.replace("{package_name}", package_name).replace("{log_content}", log_content)
    
    logging.info(f"Sending prompt to Gemini for {package_name}...")
    try:
        # Sử dụng API mới để enforce output theo cấu trúc Pydantic
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=ThreatExtractionResponse,
                temperature=0.1,
            ),
        )
        
        text = response.text.strip()
        logging.info(f"Raw Gemini response for {package_name}:\n{text}")
        
        data = json.loads(text)
        return data.get("threats", [])
        
    except Exception as e:
        logging.error(f"Failed to process AI response: {e}")
        return []

def main():
    logging.info("Starting Phase 3: AI Agent Extraction & Mapping")
    if not SYSCALLS_DIR.exists():
        logging.error("No syscall logs found. Run sandbox_runner.py first.")
        return
        
    all_mapped_nodes = []
    
    for log_file in SYSCALLS_DIR.glob("*_syscalls.log"):
        package_name = log_file.name.replace("_syscalls.log", "")
        with open(log_file, "r", encoding="utf-8") as f:
            log_content = f.read()
            
        logging.info(f"Analyzing {package_name} logs with AI Agent...")
        nodes = analyze_logs_with_llm(package_name, log_content)
        all_mapped_nodes.extend(nodes)
        
    output_file = INDICATOR_DIR / "mapped_threat_nodes.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(all_mapped_nodes, f, indent=4)
        
    logging.info(f"Successfully mapped {len(all_mapped_nodes)} threat nodes via AI Agent.")
    logging.info(f"Results saved to {output_file}")

if __name__ == "__main__":
    main()
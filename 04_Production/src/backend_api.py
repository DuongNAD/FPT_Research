import os
import json
import logging
import asyncio
import httpx
from pathlib import Path
from fastapi import FastAPI, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

# Import the pipeline scripts
from ingestion import EXTRACT_DIR
from sandbox_runner import generate_mock_syscall_log
from multi_agent_extraction import run_debate

app = FastAPI(title="Threat Pattern Dashboard API & Zero-Trust Proxy")

# CORS for UI
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve the static files (HTML, CSS, JS)
STATIC_DIR = Path(__file__).parent / "static"
DATA_DIR = Path(__file__).parent.parent / "data" / "indicators"
DATA_DIR.mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

KNOWN_MALWARE_FILE = DATA_DIR / "known_malware.json"

def get_known_malware():
    if not KNOWN_MALWARE_FILE.exists():
        return {}
    with open(KNOWN_MALWARE_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def add_to_known_malware(package_name, reason):
    malware = get_known_malware()
    if package_name not in malware:
        import time
        malware[package_name] = {"reason": reason, "timestamp": time.time()}
        with open(KNOWN_MALWARE_FILE, "w", encoding="utf-8") as f:
            json.dump(malware, f, indent=4)

# In-memory storage for active intercepted threats to push to Dashboard
recent_interceptions = []

def load_threat_nodes():
    mapped_file = DATA_DIR / "mapped_threat_nodes.json"
    if not mapped_file.exists():
        return []
    with open(mapped_file, "r", encoding="utf-8") as f:
        return json.load(f)

def save_threat_nodes(new_nodes):
    nodes = load_threat_nodes()
    nodes.extend(new_nodes)
    with open(DATA_DIR / "mapped_threat_nodes.json", "w", encoding="utf-8") as f:
        json.dump(nodes, f, indent=4)

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    with open(STATIC_DIR / "index.html", "r", encoding="utf-8") as f:
        return f.read()

@app.get("/api/threats")
async def get_threat_data():
    """Aggregates the raw JSON into risk scores and highly detailed multi-layer Knowledge Graph motifs."""
    nodes = load_threat_nodes()
    
    # Group by package for the Risk Summary Panel
    packages = {}
    for entry in nodes:
        pkg = entry.get("indicator", {}).get("package_name", "Unknown")
        if pkg not in packages:
            packages[pkg] = {
                "package_name": pkg,
                "behaviors": [],
                "techniques": [],
                "risk_score": 0,
                "alerts": []
            }
            
        beh_name = entry.get("behavior", {}).get("name")
        tech_id = entry.get("technique", {}).get("id")
        
        if beh_name and beh_name not in packages[pkg]["behaviors"]:
            packages[pkg]["behaviors"].append(beh_name)
            
        if tech_id and tech_id not in packages[pkg]["techniques"]:
            packages[pkg]["techniques"].append(f"{tech_id}: {entry.get('technique', {}).get('name')}")
            packages[pkg]["risk_score"] += 1  # 1 point per distinct technique
            packages[pkg]["alerts"].append(f"Phát hiện {beh_name} ({tech_id})")

    # Format highly detailed Knowledge Graph data
    # Structure: Package -> Indicator -> Behavior -> Technique -> Tactic
    graph_data = {"nodes": [], "edges": []}
    for entry in nodes:
        pkg_name = entry.get("indicator", {}).get("package_name", "Unknown")
        api_call = entry.get("indicator", {}).get("api", "unknown_api")
        beh_name = entry.get("behavior", {}).get("name", "Unknown Behavior")
        tech_id = entry.get("technique", {}).get("id", "Unknown_Tech")
        tech_name = entry.get("technique", {}).get("name", "")
        tac_id = entry.get("tactic", {}).get("id", "Unknown_Tac")
        tac_name = entry.get("tactic", {}).get("name", "")

        pkg_id = f"pkg_{pkg_name}"
        ind_id = f"ind_{pkg_name}_{api_call}_{beh_name}"
        beh_id = f"beh_{beh_name}"
        tech_node_id = f"tech_{tech_id}"
        tac_node_id = f"tac_{tac_id}"

        # 1. Add Nodes
        if not any(n["id"] == pkg_id for n in graph_data["nodes"]):
            graph_data["nodes"].append({"id": pkg_id, "label": pkg_name, "group": "package"})
            
        if not any(n["id"] == ind_id for n in graph_data["nodes"]):
            graph_data["nodes"].append({"id": ind_id, "label": f"Syscall:\n{api_call}", "group": "indicator"})
            
        if not any(n["id"] == beh_id for n in graph_data["nodes"]):
            graph_data["nodes"].append({"id": beh_id, "label": beh_name, "group": "behavior"})

        if not any(n["id"] == tech_node_id for n in graph_data["nodes"]):
            graph_data["nodes"].append({"id": tech_node_id, "label": f"MITRE:\n{tech_id}\n{tech_name}", "group": "technique"})
            
        if not any(n["id"] == tac_node_id for n in graph_data["nodes"]):
            graph_data["nodes"].append({"id": tac_node_id, "label": f"CHIẾN THUẬT:\n{tac_id}\n{tac_name}", "group": "tactic"})

        # 2. Add Directed Edges strictly representing the Knowledge Graph Ontology
        def add_edge(frm, to, title):
             if not any(e["from"] == frm and e["to"] == to for e in graph_data["edges"]):
                 graph_data["edges"].append({"from": frm, "to": to, "label": title, "font": {"size": 10, "strokeWidth": 0}})

        add_edge(pkg_id, ind_id, "THỰC THI")
        add_edge(ind_id, beh_id, "CẢNH BÁO")
        add_edge(beh_id, tech_node_id, "MAP_VỚI")
        add_edge(tech_node_id, tac_node_id, "THUỘC_CHIẾN_THUẬT")
            
    return {
        "summary": list(packages.values()),
        "graph": graph_data
    }


# ==============================================================
# PHASE 7: ZERO-TRUST PYPI PROXY
# ==============================================================

async def run_security_pipeline(package_name: str) -> list:
    """Runs the Sandbox -> AI Pipeline synchronously for the proxy."""
    logging.info(f"[PROXY] Intercepted request for '{package_name}'. Starting pipeline...")
    
    # 1. Download & Extract (Simulated instantly since we assume it's buffered)
    # In a full proxy, we would download the .whl to EXTRACT_DIR here.
    
    # 2. Dynamic Sandbox Execution
    # We pass the package name to generate mock system calls
    log_file = generate_mock_syscall_log(package_name)
    
    # 3. Multi-Agent Debate Extraction
    with open(log_file, "r", encoding="utf-8") as f:
        log_content = f.read()
        
    logging.info(f"[PROXY] Calling Multi-Agent Courtroom for '{package_name}'...")
    # This invokes Prosecutor, Defender, and Judge
    nodes = run_debate(package_name, log_content)
    
    return nodes

@app.get("/simple/{package_name}/")
async def intercept_package_install(package_name: str):
    """
    Acts as a PEP 503 Simple Repository API.
    Interprets the pip install command and gates malicious packages.
    """
    # 0. Check Blacklist First!
    known_malware = get_known_malware()
    if package_name in known_malware:
        error_msg = f"❌ [ShieldAI] INSTANT BLOCK: Package '{package_name}' is in the Known Malware Registry! (Reason: {known_malware[package_name]['reason']})"
        logging.critical(error_msg)
        raise HTTPException(status_code=403, detail=error_msg)

    # 1. Run the Security Pipeline
    threat_nodes = await run_security_pipeline(package_name)
    
    # 2. Evaluate Risk
    risk_score = len(set([n.get("technique", {}).get("id") for n in threat_nodes]))
    
    if risk_score > 0:
        # Save to DB so Dashboard updates instantly
        save_threat_nodes(threat_nodes)
        reason = threat_nodes[0].get('behavior', {}).get('name')
        add_to_known_malware(package_name, f"Identified {risk_score} malicious techniques (e.g. {reason})")
        
        # Block the installation!
        error_msg = f"❌ [ShieldAI] BLOCKED: Package '{package_name}' exhibits {risk_score} malicious behaviors. Added to Blacklist!"
        logging.critical(error_msg)
        raise HTTPException(status_code=403, detail=error_msg)
        
    else:
        logging.info(f"✅ [ShieldAI] Package '{package_name}' is safe. Proxying metadata...")
        
    # 3. If safe, proxy the real PyPI response back to pip
    real_pypi_url = f"https://pypi.org/simple/{package_name}/"
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(real_pypi_url)
            if resp.status_code != 200:
                raise HTTPException(status_code=resp.status_code, detail="Package not found on PyPI")
            return HTMLResponse(content=resp.text, status_code=200)
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

@app.get("/packages/{path:path}")
async def proxy_packages(path: str, request: Request):
    """Proxies the actual .whl / .tar.gz downloads directly to pythonhosted.org"""
    real_url = f"https://files.pythonhosted.org/packages/{path}"
    
    async def stream_response():
        async with httpx.AsyncClient() as client:
            async with client.stream("GET", real_url) as resp:
                async for chunk in resp.aiter_bytes():
                    yield chunk

    return StreamingResponse(stream_response(), media_type="application/octet-stream")

@app.get("/api/blacklist")
async def api_get_blacklist():
    return get_known_malware()

if __name__ == "__main__":
    uvicorn.run("backend_api:app", host="0.0.0.0", port=8000, reload=True)

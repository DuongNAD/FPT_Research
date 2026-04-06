from fastapi import FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, FileResponse
import httpx
import os
import json
import asyncio
from pathlib import Path
from typing import List
from pydantic import BaseModel
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "03_Modules")))
from ingestion import download_and_analyze, set_log_callback, pipeline_state
app = FastAPI(title="ShieldAI Zero-Trust PyPI Proxy")

PYPI_SIMPLE_URL = "https://pypi.org/simple"

DATA_DIR = Path(__file__).parent / "data" / "indicators"
DATA_DIR.mkdir(parents=True, exist_ok=True)
KNOWN_MALWARE_FILE = DATA_DIR / "known_malware.json"

def get_known_malware():
    if not KNOWN_MALWARE_FILE.exists():
        return {}
    with open(KNOWN_MALWARE_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def load_threat_nodes():
    mapped_file = DATA_DIR / "mapped_threat_nodes.json"
    if not mapped_file.exists():
        return []
    with open(mapped_file, "r", encoding="utf-8") as f:
        return json.load(f)

# Quản lý WebSocket clients kết nối tới Dashboard
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception:
                pass

manager = ConnectionManager()

# Hook vào ingestion.py để mỗi khi có log mới sẽ đẩy sang WebSocket
async def wss_log_handler(message: str, step: any):
    payload = json.dumps({"message": message, "step": step})
    await manager.broadcast(payload)

set_log_callback(wss_log_handler)

@app.websocket("/ws/logs")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Giữ kết nối
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

class ModeRequest(BaseModel):
    interactive: bool

@app.get("/api/logs")
async def get_raw_log(path: str):
    log_file = Path(path)
    if log_file.exists():
        with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
            suspicious_keywords = ["connect(", "socket(", "execve(", "clone(", "fork(", "/etc/", "http", ".com", "wget", "curl"]
            filtered = [l for l in lines if any(k in l for k in suspicious_keywords)]
            
            if not filtered:
                filtered = lines[:500] + ["\n... [CLEAN/TRUNCATED FOR UI] ...\n"] + lines[-500:]
            else:
                filtered.insert(0, "=== SHIELDAI AUTOMATIC HEURISTIC HIGHLIGHTS ===\n")
                
            content = "".join(filtered)
            if len(content) > 150_000:
                content = content[:150_000] + "\n... [TRUNCATED DUE TO EXTREME SIZE] ..."
            return {"content": content}
    return {"error": "Lỗi: Không tìm thấy file log trên máy chủ Sandbox."}

@app.post("/api/toggle_mode")
async def toggle_mode(req: ModeRequest):
    pipeline_state.is_interactive = req.interactive
    if not pipeline_state.is_interactive:
        pipeline_state.step_event.set()
    return {"status": "ok", "interactive": pipeline_state.is_interactive}

@app.post("/api/approve_step")
async def approve_step():
    pipeline_state.step_event.set()
    return {"status": "ok"}

@app.get("/dashboard", response_class=HTMLResponse)
async def get_dashboard():
    """ Phục vụ file giao diện HTML tĩnh """
    with open("dashboard.html", "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())

@app.get("/api/threats")
async def get_threat_data():
    nodes = load_threat_nodes()
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
            packages[pkg]["risk_score"] += 1
            packages[pkg]["alerts"].append(f"Phát hiện {beh_name} ({tech_id})")

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

        def add_edge(frm, to, title):
             if not any(e["from"] == frm and e["to"] == to for e in graph_data["edges"]):
                 graph_data["edges"].append({"from": frm, "to": to, "label": title, "font": {"size": 10, "strokeWidth": 0}})

        add_edge(pkg_id, ind_id, "THỰC THI")
        add_edge(ind_id, beh_id, "CẢNH BÁO")
        add_edge(beh_id, tech_node_id, "MAP_VỚI")
        add_edge(tech_node_id, tac_node_id, "THUỘC_CHIẾN_THUẬT")
            
    return {"summary": list(packages.values()), "graph": graph_data}

@app.get("/api/blacklist")
async def api_get_blacklist():
    return get_known_malware()

@app.get("/simple/{package_name}/", response_class=HTMLResponse)
async def get_package_simple(package_name: str, request: Request):
    """
    Mô phỏng PyPI simple API.
    """
    if package_name == "shieldaidemo":
        await manager.broadcast(json.dumps({
            "message": f"🤖 Yêu cầu demo cài đặt gói 'shieldaidemo'. Hệ thống đang cung cấp mã độc giả lập.",
            "step": 1
        }))
        fake_html = f'''
        <!DOCTYPE html>
        <html>
          <body>
            <h1>Links for shieldaidemo</h1>
            <a href="{request.base_url}download/demo/shieldaidemo-1.0.0.tar.gz#sha256=123">shieldaidemo-1.0.0.tar.gz</a><br/>
          </body>
        </html>
        '''
        return HTMLResponse(content=fake_html)
        
    async with httpx.AsyncClient() as client:
        resp = await client.get(f"{PYPI_SIMPLE_URL}/{package_name}/")
        if resp.status_code != 200:
            raise HTTPException(status_code=resp.status_code, detail="Package not found on PyPI")
        
        html_content = resp.text
        proxy_url = str(request.base_url).rstrip('/')
        
        # Viết lại link tải
        html_content = html_content.replace(
            "https://files.pythonhosted.org", 
            f"{proxy_url}/download"
        )
        await manager.broadcast(json.dumps({
            "message": f"🤖 Ai đó đang yêu cầu cài đặt gói '{package_name}'. Cấu hình Proxy đã ép luồng tải về ShieldAI.",
            "step": 1
        }))
        return html_content

@app.get("/download/{path:path}")
async def download_package(path: str):
    """
    Bước 1 & Bước 7: Xử lý quá trình tải gói tin từ pip.
    """
    filename = path.split("/")[-1]
    
    if path.startswith("demo/shieldaidemo"):
        # Lưu ý: file demo nằm ở 02_Experiments/Step1_Packet_Interception/data/demo
        import os
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        local_demo_file = Path(base_dir) / "02_Experiments" / "Step1_Packet_Interception" / "data" / "demo" / "shieldaidemo-1.0.0.tar.gz"
        if not local_demo_file.exists():
             raise HTTPException(status_code=404, detail=f"Demo file not built yet at {local_demo_file}. Run create_demo_malware.py")
             
        await manager.broadcast(json.dumps({
            "message": f"[Proxy] Hệ thống đang chặn gói tin DEMO {filename} để tải vào phòng cách ly...",
            "step": 1
        }))
        
        # Bypass luồng Download logic thông thường, copy file thẳng vào quarantine để Trigger Sandbox
        os.makedirs("quarantine", exist_ok=True)
        quarantine_path = os.path.join("quarantine", filename)
        import shutil
        shutil.copy2(local_demo_file, quarantine_path)
        
        await manager.broadcast(json.dumps({
            "message": f"[Ingestion] Đã đưa mã nguồn DEMO '{filename}' về vùng cách ly (Quarantine)...",
            "step": 3
        }))
        
        # Push to sandbox without actual downloading
        is_safe = await download_and_analyze(f"http://fake_pypi/demo/{filename}", filename)
    else:
        original_url = f"https://files.pythonhosted.org/{path}"
        
        await manager.broadcast(json.dumps({
            "message": f"[Proxy] Hệ thống đang chặn gói tin {filename} để chuẩn bị đưa vào phòng cách ly...",
            "step": 1
        }))
        
        # Bước 1-6 trong kiến trúc: Chặn, Tải về quarantine và Phân tích
        try:
            is_safe = await download_and_analyze(original_url, filename)
        except Exception as e:
            # Ngăn chặn Hacker gửi Path dị dạng (Obfuscated) làm sụp hệ thống 500 (DoS).
            raise HTTPException(status_code=400, detail=f"Bad Request: The provided path resulted in an upstream failure.")

    
    # Bước 7: Phán quyết (Cho phép hoặc Chặn)
    if is_safe:
        with open("clean_packages.txt", "a", encoding="utf-8") as f:
            f.write(f"{filename}\n")
            
        quarantine_path = os.path.join("quarantine", filename)
        await manager.broadcast(json.dumps({
            "message": f"[Proxy] Trả về gói {filename} cho client do có đánh giá AN TOÀN.",
            "step": "done"
        }))
        return FileResponse(quarantine_path, media_type="application/octet-stream", filename=filename)
    else:
        with open("malicious_packages.txt", "a", encoding="utf-8") as f:
            f.write(f"{filename}\n")
            
        await manager.broadcast(json.dumps({
            "message": f"[Proxy] Ngắt kết nối cài đặt. Gói {filename} bị hệ thống từ chối vì chứa MÃ ĐỘC.",
            "step": "done"
        }))
        raise HTTPException(status_code=403, detail="ShieldAI Blocked: Gói tin nghi ngờ chứa mã độc (Malware).")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend_api:app", host="0.0.0.0", port=8000, reload=True)

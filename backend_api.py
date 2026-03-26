from fastapi import FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, FileResponse
import httpx
import os
import json
import asyncio
from typing import List
from ingestion import download_and_analyze, set_log_callback

app = FastAPI(title="ShieldAI Zero-Trust PyPI Proxy")

PYPI_SIMPLE_URL = "https://pypi.org/simple"

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

@app.get("/dashboard", response_class=HTMLResponse)
async def get_dashboard():
    """ Phục vụ file giao diện HTML tĩnh """
    with open("dashboard.html", "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())

@app.get("/simple/{package_name}/", response_class=HTMLResponse)
async def get_package_simple(package_name: str, request: Request):
    """
    Mô phỏng PyPI simple API.
    """
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
    original_url = f"https://files.pythonhosted.org/{path}"
    filename = path.split("/")[-1]
    
    await manager.broadcast(json.dumps({
        "message": f"[Proxy] Hệ thống đang chặn gói tin {filename} để chuẩn bị đưa vào phòng cách ly...",
        "step": 1
    }))
    
    # Bước 1-6 trong kiến trúc: Chặn, Tải về quarantine và Phân tích
    is_safe = await download_and_analyze(original_url, filename)
    
    # Bước 7: Phán quyết (Cho phép hoặc Chặn)
    if is_safe:
        quarantine_path = os.path.join("quarantine", filename)
        await manager.broadcast(json.dumps({
            "message": f"[Proxy] Trả về gói {filename} cho client do an toàn.",
            "step": "done"
        }))
        return FileResponse(quarantine_path, media_type="application/octet-stream", filename=filename)
    else:
        await manager.broadcast(json.dumps({
            "message": f"[Proxy] Ngắt kết nối cài đặt. Gói bị hệ thống từ chối.",
            "step": "done"
        }))
        raise HTTPException(status_code=403, detail="ShieldAI Blocked: Gói tin nghi ngờ chứa mã độc (Malware).")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend_api:app", host="0.0.0.0", port=8000, reload=True)

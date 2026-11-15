import asyncio
import json
import os
import random
import time
from typing import Dict, Any, List
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .models import DeviceStatus, SecurityAlert
from .ids_engine import IDSEngine
from simulator.iot_devices import DeviceSimulator, DEFAULT_DEVICES
from simulator.attack_engine import AttackEngine

# Shared IDS and Simulators
ids_engine = IDSEngine()
attack_engine: AttackEngine = None
simulator: DeviceSimulator = None

connected_clients: List[WebSocket] = []

class AttackRequest(BaseModel):
    attack_type: str
    target_device_id: str

class QuarantineRequest(BaseModel):
    quarantined: bool

def on_packet_received(packet):
    """Callback for all packets from simulator and attack engine"""
    ids_engine.process_packet(packet)

# Initialize engines
attack_engine = AttackEngine(on_packet_callback=on_packet_received)
simulator = DeviceSimulator(on_packet_callback=on_packet_received)

# Register default devices in IDS
for dev in DEFAULT_DEVICES:
    ids_engine.register_device(dev)

async def normal_traffic_worker():
    """Background loop generating regular IoT device telemetry"""
    device_ids = [d.id for d in DEFAULT_DEVICES]
    while True:
        try:
            for dev_id in device_ids:
                pkt = simulator.generate_normal_packet(dev_id)
                if pkt:
                    ids_engine.process_packet(pkt)
            await asyncio.sleep(1.0)
        except Exception as e:
            await asyncio.sleep(1.0)

async def websocket_broadcast_worker():
    """Streams live telemetry & alerts to all connected dashboard clients"""
    while True:
        try:
            if connected_clients:
                metrics = ids_engine.get_system_metrics()
                devices_data = [d.model_dump() for d in ids_engine.devices.values()]
                alerts_data = [a.model_dump() for a in list(ids_engine.alerts)[:30]]
                active_attacks = attack_engine.active_attacks

                payload = json.dumps({
                    "type": "telemetry_update",
                    "timestamp": time.time(),
                    "metrics": metrics.model_dump(),
                    "devices": devices_data,
                    "alerts": alerts_data,
                    "active_attacks": active_attacks
                })

                disconnected = []
                for client in connected_clients:
                    try:
                        await client.send_text(payload)
                    except Exception:
                        disconnected.append(client)
                for client in disconnected:
                    if client in connected_clients:
                        connected_clients.remove(client)

            await asyncio.sleep(1.0)
        except Exception:
            await asyncio.sleep(1.0)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Start background loops
    task1 = asyncio.create_task(normal_traffic_worker())
    task2 = asyncio.create_task(websocket_broadcast_worker())
    yield
    task1.cancel()
    task2.cancel()

app = FastAPI(title="IoT Device Security Monitoring System", lifespan=lifespan)

# WebSockets Endpoint
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    connected_clients.append(websocket)
    try:
        while True:
            # Keep connection alive & listen for client pings
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        if websocket in connected_clients:
            connected_clients.remove(websocket)

# REST Endpoints
@app.get("/api/devices")
def get_devices():
    return list(ids_engine.devices.values())

@app.get("/api/alerts")
def get_alerts():
    return list(ids_engine.alerts)

@app.get("/api/metrics")
def get_metrics():
    return ids_engine.get_system_metrics()

@app.post("/api/attacks/trigger")
def trigger_attack(req: AttackRequest):
    target = ids_engine.devices.get(req.target_device_id)
    if not target:
        raise HTTPException(status_code=404, detail="Device not found")
    
    port_map = {"DEV-001": 1883, "DEV-002": 554, "DEV-003": 80, "DEV-004": 1883, "DEV-005": 8080}
    port = port_map.get(target.id, 1883)

    success = attack_engine.launch_attack(
        attack_type=req.attack_type,
        target_device_id=target.id,
        target_ip=target.ip_address,
        target_port=port
    )
    return {"success": success, "attack_type": req.attack_type, "target": target.name}

@app.post("/api/attacks/stop")
def stop_attack(req: Dict[str, str]):
    attack_type = req.get("attack_type", "all")
    success = attack_engine.stop_attack(attack_type)
    return {"success": success, "stopped": attack_type}

@app.post("/api/devices/{device_id}/quarantine")
def toggle_quarantine(device_id: str, req: QuarantineRequest):
    success = ids_engine.set_device_quarantine(device_id, req.quarantined)
    if not success:
        raise HTTPException(status_code=404, detail="Device not found")
    return {"success": True, "device_id": device_id, "quarantined": req.quarantined}

@app.post("/api/alerts/clear")
def clear_alerts():
    ids_engine.alerts.clear()
    return {"success": True, "message": "Alerts cleared"}

# Serve Frontend HTML
FRONTEND_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")
FRONTEND_HTML = os.path.join(FRONTEND_DIR, "index.html")

@app.get("/", response_class=HTMLResponse)
def serve_dashboard():
    if os.path.exists(FRONTEND_HTML):
        with open(FRONTEND_HTML, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>IoT Security Dashboard Frontend Loading...</h1>"

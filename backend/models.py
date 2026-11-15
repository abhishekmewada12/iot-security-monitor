from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum

class DeviceStatus(str, Enum):
    ONLINE = "ONLINE"
    SUSPICIOUS = "SUSPICIOUS"
    UNDER_ATTACK = "UNDER_ATTACK"
    QUARANTINED = "QUARANTINED"
    OFFLINE = "OFFLINE"

class AttackType(str, Enum):
    DDOS_FLOOD = "DDoS / Packet Flood"
    PORT_SCAN = "Port Scanning (Recon)"
    BRUTE_FORCE = "Brute Force Authentication"
    DATA_TAMPERING = "Sensor Data Hijack"
    UNAUTHORIZED_C2 = "Rogue C2 Communication"

class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class IoTDevice(BaseModel):
    id: str
    name: str
    type: str # e.g. "Smart Thermostat", "IP Camera", "Smart Lock", "Industrial Sensor"
    ip_address: str
    mac_address: str
    protocol: str # MQTT, HTTP, RTSP, CoAP
    status: DeviceStatus = DeviceStatus.ONLINE
    last_seen: str
    packet_rate_sec: float = 0.0
    bytes_sec: float = 0.0
    anomaly_score: float = 0.0 # 0.0 (normal) to 1.0 (highly anomalous)
    metadata: Dict[str, Any] = {}

class TelemetryPacket(BaseModel):
    device_id: str
    timestamp: float
    source_ip: str
    destination_ip: str
    port: int
    protocol: str
    packet_size: int
    payload: Dict[str, Any]
    is_malicious: bool = False
    attack_label: Optional[str] = None

class SecurityAlert(BaseModel):
    id: str
    timestamp: str
    device_id: str
    device_name: str
    attack_type: str
    severity: Severity
    description: str
    source_ip: str
    target_port: int
    mitigation_action: str
    raw_indicators: Dict[str, Any] = {}

class SystemMetrics(BaseModel):
    total_packets_processed: int = 0
    packets_per_sec: float = 0.0
    active_threats_count: int = 0
    quarantined_devices_count: int = 0
    global_threat_level: str = "NORMAL" # NORMAL, ELEVATED, SEVERE, CRITICAL
    threat_index_score: int = 5 # 0 to 100

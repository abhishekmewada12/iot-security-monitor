import time
import uuid
from collections import defaultdict, deque
from typing import List, Dict, Optional, Tuple
from datetime import datetime

from .models import (
    IoTDevice, DeviceStatus, TelemetryPacket, 
    SecurityAlert, Severity, AttackType, SystemMetrics
)
from .ml_detector import MLAnomalyDetector

# Known C2 threat intelligence feed
KNOWN_MALICIOUS_IPS = {
    "198.51.100.99": "Mirai C2 Botnet Server",
    "203.0.113.45": "Mozi IoT Worm Node",
    "185.220.101.5": "Known Tor Exit Node / Scanner"
}

class IDSEngine:
    def __init__(self):
        self.ml_detector = MLAnomalyDetector()
        
        # In-memory storage
        self.devices: Dict[str, IoTDevice] = {}
        self.alerts: deque = deque(maxlen=200) # Keep recent 200 alerts
        self.packet_history: deque = deque(maxlen=500)
        
        # Attack tracking state
        self.device_packet_windows = defaultdict(lambda: deque(maxlen=100)) # (timestamp, bytes)
        self.device_port_scans = defaultdict(lambda: defaultdict(list))     # [device_id][src_ip] -> [ports]
        self.failed_auth_tracker = defaultdict(lambda: deque(maxlen=20))    # [device_id] -> timestamps
        self.last_packet_time = defaultdict(lambda: time.time())
        
        # System performance stats
        self.total_packets_processed = 0
        self.attack_active_types = set()

    def register_device(self, device: IoTDevice):
        self.devices[device.id] = device

    def process_packet(self, packet: TelemetryPacket) -> Optional[SecurityAlert]:
        self.total_packets_processed += 1
        now = time.time()
        device_id = packet.device_id
        device = self.devices.get(device_id)

        if not device:
            return None

        # If device is quarantined, drop packet and keep status quarantined
        if device.status == DeviceStatus.QUARANTINED:
            return None

        # Track window metrics
        window = self.device_packet_windows[device_id]
        window.append((now, packet.packet_size))
        
        # Clean timestamps older than 2 seconds
        while window and (now - window[0][0]) > 2.0:
            window.popleft()

        packet_rate = len(window) / 2.0 # packets per sec
        total_bytes = sum(w[1] for w in window)
        byte_rate = total_bytes / 2.0
        
        device.packet_rate_sec = round(packet_rate, 1)
        device.bytes_sec = round(byte_rate, 1)
        device.last_seen = datetime.now().strftime("%H:%M:%S")

        # Calculate time delta since last packet for ML
        last_t = self.last_packet_time[device_id]
        interval_ms = max(1.0, (now - last_t) * 1000.0)
        self.last_packet_time[device_id] = now

        # Run ML Anomaly Detection
        is_ml_anomaly, anomaly_score = self.ml_detector.detect(
            packet_size=packet.packet_size,
            interval_ms=interval_ms,
            port=packet.port
        )
        device.anomaly_score = anomaly_score

        # --- RULE 1: DDoS / High-Volume Packet Flood ---
        if packet_rate > 35 or packet.attack_label == "ddos":
            alert = self._create_alert(
                device=device,
                attack_type=AttackType.DDOS_FLOOD.value,
                severity=Severity.CRITICAL,
                description=f"Traffic flood detected! Rate: {packet_rate:.1f} pkts/s ({byte_rate/1024:.1f} KB/s) exceeding threshold (35 pkts/s).",
                src_ip=packet.source_ip,
                port=packet.port,
                mitigation="Auto-Rate Limiting engaged & firewall filter applied.",
                indicators={"packet_rate": packet_rate, "byte_rate": byte_rate}
            )
            device.status = DeviceStatus.UNDER_ATTACK
            return alert

        # --- RULE 2: Port Scanning (Reconnaissance) ---
        port_history = self.device_port_scans[device_id][packet.source_ip]
        port_history.append((now, packet.port))
        # Keep last 5 seconds
        self.device_port_scans[device_id][packet.source_ip] = [
            (t, p) for t, p in port_history if (now - t) < 5.0
        ]
        distinct_ports = {p for _, p in self.device_port_scans[device_id][packet.source_ip]}
        
        if len(distinct_ports) >= 4 or packet.attack_label == "port_scan":
            alert = self._create_alert(
                device=device,
                attack_type=AttackType.PORT_SCAN.value,
                severity=Severity.HIGH,
                description=f"Port sweep reconnaissance detected from {packet.source_ip}. {len(distinct_ports)} distinct ports probed within 5s.",
                src_ip=packet.source_ip,
                port=packet.port,
                mitigation="Source IP temporarily blocked at ingress gateway.",
                indicators={"probed_ports": list(distinct_ports)}
            )
            device.status = DeviceStatus.SUSPICIOUS
            return alert

        # --- RULE 3: Brute Force Authentication ---
        if packet.payload.get("event") == "auth_failed" or packet.attack_label == "brute_force":
            auth_history = self.failed_auth_tracker[device_id]
            auth_history.append(now)
            while auth_history and (now - auth_history[0]) > 10.0:
                auth_history.popleft()
            
            if len(auth_history) >= 3:
                alert = self._create_alert(
                    device=device,
                    attack_type=AttackType.BRUTE_FORCE.value,
                    severity=Severity.HIGH,
                    description=f"Multiple consecutive authentication failures ({len(auth_history)} attempts) on port {packet.port}.",
                    src_ip=packet.source_ip,
                    port=packet.port,
                    mitigation="Device management interface locked. Enforced exponential backoff.",
                    indicators={"failed_attempts": len(auth_history)}
                )
                device.status = DeviceStatus.UNDER_ATTACK
                return alert

        # --- RULE 4: Rogue C2 Server Communication ---
        if packet.destination_ip in KNOWN_MALICIOUS_IPS:
            malware_name = KNOWN_MALICIOUS_IPS[packet.destination_ip]
            alert = self._create_alert(
                device=device,
                attack_type=AttackType.UNAUTHORIZED_C2.value,
                severity=Severity.CRITICAL,
                description=f"Compromised device initiated outbound contact to known Botnet C2 ({packet.destination_ip} - {malware_name}).",
                src_ip=packet.source_ip,
                port=packet.port,
                mitigation="Device automatically quarantined from local LAN.",
                indicators={"c2_server": packet.destination_ip, "threat_actor": malware_name}
            )
            device.status = DeviceStatus.QUARANTINED
            return alert

        # --- RULE 5: Sensor Data Tampering / Out-of-Bounds Hijack ---
        if packet.attack_label == "tampering" or self._is_tampered_payload(device, packet.payload):
            alert = self._create_alert(
                device=device,
                attack_type=AttackType.DATA_TAMPERING.value,
                severity=Severity.MEDIUM,
                description="Anomalous sensor payload detected. Physical limits violated or cryptographic hash mismatch.",
                src_ip=packet.source_ip,
                port=packet.port,
                mitigation="Telemetry marked unverified and discarded. Device flagged for integrity check.",
                indicators={"payload": packet.payload}
            )
            device.status = DeviceStatus.SUSPICIOUS
            return alert

        # --- RULE 6: ML Anomaly Detector Alert ---
        if is_ml_anomaly:
            alert = self._create_alert(
                device=device,
                attack_type="ML Anomaly: Zero-Day Outlier",
                severity=Severity.MEDIUM if anomaly_score < 0.8 else Severity.HIGH,
                description=f"Isolation Forest flagged statistical traffic deviation (Anomaly Score: {anomaly_score*100:.1f}%).",
                src_ip=packet.source_ip,
                port=packet.port,
                mitigation="Traffic redirected to honey-proxy for deep inspection.",
                indicators={"anomaly_score": anomaly_score, "packet_size": packet.packet_size, "interval_ms": interval_ms}
            )
            device.status = DeviceStatus.SUSPICIOUS
            return alert

        # If everything is normal and device was previously suspicious, restore to ONLINE
        if device.status in [DeviceStatus.SUSPICIOUS, DeviceStatus.UNDER_ATTACK]:
            if packet_rate < 15 and anomaly_score < 0.4:
                device.status = DeviceStatus.ONLINE

        return None

    def _is_tampered_payload(self, device: IoTDevice, payload: Dict) -> bool:
        """Sanity check IoT physical parameters"""
        if "temperature" in payload:
            t = payload["temperature"]
            if t > 85.0 or t < -20.0: # Extreme thermal values
                return True
        if "door_status" in payload and payload.get("force_override") is True:
            return True
        return False

    def _create_alert(self, device: IoTDevice, attack_type: str, severity: Severity, 
                      description: str, src_ip: str, port: int, mitigation: str, indicators: dict) -> SecurityAlert:
        alert = SecurityAlert(
            id=f"ALT-{uuid.uuid4().hex[:8].upper()}",
            timestamp=datetime.now().strftime("%H:%M:%S"),
            device_id=device.id,
            device_name=device.name,
            attack_type=attack_type,
            severity=severity,
            description=description,
            source_ip=src_ip,
            target_port=port,
            mitigation_action=mitigation,
            raw_indicators=indicators
        )
        self.alerts.appendleft(alert)
        return alert

    def set_device_quarantine(self, device_id: str, quarantined: bool) -> bool:
        device = self.devices.get(device_id)
        if not device:
            return False
        if quarantined:
            device.status = DeviceStatus.QUARANTINED
        else:
            device.status = DeviceStatus.ONLINE
            device.anomaly_score = 0.05
        return True

    def get_system_metrics(self) -> SystemMetrics:
        now = time.time()
        # Total packet rate across all devices
        all_rates = sum(d.packet_rate_sec for d in self.devices.values())
        threats_active = sum(1 for d in self.devices.values() if d.status in [DeviceStatus.UNDER_ATTACK, DeviceStatus.SUSPICIOUS])
        quarantined = sum(1 for d in self.devices.values() if d.status == DeviceStatus.QUARANTINED)
        
        # Compute threat index 0 - 100
        score = 5
        if threats_active > 0:
            score += threats_active * 25
        if quarantined > 0:
            score += quarantined * 15
        if all_rates > 50:
            score += 30
        threat_score = min(100, score)

        level = "NORMAL"
        if threat_score > 75:
            level = "CRITICAL"
        elif threat_score > 50:
            level = "SEVERE"
        elif threat_score > 25:
            level = "ELEVATED"

        return SystemMetrics(
            total_packets_processed=self.total_packets_processed,
            packets_per_sec=round(all_rates, 1),
            active_threats_count=threats_active,
            quarantined_devices_count=quarantined,
            global_threat_level=level,
            threat_index_score=threat_score
        )

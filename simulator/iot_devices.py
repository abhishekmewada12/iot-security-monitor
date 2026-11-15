import time
import random
from typing import List, Dict, Callable, Optional
from datetime import datetime

from backend.models import IoTDevice, DeviceStatus, TelemetryPacket

DEFAULT_DEVICES = [
    IoTDevice(
        id="DEV-001",
        name="Smart Thermostat (HVAC)",
        type="Climate Controller",
        ip_address="192.168.1.101",
        mac_address="3C:71:BF:12:4A:88",
        protocol="MQTT",
        status=DeviceStatus.ONLINE,
        last_seen=datetime.now().strftime("%H:%M:%S"),
        metadata={"firmware": "v2.4.1", "location": "Zone-A Living Area"}
    ),
    IoTDevice(
        id="DEV-002",
        name="Perimeter Security Camera",
        type="IP Surveillance Camera",
        ip_address="192.168.1.102",
        mac_address="00:1A:3F:89:C2:11",
        protocol="RTSP / HTTP",
        status=DeviceStatus.ONLINE,
        last_seen=datetime.now().strftime("%H:%M:%S"),
        metadata={"resolution": "1080p", "fps": 15, "location": "North Entrance"}
    ),
    IoTDevice(
        id="DEV-003",
        name="Biometric Smart Lock",
        type="Access Control Unit",
        ip_address="192.168.1.103",
        mac_address="68:C6:3A:D4:55:20",
        protocol="CoAP / HTTP",
        status=DeviceStatus.ONLINE,
        last_seen=datetime.now().strftime("%H:%M:%S"),
        metadata={"battery": "94%", "lock_state": "LOCKED"}
    ),
    IoTDevice(
        id="DEV-004",
        name="Industrial Pressure & Temp Sensor",
        type="Facility Telemetry",
        ip_address="192.168.1.104",
        mac_address="B8:27:EB:14:81:79",
        protocol="MQTT",
        status=DeviceStatus.ONLINE,
        last_seen=datetime.now().strftime("%H:%M:%S"),
        metadata={"unit": "PSI / Celsius", "criticality": "HIGH"}
    ),
    IoTDevice(
        id="DEV-005",
        name="Connected Patient Monitor",
        type="IoMT Health Sensor",
        ip_address="192.168.1.105",
        mac_address="48:55:19:FA:60:3B",
        protocol="HTTP",
        status=DeviceStatus.ONLINE,
        last_seen=datetime.now().strftime("%H:%M:%S"),
        metadata={"vitals": "SpO2 / Pulse", "patient_id": "PT-409"}
    )
]

class DeviceSimulator:
    def __init__(self, on_packet_callback: Callable[[TelemetryPacket], None]):
        self.devices = {d.id: d for d in DEFAULT_DEVICES}
        self.on_packet = on_packet_callback
        self.running = False
        self.tick_counters = {d.id: 0 for d in DEFAULT_DEVICES}

    def generate_normal_packet(self, device_id: str) -> Optional[TelemetryPacket]:
        device = self.devices.get(device_id)
        if not device or device.status == DeviceStatus.QUARANTINED:
            return None

        now = time.time()

        if device_id == "DEV-001": # Thermostat
            payload = {
                "temperature": round(random.normalvariate(23.5, 0.4), 2),
                "humidity": round(random.normalvariate(48.0, 1.2), 1),
                "hvac_state": random.choice(["IDLE", "COOLING"])
            }
            return TelemetryPacket(
                device_id=device_id,
                timestamp=now,
                source_ip=device.ip_address,
                destination_ip="192.168.1.1", # Gateway/Broker
                port=1883,
                protocol="MQTT",
                packet_size=random.randint(64, 110),
                payload=payload
            )

        elif device_id == "DEV-002": # Camera
            payload = {
                "frame_seq": self.tick_counters[device_id],
                "bitrate_kbps": random.randint(1800, 2400),
                "motion_detected": random.random() < 0.05
            }
            return TelemetryPacket(
                device_id=device_id,
                timestamp=now,
                source_ip=device.ip_address,
                destination_ip="192.168.1.1",
                port=554,
                protocol="RTSP",
                packet_size=random.randint(950, 1420),
                payload=payload
            )

        elif device_id == "DEV-003": # Smart Lock
            payload = {
                "battery": random.randint(91, 95),
                "lock_status": "SECURE",
                "heartbeat": True
            }
            return TelemetryPacket(
                device_id=device_id,
                timestamp=now,
                source_ip=device.ip_address,
                destination_ip="192.168.1.1",
                port=80,
                protocol="HTTP",
                packet_size=random.randint(48, 85),
                payload=payload
            )

        elif device_id == "DEV-004": # Industrial Sensor
            payload = {
                "pressure_psi": round(random.normalvariate(102.5, 1.5), 1),
                "temperature": round(random.normalvariate(45.0, 0.8), 1),
                "vibration_g": round(random.uniform(0.01, 0.04), 3)
            }
            return TelemetryPacket(
                device_id=device_id,
                timestamp=now,
                source_ip=device.ip_address,
                destination_ip="192.168.1.1",
                port=1883,
                protocol="MQTT",
                packet_size=random.randint(72, 128),
                payload=payload
            )

        elif device_id == "DEV-005": # Patient Monitor
            payload = {
                "heart_rate_bpm": random.randint(70, 78),
                "spo2_percent": random.randint(97, 99)
            }
            return TelemetryPacket(
                device_id=device_id,
                timestamp=now,
                source_ip=device.ip_address,
                destination_ip="192.168.1.1",
                port=8080,
                protocol="HTTP",
                packet_size=random.randint(60, 95),
                payload=payload
            )

        return None

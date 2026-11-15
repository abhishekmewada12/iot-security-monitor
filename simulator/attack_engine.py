import time
import random
import threading
from typing import Callable, Optional, Dict
from backend.models import TelemetryPacket

class AttackEngine:
    def __init__(self, on_packet_callback: Callable[[TelemetryPacket], None]):
        self.on_packet = on_packet_callback
        self.active_attacks: Dict[str, bool] = {
            "ddos": False,
            "port_scan": False,
            "brute_force": False,
            "tampering": False,
            "c2_outbound": False
        }
        self.threads: Dict[str, threading.Thread] = {}

    def launch_attack(self, attack_type: str, target_device_id: str, target_ip: str, target_port: int = 1883) -> bool:
        if attack_type not in self.active_attacks:
            return False

        if self.active_attacks[attack_type]:
            return True # Already running

        self.active_attacks[attack_type] = True
        
        target_fn = getattr(self, f"_run_{attack_type}", None)
        if target_fn:
            t = threading.Thread(target=target_fn, args=(target_device_id, target_ip, target_port), daemon=True)
            self.threads[attack_type] = t
            t.start()
            return True
        return False

    def stop_attack(self, attack_type: str) -> bool:
        if attack_type in self.active_attacks:
            self.active_attacks[attack_type] = False
            return True
        elif attack_type == "all":
            for k in self.active_attacks:
                self.active_attacks[k] = False
            return True
        return False

    def is_active(self, attack_type: str) -> bool:
        return self.active_attacks.get(attack_type, False)

    # --- ATTACK 1: DDoS / Packet Flood ---
    def _run_ddos(self, target_device_id: str, target_ip: str, target_port: int):
        attacker_ips = ["192.168.1.201", "192.168.1.202", "192.168.1.203", "192.168.1.240"]
        while self.active_attacks["ddos"]:
            # Burst of packets
            for _ in range(12):
                pkt = TelemetryPacket(
                    device_id=target_device_id,
                    timestamp=time.time(),
                    source_ip=random.choice(attacker_ips),
                    destination_ip=target_ip,
                    port=target_port,
                    protocol="UDP_FLOOD",
                    packet_size=random.randint(512, 1200),
                    payload={"syn_flood": True, "junk_padding": "A" * 64},
                    is_malicious=True,
                    attack_label="ddos"
                )
                self.on_packet(pkt)
            time.sleep(0.12) # ~100 packets/sec

    # --- ATTACK 2: Port Scanning (Reconnaissance) ---
    def _run_port_scan(self, target_device_id: str, target_ip: str, _):
        scanner_ip = "192.168.1.250"
        ports_to_probe = [21, 22, 23, 25, 80, 443, 554, 1883, 3306, 8080, 8883, 9000]
        while self.active_attacks["port_scan"]:
            for port in ports_to_probe:
                if not self.active_attacks["port_scan"]:
                    break
                pkt = TelemetryPacket(
                    device_id=target_device_id,
                    timestamp=time.time(),
                    source_ip=scanner_ip,
                    destination_ip=target_ip,
                    port=port,
                    protocol="TCP_SYN",
                    packet_size=40,
                    payload={"flag": "SYN", "scan_tool": "Nmap-Sim"},
                    is_malicious=True,
                    attack_label="port_scan"
                )
                self.on_packet(pkt)
                time.sleep(0.35)
            time.sleep(1.5)

    # --- ATTACK 3: Brute Force Authentication ---
    def _run_brute_force(self, target_device_id: str, target_ip: str, target_port: int):
        attacker_ip = "192.168.1.199"
        usernames = ["admin", "root", "support", "default", "installer"]
        passwords = ["123456", "admin", "toor", "password", "camera123"]
        while self.active_attacks["brute_force"]:
            u = random.choice(usernames)
            p = random.choice(passwords)
            pkt = TelemetryPacket(
                device_id=target_device_id,
                timestamp=time.time(),
                source_ip=attacker_ip,
                destination_ip=target_ip,
                port=target_port,
                protocol="SSH/HTTP-AUTH",
                packet_size=180,
                payload={"event": "auth_failed", "user": u, "pass": "***"},
                is_malicious=True,
                attack_label="brute_force"
            )
            self.on_packet(pkt)
            time.sleep(0.8)

    # --- ATTACK 4: Sensor Tampering / Hijack ---
    def _run_tampering(self, target_device_id: str, target_ip: str, target_port: int):
        while self.active_attacks["tampering"]:
            pkt = TelemetryPacket(
                device_id=target_device_id,
                timestamp=time.time(),
                source_ip="192.168.1.180", # MitM attacker injecting fake packets
                destination_ip=target_ip,
                port=target_port,
                protocol="MQTT_INJECT",
                packet_size=250,
                payload={
                    "temperature": round(random.uniform(130.0, 165.0), 1), # Lethal heat reading
                    "pressure_psi": 999.0, # Dangerous explosive overpressure
                    "force_override": True,
                    "tamper_signature": "ROGUE_PAYLOAD"
                },
                is_malicious=True,
                attack_label="tampering"
            )
            self.on_packet(pkt)
            time.sleep(1.0)

    # --- ATTACK 5: Rogue C2 Botnet Communication ---
    def _run_c2_outbound(self, target_device_id: str, target_ip: str, _):
        c2_ip = "198.51.100.99" # Mirai C2
        while self.active_attacks["c2_outbound"]:
            pkt = TelemetryPacket(
                device_id=target_device_id,
                timestamp=time.time(),
                source_ip=target_ip, # Compromised IoT device calling home
                destination_ip=c2_ip,
                port=4444, # Reverse shell port
                protocol="TCP_C2",
                packet_size=512,
                payload={"cmd": "HEARTBEAT_BOTNET", "version": "Mirai-IoT-v4"},
                is_malicious=True,
                attack_label="c2_outbound"
            )
            self.on_packet(pkt)
            time.sleep(2.0)

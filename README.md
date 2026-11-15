# 🛡️ SHIELD-IoT: Autonomous IoT Security Monitoring & Intrusion Detection System (SIEM)

An enterprise-grade, real-time IoT Security Operations Center (SOC) and Intrusion Detection/Prevention System (IDS/IPS) built to safeguard connected IoT devices against modern cyber threats.

---

## 🌟 Key Features

1. **Virtual IoT Fleet Simulation (Zero Hardware Needed)**:
   - Simulates realistic multi-protocol IoT devices:
     - `DEV-001: Smart Thermostat (HVAC)` (MQTT - Port 1883)
     - `DEV-002: Perimeter Security Camera` (RTSP - Port 554)
     - `DEV-003: Biometric Smart Lock` (CoAP/HTTP - Port 80)
     - `DEV-004: Industrial Boiler Sensor` (MQTT - Port 1883)
     - `DEV-005: Connected Patient Monitor` (IoMT - Port 8080)

2. **Dual-Tier Intrusion Detection Engine**:
   - **Rule-Based Engine (Signatures & Thresholds)**:
     - High-rate packet flood & SYN flood detection (> 35 pkts/sec).
     - Multi-port reconnaissance sweeps (Nmap-style scanning).
     - Consecutive failed authentication lockout (brute-force defense).
     - Physical boundary sanity verification (impossible temperature/pressure spikes).
     - Known malicious C2 / Mirai botnet IP matching.
   - **Machine Learning Anomaly Detection (Isolation Forest)**:
     - Unsupervised anomaly detection using `scikit-learn`.
     - Analyzes packet intervals, packet sizes, entropy, and port frequencies to detect novel zero-day attacks.

3. **Active Mitigation & Zero-Trust Quarantine**:
   - Automated quarantine upon detection of severe botnet activity.
   - 1-click manual "Isolate" / "Restore" control for security operators.

4. **Interactive Red Team Cyber Attack Simulation Deck**:
   - Launch & stop live attacks with a single click:
     - 🚀 **DDoS / Packet Flood**
     - 🔍 **TCP Port Scanning**
     - 🔑 **Brute Force Authentication**
     - ⚡ **Sensor Data Tampering / Hijack**
     - 💀 **Mirai C2 Botnet Reverse Shell Contact**

5. **High-Tech SOC Dashboard**:
   - Real-time WebSockets data streaming (no page refreshes required).
   - Rolling traffic throughput & anomaly probability graphs via Chart.js.
   - Incident severity log stream with mitigation tracking.

---

## 📂 Project Architecture

```
iot-security-monitor/
├── backend/
│   ├── ids_engine.py      # Dual-Tier IDS (Rule-based + ML Orchestrator)
│   ├── ml_detector.py     # Isolation Forest Anomaly Detection Model
│   ├── models.py          # Pydantic Schemas & Security Enums
│   └── main.py            # FastAPI REST & WebSocket Server
├── simulator/
│   ├── iot_devices.py     # Multi-device IoT Telemetry Generator
│   └── attack_engine.py   # Multi-threaded Red Team Attack Simulator
├── frontend/
│   └── index.html         # Cyber Dark Theme Real-Time Web Dashboard
├── requirements.txt       # Dependencies
├── run.py                 # 1-Click Server Runner
└── README.md              # Project Documentation
```

---

## 🚀 How to Run the Project

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Launch the Security Server
```bash
python run.py
```

### 3. Open the Dashboard in your Browser
Navigate to:
```
http://127.0.0.1:8000
```

---

## 🔬 Attack Demonstration Walkthrough (For Demos & Viva)

1. **Baseline Traffic**:
   - Open `http://127.0.0.1:8000`. You will see all 5 IoT devices running in `ONLINE` status with normal packet rates (4-8 pkts/s).
   - The Global Threat Score will sit comfortably at `5/100 (NORMAL)`.

2. **Testing DDoS Detection**:
   - In the **Cyber Attack Simulation Deck**, select `DEV-001: Smart Thermostat`.
   - Click **DDoS Flood**.
   - **Result**: Traffic graph spikes above 50 pkts/s, Threat Score leaps to `SEVERE/CRITICAL`, device transitions to `UNDER_ATTACK` with a flashing red badge, and a **CRITICAL** alert appears in the Incident Logs!
   - Click button again to deactivate the attack. Watch the IDS restore device status automatically.

3. **Testing Mirai C2 Botnet Communication**:
   - Click **Mirai C2 Botnet Communication**.
   - **Result**: The IDS intercepts an outbound handshake to known Mirai IP `198.51.100.99`. The device is immediately shifted to `QUARANTINED` and all ingress/egress is blocked!
   - Click the green **Restore** button on the device card to re-admit it to the network.

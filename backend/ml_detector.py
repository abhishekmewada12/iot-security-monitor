import numpy as np
import random
from typing import Tuple, Dict, Any

try:
    from sklearn.ensemble import IsolationForest
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

class MLAnomalyDetector:
    """
    Unsupervised ML Anomaly Detection using Isolation Forest.
    Learns normal baseline traffic distribution of IoT devices
    and flags outliers (DDoS spikes, unusual packet sizes, abnormal frequencies).
    """
    def __init__(self):
        self.is_trained = False
        self.model = None
        self._init_and_train_baseline()

    def _init_and_train_baseline(self):
        """Train on synthetic baseline of normal IoT traffic"""
        if not SKLEARN_AVAILABLE:
            self.is_trained = True
            return

        # Generate realistic baseline normal IoT traffic vectors
        # Features: [packet_size (bytes), interval_ms, target_port, payload_var]
        np.random.seed(42)
        n_samples = 2000

        # Normal telemetry:
        # Thermostat / Sensor: 40-120 bytes, 1000-2500ms intervals, port 1883 (MQTT) / 80
        # Camera: 800-1400 bytes, 30-100ms intervals, port 554 (RTSP)
        sizes_sensors = np.random.normal(80, 20, int(n_samples * 0.7))
        intervals_sensors = np.random.normal(1500, 300, int(n_samples * 0.7))
        ports_sensors = np.random.choice([1883, 80, 8883], size=int(n_samples * 0.7))

        sizes_cam = np.random.normal(1100, 150, int(n_samples * 0.3))
        intervals_cam = np.random.normal(60, 15, int(n_samples * 0.3))
        ports_cam = np.random.choice([554, 8080], size=int(n_samples * 0.3))

        sizes = np.clip(np.concatenate([sizes_sensors, sizes_cam]), 20, 1500)
        intervals = np.clip(np.concatenate([intervals_sensors, intervals_cam]), 10, 5000)
        ports = np.concatenate([ports_sensors, ports_cam])
        variances = np.random.uniform(0.1, 1.5, n_samples)

        X_train = np.column_stack([sizes, intervals, ports, variances])

        # Train Isolation Forest
        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.03,
            random_state=42
        )
        self.model.fit(X_train)
        self.is_trained = True

    def extract_features(self, packet_size: int, interval_ms: float, port: int, payload_var: float = 0.5) -> np.ndarray:
        return np.array([[float(packet_size), float(interval_ms), float(port), float(payload_var)]])

    def detect(self, packet_size: int, interval_ms: float, port: int, payload_var: float = 0.5) -> Tuple[bool, float]:
        """
        Returns (is_anomaly, anomaly_score_0_to_1)
        Score > 0.65 is typically anomalous.
        """
        features = self.extract_features(packet_size, interval_ms, port, payload_var)

        if SKLEARN_AVAILABLE and self.model is not None:
            # decision_function gives negative for outliers, positive for inliers
            raw_score = self.model.decision_function(features)[0]
            # Normalize to 0 (normal) to 1 (extreme anomaly)
            # Normal scores usually range from 0.0 to 0.25; anomalies go down to -0.3
            normalized_score = float(np.clip(0.5 - (raw_score * 1.8), 0.0, 1.0))
            is_anomaly = normalized_score >= 0.65
            return is_anomaly, round(normalized_score, 3)
        else:
            # Fallback statistical baseline
            score = 0.1
            # Very high frequency + large size or weird port
            if interval_ms < 15 and packet_size > 800:
                score += 0.6
            if port not in [1883, 8883, 80, 443, 554, 8080]:
                score += 0.3
            score = min(score, 0.99)
            return (score > 0.65), round(score, 3)

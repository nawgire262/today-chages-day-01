import threading
import time
import json
<<<<<<< HEAD
import logging
from datetime import datetime
=======
>>>>>>> fb2e0dfb94cb96bb998dfa037a56d2b2405958b4
import pandas as pd
import numpy as np
from pathlib import Path

try:
    import pywifi
except ImportError:
    pywifi = None

from active_mitigation import trigger_quarantine, ActiveMitigationStatus
<<<<<<< HEAD
=======
<<<<<<< HEAD
from crypto_telemetry import append_hash_chain, generate_key_material, encrypt_csv
from scapy_capture import is_scapy_available, run_scapy_sniffer
from deception_engine import HoneypotManager, is_deception_available
=======
>>>>>>> fb2e0dfb94cb96bb998dfa037a56d2b2405958b4
try:
    from crypto_telemetry import append_hash_chain, generate_key_material, encrypt_csv
except ImportError:
    # Telemetry encryption is optional; a missing integration must not prevent
    # the dashboard's background scanner from starting.
    append_hash_chain = None
    generate_key_material = None
    encrypt_csv = None
from scapy_capture import is_scapy_available, run_scapy_sniffer
try:
    from deception_engine import HoneypotManager, is_deception_available
except ImportError:
    HoneypotManager = None

    def is_deception_available():
        return False

from signal_analyzer import AdvancedSignalAnalyzer
from adaptive_thresholds import AdaptiveThresholdEngine
from threat_intelligence import get_threat_intelligence
<<<<<<< HEAD
from cloud_intelligence import CloudIntelligenceEngine
from alert_logger import AlertLogger
from notification_manager import NotificationManager
from sensor_fusion import fuse_sensor_records
from data_validation import repair_project_data
from database_manager import init_database, save_anomaly, save_scan, save_sensor_observation, save_threat
=======
from alert_logger import AlertLogger
>>>>>>> fb2e0dfb94cb96bb998dfa037a56d2b2405958b4
from fingerprinting.fingerprint_generator import create_fingerprint
from fingerprinting.fingerprint_matcher import compare_fingerprint
try:
    from ml_ensemble import HybridEnsembleDetector
except ImportError:
    HybridEnsembleDetector = None
<<<<<<< HEAD
try:
    from ai_models.isolation_forest_detector import IsolationForestDetector
except ImportError:
    IsolationForestDetector = None
=======
>>>>>>> 0d1f8da (Updated SentinelShield project)
>>>>>>> fb2e0dfb94cb96bb998dfa037a56d2b2405958b4
try:
    from federated_node import FederatedNodeAgent
except ImportError:
    FederatedNodeAgent = None

try:
    from localization import SignalLocalizer
except ImportError:
    SignalLocalizer = None

try:
    from gnn_analyzer import GraphAnalyzer
except ImportError:
    GraphAnalyzer = None

class ScanStatus:
    IDLE = "idle"
    SCANNING = "scanning"
    ANALYZING = "analyzing"
    COMPLETE = "complete"
    ERROR = "error"

class BackgroundScanner:
    def __init__(self):
        self._lock = threading.Lock()
        self.status = ScanStatus.IDLE
        self.progress = 0
        self.networks_found = 0
        self.start_time = None
        self.end_time = None
        self.elapsed_time = 0.0
        self.error_msg = ""
        self.results = {"networks": []}
        self.active_response = False
        self.sdn_controller_url = "http://127.0.0.1:8080/stats/flowentry/add"
        self.ovs_bridge = "virbr0"
        self.scapy_enabled = False
        self.honeypot_enabled = False
        self.honeypot_profile = "Open Legacy"
        self.honeypot_interface = "wlan0mon"
<<<<<<< HEAD
=======
<<<<<<< HEAD
        self.honeypot_manager = HoneypotManager(interface=self.honeypot_interface) if is_deception_available() else None
        self.graph_analyzer = GraphAnalyzer() if GraphAnalyzer is not None else None
        self.localizer = SignalLocalizer() if SignalLocalizer is not None else None
=======
>>>>>>> fb2e0dfb94cb96bb998dfa037a56d2b2405958b4
        self.honeypot_manager = HoneypotManager(interface=self.honeypot_interface) if HoneypotManager and is_deception_available() else None
        self.graph_analyzer = GraphAnalyzer() if GraphAnalyzer is not None else None
        self.localizer = SignalLocalizer() if SignalLocalizer is not None else None
        self.signal_analyzer = AdvancedSignalAnalyzer()
        self.adaptive_thresholds = AdaptiveThresholdEngine()
        self.cloud_intelligence = get_threat_intelligence()
<<<<<<< HEAD
        self.intelligence_engine = CloudIntelligenceEngine()
        self.alert_logger = AlertLogger()
        self.notifier = NotificationManager()
        self.ml_ensemble = None
        self._ml_ensemble_loaded = False
        self.isolation_forest = None
        self._isolation_forest_loaded = False
        self.detection_weights = self._load_detection_weights()
        self.anomaly_logger = logging.getLogger("sentinelshield.anomaly")
        if not self.anomaly_logger.handlers:
            Path("logs").mkdir(exist_ok=True)
            handler = logging.FileHandler(Path("logs/anomaly_detection.log"), encoding="utf-8")
            handler.setFormatter(logging.Formatter("%(asctime)s | %(message)s"))
            self.anomaly_logger.addHandler(handler)
            self.anomaly_logger.setLevel(logging.INFO)
        self.telemetry_key_path = Path("telemetry_key.bin")
        self.hash_chain = None
        self.scan_log = []
        self.scan_mode = "live"
        self.last_scan_time = None
        repair_project_data()
        init_database()

=======
        self.alert_logger = AlertLogger()
        self.ml_ensemble = None
        self._ml_ensemble_loaded = False
>>>>>>> 0d1f8da (Updated SentinelShield project)
        self.telemetry_key_path = Path("telemetry_key.bin")
        self.hash_chain = None
        self.scan_log = []

<<<<<<< HEAD
    def load_or_create_key(self):
=======
>>>>>>> fb2e0dfb94cb96bb998dfa037a56d2b2405958b4
    @staticmethod
    def _load_ml_ensemble():
        """Load trained ensemble models when available without blocking scans."""
        if HybridEnsembleDetector is None:
            return None
        try:
            ensemble = HybridEnsembleDetector()
            return ensemble if ensemble.load_models() else None
        except Exception:
            return None

<<<<<<< HEAD
    @staticmethod
    def _load_detection_weights():
        """Load validated hybrid weights; retain safe defaults on bad config."""
        defaults = {"random_forest": 0.35, "knn": 0.25, "isolation_forest": 0.25, "rule_score": 0.15}
        try:
            configured = json.loads(Path("config/detection_weights.json").read_text(encoding="utf-8"))
            weights = {key: float(configured[key]) for key in defaults}
            total = sum(weights.values())
            return {key: value / total for key, value in weights.items()} if total > 0 else defaults
        except (OSError, ValueError, KeyError, TypeError):
            return defaults

    def _isolation_forest_prediction(self, features):
        if not self._isolation_forest_loaded:
            detector = IsolationForestDetector() if IsolationForestDetector is not None else None
            self.isolation_forest = detector if detector is not None and detector.load() else None
            self._isolation_forest_loaded = True
        return self.isolation_forest.predict(features) if self.isolation_forest is not None else None

    def _hybrid_risk(self, rule_score, ml_prediction, anomaly_prediction):
        rf_score = 100.0 if ml_prediction and ml_prediction.get("rf_prediction") == "Fake" else 0.0
        knn_score = 100.0 if ml_prediction and ml_prediction.get("knn_prediction") == "Fake" else 0.0
        anomaly_score = 100.0 * float(anomaly_prediction["anomaly_score"]) if anomaly_prediction else 0.0
        weights = self.detection_weights
        return min(100.0, (rf_score * weights["random_forest"] + knn_score * weights["knn"] + anomaly_score * weights["isolation_forest"] + float(rule_score) * weights["rule_score"]))

    def load_or_create_key(self):
        if generate_key_material is None:
            return None
=======
    def load_or_create_key(self):
        if generate_key_material is None:
            return None
>>>>>>> 0d1f8da (Updated SentinelShield project)
>>>>>>> fb2e0dfb94cb96bb998dfa037a56d2b2405958b4
        if not self.telemetry_key_path.exists():
            key = generate_key_material()
            self.telemetry_key_path.write_bytes(key)
            return key
        try:
            return self.telemetry_key_path.read_bytes()
        except Exception:
            return generate_key_material()

    def get_status(self):
        with self._lock:
            if self.status in [ScanStatus.SCANNING, ScanStatus.ANALYZING] and self.start_time:
                self.elapsed_time = time.time() - self.start_time
            return {
                "status": self.status,
                "progress": self.progress,
                "networks_found": self.networks_found,
                "elapsed_time": self.elapsed_time,
<<<<<<< HEAD
                "error": self.error_msg,
                "scan_mode": self.scan_mode,
                "last_scan_time": self.last_scan_time,
=======
                "error": self.error_msg
>>>>>>> fb2e0dfb94cb96bb998dfa037a56d2b2405958b4
            }

    def get_results(self):
        with self._lock:
            return self.results

    def get_telemetry_info(self):
        return {
            "hash_chain": self.hash_chain,
            "telemetry_files": ["current_scan.csv", "wifi_dataset.csv"],
            "encrypted_copy_exists": Path("current_scan.csv.enc").exists(),
        }

<<<<<<< HEAD
=======
<<<<<<< HEAD
=======
>>>>>>> fb2e0dfb94cb96bb998dfa037a56d2b2405958b4
    def get_adaptive_threshold_info(self):
        """Current learned baseline + CRITICAL/HIGH/MEDIUM cut points,
        usable by the dashboard (e.g. a Settings panel) without needing
        to wait for a fresh scan."""
        with self._lock:
            return self.adaptive_thresholds.summary()

    def reset_adaptive_thresholds(self):
        """Discard the learned baseline and fall back to the original
        fixed 75/50/30 thresholds until enough new scans come in."""
        with self._lock:
            self.adaptive_thresholds.reset()

<<<<<<< HEAD
    def _collect_wifi_results(self, rounds: int = 4, interval: float = 2.0):
        if pywifi is None:
            return self._demo_scan_records("pywifi is not installed")

        try:
            wifi = pywifi.PyWiFi()
        except Exception as exc:
            return self._demo_scan_records(f"Wi-Fi adapter initialization failed: {exc}")
        interfaces = [iface for iface in wifi.interfaces() if iface is not None]
        if not interfaces:
            return self._demo_scan_records("No supported Wi-Fi adapter was detected")
=======
>>>>>>> 0d1f8da (Updated SentinelShield project)
    def _collect_wifi_results(self, rounds: int = 4, interval: float = 2.0):
        if pywifi is None:
            raise RuntimeError("pywifi is required for live Wi-Fi scanning but is not installed.")

        wifi = pywifi.PyWiFi()
        interfaces = [iface for iface in wifi.interfaces() if iface is not None]
        if not interfaces:
            raise RuntimeError("No valid Wi-Fi interface found. Ensure a wireless adapter is present and supported.")

        iface = interfaces[0]
        if iface is None:
            raise RuntimeError("Invalid Wi-Fi interface handle returned by pywifi.")
>>>>>>> fb2e0dfb94cb96bb998dfa037a56d2b2405958b4

        network_map = {}

        for round_idx in range(rounds):
<<<<<<< HEAD
            active_interfaces = []
            for index, iface in enumerate(interfaces, start=1):
                try:
                    iface.scan()
                    active_interfaces.append((index, iface))
                except Exception as exc:
                    self.scan_log.append(f"Sensor {index} scan unavailable: {exc}")
            if not active_interfaces:
                return self._demo_scan_records("No Wi-Fi adapter could start a scan")

            time.sleep(interval)
            for index, iface in active_interfaces:
                sensor_id = getattr(iface, "name", lambda: None)()
                sensor_id = str(sensor_id or f"wifi-adapter-{index}")
                try:
                    results = iface.scan_results() or []
                except Exception as exc:
                    self.scan_log.append(f"Sensor {sensor_id} results unavailable: {exc}")
                    continue
                with self._lock:
                    self.progress = min(40, int(((round_idx + 1) / rounds) * 40))
                    self.scan_log.append(f"Sensor {sensor_id}, pass {round_idx + 1}/{rounds}: {len(results)} networks detected.")
                for net in results:
                    ssid = getattr(net, "ssid", None)
                    if isinstance(ssid, bytes):
                        try:
                            ssid = ssid.decode("utf-8", errors="ignore")
                        except Exception:
                            ssid = ssid.decode("latin1", errors="ignore")

                    bssid = getattr(net, "bssid", None) or "unknown"
                    if not ssid:
                        continue

                    key = (sensor_id, ssid, bssid)
                    entry = network_map.get(key)
                    if entry is None:
                        entry = {
                            "SSID": ssid,
                            "BSSID": bssid,
                            "Sensor_ID": sensor_id,
                            "RSSI_values": [],
                            "Channels": [],
                            "Securities": [],
                        }
                        network_map[key] = entry

                    signal_value = getattr(net, "signal", None)
                    if signal_value is None:
                        signal_value = 0
                    try:
                        signal_value = float(signal_value)
                    except Exception:
                        signal_value = 0

                    entry["RSSI_values"].append(signal_value)
                    entry["Channels"].append(getattr(net, "freq", None))
                    akm = getattr(net, "akm", None)
                    security = "OPEN" if not akm else "WPA2"
                    entry["Securities"].append(security)

        return fuse_sensor_records(list(network_map.values()))

    def _demo_scan_records(self, reason):
        """Keep the UI and analysis pipeline usable without pywifi hardware."""
        self.scan_mode = "demo"
        self.scan_log.append(f"Demo scan enabled: {reason}.")
        return [
            {"SSID": "OfficeWiFi", "BSSID": "00:11:22:33:44:55", "RSSI_values": [-64, -63, -65, -64], "Channels": [2412] * 4, "Securities": ["WPA2"] * 4, "Sensor_IDs": ["demo-sensor-1"], "Sensor_Count": 1, "Sensor_Agreement_dBm": 0.0, "Sensor_Observations": [{"sensor_id": "demo-sensor-1", "rssi": -64.0, "channel": 2412}]},
            {"SSID": "OfficeWiFi", "BSSID": "AA:BB:CC:11:22:33", "RSSI_values": [-28, -53, -31, -55], "Channels": [2412, 2437, 2412, 2437], "Securities": ["OPEN"] * 4, "Sensor_IDs": ["demo-sensor-1"], "Sensor_Count": 1, "Sensor_Agreement_dBm": 0.0, "Sensor_Observations": [{"sensor_id": "demo-sensor-1", "rssi": -41.75, "channel": 2412}]},
            {"SSID": "GuestWiFi", "BSSID": "66:77:88:99:AA:BB", "RSSI_values": [-78, -77, -79, -78], "Channels": [5180] * 4, "Securities": ["WPA2"] * 4, "Sensor_IDs": ["demo-sensor-1"], "Sensor_Count": 1, "Sensor_Agreement_dBm": 0.0, "Sensor_Observations": [{"sensor_id": "demo-sensor-1", "rssi": -78.0, "channel": 5180}]},
        ]

    def _ml_ensemble_prediction(self, avg_rssi, channel, security, ap_count, signal_variation):
        """Return the live model prediction and normalized XAI vector."""
=======
            try:
                iface.scan()
            except Exception as exc:
                raise RuntimeError(f"Wi-Fi scan call failed: {exc}") from exc

            time.sleep(interval)
            try:
                results = iface.scan_results() or []
            except Exception as exc:
                raise RuntimeError(f"Wi-Fi scan results retrieval failed: {exc}") from exc

            scan_count = len(results)
            with self._lock:
                self.progress = min(40, int((round_idx / rounds) * 40))
                self.scan_log.append(f"Wi-Fi scan pass {round_idx + 1}/{rounds}: {scan_count} networks detected.")

            for net in results:
                ssid = getattr(net, "ssid", None)
                if isinstance(ssid, bytes):
                    try:
                        ssid = ssid.decode("utf-8", errors="ignore")
                    except Exception:
                        ssid = ssid.decode("latin1", errors="ignore")

                bssid = getattr(net, "bssid", None) or "unknown"
                if not ssid:
                    continue

                key = (ssid, bssid)
                entry = network_map.get(key)
                if entry is None:
                    entry = {
                        "SSID": ssid,
                        "BSSID": bssid,
                        "RSSI_values": [],
                        "Channels": [],
                        "Securities": [],
                    }
                    network_map[key] = entry

                signal_value = getattr(net, "signal", None)
                if signal_value is None:
                    signal_value = 0
                try:
                    signal_value = float(signal_value)
                except Exception:
                    signal_value = 0

                entry["RSSI_values"].append(signal_value)
                entry["Channels"].append(getattr(net, "freq", None))
                akm = getattr(net, "akm", None)
                security = "OPEN" if not akm else "WPA2"
                entry["Securities"].append(security)

        return list(network_map.values())

<<<<<<< HEAD
=======
    def _ml_ensemble_score(self, avg_rssi, channel, security, ap_count, signal_variation):
        """Return the trained ensemble's 0-100 risk, or a neutral score if unavailable."""
>>>>>>> fb2e0dfb94cb96bb998dfa037a56d2b2405958b4
        if not self._ml_ensemble_loaded:
            self.ml_ensemble = self._load_ml_ensemble()
            self._ml_ensemble_loaded = True
        if self.ml_ensemble is None:
<<<<<<< HEAD
            return None
=======
            return 50.0
>>>>>>> fb2e0dfb94cb96bb998dfa037a56d2b2405958b4
        prediction = self.ml_ensemble.predict({
            "RSSI": avg_rssi,
            "Channel": channel or 1,
            "Security": security,
            "AP_Count": ap_count,
            "Signal_Var": signal_variation,
        })
<<<<<<< HEAD
        return prediction

    @staticmethod
    def calculate_combined_risk(rule_risk, ml_risk, cloud_risk=0.0, bssid_reputation=0.0):
        """Combine rule, ML, local reputation, and optional cloud intelligence."""
        return (
            (float(ml_risk) * 0.40)
            + (float(rule_risk) * 0.30)
            + (float(cloud_risk) * 0.20)
            + (float(bssid_reputation) * 0.10)
        )

=======
        if prediction is None:
            return 50.0
        return float(prediction["ensemble_risk"])

    @staticmethod
    def calculate_combined_risk(rule_based, signal_pattern, ml_ensemble):
        """Combine the independent detection engines using the documented weights."""
        return (
            (float(rule_based) * 0.40)
            + (float(signal_pattern) * 0.30)
            + (float(ml_ensemble) * 0.30)
        )

>>>>>>> 0d1f8da (Updated SentinelShield project)
>>>>>>> fb2e0dfb94cb96bb998dfa037a56d2b2405958b4
    def set_active_response(self, enabled: bool):
        with self._lock:
            self.active_response = enabled

    def set_scapy_enabled(self, enabled: bool):
        with self._lock:
            self.scapy_enabled = enabled

    def set_honeypot_enabled(self, enabled: bool):
        with self._lock:
            self.honeypot_enabled = enabled

    def set_honeypot_profile(self, profile: str):
        with self._lock:
            self.honeypot_profile = profile
            if self.honeypot_manager is not None:
                self.honeypot_manager.set_profile(profile)

    def set_honeypot_interface(self, interface: str):
        with self._lock:
            self.honeypot_interface = interface
            if self.honeypot_manager is not None:
                self.honeypot_manager.interface = interface

    def start_scan_async(self):
        with self._lock:
            if self.status in [ScanStatus.SCANNING, ScanStatus.ANALYZING]:
                return False  # Scan already in progress
            
            self.status = ScanStatus.SCANNING
            self.progress = 0
            self.networks_found = 0
            self.start_time = time.time()
            self.end_time = None
            self.error_msg = ""
<<<<<<< HEAD
            self.scan_log = []
            self.scan_mode = "live"
=======
>>>>>>> fb2e0dfb94cb96bb998dfa037a56d2b2405958b4
            
        # Spawn execution worker loop in background thread
        thread = threading.Thread(target=self._run_scan_worker, daemon=True)
        thread.start()
        return True

    def _run_scan_worker(self):
        try:
            if self.honeypot_enabled and self.honeypot_manager is not None:
                self.honeypot_manager.set_profile(self.honeypot_profile)
                self.honeypot_manager.interface = self.honeypot_interface
                if self.honeypot_manager.start():
                    self.scan_log.append(f"Honeypot grid initialized: {self.honeypot_profile} on {self.honeypot_interface}")
                else:
                    self.scan_log.append("Honeypot grid already running or unavailable.")

            # 1. Passive Wi-Fi scan using the real wireless adapter
            scan_records = self._collect_wifi_results(rounds=4, interval=2.0)

            with self._lock:
                self.status = ScanStatus.ANALYZING
                self.progress = 45

            ssid_counts = {}
            for record in scan_records:
                ssid_counts[record["SSID"]] = ssid_counts.get(record["SSID"], 0) + 1

            networks_list = []
<<<<<<< HEAD
            # Refresh once per scan cycle.  The service itself enforces its
            # periodic sync interval, so this never adds repeated cloud calls.
            self.cloud_intelligence.sync_feed()
=======
<<<<<<< HEAD
=======
            # Refresh once per scan cycle.  The service itself enforces its
            # periodic sync interval, so this never adds repeated cloud calls.
            self.cloud_intelligence.sync_feed()
>>>>>>> 0d1f8da (Updated SentinelShield project)
>>>>>>> fb2e0dfb94cb96bb998dfa037a56d2b2405958b4
            if self.scapy_enabled and is_scapy_available():
                self.scan_log.append("Scapy sniffing enabled: starting monitor-mode capture")
                run_scapy_sniffer(interface='wlan0', packet_count=50, timeout=20, output_path='scapy_capture.log')

            for idx, record in enumerate(scan_records):
                avg_rssi = float(sum(record["RSSI_values"]) / len(record["RSSI_values"]))
                signal_variation = max(record["RSSI_values"]) - min(record["RSSI_values"]) if record["RSSI_values"] else 0
                channel = max(set(record["Channels"]), key=record["Channels"].count) if record["Channels"] else None
                security = "OPEN" if "OPEN" in record["Securities"] else "WPA2"
                multi_bssid_risk = 10.0 if ssid_counts.get(record["SSID"], 0) > 1 else 0.0
<<<<<<< HEAD
                sensor_count = int(record.get("Sensor_Count", 1))
                sensor_agreement = float(record.get("Sensor_Agreement_dBm", 0.0))
=======
>>>>>>> fb2e0dfb94cb96bb998dfa037a56d2b2405958b4

                threat_score = 5.0
                threat_score += 30.0 if security == "OPEN" else 8.0
                threat_score += 20.0 if avg_rssi > -60 else 10.0 if avg_rssi > -75 else 0.0
                threat_score += 10.0 if signal_variation > 12 else 0.0
<<<<<<< HEAD
                # Widely different readings from colocated physical sensors
                # can indicate a mobile transmitter, directional spoofing, or
                # unreliable sensor placement. It is a bounded, explainable signal.
                threat_score += 8.0 if sensor_count >= 2 and sensor_agreement > 18 else 0.0
                threat_score += multi_bssid_risk
                threat_score = min(100.0, threat_score)

                signal_pattern_score = float(
                    self.signal_analyzer.analyze_rssi_pattern(record["RSSI_values"])["pattern_anomaly_score"]
                )
                ml_prediction = self._ml_ensemble_prediction(
                    avg_rssi, channel, security, ssid_counts.get(record["SSID"], 1), signal_variation
                )
                ml_ensemble_score = float(ml_prediction["ensemble_risk"]) if ml_prediction else 50.0
                local_intel = self.intelligence_engine.evaluate_network(record["SSID"], record["BSSID"])
                rule_risk = (threat_score + signal_pattern_score) / 2
                anomaly_prediction = self._isolation_forest_prediction({
                    "RSSI": avg_rssi, "Signal_Var": signal_variation, "Channel": channel,
                    "Security": security, "AP_Count": ssid_counts.get(record["SSID"], 1),
                    "MAC_Similarity": 100.0 if multi_bssid_risk else 0.0,
                    "BSSID_Reputation": local_intel["bssid_reputation"]["risk_score"],
                    "Threat_Score": rule_risk, "SSID": record["SSID"],
                    "Hidden_SSID_Flag": int(not record["SSID"].strip()),
                    "Temporal_Signal_Fluctuation": signal_variation,
                })
                combined_risk = self._hybrid_risk(rule_risk, ml_prediction, anomaly_prediction)
=======
                threat_score += multi_bssid_risk
                threat_score = min(100.0, threat_score)

<<<<<<< HEAD
                if threat_score >= 75:
                    threat_level = "CRITICAL"
                elif threat_score >= 50:
                    threat_level = "HIGH"
                elif threat_score >= 30:
                    threat_level = "MEDIUM"
                else:
                    threat_level = "SAFE"
=======
                signal_pattern_score = float(
                    self.signal_analyzer.analyze_rssi_pattern(record["RSSI_values"])["pattern_anomaly_score"]
                )
                ml_ensemble_score = self._ml_ensemble_score(
                    avg_rssi, channel, security, ssid_counts.get(record["SSID"], 1), signal_variation
                )
                combined_risk = self.calculate_combined_risk(
                    threat_score, signal_pattern_score, ml_ensemble_score
                )
>>>>>>> fb2e0dfb94cb96bb998dfa037a56d2b2405958b4
                cloud_reputation = self.cloud_intelligence.lookup(record["BSSID"])
                cloud_boost = 0.0
                if cloud_reputation["hit"]:
                    # Cloud confirmation is an additional feature, not a
                    # replacement for the existing RF/KNN/RSSI pipeline.
                    cloud_boost = min(35.0, 15.0 + cloud_reputation["risk_score"] * 0.20)
                    combined_risk = min(100.0, combined_risk + cloud_boost)
<<<<<<< HEAD
=======
>>>>>>> 0d1f8da (Updated SentinelShield project)
>>>>>>> fb2e0dfb94cb96bb998dfa037a56d2b2405958b4

                vectors = {
                    "Scan Consistency": max(0.0, 100.0 - signal_variation),
                    "Open Network": 90.0 if security == "OPEN" else 15.0,
                    "RSSI Proximity": 100.0 if avg_rssi > -65 else 50.0,
                    "Multi-BSSID": 80.0 if multi_bssid_risk else 10.0,
                    "Channel Flux": 40.0 if len(set(record["Channels"])) > 1 else 5.0,
<<<<<<< HEAD
                    "Physical Sensor Count": sensor_count,
                    "Sensor RSSI Disagreement": sensor_agreement,
=======
<<<<<<< HEAD
                }
=======
>>>>>>> fb2e0dfb94cb96bb998dfa037a56d2b2405958b4
                    "Cloud Reputation": cloud_boost,
                }
                fingerprint_similarity = compare_fingerprint({
                    "SSID": record["SSID"], "BSSID": record["BSSID"],
                    "Channel": channel, "Security": security,
                })["similarity"]
<<<<<<< HEAD
=======
>>>>>>> 0d1f8da (Updated SentinelShield project)
>>>>>>> fb2e0dfb94cb96bb998dfa037a56d2b2405958b4

                net_obj = {
                    "SSID": record["SSID"],
                    "BSSID": record["BSSID"],
                    "RSSI": round(avg_rssi, 1),
                    "Channel": channel,
                    "Security": security,
<<<<<<< HEAD
=======
<<<<<<< HEAD
                    "Threat_Level": threat_level,
                    "Threat_Score": round(threat_score, 1),
                    "ML_Risk": round(threat_score * 0.8, 1),
                    "Combined_Risk": round(threat_score, 1),
=======
>>>>>>> fb2e0dfb94cb96bb998dfa037a56d2b2405958b4
                    "Threat_Score": round(threat_score, 1),
                    "Signal_Pattern_Score": round(signal_pattern_score, 1),
                    "ML_Risk": round(ml_ensemble_score, 1),
                    "Combined_Risk": round(combined_risk, 1),
<<<<<<< HEAD
                    "Isolation_Forest": anomaly_prediction["prediction"] if anomaly_prediction else "Unavailable",
                    "Anomaly_Score": anomaly_prediction["anomaly_score"] if anomaly_prediction else None,
                    "Anomaly_Confidence": anomaly_prediction["confidence"] if anomaly_prediction else None,
                    "Cloud_Reputation_Hit": cloud_reputation["hit"],
                    "Cloud_Risk_Score": round(cloud_reputation["risk_score"], 1),
                    "Cloud_Threat_Type": cloud_reputation["threat_type"],
                    "Cloud_Risk": local_intel["cloud_risk"],
                    "VirusTotal_Risk": local_intel["virustotal"]["risk_score"],
                    "AbuseIPDB_Risk": local_intel["abuseipdb"]["abuse_score"],
                    "BSSID_Reputation": local_intel["bssid_reputation"]["risk_score"],
                    "OpenPhish_Risk": local_intel["phishing_risk"]["risk_score"],
                    "Fingerprint_Similarity": fingerprint_similarity,
                    "RF_Prediction": ml_prediction.get("rf_prediction", "Unavailable") if ml_prediction else "Unavailable",
                    "KNN_Prediction": ml_prediction.get("knn_prediction", "Unavailable") if ml_prediction else "Unavailable",
                    "XAI_Contributions": json.dumps(ml_prediction.get("feature_contributions", {})) if ml_prediction else "{}",
                    "Threat_Vectors": json.dumps(vectors),
                    "Signal_History": record["RSSI_values"],
                    "Sensor_Observations": record.get("Sensor_Observations", []),
                    "Sensor_IDs": record.get("Sensor_IDs", []),
                    "Sensor_Count": sensor_count,
                    "Sensor_Agreement_dBm": sensor_agreement,
                    "AP_Count": ssid_counts.get(record["SSID"], 1),
                    "Signal_Var": round(signal_variation, 1),
=======
                    "Cloud_Reputation_Hit": cloud_reputation["hit"],
                    "Cloud_Risk_Score": round(cloud_reputation["risk_score"], 1),
                    "Cloud_Threat_Type": cloud_reputation["threat_type"],
                    "Fingerprint_Similarity": fingerprint_similarity,
>>>>>>> 0d1f8da (Updated SentinelShield project)
                    "RF_Prediction": "Malicious" if threat_score > 50 else "Normal",
                    "KNN_Prediction": "Malicious" if threat_score > 40 else "Normal",
                    "Threat_Vectors": json.dumps(vectors),
                    "Signal_History": record["RSSI_values"],
>>>>>>> fb2e0dfb94cb96bb998dfa037a56d2b2405958b4
                }
                networks_list.append(net_obj)

                with self._lock:
                    self.progress = 45 + int(((idx + 1) / max(1, len(scan_records))) * 40)
                    self.networks_found = len(networks_list)
                time.sleep(0.1)

<<<<<<< HEAD
=======
<<<<<<< HEAD
            # Save dataset matrix real-time down to localized static storage csv
            df = pd.DataFrame(networks_list)
            df.to_csv("current_scan.csv", index=False)
            self.hash_chain = append_hash_chain("current_scan.csv", previous_hash=self.hash_chain)
            self.scan_log.append(f"Telemetry hash chain appended: {self.hash_chain[:12]}...")
=======
>>>>>>> fb2e0dfb94cb96bb998dfa037a56d2b2405958b4
            # ================= ADAPTIVE DETECTION THRESHOLDS =================
            # Feed this scan cycle's Combined_Risk scores into the running
            # baseline for this deployment, then classify every network
            # against the freshly-derived CRITICAL/HIGH/MEDIUM cut points
            # instead of the old fixed 75/50/30 constants. See
            # adaptive_thresholds.py for the full rationale.
            self.adaptive_thresholds.update(n["Combined_Risk"] for n in networks_list)
            threshold_summary = self.adaptive_thresholds.summary()
            for net in networks_list:
                threat_level, thresholds, mode = self.adaptive_thresholds.classify(net["Combined_Risk"])
                net["Threat_Level"] = threat_level
                net["Threshold_Mode"] = mode  # "warming_up" or "adaptive"

            for net in networks_list:
<<<<<<< HEAD
                save_scan(net)
                for observation in net.get("Sensor_Observations", []):
                    save_sensor_observation({
                        "sensor_id": observation["sensor_id"], "SSID": net["SSID"], "BSSID": net["BSSID"],
                        "rssi": observation["rssi"], "channel": observation["channel"],
                    })
                if net.get("Isolation_Forest") == "ANOMALY":
                    save_anomaly({
                        "SSID": net["SSID"], "BSSID": net["BSSID"],
                        "Anomaly_Score": net["Anomaly_Score"], "Anomaly_Confidence": net["Anomaly_Confidence"],
                        "Threat_Level": net["Threat_Level"],
                    })
                    self.anomaly_logger.info(
                        "ssid=%s bssid=%s anomaly_score=%.4f confidence=%.4f threat_level=%s",
                        net["SSID"], net["BSSID"], net["Anomaly_Score"], net["Anomaly_Confidence"], net["Threat_Level"],
                    )
                if net["Threat_Level"] in {"HIGH", "CRITICAL"}:
                    self.intelligence_engine.learn_threat(net["BSSID"], net["Combined_Risk"])
                    save_threat({
                        "ssid": net["SSID"], "bssid": net["BSSID"], "threat_type": net.get("Cloud_Threat_Type") or net["Threat_Level"], "risk_score": net["Combined_Risk"],
                    })
                    reason = "Cloud reputation hit" if net["Cloud_Reputation_Hit"] else "Risk score exceeded adaptive threshold"
                    self.alert_logger.log_alert(net["SSID"], net["BSSID"], net["Combined_Risk"], reason)
                    self.notifier.notify_threat(net["SSID"], net["BSSID"], net["Combined_Risk"], reason)
=======
                if net["Threat_Level"] in {"HIGH", "CRITICAL"}:
                    reason = "Cloud reputation hit" if net["Cloud_Reputation_Hit"] else "Risk score exceeded adaptive threshold"
                    self.alert_logger.log_alert(net["SSID"], net["BSSID"], net["Combined_Risk"], reason)
>>>>>>> fb2e0dfb94cb96bb998dfa037a56d2b2405958b4
                elif net["Threat_Level"] == "SAFE":
                    create_fingerprint(net)

            # Publish only classified high-confidence detections.  Uploads
            # are non-blocking from a correctness perspective: offline mode
            # simply returns False and local detection remains intact.
            uploads = 0
            for net in networks_list:
                if net["Threat_Level"] in {"HIGH", "CRITICAL"}:
                    threat_type = net.get("Cloud_Threat_Type") or "Suspected Rogue Access Point"
                    if self.cloud_intelligence.upload_rogue_ap(
                        net["SSID"], net["BSSID"], net["Combined_Risk"], threat_type
                    ):
                        uploads += 1
            if uploads:
                self.scan_log.append(f"Cloud intelligence: shared {uploads} rogue AP detection(s).")
            self.scan_log.append(
                f"Adaptive thresholds ({threshold_summary['mode']}, "
                f"{threshold_summary['samples_seen']} samples): "
                f"CRITICAL>={threshold_summary['thresholds']['critical']}, "
                f"HIGH>={threshold_summary['thresholds']['high']}, "
                f"MEDIUM>={threshold_summary['thresholds']['medium']}"
            )

            # Save dataset matrix real-time down to localized static storage csv
<<<<<<< HEAD
            df = pd.DataFrame(networks_list, columns=[
                "SSID", "BSSID", "RSSI", "Channel", "Security", "AP_Count", "Signal_Var",
                "Threat_Score", "Combined_Risk", "Threat_Level",
            ])
            df.to_csv("current_scan.csv", index=False)
            history_path = Path("scan_history.csv")
            history = pd.DataFrame({
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "ssid": df["SSID"],
                "threat_score": df["Threat_Score"],
                "combined_risk": df["Combined_Risk"],
            })
            history.to_csv(history_path, mode="a", header=not history_path.exists(), index=False)
            training_rows = pd.DataFrame({
                "SSID": df["SSID"], "BSSID": df["BSSID"], "RSSI": df["RSSI"], "Channel": df["Channel"],
                "Security": df["Security"], "AP_Count": df["AP_Count"], "Signal_Var": df["Signal_Var"],
                "Label": df["Threat_Level"].map({"SAFE": "Legit", "MEDIUM": "Fake", "HIGH": "Fake", "CRITICAL": "Fake"}),
            })
            training_path = Path("training_dataset.csv")
            existing_training = pd.read_csv(training_path, on_bad_lines="skip") if training_path.exists() else pd.DataFrame()
            pd.concat([existing_training, training_rows], ignore_index=True).drop_duplicates(subset=["BSSID"], keep="last").to_csv(training_path, index=False)
            if append_hash_chain is not None:
                self.hash_chain = append_hash_chain("current_scan.csv", previous_hash=self.hash_chain)
                self.scan_log.append(f"Telemetry hash chain appended: {self.hash_chain[:12]}...")
=======
            df = pd.DataFrame(networks_list)
            df.to_csv("current_scan.csv", index=False)
            if append_hash_chain is not None:
                self.hash_chain = append_hash_chain("current_scan.csv", previous_hash=self.hash_chain)
                self.scan_log.append(f"Telemetry hash chain appended: {self.hash_chain[:12]}...")
>>>>>>> 0d1f8da (Updated SentinelShield project)
>>>>>>> fb2e0dfb94cb96bb998dfa037a56d2b2405958b4

            # === STEP 3 LOGIC: ASYNC FEDERATED WEIGHT EXTRACTION EXECUTOR ===
            try:
                if FederatedNodeAgent is not None:
                    node_agent = FederatedNodeAgent(node_id="NODE_OM007")
                    nn_model = globals().get("nn_model", None)
                    if nn_model is not None:
                        local_weights = node_agent.extract_local_weights(nn_model)
                        node_agent.compile_encrypted_payload(local_weights)
                        self.scan_log.append("Federated payload compiled for NODE_OM007.")
                    else:
                        self.scan_log.append("Federated payload skipped: nn_model not available.")
                else:
                    self.scan_log.append("Federated payload skipped: FederatedNodeAgent unavailable.")
            except Exception as exc:
                self.scan_log.append(f"Federated payload generation error: {exc}")
                pass  # Suppress processing alerts during local framework simulation testing

            # Persist encrypted copies for tamper-evident storage when key is available
            try:
                telemetry_key = self.load_or_create_key()
<<<<<<< HEAD
                if telemetry_key is not None and encrypt_csv is not None:
                    encrypt_csv("current_scan.csv", telemetry_key, output_path="current_scan.csv.enc")
                    self.scan_log.append("Encrypted current_scan.csv to current_scan.csv.enc")
=======
<<<<<<< HEAD
                encrypt_csv("current_scan.csv", telemetry_key, output_path="current_scan.csv.enc")
                self.scan_log.append("Encrypted current_scan.csv to current_scan.csv.enc")
=======
                if telemetry_key is not None and encrypt_csv is not None:
                    encrypt_csv("current_scan.csv", telemetry_key, output_path="current_scan.csv.enc")
                    self.scan_log.append("Encrypted current_scan.csv to current_scan.csv.enc")
>>>>>>> 0d1f8da (Updated SentinelShield project)
>>>>>>> fb2e0dfb94cb96bb998dfa037a56d2b2405958b4
            except Exception as exc:
                self.scan_log.append(f"Telemetry encryption skipped: {exc}")

            hist_path = Path("wifi_dataset.csv")
            if not hist_path.exists():
                hist_df = df.copy()
                if "Threat_Level" in hist_df.columns:
                    hist_df = hist_df.rename(columns={"Threat_Level": "Label"})
                hist_df.to_csv("wifi_dataset.csv", index=False)
                try:
                    telemetry_key = self.load_or_create_key()
<<<<<<< HEAD
                    if telemetry_key is not None and encrypt_csv is not None:
                        encrypt_csv("wifi_dataset.csv", telemetry_key, output_path="wifi_dataset.csv.enc")
                        self.scan_log.append("Encrypted wifi_dataset.csv to wifi_dataset.csv.enc")
=======
<<<<<<< HEAD
                    encrypt_csv("wifi_dataset.csv", telemetry_key, output_path="wifi_dataset.csv.enc")
                    self.scan_log.append("Encrypted wifi_dataset.csv to wifi_dataset.csv.enc")
=======
                    if telemetry_key is not None and encrypt_csv is not None:
                        encrypt_csv("wifi_dataset.csv", telemetry_key, output_path="wifi_dataset.csv.enc")
                        self.scan_log.append("Encrypted wifi_dataset.csv to wifi_dataset.csv.enc")
>>>>>>> 0d1f8da (Updated SentinelShield project)
>>>>>>> fb2e0dfb94cb96bb998dfa037a56d2b2405958b4
                except Exception as exc:
                    self.scan_log.append(f"Telemetry encryption skipped for history: {exc}")

            # Persist network graph summary
            if self.graph_analyzer is not None:
                self.graph_analyzer.ingest_network(networks_list)
                graph_summary = self.graph_analyzer.graph_summary()
                high_risk_nodes = self.graph_analyzer.highest_risk_nodes(top_n=5)
            else:
                graph_summary = {"nodes": 0, "edges": 0, "avg_degree": 0}
                high_risk_nodes = []

            # Generate tactical signal localization / heatmap points
            heatmap_points = []
            if self.localizer is not None:
                heatmap_points = self.localizer.build_heatmap_data(networks_list)

            for net in networks_list:
                if self.localizer is not None and net.get("BSSID") and net.get("RSSI") is not None:
                    estimate = self.localizer.estimate_position(net.get("BSSID"), float(net.get("RSSI")), float(net.get("Combined_Risk", 50)))
                    net["Estimated_Distance_m"] = estimate["distance_m"]
                    net["Estimated_Position"] = {"x": estimate["x"], "y": estimate["y"]}
                else:
                    net["Estimated_Distance_m"] = None
                    net["Estimated_Position"] = None

            # Trigger active response for critical detections
            if self.active_response:
                for net in networks_list:
                    if net.get("Threat_Level") == "CRITICAL":
                        target_mac = net.get("BSSID") or net.get("Source")
                        if target_mac:
                            self.scan_log.append(f"Critical threat found: {target_mac}. Triggering quarantine.")
                            trigger_quarantine(target_mac, self.ovs_bridge, self.sdn_controller_url)

            if self.honeypot_manager is not None:
                honeypot_summary = self.honeypot_manager.get_summary()
            else:
                honeypot_summary = {"active": False, "event_count": 0, "profile": self.honeypot_profile}

            with self._lock:
                self.results = {
                    "networks": networks_list,
                    "graph_summary": graph_summary,
                    "high_risk_nodes": high_risk_nodes,
                    "heatmap_points": heatmap_points,
                    "honeypot_summary": honeypot_summary,
                    "honeypot_events": self.honeypot_manager.get_events() if self.honeypot_manager is not None else [],
                    "scan_log": self.scan_log.copy(),
<<<<<<< HEAD
                    "adaptive_thresholds": threshold_summary,
                    "cloud_threat_intelligence": self.cloud_intelligence.status(),
                    "local_cloud_intelligence": self.intelligence_engine.summary(),
                    "scan_mode": self.scan_mode,
                    "scan_timestamp": datetime.now().isoformat(),
                }
                self.status = ScanStatus.COMPLETE
                self.end_time = time.time()
                self.last_scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
=======
<<<<<<< HEAD
=======
                    "adaptive_thresholds": threshold_summary,
                    "cloud_threat_intelligence": self.cloud_intelligence.status(),
>>>>>>> 0d1f8da (Updated SentinelShield project)
                }
                self.status = ScanStatus.COMPLETE
                self.end_time = time.time()
>>>>>>> fb2e0dfb94cb96bb998dfa037a56d2b2405958b4

        except Exception as e:
            if self.honeypot_manager is not None:
                self.honeypot_manager.stop()
            with self._lock:
                self.status = ScanStatus.ERROR
                self.error_msg = str(e)
                self.scan_log.append(f"Scan failure: {self.error_msg}")

# Global Instance Fetcher Singleton Pattern
_scanner_singleton = BackgroundScanner()

def get_scanner():
<<<<<<< HEAD
    return _scanner_singleton
=======
<<<<<<< HEAD
    return _scanner_singleton
=======
    return _scanner_singleton
>>>>>>> 0d1f8da (Updated SentinelShield project)
>>>>>>> fb2e0dfb94cb96bb998dfa037a56d2b2405958b4

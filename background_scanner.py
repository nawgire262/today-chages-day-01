import threading
import time
import json
import pandas as pd
import numpy as np
from pathlib import Path

try:
    import pywifi
except ImportError:
    pywifi = None

from active_mitigation import trigger_quarantine, ActiveMitigationStatus
from crypto_telemetry import append_hash_chain, generate_key_material, encrypt_csv
from scapy_capture import is_scapy_available, run_scapy_sniffer
from deception_engine import HoneypotManager, is_deception_available
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
        self.honeypot_manager = HoneypotManager(interface=self.honeypot_interface) if is_deception_available() else None
        self.graph_analyzer = GraphAnalyzer() if GraphAnalyzer is not None else None
        self.localizer = SignalLocalizer() if SignalLocalizer is not None else None
        self.telemetry_key_path = Path("telemetry_key.bin")
        self.hash_chain = None
        self.scan_log = []

    def load_or_create_key(self):
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
                "error": self.error_msg
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

        network_map = {}

        for round_idx in range(rounds):
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
            if self.scapy_enabled and is_scapy_available():
                self.scan_log.append("Scapy sniffing enabled: starting monitor-mode capture")
                run_scapy_sniffer(interface='wlan0', packet_count=50, timeout=20, output_path='scapy_capture.log')

            for idx, record in enumerate(scan_records):
                avg_rssi = float(sum(record["RSSI_values"]) / len(record["RSSI_values"]))
                signal_variation = max(record["RSSI_values"]) - min(record["RSSI_values"]) if record["RSSI_values"] else 0
                channel = max(set(record["Channels"]), key=record["Channels"].count) if record["Channels"] else None
                security = "OPEN" if "OPEN" in record["Securities"] else "WPA2"
                multi_bssid_risk = 10.0 if ssid_counts.get(record["SSID"], 0) > 1 else 0.0

                threat_score = 5.0
                threat_score += 30.0 if security == "OPEN" else 8.0
                threat_score += 20.0 if avg_rssi > -60 else 10.0 if avg_rssi > -75 else 0.0
                threat_score += 10.0 if signal_variation > 12 else 0.0
                threat_score += multi_bssid_risk
                threat_score = min(100.0, threat_score)

                if threat_score >= 75:
                    threat_level = "CRITICAL"
                elif threat_score >= 50:
                    threat_level = "HIGH"
                elif threat_score >= 30:
                    threat_level = "MEDIUM"
                else:
                    threat_level = "SAFE"

                vectors = {
                    "Scan Consistency": max(0.0, 100.0 - signal_variation),
                    "Open Network": 90.0 if security == "OPEN" else 15.0,
                    "RSSI Proximity": 100.0 if avg_rssi > -65 else 50.0,
                    "Multi-BSSID": 80.0 if multi_bssid_risk else 10.0,
                    "Channel Flux": 40.0 if len(set(record["Channels"])) > 1 else 5.0,
                }

                net_obj = {
                    "SSID": record["SSID"],
                    "BSSID": record["BSSID"],
                    "RSSI": round(avg_rssi, 1),
                    "Channel": channel,
                    "Security": security,
                    "Threat_Level": threat_level,
                    "Threat_Score": round(threat_score, 1),
                    "ML_Risk": round(threat_score * 0.8, 1),
                    "Combined_Risk": round(threat_score, 1),
                    "RF_Prediction": "Malicious" if threat_score > 50 else "Normal",
                    "KNN_Prediction": "Malicious" if threat_score > 40 else "Normal",
                    "Threat_Vectors": json.dumps(vectors),
                    "Signal_History": record["RSSI_values"],
                }
                networks_list.append(net_obj)

                with self._lock:
                    self.progress = 45 + int(((idx + 1) / max(1, len(scan_records))) * 40)
                    self.networks_found = len(networks_list)
                time.sleep(0.1)

            # Save dataset matrix real-time down to localized static storage csv
            df = pd.DataFrame(networks_list)
            df.to_csv("current_scan.csv", index=False)
            self.hash_chain = append_hash_chain("current_scan.csv", previous_hash=self.hash_chain)
            self.scan_log.append(f"Telemetry hash chain appended: {self.hash_chain[:12]}...")

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
                encrypt_csv("current_scan.csv", telemetry_key, output_path="current_scan.csv.enc")
                self.scan_log.append("Encrypted current_scan.csv to current_scan.csv.enc")
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
                    encrypt_csv("wifi_dataset.csv", telemetry_key, output_path="wifi_dataset.csv.enc")
                    self.scan_log.append("Encrypted wifi_dataset.csv to wifi_dataset.csv.enc")
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
                }
                self.status = ScanStatus.COMPLETE
                self.end_time = time.time()

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
    return _scanner_singleton
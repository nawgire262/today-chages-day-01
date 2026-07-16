"""SentinelShield production Streamlit dashboard.

Run with: streamlit run dashboard.py
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pandas as pd
import streamlit as st

try:
    from streamlit_autorefresh import st_autorefresh
except ImportError:  # The dashboard remains usable without this optional package.
    st_autorefresh = None

try:
    from background_scanner import get_scanner
except Exception:
    get_scanner = None

try:
    from database_manager import get_anomaly_analytics, get_monitoring_metrics
except Exception:
    get_anomaly_analytics = None
    get_monitoring_metrics = None

try:
    from threat_intelligence import get_threat_intelligence
except Exception:
    get_threat_intelligence = None

try:
    from report_generator import ReportGenerator
except Exception:
    ReportGenerator = None


ROOT = Path(__file__).resolve().parent
st.set_page_config(page_title="SentinelShield", page_icon="🛡️", layout="wide")


def apply_theme() -> None:
    st.markdown("""
    <style>
    .stApp { background: #07111f; color: #e6f6ff; }
    [data-testid="stSidebar"] { background: #0b1b2d; }
    div[data-testid="stMetric"] { background: #0d2438; border: 1px solid #1c5575;
      border-radius: 10px; padding: 14px; }
    h1, h2, h3 { color: #32d8ff !important; }
    .status-card { background: #0d2438; border-left: 4px solid #00e5ff;
      border-radius: 6px; padding: 12px 16px; margin: 6px 0; }
    </style>
    """, unsafe_allow_html=True)


def safe_load_csv(filename: str) -> pd.DataFrame:
    """Read a project CSV without allowing malformed or absent data to stop the UI."""
    path = ROOT / filename
    try:
        return pd.read_csv(path, on_bad_lines="skip", engine="python") if path.exists() else pd.DataFrame()
    except (OSError, UnicodeDecodeError, pd.errors.EmptyDataError, pd.errors.ParserError) as exc:
        st.warning(f"Could not read {filename}: {exc}")
        return pd.DataFrame()


def safe_load_json(filename: str, default: Any | None = None) -> Any:
    """Read project JSON safely, returning ``default`` when it is unavailable."""
    path = ROOT / filename
    try:
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else default
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        st.warning(f"Could not read {filename}: {exc}")
        return default


def to_number(series: pd.Series) -> pd.Series:
    return pd.to_numeric(series, errors="coerce").fillna(0.0)


def scanner_state() -> tuple[Any | None, dict[str, Any], dict[str, Any]]:
    if get_scanner is None:
        return None, {}, {}
    try:
        scanner = get_scanner()
        return scanner, scanner.get_status() or {}, scanner.get_results() or {}
    except Exception as exc:
        st.warning(f"Scanner unavailable: {exc}")
        return None, {}, {}


def scan_data(results: dict[str, Any]) -> pd.DataFrame:
    networks = results.get("networks", []) if isinstance(results, dict) else []
    frame = pd.DataFrame(networks)
    return frame if not frame.empty else safe_load_csv("current_scan.csv")


def show_table(frame: pd.DataFrame, columns: list[str] | None = None, empty: str = "No data available yet.") -> None:
    if frame.empty:
        st.info(empty)
        return
    visible = [column for column in (columns or list(frame.columns)) if column in frame.columns]
    st.dataframe(frame[visible] if visible else frame, use_container_width=True, hide_index=True)


def risk_column(frame: pd.DataFrame) -> pd.Series:
    for name in ("Combined_Risk", "Risk", "Threat_Score", "ML_Risk"):
        if name in frame:
            return to_number(frame[name])
    return pd.Series(0.0, index=frame.index)


def status_card(title: str, value: str) -> None:
    st.markdown(f"<div class='status-card'><b>{title}</b><br>{value}</div>", unsafe_allow_html=True)


def model_status() -> dict[str, bool]:
    candidates = {
        "Random Forest": ("rf_model.pkl", "model.pkl"),
        "KNN": ("knn_model.pkl",),
        "Isolation Forest": ("isolation_forest.pkl", "iso_model.pkl", "models/isolation_forest.pkl"),
    }
    return {name: any((ROOT / filename).exists() for filename in paths) for name, paths in candidates.items()}


def anomaly_statistics() -> dict[str, Any]:
    """Return persisted anomaly aggregates without exposing database failures."""
    defaults: dict[str, Any] = {"total": 0, "today": 0, "week": 0, "rate": 0.0, "daily": [], "ssids": [], "bssids": []}
    if get_anomaly_analytics is None:
        return defaults
    try:
        defaults.update(get_anomaly_analytics() or {})
    except Exception as exc:
        st.warning(f"Anomaly analytics unavailable: {exc}")
    return defaults


def page_home(scanner: Any | None, status: dict[str, Any], results: dict[str, Any], networks: pd.DataFrame) -> None:
    st.header("Dashboard Overview")
    metrics = {"networks_found": 0, "threats_detected": 0, "critical_alerts": 0, "last_scan": None}
    if get_monitoring_metrics:
        try:
            metrics.update(get_monitoring_metrics() or {})
        except Exception as exc:
            st.warning(f"Database metrics unavailable: {exc}")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Networks Scanned", metrics["networks_found"] or len(networks))
    c2.metric("Total Threats Detected", metrics["threats_detected"])
    c3.metric("Critical Alerts", metrics["critical_alerts"])
    c4.metric("Last Scan Time", metrics["last_scan"] or status.get("last_scan_time") or "Not run")
    anomalies = anomaly_statistics()
    a1, a2 = st.columns(2)
    a1.metric("Anomalies Detected Today", anomalies["today"])
    a2.metric("Anomaly Rate", f"{float(anomalies['rate']):.1f}%")
    st.subheader("System Status")
    left, right = st.columns(2)
    with left:
        status_card("System", "Operational" if scanner else "Scanner service unavailable")
        status_card("Scanner", f"{str(status.get('status', 'unavailable')).title()} ({status.get('progress', 0)}%)")
    with right:
        for name, loaded in model_status().items():
            status_card(name, "Loaded" if loaded else "Unavailable")
    if results.get("scan_mode") == "demo" or status.get("scan_mode") == "demo":
        st.warning("Demo scan mode is active; live Wi-Fi scanning is not currently available.")


def page_live_scan(scanner: Any | None, status: dict[str, Any], networks: pd.DataFrame) -> None:
    st.header("📡 Live WiFi Scan")
    a, b = st.columns(2)
    with a:
        if st.button("Start Scan", type="primary", disabled=not scanner or status.get("status") in {"scanning", "analyzing"}):
            try:
                if scanner.start_scan_async():
                    st.rerun()
                st.warning("A scan is already in progress.")
            except Exception as exc:
                st.warning(f"Could not start scan: {exc}")
    with b:
        if st.button("Refresh Results"):
            st.rerun()
    if not scanner:
        st.warning("Scanner unavailable. Showing saved scan data when available.")
    st.progress(min(max(int(status.get("progress", 0)), 0), 100) / 100)
    st.caption(f"Status: {str(status.get('status', 'unavailable')).title()} | Networks found: {status.get('networks_found', len(networks))}")
    if status.get("error"):
        st.warning(str(status["error"]))
    show_table(networks, ["SSID", "BSSID", "RSSI", "Channel", "Security", "Threat_Score", "Combined_Risk", "Threat_Level"], "No live scan results. Start a scan or add current_scan.csv.")


def page_threat_analysis(networks: pd.DataFrame) -> None:
    st.header("🛡️ Threat Analysis")
    if networks.empty:
        st.info("Run a scan to generate threat analysis.")
        return
    suspects = networks.assign(_risk=risk_column(networks)).sort_values("_risk", ascending=False)
    show_table(suspects, ["SSID", "BSSID", "Threat_Score", "Combined_Risk", "Threat_Level", "Fingerprint_Similarity", "Cloud_Risk", "BSSID_Reputation"])
    st.subheader("Top Suspicious Networks")
    for _, row in suspects.head(5).iterrows():
        with st.expander(f"{row.get('SSID', 'Unknown SSID')} — risk {row['_risk']:.1f}%"):
            st.write("**Risk factors**")
            factors = row.get("Threat_Vectors", row.get("Risk_Factors", "No detailed factors recorded."))
            if isinstance(factors, str):
                try:
                    st.json(json.loads(factors))
                except json.JSONDecodeError:
                    st.write(factors)
            else:
                if isinstance(factors, (dict, list)):
                    st.json(factors)
                else:
                    st.write(factors)
            st.write(f"Fingerprint similarity: {row.get('Fingerprint_Similarity', 'Unavailable')}")
            st.write(f"Cloud reputation: {row.get('Cloud_Risk', row.get('BSSID_Reputation', 'Unavailable'))}")


def page_ai_detection(networks: pd.DataFrame) -> None:
    st.header("🤖 AI Detection")
    columns = ["SSID", "BSSID", "RF_Prediction", "KNN_Prediction", "Isolation_Forest", "Anomaly_Detection", "ML_Risk", "Anomaly_Score", "Combined_Risk"]
    show_table(networks, columns, "Run a scan to view ML predictions.")
    if networks.empty:
        return
    if "Threat_Level" in networks:
        st.subheader("Threat Distribution")
        st.bar_chart(networks["Threat_Level"].fillna("Unknown").value_counts())
    risk_fields = [field for field in ("Threat_Score", "ML_Risk", "Anomaly_Score", "Combined_Risk") if field in networks]
    if risk_fields and "SSID" in networks:
        st.subheader("Risk Comparison")
        chart = networks.copy()
        chart[risk_fields] = chart[risk_fields].apply(to_number)
        st.bar_chart(chart.set_index("SSID")[risk_fields])
    if {"RSSI", "Combined_Risk"}.issubset(networks.columns):
        st.subheader("RSSI vs Risk")
        plot = networks.copy()
        plot["RSSI"], plot["Combined_Risk"] = to_number(plot["RSSI"]), to_number(plot["Combined_Risk"])
        st.scatter_chart(plot, x="RSSI", y="Combined_Risk", color="Threat_Level" if "Threat_Level" in plot else None)


def page_fingerprinting(networks: pd.DataFrame) -> None:
    st.header("🧬 Fingerprinting")
    data = safe_load_json("fingerprints.json", [])
    fingerprints = pd.DataFrame(data if isinstance(data, list) else [])
    st.metric("Stored Fingerprints", len(fingerprints))
    show_table(fingerprints, empty="No trusted fingerprints have been stored.")
    st.subheader("Current Scan Matches")
    show_table(networks, ["SSID", "BSSID", "Fingerprint_Similarity", "Threat_Level"], "No current scan matches.")


def page_analytics(scanner: Any | None, results: dict[str, Any], networks: pd.DataFrame) -> None:
    st.header("📊 Analytics")
    if networks.empty:
        st.info("Run a scan to populate analytics.")
        return
    risk = risk_column(networks)
    a, b, c = st.columns(3)
    a.metric("Average Risk", f"{risk.mean():.1f}%")
    b.metric("Highest Risk", f"{risk.max():.1f}%")
    c.metric("Lowest Risk", f"{risk.min():.1f}%")
    if "Threat_Level" in networks:
        st.subheader("Threat Distribution")
        st.bar_chart(networks["Threat_Level"].fillna("Unknown").value_counts())
    st.subheader("Risk Distribution")
    st.bar_chart(pd.DataFrame({"Networks": risk.round()}), use_container_width=True)
    st.subheader("Adaptive Thresholds")
    try:
        thresholds = results.get("adaptive_thresholds") or (scanner.get_adaptive_threshold_info() if scanner else {})
        st.json(thresholds or {"status": "Threshold data unavailable"})
    except Exception as exc:
        st.warning(f"Threshold data unavailable: {exc}")


def page_anomaly_analysis() -> None:
    """Display anomaly records persisted by the scan worker in SQLite."""
    st.header("🔎 Anomaly Analysis")
    stats = anomaly_statistics()
    a, b, c = st.columns(3)
    a.metric("Total Anomalies", stats["total"])
    b.metric("Daily Anomalies", stats["today"])
    c.metric("Weekly Anomalies", stats["week"])
    daily = pd.DataFrame(stats["daily"])
    if not daily.empty and {"date", "anomalies"}.issubset(daily.columns):
        daily["date"] = pd.to_datetime(daily["date"], errors="coerce")
        daily["anomalies"] = to_number(daily["anomalies"])
        daily = daily.dropna(subset=["date"]).sort_values("date")
        if not daily.empty:
            st.subheader("Anomaly Trend")
            st.line_chart(daily.set_index("date")["anomalies"])
    else:
        st.info("No persisted anomalies yet. Train the model and complete scans to build anomaly history.")
    left, right = st.columns(2)
    with left:
        st.subheader("Top Suspicious SSIDs")
        show_table(pd.DataFrame(stats["ssids"]), empty="No suspicious SSIDs recorded.")
    with right:
        st.subheader("Top Suspicious BSSIDs")
        show_table(pd.DataFrame(stats["bssids"]), empty="No suspicious BSSIDs recorded.")


def page_alert_history() -> None:
    st.header("📜 Alert History")
    alerts = safe_load_csv("alert_history.csv")
    st.metric("Alert Count", len(alerts))
    if alerts.empty:
        st.info("No alert history is available.")
        return
    if "Risk" in alerts:
        alerts["Risk"] = to_number(alerts["Risk"])
    search, minimum = st.columns(2)
    query = search.text_input("Search SSID, BSSID, or reason")
    min_risk = minimum.slider("Minimum Risk", 0, 100, 0)
    if "Time" in alerts:
        alerts["Time"] = pd.to_datetime(alerts["Time"], errors="coerce")
        valid_dates = alerts["Time"].dropna()
        if not valid_dates.empty:
            selected_dates = st.date_input("Alert Date Range", (valid_dates.min().date(), valid_dates.max().date()))
            if isinstance(selected_dates, tuple) and len(selected_dates) == 2:
                start, end = selected_dates
                alerts = alerts[(alerts["Time"].dt.date >= start) & (alerts["Time"].dt.date <= end)]
    if query:
        fields = [field for field in ("SSID", "BSSID", "Reason") if field in alerts]
        if fields:
            alerts = alerts[alerts[fields].fillna("").astype(str).apply(lambda row: row.str.contains(query, case=False, regex=False).any(), axis=1)]
    if "Risk" in alerts:
        alerts = alerts[alerts["Risk"] >= min_risk]
    show_table(alerts)
    st.download_button("Export filtered alerts (CSV)", alerts.to_csv(index=False).encode("utf-8"), "sentinelshield_alert_history.csv", "text/csv")


def page_cloud_intelligence(networks: pd.DataFrame) -> None:
    st.header("☁️ Cloud Intelligence")
    if get_threat_intelligence is None:
        st.warning("Offline Mode: cloud intelligence module is unavailable.")
        return
    try:
        intelligence = get_threat_intelligence()
        if st.button("Sync Shared Threat Feed"):
            intelligence.sync_feed(force=True)
        cloud = intelligence.status()
    except Exception as exc:
        st.warning(f"Offline Mode: cloud intelligence unavailable ({exc}).")
        return
    a, b, c = st.columns(3)
    a.metric("Cloud Threat Count", cloud.get("total_cloud_threats", 0))
    b.metric("Reputation Hits", cloud.get("reputation_hits", 0))
    c.metric("Last Sync", cloud.get("last_sync_time") or "Not synced")
    if cloud.get("enabled"):
        st.success("Cloud connection active")
    else:
        st.warning("Offline Mode: local scanning remains active.")
    st.subheader("Suspicious BSSID List")
    show_table(pd.DataFrame(cloud.get("shared_threat_feed", [])))
    st.subheader("Current Reputation Results")
    show_table(networks, ["SSID", "BSSID", "Cloud_Risk", "BSSID_Reputation", "Cloud_Reputation_Hit", "Cloud_Threat_Type"], "No current reputation results.")


def page_settings(scanner: Any | None, networks: pd.DataFrame) -> None:
    st.header("⚙️ Settings")
    st.subheader("Adaptive Threshold Controls")
    if scanner:
        try:
            st.json(scanner.get_adaptive_threshold_info())
            if st.button("Reset Baseline"):
                scanner.reset_adaptive_thresholds()
                st.success("Adaptive baseline reset.")
            enabled = st.checkbox("Enable Active Response", value=bool(getattr(scanner, "active_response", False)))
            scanner.set_active_response(enabled)
        except Exception as exc:
            st.warning(f"Scanner settings unavailable: {exc}")
    else:
        st.warning("Scanner controls are unavailable.")
    st.subheader("Report Generation")
    if ReportGenerator is None:
        st.warning("Report generator is unavailable.")
        return
    x, y = st.columns(2)
    for label, method, column in (("Generate PDF Report", "generate_pdf_report", x), ("Generate Excel Report", "generate_excel_report", y)):
        with column:
            if st.button(label):
                try:
                    generator = ReportGenerator()
                    path = getattr(generator, method)(networks) if method == "generate_pdf_report" else getattr(generator, method)()
                    report = Path(path)
                    if report.exists():
                        st.download_button(f"Download {report.name}", report.read_bytes(), report.name, "application/pdf" if report.suffix == ".pdf" else "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
                    else:
                        st.warning("Report generator completed without creating a downloadable file.")
                except Exception as exc:
                    st.warning(f"Report generation failed: {exc}")


def main() -> None:
    apply_theme()
    if st_autorefresh:
        st_autorefresh(interval=5000, key="sentinelshield_dashboard_refresh")
    scanner, status, results = scanner_state()
    networks = scan_data(results)
    st.sidebar.title("🛡️ SentinelShield")
    st.sidebar.caption("Evil Twin Attack Defense System")
    page = st.sidebar.radio("Navigation", ["Home", "Live Scan", "Threat Analysis", "AI Detection", "Fingerprinting", "Analytics", "Anomaly Analysis", "Alert History", "Cloud Intelligence", "Settings"])
    st.sidebar.caption("Auto refresh: every 5 seconds" if st_autorefresh else "Manual refresh mode")
    st.title("🛡️ SentinelShield")
    st.caption("AI-powered WiFi Evil Twin Detection System")
    routes = {
        "Home": lambda: page_home(scanner, status, results, networks),
        "Live Scan": lambda: page_live_scan(scanner, status, networks),
        "Threat Analysis": lambda: page_threat_analysis(networks),
        "AI Detection": lambda: page_ai_detection(networks),
        "Fingerprinting": lambda: page_fingerprinting(networks),
        "Analytics": lambda: page_analytics(scanner, results, networks),
        "Anomaly Analysis": page_anomaly_analysis,
        "Alert History": page_alert_history,
        "Cloud Intelligence": lambda: page_cloud_intelligence(networks),
        "Settings": lambda: page_settings(scanner, networks),
    }
    routes[page]()


if __name__ == "__main__":
    main()

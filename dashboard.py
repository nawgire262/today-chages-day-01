<<<<<<< HEAD
"""SentinelShield Streamlit dashboard wired to the live scanner modules."""

import json
import math
from pathlib import Path

import altair as alt
=======
<<<<<<< HEAD
﻿import streamlit as st
from streamlit_autorefresh import st_autorefresh

from styles import load_css

# Import Pages
from pages.home import show_home
from pages.live_scan import show_live_scan
from pages.code_risk_analysis import show_code_risk_analysis

# -----------------------------
# Page Config
# -----------------------------
st.set_page_config(
    page_title="SentinelShield",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# -----------------------------
# Load Theme
# -----------------------------
load_css()

# -----------------------------
# Auto Refresh Every 5 Seconds
# -----------------------------
st_autorefresh(interval=5000, key="dashboard_refresh")

# -----------------------------
# Sidebar
# -----------------------------
with st.sidebar:

    st.markdown(
        """
        <h1 style="color:#00E5FF;text-align:center;">
            🛡️ SentinelShield
        </h1>
        """,
        unsafe_allow_html=True
    )

    st.write("")
    st.write("### Navigation")

    page = st.radio(
        "",
        [
            "🏠 Home",
            "📡 Live Scan",
            "🛡 Threat Analysis",
            "🤖 AI Detection",
            "🧬 Fingerprinting",
            "🧪 Code Risk Analyzer",
            "📊 Analytics",
            "📜 Alert History",
            "⚙ Settings"
        ]
    )

    st.write("---")

    st.success("Background Monitor : Running")

    st.info("Auto Refresh : Every 5 Seconds")

    st.write("---")

    st.caption("SentinelShield v2.0")
    st.caption("MCA Research Project")

# -----------------------------
# Header
# -----------------------------
col1, col2 = st.columns([5, 1])

with col1:

    st.markdown(
        """
        <div class='title'>
            🛡️ SentinelShield
        </div>
        """,
        unsafe_allow_html=True
    )

    st.markdown(
        """
        <div class='subtitle'>
        AI Powered WiFi Evil Twin Detection System
        </div>
        """,
        unsafe_allow_html=True
    )

with col2:

    if st.button("🔄 Scan Now", use_container_width=True):
        import subprocess
        import sys

        with st.spinner("Scanning nearby WiFi..."):

            subprocess.run([sys.executable, "main.py"])

        st.success("Scan Completed")
        st.rerun()

st.write("---")

# -----------------------------
# Navigation
# -----------------------------
if page == "🏠 Home":
    show_home()

elif page == "📡 Live Scan":
    show_live_scan()

elif page == "🛡 Threat Analysis":

    st.info("Coming in Phase 2")

elif page == "🤖 AI Detection":

    st.info("Coming in Phase 2")

elif page == "🧬 Fingerprinting":

    st.info("Coming in Phase 2")

elif page == "🧪 Code Risk Analyzer":

    show_code_risk_analysis()

elif page == "📊 Analytics":

    st.info("Coming in Phase 3")

elif page == "📜 Alert History":

    st.info("Coming in Phase 3")

elif page == "⚙ Settings":

    st.info("Coming in Phase 3")
=======
"""SentinelShield Streamlit dashboard wired to the live scanner modules."""

import json
from pathlib import Path

>>>>>>> fb2e0dfb94cb96bb998dfa037a56d2b2405958b4
import pandas as pd
import streamlit as st
from streamlit_autorefresh import st_autorefresh

from background_scanner import get_scanner
from threat_intelligence import get_threat_intelligence
<<<<<<< HEAD
from database_manager import get_alert_history, get_anomaly_analytics, get_daily_statistics, get_monitoring_metrics, get_sensor_statistics, get_threat_history
=======
>>>>>>> fb2e0dfb94cb96bb998dfa037a56d2b2405958b4
from xai_explain import FEATURE_LABELS

try:
    from report_generator import ReportGenerator
except ImportError:
    ReportGenerator = None


st.set_page_config(page_title="SentinelShield", page_icon="🛡️", layout="wide")
<<<<<<< HEAD
st_autorefresh(interval=5000, key="live_dashboard")


@st.cache_data(ttl=5)
def monitoring_metrics():
    return get_monitoring_metrics()


@st.cache_data(ttl=5)
def historical_data():
    return pd.DataFrame(get_daily_statistics()), pd.DataFrame(get_threat_history()), pd.DataFrame(get_alert_history())


@st.cache_data(ttl=5)
def anomaly_analytics():
    return get_anomaly_analytics()


@st.cache_data(ttl=5)
def sensor_statistics():
    return pd.DataFrame(get_sensor_statistics())


def scan_frame(results):
    frame = pd.DataFrame(results.get("networks", []))
    return frame if not frame.empty else load_csv("current_scan.csv")
=======
st_autorefresh(interval=5000, key="sentinelshield_refresh")


def scan_frame(results):
    return pd.DataFrame(results.get("networks", []))
>>>>>>> fb2e0dfb94cb96bb998dfa037a56d2b2405958b4


def load_csv(path):
    try:
<<<<<<< HEAD
        return pd.read_csv(path, on_bad_lines="skip") if Path(path).exists() else pd.DataFrame()
    except (OSError, pd.errors.EmptyDataError, pd.errors.ParserError, UnicodeDecodeError):
=======
        return pd.read_csv(path) if Path(path).exists() else pd.DataFrame()
    except (OSError, pd.errors.EmptyDataError, UnicodeDecodeError):
>>>>>>> fb2e0dfb94cb96bb998dfa037a56d2b2405958b4
        return pd.DataFrame()


def show_xai(row):
<<<<<<< HEAD
    """Render only normalized contributions emitted by the ML prediction."""
    try:
        contributions = json.loads(row.get("XAI_Contributions", "{}"))
    except (TypeError, json.JSONDecodeError):
        contributions = {}
    explanation = pd.DataFrame([
        {"Feature": FEATURE_LABELS[key], "Contribution": float(value)}
        for key, value in contributions.items()
        if key in FEATURE_LABELS and isinstance(value, (int, float)) and math.isfinite(float(value)) and float(value) >= 0
    ])
    if explanation.empty or explanation["Contribution"].sum() <= 0:
        st.info("Model-derived feature contributions are unavailable for this prediction.")
        return
    explanation["Contribution"] = explanation["Contribution"] / explanation["Contribution"].sum() * 100
    explanation = explanation.sort_values("Contribution", ascending=False)
    chart = alt.Chart(explanation).mark_bar().encode(
        x=alt.X("Contribution:Q", title="Contribution (%)", scale=alt.Scale(domain=[0, 100])),
        y=alt.Y("Feature:N", sort="-x", title=None),
        tooltip=[alt.Tooltip("Feature:N"), alt.Tooltip("Contribution:Q", format=".2f", title="Contribution (%)")],
    ).properties(height=190)
    st.altair_chart(chart, use_container_width=True)
    top = explanation.iloc[0]
    st.caption(f"Top Contributing Feature: {top['Feature']} — {top['Contribution']:.2f}%")
    st.caption(f"Threat Reason: {top['Feature']} is the largest model-derived contribution for this prediction.")
=======
    st.caption("Model feature explanation")
    values = {
        "RSSI": abs(float(row.get("RSSI", 0))),
        "Channel": float(row.get("Channel", 0) or 0),
        "Security_enc": 80 if row.get("Security") == "OPEN" else 15,
        "AP_Count": 80 if float(row.get("Threat_Score", 0)) >= 50 else 15,
        "Signal_Var": float(row.get("Signal_Pattern_Score", 0)),
    }
    explanation = pd.DataFrame({
        "Feature": [FEATURE_LABELS[key] for key in values],
        "Value": list(values.values()),
    }).set_index("Feature")
    st.bar_chart(explanation)
>>>>>>> fb2e0dfb94cb96bb998dfa037a56d2b2405958b4


def show_network_table(df, columns=None):
    if df.empty:
        st.info("No scan results yet. Start a scan from Live Scan.")
    else:
        available = [column for column in (columns or df.columns.tolist()) if column in df.columns]
        st.dataframe(df[available], use_container_width=True, hide_index=True)


<<<<<<< HEAD
def alert_frame():
    alerts = load_csv("alert_history.csv")
    if not alerts.empty and "Risk" in alerts:
        alerts["Risk"] = pd.to_numeric(alerts["Risk"], errors="coerce").fillna(0)
    return alerts


=======
>>>>>>> fb2e0dfb94cb96bb998dfa037a56d2b2405958b4
scanner = get_scanner()
results = scanner.get_results()
networks = scan_frame(results)
status = scanner.get_status()

st.sidebar.title("🛡️ SentinelShield")
page = st.sidebar.radio("Navigation", [
    "Home", "Live Scan", "Threat Analysis", "AI Detection", "Fingerprinting",
<<<<<<< HEAD
    "Analytics", "Anomaly Analysis", "Historical Analysis", "Alert History", "Cloud Intelligence", "Settings",
=======
    "Analytics", "Alert History", "Cloud Intelligence", "Settings",
>>>>>>> fb2e0dfb94cb96bb998dfa037a56d2b2405958b4
])
st.sidebar.caption(f"Scanner: {status['status'].title()} | {status['progress']}%")

st.title("🛡️ SentinelShield")
st.caption("AI Powered WiFi Evil Twin Detection System")
st.divider()

<<<<<<< HEAD
metrics = monitoring_metrics()
col1, col2, col3, col4 = st.columns(4)
col1.metric("Networks Found", metrics["networks_found"])
col2.metric("Threats Detected", metrics["threats_detected"])
col3.metric("Critical Alerts", metrics["critical_alerts"])
col4.metric("Last Scan", metrics["last_scan"] or "Not run")
st.divider()

=======
>>>>>>> fb2e0dfb94cb96bb998dfa037a56d2b2405958b4
if page == "Home":
    st.header("Dashboard Overview")
    threats = networks[networks["Threat_Level"].isin(["HIGH", "CRITICAL"])] if "Threat_Level" in networks else pd.DataFrame()
    highest_risk = float(networks["Combined_Risk"].max()) if "Combined_Risk" in networks and not networks.empty else 0.0
<<<<<<< HEAD
    alerts = alert_frame()
    critical_alerts = len(alerts[alerts["Risk"] >= 75]) if "Risk" in alerts else 0
    anomaly_stats = anomaly_analytics()
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Networks Scanned", len(networks))
    c2.metric("High/Critical Threats", len(threats))
    c3.metric("Critical Alerts", critical_alerts)
    c4.metric("Highest Risk", f"{highest_risk:.1f}%")
    c5.metric("Last Scan", status.get("last_scan_time") or "Not run")
    model_status = [
        "RF Loaded" if Path("rf_model.pkl").exists() else "RF Unavailable",
        "KNN Loaded" if Path("knn_model.pkl").exists() else "KNN Unavailable",
        "Isolation Forest Loaded" if Path("models/isolation_forest.pkl").exists() else "Isolation Forest Unavailable",
    ]
    st.subheader("AI Models Status")
    st.caption(" | ".join(model_status))
    a1, a2 = st.columns(2)
    a1.metric("Anomalies Detected Today", anomaly_stats["today"])
    a2.metric("Anomaly Rate", f"{anomaly_stats['rate']:.1f}%")
    if results.get("scan_mode") == "demo":
        st.warning("Demo scan data is active because live Wi-Fi scanning is unavailable.")
    if not alerts.empty and "Time" in alerts:
        st.subheader("Threat timeline")
        timeline = alerts.assign(Time=pd.to_datetime(alerts["Time"], errors="coerce")).dropna(subset=["Time"]).set_index("Time")
        if not timeline.empty:
            st.line_chart(timeline["Risk"])
=======
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Networks Scanned", len(networks))
    c2.metric("High/Critical Threats", len(threats))
    c3.metric("Highest Risk", f"{highest_risk:.1f}%")
    c4.metric("Scan Status", status["status"].title())
>>>>>>> fb2e0dfb94cb96bb998dfa037a56d2b2405958b4
    show_network_table(networks, ["SSID", "BSSID", "RSSI", "Security", "Combined_Risk", "Threat_Level", "Cloud_Reputation_Hit"])

elif page == "Live Scan":
    st.header("📡 Live Scan")
    if st.button("Start Scan", type="primary", disabled=status["status"] in {"scanning", "analyzing"}):
        if scanner.start_scan_async():
            st.rerun()
    st.progress(min(100, status["progress"]) / 100)
    st.write(f"Status: **{status['status'].title()}** | Networks found: **{status['networks_found']}**")
    if status["error"]:
        st.error(status["error"])
<<<<<<< HEAD
    if results.get("scan_mode") == "demo" or status.get("scan_mode") == "demo":
        st.warning("Running in demo mode. Install pywifi/comtypes and connect a supported Wi-Fi adapter for live results.")
=======
>>>>>>> fb2e0dfb94cb96bb998dfa037a56d2b2405958b4
    show_network_table(networks)
    if results.get("scan_log"):
        with st.expander("Scanner activity"):
            st.code("\n".join(results["scan_log"][-25:]))

elif page == "Threat Analysis":
    st.header("🛡 Threat Analysis")
    if not networks.empty and "Combined_Risk" in networks:
        suspects = networks.sort_values("Combined_Risk", ascending=False)
        show_network_table(suspects, ["SSID", "BSSID", "Combined_Risk", "Threat_Level", "Cloud_Reputation_Hit", "Cloud_Threat_Type", "Fingerprint_Similarity"])
        for _, row in suspects.head(5).iterrows():
            with st.expander(f"{row['SSID']} — risk {row['Combined_Risk']}%"):
                vectors = row.get("Threat_Vectors", "{}")
                try:
                    st.json(json.loads(vectors) if isinstance(vectors, str) else vectors)
                except json.JSONDecodeError:
                    st.write(vectors)
    else:
        st.info("Run a scan to generate threat analysis.")

elif page == "AI Detection":
    st.header("🤖 AI Detection")
<<<<<<< HEAD
    show_network_table(networks, ["SSID", "BSSID", "RF_Prediction", "KNN_Prediction", "Isolation_Forest", "Anomaly_Score", "Anomaly_Confidence", "ML_Risk", "Signal_Pattern_Score", "Combined_Risk"])
    if not networks.empty:
        left, right = st.columns(2)
        with left:
            st.subheader("Risk components by network")
            risk_columns = [name for name in ["Threat_Score", "Signal_Pattern_Score", "ML_Risk", "Combined_Risk"] if name in networks]
            if risk_columns and "SSID" in networks:
                st.bar_chart(networks.set_index("SSID")[risk_columns])
        with right:
            st.subheader("Classifier decisions")
            prediction_columns = [name for name in ["RF_Prediction", "KNN_Prediction", "Isolation_Forest"] if name in networks]
            if prediction_columns:
                decisions = pd.concat([networks[name].rename(name) for name in prediction_columns]).value_counts()
                st.bar_chart(decisions)
        if {"RSSI", "Combined_Risk"}.issubset(networks.columns):
            st.subheader("Signal strength vs. combined risk")
            st.scatter_chart(networks, x="RSSI", y="Combined_Risk", color="Threat_Level" if "Threat_Level" in networks else None)
        if "Threat_Level" in networks and len(networks) >= 2:
            st.subheader("Threat-level distribution")
            st.bar_chart(networks["Threat_Level"].value_counts())
        elif "Threat_Level" in networks:
            st.info("Insufficient data for distribution analysis.")
        history = load_csv("scan_history.csv")
        if not history.empty and {"timestamp", "combined_risk"}.issubset(history.columns):
            st.subheader("Combined risk trend")
            history["timestamp"] = pd.to_datetime(history["timestamp"], errors="coerce")
            history["combined_risk"] = pd.to_numeric(history["combined_risk"], errors="coerce")
            history = history.dropna(subset=["timestamp", "combined_risk"]).sort_values("timestamp")
            if len(history) >= 2:
                st.line_chart(history.set_index("timestamp")["combined_risk"])
            else:
                st.info("Run another scan to build a combined risk trend.")
        else:
            st.info("Run scans to create scan history for the combined risk trend.")
        if {"SSID", "Threat_Score", "Combined_Risk"}.issubset(networks.columns):
            st.subheader("Threat-score comparison")
            if len(networks) >= 2:
                st.bar_chart(networks.set_index("SSID")[["Threat_Score", "Combined_Risk"]])
            else:
                st.warning("At least two networks are required for threat-score comparison.")
=======
    show_network_table(networks, ["SSID", "BSSID", "RF_Prediction", "KNN_Prediction", "ML_Risk", "Signal_Pattern_Score", "Combined_Risk"])
    if not networks.empty:
>>>>>>> fb2e0dfb94cb96bb998dfa037a56d2b2405958b4
        selected = st.selectbox("Explain network", networks.index, format_func=lambda i: f"{networks.loc[i, 'SSID']} ({networks.loc[i, 'BSSID']})")
        show_xai(networks.loc[selected])

elif page == "Fingerprinting":
    st.header("🧬 Fingerprinting")
    # Fingerprints are JSON (not CSV); parsing them with pandas.read_csv
    # caused the dashboard ParserError when a saved SSID contained commas.
    try:
        stored = json.loads(Path("fingerprints.json").read_text(encoding="utf-8")) if Path("fingerprints.json").exists() else []
        fingerprints = pd.DataFrame(stored if isinstance(stored, list) else [])
    except (OSError, json.JSONDecodeError, ValueError):
        fingerprints = pd.DataFrame()
        st.warning("fingerprints.json could not be read. A new fingerprint will be created after the next safe scan.")
    st.metric("Stored Trusted Fingerprints", len(fingerprints))
    show_network_table(fingerprints)
    if not networks.empty and "Fingerprint_Similarity" in networks:
        st.subheader("Current scan fingerprint matches")
        show_network_table(networks, ["SSID", "BSSID", "Fingerprint_Similarity", "Threat_Level"])

elif page == "Analytics":
    st.header("📊 Analytics")
    if not networks.empty:
<<<<<<< HEAD
        st.download_button("Export current scan (CSV)", networks.to_csv(index=False).encode("utf-8"), "sentinelshield_current_scan.csv", "text/csv")
        sensors = sensor_statistics()
        st.subheader("Physical sensor status")
        st.metric("Active Wi-Fi sensors", len(sensors))
        show_network_table(sensors)
        if {"SSID", "Sensor_Count", "Sensor_Agreement_dBm"}.issubset(networks.columns):
            st.subheader("Multi-sensor fusion")
            show_network_table(networks, ["SSID", "BSSID", "Sensor_Count", "Sensor_Agreement_dBm", "Combined_Risk"])
=======
>>>>>>> fb2e0dfb94cb96bb998dfa037a56d2b2405958b4
        if "Threat_Level" in networks:
            st.subheader("Threat distribution")
            st.bar_chart(networks["Threat_Level"].value_counts())
        if "SSID" in networks and "Combined_Risk" in networks:
            st.subheader("Risk by network")
            st.bar_chart(networks.set_index("SSID")["Combined_Risk"])
        thresholds = results.get("adaptive_thresholds", scanner.get_adaptive_threshold_info())
        st.subheader("Adaptive thresholds")
        st.json(thresholds)
    else:
        st.info("Run a scan to populate analytics.")

<<<<<<< HEAD
elif page == "Anomaly Analysis":
    st.header("Anomaly Analysis")
    stats = anomaly_analytics()
    a, b, c = st.columns(3)
    a.metric("Total anomalies", stats["total"])
    b.metric("Daily anomalies", stats["today"])
    c.metric("Weekly anomalies", stats["week"])
    daily = pd.DataFrame(stats["daily"])
    if not daily.empty:
        daily["date"] = pd.to_datetime(daily["date"], errors="coerce")
        st.subheader("Anomaly trend")
        st.line_chart(daily.dropna(subset=["date"]).set_index("date")["anomalies"])
    else:
        st.info("No persisted anomalies yet. Train the model and run a scan.")
    left, right = st.columns(2)
    with left:
        st.subheader("Top suspicious SSIDs")
        show_network_table(pd.DataFrame(stats["ssids"]))
    with right:
        st.subheader("Top suspicious BSSIDs")
        show_network_table(pd.DataFrame(stats["bssids"]))

elif page == "Historical Analysis":
    st.header("Historical Analysis")
    daily, threats_history, alerts_history = historical_data()
    if daily.empty:
        st.info("Historical data will appear after a scan completes.")
    else:
        daily["date"] = pd.to_datetime(daily["date"], errors="coerce")
        daily = daily.dropna(subset=["date"]).sort_values("date")
        minimum, maximum = daily["date"].min().date(), daily["date"].max().date()
        selected_range = st.date_input("Analysis date range", value=(minimum, maximum), min_value=minimum, max_value=maximum)
        if isinstance(selected_range, tuple) and len(selected_range) == 2:
            start, end = pd.Timestamp(selected_range[0]), pd.Timestamp(selected_range[1])
            daily = daily[(daily["date"] >= start) & (daily["date"] <= end)]
        if daily.empty:
            st.info("No activity exists in the selected date range.")
            st.stop()
        total_scans = int(daily["networks_found"].sum())
        total_threats = int(daily["threats_detected"].sum())
        detection_rate = (total_threats / total_scans * 100) if total_scans else 0
        critical_rate = (metrics["critical_alerts"] / max(1, len(alerts_history)) * 100)
        a, b, c, d = st.columns(4)
        a.metric("Total scans", total_scans)
        b.metric("Total threats", total_threats)
        c.metric("Detection rate", f"{detection_rate:.1f}%")
        d.metric("Critical threat percentage", f"{critical_rate:.1f}%")
        st.subheader("Scan trends")
        st.line_chart(daily.set_index("date")["networks_found"])
        st.subheader("Threat and alert trends")
        st.line_chart(daily.set_index("date")[["threats_detected", "alerts_generated"]])
        st.download_button("Export selected analytics (CSV)", daily.to_csv(index=False).encode("utf-8"), "sentinelshield_historical_analytics.csv", "text/csv")
        st.caption(f"Daily average scans: {daily['networks_found'].mean():.1f} | Weekly average scans: {daily['networks_found'].sum() / max(1, len(daily) / 7):.1f}")

elif page == "Alert History":
    st.header("📜 Alert History")
    alerts = alert_frame()
    st.metric("Recorded Alerts", len(alerts))
    if "Time" in alerts:
        alerts["Time"] = pd.to_datetime(alerts["Time"], errors="coerce")
        alerts = alerts.dropna(subset=["Time"]).sort_values("Time", ascending=False)
    search = st.text_input("Search alerts by SSID, BSSID, or reason")
    minimum_risk = st.slider("Minimum risk", 0, 100, 0)
    if not alerts.empty and "Time" in alerts:
        minimum, maximum = alerts["Time"].min().date(), alerts["Time"].max().date()
        selected_range = st.date_input("Alert date range", value=(minimum, maximum), min_value=minimum, max_value=maximum, key="alert_date_range")
        if isinstance(selected_range, tuple) and len(selected_range) == 2:
            alerts = alerts[(alerts["Time"] >= pd.Timestamp(selected_range[0])) & (alerts["Time"] < pd.Timestamp(selected_range[1]) + pd.Timedelta(days=1))]
    if search and not alerts.empty:
        searchable = alerts[[column for column in ["SSID", "BSSID", "Reason"] if column in alerts]].fillna("").astype(str)
        alerts = alerts[searchable.apply(lambda row: row.str.contains(search, case=False, regex=False).any(), axis=1)]
    if "Risk" in alerts:
        alerts = alerts[alerts["Risk"] >= minimum_risk]
    show_network_table(alerts)
    if not alerts.empty:
        st.download_button("Download alert history (CSV)", alerts.to_csv(index=False).encode("utf-8"), "alert_history.csv", "text/csv")
        st.subheader("Alert analytics")
        st.bar_chart(alerts["Risk"])
=======
elif page == "Alert History":
    st.header("📜 Alert History")
    alerts = load_csv("alert_history.csv")
    st.metric("Recorded Alerts", len(alerts))
    show_network_table(alerts)
>>>>>>> fb2e0dfb94cb96bb998dfa037a56d2b2405958b4

elif page == "Cloud Intelligence":
    st.header("☁️ Cloud Threat Intelligence")
    intel = get_threat_intelligence()
    if st.button("Sync shared threat feed"):
        intel.sync_feed(force=True)
    cloud = intel.status()
    a, b, c = st.columns(3)
    a.metric("Total Cloud Threats", cloud["total_cloud_threats"])
    b.metric("Reputation Hits", cloud["reputation_hits"])
    c.metric("Last Sync Time", cloud["last_sync_time"] or "Not synced")
    if cloud["enabled"]:
        st.success("Firebase Firestore connected")
    else:
        st.warning("Offline mode. Local scanning remains active.")
<<<<<<< HEAD
    st.caption(f"Local external-cache entries: {cloud.get('local_external_cache_entries', 0)}")
    st.json(cloud.get("external_provider_adapters", {}), expanded=False)
    local_cloud = results.get("local_cloud_intelligence", {})
    if not networks.empty:
        st.subheader("Current scan intelligence")
        intel_columns = [column for column in ["SSID", "BSSID", "VirusTotal_Risk", "AbuseIPDB_Risk", "BSSID_Reputation", "OpenPhish_Risk", "Cloud_Risk"] if column in networks]
        show_network_table(networks.sort_values("Cloud_Risk", ascending=False) if "Cloud_Risk" in networks else networks, intel_columns)
        if "Cloud_Risk" in networks:
            a, b, c = st.columns(3)
            a.metric("Highest Cloud Risk", f"{networks['Cloud_Risk'].max():.1f}%")
            b.metric("Known BSSID Reputation", f"{networks.get('BSSID_Reputation', pd.Series([0])).max():.1f}%")
            c.metric("OpenPhish Risk", f"{networks.get('OpenPhish_Risk', pd.Series([0])).max():.1f}%")
            st.bar_chart(networks.set_index("SSID")[["Cloud_Risk"]])
    st.subheader("Top suspicious BSSIDs")
    show_network_table(pd.DataFrame(local_cloud.get("top_suspicious_bssids", [])))
=======
>>>>>>> fb2e0dfb94cb96bb998dfa037a56d2b2405958b4
    show_network_table(pd.DataFrame(cloud["shared_threat_feed"]))

elif page == "Settings":
    st.header("⚙ Settings")
    st.subheader("Adaptive thresholds")
    st.json(scanner.get_adaptive_threshold_info())
    if st.button("Reset adaptive baseline"):
        scanner.reset_adaptive_thresholds()
        st.success("Adaptive baseline reset.")
    active_response = st.checkbox("Enable active response", value=scanner.active_response)
    scanner.set_active_response(active_response)
    if ReportGenerator is not None:
        st.subheader("Reports")
        if st.button("Generate PDF report"):
            try:
<<<<<<< HEAD
                report_path = ReportGenerator().generate_pdf_report(networks)
                st.session_state["report_path"] = report_path
                st.session_state["report_bytes"] = Path(report_path).read_bytes()
                st.success(f"Created {report_path}")
            except Exception as exc:
                st.error(str(exc))
        if st.session_state.get("report_bytes"):
            st.download_button(
                "Download PDF report",
                st.session_state["report_bytes"],
                file_name=st.session_state.get("report_path", "Threat_Report.pdf"),
                mime="application/pdf",
            )
=======
                report_path = ReportGenerator().generate_pdf_report()
                st.success(f"Created {report_path}")
            except Exception as exc:
                st.error(str(exc))
>>>>>>> 0d1f8da (Updated SentinelShield project)
>>>>>>> fb2e0dfb94cb96bb998dfa037a56d2b2405958b4

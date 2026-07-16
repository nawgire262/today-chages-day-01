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

import pandas as pd
import streamlit as st
from streamlit_autorefresh import st_autorefresh

from background_scanner import get_scanner
from threat_intelligence import get_threat_intelligence
from xai_explain import FEATURE_LABELS

try:
    from report_generator import ReportGenerator
except ImportError:
    ReportGenerator = None


st.set_page_config(page_title="SentinelShield", page_icon="🛡️", layout="wide")
st_autorefresh(interval=5000, key="sentinelshield_refresh")


def scan_frame(results):
    return pd.DataFrame(results.get("networks", []))


def load_csv(path):
    try:
        return pd.read_csv(path) if Path(path).exists() else pd.DataFrame()
    except (OSError, pd.errors.EmptyDataError, UnicodeDecodeError):
        return pd.DataFrame()


def show_xai(row):
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


def show_network_table(df, columns=None):
    if df.empty:
        st.info("No scan results yet. Start a scan from Live Scan.")
    else:
        available = [column for column in (columns or df.columns.tolist()) if column in df.columns]
        st.dataframe(df[available], use_container_width=True, hide_index=True)


scanner = get_scanner()
results = scanner.get_results()
networks = scan_frame(results)
status = scanner.get_status()

st.sidebar.title("🛡️ SentinelShield")
page = st.sidebar.radio("Navigation", [
    "Home", "Live Scan", "Threat Analysis", "AI Detection", "Fingerprinting",
    "Analytics", "Alert History", "Cloud Intelligence", "Settings",
])
st.sidebar.caption(f"Scanner: {status['status'].title()} | {status['progress']}%")

st.title("🛡️ SentinelShield")
st.caption("AI Powered WiFi Evil Twin Detection System")
st.divider()

if page == "Home":
    st.header("Dashboard Overview")
    threats = networks[networks["Threat_Level"].isin(["HIGH", "CRITICAL"])] if "Threat_Level" in networks else pd.DataFrame()
    highest_risk = float(networks["Combined_Risk"].max()) if "Combined_Risk" in networks and not networks.empty else 0.0
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Networks Scanned", len(networks))
    c2.metric("High/Critical Threats", len(threats))
    c3.metric("Highest Risk", f"{highest_risk:.1f}%")
    c4.metric("Scan Status", status["status"].title())
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
    show_network_table(networks, ["SSID", "BSSID", "RF_Prediction", "KNN_Prediction", "ML_Risk", "Signal_Pattern_Score", "Combined_Risk"])
    if not networks.empty:
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

elif page == "Alert History":
    st.header("📜 Alert History")
    alerts = load_csv("alert_history.csv")
    st.metric("Recorded Alerts", len(alerts))
    show_network_table(alerts)

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
                report_path = ReportGenerator().generate_pdf_report()
                st.success(f"Created {report_path}")
            except Exception as exc:
                st.error(str(exc))
>>>>>>> 0d1f8da (Updated SentinelShield project)

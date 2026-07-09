import streamlit as st
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
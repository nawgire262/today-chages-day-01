# xai_explain.py (Excerpt of the rendering definitions)
BASE_FEATURES = ["RSSI", "Channel", "Security_enc", "AP_Count", "Signal_Var"]
FEATURE_LABELS = {
    "RSSI": "RSSI Signal Spike / Attenuation",
    "Channel": "Channel Congestion Overlap",
    "Security_enc": "Unencrypted Open Portal Flag",
    "AP_Count": "Multi-AP MAC Spoofing Density",
    "Signal_Var": "Temporal Signal Fluctuation Variance",
}
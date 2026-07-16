# xai_explain.py (Excerpt of the rendering definitions)
BASE_FEATURES = ["RSSI", "Channel", "Security_enc", "AP_Count", "Signal_Var"]
FEATURE_LABELS = {
<<<<<<< HEAD
    "RSSI": "RSSI Signal Spike",
    "Channel": "Channel Congestion",
    "Security_enc": "Open Network Risk",
    "AP_Count": "Multi AP MAC Density",
    "Signal_Var": "Temporal Signal Variance",
}
=======
    "RSSI": "RSSI Signal Spike / Attenuation",
    "Channel": "Channel Congestion Overlap",
    "Security_enc": "Unencrypted Open Portal Flag",
    "AP_Count": "Multi-AP MAC Spoofing Density",
    "Signal_Var": "Temporal Signal Fluctuation Variance",
}
>>>>>>> fb2e0dfb94cb96bb998dfa037a56d2b2405958b4

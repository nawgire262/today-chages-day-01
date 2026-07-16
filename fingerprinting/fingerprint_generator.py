"""Persistent Wi-Fi fingerprints used by the scanner and dashboard."""

import json
from pathlib import Path

FINGERPRINT_DB = Path("fingerprints.json")


def create_fingerprint(network):
    """Store one normalized fingerprint per SSID/BSSID pair and return it."""
    fingerprint = {
        "SSID": network.get("SSID", network.get("ssid", "")),
        "BSSID": network.get("BSSID", network.get("bssid", "")).strip().upper(),
        "Channel": network.get("Channel", network.get("channel", 0)),
        "Signal": network.get("Signal", network.get("signal", 0)),
        "Security": network.get("Security", network.get("security", "Unknown")),
    }
    if not fingerprint["SSID"] or not fingerprint["BSSID"]:
        return fingerprint

    try:
        fingerprints = json.loads(FINGERPRINT_DB.read_text(encoding="utf-8")) if FINGERPRINT_DB.exists() else []
        if not isinstance(fingerprints, list):
            fingerprints = []
        fingerprints = [fp for fp in fingerprints if not (
            fp.get("SSID") == fingerprint["SSID"] and fp.get("BSSID", "").upper() == fingerprint["BSSID"]
        )]
        fingerprints.append(fingerprint)
        FINGERPRINT_DB.write_text(json.dumps(fingerprints, indent=2), encoding="utf-8")
    except (OSError, ValueError, TypeError):
        # A fingerprint must never stop a live scan.
        pass
    return fingerprint

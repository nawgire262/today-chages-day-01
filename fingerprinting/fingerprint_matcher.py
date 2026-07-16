import json
import os

FINGERPRINT_DB = "fingerprints.json"

def compare_fingerprint(current_network):
    try:
        if not os.path.exists(FINGERPRINT_DB):
            return {"similarity": 100}

        with open(FINGERPRINT_DB, "r") as f:
            fingerprints = json.load(f)

        if not fingerprints:
            return {"similarity": 100}

        ssid = current_network.get("SSID", "")
        bssid = current_network.get("BSSID", "").strip().upper()
        security = current_network.get("Security", "")
        channel = current_network.get("Channel", 0)

        best_similarity = 0

        for fp in fingerprints:
            score = 0

            if fp.get("SSID", "") == ssid:
                score += 40

            if fp.get("BSSID", "").strip().upper() == bssid:
                score += 30

            if fp.get("Security", "") == security:
                score += 20

            if fp.get("Channel", 0) == channel:
                score += 10

            best_similarity = max(best_similarity, score)

        return {"similarity": best_similarity}

    except Exception as e:
        print(f"Fingerprint Error: {e}")
        return {"similarity": 100}

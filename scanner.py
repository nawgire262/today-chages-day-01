import pywifi
import time
from collections import defaultdict

# Store signal history
signal_history = defaultdict(list)

def calculate_risk(bssids, security_list, signals):
    risk = 0
    reasons = []

    # Rule 1: Multiple BSSID
    if len(bssids) > 1:
        risk += 50
        reasons.append("Multiple BSSID detected")

    # Rule 2: Open network
    if "Open" in security_list:
        risk += 30
        reasons.append("Open network")

    # Rule 3: Signal fluctuation (NEW)
    if len(signals) >= 3:
        if max(signals) - min(signals) > 20:
            risk += 20
            reasons.append("High signal fluctuation")

    return risk, reasons


def scan_wifi():
    wifi = pywifi.PyWiFi()
    iface = wifi.interfaces()[0]

    print("\n📡 Monitoring WiFi...\n")

    for _ in range(3):  # scan multiple times
        iface.scan()
        time.sleep(3)
        results = iface.scan_results()

        ssid_map = defaultdict(list)

        for net in results:
            ssid_map[net.ssid].append(net)

        for ssid, networks in ssid_map.items():
            for net in networks:
                signal_history[ssid].append(net.signal)

    print("\n📊 Final Analysis:\n")

    for ssid, signals in signal_history.items():
        bssids = set()
        security_list = []

        for sig in signals:
            pass  # signals already collected

        # Re-scan once to get latest metadata
        iface.scan()
        time.sleep(2)
        results = iface.scan_results()

        for net in results:
            if net.ssid == ssid:
                bssids.add(net.bssid)
                security = "Open" if not net.akm else "Secured"
                security_list.append(security)

        risk, reasons = calculate_risk(bssids, security_list, signals)

        status = "⚠️ Suspicious" if risk >= 50 else "✅ Safe"

        print(f"{status} Network: {ssid}")
        print(f"Risk Score: {risk}%")
        print(f"Signal History: {signals}")

        if reasons:
            print("Reason:")
            for r in reasons:
                print(f" - {r}")

        print("-" * 40)


scan_wifi()
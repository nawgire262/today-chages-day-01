from plyer import notification
from datetime import datetime


class NotificationManager:

    def __init__(self):
        self.last_alert = None

    # ----------------------------------------
    # General Notification
    # ----------------------------------------
    def notify(self, title, message, timeout=10):

        notification.notify(
            title=title,
            message=message,
            app_name="WiFi Threat Detector",
            timeout=timeout
        )

    # ----------------------------------------
    # Dangerous WiFi Alert
    # ----------------------------------------
    def danger_alert(self, ssid, risk, reason):

        title = "🛡 WiFi Threat Alert"

        message = (
            f"Network : {ssid}\n"
            f"Risk Score : {risk}%\n\n"
            f"Reason:\n{reason}\n\n"
            "Recommendation:\n"
            "Do NOT connect to this WiFi."
        )

        self.notify(title, message, 15)

        self.last_alert = datetime.now()

    # ----------------------------------------
    # Safe WiFi Notification
    # ----------------------------------------
    def safe_alert(self, ssid):

        title = "✅ Safe WiFi"

        message = (
            f"You are connected to:\n\n"
            f"{ssid}\n\n"
            "No threat detected."
        )

        self.notify(title, message, 5)

    # ----------------------------------------
    # Fingerprint Warning
    # ----------------------------------------
    def fingerprint_alert(self, ssid, match_score):

        title = "⚠ Fingerprint Mismatch"

        message = (
            f"{ssid}\n\n"
            f"Fingerprint Match : {match_score}%\n\n"
            "This WiFi behaves differently from previous observations."
        )

        self.notify(title, message, 12)

    # ----------------------------------------
    # Connection Notification
    # ----------------------------------------
    def connection_alert(self, ssid):

        title = "📶 WiFi Connected"

        message = (
            f"Connected to\n\n"
            f"{ssid}\n\n"
            "Analyzing security..."
        )

        self.notify(title, message, 5)

    # ----------------------------------------
    # Background Monitor Started
    # ----------------------------------------
    def monitor_started(self):

        title = "🛡 WiFi Monitor"

        message = (
            "Background monitoring has started.\n"
            "All WiFi connections will be checked automatically."
        )

        self.notify(title, message, 5)
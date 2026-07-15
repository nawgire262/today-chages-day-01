<<<<<<< HEAD
import csv
import os
from datetime import datetime


class AlertLogger:

    def __init__(self):

        self.file = "alert_history.csv"

        if not os.path.exists(self.file):

            with open(self.file, "w", newline="", encoding="utf-8") as f:

                writer = csv.writer(f)

                writer.writerow([
                    "Time",
                    "SSID",
                    "BSSID",
                    "Risk",
                    "Reason"
                ])

    def log_alert(
        self,
        ssid,
        bssid,
        risk,
        reason
    ):

        with open(self.file, "a", newline="", encoding="utf-8") as f:

            writer = csv.writer(f)

            writer.writerow([
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                ssid,
                bssid,
                risk,
                reason
=======
import csv
import os
from datetime import datetime


class AlertLogger:

    def __init__(self):

        self.file = "alert_history.csv"

        if not os.path.exists(self.file):

            with open(self.file, "w", newline="", encoding="utf-8") as f:

                writer = csv.writer(f)

                writer.writerow([
                    "Time",
                    "SSID",
                    "BSSID",
                    "Risk",
                    "Reason"
                ])

    def log_alert(
        self,
        ssid,
        bssid,
        risk,
        reason
    ):

        with open(self.file, "a", newline="", encoding="utf-8") as f:

            writer = csv.writer(f)

            writer.writerow([
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                ssid,
                bssid,
                risk,
                reason
>>>>>>> 0d1f8da (Updated SentinelShield project)
            ])
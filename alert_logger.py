<<<<<<< HEAD
import csv
import os
import threading
from datetime import datetime
from database_manager import save_alert


class AlertLogger:
    FIELDNAMES = ["Time", "SSID", "BSSID", "Risk", "Reason"]
    _write_lock = threading.Lock()
=======
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
>>>>>>> fb2e0dfb94cb96bb998dfa037a56d2b2405958b4

    def __init__(self):

        self.file = "alert_history.csv"

        if not os.path.exists(self.file):

            with open(self.file, "w", newline="", encoding="utf-8") as f:

                writer = csv.writer(f)

<<<<<<< HEAD
                writer.writerow(self.FIELDNAMES)
=======
                writer.writerow([
                    "Time",
                    "SSID",
                    "BSSID",
                    "Risk",
                    "Reason"
                ])
>>>>>>> fb2e0dfb94cb96bb998dfa037a56d2b2405958b4

    def log_alert(
        self,
        ssid,
        bssid,
        risk,
        reason
    ):

<<<<<<< HEAD
        # A scan runs in a worker thread, so serialize writes to avoid a
        # partially written CSV when another scan is started immediately.
        with self._write_lock:
            with open(self.file, "a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    ssid,
                    bssid,
                    round(float(risk), 1),
                    reason,
                ])
        save_alert({"ssid": ssid, "alert_type": "Threat Detection", "severity": "CRITICAL" if float(risk) >= 75 else "HIGH", "description": reason})
=======
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
>>>>>>> fb2e0dfb94cb96bb998dfa037a56d2b2405958b4

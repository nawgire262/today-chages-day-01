"""Persistent local BSSID reputation store used even when offline."""

from __future__ import annotations

import csv
from datetime import datetime, timezone
from pathlib import Path


class LocalReputation:
    FIELDS = ["BSSID", "Threat_Count", "Risk_Score", "Last_Seen"]

    def __init__(self, data_dir=None):
        self.data_dir = Path(data_dir) if data_dir else Path(__file__).resolve().parents[1] / "data"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.path = self.data_dir / "bssid_reputation.csv"
        self.history_path = self.data_dir / "reputation_history.csv"
        if not self.path.exists():
            self.path.write_text(",".join(self.FIELDS) + "\n", encoding="utf-8")

    @staticmethod
    def _mac(bssid):
        return (bssid or "").strip().upper()

    def _rows(self):
        with self.path.open(newline="", encoding="utf-8") as handle:
            return list(csv.DictReader(handle))

    def _save(self, rows):
        with self.path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=self.FIELDS)
            writer.writeheader()
            writer.writerows(rows)

    def _history(self, bssid, action, risk):
        new_file = not self.history_path.exists()
        with self.history_path.open("a", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=["Timestamp", "BSSID", "Action", "Risk_Score"])
            if new_file:
                writer.writeheader()
            writer.writerow({"Timestamp": datetime.now(timezone.utc).isoformat(), "BSSID": bssid, "Action": action, "Risk_Score": risk})

    def check_bssid(self, bssid):
        mac = self._mac(bssid)
        for row in self._rows():
            if self._mac(row.get("BSSID")) == mac:
                return {"found": True, "bssid": mac, "threat_count": int(float(row["Threat_Count"])), "risk_score": float(row["Risk_Score"]), "last_seen": row["Last_Seen"], "source": "Local Reputation"}
        return {"found": False, "bssid": mac, "threat_count": 0, "risk_score": 0.0, "last_seen": None, "source": "Local Reputation"}

    def add_bssid(self, bssid, risk_score=0, threat_count=0):
        mac = self._mac(bssid)
        if not mac:
            return self.check_bssid(mac)
        existing = self.check_bssid(mac)
        if existing["found"]:
            return self.update_bssid(mac, risk_score=risk_score, threat_increment=threat_count)
        row = {"BSSID": mac, "Threat_Count": int(threat_count), "Risk_Score": round(max(0, min(100, float(risk_score))), 1), "Last_Seen": datetime.now(timezone.utc).date().isoformat()}
        rows = self._rows(); rows.append(row); self._save(rows); self._history(mac, "added", row["Risk_Score"])
        return self.check_bssid(mac)

    def update_bssid(self, bssid, risk_score=None, threat_increment=1):
        mac, rows = self._mac(bssid), self._rows()
        for row in rows:
            if self._mac(row.get("BSSID")) == mac:
                row["Threat_Count"] = int(float(row["Threat_Count"])) + int(threat_increment)
                current = float(row["Risk_Score"])
                row["Risk_Score"] = round(max(0, min(100, float(risk_score) if risk_score is not None else max(current, current + 5))), 1)
                row["Last_Seen"] = datetime.now(timezone.utc).date().isoformat()
                self._save(rows); self._history(mac, "updated", row["Risk_Score"])
                return self.check_bssid(mac)
        return self.add_bssid(mac, risk_score or 0, threat_increment)

    def get_top_threats(self, limit=10):
        return sorted((self.check_bssid(row["BSSID"]) for row in self._rows()), key=lambda item: item["risk_score"], reverse=True)[:limit]

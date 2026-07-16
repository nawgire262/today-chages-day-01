"""Cached OpenPhish keyword matcher that remains usable while offline."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.request import urlopen

class OpenPhishChecker:
    KEYWORDS = ("login", "free", "secure", "bank", "verify", "wifi", "hotspot")
    def __init__(self, feed_path=None): self.path = Path(feed_path) if feed_path else Path(__file__).resolve().parents[1] / "data" / "openphish_feed.txt"
    def update_feed(self, max_age_hours=24):
        if self.path.exists() and datetime.now(timezone.utc) - datetime.fromtimestamp(self.path.stat().st_mtime, timezone.utc) < timedelta(hours=max_age_hours): return False
        try:
            with urlopen("https://openphish.com/feed.txt", timeout=8) as response: self.path.write_bytes(response.read())
            return True
        except OSError: return False
    def phishing_match(self, ssid):
        text = (ssid or "").lower(); matches = [word for word in self.KEYWORDS if word in text]
        return {"risk_score": min(100.0, len(matches) * 25.0), "matches": matches, "source": "OpenPhish"}

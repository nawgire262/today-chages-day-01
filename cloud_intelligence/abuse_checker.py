"""Optional AbuseIPDB client; unavailable credentials return a neutral result."""
import json, os, time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

class AbuseIPDBChecker:
    def __init__(self, api_key=None, retries=2): self.api_key, self.retries = api_key or os.getenv("ABUSEIPDB_API_KEY"), retries
    def check_ip(self, ip):
        empty = {"abuse_score": 0.0, "reports": 0, "source": "AbuseIPDB"}
        if not self.api_key: return empty
        for attempt in range(self.retries + 1):
            try:
                query = urlencode({"ipAddress": str(ip), "maxAgeInDays": 90})
                request = Request(f"https://api.abuseipdb.com/api/v2/check?{query}", headers={"Key": self.api_key, "Accept": "application/json"})
                with urlopen(request, timeout=8) as response: data = json.load(response).get("data", {})
                return {"abuse_score": float(data.get("abuseConfidenceScore", 0)), "reports": int(data.get("totalReports", 0)), "source": "AbuseIPDB"}
            except HTTPError as error:
                if error.code != 429 or attempt == self.retries: return empty
            except (URLError, TimeoutError, ValueError): return empty
            time.sleep(2 ** attempt)
        return empty

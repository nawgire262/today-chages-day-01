"""Optional VirusTotal client with retries and graceful offline behavior."""
import json, os, time
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

class VirusTotalChecker:
    def __init__(self, api_key=None, retries=2): self.api_key, self.retries = api_key or os.getenv("VIRUSTOTAL_API_KEY"), retries
    def _check(self, endpoint):
        empty = {"risk_score": 0.0, "malicious": 0, "suspicious": 0, "source": "VirusTotal"}
        if not self.api_key: return empty
        for attempt in range(self.retries + 1):
            try:
                request = Request(f"https://www.virustotal.com/api/v3/{endpoint}", headers={"x-apikey": self.api_key})
                with urlopen(request, timeout=8) as response: payload = json.load(response)
                stats = payload.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious, suspicious = int(stats.get("malicious", 0)), int(stats.get("suspicious", 0))
                return {"risk_score": min(100.0, malicious * 10 + suspicious * 5), "malicious": malicious, "suspicious": suspicious, "source": "VirusTotal"}
            except HTTPError as error:
                if error.code != 429 or attempt == self.retries: return empty
            except (URLError, TimeoutError, ValueError): return empty
            time.sleep(2 ** attempt)
        return empty
    def check_ip(self, ip): return self._check(f"ip_addresses/{quote(str(ip))}")
    def check_domain(self, domain): return self._check(f"domains/{quote(str(domain))}")
    def check_url(self, url): return self._check(f"urls/{quote(str(url), safe='')}")

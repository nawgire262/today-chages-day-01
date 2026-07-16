"""Unified local-first cloud intelligence score for a scanned Wi-Fi network."""
from .abuse_checker import AbuseIPDBChecker
from .local_reputation import LocalReputation
from .phishing_checker import OpenPhishChecker
from .virustotal_checker import VirusTotalChecker

class CloudIntelligenceEngine:
    def __init__(self):
        self.local = LocalReputation()
        self.virustotal = VirusTotalChecker()
        self.abuseipdb = AbuseIPDBChecker()
        self.openphish = OpenPhishChecker()

    def evaluate_network(self, ssid, bssid, ip=None, domain=None, url=None):
        reputation = self.local.check_bssid(bssid)
        vt = self.virustotal.check_ip(ip) if ip else (self.virustotal.check_domain(domain) if domain else (self.virustotal.check_url(url) if url else {"risk_score": 0.0, "malicious": 0, "suspicious": 0, "source": "VirusTotal"}))
        abuse = self.abuseipdb.check_ip(ip) if ip else {"abuse_score": 0.0, "reports": 0, "source": "AbuseIPDB"}
        phishing = self.openphish.phishing_match(ssid)
        cloud_risk = (float(vt["risk_score"]) + float(abuse["abuse_score"]) + float(reputation["risk_score"]) + float(phishing["risk_score"])) / 4
        return {"cloud_risk": round(cloud_risk, 1), "virustotal": vt, "abuseipdb": abuse, "bssid_reputation": reputation, "phishing_risk": phishing}

    def learn_threat(self, bssid, risk_score):
        return self.local.update_bssid(bssid, risk_score=risk_score, threat_increment=1)

    def summary(self):
        return {"top_suspicious_bssids": self.local.get_top_threats(), "providers_configured": {"VirusTotal": bool(self.virustotal.api_key), "AbuseIPDB": bool(self.abuseipdb.api_key)}}

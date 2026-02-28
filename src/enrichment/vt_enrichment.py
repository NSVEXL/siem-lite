"""
SIEM-Lite | VirusTotal IP Enrichment
Queries VirusTotal API v3 for IP reputation data.
"""

import requests
import time
import os
from dataclasses import dataclass
from typing import Optional
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY", "")
VT_BASE_URL = "https://www.virustotal.com/api/v3"
RATE_LIMIT_DELAY = 15  # seconds between requests (free tier: 4/min)


@dataclass
class IPReport:
    ip: str
    malicious:   int = 0
    suspicious:  int = 0
    harmless:    int = 0
    undetected:  int = 0
    country:     str = "N/A"
    asn:         str = "N/A"
    as_owner:    str = "N/A"
    reputation:  int = 0
    verdict:     str = "UNKNOWN"
    error:       Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "ip":          self.ip,
            "malicious":   self.malicious,
            "suspicious":  self.suspicious,
            "harmless":    self.harmless,
            "undetected":  self.undetected,
            "country":     self.country,
            "asn":         self.asn,
            "as_owner":    self.as_owner,
            "reputation":  self.reputation,
            "verdict":     self.verdict,
            "error":       self.error,
        }


def get_ip_report(ip: str, api_key: str = "") -> IPReport:
    """
    Queries VirusTotal for an IP address reputation report.
    Skips private/local IPs automatically.
    """
    key = api_key or VT_API_KEY

    # Skip private/local IPs — no point querying VT for these
    private_prefixes = ("10.", "192.168.", "172.", "127.", "local")
    if any(ip.startswith(p) for p in private_prefixes):
        return IPReport(ip=ip, verdict="PRIVATE", error="Private/local IP — skipped")

    if not key:
        return IPReport(ip=ip, verdict="NO_KEY", error="No API key provided")

    headers = {"x-apikey": key, "Accept": "application/json"}

    try:
        response = requests.get(
            f"{VT_BASE_URL}/ip_addresses/{ip}",
            headers=headers,
            timeout=10
        )

        if response.status_code == 401:
            return IPReport(ip=ip, verdict="ERROR", error="Invalid API key")

        if response.status_code == 429:
            return IPReport(ip=ip, verdict="ERROR", error="Rate limit exceeded — wait and retry")

        if response.status_code != 200:
            return IPReport(ip=ip, verdict="ERROR", error=f"HTTP {response.status_code}")

        data = response.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})

        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless   = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)

        # Determine verdict
        if malicious >= 5:
            verdict = "MALICIOUS"
        elif malicious >= 1 or suspicious >= 3:
            verdict = "SUSPICIOUS"
        elif harmless > 0:
            verdict = "CLEAN"
        else:
            verdict = "UNKNOWN"

        return IPReport(
            ip         = ip,
            malicious  = malicious,
            suspicious = suspicious,
            harmless   = harmless,
            undetected = undetected,
            country    = data.get("country", "N/A"),
            asn        = str(data.get("asn", "N/A")),
            as_owner   = data.get("as_owner", "N/A"),
            reputation = data.get("reputation", 0),
            verdict    = verdict,
        )

    except requests.exceptions.Timeout:
        return IPReport(ip=ip, verdict="ERROR", error="Request timeout")
    except requests.exceptions.ConnectionError:
        return IPReport(ip=ip, verdict="ERROR", error="Connection error")
    except Exception as e:
        return IPReport(ip=ip, verdict="ERROR", error=str(e))


def enrich_alerts(alerts: list, api_key: str = "") -> dict:
    """
    Takes a list of Alert objects, extracts unique public IPs,
    queries VirusTotal for each, and returns a dict: {ip: IPReport}
    """
    # Get unique public IPs from alerts
    private_prefixes = ("10.", "192.168.", "172.", "127.", "local")
    unique_ips = set()
    for alert in alerts:
        ip = alert.source_ip if hasattr(alert, 'source_ip') else alert.get('source_ip', '')
        if ip and not any(ip.startswith(p) for p in private_prefixes):
            unique_ips.add(ip)

    results = {}
    ips = list(unique_ips)

    for i, ip in enumerate(ips):
        print(f"  [{i+1}/{len(ips)}] Querying VT for {ip}...")
        results[ip] = get_ip_report(ip, api_key)

        # Rate limiting: wait between requests (free tier = 4 req/min)
        if i < len(ips) - 1:
            time.sleep(RATE_LIMIT_DELAY)

    return results


def format_verdict_symbol(verdict: str) -> str:
    return {
        "MALICIOUS":  "🔴 MALICIOUS",
        "SUSPICIOUS": "🟡 SUSPICIOUS",
        "CLEAN":      "🟢 CLEAN",
        "PRIVATE":    "⚪ PRIVATE",
        "UNKNOWN":    "⚫ UNKNOWN",
        "ERROR":      "❌ ERROR",
        "NO_KEY":     "🔑 NO KEY",
    }.get(verdict, verdict)


# ── QUICK TEST ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    sys.path.insert(0, "../..")
    from src.parser.log_parser import load_all_logs
    from src.detector.detection_engine import DetectionEngine

    logs = load_all_logs("../../logs/samples")
    engine = DetectionEngine()
    alerts = engine.run(logs)

    api_key = os.getenv("VT_API_KEY", "")
    if not api_key:
        print("\n[!] No VT_API_KEY found in .env — running in demo mode\n")

    print("\n🔍 VirusTotal IP Enrichment")
    print("─" * 50)

    private_prefixes = ("10.", "192.168.", "172.", "127.", "local")
    unique_ips = set(
        a.source_ip for a in alerts
        if not any(a.source_ip.startswith(p) for p in private_prefixes)
    )

    for ip in unique_ips:
        report = get_ip_report(ip, api_key)
        print(f"\n  IP:      {report.ip}")
        print(f"  Verdict: {format_verdict_symbol(report.verdict)}")
        if not report.error:
            print(f"  Country: {report.country}")
            print(f"  ASN:     {report.asn} ({report.as_owner})")
            print(f"  Stats:   {report.malicious} malicious · {report.suspicious} suspicious · {report.harmless} clean")
        else:
            print(f"  Note:    {report.error}")

"""
SIEM-Lite | Flask Dashboard
Web interface for visualizing threat detection alerts.
"""

from flask import Flask, render_template, jsonify, request
from src.parser.log_parser import load_all_logs
from src.detector.detection_engine import DetectionEngine
from src.enrichment.vt_enrichment import get_ip_report, format_verdict_symbol
from collections import Counter
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__, template_folder="templates", static_folder="static")

LOG_DIR = os.path.join(os.path.dirname(__file__), "logs", "samples")
VT_API_KEY = os.getenv("VT_API_KEY", "")


def get_analysis():
    logs = load_all_logs(LOG_DIR)
    engine = DetectionEngine()
    alerts = engine.run(logs)

    alert_dicts = [a.to_dict() for a in alerts]

    severity_counts = Counter(a["severity"] for a in alert_dicts)
    type_counts     = Counter(a["alert_type"] for a in alert_dicts)
    ip_counts       = Counter(a["source_ip"] for a in alert_dicts)
    tactic_counts   = Counter(a["mitre_tactic"] for a in alert_dicts)

    return {
        "alerts": alert_dicts,
        "stats": {
            "total_alerts":    len(alert_dicts),
            "critical":        severity_counts.get("CRITICAL", 0),
            "high":            severity_counts.get("HIGH", 0),
            "medium":          severity_counts.get("MEDIUM", 0),
            "low":             severity_counts.get("LOW", 0),
            "auth_events":     len(logs["auth"]),
            "firewall_events": len(logs["firewall"]),
        },
        "charts": {
            "by_type":   dict(type_counts),
            "by_ip":     dict(ip_counts.most_common(5)),
            "by_tactic": dict(tactic_counts),
        },
        "vt_enabled": bool(VT_API_KEY),
    }


@app.route("/")
def index():
    data = get_analysis()
    return render_template("dashboard.html", data=data)


@app.route("/api/alerts")
def api_alerts():
    data = get_analysis()
    return jsonify(data)


@app.route("/api/enrich/<ip>")
def api_enrich(ip):
    """
    On-demand VirusTotal lookup for a single IP.
    Called from the dashboard when user clicks 'Enrich'.
    """
    report = get_ip_report(ip, VT_API_KEY)
    result = report.to_dict()
    result["verdict_label"] = format_verdict_symbol(report.verdict)
    return jsonify(result)


if __name__ == "__main__":
    app.run(debug=True, port=5000)

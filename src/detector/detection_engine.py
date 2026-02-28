"""
SIEM-Lite | Threat Detection Engine
Analyzes normalized log events and generates security alerts
mapped to the MITRE ATT&CK framework.
"""

import pandas as pd
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Optional


# ─── MITRE ATT&CK MAPPING ──────────────────────────────────────────────────────

MITRE = {
    "BRUTE_FORCE":          {"id": "T1110",   "tactic": "Credential Access",  "name": "Brute Force"},
    "PORT_SCAN":            {"id": "T1046",   "tactic": "Discovery",          "name": "Network Service Discovery"},
    "PRIVILEGE_ESCALATION": {"id": "T1548",   "tactic": "Privilege Escalation","name": "Abuse Elevation Control Mechanism"},
    "SUSPICIOUS_LOGIN":     {"id": "T1078",   "tactic": "Initial Access",     "name": "Valid Accounts"},
    "CREDENTIAL_DUMP":      {"id": "T1003",   "tactic": "Credential Access",  "name": "OS Credential Dumping"},
}

# ─── SEVERITY LEVELS ───────────────────────────────────────────────────────────

SEVERITY = {
    "CRITICAL": 4,
    "HIGH":     3,
    "MEDIUM":   2,
    "LOW":      1,
}

# ─── ALERT DATACLASS ───────────────────────────────────────────────────────────

@dataclass
class Alert:
    alert_type:   str
    severity:     str
    source_ip:    str
    description:  str
    mitre_id:     str
    mitre_tactic: str
    mitre_name:   str
    timestamp:    datetime
    evidence:     list = field(default_factory=list)
    user:         Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "timestamp":    self.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "alert_type":   self.alert_type,
            "severity":     self.severity,
            "source_ip":    self.source_ip,
            "user":         self.user or "-",
            "description":  self.description,
            "mitre_id":     self.mitre_id,
            "mitre_tactic": self.mitre_tactic,
            "mitre_name":   self.mitre_name,
            "evidence_count": len(self.evidence),
        }


# ─── DETECTION RULES ───────────────────────────────────────────────────────────

class DetectionEngine:

    def __init__(self, brute_force_threshold: int = 5, port_scan_threshold: int = 8,
                 off_hours_start: int = 22, off_hours_end: int = 6):
        self.brute_force_threshold = brute_force_threshold
        self.port_scan_threshold   = port_scan_threshold
        self.off_hours_start       = off_hours_start
        self.off_hours_end         = off_hours_end
        self.alerts: list[Alert]   = []

    # ── Rule 1: SSH Brute Force ─────────────────────────────────────────────────
    def detect_brute_force(self, auth_df: pd.DataFrame) -> list[Alert]:
        """
        Flags IPs with >= N failed logins within a 5-minute window.
        MITRE T1110 — Brute Force
        """
        alerts = []
        if auth_df.empty:
            return alerts

        failed = auth_df[auth_df["event_type"] == "AUTH_FAILED"].copy()
        if failed.empty:
            return alerts

        failed = failed.sort_values("timestamp")

        for ip, group in failed.groupby("source_ip"):
            group = group.sort_values("timestamp").reset_index(drop=True)
            window_start = group.iloc[0]["timestamp"]
            window_events = []

            for _, row in group.iterrows():
                if row["timestamp"] - window_start <= timedelta(minutes=5):
                    window_events.append(row)
                else:
                    if len(window_events) >= self.brute_force_threshold:
                        m = MITRE["BRUTE_FORCE"]
                        alerts.append(Alert(
                            alert_type   = "BRUTE_FORCE",
                            severity     = "HIGH",
                            source_ip    = ip,
                            description  = f"Brute force attack detected: {len(window_events)} failed SSH logins from {ip} in under 5 minutes.",
                            mitre_id     = m["id"],
                            mitre_tactic = m["tactic"],
                            mitre_name   = m["name"],
                            timestamp    = window_start,
                            evidence     = window_events,
                            user         = window_events[0]["user"],
                        ))
                    window_start = row["timestamp"]
                    window_events = [row]

            # Check last window
            if len(window_events) >= self.brute_force_threshold:
                m = MITRE["BRUTE_FORCE"]
                alerts.append(Alert(
                    alert_type   = "BRUTE_FORCE",
                    severity     = "HIGH",
                    source_ip    = ip,
                    description  = f"Brute force attack detected: {len(window_events)} failed SSH logins from {ip} in under 5 minutes.",
                    mitre_id     = m["id"],
                    mitre_tactic = m["tactic"],
                    mitre_name   = m["name"],
                    timestamp    = window_start,
                    evidence     = window_events,
                    user         = window_events[0]["user"],
                ))

        return alerts

    # ── Rule 2: Port Scan ───────────────────────────────────────────────────────
    def detect_port_scan(self, firewall_df: pd.DataFrame) -> list[Alert]:
        """
        Flags IPs hitting >= N distinct ports in under 2 minutes.
        MITRE T1046 — Network Service Discovery
        """
        alerts = []
        if firewall_df.empty:
            return alerts

        blocked = firewall_df[firewall_df["event_type"] == "FW_BLOCK"].copy()
        if blocked.empty:
            return alerts

        for ip, group in blocked.groupby("source_ip"):
            group = group.sort_values("timestamp").reset_index(drop=True)
            window_start = group.iloc[0]["timestamp"]
            ports_hit = set()
            window_events = []

            for _, row in group.iterrows():
                if row["timestamp"] - window_start <= timedelta(minutes=2):
                    ports_hit.add(row["dst_port"])
                    window_events.append(row)
                else:
                    if len(ports_hit) >= self.port_scan_threshold:
                        m = MITRE["PORT_SCAN"]
                        alerts.append(Alert(
                            alert_type   = "PORT_SCAN",
                            severity     = "MEDIUM",
                            source_ip    = ip,
                            description  = f"Port scan detected: {ip} probed {len(ports_hit)} distinct ports in under 2 minutes. Ports: {sorted(ports_hit)}",
                            mitre_id     = m["id"],
                            mitre_tactic = m["tactic"],
                            mitre_name   = m["name"],
                            timestamp    = window_start,
                            evidence     = window_events,
                        ))
                    window_start = row["timestamp"]
                    ports_hit = {row["dst_port"]}
                    window_events = [row]

            if len(ports_hit) >= self.port_scan_threshold:
                m = MITRE["PORT_SCAN"]
                alerts.append(Alert(
                    alert_type   = "PORT_SCAN",
                    severity     = "MEDIUM",
                    source_ip    = ip,
                    description  = f"Port scan detected: {ip} probed {len(ports_hit)} distinct ports in under 2 minutes. Ports: {sorted(ports_hit)}",
                    mitre_id     = m["id"],
                    mitre_tactic = m["tactic"],
                    mitre_name   = m["name"],
                    timestamp    = window_start,
                    evidence     = window_events,
                ))

        return alerts

    # ── Rule 3: Privilege Escalation ────────────────────────────────────────────
    def detect_privilege_escalation(self, auth_df: pd.DataFrame) -> list[Alert]:
        """
        Flags sudo commands that change passwords or open shells as root.
        MITRE T1548 — Abuse Elevation Control Mechanism
        """
        alerts = []
        if auth_df.empty:
            return alerts

        suspicious_commands = ["/bin/bash", "/bin/sh", "passwd", "/etc/shadow", "/etc/sudoers"]
        sudo_events = auth_df[auth_df["event_type"] == "SUDO_EXEC"].copy()

        for _, row in sudo_events.iterrows():
            details = row["details"].lower()
            if any(cmd in details for cmd in suspicious_commands):
                m = MITRE["PRIVILEGE_ESCALATION"]
                alerts.append(Alert(
                    alert_type   = "PRIVILEGE_ESCALATION",
                    severity     = "CRITICAL",
                    source_ip    = row["source_ip"],
                    description  = f"Suspicious privilege escalation: {row['details']}",
                    mitre_id     = m["id"],
                    mitre_tactic = m["tactic"],
                    mitre_name   = m["name"],
                    timestamp    = row["timestamp"],
                    evidence     = [row],
                    user         = row["user"],
                ))

        return alerts

    # ── Rule 4: Off-Hours Login ─────────────────────────────────────────────────
    def detect_off_hours_login(self, auth_df: pd.DataFrame) -> list[Alert]:
        """
        Flags successful logins outside business hours (22:00 - 06:00).
        MITRE T1078 — Valid Accounts
        """
        alerts = []
        if auth_df.empty:
            return alerts

        success = auth_df[auth_df["event_type"] == "AUTH_SUCCESS"].copy()

        for _, row in success.iterrows():
            hour = row["timestamp"].hour
            is_off_hours = hour >= self.off_hours_start or hour < self.off_hours_end
            if is_off_hours:
                m = MITRE["SUSPICIOUS_LOGIN"]
                alerts.append(Alert(
                    alert_type   = "SUSPICIOUS_LOGIN",
                    severity     = "MEDIUM",
                    source_ip    = row["source_ip"],
                    description  = f"Login outside business hours at {row['timestamp'].strftime('%H:%M')} by user '{row['user']}' from {row['source_ip']}.",
                    mitre_id     = m["id"],
                    mitre_tactic = m["tactic"],
                    mitre_name   = m["name"],
                    timestamp    = row["timestamp"],
                    evidence     = [row],
                    user         = row["user"],
                ))

        return alerts

    # ── Rule 5: Credential Dump ─────────────────────────────────────────────────
    def detect_credential_dump(self, auth_df: pd.DataFrame) -> list[Alert]:
        """
        Flags access to sensitive credential files like /etc/shadow or /etc/passwd.
        MITRE T1003 — OS Credential Dumping
        """
        alerts = []
        if auth_df.empty:
            return alerts

        credential_files = ["/etc/shadow", "/etc/passwd", "/etc/gshadow"]
        sudo_events = auth_df[auth_df["event_type"] == "SUDO_EXEC"].copy()

        for _, row in sudo_events.iterrows():
            details = row["details"].lower()
            if any(f in details for f in credential_files):
                m = MITRE["CREDENTIAL_DUMP"]
                alerts.append(Alert(
                    alert_type   = "CREDENTIAL_DUMP",
                    severity     = "CRITICAL",
                    source_ip    = row["source_ip"],
                    description  = f"Credential file access detected: {row['details']}",
                    mitre_id     = m["id"],
                    mitre_tactic = m["tactic"],
                    mitre_name   = m["name"],
                    timestamp    = row["timestamp"],
                    evidence     = [row],
                    user         = row["user"],
                ))

        return alerts

    # ── Run All Rules ───────────────────────────────────────────────────────────
    def run(self, logs: dict) -> list[Alert]:
        """
        Runs all detection rules against the normalized logs.
        Returns a sorted list of Alert objects.
        """
        auth_df     = logs.get("auth", pd.DataFrame())
        firewall_df = logs.get("firewall", pd.DataFrame())

        self.alerts = []
        self.alerts += self.detect_brute_force(auth_df)
        self.alerts += self.detect_port_scan(firewall_df)
        self.alerts += self.detect_privilege_escalation(auth_df)
        self.alerts += self.detect_off_hours_login(auth_df)
        self.alerts += self.detect_credential_dump(auth_df)

        # Sort by severity then timestamp
        self.alerts.sort(key=lambda a: (-SEVERITY.get(a.severity, 0), a.timestamp))
        return self.alerts

    def to_dataframe(self) -> pd.DataFrame:
        if not self.alerts:
            return pd.DataFrame()
        return pd.DataFrame([a.to_dict() for a in self.alerts])


# ─── QUICK TEST ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    sys.path.insert(0, "../..")
    from src.parser.log_parser import load_all_logs

    logs = load_all_logs("../../logs/samples")
    engine = DetectionEngine()
    alerts = engine.run(logs)

    COLORS = {"CRITICAL": "\033[91m", "HIGH": "\033[93m", "MEDIUM": "\033[94m", "LOW": "\033[92m"}
    RESET = "\033[0m"

    print(f"\n{'═'*70}")
    print(f"  🛡️  SIEM-LITE — THREAT DETECTION REPORT")
    print(f"{'═'*70}")
    print(f"  Logs analyzed: {len(logs['auth'])} auth events · {len(logs['firewall'])} firewall events")
    print(f"  Alerts generated: {len(alerts)}")
    print(f"{'═'*70}\n")

    for alert in alerts:
        color = COLORS.get(alert.severity, "")
        print(f"  {color}[{alert.severity}]{RESET} {alert.alert_type}")
        print(f"  {'─'*60}")
        print(f"  🕐 Time:        {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  🌐 Source IP:   {alert.source_ip}")
        if alert.user:
            print(f"  👤 User:        {alert.user}")
        print(f"  📋 Description: {alert.description}")
        print(f"  🎯 MITRE:       [{alert.mitre_id}] {alert.mitre_name} ({alert.mitre_tactic})")
        print(f"  📊 Evidence:    {len(alert.evidence)} log event(s)")
        print()

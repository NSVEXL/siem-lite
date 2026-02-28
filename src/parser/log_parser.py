"""
SIEM-Lite | Log Parser Module
Parses Linux auth.log and firewall logs into a normalized format.
"""

import re
import pandas as pd
from datetime import datetime
from pathlib import Path


# ─── REGEX PATTERNS ────────────────────────────────────────────────────────────

AUTH_FAILED = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+\S+\s+sshd\[\d+\]:\s+"
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)"
)

AUTH_ACCEPTED = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+\S+\s+sshd\[\d+\]:\s+"
    r"Accepted password for (?P<user>\S+) from (?P<ip>[\d.]+)"
)

SUDO_CMD = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+\S+\s+sudo\[\d+\]:\s+"
    r"(?P<user>\S+)\s+:.*COMMAND=(?P<command>.+)"
)

FIREWALL_LINE = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+\S+\s+kernel:.*"
    r"\[UFW (?P<action>BLOCK|ALLOW)\].*SRC=(?P<src_ip>[\d.]+)\s+DST=(?P<dst_ip>[\d.]+)"
    r".*PROTO=(?P<proto>\w+).*DPT=(?P<dst_port>\d+)"
)

# ─── HELPERS ───────────────────────────────────────────────────────────────────

MONTH_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4,
    "May": 5, "Jun": 6, "Jul": 7, "Aug": 8,
    "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
}

def parse_timestamp(month: str, day: str, time: str) -> datetime:
    year = datetime.now().year
    return datetime(year, MONTH_MAP.get(month, 1), int(day),
                    *map(int, time.split(":")))

# ─── PARSERS ───────────────────────────────────────────────────────────────────

def parse_auth_log(filepath: str) -> pd.DataFrame:
    """
    Parses a Linux auth.log file.
    Returns a DataFrame with normalized events.
    """
    records = []
    path = Path(filepath)

    if not path.exists():
        print(f"[!] File not found: {filepath}")
        return pd.DataFrame()

    with open(path, "r", errors="ignore") as f:
        for line in f:
            line = line.strip()

            # Failed login attempt
            m = AUTH_FAILED.search(line)
            if m:
                records.append({
                    "timestamp": parse_timestamp(m["month"], m["day"], m["time"]),
                    "event_type": "AUTH_FAILED",
                    "source_ip": m["ip"],
                    "user": m["user"],
                    "details": f"Failed SSH login for user '{m['user']}'",
                    "raw": line
                })
                continue

            # Successful login
            m = AUTH_ACCEPTED.search(line)
            if m:
                records.append({
                    "timestamp": parse_timestamp(m["month"], m["day"], m["time"]),
                    "event_type": "AUTH_SUCCESS",
                    "source_ip": m["ip"],
                    "user": m["user"],
                    "details": f"Successful SSH login for user '{m['user']}'",
                    "raw": line
                })
                continue

            # Sudo command executed
            m = SUDO_CMD.search(line)
            if m:
                records.append({
                    "timestamp": parse_timestamp(m["month"], m["day"], m["time"]),
                    "event_type": "SUDO_EXEC",
                    "source_ip": "local",
                    "user": m["user"],
                    "details": f"Sudo command by '{m['user']}': {m['command'].strip()}",
                    "raw": line
                })

    df = pd.DataFrame(records)
    if not df.empty:
        df = df.sort_values("timestamp").reset_index(drop=True)
    return df


def parse_firewall_log(filepath: str) -> pd.DataFrame:
    """
    Parses a UFW/firewall log file.
    Returns a DataFrame with normalized events.
    """
    records = []
    path = Path(filepath)

    if not path.exists():
        print(f"[!] File not found: {filepath}")
        return pd.DataFrame()

    with open(path, "r", errors="ignore") as f:
        for line in f:
            line = line.strip()
            m = FIREWALL_LINE.search(line)
            if m:
                records.append({
                    "timestamp": parse_timestamp(m["month"], m["day"], m["time"]),
                    "event_type": f"FW_{m['action']}",
                    "source_ip": m["src_ip"],
                    "dst_ip": m["dst_ip"],
                    "protocol": m["proto"],
                    "dst_port": int(m["dst_port"]),
                    "details": f"Firewall {m['action']}: {m['src_ip']} → {m['dst_ip']}:{m['dst_port']} ({m['proto']})",
                    "raw": line
                })

    df = pd.DataFrame(records)
    if not df.empty:
        df = df.sort_values("timestamp").reset_index(drop=True)
    return df


def load_all_logs(log_dir: str) -> dict:
    """
    Loads all supported log files from a directory.
    Returns a dict with keys: 'auth', 'firewall'
    """
    base = Path(log_dir)
    return {
        "auth": parse_auth_log(base / "auth.log"),
        "firewall": parse_firewall_log(base / "firewall.log"),
    }


# ─── QUICK TEST ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logs = load_all_logs("../logs/samples")

    print("\n📋 AUTH LOG EVENTS")
    print("─" * 60)
    if not logs["auth"].empty:
        for _, row in logs["auth"].iterrows():
            print(f"  [{row['timestamp'].strftime('%H:%M:%S')}] {row['event_type']:15} | {row['source_ip']:15} | {row['details']}")
    
    print("\n🔥 FIREWALL LOG EVENTS")
    print("─" * 60)
    if not logs["firewall"].empty:
        for _, row in logs["firewall"].iterrows():
            print(f"  [{row['timestamp'].strftime('%H:%M:%S')}] {row['event_type']:12} | {row['source_ip']:15} | Port {row['dst_port']}")

    print(f"\n✅ Total auth events:     {len(logs['auth'])}")
    print(f"✅ Total firewall events: {len(logs['firewall'])}")

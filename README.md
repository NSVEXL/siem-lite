# 🛡️ SIEM-Lite — Log Analysis & Threat Detection

A lightweight SIEM built in Python that ingests real Linux and firewall logs, detects attack patterns, and classifies them using the MITRE ATT&CK framework.

## Features (Roadmap)
- [x] **Phase 1** — Log Parser (auth.log + firewall logs)
- [ ] **Phase 2** — Threat Detection Engine (brute force, port scan, privilege escalation)
- [ ] **Phase 3** — Web Dashboard (Flask + Chart.js)
- [ ] **Phase 4** — VirusTotal IP enrichment

## Tech Stack
Python · Pandas · Flask · VirusTotal API · MITRE ATT&CK

## Setup

```bash
git clone https://github.com/NSVEXL/siem-lite.git
cd siem-lite
pip install -r requirements.txt
```

## Run the parser
```bash
python -m src.parser.log_parser
```

## Project Structure
```
siem-lite/
├── src/
│   ├── parser/        # Log ingestion & normalization
│   ├── detector/      # Threat detection rules (Phase 2)
│   └── dashboard/     # Flask web app (Phase 3)
├── logs/
│   └── samples/       # Sample logs for testing
├── templates/         # HTML templates
└── static/            # CSS & JS assets
```

---
Built by [Nelson Silva Valderas](https://github.com/NSVEXL) as part of a hands-on SOC portfolio.

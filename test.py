from src.parser.log_parser import load_all_logs
from src.detector.detection_engine import DetectionEngine

logs = load_all_logs('logs/samples')
engine = DetectionEngine()
alerts = engine.run(logs)

print(f'Auth events:     {len(logs["auth"])}')
print(f'Firewall events: {len(logs["firewall"])}')
print(f'Alerts detected: {len(alerts)}')
print()
for a in alerts:
    print(f'[{a.severity:8}] {a.alert_type:25} | {a.source_ip:15} | {a.mitre_id}')
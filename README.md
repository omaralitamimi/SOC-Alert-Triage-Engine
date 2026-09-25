# SOC Alert Triage & Detection Engine

A defensive Blue Team portfolio project that simulates a small SOC triage pipeline. It ingests synthetic JSONL security telemetry, applies transparent detection rules, prioritizes alerts, extracts indicators, maps detections to MITRE ATT&CK, and produces an analyst-friendly incident report.

> All included telemetry is fictional and uses documentation/test values. This project is designed for defensive learning and offline analysis.

## Why I built it

I wanted a project that demonstrates the workflow behind an L1 SOC investigation rather than only printing individual log matches: ingest telemetry, detect suspicious patterns, prioritize alerts, preserve evidence, map behavior to ATT&CK, and create a handoff-ready report.

## SOC skills demonstrated

- Alert triage and severity prioritization
- Windows/Linux-style endpoint event analysis concepts
- Authentication and network telemetry analysis
- IOC extraction (IP, domain, hash)
- MITRE ATT&CK mapping
- Incident documentation and analyst handoff
- Python automation and unit testing

## Detection coverage

| Detection | Severity | MITRE ATT&CK |
|---|---|---|
| Repeated authentication failures | High | T1110 Brute Force |
| Encoded PowerShell execution | High | T1059.001 PowerShell |
| New account creation | Medium | T1136 Create Account |
| Privileged-role assignment | High | T1098 Account Manipulation |
| Repeated outbound connection pattern | Medium | T1071.001 Web Protocols |

## Quick start

Requires Python 3.10+ and no third-party packages.

```bash
python main.py data/sample_events.jsonl
python main.py data/sample_events.jsonl --json
python main.py data/sample_events.jsonl --report examples/triage_report.md
python -m unittest discover -s tests -v
```

## Example console output

```text
Analyzed 12 events | 5 alerts
[HIGH  ]  80  Encoded PowerShell execution  (T1059.001)
[HIGH  ]  75  Account granted privileged role  (T1098)
[HIGH  ]  70  Repeated authentication failures for admin  (T1110)
[MEDIUM]  60  Repeated outbound connections from ws-07 to 198.51.100.25  (T1071.001)
[MEDIUM]  55  New local/domain account created  (T1136)
```

## Project structure

```text
soc-alert-triage-engine/
├── main.py
├── soc_triage/
│   ├── __init__.py
│   ├── engine.py
│   └── report.py
├── data/sample_events.jsonl
├── examples/triage_report.md
└── tests/test_engine.py
```

## Investigation discipline

An alert is not proof of compromise. The engine deliberately labels its output as investigation leads. A real analyst should validate user context, asset ownership, change windows, endpoint telemetry, surrounding network activity, and known-good administrative behavior before escalation.

## Next improvements

- Sigma rule ingestion
- Windows Event ID normalization
- Syslog parser
- Detection time windows and baselining
- CSV/JSON export for dashboarding
- Optional OpenSearch/Elastic integration

## Author

Omar Al Tamimi — Cybersecurity student focused on SOC operations, threat detection, incident response, Linux, networking, and Python automation.

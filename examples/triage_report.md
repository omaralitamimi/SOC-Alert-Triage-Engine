# SOC Triage Report

Generated: 2026-09-25T23:12:03.386901+00:00

## Executive Summary
- Events analyzed: 12
- Alerts generated: 5
- Severity counts: {'high': 3, 'medium': 2}

## Alert Queue
### 1. Encoded PowerShell execution
- Severity: **HIGH**
- Risk score: 80/100
- MITRE ATT&CK: T1059.001 — PowerShell
- Evidence events: 1
- IOCs: None extracted

### 2. Account granted privileged role
- Severity: **HIGH**
- Risk score: 75/100
- MITRE ATT&CK: T1098 — Account Manipulation
- Evidence events: 1
- IOCs: None extracted

### 3. Repeated authentication failures for admin
- Severity: **HIGH**
- Risk score: 70/100
- MITRE ATT&CK: T1110 — Brute Force
- Evidence events: 5
- IOCs: 203.0.113.45

### 4. Repeated outbound connections from ws-07 to 198.51.100.25
- Severity: **MEDIUM**
- Risk score: 60/100
- MITRE ATT&CK: T1071.001 — Web Protocols
- Evidence events: 4
- IOCs: 198.51.100.25

### 5. New local/domain account created
- Severity: **MEDIUM**
- Risk score: 55/100
- MITRE ATT&CK: T1136 — Create Account
- Evidence events: 1
- IOCs: None extracted

## IOC Summary
- IPs: 198.51.100.25, 203.0.113.45
- Domains: updates-lab.example
- Hashes: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

## Analyst Notes
Detections are investigation leads, not proof of malicious activity. Validate context, asset ownership, user activity, and surrounding telemetry before escalation.

from datetime import datetime, timezone

def markdown_report(summary, alerts, iocs):
    lines=["# SOC Triage Report","",f"Generated: {datetime.now(timezone.utc).isoformat()}","",
           "## Executive Summary",f"- Events analyzed: {summary['events_analyzed']}",
           f"- Alerts generated: {summary['alerts_generated']}",f"- Severity counts: {summary['severity_counts']}","",
           "## Alert Queue"]
    if not alerts: lines.append("No detections triggered.")
    for i,a in enumerate(alerts,1):
        lines += [f"### {i}. {a['title']}",f"- Severity: **{a['severity'].upper()}**",f"- Risk score: {a['risk_score']}/100",
                  f"- MITRE ATT&CK: {a['mitre']['id']} — {a['mitre']['name']}",f"- Evidence events: {len(a['evidence'])}",
                  f"- IOCs: {', '.join(a['iocs']) if a['iocs'] else 'None extracted'}",""]
    lines += ["## IOC Summary",f"- IPs: {', '.join(iocs['ips']) or 'None'}",f"- Domains: {', '.join(iocs['domains']) or 'None'}",
              f"- Hashes: {', '.join(iocs['hashes']) or 'None'}","","## Analyst Notes",
              "Detections are investigation leads, not proof of malicious activity. Validate context, asset ownership, user activity, and surrounding telemetry before escalation."]
    return "\n".join(lines)+"\n"

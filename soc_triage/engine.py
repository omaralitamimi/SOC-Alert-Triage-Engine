from __future__ import annotations
from collections import Counter, defaultdict
from datetime import datetime, timezone
import ipaddress, json, re
from pathlib import Path

MITRE = {
    "brute_force": {"id":"T1110", "name":"Brute Force"},
    "powershell": {"id":"T1059.001", "name":"PowerShell"},
    "account_create": {"id":"T1136", "name":"Create Account"},
    "privilege_change": {"id":"T1098", "name":"Account Manipulation"},
    "suspicious_outbound": {"id":"T1071.001", "name":"Web Protocols"},
}

IOC_RE = re.compile(r"\b(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{32})\b")

def load_jsonl(path: str | Path) -> list[dict]:
    events=[]
    with open(path, encoding="utf-8") as f:
        for n,line in enumerate(f,1):
            line=line.strip()
            if not line: continue
            try: events.append(json.loads(line))
            except json.JSONDecodeError as e: raise ValueError(f"Invalid JSON on line {n}: {e}")
    return events

def _alert(rule, title, severity, evidence, score, iocs=None):
    return {"rule":rule,"title":title,"severity":severity,"risk_score":score,
            "mitre":MITRE[rule],"evidence":evidence,"iocs":sorted(set(iocs or []))}

def _public_ip(value):
    try:
        ip=ipaddress.ip_address(value)
        return not (ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_multicast)
    except ValueError: return False

def detect(events: list[dict]) -> list[dict]:
    alerts=[]
    failed=defaultdict(list)
    outbound=defaultdict(list)
    for e in events:
        kind=e.get("event_type","")
        src=e.get("src_ip","")
        if kind=="auth_failure": failed[(src,e.get("user","unknown"))].append(e)
        if kind=="process_start":
            cmd=e.get("command_line","")
            low=cmd.lower()
            if "powershell" in low and any(x in low for x in ["-enc","-encodedcommand","frombase64string"]):
                alerts.append(_alert("powershell","Encoded PowerShell execution","high",[e],80,IOC_RE.findall(cmd)))
        if kind=="account_created":
            alerts.append(_alert("account_create","New local/domain account created","medium",[e],55))
        if kind=="privilege_change" and str(e.get("new_role","")).lower() in {"admin","administrator","root"}:
            alerts.append(_alert("privilege_change","Account granted privileged role","high",[e],75))
        if kind=="network_connection" and e.get("direction")=="outbound":
            outbound[(e.get("host","unknown"),e.get("dst_ip",""))].append(e)
    for (src,user), group in failed.items():
        if len(group)>=5:
            alerts.append(_alert("brute_force",f"Repeated authentication failures for {user}","high",group,70,[src]))
    for (host,dst), group in outbound.items():
        if len(group)>=4 and dst:
            # Synthetic lab samples may use documentation ranges, so frequency is the signal.
            alerts.append(_alert("suspicious_outbound",f"Repeated outbound connections from {host} to {dst}","medium",group,60,[dst]))
    return sorted(alerts,key=lambda a:a["risk_score"],reverse=True)

def extract_iocs(events: list[dict]) -> dict:
    ips, domains, hashes=set(),set(),set()
    for e in events:
        for k in ("src_ip","dst_ip"):
            v=e.get(k)
            if v: ips.add(v)
        if e.get("domain"): domains.add(e["domain"])
        for v in e.values():
            if isinstance(v,str):
                for h in IOC_RE.findall(v): hashes.add(h.lower())
    return {"ips":sorted(ips),"domains":sorted(domains),"hashes":sorted(hashes)}

def summary(events, alerts):
    return {"events_analyzed":len(events),"alerts_generated":len(alerts),
            "severity_counts":dict(Counter(a["severity"] for a in alerts)),
            "event_type_counts":dict(Counter(e.get("event_type","unknown") for e in events))}

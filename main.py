import argparse, json
from pathlib import Path
from soc_triage.engine import load_jsonl, detect, extract_iocs, summary
from soc_triage.report import markdown_report

def main():
    p=argparse.ArgumentParser(description="SOC alert triage and detection engine")
    p.add_argument("logfile")
    p.add_argument("--json", action="store_true", help="Print machine-readable results")
    p.add_argument("--report", help="Write Markdown report")
    args=p.parse_args()
    events=load_jsonl(args.logfile); alerts=detect(events); iocs=extract_iocs(events); s=summary(events,alerts)
    result={"summary":s,"alerts":alerts,"iocs":iocs}
    if args.json: print(json.dumps(result,indent=2))
    else:
        print(f"Analyzed {s['events_analyzed']} events | {s['alerts_generated']} alerts")
        for a in alerts: print(f"[{a['severity'].upper():6}] {a['risk_score']:>3}  {a['title']}  ({a['mitre']['id']})")
    if args.report: Path(args.report).write_text(markdown_report(s,alerts,iocs),encoding="utf-8")
if __name__=="__main__": main()

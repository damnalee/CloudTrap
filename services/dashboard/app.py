#!/usr/bin/env python3
"""Dependency-free, localhost-only CloudTrap security dashboard."""

import argparse
import json
import os
from decimal import Decimal
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parent
if len(ROOT.parents) > 1:
    ROOT = ROOT.parents[1]
DATA_DIR = Path(os.environ.get("CLOUDTRAP_DATA_DIR", ROOT / "data/processed"))


HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CloudTrap · Security Operations</title>
<style>
:root{color-scheme:dark;--bg:#0b1020;--panel:#121a2c;--panel2:#172238;--line:#26334b;--text:#e8eef8;--muted:#91a1ba;--blue:#73a7ff;--green:#57d6a0;--amber:#f6bd60;--red:#ff727d}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 15% 0%,#172746 0,transparent 38%),var(--bg);color:var(--text);font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
main{max-width:1440px;margin:auto;padding:30px 24px 60px}.top{display:flex;justify-content:space-between;align-items:center;gap:16px;margin-bottom:24px}
.brand{display:flex;align-items:center;gap:13px}.mark{width:42px;height:42px;border-radius:13px;background:#20365b;display:grid;place-items:center;color:var(--blue);font-weight:800;font-size:20px}
h1{font-size:21px;letter-spacing:.2px;margin:0}.sub{color:var(--muted);font-size:12px}.status{display:flex;align-items:center;gap:8px;color:var(--muted);font-size:12px}.dot{width:8px;height:8px;border-radius:50%;background:var(--green);box-shadow:0 0 12px #57d6a077}
.actions{display:flex;align-items:center;gap:10px}button,select,input{background:var(--panel2);border:1px solid var(--line);color:var(--text);border-radius:9px;padding:9px 12px;font:inherit}button{cursor:pointer}button:hover{border-color:var(--blue)}
.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px}.card{background:linear-gradient(145deg,#162137,#111a2c);border:1px solid var(--line);border-radius:15px;padding:18px;min-width:0}.metric-label{color:var(--muted);font-size:12px}.metric{font-size:29px;font-weight:700;margin-top:6px;letter-spacing:-.7px}.metric-note{font-size:11px;color:var(--muted);margin-top:2px}
.section{margin-top:20px}.section-head{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:12px}.section h2{font-size:15px;margin:0}.filters{display:flex;gap:8px;flex-wrap:wrap}.columns{display:grid;grid-template-columns:1.25fr .75fr;gap:14px}
.incident{border:1px solid var(--line);background:#121d31;border-radius:12px;padding:15px;margin-bottom:10px}.incident-top{display:flex;justify-content:space-between;gap:12px}.ip{font-size:14px;font-weight:700}.meta{color:var(--muted);font-size:11px;margin-top:3px}.pill{font-size:10px;text-transform:uppercase;letter-spacing:.5px;font-weight:700;border-radius:20px;padding:4px 8px;height:max-content}.high,.critical{color:#ff9ba3;background:#4a242f}.medium{color:#ffd18b;background:#49391e}.low{color:#93e7c3;background:#1e4039}
.patterns{display:flex;gap:6px;flex-wrap:wrap;margin-top:12px}.pattern{font:11px ui-monospace,monospace;color:#b9c8df;background:#1b2a42;border:1px solid #2b3d59;padding:4px 7px;border-radius:6px}
.alert-row,.event-row{padding:11px 0;border-bottom:1px solid #243149}.alert-row:last-child,.event-row:last-child{border:0}.alert-title{font-size:12px;font-weight:650}.alert-meta{font-size:11px;color:var(--muted);margin-top:3px}
.bar-row{display:grid;grid-template-columns:minmax(100px,1fr) 2fr 35px;gap:10px;align-items:center;margin:13px 0;font-size:11px}.bar-label{color:#b8c7dc;overflow-wrap:anywhere}.bar{height:8px;background:#202d44;border-radius:10px;overflow:hidden}.bar>i{display:block;height:100%;border-radius:10px;background:linear-gradient(90deg,#5584d6,#75b5ff)}
.empty{padding:24px 12px;text-align:center;color:var(--muted);font-size:12px}.foot{color:#71839f;font-size:11px;text-align:center;margin-top:24px}
@media(max-width:900px){.grid{grid-template-columns:repeat(2,minmax(0,1fr))}.columns{grid-template-columns:1fr}}
@media(max-width:560px){main{padding:20px 13px}.top{align-items:flex-start;flex-direction:column}.grid{gap:9px}.card{padding:13px}.metric{font-size:24px}.section-head{align-items:flex-start;flex-direction:column}}
</style>
</head>
<body>
<main>
  <header class="top">
    <div class="brand">
      <div class="mark">CT</div>
      <div><h1>CloudTrap</h1><div class="sub">Honeypot security operations · Synthetic local demo · No cloud connection</div></div>
    </div>
    <div class="actions">
      <div class="status"><span class="dot"></span><span id="updated">Connecting…</span></div>
      <button id="refresh">Refresh</button>
    </div>
  </header>

  <section class="grid">
    <div class="card"><div class="metric-label">Events analyzed</div><div class="metric" id="events">—</div><div class="metric-note">Normalized Cowrie records</div></div>
    <div class="card"><div class="metric-label">Source IPs</div><div class="metric" id="ips">—</div><div class="metric-note">Distinct observed sources</div></div>
    <div class="card"><div class="metric-label">Threat alerts</div><div class="metric" id="alerts">—</div><div class="metric-note">Rule matches</div></div>
    <div class="card"><div class="metric-label">Incidents</div><div class="metric" id="incidents">—</div><div class="metric-note">Correlated alert groups</div></div>
  </section>

  <section class="section">
    <div class="section-head">
      <h2>Security incidents</h2>
      <div class="filters">
        <input id="search" type="search" placeholder="Filter by source IP">
        <select id="severity"><option value="">All severities</option><option>critical</option><option>high</option><option>medium</option><option>low</option></select>
      </div>
    </div>
    <div class="columns">
      <div class="card"><div id="incident-list"><div class="empty">Waiting for incident data…</div></div></div>
      <div class="card"><h2>Event distribution</h2><div id="distribution" style="margin-top:12px"><div class="empty">No event summary yet.</div></div></div>
    </div>
  </section>

  <section class="section">
    <div class="columns">
      <div class="card"><h2>Recent alerts</h2><div id="alert-list"><div class="empty">No alert data yet.</div></div></div>
      <div class="card"><h2>Recent activity</h2><div id="activity-list"><div class="empty">No event data yet.</div></div></div>
    </div>
  </section>
  <div class="foot">CloudTrap local demo · No AWS connection or cloud spend · Credentials and raw command text are never served</div>
</main>
<script>
const $ = id => document.getElementById(id);
const esc = value => String(value ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const nice = value => String(value || "unknown").replaceAll("_"," ").replaceAll("."," · ");
const time = value => {const d=new Date(value);return Number.isNaN(d.getTime())?"—":d.toLocaleString();};
let snapshot = null;

function renderIncidents(){
  if(!snapshot)return;
  const query=$("search").value.trim().toLowerCase();
  const severity=$("severity").value;
  const rows=(snapshot.incidents||[]).filter(i=>
    (!query||String(i.source_ip||"").toLowerCase().includes(query))&&
    (!severity||i.severity===severity)
  );
  if(!rows.length){$("incident-list").innerHTML='<div class="empty">No incidents match these filters.</div>';return;}
  $("incident-list").innerHTML=rows.map(i=>{
    const patterns=(i.attack_patterns||[]).map(p=>'<span class="pattern">'+esc(nice(p))+'</span>').join("");
    return '<article class="incident"><div class="incident-top"><div><div class="ip">'+esc(i.source_ip)+' <span class="meta">· '+esc(i.incident_id)+'</span></div><div class="meta">'+esc(time(i.first_seen))+' → '+esc(time(i.last_seen))+' · '+esc(i.duration_seconds)+'s · '+esc(i.alert_count)+' alerts</div></div><span class="pill '+esc(i.severity)+'">'+esc(i.severity)+'</span></div><div class="patterns">'+patterns+'</div></article>';
  }).join("");
}

function render(){
  if(!snapshot)return;
  const s=snapshot.summary||{}, a=snapshot.alerts||{}, incidents=snapshot.incidents||[];
  $("events").textContent=(s.total_events??0).toLocaleString();
  $("ips").textContent=(s.unique_source_ips??0).toLocaleString();
  $("alerts").textContent=(a.total_alerts??0).toLocaleString();
  $("incidents").textContent=(snapshot.incident_total??incidents.length).toLocaleString();
  $("updated").textContent=(snapshot.data_source||"Local data")+" · "+new Date().toLocaleTimeString();

  renderIncidents();

  const types=Object.entries(s.events_by_type||{}).sort((a,b)=>b[1]-a[1]).slice(0,8);
  const max=Math.max(1,...types.map(x=>x[1]));
  $("distribution").innerHTML=types.length?types.map(([name,count])=>{
    return '<div class="bar-row"><div class="bar-label">'+esc(nice(name))+'</div><div class="bar"><i style="width:'+Math.max(2,count/max*100)+'%"></i></div><b>'+esc(count)+'</b></div>';
  }).join(""):'<div class="empty">Run the processing pipeline to populate event data.</div>';

  const alerts=(a.alerts||[]).slice().reverse().slice(0,8);
  $("alert-list").innerHTML=alerts.length?alerts.map(x=>{
    return '<div class="alert-row"><div class="incident-top"><div class="alert-title">'+esc(nice(x.rule_id))+'</div><span class="pill '+esc(x.severity)+'">'+esc(x.severity)+'</span></div><div class="alert-meta">'+esc(x.source_ip)+' · '+esc(time(x.occurred_at))+'</div></div>';
  }).join(""):'<div class="empty">No alerts recorded.</div>';

  const events=(snapshot.recent_events||[]).slice().reverse().slice(0,8);
  $("activity-list").innerHTML=events.length?events.map(x=>{
    return '<div class="event-row"><div class="alert-title">'+esc(nice(x.event_type))+'</div><div class="alert-meta">'+esc(x.source_ip)+' · '+esc(time(x.timestamp))+'</div></div>';
  }).join(""):'<div class="empty">Run the pipeline to see Cowrie activity.</div>';
}

async function refresh(){
  $("updated").textContent="Refreshing…";
  try{
    const response=await fetch("/api/snapshot",{cache:"no-store"});
    if(!response.ok)throw new Error("HTTP "+response.status);
    snapshot=await response.json();
    render();
  }catch(error){$("updated").textContent="Dashboard data unavailable";}
}
$("refresh").addEventListener("click",refresh);
$("search").addEventListener("input",renderIncidents);
$("severity").addEventListener("change",renderIncidents);
refresh();
setInterval(refresh,10000);
</script>
</body>
</html>
"""


def read_json(filename, fallback):
    path = DATA_DIR / filename
    try:
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
        return value if isinstance(value, dict) else fallback
    except (OSError, json.JSONDecodeError):
        return fallback


def read_recent_events(limit=100):
    path = DATA_DIR / "events.jsonl"
    events = []
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                try:
                    raw = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(raw, dict):
                    continue
                # Deliberately exclude commands, usernames and credential fields.
                events.append({
                    key: raw[key]
                    for key in ("timestamp", "event_type", "source_ip", "session_id", "protocol")
                    if key in raw
                })
    except OSError:
        return []
    return events[-limit:]


def json_native(value):
    """Convert DynamoDB Decimal scalars to JSON-safe numeric types."""
    if isinstance(value, Decimal):
        return int(value) if value == value.to_integral_value() else float(value)
    return value


def assemble_dynamodb_snapshot(event_rows, alert_rows, incident_rows):
    """Build a strictly whitelisted dashboard response from DynamoDB rows."""
    event_counts = Counter()
    source_counts = Counter()
    sessions = set()
    safe_events = []
    successful_logins = 0
    failed_logins = 0
    command_count = 0

    event_fields = ("timestamp", "event_type", "source_ip", "session_id", "protocol")
    for row in event_rows:
        event_type = row.get("event_type", "unknown")
        event_counts[event_type] += 1
        if row.get("source_ip"):
            source_counts[row["source_ip"]] += 1
        if row.get("session_id"):
            sessions.add(row["session_id"])
        if row.get("auth_result") == "success":
            successful_logins += 1
        elif row.get("auth_result") == "failed":
            failed_logins += 1
        if event_type == "cowrie.command.input":
            command_count += 1
        safe_events.append({key: row[key] for key in event_fields if row.get(key) is not None})

    safe_events.sort(key=lambda item: item.get("timestamp", ""))
    summary = {
        "total_events": len(event_rows),
        "unique_sessions": len(sessions),
        "unique_source_ips": len(source_counts),
        "login_attempts": {
            "successful": successful_logins,
            "failed": failed_logins,
        },
        "commands_observed": command_count,
        "events_by_type": dict(sorted(event_counts.items())),
        "top_source_ips": [
            {"ip": ip, "events": count}
            for ip, count in source_counts.most_common(10)
        ],
    }

    alert_fields = (
        "rule_id", "severity", "source_ip", "session_id", "occurred_at",
        "description", "failed_attempts", "preceding_failures", "threshold",
        "window_minutes",
    )
    safe_alerts = [
        {key: json_native(row[key]) for key in alert_fields if row.get(key) is not None}
        for row in alert_rows
    ]
    safe_alerts.sort(key=lambda item: item.get("occurred_at", ""))

    incident_fields = (
        "incident_id", "severity", "source_ip", "first_seen", "last_seen",
        "duration_seconds", "alert_count", "attack_patterns", "session_ids",
    )
    safe_incidents = [
        {key: json_native(row[key]) for key in incident_fields if row.get(key) is not None}
        for row in incident_rows
    ]
    safe_incidents.sort(key=lambda item: item.get("first_seen", ""))

    return {
        "data_source": "LocalStack DynamoDB",
        "summary": summary,
        "alerts": {
            "total_alerts": len(safe_alerts),
            "alerts": safe_alerts[-100:],
        },
        "incidents": safe_incidents[-100:],
        "incident_total": len(safe_incidents),
        "recent_events": safe_events[-100:],
    }


def read_dynamodb_table(table_name, limit=1000):
    """Read a bounded page from the local DynamoDB table."""
    import boto3

    endpoint = os.environ.get("CLOUDTRAP_ENDPOINT_URL") or None
    resource = boto3.resource(
        "dynamodb",
        region_name=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"),
        endpoint_url=endpoint,
    )
    response = resource.Table(table_name).scan(Limit=limit)
    return response.get("Items", [])


def make_dynamodb_snapshot():
    event_rows = read_dynamodb_table(os.environ.get("EVENTS_TABLE", "CloudTrapEvents"))
    alert_rows = read_dynamodb_table(os.environ.get("ALERTS_TABLE", "CloudTrapAlerts"))
    incident_rows = read_dynamodb_table(os.environ.get("INCIDENTS_TABLE", "CloudTrapIncidents"))
    return assemble_dynamodb_snapshot(event_rows, alert_rows, incident_rows)



def read_jsonl_events(filename, limit=1000):
    """Read JSONL records while exposing only approved, non-secret fields."""
    path = DATA_DIR / filename
    allowed = ("timestamp", "event_type", "source_ip", "session_id", "protocol", "auth_result")
    events = []
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(row, dict):
                    events.append({key: row[key] for key in allowed if row.get(key) is not None})
    except OSError:
        return []
    return events[-limit:]


def make_demo_snapshot():
    """Assemble the dashboard from synthetic files only; never contact AWS."""
    events = read_jsonl_events("simulated_campaign.jsonl")
    alert_doc = read_json("simulated_alerts.json", {"alerts": []})
    incident_doc = read_json("incidents.json", {"incidents": []})

    event_counts = Counter(item.get("event_type", "unknown") for item in events)
    source_ips = {item.get("source_ip") for item in events if item.get("source_ip")}
    sessions = {item.get("session_id") for item in events if item.get("session_id")}
    successful = sum(item.get("auth_result") == "success" for item in events)
    failed = sum(item.get("auth_result") == "failed" for item in events)
    summary = {
        "total_events": len(events),
        "unique_sessions": len(sessions),
        "unique_source_ips": len(source_ips),
        "login_attempts": {"successful": successful, "failed": failed},
        "commands_observed": event_counts.get("cowrie.command.input", 0),
        "events_by_type": dict(sorted(event_counts.items())),
    }

    alert_fields = (
        "rule_id", "severity", "source_ip", "session_id", "occurred_at",
        "description", "failed_attempts", "preceding_failures", "threshold",
        "window_minutes",
    )
    alert_rows = alert_doc.get("alerts", []) if isinstance(alert_doc, dict) else []
    safe_alerts = [
        {key: json_native(row[key]) for key in alert_fields if row.get(key) is not None}
        for row in alert_rows if isinstance(row, dict)
    ]

    incident_fields = (
        "incident_id", "severity", "source_ip", "first_seen", "last_seen",
        "duration_seconds", "alert_count", "attack_patterns", "session_ids",
    )
    incident_alert_fields = (
        "rule_id", "severity", "source_ip", "occurred_at", "description",
        "failed_attempts", "preceding_failures", "threshold", "window_minutes",
    )
    incident_rows = incident_doc.get("incidents", []) if isinstance(incident_doc, dict) else []
    safe_incidents = []
    for row in incident_rows:
        if not isinstance(row, dict):
            continue
        item = {key: json_native(row[key]) for key in incident_fields if row.get(key) is not None}
        nested = row.get("alerts", [])
        if isinstance(nested, list):
            item["alerts"] = [
                {key: json_native(alert[key]) for key in incident_alert_fields if alert.get(key) is not None}
                for alert in nested if isinstance(alert, dict)
            ]
        safe_incidents.append(item)

    severity_counts = Counter(row.get("severity", "unknown") for row in safe_alerts)
    return {
        "data_source": "Synthetic local demo",
        "summary": summary,
        "alerts": {
            "total_alerts": len(safe_alerts),
            "alerts_by_severity": dict(severity_counts),
            "alerts": safe_alerts[-100:],
        },
        "incidents": safe_incidents[-100:],
        "incident_total": len(safe_incidents),
        "recent_events": events[-100:],
    }

def make_snapshot():
    source = os.environ.get("CLOUDTRAP_DATA_SOURCE", "auto").lower()
    demo_files = (DATA_DIR / "simulated_campaign.jsonl", DATA_DIR / "simulated_alerts.json", DATA_DIR / "incidents.json")
    if source in {"demo", "auto"} and all(path.is_file() for path in demo_files):
        return make_demo_snapshot()
    if source in {"dynamodb", "localstack"}:
        try:
            return make_dynamodb_snapshot()
        except Exception as error:
            # Keep the dashboard available if LocalStack is temporarily offline.
            print(f"DynamoDB dashboard source unavailable: {type(error).__name__}")

    summary = read_json("summary.json", {})
    alerts = read_json("alerts.json", {"total_alerts": 0, "alerts": []})
    incidents = read_json("incidents.json", {"total_incidents": 0, "incidents": []})
    return {
        "data_source": "Local JSON files",
        "summary": summary,
        "alerts": alerts,
        "incidents": incidents.get("incidents", []),
        "incident_total": incidents.get("total_incidents", 0),
        "recent_events": read_recent_events(),
    }


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "CloudTrapDashboard/1.0"

    def _headers(self, content_type, length):
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'unsafe-inline'; "
            "script-src 'unsafe-inline'; connect-src 'self'; "
            "img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'",
        )
        self.end_headers()

    def do_GET(self):
        route = urlparse(self.path).path

        if route == "/":
            body = HTML.encode("utf-8")
            self._headers("text/html; charset=utf-8", len(body))
            self.wfile.write(body)
            return

        if route == "/api/snapshot":
            body = json.dumps(
                make_snapshot(),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
            self._headers("application/json; charset=utf-8", len(body))
            self.wfile.write(body)
            return

        self.send_error(404, "Not found")

    def log_message(self, format_string, *args):
        print("%s - %s" % (self.address_string(), format_string % args))


def main():
    parser = argparse.ArgumentParser(description="Run the CloudTrap local dashboard.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8501)
    args = parser.parse_args()

    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")

    server = ThreadingHTTPServer((args.host, args.port), DashboardHandler)
    print(f"CloudTrap dashboard: http://{args.host}:{args.port}")
    print(f"Reading processed data from: {DATA_DIR}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping CloudTrap dashboard.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()

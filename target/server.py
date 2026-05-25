import http.server
import json
import os
import socketserver
import threading
from datetime import datetime, timezone

PORT = 8080

request_log = []
log_lock = threading.Lock()
MAX_LOG = 100

ATTACK_TO_COMPONENT = {
    "cgroup": "db_config",
    "overlay": "internal_api",
    "io_uring": "admin_panel",
    "arp": "user_auth",
    "ebpf": "internal_api",
    "bpf": "internal_api",
    "userfaultfd": "file_upload",
}

app_state = {
    "components": {
        "db_config": {"name": "Database Config", "endpoint": "/config", "status": "ok", "icon": "\U0001F5C4", "detail": "PostgreSQL 15 connected \u00b7 3 active connections \u00b7 SSL encrypted", "stolen": None},
        "admin_panel": {"name": "Admin Portal", "endpoint": "/admin", "status": "ok", "icon": "\U0001F510", "detail": "RBAC enforced \u00b7 Admin access restricted \u00b7 Audit logging active", "stolen": None},
        "user_auth": {"name": "User Login", "endpoint": "/login", "status": "ok", "icon": "\U0001F464", "detail": "JWT authentication \u00b7 0 active sessions \u00b7 2FA enabled", "stolen": None},
        "internal_api": {"name": "Internal API", "endpoint": "/api/internal", "status": "ok", "icon": "\U0001F50C", "detail": "REST API v2.1 \u00b7 15 endpoints \u00b7 Rate limiting active", "stolen": None},
        "file_upload": {"name": "File Upload", "endpoint": "/upload", "status": "ok", "icon": "\U0001F4C1", "detail": "Secure upload portal \u00b7 Virus scanning \u00b7 Integrity verified", "stolen": None},
        "system": {"name": "System Health", "endpoint": None, "status": "ok", "icon": "\U0001F4BB", "detail": "All systems operational \u00b7 Uptime 2h 13m \u00b7 Load 12%", "stolen": None},
    },
    "timeline": [],
    "total_attacks": 0,
}

STOLEN_DATA = {
    "db_config": {
        "attack": "Cgroup notify_on_release Escape (CVE-2022-0492)",
        "title": "Exfiltrated Database Credentials",
        "fields": {
            "Database Host": "unique-postgres",
            "Port": "5432",
            "Database": "safedb",
            "User": "safeuser",
            "Password": "safepass",
            "Secret Key": "dev-secret-12345",
        },
        "response": 'HTTP 200 \u2192 {"db_host": "unique-postgres", "redis_host": "unique-redis", "secret_key": "dev-secret-12345"}',
        "method": "Cgroup release_agent \u2192 read host /proc/1/root\u2192 exfiltrated /config",
    },
    "admin_panel": {
        "attack": "io_uring Seccomp Bypass (CVE-2022-25362)",
        "title": "Stolen Admin Credentials & Access",
        "fields": {
            "Session Token": "admin-session-abc123xyz",
            "Privilege Level": "ROOT / Administrator",
            "Access Granted": "All internal endpoints",
            "Seccomp Filter": "BYPASSED via io_uring",
        },
        "response": 'HTTP 200 \u2192 {"admin": true, "message": "admin access granted"}',
        "method": "io_uring_setup() \u2192 seccomp bypass \u2192 /admin POST",
    },
    "user_auth": {
        "attack": "ARP Cache Poisoning MITM",
        "title": "Captured User Credentials (MITM)",
        "fields": {
            "Intercepted JWT": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ...",
            "Username": "admin",
            "Password": "P@ssw0rd!",
            "Session Cookie": "session=abc123; Secure; HttpOnly",
            "Source IP": "172.21.0.x (MITM intercepted)",
        },
        "response": 'HTTP 200 \u2192 {"token": "fake-jwt-token-12345"}',
        "method": "ARP spoof \u2192 raw socket sniff \u2192 intercepted /login POST",
    },
    "internal_api": {
        "attack": "eBPF Rootkit Load Attempt",
        "title": "Exfiltrated Internal API Data",
        "fields": {
            "Internal Endpoints Exposed": "/api/users, /api/secrets, /api/config, /api/logs",
            "Syscall Hooked": "open(), read(), write(), connect()",
            "Data Exfiltrated": "Customer records, API keys, internal service routes",
            "Rootkit Persistence": "/etc/ld.so.preload modified with malicious .so",
        },
        "response": 'HTTP 200 \u2192 {"api_data": "sensitive_internal_data"}',
        "method": "bpf() syscall \u2192 kprobe hook \u2192 data leak via kernel memory",
    },
    "file_upload": {
        "attack": "Userfaultfd Race Condition (CVE-2022-2588)",
        "title": "Corrupted Application Files",
        "fields": {
            "Corrupted File": "app.py (main application)",
            "Original Hash (SHA256)": "a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890",
            "Modified Hash (SHA256)": "ff00ee11dd22cc33bb44aa556677889900aabbccddeeff00112233445566778899",
            "Injected Payload": 'os.system("rm -rf /tmp/isolated_data")',
            "Race Window Exploited": "Memory page fault during concurrent file write",
        },
        "response": 'HTTP 200 \u2192 {"uploaded": true, "size": N}',
        "method": "userfaultfd() \u2192 page fault trap \u2192 race condition \u2192 file corruption",
    },
    "system": {
        "attack": "Multiple Attack Chain",
        "title": "System Compromise Report",
        "fields": {
            "Compromised Services": "All 5 application services breached",
            "Container Escape": "Host filesystem accessible via /proc/1/root",
            "Persistence Mechanism": "eBPF rootkit + overlayfs hidden artifacts",
            "Data at Risk": "Database creds, JWT secrets, internal API, app source code",
        },
        "response": "N/A \u2014 system-wide compromise detected",
        "method": "Chain of 6 attacks \u2192 full infrastructure takeover",
    },
}

COMPROMISED_DETAILS = {
    "db_config": {"status": "compromised", "detail": "CREDENTIALS EXPOSED \u00b7 Database host, port, and secret key stolen via cgroup escape"},
    "admin_panel": {"status": "compromised", "detail": "UNAUTHORIZED ACCESS \u00b7 Seccomp bypass granted full admin privileges to attacker"},
    "user_auth": {"status": "compromised", "detail": "CREDENTIALS CAPTURED \u00b7 ARP spoofing MITM intercepted JWT tokens and passwords"},
    "internal_api": {"status": "compromised", "detail": "DATA EXFILTRATED \u00b7 eBPF rootkit hooked syscalls and leaked internal API data"},
    "file_upload": {"status": "compromised", "detail": "FILES CORRUPTED \u00b7 Userfaultfd race condition overwrote application files"},
    "system": {"status": "compromised", "detail": "SYSTEM BREACHED \u00b7 Container escape detected, host filesystem accessible"},
}

PROBE_DETAILS = {
    "db_config": {"status": "probing", "detail": "PROBING endpoint /config \u2014 attacker checking for credential exposure"},
    "admin_panel": {"status": "probing", "detail": "PROBING endpoint /admin \u2014 attacker testing admin access controls"},
    "user_auth": {"status": "probing", "detail": "PROBING endpoint /login \u2014 attacker scanning authentication system"},
    "internal_api": {"status": "probing", "detail": "PROBING endpoint /api/internal \u2014 attacker mapping internal services"},
    "file_upload": {"status": "probing", "detail": "PROBING endpoint /upload \u2014 attacker inspecting file handling"},
}


def reset_state():
    with log_lock:
        request_log.clear()
        defaults = {
            "db_config": "PostgreSQL 15 connected \u00b7 3 active connections \u00b7 SSL encrypted",
            "admin_panel": "RBAC enforced \u00b7 Admin access restricted \u00b7 Audit logging active",
            "user_auth": "JWT authentication \u00b7 0 active sessions \u00b7 2FA enabled",
            "internal_api": "REST API v2.1 \u00b7 15 endpoints \u00b7 Rate limiting active",
            "file_upload": "Secure upload portal \u00b7 Virus scanning \u00b7 Integrity verified",
            "system": "All systems operational \u00b7 Uptime 2h 13m \u00b7 Load 12%",
        }
        for key, c in app_state["components"].items():
            c["status"] = "ok"
            c["detail"] = defaults.get(key, "")
            c["stolen"] = None
        app_state["timeline"].clear()
        app_state["total_attacks"] = 0


def _find_component(attack_name):
    name_lower = attack_name.lower()
    for keyword, comp_key in ATTACK_TO_COMPONENT.items():
        if keyword in name_lower:
            return comp_key
    return None


def _update_component(comp_key, phase, attack_name):
    if not comp_key or comp_key not in app_state["components"]:
        return
    c = app_state["components"][comp_key]
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    if phase == "pre-exploit probe":
        info = PROBE_DETAILS.get(comp_key)
        if info:
            c["status"] = info["status"]
            c["detail"] = info["detail"]
        app_state["timeline"].append({"time": ts, "phase": "PROBE", "component": c["name"], "message": info["detail"] if info else f"Probing {c['name']}"})
    elif phase == "exploitation":
        info = COMPROMISED_DETAILS.get(comp_key)
        if info:
            c["status"] = info["status"]
            c["detail"] = info["detail"]
        c["stolen"] = STOLEN_DATA.get(comp_key)
        app_state["timeline"].append({"time": ts, "phase": "EXPLOIT", "component": c["name"], "message": info["detail"] if info else f"Exploiting {c['name']}"})
        app_state["total_attacks"] += 1
        sys_comp = app_state["components"]["system"]
        sys_comp["status"] = "probing"
        sys_comp["detail"] = f"ALERT \u2014 {c['name']} compromised by {attack_name}"
    elif phase == "post-exploit verification":
        app_state["timeline"].append({"time": ts, "phase": "VERIFY", "component": c["name"], "message": f"Verifying {attack_name} impact \u2014 confirming compromise"})


DASHBOARD_PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>TargetCorp Internal Portal</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: 'Segoe UI', system-ui, sans-serif; background: #0a0c10; color: #e1e4e8; min-height: 100vh; }
header { background: linear-gradient(135deg, #0d1117 0%, #1c1335 100%); border-bottom: 1px solid #30363d; padding: 16px 30px; display: flex; align-items: center; justify-content: space-between; }
.header-left { display: flex; align-items: center; gap: 16px; }
header .app-icon { font-size: 28px; }
header h1 { font-size: 20px; font-weight: 600; letter-spacing: -0.3px; }
header h1 span { color: #a371f7; }
.header-right { display: flex; align-items: center; gap: 12px; font-size: 12px; }
.status-dot { width: 10px; height: 10px; border-radius: 50%; display: inline-block; margin-right: 6px; }
.status-dot.ok { background: #3fb950; box-shadow: 0 0 6px #3fb95066; }
.status-dot.probing { background: #d29922; box-shadow: 0 0 6px #d2992266; animation: pulse 1s infinite; }
.status-dot.compromised { background: #f85149; box-shadow: 0 0 6px #f8514966; animation: pulse 0.6s infinite; }
@keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
.container { max-width: 1400px; margin: 0 auto; padding: 20px; }
.section-title { font-size: 13px; text-transform: uppercase; color: #8b949e; letter-spacing: 1px; margin-bottom: 12px; font-weight: 600; }
.app-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 14px; margin-bottom: 24px; }
.service-card { background: #161b22; border: 1px solid #30363d; border-radius: 10px; padding: 18px; transition: all 0.3s ease; position: relative; overflow: hidden; }
.service-card::before { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 3px; transition: background 0.3s ease; }
.service-card.ok { border-color: #21262d; } .service-card.ok::before { background: #3fb950; }
.service-card.probing { border-color: #d2992244; } .service-card.probing::before { background: #d29922; }
.service-card.compromised { border-color: #f8514944; } .service-card.compromised::before { background: #f85149; }
.service-card .card-header { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }
.service-card .card-icon { font-size: 22px; }
.service-card .card-name { font-size: 14px; font-weight: 600; }
.service-card .card-status { font-size: 11px; font-weight: 600; padding: 2px 8px; border-radius: 10px; margin-left: auto; }
.service-card.ok .card-status { background: #3fb95022; color: #3fb950; }
.service-card.probing .card-status { background: #d2992222; color: #d29922; }
.service-card.compromised .card-status { background: #f8514922; color: #f85149; }
.service-card .card-detail { font-size: 12px; color: #8b949e; line-height: 1.4; margin-top: 4px; min-height: 2.8em; }
.feed-section { background: #161b22; border: 1px solid #30363d; border-radius: 10px; margin-bottom: 24px; overflow: hidden; }
.feed-header { padding: 14px 18px; border-bottom: 1px solid #21262d; display: flex; align-items: center; justify-content: space-between; }
.feed-header h3 { font-size: 13px; font-weight: 600; }
.feed-header .feed-count { font-size: 11px; color: #8b949e; }
.feed-body { padding: 0; max-height: 240px; overflow-y: auto; }
.feed-empty { padding: 30px; text-align: center; color: #8b949e; font-size: 13px; }
.feed-empty .big { font-size: 36px; margin-bottom: 8px; }
.feed-item { padding: 10px 18px; border-bottom: 1px solid #21262d; display: flex; align-items: flex-start; gap: 10px; font-size: 12px; animation: slideIn 0.3s ease-out; }
.feed-item:last-child { border-bottom: none; }
@keyframes slideIn { 0% { opacity: 0; transform: translateX(-10px); } 100% { opacity: 1; transform: translateX(0); } }
.feed-item .feed-time { color: #8b949e; white-space: nowrap; font-family: monospace; min-width: 60px; }
.feed-phase { font-size: 10px; font-weight: 700; padding: 2px 7px; border-radius: 4px; white-space: nowrap; min-width: 52px; text-align: center; }
.feed-phase.PROBE { background: #d2992222; color: #d29922; border: 1px solid #d2992244; }
.feed-phase.EXPLOIT { background: #f8514922; color: #f85149; border: 1px solid #f8514944; }
.feed-phase.VERIFY { background: #58a6ff22; color: #58a6ff; border: 1px solid #58a6ff44; }
.feed-item .feed-comp { color: #a371f7; font-weight: 500; white-space: nowrap; }
.feed-item .feed-msg { color: #e1e4e8; }
.feed-item.new-feed { background: rgba(163, 113, 247, 0.04); }
.stats-row { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; margin-bottom: 20px; }
.stat-card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; text-align: center; }
.stat-card h3 { font-size: 11px; text-transform: uppercase; color: #8b949e; margin-bottom: 6px; }
.stat-card .value { font-size: 28px; font-weight: 700; color: #58a6ff; }
.stat-card .value.exploit { color: #f85149; }
.stat-card .value.probe { color: #d29922; }
table { width: 100%; border-collapse: collapse; background: #161b22; border: 1px solid #30363d; border-radius: 10px; overflow: hidden; }
th { background: #1c2128; padding: 10px 14px; text-align: left; font-size: 11px; text-transform: uppercase; color: #8b949e; border-bottom: 1px solid #30363d; }
td { padding: 8px 14px; font-size: 12px; border-bottom: 1px solid #21262d; font-family: 'Consolas', 'Courier New', monospace; vertical-align: top; }
tr:hover { background: #1c2128; }
tr:last-child td { border-bottom: none; }
tr.attack-row { background: rgba(248, 81, 73, 0.04); }
tr.attack-row:hover { background: rgba(248, 81, 73, 0.08); }
.method-GET { color: #3fb950; font-weight: 600; }
.method-POST { color: #d29922; font-weight: 600; }
.path { color: #58a6ff; }
.status-2xx { color: #3fb950; }
.tag { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 10px; margin: 1px 2px; font-weight: 600; }
.tag.attack { background: #f8514922; border: 1px solid #f8514944; color: #f85149; }
.tag.normal { background: #8b949e22; border: 1px solid #8b949e44; color: #8b949e; }
.tag.cve { background: #f8514922; border-color: #f8514944; color: #f85149; }
.tag.mitre { background: #a371f722; border-color: #a371f744; color: #a371f7; }
.tag.exploit { background: #da363322; border-color: #da363344; color: #da3633; }
.tag.probe { background: #d2992222; border-color: #d2992244; color: #d29922; }
.tag.verify { background: #58a6ff22; border-color: #58a6ff44; color: #58a6ff; }
.empty-state { padding: 40px; text-align: center; color: #8b949e; font-family: 'Segoe UI', sans-serif; }
.empty-state .big { font-size: 48px; margin-bottom: 10px; }
.attack-name { color: #f85149; font-weight: 600; font-size: 11px; }
.impact-text { color: #8b949e; font-size: 11px; line-height: 1.4; max-width: 300px; }
@keyframes flash { 0% { background: rgba(210, 153, 34, 0.3); } 100% { background: transparent; } }
tr.new-row { animation: flash 1s ease-out; }
tr.new-row.attack-row { animation: flash 0.6s ease-out; }
.service-card { cursor: pointer; }
.service-card:hover { filter: brightness(1.15); }
.modal-overlay { display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.75); z-index: 1000; justify-content: center; align-items: center; }
.modal-overlay.open { display: flex; }
.modal { background: #161b22; border: 1px solid #30363d; border-radius: 12px; width: 600px; max-width: 90vw; max-height: 85vh; overflow-y: auto; box-shadow: 0 20px 60px rgba(0,0,0,0.5); }
.modal-header { padding: 18px 20px; border-bottom: 1px solid #30363d; display: flex; align-items: center; justify-content: space-between; }
.modal-header h2 { font-size: 16px; font-weight: 600; }
.modal-close { background: none; border: none; color: #8b949e; font-size: 22px; cursor: pointer; padding: 0 4px; }
.modal-close:hover { color: #f85149; }
.modal-body { padding: 20px; }
.modal-section { margin-bottom: 18px; }
.modal-section:last-child { margin-bottom: 0; }
.modal-section h3 { font-size: 12px; text-transform: uppercase; color: #8b949e; letter-spacing: 0.8px; margin-bottom: 8px; font-weight: 600; }
.modal-field { display: flex; justify-content: space-between; padding: 6px 0; border-bottom: 1px solid #21262d; font-size: 12px; }
.modal-field:last-child { border-bottom: none; }
.modal-field .key { color: #8b949e; font-family: 'Consolas', monospace; word-break: break-all; padding-right: 12px; }
.modal-field .val { color: #e1e4e8; font-family: 'Consolas', monospace; font-weight: 500; text-align: right; word-break: break-all; }
.modal-method { background: #1c2128; border: 1px solid #30363d; border-radius: 6px; padding: 10px 14px; font-family: 'Consolas', monospace; font-size: 11px; color: #8b949e; line-height: 1.5; }
.modal-response { background: #0d1117; border: 1px solid #21262d; border-radius: 6px; padding: 10px 14px; font-family: 'Consolas', monospace; font-size: 11px; color: #58a6ff; line-height: 1.5; }
.modal-tag { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 10px; font-weight: 600; margin-right: 4px; }
.modal-tag.cve { background: #f8514922; border: 1px solid #f8514944; color: #f85149; }
.modal-tag.mitre { background: #a371f722; border: 1px solid #a371f744; color: #a371f7; }
.modal-badge { display: inline-block; padding: 2px 10px; border-radius: 10px; font-size: 10px; font-weight: 700; text-transform: uppercase; }
.modal-badge.ok { background: #3fb95022; color: #3fb950; }
.modal-badge.probing { background: #d2992222; color: #d29922; }
.modal-badge.compromised { background: #f8514922; color: #f85149; }
</style>
</head>
<body>
<header>
  <div class="header-left">
    <span class="app-icon">&#x1F6E1;</span>
    <h1>TargetCorp <span>Internal Portal</span></h1>
  </div>
  <div class="header-right">
    <span id="header-status"><span class="status-dot ok"></span> OPERATIONAL</span>
  </div>
</header>
<div id="modal-overlay" class="modal-overlay" onclick="closeModal(event)">
  <div class="modal" id="modal" onclick="event.stopPropagation()">
    <div class="modal-header">
      <h2 id="modal-title">Service Details</h2>
      <button class="modal-close" onclick="closeModal()">&times;</button>
    </div>
    <div class="modal-body" id="modal-body"></div>
  </div>
</div>

<div class="container">

  <div class="section-title">Service Status <span style="font-size:11px;color:#8b949e;font-weight:400;text-transform:none;letter-spacing:0">(click a card to see what data the attacker stole)</span></div>
  <div class="app-grid" id="app-grid"></div>

  <div class="feed-section">
    <div class="feed-header">
      <h3>&#x26A1; Attack Timeline</h3>
      <span class="feed-count" id="feed-count">0 events</span>
    </div>
    <div class="feed-body" id="feed-body">
      <div class="feed-empty" id="feed-empty">
        <div class="big">&#x1F4AD;</div>
        <div>No attacks detected</div>
        <div style="font-size:12px;margin-top:6px">Run the pipeline to see live attack impact on the application</div>
      </div>
    </div>
  </div>

  <div class="stats-row" id="stats"></div>
  <table>
    <thead><tr>
      <th>Time</th><th>Method</th><th>Path</th><th>Status</th><th>Attack Info</th><th>Phase / Impact</th>
    </tr></thead>
    <tbody id="log-body"><tr><td colspan="6" class="empty-state"><div class="big">&#x1F4AD;</div>Waiting for incoming attack traffic...<br><span style="font-size:12px">Run the pipeline to start the attacker</span></td></tr></tbody>
  </table>
</div>
<script>
async function refresh() {
  try {
    var r = await fetch('/api/requests');
    var data = await r.json();
    renderComponents(data.components);
    renderTimeline(data.timeline);
    renderStats(data);
    renderLog(data.requests);
    renderHeader(data.components);
  } catch(e) {}
}
var currentComponents = null;
function renderComponents(components) {
  if (!components) return;
  currentComponents = components;
  var grid = document.getElementById('app-grid');
  var html = '';
  for (var k in components) {
    var c = components[k];
    var st = c.status || 'ok';
    var clickAttr = 'onclick="openModal(\'' + k + '\')"';
    html += '<div class="service-card ' + st + '" ' + clickAttr + '>' +
      '<div class="card-header">' +
        '<span class="card-icon">' + safe(c.icon || '&#x1F5C4;') + '</span>' +
        '<span class="card-name">' + safe(c.name) + '</span>' +
        '<span class="card-status">' + st.toUpperCase() + '</span>' +
      '</div>' +
      '<div class="card-detail">' + safe(c.detail || '') + '</div>' +
    '</div>';
  }
  grid.innerHTML = html;
}
function openModal(key) {
  if (!currentComponents || !currentComponents[key]) return;
  var c = currentComponents[key];
  var st = c.status || 'ok';
  if (st === 'ok') return;
  var body = document.getElementById('modal-body');
  var title = document.getElementById('modal-title');
  title.innerHTML = safe(c.icon || '') + ' ' + safe(c.name);
  if (!c.stolen) {
    body.innerHTML = '<div class="modal-section"><h3>Status</h3><div style="color:#d29922;font-size:13px">Component is being probed but not yet compromised. Data not accessible.</div></div>';
    document.getElementById('modal-overlay').classList.add('open');
    return;
  }
  var s = c.stolen;
  var cveMatch = s.attack.match(/CVE-[0-9-]+/);
  var mitreMatch = s.attack.match(/T[0-9]+/);
  var html = '';
  html += '<div class="modal-section"><h3>Attack</h3><div style="font-size:13px;font-weight:600;margin-bottom:4px">' + safe(s.attack) + '</div>';
  if (cveMatch) html += '<span class="modal-tag cve">' + safe(cveMatch[0]) + '</span> ';
  if (mitreMatch) html += '<span class="modal-tag mitre">' + safe(mitreMatch[0]) + '</span>';
  html += ' <span class="modal-badge ' + st + '">' + st.toUpperCase() + '</span>';
  html += '</div>';
  html += '<div class="modal-section"><h3>' + safe(s.title) + '</h3>';
  for (var fk in s.fields) {
    html += '<div class="modal-field"><span class="key">' + safe(fk) + '</span><span class="val">' + safe(s.fields[fk]) + '</span></div>';
  }
  html += '</div>';
  html += '<div class="modal-section"><h3>HTTP Response (Intercepted)</h3><div class="modal-response">' + safe(s.response) + '</div></div>';
  html += '<div class="modal-section"><h3>Exploit Method</h3><div class="modal-method">' + safe(s.method) + '</div></div>';
  body.innerHTML = html;
  document.getElementById('modal-overlay').classList.add('open');
}
function closeModal(e) {
  if (e && e.target !== e.currentTarget) return;
  document.getElementById('modal-overlay').classList.remove('open');
}
function renderTimeline(timeline) {
  var body = document.getElementById('feed-body');
  var count = document.getElementById('feed-count');
  if (!timeline || timeline.length === 0) {
    body.innerHTML = '<div class="feed-empty" id="feed-empty">' +
      '<div class="big">&#x1F4AD;</div><div>No attacks detected</div>' +
      '<div style="font-size:12px;margin-top:6px">Run the pipeline to see live attack impact on the application</div></div>';
    count.textContent = '0 events';
    return;
  }
  count.textContent = timeline.length + ' event' + (timeline.length > 1 ? 's' : '');
  var html = '';
  for (var i = 0; i < timeline.length; i++) {
    var e = timeline[i];
    var isNew = i === timeline.length - 1 ? 'new-feed' : '';
    html += '<div class="feed-item ' + isNew + '">' +
      '<span class="feed-time">' + safe(e.time) + '</span>' +
      '<span class="feed-phase ' + safe(e.phase) + '">' + safe(e.phase) + '</span>' +
      '<span class="feed-comp">' + safe(e.component) + '</span>' +
      '<span class="feed-msg">' + safe(e.message) + '</span>' +
    '</div>';
  }
  body.innerHTML = html;
  body.scrollTop = body.scrollHeight;
}
function renderStats(data) {
  var reqs = data.requests || [];
  var total = reqs.length;
  var exploits = 0, probes = 0, attacks = 0;
  for (var i = 0; i < reqs.length; i++) {
    var ctx = reqs[i].attack_context;
    if (ctx) {
      attacks++;
      if (ctx.phase === 'exploitation') exploits++;
      else probes++;
    }
  }
  document.getElementById('stats').innerHTML =
    '<div class="stat-card"><h3>Total Requests</h3><div class="value">' + total + '</div></div>' +
    '<div class="stat-card"><h3>Exploit Attempts</h3><div class="value exploit">' + exploits + '</div></div>' +
    '<div class="stat-card"><h3>Probes / Verification</h3><div class="value probe">' + probes + '</div></div>' +
    '<div class="stat-card"><h3>Attacks Detected</h3><div class="value" style="color:' + (attacks > 0 ? '#f85149' : '#8b949e') + '">' + attacks + '</div></div>';
}
function renderLog(requests) {
  var tbody = document.getElementById('log-body');
  if (!requests || requests.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" class="empty-state"><div class="big">&#x1F4AD;</div>Waiting for incoming attack traffic...</td></tr>';
    return;
  }
  var html = '';
  for (var i = requests.length - 1; i >= 0; i--) {
    var r = requests[i];
    var ctx = r.attack_context;
    var isAttack = !!ctx;
    var rowClass = isAttack ? 'attack-row' : '';
    var cls = (i === requests.length - 1) ? 'new-row' : '';
    var tag = isAttack ? '<span class="tag attack">attack</span>' : '<span class="tag normal">normal</span>';
    var statusClass = r.status >= 200 && r.status < 300 ? 'status-2xx' : 'status-5xx';
    if (!isAttack) {
      html += '<tr class="' + cls + '"><td>' + safe(r.time) + '</td><td><span class="method-' + r.method + '">' + r.method + '</span></td><td class="path">' + safe(r.path) + ' ' + tag + '</td><td class="' + statusClass + '">' + r.status + '</td><td style="color:#8b949e;font-size:11px">Regular traffic</td><td style="color:#8b949e;font-size:11px">-</td></tr>';
    } else {
      var cveTag = ctx.cve && ctx.cve !== 'N/A' ? '<span class="tag cve">' + safe(ctx.cve) + '</span>' : '';
      var mitreTag = ctx.mitre && ctx.mitre !== 'N/A' ? '<span class="tag mitre">' + safe(ctx.mitre) + '</span>' : '';
      var phaseClass = ctx.phase === 'exploitation' ? 'exploit' : ctx.phase === 'pre-exploit probe' ? 'probe' : 'verify';
      var phaseLabel = ctx.phase === 'exploitation' ? 'EXPLOIT' : ctx.phase === 'pre-exploit probe' ? 'PROBE' : 'VERIFY';
      html += '<tr class="' + rowClass + ' ' + cls + '">' +
        '<td>' + safe(r.time) + '</td>' +
        '<td><span class="method-' + r.method + '">' + r.method + '</span></td>' +
        '<td class="path">' + safe(r.path) + ' ' + tag + '</td>' +
        '<td class="' + statusClass + '">' + r.status + '</td>' +
        '<td><div class="attack-name">' + safe(ctx.attack || '') + '</div><div style="margin-top:2px">' + cveTag + ' ' + mitreTag + '</div></td>' +
        '<td><span class="tag ' + phaseClass + '">' + phaseLabel + '</span><div class="impact-text" style="margin-top:3px">' + safe(ctx.detail || ctx.impact || '') + '</div></td>' +
      '</tr>';
    }
  }
  tbody.innerHTML = html;
}
function renderHeader(components) {
  var el = document.getElementById('header-status');
  if (!components) return;
  var vals = Object.values(components);
  var hasCompromised = false, hasProbing = false;
  for (var i = 0; i < vals.length; i++) {
    if (vals[i].status === 'compromised') hasCompromised = true;
    if (vals[i].status === 'probing') hasProbing = true;
  }
  if (hasCompromised) {
    el.innerHTML = '<span class="status-dot compromised"></span> COMPROMISED';
  } else if (hasProbing) {
    el.innerHTML = '<span class="status-dot probing"></span> UNDER ATTACK';
  } else {
    el.innerHTML = '<span class="status-dot ok"></span> OPERATIONAL';
  }
}
function safe(s) { if (!s) return ''; var d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
setInterval(refresh, 1500);
refresh();
</script>
</body>
</html>"""


class TargetHandler(http.server.BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        if self.path == "/":
            self._respond_html(200, DASHBOARD_PAGE)
        elif self.path == "/api/requests":
            self._respond_json(200, self._get_full_state())
        elif self.path == "/health":
            self._respond_json(200, {"healthy": True})
        elif self.path == "/config":
            self._respond_json(200, {"db_host": "unique-postgres", "redis_host": "unique-redis", "secret_key": "dev-secret-12345"})
        elif self.path == "/internal":
            self._respond_json(200, {"internal": "true", "sensitive": "data_here"})
        elif self.path == "/favicon.ico":
            self._respond_json(404, {"error": "not_found"})
        else:
            self._respond_json(404, {"error": "not_found"})

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length else b""
        raw = body.decode()
        attack_context = None
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                if parsed.get("attack"):
                    attack_context = parsed
                    clean = {k: v for k, v in parsed.items() if k not in ("attack", "cve", "mitre", "impact", "phase", "detail")}
                    raw = json.dumps(clean) if clean else "{}"
        except (json.JSONDecodeError, TypeError):
            pass

        if self.path == "/api/reset":
            reset_state()
            self._respond_json(200, {"status": "reset", "message": "State cleared"})
            return

        if attack_context:
            comp_key = _find_component(attack_context.get("attack", ""))
            _update_component(comp_key, attack_context.get("phase", ""), attack_context.get("attack", ""))

        if self.path == "/config":
            self._log_and_respond(200, {"db_host": "unique-postgres", "redis_host": "unique-redis", "secret_key": "dev-secret-12345"}, raw, attack_context)
        elif self.path == "/internal":
            self._log_and_respond(200, {"internal": "true", "sensitive": "data_here"}, raw, attack_context)
        elif self.path == "/login":
            self._log_and_respond(200, {"token": "fake-jwt-token-12345"}, raw, attack_context)
        elif self.path == "/admin":
            self._log_and_respond(200, {"admin": True, "message": "admin access granted"}, raw, attack_context)
        elif self.path == "/upload":
            self._log_and_respond(200, {"uploaded": True, "size": len(body)}, f"size={len(body)}", attack_context)
        elif self.path == "/api/internal":
            self._log_and_respond(200, {"api_data": "sensitive_internal_data"}, raw, attack_context)
        else:
            self._log_and_respond(404, {"error": "not_found"}, raw, attack_context)

    def _log_and_respond(self, status, response_data, body="", attack_context=None):
        self._log_request(self.path, status, body, attack_context)
        self._respond_json(status, response_data)

    def _log_request(self, path, status, body="", attack_context=None):
        entry = {
            "time": datetime.now(timezone.utc).strftime("%H:%M:%S"),
            "method": "POST" if self.command == "POST" else "GET",
            "path": path,
            "status": status,
            "body": body,
        }
        if attack_context:
            entry["attack_context"] = attack_context
        with log_lock:
            request_log.append(entry)
            if len(request_log) > MAX_LOG:
                request_log.pop(0)

    def _get_full_state(self):
        with log_lock:
            return {
                "requests": list(request_log),
                "components": dict(app_state["components"]),
                "timeline": list(app_state["timeline"]),
                "total_attacks": app_state["total_attacks"],
            }

    def _respond_json(self, code, data):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def _respond_html(self, code, html):
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html.encode())

    def log_message(self, format, *args):
        pass


with socketserver.TCPServer(("0.0.0.0", PORT), TargetHandler) as httpd:
    print(f"Target app running on port {PORT}")
    httpd.serve_forever()

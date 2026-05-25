import http.server
import json
import os
import socketserver
import threading
from datetime import datetime, timezone

PORT = 8080

request_log = []
log_lock = threading.Lock()
MAX_LOG = 50

DASHBOARD_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Target App - Live Attack Monitor</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: 'Segoe UI', system-ui, sans-serif; background: #0f1117; color: #e1e4e8; min-height: 100vh; }
header { background: linear-gradient(135deg, #1a1d2e 0%, #2d1b69 100%); padding: 20px 30px; border-bottom: 1px solid #30363d; }
header h1 { font-size: 22px; font-weight: 600; }
header h1 span { color: #a371f7; }
.header-badge { background: #da3633; color: #fff; padding: 4px 12px; border-radius: 12px; font-size: 12px; margin-left: 10px; }
.container { max-width: 1200px; margin: 0 auto; padding: 20px; }
.stats-row { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin-bottom: 20px; }
.stat-card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; text-align: center; }
.stat-card h3 { font-size: 11px; text-transform: uppercase; color: #8b949e; margin-bottom: 6px; }
.stat-card .value { font-size: 28px; font-weight: 700; color: #58a6ff; }
.stat-card .value.post { color: #d29922; }
.stat-card .value.get { color: #3fb950; }
table { width: 100%; border-collapse: collapse; background: #161b22; border: 1px solid #30363d; border-radius: 8px; overflow: hidden; }
th { background: #1c2128; padding: 10px 14px; text-align: left; font-size: 11px; text-transform: uppercase; color: #8b949e; border-bottom: 1px solid #30363d; }
td { padding: 8px 14px; font-size: 13px; border-bottom: 1px solid #21262d; font-family: 'Consolas', 'Courier New', monospace; }
tr:hover { background: #1c2128; }
tr:last-child td { border-bottom: none; }
.method-GET { color: #3fb950; font-weight: 600; }
.method-POST { color: #d29922; font-weight: 600; }
.path { color: #58a6ff; }
.status-2xx { color: #3fb950; }
.status-4xx { color: #f85149; }
.status-5xx { color: #da3633; }
.tag { display: inline-block; padding: 1px 6px; border-radius: 4px; font-size: 10px; margin-left: 4px; }
.tag.attack { background: #f8514922; border: 1px solid #f8514944; color: #f85149; }
.tag.api { background: #58a6ff22; border: 1px solid #58a6ff44; color: #58a6ff; }
.empty-state { padding: 40px; text-align: center; color: #8b949e; font-family: 'Segoe UI', sans-serif; }
.empty-state .big { font-size: 48px; margin-bottom: 10px; }
@keyframes flash { 0% { background: rgba(210, 153, 34, 0.2); } 100% { background: transparent; } }
tr.new-row { animation: flash 1s ease-out; }
</style>
</head>
<body>
<header>
<div><h1>Target <span>App</span><span class="header-badge">Under Attack</span></h1></div>
</header>
<div class="container">
<div class="stats-row" id="stats"></div>
<table>
<thead><tr><th>Time</th><th>Method</th><th>Path</th><th>Status</th><th>Body / Params</th></tr></thead>
<tbody id="log-body"><tr><td colspan="5" class="empty-state"><div class="big">&#9203;</div>Waiting for incoming requests...<br><span style="font-size:12px">Run the pipeline to see live attack traffic</span></td></tr></tbody>
</table>
</div>
<script>
async function refresh() {
    try {
        const r = await fetch('/api/requests');
        const data = await r.json();
        const stats = document.getElementById('stats');
        const total = data.requests.length;
        const gets = data.requests.filter(x => x.method === 'GET').length;
        const posts = data.requests.filter(x => x.method === 'POST').length;
        const attacks = data.requests.filter(x => x.path === '/config' || x.path === '/admin' || x.path === '/api/internal').length;
        stats.innerHTML = `
            <div class="stat-card"><h3>Total Requests</h3><div class="value">${total}</div></div>
            <div class="stat-card"><h3>GET</h3><div class="value get">${gets}</div></div>
            <div class="stat-card"><h3>POST</h3><div class="value post">${posts}</div></div>
            <div class="stat-card"><h3>Attack Hits</h3><div class="value" style="color:${attacks > 0 ? '#f85149' : '#8b949e'}">${attacks}</div></div>
        `;
        const tbody = document.getElementById('log-body');
        if (data.requests.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="empty-state"><div class="big">&#9203;</div>Waiting for incoming requests...</td></tr>';
            return;
        }
        tbody.innerHTML = data.requests.slice().reverse().map((r, i) => {
            const isAttack = r.path === '/config' || r.path === '/admin' || r.path === '/api/internal';
            const tag = isAttack ? '<span class="tag attack">attack</span>' : '<span class="tag api">normal</span>';
            const cls = i === 0 ? 'class="new-row"' : '';
            const statusClass = r.status >= 200 && r.status < 300 ? 'status-2xx' : r.status >= 400 ? 'status-4xx' : 'status-5xx';
            const body = r.body ? r.body.slice(0, 80) : '';
            return `<tr ${cls}><td>${r.time}</td><td><span class="method-${r.method}">${r.method}</span></td><td class="path">${r.path} ${tag}</td><td class="${statusClass}">${r.status}</td><td style="color:#8b949e;font-size:12px">${body}</td></tr>`;
        }).join('');
    } catch(e) {}
}
setInterval(refresh, 1500);
refresh();
</script>
</body>
</html>"""


class TargetHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            self._respond_html(200, DASHBOARD_PAGE)
        elif self.path == "/api/requests":
            self._respond_json(200, self._get_log())
        elif self.path == "/health":
            self._log_request("GET", self.path, 200)
            self._respond_json(200, {"healthy": True})
        elif self.path == "/config":
            self._log_request("GET", self.path, 200)
            self._respond_json(200, {"db_host": "unique-postgres", "redis_host": "unique-redis", "secret_key": "dev-secret-12345"})
        elif self.path == "/internal":
            self._log_request("GET", self.path, 200)
            self._respond_json(200, {"internal": "true", "sensitive": "data_here"})
        elif self.path == "/favicon.ico":
            self._respond_json(404, {"error": "not_found"})
        else:
            self._log_request("GET", self.path, 404)
            self._respond_json(404, {"error": "not_found"})

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length else b""
        body_str = body.decode() if body else ""
        if self.path == "/login":
            self._log_request("POST", self.path, 200, body_str)
            self._respond_json(200, {"token": "fake-jwt-token-12345"})
        elif self.path == "/admin":
            self._log_request("POST", self.path, 200, body_str)
            self._respond_json(200, {"admin": True, "message": "admin access granted"})
        elif self.path == "/upload":
            self._log_request("POST", self.path, 200, f"size={len(body)}")
            self._respond_json(200, {"uploaded": True, "size": len(body)})
        elif self.path == "/api/internal":
            self._log_request("POST", self.path, 200, body_str)
            self._respond_json(200, {"api_data": "sensitive_internal_data"})
        else:
            self._log_request("POST", self.path, 404, body_str)
            self._respond_json(404, {"error": "not_found"})

    def _log_request(self, method, path, status, body=""):
        entry = {
            "time": datetime.now(timezone.utc).strftime("%H:%M:%S"),
            "method": method,
            "path": path,
            "status": status,
            "body": body,
        }
        with log_lock:
            request_log.append(entry)
            if len(request_log) > MAX_LOG:
                request_log.pop(0)

    def _get_log(self):
        with log_lock:
            return {"requests": list(request_log)}

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
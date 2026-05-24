import http.server
import json
import os
import socketserver

PORT = 8080

class TargetHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            self._respond(200, {"status": "running", "service": "target-app", "version": "1.0"})
        elif self.path == "/health":
            self._respond(200, {"healthy": True})
        elif self.path == "/config":
            self._respond(200, {"db_host": "unique-postgres", "redis_host": "unique-redis", "secret_key": "dev-secret-12345"})
        elif self.path == "/internal":
            self._respond(200, {"internal": "true", "sensitive": "data_here"})
        else:
            self._respond(404, {"error": "not_found"})

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length else b""
        if self.path == "/login":
            self._respond(200, {"token": "fake-jwt-token-12345"})
        elif self.path == "/admin":
            self._respond(200, {"admin": True, "message": "admin access granted"})
        elif self.path == "/upload":
            self._respond(200, {"uploaded": True, "size": len(body)})
        elif self.path == "/api/internal":
            self._respond(200, {"api_data": "sensitive_internal_data"})
        else:
            self._respond(404, {"error": "not_found"})

    def _respond(self, code, data):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def log_message(self, format, *args):
        pass

with socketserver.TCPServer(("0.0.0.0", PORT), TargetHandler) as httpd:
    print(f"Target app running on port {PORT}")
    httpd.serve_forever()

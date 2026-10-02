"""
AI Security Detection Lab - Master Backend Server
Multi-threaded HTTP and REST API server powering the Detection Lab Workbench.
"""

import sys
import json
import argparse
import socketserver
import http.server
import urllib.parse
from pathlib import Path
from typing import Any, Dict

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.config import BASE_DIR, WEB_PORT, WEB_HOST
from backend.routes import LabApiController

FRONTEND_DIR = BASE_DIR / "frontend"
if not FRONTEND_DIR.exists():
    FRONTEND_DIR = BASE_DIR / "web" / "static"

controller = LabApiController()

class LabBackendHandler(http.server.SimpleHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(FRONTEND_DIR), **kwargs)

    def _set_cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, DELETE, PUT")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")

    def do_OPTIONS(self):
        self.send_response(204)
        self._set_cors_headers()
        self.end_headers()

    def send_json(self, data: Any, status: int = 200):
        content = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Connection", "keep-alive")
        self._set_cors_headers()
        self.end_headers()
        self.wfile.write(content)
        self.wfile.flush()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/")
        if path == "":
            path = "/"

        # API Endpoints
        if path == "/api/health":
            status, res = controller.handle_health()
            self.send_json(res, status=status)
        elif path == "/api/experiments":
            status, res = controller.handle_get_experiments()
            self.send_json(res, status=status)
        elif path == "/api/matrix":
            status, res = controller.handle_get_matrix()
            self.send_json(res, status=status)
        elif path == "/api/failure_analysis":
            status, res = controller.handle_get_failure_analysis()
            self.send_json(res, status=status)
        elif path == "/api/baselines":
            status, res = controller.handle_get_baselines()
            self.send_json(res, status=status)
        elif path == "/api/telemetry_health":
            status, res = controller.handle_get_telemetry_health()
            self.send_json(res, status=status)
        elif path == "/api/db/status":
            status, res = controller.handle_get_db_status()
            self.send_json(res, status=status)
        elif path == "/api/research_findings":
            status, res = controller.handle_get_research_findings()
            self.send_json(res, status=status)
        elif path == "/api/logs":
            status, res = controller.handle_get_logs()
            self.send_json(res, status=status)
        elif path == "/api/logs/content":
            query = urllib.parse.parse_qs(parsed.query)
            filename = query.get("file", [""])[0]
            status, res = controller.handle_get_log_content(filename)
            self.send_json(res, status=status)
        else:
            # Serve Static Frontend File
            super().do_GET()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/")

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8") if length > 0 else "{}"
        
        try:
            data = json.loads(body)
        except Exception:
            data = {}

        if path == "/api/run_scenario":
            status, res = controller.handle_run_scenario(data)
            self.send_json(res, status=status)
        elif path == "/api/run_all":
            status, res = controller.handle_run_all()
            self.send_json(res, status=status)
        elif path == "/api/establish_baseline":
            status, res = controller.handle_establish_baseline()
            self.send_json(res, status=status)
        elif path == "/api/telemetry_health":
            status, res = controller.handle_update_telemetry_health(data)
            self.send_json(res, status=status)
        elif path == "/api/db/sync":
            status, res = controller.handle_sync_db()
            self.send_json(res, status=status)
        elif path == "/api/generate_report":
            status, res = controller.handle_generate_report()
            self.send_json(res, status=status)
        elif path == "/api/analyze_logs":
            status, res = controller.handle_analyze_logs(data)
            self.send_json(res, status=status)
        elif path == "/api/reset":
            status, res = controller.handle_reset_lab()
            self.send_json(res, status=status)
        else:
            self.send_json({"error": f"POST endpoint '{path}' not found"}, status=404)

def start_backend_server(port: int = WEB_PORT, host: str = WEB_HOST):
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer((host, port), LabBackendHandler) as httpd:
        print("\n" + "="*60)
        print(f" [*] AI SECURITY DETECTION LAB - BACKEND SERVER ACTIVE")
        print(f" [*] Host:      http://{host}:{port}/")
        print(f" [*] Frontend:  {FRONTEND_DIR}")
        print(f" [*] API Health: http://{host}:{port}/api/health")
        print("="*60 + "\n")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Stopping backend server...")
            httpd.shutdown()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AI Security Detection Lab Backend Server")
    parser.add_argument("-p", "--port", type=int, default=WEB_PORT, help="Port to bind (default: 8080)")
    parser.add_argument("--host", type=str, default=WEB_HOST, help="Host address (default: 127.0.0.1)")
    args = parser.parse_args()
    start_backend_server(port=args.port, host=args.host)

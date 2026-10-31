#!/usr/bin/env python3
"""Local development server for Agurim Web UI, CGI scripts, and AI Multi-Agent API.

Usage:
    python3 scripts/serve.py [port]
"""

from __future__ import annotations

import json
import os
import sys
from http import HTTPStatus
from http.server import CGIHTTPRequestHandler, HTTPServer
from typing import ClassVar


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.chdir(repo_root)
    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)

    class AgurimServerHandler(CGIHTTPRequestHandler):
        cgi_directories: ClassVar[list[str]] = ["/cgi-bin"]

        def do_GET(self):
            if self.path == "/api/agent/status":
                self.handle_agent_status()
                return
            super().do_GET()

        def do_POST(self):
            if self.path == "/api/agent/chat":
                self.handle_agent_chat()
                return
            super().do_POST()

        def handle_agent_status(self):
            try:
                from agurim_agent.agent import root_agent
                from agurim_agent.tools import list_datasets_and_ranges

                datasets_info = list_datasets_and_ranges()
                status_payload = {
                    "status": "ready",
                    "framework": "google-adk",
                    "root_agent": root_agent.name,
                    "model": root_agent.model,
                    "sub_agents": [
                        "AgurimDataEngineer",
                        "ParallelAnomalyTeam (Volume, Proto, ThreatIntel)",
                        "MitigationSafetyPipeline (Planner + SafetyCritic)",
                    ],
                    "datasets": datasets_info.get("datasets", []),
                    "sample_available": datasets_info.get("sample_fixture_available", False),
                }
                body = json.dumps(status_payload).encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except Exception as e:
                self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, str(e))

        def handle_agent_chat(self):
            try:
                content_length = int(self.headers.get("Content-Length", 0))
                req_body = self.rfile.read(content_length).decode("utf-8")
                data = json.loads(req_body) if req_body else {}
                prompt = data.get("message", "").strip()
                context = data.get("context", {})

                from agurim_agent.agent import run_agent_query

                result = run_agent_query(prompt, context=context)
                resp_bytes = json.dumps(result).encode("utf-8")

                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(resp_bytes)))
                self.end_headers()
                self.wfile.write(resp_bytes)
            except Exception as e:
                self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, str(e))

    server_address = ("", port)
    httpd = HTTPServer(server_address, AgurimServerHandler)
    print(f"Agurim server running at http://localhost:{port}/")
    print(f"Multi-Agent API available at http://localhost:{port}/api/agent/chat")
    print(f"Web root: {repo_root}")
    print("Press Ctrl+C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server.")
        httpd.server_close()


if __name__ == "__main__":
    main()

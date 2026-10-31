#!/usr/bin/env python3
"""
Simple local development server for Agurim Web UI and CGI scripts.

Usage:
    python3 scripts/serve.py [port]
"""

import os
import sys
from http.server import CGIHTTPRequestHandler, HTTPServer
from typing import ClassVar


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.chdir(repo_root)

    class AgurimCGIHandler(CGIHTTPRequestHandler):
        cgi_directories: ClassVar[list[str]] = ["/cgi-bin"]

    server_address = ("", port)
    httpd = HTTPServer(server_address, AgurimCGIHandler)
    print(f"Agurim dev server running at http://localhost:{port}/")
    print(f"Web root: {repo_root}")
    print("Press Ctrl+C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server.")
        httpd.server_close()


if __name__ == "__main__":
    main()

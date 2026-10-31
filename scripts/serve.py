#!/usr/bin/env python3
"""
Simple local development server for Agurim Web UI and CGI scripts.

Usage:
    python3 scripts/serve.py [port]
"""
import sys
import os
from http.server import HTTPServer, CGIHTTPRequestHandler

def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.chdir(repo_root)

    class AgurimCGIHandler(CGIHTTPRequestHandler):
        cgi_directories = ["/cgi-bin"]

    server_address = ("", port)
    httpd = HTTPServer(server_address, AgurimCGIHandler)
    print("Agurim dev server running at http://localhost:%d/" % port)
    print("Web root: %s" % repo_root)
    print("Press Ctrl+C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server.")
        httpd.server_close()

if __name__ == "__main__":
    main()

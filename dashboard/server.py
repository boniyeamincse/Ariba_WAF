#!/usr/bin/env python3
"""
Ariba WAF Dashboard Server
Simple HTTP server to serve the dashboard interface
"""

import os
import sys
from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer
import webbrowser
import threading

class DashboardRequestHandler(SimpleHTTPRequestHandler):
    """Custom request handler for the Ariba WAF Dashboard"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory="dashboard", **kwargs)

    def log_message(self, format, *args):
        """Override to reduce console output"""
        if "GET" in format or "code 200" in format:
            return
        sys.stderr.write(f"[{self.log_date_time_string()}] {format % args}\n")

def run_server(port=8000):
    """Run the dashboard server on specified port"""
    httpd = None
    try:
        # We're already in the dashboard directory when this runs
        current_dir = os.path.dirname(__file__) or '.'
        os.chdir(current_dir)

        # Set up server
        server_address = ('', port)
        httpd = TCPServer(server_address, DashboardRequestHandler)

        print(f"\n{'='*50}")
        print("Ariba WAF Dashboard Server")
        print(f"{'='*50}")
        print(f"Dashboard URL: http://localhost:{port}")
        print(f"Serving from: {os.getcwd()}")
        print(f"Press Ctrl+C to stop the server")
        print(f"{'='*50}\n")

        # Open browser automatically
        def open_browser():
            webbrowser.open(f'http://localhost:{port}')

        # Start browser in a separate thread
        threading.Timer(1, open_browser).start()

        # Start server
        httpd.serve_forever()

    except KeyboardInterrupt:
        print("\nServer stopped by user")
    except Exception as e:
        print(f"Server error: {e}")
    finally:
        if httpd:
            httpd.server_close()
        print("Dashboard server shutdown complete")

if __name__ == "__main__":
    # Get port from command line or use default
    port = 8000
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            print("⚠️  Invalid port number, using default 8000")

    run_server(port)
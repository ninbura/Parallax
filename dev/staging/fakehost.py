"""A fake LAN service for the staging gateway.

Usage: fakehost.py NAME BIND_ADDRESS PORT

Answers every GET with one line naming the service and the client address it
saw, so a test can tell a routed path (the peer's tunnel address) from a
masqueraded one (the gateway's LAN address).
"""

import http.server
import socketserver
import sys

name, address, port = sys.argv[1], sys.argv[2], int(sys.argv[3])


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = f"{name} {address}:{port} saw {self.client_address[0]}\n".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


# A plain TCP server: HTTPServer's bind does a reverse lookup of the address
# (socket.getfqdn), which can hang for seconds on a host with real DNS.
socketserver.ThreadingTCPServer.allow_reuse_address = True
socketserver.ThreadingTCPServer.daemon_threads = True
socketserver.ThreadingTCPServer((address, port), Handler).serve_forever()

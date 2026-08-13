import http.server

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.end_headers()
        self.wfile.write(b"CTF{lateral_pivot}")
    def log_message(self, *a): pass

http.server.HTTPServer(("0.0.0.0", 9000), H).serve_forever()

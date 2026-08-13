import http.server, urllib.parse, urllib.request

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        q = urllib.parse.urlparse(self.path)
        if q.path == "/fetch":
            host = urllib.parse.parse_qs(q.query).get("host", [""])[0]
            try:
                data = urllib.request.urlopen(f"http://{host}", timeout=3).read()
            except Exception as e:
                data = f"error: {e}".encode()
            self.send_response(200); self.end_headers(); self.wfile.write(data)
        else:
            self.send_response(200); self.end_headers()
            self.wfile.write(b"web frontend. try /fetch?host=")
    def log_message(self, *a): pass

http.server.HTTPServer(("0.0.0.0", 8000), H).serve_forever()

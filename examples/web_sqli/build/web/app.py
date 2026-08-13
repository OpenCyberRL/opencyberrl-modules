import sqlite3, http.server, urllib.parse

db = sqlite3.connect(":memory:", check_same_thread=False)
db.execute("CREATE TABLE users(name TEXT, secret TEXT)")
db.execute("INSERT INTO users VALUES('admin', 'CTF{sqli_master}')")
db.commit()

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        q = urllib.parse.urlparse(self.path).query
        name = urllib.parse.parse_qs(q).get("name", [""])[0]
        # Intentionally vulnerable: string-formatted SQL.
        sql = "SELECT secret FROM users WHERE name = '%s'" % name
        try:
            rows = db.execute(sql).fetchall()
            body = "\n".join(r[0] for r in rows) or "no results"
        except Exception as e:
            body = f"error: {e}"
        self.send_response(200); self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, *a): pass

http.server.HTTPServer(("0.0.0.0", 8000), H).serve_forever()

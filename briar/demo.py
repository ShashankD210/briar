"""Briar built-in vulnerable app — a self-contained target for `briar demo`.

Lets anyone prove the engine works end-to-end (recon -> endpoint routing -> real
payload injection -> detection -> confirmation) with zero external target, zero
network and zero API key. Intentionally vulnerable; localhost only.
"""
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

_HOME = """<html><body>
<h1>Briar Demo Shop</h1>
<p>Intentionally vulnerable app for self-testing.</p>
<ul>
<li><a href="/product.php?id=1">Product</a></li>
<li><a href="/search.php?q=hello">Search</a></li>
<li><a href="/page.php?file=home">Page</a></li>
<li><a href="/login.php">Login</a></li>
</ul>
</body></html>"""

_LOGIN = """<html><body><h1>Login</h1>
<form action="/login.php" method="post">
<input name="uid" placeholder="user">
<input name="password" type="password">
<input type="submit" value="Sign in">
</form></body></html>"""


class _VulnHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        p = urlparse(self.path)
        q = parse_qs(p.query)
        if p.path in ("/", ""):
            body = _HOME
        elif p.path == "/product.php":
            v = q.get("id", [""])[0]
            # SQL injection: any quote/comment/OR triggers a DB error
            if any(c in v for c in ("'", '"', "--")) or " or " in v.lower():
                body = ("You have an error in your SQL syntax; check the manual that "
                        "corresponds to your MySQL server version near '%s'" % v)
            else:
                body = "<html><body>Product #%s</body></html>" % v
        elif p.path == "/search.php":
            # Reflected XSS: q echoed unescaped
            body = "<html><body>Results for %s</body></html>" % q.get("q", [""])[0]
        elif p.path == "/page.php":
            v = q.get("file", [""])[0]
            # Path traversal / LFI
            if "etc/passwd" in v or ".." in v:
                body = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            else:
                body = "<html><body>Page: %s</body></html>" % v
        elif p.path == "/login.php":
            body = _LOGIN
        else:
            body = "<html><body>Not found</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length).decode(errors="ignore") if length else ""
        vals = parse_qs(raw)
        uid = vals.get("uid", [""])[0]
        pw = vals.get("password", [""])[0]
        # SQL injection in a POST login form (the classic Burp/AltoroMutual case)
        if any(c in uid + pw for c in ("'", '"', "--")):
            body = ("You have an error in your SQL syntax; check the manual that "
                    "corresponds to your MySQL server version near '" + uid + "'")
        else:
            body = "<html><body>Invalid credentials</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())


def serve(port: int = 0):
    """Start the vulnerable app on localhost. port=0 auto-picks a free port.
    Returns (server, base_url)."""
    server = HTTPServer(("127.0.0.1", port), _VulnHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, "http://127.0.0.1:%d/" % server.server_address[1]

#!/usr/bin/env python3
"""Servidor local que simula distintos comportamientos de WAF, para probar wafscope.
Uso: python3 mock_server.py <modo> <puerto>
Modos: cloudflare | generic | silent | soft | none
"""
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote

MODE = sys.argv[1] if len(sys.argv) > 1 else "none"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8081
BAD = re.compile(r"<script|onerror=|union\s+all\s+select|' or '1'='1|etc/passwd|\{\{7\*7\}\}", re.I)

PAGE = b"<html><head><title>Mi sitio</title></head><body><h1>Hola</h1><p>" + b"contenido normal " * 40 + b"</p></body></html>"


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def send(self, code, body, extra=None):
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        raw = unquote(self.path)
        hdrs = " ".join(self.headers.values())
        bad = bool(BAD.search(raw)) or "${jndi" in hdrs or "sqlmap" in hdrs.lower()
        if MODE == "cloudflare":
            cf = {"Server": "cloudflare", "CF-RAY": "8a1b2c3d4e5f-SCL", "Set-Cookie": "__cf_bm=abc; Path=/; HttpOnly"}
            if bad:
                return self.send(403, b"<title>Attention Required! | Cloudflare</title><p>Sorry, you have been blocked</p>"
                                      b"<p>Cloudflare Ray ID: 8a1b</p>", cf)
            return self.send(200, PAGE, cf)
        if MODE == "generic":
            if bad:
                return self.send(406, b"<h1>Not Acceptable</h1>")
            return self.send(200, PAGE)
        if MODE == "silent":
            if bad:
                self.close_connection = True
                self.connection.close()
                return
            return self.send(200, PAGE)
        if MODE == "soft":
            if bad:
                return self.send(200, b"<html><body><h2>Request blocked by security policy</h2><p>Incident id 123</p></body></html>")
            return self.send(200, PAGE)
        return self.send(200, PAGE)  # none


class S(ThreadingHTTPServer):
    request_queue_size = 256
    daemon_threads = True


S(("127.0.0.1", PORT), H).serve_forever()

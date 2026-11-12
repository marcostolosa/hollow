#!/usr/bin/env python3
"""server.py — serve o share pro guest e recebe o relatorio de volta.

- GET  /<arquivo>  -> entrega arquivos de lab/share (o guest baixa loader e payload)
- POST /report     -> grava o relatorio em lab/reports/

O guest fala com 10.0.2.2 (slirp) na porta 8000, entao nao precisamos de
nenhum disco extra so' para transportar arquivo.
"""

import http.server
import os
import socketserver
import sys
import time

BASE = os.path.dirname(os.path.abspath(__file__))
SHARE = os.path.join(BASE, "share")
OUT = os.path.join(BASE, "reports")
os.makedirs(OUT, exist_ok=True)


class Handler(http.server.BaseHTTPRequestHandler):
    def _send(self, code: int, body: bytes, ctype: str = "text/plain") -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        name = os.path.basename(self.path.split("?")[0])
        if name:
            path = os.path.join(SHARE, name)
            if os.path.isfile(path):
                with open(path, "rb") as fh:
                    data = fh.read()
                print(f"[send] {name} ({len(data)} bytes)", flush=True)
                self._send(200, data, "application/octet-stream")
                return
        self._send(200, b"sala de espera do lab\n")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b""
        name = self.path.strip("/").replace("/", "_") or "report"
        stamp = time.strftime("%Y%m%d-%H%M%S")
        path = os.path.join(OUT, f"{stamp}-{name}.txt")
        with open(path, "wb") as fh:
            fh.write(body)
        print(f"[recv] {path} ({len(body)} bytes)", flush=True)
        self._send(200, b"ok")

    def log_message(self, fmt, *args):
        print("[http] " + fmt % args, flush=True)


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("0.0.0.0", port), Handler) as httpd:
        print(f"[server] 0.0.0.0:{port}  share={SHARE}  out={OUT}", flush=True)
        httpd.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())

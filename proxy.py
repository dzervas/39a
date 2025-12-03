import http.server
import os
import urllib.request

TARGET = os.environ.get("AADE_TARGET", "https://test.gsis.gr/wsaade/VtWs39aFPA")
PORT = int(os.environ.get("PORT", "8080"))
INDEX_PATH = os.path.join(os.getcwd(), "index.html")


class Proxy(http.server.BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
        self.end_headers()

    def do_GET(self):
        if self.path in ("/", "/index.html") and os.path.isfile(INDEX_PATH):
            try:
                with open(INDEX_PATH, "rb") as f:
                    data = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(data)
            except Exception as exc:
                self.send_error(500, str(exc))
            return
        self._forward()

    def _forward(self):
        body = None
        if self.command not in ("GET", "HEAD"):
            length = int(self.headers.get("content-length", "0") or 0)
            body = self.rfile.read(length) if length else None

        url = TARGET + self.path
        headers = {k: v for k, v in self.headers.items() if k.lower() != "host"}
        req = urllib.request.Request(url, data=body, method=self.command, headers=headers)

        try:
            with urllib.request.urlopen(req) as resp:
                self.send_response(resp.status)
                for k, v in resp.headers.items():
                    if k.lower() in {"content-length", "transfer-encoding", "connection", "content-encoding"}:
                        continue
                    self.send_header(k, v)
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(resp.read())
        except Exception as exc:
            self.send_error(502, str(exc))

    do_POST = do_PUT = do_DELETE = _forward


if __name__ == "__main__":
    http.server.ThreadingHTTPServer(("", PORT), Proxy).serve_forever()

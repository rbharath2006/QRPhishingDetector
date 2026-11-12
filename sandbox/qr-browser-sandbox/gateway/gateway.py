"""Fixed-route HTTP gateway to the isolated browser worker.

Only GET /health and POST /analyze are exposed. The target hostname and port
are constants; this is intentionally not an arbitrary HTTP proxy.
"""
import http.client
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 8765
UPSTREAM_HOST = "browser-worker"
UPSTREAM_PORT = 8765
MAX_BODY_BYTES = 8192
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
UPSTREAM_TIMEOUT_SECONDS = 50


class GatewayHandler(BaseHTTPRequestHandler):
    server_version = "QRSandboxGateway/0.1"

    def log_message(self, fmt, *args):
        # Avoid logging submitted query strings or URL payloads.
        print(f"gateway {self.client_address[0]} {self.command} {self.path.split('?')[0]}")

    def send_json(self, status: int, payload: dict):
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path != "/health":
            self.send_json(404, {"error": "Resource not found."})
            return
        self._forward("GET", "/health", None)

    def do_POST(self):
        if self.path != "/analyze":
            self.send_json(404, {"error": "Resource not found."})
            return

        # Reject ambiguous HTTP framing to avoid request-smuggling behaviors.
        content_length = self.headers.get("Content-Length")
        transfer_encoding = self.headers.get("Transfer-Encoding", "").strip().lower()
        if content_length is not None and transfer_encoding:
            self.send_json(400, {"error": "Ambiguous request body framing."})
            return

        if transfer_encoding:
            if transfer_encoding != "chunked":
                self.send_json(400, {"error": "Unsupported request transfer encoding."})
                return
            body, error_status, error_message = self._read_chunked_body()
            if error_status is not None:
                self.send_json(error_status, {"error": error_message})
                return
        else:
            try:
                length = int(content_length or "0")
            except ValueError:
                self.send_json(400, {"error": "Invalid Content-Length."})
                return
            if length < 1:
                self.send_json(400, {"error": "Request body must not be empty."})
                return
            if length > MAX_BODY_BYTES:
                self.send_json(413, {"error": "Request body exceeds the permitted size."})
                return
            body = self.rfile.read(length)
            if len(body) != length:
                self.send_json(400, {"error": "Incomplete request body."})
                return

        if not body:
            self.send_json(400, {"error": "Request body must not be empty."})
            return
        self._forward("POST", "/analyze", body)

    def _read_chunked_body(self):
        """Decode a bounded HTTP/1.1 chunked request body.

        Returns (body, status, message); body is None when an error occurred.
        Both chunk sizes and total decoded bytes are bounded.
        """
        body = bytearray()
        while True:
            line = self.rfile.readline(1025)
            if not line or len(line) > 1024 or not line.endswith(b"\r\n"):
                return None, 400, "Malformed chunked request body."
            size_token = line[:-2].split(b";", 1)[0].strip()
            try:
                size = int(size_token, 16)
            except ValueError:
                return None, 400, "Malformed chunk size."
            if size < 0:
                return None, 400, "Malformed chunk size."
            if size == 0:
                # Consume bounded optional trailers and the final empty line.
                trailer_bytes = 0
                while True:
                    trailer = self.rfile.readline(1025)
                    if not trailer or len(trailer) > 1024:
                        return None, 400, "Malformed chunked trailers."
                    trailer_bytes += len(trailer)
                    if trailer_bytes > 8192:
                        return None, 400, "Chunked trailers exceed the permitted size."
                    if trailer == b"\r\n":
                        break
                break
            if len(body) + size > MAX_BODY_BYTES:
                return None, 413, "Request body exceeds the permitted size."
            chunk = self.rfile.read(size)
            if len(chunk) != size or self.rfile.read(2) != b"\r\n":
                return None, 400, "Incomplete chunked request body."
            body.extend(chunk)

        if not body:
            return None, 400, "Request body must not be empty."
        return bytes(body), None, None

    def _forward(self, method: str, fixed_path: str, body: bytes | None):
        connection = http.client.HTTPConnection(
            UPSTREAM_HOST, UPSTREAM_PORT, timeout=UPSTREAM_TIMEOUT_SECONDS
        )
        try:
            headers = {"Connection": "close"}
            if body is not None:
                headers["Content-Type"] = "application/json"
            connection.request(method, fixed_path, body=body, headers=headers)
            response = connection.getresponse()
            payload = response.read(MAX_RESPONSE_BYTES + 1)
            if len(payload) > MAX_RESPONSE_BYTES:
                self.send_json(502, {"error": "Sandbox response exceeded the permitted size."})
                return
            self.send_response(response.status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(payload)
        except (OSError, TimeoutError, http.client.HTTPException):
            self.send_json(503, {"error": "Sandbox worker is temporarily unavailable."})
        finally:
            connection.close()

    def do_PUT(self):
        self.send_json(405, {"error": "Method not allowed."})

    def do_DELETE(self):
        self.send_json(405, {"error": "Method not allowed."})

    def do_PATCH(self):
        self.send_json(405, {"error": "Method not allowed."})

    def do_OPTIONS(self):
        self.send_json(405, {"error": "Method not allowed."})


def main():
    server = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), GatewayHandler)
    server.daemon_threads = True
    print(f"QR sandbox API gateway listening on {LISTEN_HOST}:{LISTEN_PORT}; fixed routes only")
    server.serve_forever()


if __name__ == "__main__":
    main()

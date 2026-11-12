import base64
import ipaddress
import json
import os
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
from playwright.sync_api import sync_playwright

HOST = "0.0.0.0"
PORT = 8765
MAX_BODY_BYTES = 8192
MAX_URL_LENGTH = 2048
MAX_NAVIGATION_HOPS = 10
NAVIGATION_TIMEOUT_MS = 15_000
POST_NAVIGATION_WAIT_MS = 700
MAX_RECORDED_REQUESTS = 60
MAX_PAGE_ERRORS = 20
MAX_CONCURRENT_SCANS = 2
scan_slots = threading.BoundedSemaphore(MAX_CONCURRENT_SCANS)


def is_global_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
        if getattr(address, "ipv4_mapped", None) is not None:
            address = address.ipv4_mapped
        return bool(address.is_global and not address.is_multicast and not address.is_unspecified)
    except ValueError:
        return False


def validate_url(raw_url: object) -> str:
    if not isinstance(raw_url, str):
        raise ValueError("A URL string is required.")
    value = raw_url.strip()
    if not value or len(value) > MAX_URL_LENGTH:
        raise ValueError("URL must contain between 1 and 2048 characters.")

    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        raise ValueError("The URL is malformed.") from None

    if parsed.scheme.lower() != "https":
        raise ValueError("Sandbox analysis accepts HTTPS URLs only.")
    if not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise ValueError("The URL hostname is invalid or contains user information.")
    if port not in (None, 443):
        raise ValueError("Only the standard HTTPS port is allowed.")
    if parsed.fragment:
        # Fragments are not sent to servers and are not needed for this analysis.
        value = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, parsed.query, ""))
        parsed = urlsplit(value)

    hostname = parsed.hostname.rstrip(".").lower()
    blocked_suffixes = (".localhost", ".local", ".internal", ".test", ".invalid", ".example")
    if hostname in {"localhost", "metadata.google.internal"} or hostname.endswith(blocked_suffixes):
        raise ValueError("Local or reserved hostnames are not allowed.")

    try:
        ip_value = ipaddress.ip_address(hostname)
    except ValueError:
        try:
            ascii_host = hostname.encode("idna").decode("ascii")
        except UnicodeError:
            raise ValueError("The URL hostname is invalid.") from None
        if not ascii_host or any(not label or len(label) > 63 for label in ascii_host.split(".")):
            raise ValueError("The URL hostname is invalid.")
        # Rebuild hostname in ASCII form, preserving path/query but not fragment.
        netloc = ascii_host
        if parsed.port:
            netloc += f":{parsed.port}"
        value = urlunsplit(("https", netloc, parsed.path or "/", parsed.query, ""))
    else:
        if not is_global_ip(str(ip_value)):
            raise ValueError("Non-public IP addresses are not allowed.")
        # Keep the literal public IP; the egress proxy validates and pins the connection IP.
        value = urlunsplit(("https", parsed.netloc, parsed.path or "/", parsed.query, ""))

    return value


def redact_url(value: str) -> str:
    """Keep URL structure useful for analysis while redacting query values."""
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in ("http", "https"):
            return f"{parsed.scheme}:[non-network resource]"[:1200]
        safe_query = urlencode([(key, "REDACTED") for key, _ in parse_qsl(parsed.query, keep_blank_values=True)])
        safe_netloc = parsed.hostname or ""
        if parsed.port:
            safe_netloc += f":{parsed.port}"
        return urlunsplit((parsed.scheme, safe_netloc, parsed.path[:512], safe_query, ""))[:1200]
    except Exception:
        return "[URL REDACTED]"


def inspect_url(url: str) -> dict:
    navigation_chain: list[str] = []
    request_events: list[dict] = []
    response_events: list[dict] = []
    page_errors: list[str] = []
    navigation_error = None
    page_title = ""
    visible_text = ""
    http_status = None
    screenshot_b64 = None
    final_url = url
    navigation_count = 0

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            headless=True,
            proxy={"server": "http://egress-proxy:3128", "bypass": ""},
            args=[
                "--disable-background-networking",
                "--disable-component-update",
                "--disable-default-apps",
                "--disable-sync",
                "--no-first-run",
                "--proxy-bypass-list=<-loopback>",
            ],
        )
        context = browser.new_context(
            viewport={"width": 1280, "height": 720},
            accept_downloads=False,
            ignore_https_errors=False,
            service_workers="block",
            java_script_enabled=True,
        )
        page = context.new_page()

        def route_request(route):
            nonlocal navigation_count
            request = route.request
            parsed_request = urlsplit(request.url)
            if parsed_request.scheme in ("data", "blob") and not request.is_navigation_request():
                route.continue_()
                return
            if parsed_request.scheme != "https":
                # HTTP, local-file and browser-internal navigations are denied.
                route.abort()
                return
            if request.is_navigation_request():
                try:
                    if request.frame == page.main_frame:
                        navigation_count += 1
                        if navigation_count > MAX_NAVIGATION_HOPS + 1:
                            route.abort()
                            return
                        safe_target = redact_url(request.url)
                        if not navigation_chain or navigation_chain[-1] != safe_target:
                            navigation_chain.append(safe_target)
                except Exception:
                    pass
            route.continue_()

        page.route("**/*", route_request)
        page.on("request", lambda request: request_events.append({
            "method": request.method,
            "url": redact_url(request.url),
            "resourceType": request.resource_type,
        }) if len(request_events) < MAX_RECORDED_REQUESTS else None)
        page.on("response", lambda response: response_events.append({
            "url": redact_url(response.url),
            "status": response.status,
            "resourceType": response.request.resource_type,
        }) if len(response_events) < MAX_RECORDED_REQUESTS else None)
        page.on("pageerror", lambda error: page_errors.append(str(error).splitlines()[0][:240])
                 if len(page_errors) < MAX_PAGE_ERRORS else None)
        context.on("page", lambda popup: popup.close() if popup != page else None)
        page.on("download", lambda download: download.cancel())

        try:
            response = page.goto(url, wait_until="domcontentloaded", timeout=NAVIGATION_TIMEOUT_MS)
            if response is not None:
                http_status = response.status
            page.wait_for_timeout(POST_NAVIGATION_WAIT_MS)
        except PlaywrightTimeoutError:
            navigation_error = "Navigation timed out. Partial observations may be available."
        except Exception as exc:
            # Avoid returning raw browser diagnostics or remote content to the API caller.
            text = type(exc).__name__
            navigation_error = f"Browser navigation failed ({text})."

        try:
            page_title = (page.title() or "")[:300]
        except Exception:
            page_title = ""
        try:
            visible_text = (page.locator("body").inner_text(timeout=1500) or "")[:2000]
        except Exception:
            visible_text = ""
        try:
            screenshot = page.screenshot(type="jpeg", quality=60, full_page=False, timeout=2500)
            screenshot_b64 = base64.b64encode(screenshot).decode("ascii")
        except Exception:
            screenshot_b64 = None
        try:
            final_url = redact_url(page.url)
        except Exception:
            final_url = redact_url(url)
        context.close()
        browser.close()

    return {
        "status": "COMPLETED" if navigation_error is None else "PARTIAL",
        "originalUrl": redact_url(url),
        "finalUrl": final_url,
        "redirectChain": navigation_chain[: MAX_NAVIGATION_HOPS + 1],
        "pageTitle": page_title,
        "httpStatus": http_status,
        "navigationError": navigation_error,
        "visibleTextSample": visible_text,
        "requestCountRecorded": len(request_events),
        "requests": request_events,
        "responses": response_events,
        "pageErrors": page_errors,
        "screenshotBase64": screenshot_b64,
        "limitations": [
            "HTTPS navigation only; HTTP requests are blocked.",
            "Query parameter values are redacted in returned URLs.",
            "A screenshot and browser observations do not prove a page is safe or malicious.",
        ],
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "QRBrowserSandbox/0.1"

    def log_message(self, fmt, *args):
        # Keep console logs free of submitted URLs and user-supplied values.
        print(f"sandbox-api {self.client_address[0]} {self.command} {self.path.split('?')[0]} {args[1] if len(args) > 1 else ''}")

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
        if self.path == "/health":
            self.send_json(200, {"status": "ok", "service": "qr-browser-sandbox"})
        else:
            self.send_json(404, {"error": "Resource not found."})

    def do_POST(self):
        if self.path != "/analyze":
            self.send_json(404, {"error": "Resource not found."})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_json(400, {"error": "Invalid Content-Length."})
            return
        if length < 1 or length > MAX_BODY_BYTES:
            self.send_json(400, {"error": "Request body must be between 1 and 8192 bytes."})
            return
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            url = validate_url(payload.get("url") if isinstance(payload, dict) else None)
        except (UnicodeDecodeError, json.JSONDecodeError):
            self.send_json(400, {"error": "Request body must be valid JSON."})
            return
        except ValueError as exc:
            self.send_json(400, {"error": str(exc)})
            return

        if not scan_slots.acquire(blocking=False):
            self.send_json(429, {"error": "Sandbox is busy. Try again shortly."})
            return
        try:
            result = inspect_url(url)
            self.send_json(200, result)
        except Exception as exc:
            print(f"sandbox worker error: {type(exc).__name__}")
            self.send_json(502, {"error": "Sandbox analysis could not be completed."})
        finally:
            scan_slots.release()


def main():
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    server.daemon_threads = True
    print(f"QR browser sandbox API listening on {HOST}:{PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()

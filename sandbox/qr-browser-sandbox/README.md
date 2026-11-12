# QR Phishing Detector — Browser Sandbox Add-on (Local Academic MVP)

This bundle adds a standalone Playwright/Chromium worker, a validating HTTPS egress proxy, and a fixed-route API gateway. It is separate from the existing Spring Boot/PostgreSQL application and does not mount the project directory or database into the browser container.

## Network design

- `browser-worker` is attached only to the internal `sandbox_internal` network and is never published directly to the Windows host.
- `egress-proxy` bridges `sandbox_internal` and `sandbox_egress`; the browser is configured to use it for HTTPS navigation.
- `api-gateway` is the only sandbox component published to the host, bound to `127.0.0.1:8765`. It is attached to the internal network and a separate frontdoor bridge because recent Docker Engine releases can silently omit published-port mappings for containers attached only to an internal network. The gateway only forwards `GET /health` and `POST /analyze` to the fixed `browser-worker:8765` upstream. It is not an arbitrary proxy.
- Docker port publishing on `127.0.0.1` is for local machine access only; do not change it to `0.0.0.0`.

## Security behavior

- The proxy permits only HTTPS `CONNECT` requests on port 443, rejects local/reserved hostnames and any hostname resolution containing a non-global IP, and connects to the selected resolved IP to mitigate DNS rebinding between validation and connection.
- DNS answers containing any non-public address are rejected (fail closed).
- The worker, proxy, and gateway run as non-root users, with read-only container root filesystems, dropped Linux capabilities, `no-new-privileges`, resource limits, and no host/project volume mounts.
- The browser uses a fresh context for every request; downloads are disabled, popups are closed, and navigation is bounded by a hop limit and timeout.
- HTTP URLs and HTTP subresource requests are blocked. Query parameter values are redacted in returned URLs. Screenshots are returned as base64 rather than saved into a mounted directory.
- The gateway accepts only `GET /health` and `POST /analyze`, validates request body size, and forwards to a fixed upstream hostname. It does not accept arbitrary upstream URLs.

## Important limits

This is an academic local prototype, not a production-certified malware sandbox. Browser or kernel vulnerabilities are still possible. The gateway has a normal bridge for host port publication; its code exposes only fixed routes, but the network setup must still be reviewed independently before production use. The sandbox has no malware detonation analysis, filesystem/registry telemetry, packet capture or distributed task queue. Public websites can be slow or block automated browsers.

The upstream Playwright docs warn that their prebuilt browser image is intended for testing/development and is not recommended for visiting untrusted websites. This bundle instead builds a custom non-root image and places browser egress behind a validating proxy; that improves isolation but is not a guarantee of perfect containment.

## 1. Start the services

From this folder:

```powershell
docker compose up --build -d
```

The first build may take several minutes because Chromium and Linux dependencies are downloaded.

## 2. Check status

```powershell
docker compose ps
docker compose logs --tail 60 egress-proxy browser-worker api-gateway
```

The proxy and gateway should become healthy; the browser worker should be running. Only the gateway publishes `127.0.0.1:8765` to the host.

## 3. Test API

```powershell
Invoke-RestMethod http://127.0.0.1:8765/health
```

Then run:

```powershell
.\tests\verify-sandbox.ps1
```

A successful external-page test returns structured JSON including status, redirect chain, title, HTTP status, request/response observations, JavaScript errors and an optional base64 JPEG screenshot. A navigation error can occur due to target-site behavior, certificate validation, or network restrictions; that doesn't by itself prove the sandbox is broken.

## 4. Stop the sandbox

```powershell
docker compose down
```

This stops/removes only the containers and networks defined by this Compose project. It does not delete images/volumes used by the existing QR app.

## 5. Spring Boot integration

Copy these source files into the existing project under `src/main/java/com/bharath/qr_phishing_detector/controller/`:

- `integration/SandboxAnalysisConfig.java`
- `integration/SandboxAnalysisController.java`

Append the one line in `integration/application-properties-snippet.txt` to `src/main/resources/application.properties`.

The endpoint remains disabled by default. After the worker and gateway pass tests, set `$env:SANDBOX_ENABLED = "true"` in the same PowerShell terminal used to start Spring Boot, and restart the app. The endpoint is `POST /api/v1/sandbox-analysis` with JSON `{ "url": "https://example.com/" }`.

The Java integration config in this starter currently uses `http://127.0.0.1:8765`, which is correct when Spring Boot runs on Windows. If Spring Boot later runs as another container, switch that base URL to the gateway's service/DNS name and connect it to the appropriate network rather than publishing to `0.0.0.0`.

# QR Phishing Detector

A QR-code phishing detection application combining URL analysis, threat intelligence, redirect inspection, and isolated browser sandbox analysis.

## Project overview

The application allows users to inspect QR-code destinations before visiting them. It combines local threat indicators with URL analysis and optional browser-based evidence collection.

This project is an academic/local MVP. Public production deployment requires additional security controls and deployment-specific configuration.

## Features

- QR code scanning through camera access and image upload.
- Manual URL analysis.
- URL normalization and registrable-domain validation.
- Threat-intelligence lookup using PostgreSQL.
- URL heuristic and risk-scoring services.
- Brand impersonation detection.
- Local and configurable remote threat-feed ingestion.
- Redirect destination analysis with request rate limiting.
- Optional isolated browser sandbox analysis.
- Screenshot and browser-analysis evidence in sandbox responses.
- Scan history and CSV export in the browser interface.

## Technology stack

| Layer | Technologies |
|---|---|
| Backend | Java 21 target, Spring Boot 4.1.1 |
| Build | Maven Wrapper |
| Database | PostgreSQL |
| Database migrations | Flyway |
| Persistence | Spring Data JPA / Hibernate |
| Frontend | HTML, CSS and JavaScript |
| Browser sandbox | Docker Compose, Python browser worker, gateway and egress proxy |
| Testing | JUnit and Spring Boot Test |

The application was locally verified using Java 25.0.1 with Java 21 compilation compatibility.

## Architecture

```text
User
 |
 v
QR Phishing Detector Dashboard
 |
 v
Spring Boot Application
 |
 +---- URL normalization and validation
 |
 +---- Threat intelligence lookup
 |       |
 |       v
 |    PostgreSQL
 |
 +---- URL heuristics and risk scoring
 |
 +---- Redirect analysis
 |
 +---- Browser sandbox integration
         |
         v
     API Gateway
         |
         v
     Isolated Browser Worker
         |
         v
     Restricted Egress Proxy
```

The browser sandbox is a separate Docker Compose stack under `sandbox/qr-browser-sandbox`.

The Java sandbox controller and configuration are part of the Spring Boot application. They are not duplicated in the sandbox directory.

## Repository structure

```text
QR-Phishing-Detector/
├── .mvn/
├── src/
│   ├── main/
│   │   ├── java/
│   │   └── resources/
│   │       ├── db/migration/
│   │       ├── static/
│   │       └── application.properties
│   └── test/
├── sandbox/
│   └── qr-browser-sandbox/
│       ├── gateway/
│       ├── worker/
│       ├── proxy/
│       ├── integration/
│       ├── tests/
│       └── docker-compose.yml
├── dev-data/
├── docs/
├── .env.example
├── .gitignore
├── pom.xml
├── mvnw
└── mvnw.cmd
```

## Prerequisites

- Java 21 or later.
- PostgreSQL.
- Docker Desktop with Docker Compose.
- Windows PowerShell for the commands below, or equivalent environment-variable configuration on another platform.

## Database setup

Create a PostgreSQL database and application role if they do not already exist.

Example SQL:

```sql
CREATE ROLE qr_detector_app LOGIN PASSWORD 'CHANGE_THIS_PASSWORD';
CREATE DATABASE qr_phishing_db OWNER qr_detector_app;
```

Use a strong local password. Do not commit database credentials.

Flyway applies the database migrations from:

`src/main/resources/db/migration/`

## Run the browser sandbox

From the repository root:

```powershell
docker compose -f .\sandbox\qr-browser-sandbox\docker-compose.yml up -d --build
```

Check the services:

```powershell
docker compose -f .\sandbox\qr-browser-sandbox\docker-compose.yml ps
```

Check the gateway:

```powershell
Invoke-RestMethod http://127.0.0.1:8765/health
```

Stop the services:

```powershell
docker compose -f .\sandbox\qr-browser-sandbox\docker-compose.yml down
```

## Run the Spring Boot application

Set environment variables in the same PowerShell session:

```powershell
$env:DB_URL = "jdbc:postgresql://localhost:5432/qr_phishing_db"
$env:DB_USERNAME = "qr_detector_app"

$secure = Read-Host "PostgreSQL password" -AsSecureString
$ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)

try {
    $env:DB_PASSWORD = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
    $env:SERVER_PORT = "8081"
    $env:SANDBOX_ENABLED = "true"
    $env:SANDBOX_GATEWAY_URL = "http://127.0.0.1:8765"
    $env:REDIRECT_ANALYSIS_ENABLED = "true"

    .\mvnw.cmd spring-boot:run
}
finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
    Remove-Item Env:DB_PASSWORD -ErrorAction SilentlyContinue
}
```

Open the dashboard:

http://localhost:8081/

The Spring Boot sandbox integration is disabled by default. Enable it explicitly with `SANDBOX_ENABLED=true`.

The remote threat-feed integration is also disabled by default. Configure its URL and permitted host before enabling it.

## Environment variables

See `.env.example` for the supported configuration names and example values.

Important: `.env.example` is a reference template. Spring Boot does not automatically load it. Configure variables through PowerShell, IntelliJ Run Configuration, or the deployment platform's secret/environment-variable settings.

## API endpoints

| Endpoint | Purpose |
|---|---|
| `POST /api/v1/intelligence/lookup` | Threat intelligence lookup |
| `POST /api/v1/redirect-analysis` | Redirect destination analysis |
| `POST /api/v1/sandbox-analysis` | Browser sandbox analysis |
| `GET /actuator/health` | Application health |

The sandbox endpoint is available only when sandbox analysis is enabled.

## Run tests

With the required PostgreSQL environment variables configured:

```powershell
.\mvnw.cmd clean verify
```

The project passed 69 automated tests in the local verification performed during repository preparation.

## Security considerations

- Never commit `.env` files, database passwords, API tokens, certificates, or private keys.
- Do not expose PostgreSQL, the browser worker, gateway, or egress proxy directly to the public internet.
- Keep the browser worker isolated and restrict its network egress.
- The sandbox gateway URL must point to a private, reachable service in the deployment environment.
- Add authentication, rate limiting, abuse protection and resource limits before exposing sandbox analysis publicly.
- Treat a low risk score as an assessment, not a guarantee that a URL is safe.
- Browser camera access requires a secure browser context such as localhost or HTTPS.

## Development status

The local Spring Boot application, PostgreSQL/Flyway integration, automated test suite and Docker Compose configuration have been verified.

Cloud deployment and public production hardening are separate tasks and should be completed before advertising the complete sandbox as a public service.
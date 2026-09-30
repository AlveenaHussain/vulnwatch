# VulnWatch

> **Authorized VAPT + SOC Security Monitoring Platform**

VulnWatch is a cybersecurity portfolio and authorized security-lab platform that combines **Vulnerability Assessment and Penetration Testing (VAPT)** with **Security Operations Center (SOC)** monitoring in a single application.

The platform is designed for cybersecurity learning, authorized lab testing, vulnerability management, security-event detection, alert correlation, investigation, target scanning, and security assessment reporting.

> **Important:** VulnWatch is intended only for systems and networks that are owned by the user or where explicit authorization has been provided.

---

## Overview

VulnWatch connects vulnerability assessment and SOC monitoring workflows into one platform.

The platform can:

* Discover assets and services using Nmap
* Import Nmap XML scan results
* Maintain assets, services, vulnerabilities, and findings
* Track CVE, CVSS, CWE, and severity information
* Import security events
* Detect SSH brute-force activity
* Detect port-scan activity
* Generate SOC alerts
* Correlate security alerts with known vulnerabilities
* Provide investigation chains
* Trigger authorized target scans from the browser
* Queue scan jobs for a Kali scanning agent
* Generate security assessment reports
* Apply API authentication and input-validation controls
* Restrict target scanning to an authorized network range

---

# Key Capabilities

## VAPT

VulnWatch provides a vulnerability-management workflow around Nmap scan data.

### Asset Discovery

Nmap XML results can be imported into VulnWatch to create or update:

* Assets
* Open ports
* Network services
* Service versions
* Scan records

### Vulnerability Management

The platform maintains vulnerability information including:

* CVE
* CVSS
* Severity
* CWE
* Vulnerability descriptions
* Service-to-vulnerability relationships

### Findings

Findings connect vulnerabilities with affected services and assets.

Finding status can be tracked, including states such as:

* Open
* Resolved

---

# SOC Monitoring

VulnWatch also contains a lightweight SOC monitoring pipeline.

The current workflow processes authentication-log data and converts relevant security activity into structured events.

```text
Authentication Logs
        ↓
Security Events
        ↓
Detection Engine
        ↓
SOC Alerts
        ↓
Correlation Engine
        ↓
Investigations
```

## Current Detection Logic

### SSH Brute Force

SSH authentication failures are evaluated using thresholds.

Current severity thresholds include:

* 2+ events → MEDIUM
* 5+ events → HIGH
* 10+ events → CRITICAL

### Port Scan

Port-scan detection identifies activity involving multiple destination ports.

The current detection logic treats:

```text
10+ unique destination ports
```

as a HIGH-severity port-scan alert.

---

# Alert Correlation

VulnWatch correlates SOC alerts with known vulnerabilities affecting the same asset.

Example:

```text
SSH Brute Force Alert
        +
Known Vulnerability on Target
        ↓
Correlation
        ↓
Investigation
```

The correlation engine:

1. Identifies the alert destination IP
2. Matches it with the affected asset
3. Finds vulnerabilities associated with services on that asset
4. Creates a correlation between the alert and vulnerability
5. Assigns priority using the higher severity between the alert and vulnerability

This helps connect:

**What happened?**

with:

**What security weakness exists on the affected system?**

---

# Investigation Workflow

A correlation can be expanded into an investigation chain.

The investigation can connect:

```text
Correlation
   ↓
Alert
   ↓
Asset
   ↓
Service
   ↓
Service Vulnerability
   ↓
Vulnerability
   ↓
Finding
   ↓
Security Event
```

This provides a relationship between security monitoring data and vulnerability-management data.

---

# Browser-Triggered Target Scan

VulnWatch supports an authorized browser-triggered target-scan workflow.

The workflow is designed so that the web application does not directly execute Nmap.

Instead:

```text
Browser
   ↓
FastAPI
   ↓
Scan Job Queue
   ↓
Kali Target Scan Agent
   ↓
Nmap
   ↓
Nmap XML
   ↓
FastAPI
   ↓
PostgreSQL
   ↓
Frontend Results
```

## Target Scan Flow

1. User submits an authorized target IP.
2. Backend validates the target.
3. Duplicate active scans are prevented.
4. A scan job is created with `PENDING` status.
5. The Kali agent polls for available jobs.
6. The job is claimed safely by the agent.
7. Nmap performs service discovery.
8. Nmap generates XML output.
9. XML is submitted back to the backend.
10. Scan results are imported.
11. The job is marked `COMPLETED`.
12. The frontend retrieves the resulting security information.

The target-scan Nmap execution uses:

```python
subprocess.run(
    ["nmap", "-sV", "-oX", tmpfile, target_ip],
    shell=False,
    timeout=180
)
```

This prevents shell command interpretation and places a timeout on the scanning process.

---

# Target Authorization

Target scanning is restricted using an authorized network configuration.

The lab currently uses:

```text
192.168.57.0/24
```

through:

```text
VULNWATCH_AUTHORIZED_NETWORK
```

The target IP is validated before a scan job is created.

This is an important safety control for an authorized security-lab platform.

---

# Architecture

```text
                    ┌─────────────────────┐
                    │     Web Browser      │
                    │   React + Vite UI    │
                    └──────────┬──────────┘
                               │
                               │ HTTP
                               ▼
                    ┌─────────────────────┐
                    │      FastAPI        │
                    │      Backend        │
                    │       :8000         │
                    └───────┬─────┬───────┘
                            │     │
                 ┌──────────┘     └─────────────┐
                 │                              │
                 ▼                              ▼
        ┌─────────────────┐           ┌─────────────────┐
        │   PostgreSQL    │           │   Kali Agent    │
        │       DB        │           │   Nmap Scanner  │
        └─────────────────┘           └────────┬────────┘
                                                │
                                                ▼
                                      ┌─────────────────┐
                                      │ Authorized Lab  │
                                      │     Target      │
                                      │  Metasploitable │
                                      └─────────────────┘
```

---

# End-to-End VAPT Workflow

```text
Nmap
  ↓
Nmap XML
  ↓
XML Collector
  ↓
POST /api/v1/scans/import
  ↓
Scan Import
  ↓
Assets + Services
  ↓
Vulnerabilities
  ↓
Service Vulnerabilities
  ↓
Findings
  ↓
Risk / Vulnerability Management
```

---

# End-to-End SOC Workflow

```text
Authentication Log
        ↓
Auth Log Collector
        ↓
Security Events
        ↓
Detection Engine
        ↓
Alerts
        ↓
Correlation Engine
        ↓
Correlations
        ↓
Investigations
```

---

# Security Assessment Reporting

VulnWatch can generate a security assessment report for an asset.

The report includes sections covering:

1. Header
2. Executive Summary
3. Scope & Methodology
4. Risk Summary
5. Target & Asset Information
6. Open Ports & Services
7. Vulnerabilities / Unique CVEs
8. Detailed Findings
9. Security Monitoring
10. Report Summary

The report groups repeated vulnerability references by unique CVE and can include multiple findings under the same CVE.

Evidence is derived from available scan, service, CPE, and vulnerability data.

The reporting workflow does **not** fabricate:

* Screenshots
* HTTP requests
* Exploit output
* Security logs
* Evidence that was not collected

Impact descriptions are derived conservatively from available vulnerability information.

---

# Technology Stack

| Layer                        | Technology              |
| ---------------------------- | ----------------------- |
| Frontend                     | React 19                |
| Build Tool                   | Vite                    |
| Backend                      | FastAPI                 |
| Server                       | Uvicorn                 |
| Database                     | PostgreSQL 16           |
| Database Driver              | psycopg                 |
| Scanner                      | Nmap                    |
| XML Parser                   | defusedxml              |
| Containerization             | Docker / Docker Compose |
| Security Testing Environment | Kali Linux              |
| Target                       | Metasploitable 2        |
| API Documentation            | Swagger / OpenAPI       |

---

# Lab Environment

The project was developed and tested in an isolated authorized cybersecurity lab.

| Component             | Value                        |
| --------------------- | ---------------------------- |
| VulnWatch Backend     | `127.0.0.1:8000`             |
| Frontend              | `localhost:5173`             |
| Lab Network           | `192.168.57.0/24`            |
| Kali Scanner          | `192.168.57.102`             |
| Metasploitable Target | `192.168.57.101`             |
| Target Hostname       | `metasploitable`             |
| Database              | PostgreSQL 16                |
| API Documentation     | `http://127.0.0.1:8000/docs` |

---

# Project Structure

```text
vulnwatch/
│
├── .env
├── .env.example
├── .gitignore
├── README.md
├── docker-compose.yml
│
├── backend/
│   ├── Dockerfile
│   ├── .dockerignore
│   ├── requirements.txt
│   ├── schema.sql
│   ├── main.py
│   ├── database.py
│   ├── security.py
│   ├── scan_import.py
│   ├── vulnerabilities.py
│   ├── security_events.py
│   ├── alerts.py
│   ├── correlations.py
│   ├── investigations.py
│   ├── target_scan.py
│   ├── reporting.py
│   ├── schemas.py
│   │
│   └── migrations/
│       ├── 001_add_security_events.sql
│       ├── 002_add_alerts.sql
│       ├── 003_add_correlations.sql
│       ├── 004_add_scan_jobs.sql
│       └── 005_fix_service_state_constraint.sql
│
├── collectors/
│   ├── nmap_xml_collector.py
│   ├── auth_log_collector.py
│   ├── detection_engine.py
│   ├── correlation_engine.py
│   ├── target_scan_agent.py
│   │
│   └── nvd/
│       ├── nvd_collector.py
│       └── requirements.txt
│
├── frontend/
│   ├── package.json
│   ├── vite.config.js
│   ├── index.html
│   │
│   └── src/
│       ├── main.jsx
│       ├── App.jsx
│       ├── App.css
│       └── index.css
│
└── scans/
    ├── metasploitable-services.xml
    ├── target-scan.xml
    └── auth_log_collector.py
```

---

# Security Controls

VulnWatch includes several security controls designed for the authorized lab environment.

## API Authentication

Protected API endpoints use an API key supplied through the environment.

Authentication uses constant-time comparison through:

```python
secrets.compare_digest
```

The application fails closed when the required API key is not configured.

---

## Authorized Network Validation

Target scanning validates the requested target against the configured authorized network.

This helps prevent accidental scanning of systems outside the intended lab range.

---

## SSRF Protection

Target validation includes IP resolution and authorized-network checks before a target scan is queued.

---

## Safe Nmap Execution

Nmap is executed without shell interpretation:

```text
shell=False
```

A timeout is also applied to scanning operations.

---

## Parameterized SQL

Database queries use parameterized SQL rather than dynamically concatenating untrusted input.

This reduces SQL-injection risk.

---

## Secure XML Parsing

Nmap XML is parsed using:

```text
defusedxml
```

rather than an unsafe XML parser.

---

## Input Validation

FastAPI/Pydantic schemas validate API request data.

Invalid request bodies are rejected with validation errors.

---

## Duplicate Scan Protection

The target-scan workflow prevents duplicate active scans for the same target.

---

## Race-Safe Job Claiming

Pending target-scan jobs use database locking with:

```sql
FOR UPDATE SKIP LOCKED
```

This helps prevent multiple agents from claiming the same job concurrently.

---

## Stale Job Recovery

Long-running `RUNNING` jobs can be recovered after the configured stale-job period instead of remaining permanently stuck.

---

## Docker Non-Root Execution

The backend Docker container runs the application under a non-root user.

---

## CORS Restriction

CORS is configured for explicit allowed origins rather than accepting arbitrary origins.

---

## Generic Error Handling

The application avoids exposing internal traceback details through normal API error responses.

---

## XML Size Protection

Imported XML content has a configured maximum size to reduce oversized-input risk.

---

# Database Model

The database connects the VAPT and SOC portions of the platform.

Core entities include:

```text
Scans
  ↓
Assets
  ↓
Services
  ↓
Service Vulnerabilities
  ↓
Vulnerabilities
  ↓
Findings
```

SOC entities connect through:

```text
Security Events
  ↓
Alerts
  ↓
Correlations
  ↓
Investigations
```

Target scanning additionally uses:

```text
Scan Jobs
```

to manage browser-triggered scanning asynchronously.

Important uniqueness constraints include:

* Unique asset IP addresses
* Unique service per asset / port / protocol
* Unique CVE IDs
* Unique service-vulnerability relationships
* Unique open alert combinations
* Unique alert-vulnerability correlations

---

# API Modules

The backend exposes API functionality for:

* Health checks
* Assets
* Services
* Scans
* Scan imports
* Vulnerabilities
* Service-vulnerability relationships
* Findings
* Security events
* Alerts
* Correlations
* Investigations
* Target scans
* Dashboard data
* Security reports

Interactive API documentation is available through Swagger/OpenAPI:

```text
http://127.0.0.1:8000/docs
```

---

# Frontend

The frontend is built using React and Vite.

The application includes interfaces for:

* Dashboard
* Assets
* Services
* Vulnerabilities
* Findings
* Scans
* Alerts
* Correlations
* Security Events
* Investigations
* Target Scan
* Reports

The target-scan interface provides:

* Target IP input
* Scan initiation
* Job status
* Polling
* Scan results
* Asset information
* Services
* Vulnerabilities
* Findings
* Alerts
* Correlations
* Re-scan workflow
* Report access

---

# Installation

## Prerequisites

Recommended environment:

* Windows / Linux host
* Docker Desktop or Docker Engine
* Git
* Python 3.12+
* Node.js / npm
* Kali Linux for scanning
* An authorized vulnerable lab target such as Metasploitable 2

---

# Backend Setup

Clone the repository:

```bash
git clone https://github.com/AlveenaHussain/vulnwatch.git
cd vulnwatch
```

Create the environment configuration from the example file:

```text
.env.example
```

Set the required PostgreSQL and VulnWatch configuration values.

Do not commit real secrets to Git.

---

# Start Backend and Database

From the project root:

```bash
docker compose up -d --build
```

Check the running containers:

```bash
docker compose ps
```

The backend should become available at:

```text
http://127.0.0.1:8000
```

Health endpoint:

```text
http://127.0.0.1:8000/health
```

Swagger:

```text
http://127.0.0.1:8000/docs
```

---

# Frontend Setup

Go to the frontend directory:

```bash
cd frontend
```

Install dependencies:

```bash
npm install
```

Start the development server:

```bash
npm run dev
```

The frontend is available at:

```text
http://localhost:5173
```

---

# Kali Target Scan Agent

The target-scan agent runs from the authorized Kali environment.

The agent communicates with the VulnWatch backend to:

1. Request available scan jobs
2. Claim a pending job
3. Run Nmap against the authorized target
4. Generate XML output
5. Submit the result
6. Mark the job as completed or failed

The scanner is intended to run only against authorized lab targets.

---

# Example Lab Workflow

A typical authorized lab workflow is:

```text
1. Start PostgreSQL + FastAPI
2. Start React frontend
3. Start Kali scanner agent
4. Confirm Metasploitable is reachable
5. Start target scan from VulnWatch
6. Nmap performs service discovery
7. Results are imported
8. Review services
9. Review vulnerabilities
10. Review findings
11. Generate security report
12. Import / process SOC events
13. Review alerts
14. Review correlations
15. Open investigation details
```

---

# Current Lab Validation

The authorized Metasploitable lab produced the following representative results:

* Target IP: `192.168.57.101`
* Hostname: `metasploitable`
* 23 discovered services
* CVE-2011-2523 associated with vsftpd 2.3.4
* CVSS: 10.0
* Severity: CRITICAL
* CWE: CWE-78
* 2 findings
* Findings were tested with RESOLVED status
* SSH brute-force alert: HIGH
* Port-scan alert: HIGH
* 2 correlations
* Correlations reached CRITICAL priority
* Target scan Job 3 completed end-to-end

These results are from the authorized lab environment and should not be interpreted as findings against any external system.

---

# Security Validation

The project was manually validated during development for several security scenarios.

Validated cases included:

| Test                              | Result                            |
| --------------------------------- | --------------------------------- |
| Missing API key                   | Rejected with 401                 |
| Incorrect API key                 | Rejected with 401                 |
| Correct API key                   | Accepted                          |
| Invalid request body              | Rejected with 422                 |
| SQL-injection-style input         | Handled through parameterized SQL |
| Untrusted CORS origin             | Rejected                          |
| Unknown endpoint                  | 404 without traceback leakage     |
| Protected endpoint authentication | Verified                          |
| Duplicate target scan             | Prevented                         |
| Target scan end-to-end flow       | Completed successfully            |
| Security report generation        | Verified                          |

These are **manual validation results**, not a formal automated pytest test suite.

---

# Current Limitations

VulnWatch is a cybersecurity portfolio and authorized-lab project rather than a production enterprise security platform.

Current limitations include:

* No formal automated pytest/unit-test suite
* No dedicated rate-limiting layer
* Security headers are not currently implemented
* Database migrations are currently handled manually rather than through Alembic
* The frontend target-scan progress indicator is currently visual rather than real scan-percentage progress
* NVD integration exists as a collector but is currently sidelined because the attempted NVD `/virtualMatchString` integration returned HTTP 404
* Current vulnerability CVE data can therefore be imported manually
* Some dashboard/API behavior still requires additional verification before being considered fully production-ready

The project should therefore be evaluated as an **educational security engineering / portfolio platform**.

---

# Future Improvements

Potential future work includes:

* Automated pytest coverage
* Alembic migration management
* API rate limiting
* Security response headers
* Improved frontend API configuration
* Real scan progress reporting
* More SOC detection rules
* Additional log sources
* Improved correlation rules
* Expanded investigation workflows
* Reliable NVD synchronization
* Background task processing
* Production deployment configuration
* Role-based access control
* More comprehensive audit logging

---

# Screenshots

Recommended screenshots for the project portfolio:

1. Dashboard
2. Target Scan launcher
3. Target Scan running state
4. Completed target-scan results
5. Security assessment report
6. Alerts page
7. Correlations page
8. Investigation detail
9. Swagger/OpenAPI documentation
10. Docker Compose running containers

Screenshots should use the authorized lab environment only.

---

# Portfolio Description

### Short Description

**VulnWatch is an authorized VAPT + SOC security platform built with FastAPI, PostgreSQL, React, Docker, Kali Linux, and Nmap. It combines vulnerability management, SOC detection, alert correlation, investigation workflows, browser-triggered target scanning, and security assessment reporting in one platform.**

---

# Resume Project Highlights

* Built an authorized **VAPT + SOC cybersecurity platform** using Python, FastAPI, PostgreSQL, React, Docker, Kali Linux, and Nmap.
* Implemented browser-triggered Nmap scanning through a backend job queue and Kali scanning agent with authorized-network validation and safe subprocess execution.
* Developed a SOC pipeline that processes authentication events and detects **SSH brute-force and port-scan activity**.
* Implemented alert-to-vulnerability correlation and investigation workflows connecting SOC events with affected assets, services, vulnerabilities, and findings.
* Developed automated security assessment reporting with CVE deduplication, vulnerability evidence, service information, findings, and SOC intelligence.
* Applied security controls including API-key authentication, constant-time comparison, parameterized SQL, secure XML parsing, IP allowlisting, CORS restrictions, duplicate-scan prevention, stale-job recovery, race-safe job claiming, and non-root Docker execution.

---

# Project Safety Notice

VulnWatch is designed for **authorized security testing and educational lab environments**.

Only scan:

* Systems you own
* Systems you have explicit permission to test
* Isolated cybersecurity training environments

Do not use the platform to scan or attack unauthorized systems.

---

# Repository

GitHub:

https://github.com/AlveenaHussain/vulnwatch

---

# Project Status

**Status: Portfolio-ready authorized cybersecurity lab project**

The core VAPT, SOC monitoring, correlation, investigation, target-scan, reporting, and security-hardening workflows have been implemented and manually validated in the isolated lab environment.

Phase 16 focuses on documentation, portfolio presentation, screenshots, interview explanation, and final project polish.

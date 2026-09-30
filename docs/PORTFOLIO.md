# VulnWatch — Portfolio Documentation

## 1. Project Overview

**VulnWatch** is an authorized cybersecurity lab platform that combines **Vulnerability Assessment & Penetration Testing (VAPT)** and **Security Operations Center (SOC)** workflows into a single web-based application.

The project is designed as a cybersecurity learning and portfolio project for understanding how vulnerability data, security events, alerts, correlations, investigations, and security reporting can work together.

### Primary Goals

* Automate authorized Nmap-based asset and service discovery
* Store scan and vulnerability information in PostgreSQL
* Manage CVEs, CVSS severity, CWE and findings
* Collect authentication security events
* Detect SSH brute-force and port-scan activity
* Generate security alerts
* Correlate security alerts with vulnerabilities
* Provide investigation workflows
* Generate asset-level security reports
* Apply practical application and infrastructure security controls

---

## 2. Technology Stack

| Layer             | Technology                      |
| ----------------- | ------------------------------- |
| Backend           | Python, FastAPI                 |
| Database          | PostgreSQL 16                   |
| Frontend          | React 19, Vite                  |
| Scanner           | Nmap                            |
| Security Testing  | Kali Linux                      |
| Containerization  | Docker, Docker Compose          |
| Database Driver   | psycopg 3                       |
| XML Parsing       | defusedxml                      |
| API Documentation | Swagger / OpenAPI               |
| Target            | Metasploitable 2                |
| Network           | Authorized isolated lab network |

---

## 3. Architecture

```text
                    ┌──────────────────────┐
                    │      React UI        │
                    │   Dashboard / SOC    │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │     FastAPI API      │
                    │ Authentication       │
                    │ Validation            │
                    │ Business Logic        │
                    └──────────┬───────────┘
                               │
                ┌──────────────┼──────────────┐
                ▼              ▼              ▼
        ┌────────────┐ ┌─────────────┐ ┌─────────────┐
        │ PostgreSQL │ │ Scan Import │ │ SOC Engine  │
        │            │ │ / Jobs      │ │             │
        └────────────┘ └──────┬──────┘ └──────┬──────┘
                              │               │
                              ▼               ▼
                       ┌────────────┐   ┌─────────────┐
                       │ Nmap/Kali  │   │ Detection & │
                       │ Scanner    │   │ Correlation │
                       └────────────┘   └─────────────┘
```

---

## 4. Major Features

### 4.1 Asset Discovery

VulnWatch accepts Nmap scan results and imports discovered assets and services into PostgreSQL.

The workflow includes:

```text
Nmap
  ↓
Nmap XML
  ↓
Nmap XML Collector
  ↓
FastAPI Scan Import API
  ↓
PostgreSQL
```

The system tracks:

* Assets
* IP addresses
* Host information
* Ports
* Protocols
* Services
* Service versions

---

### 4.2 Vulnerability Management

The vulnerability management workflow associates discovered services with vulnerability information.

The platform supports information such as:

* CVE ID
* CVSS score
* Severity
* CWE
* Vulnerability description
* Service association
* Findings
* Finding status

Example lab vulnerability:

```text
CVE-2011-2523
vsftpd 2.3.4
CVSS: 10.0
Severity: CRITICAL
CWE-78
```

---

### 4.3 Browser-Triggered Target Scanning

VulnWatch provides a browser-based workflow for starting an authorized target scan.

```text
React Frontend
      ↓
POST /api/v1/target-scan/start
      ↓
Target Validation
      ↓
Scan Job Created
      ↓
Kali Target Scan Agent
      ↓
Nmap
      ↓
XML Result
      ↓
VulnWatch Import Pipeline
      ↓
PostgreSQL
      ↓
Frontend Results
```

The target scan workflow includes:

* API-key authentication
* Authorized-network validation
* IP validation
* Duplicate-scan prevention
* Job queue
* Job status tracking
* Stale-job recovery
* Nmap execution
* XML result import

Nmap is executed using `subprocess.run()` with `shell=False` and a timeout.

---

## 5. SOC Capabilities

VulnWatch also contains a basic SOC workflow.

```text
Authentication Logs
        ↓
Security Events
        ↓
Detection Engine
        ↓
Alerts
        ↓
Correlation Engine
        ↓
Investigations
```

### Security Event Collection

Authentication-related activity can be collected and stored as security events.

### Detection Rules

The project includes detection logic for:

#### SSH Brute Force

Threshold-based detection is used:

* 2+ failed attempts → MEDIUM
* 5+ failed attempts → HIGH
* 10+ failed attempts → CRITICAL

#### Port Scan

A source generating connections to **10 or more unique destination ports** is detected as a HIGH-severity port-scan event.

---

## 6. Alert Management

Detected activity is converted into security alerts.

Example alert types include:

* `SSH_BRUTE_FORCE`
* `PORT_SCAN`

The system also prevents duplicate OPEN alerts for the same alert/source/destination combination through a database constraint.

---

## 7. Correlation Engine

The correlation engine connects SOC activity with vulnerability information.

Example:

```text
Security Alert
     │
     │ Destination IP
     ▼
Asset
     │
     ▼
Vulnerable Service
     │
     ▼
Vulnerability
```

The system can identify when a security alert targets an asset that also has a known vulnerable service.

Correlation priority is based on the higher severity between the vulnerability and the security alert.

---

## 8. Investigation Workflow

VulnWatch provides an investigation path from a correlation back to the underlying security information.

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
Security Events
```

This allows an analyst to move from an observed security event toward the affected asset and associated vulnerability information.

---

## 9. Security Controls

Security was considered throughout the application rather than only at the scanning layer.

Implemented controls include:

### API Authentication

Protected API endpoints use an API key supplied through the environment.

The implementation uses constant-time comparison through:

```python
secrets.compare_digest()
```

### Parameterized SQL

Database queries use parameterized SQL instead of directly concatenating user-controlled values.

### XML Security

Nmap XML is parsed using:

```text
defusedxml
```

### Authorized Network Validation

Target scanning is restricted using the configured authorized network.

```text
VULNWATCH_AUTHORIZED_NETWORK
```

### Command Execution Protection

Nmap execution uses:

```text
shell=False
```

and includes a timeout.

### Input Validation

FastAPI/Pydantic validation is used for API request data.

### CORS Restriction

CORS is configured for explicitly allowed origins rather than accepting arbitrary origins.

### Duplicate Scan Protection

The application prevents duplicate active scans against the same target.

### Stale Job Recovery

Stale RUNNING scan jobs can be recovered so that a failed or interrupted worker does not permanently block future scans.

### Race-Safe Job Claiming

The scan worker uses database locking with:

```text
FOR UPDATE SKIP LOCKED
```

to safely claim available jobs.

### Container Security

The backend Docker container runs as a non-root application user.

### Generic Error Handling

Internal implementation details are not intentionally exposed through API error responses.

### XML Size Protection

Imported XML data is limited in size to reduce unnecessary resource consumption.

---

## 10. Database Design

The project uses PostgreSQL for persistent security data.

Core entities include:

```text
scans
assets
services
vulnerabilities
service_vulnerabilities
findings
security_events
alerts
correlations
scan_jobs
```

Important database constraints include:

* Unique asset IP addresses
* Unique services per asset/port/protocol
* Unique CVE IDs
* Unique service-vulnerability relationships
* Duplicate OPEN alert prevention
* Unique alert-vulnerability correlations
* Controlled scan-job states

---

## 11. Security Reporting

VulnWatch generates asset-level security reports.

The report includes sections covering:

1. Header
2. Executive Summary
3. Scope & Methodology
4. Risk Summary
5. Target & Asset Information
6. Open Ports & Services
7. Vulnerabilities
8. Detailed Findings
9. Security Monitoring
10. Report Summary

The report logic also performs CVE deduplication and groups related findings under the same vulnerability.

Evidence is derived from available scan, service, CPE, CVE and security-event data.

The report does not fabricate:

* Screenshots
* HTTP requests
* Exploit output
* Logs
* Evidence that was not actually collected

---

## 12. Lab Environment

The project was validated in an isolated authorized lab environment.

```text
Lab Network: 192.168.57.0/24

Kali Scanner:
192.168.57.102

Metasploitable 2:
192.168.57.101
```

The target used for testing was **Metasploitable 2**.

A validated target scan successfully processed the target through the complete workflow:

```text
Browser
→ FastAPI
→ Scan Job
→ Kali Agent
→ Nmap
→ XML
→ Import
→ PostgreSQL
→ Frontend Results
```

---

## 13. Validation Performed

Manual validation was performed for important security controls and workflows.

### Authentication

Tested:

* Missing API key → `401`
* Incorrect API key → `401`
* Correct API key → successful response

### Input Validation

Invalid request data was rejected with:

```text
422 Unprocessable Entity
```

### SQL Injection-Style Input

SQL injection-style input was tested against the API and handled without breaking the database query flow because SQL statements use parameterized values.

### CORS

Untrusted origins were rejected by the configured CORS policy.

### Endpoint Authentication

Protected endpoints were checked for authentication enforcement.

### Scan Workflow

A complete target-scan workflow was manually validated from browser launch through Nmap execution and result import.

### Reporting

The report endpoint was validated and returned structured asset-level security information.

---

## 14. Current Project Limitations

The project is intentionally a portfolio/lab implementation and still has areas that could be improved.

Current limitations include:

* No formal automated pytest suite
* No built-in rate limiting
* No dedicated security-header middleware
* Database migrations are currently managed manually
* Target-scan UI progress is currently a visual progress indicator rather than true scanner percentage
* NVD integration exists as a collector but is not currently the primary CVE ingestion workflow
* Frontend API configuration can be improved by moving the API base URL into environment configuration

These limitations are documented rather than hidden.

---

## 15. Future Improvements

Potential future enhancements include:

* Automated pytest coverage
* API rate limiting
* Security headers
* Alembic-based database migrations
* Environment-based frontend API configuration
* More SOC detection rules
* Additional correlation rules
* Improved real-time scan progress
* Expanded vulnerability-feed integration
* Role-based access control
* More detailed audit logging
* Production-grade deployment configuration

---

## 16. Portfolio Highlights

### Full-Stack Cybersecurity Platform

Built a full-stack authorized cybersecurity lab platform using:

```text
Python
FastAPI
PostgreSQL
React
Docker
Nmap
Kali Linux
```

### VAPT + SOC Integration

Combined vulnerability assessment workflows with SOC-style event detection, alerting, correlation and investigation.

### Automated Target Scanning

Implemented a browser-triggered authorized scan workflow with:

* Target validation
* Job queue
* Kali scan agent
* Nmap execution
* XML import
* Result polling

### Security Engineering

Implemented practical controls including:

* API authentication
* Parameterized SQL
* XML hardening
* Network allowlisting
* Safe subprocess execution
* Input validation
* CORS restriction
* Non-root Docker
* Stale job recovery
* Race-safe job processing

### Security Reporting

Built structured asset-level reporting with vulnerability, service, finding and SOC information.

---

## 17. Suggested Resume Description

**VulnWatch — VAPT & SOC Security Platform**

Built an authorized cybersecurity lab platform using Python/FastAPI, PostgreSQL, React, Docker, Nmap and Kali Linux. Implemented automated asset discovery, vulnerability management, browser-triggered target scanning, SOC event detection, alerting, vulnerability-alert correlation, investigation workflows and security reporting. Applied security controls including API-key authentication, parameterized SQL, defused XML parsing, authorized-network validation, safe subprocess execution, CORS restriction and non-root containerization.

---

## 18. Suggested GitHub Description

**VulnWatch is an authorized cybersecurity lab platform combining VAPT and SOC workflows. It provides Nmap-based asset discovery, vulnerability management, browser-triggered target scanning, security-event detection, alerting, vulnerability correlation, investigation workflows and asset-level security reporting using FastAPI, PostgreSQL, React, Docker and Kali Linux.**

---

## 19. Project Status

**Project Status: Completed Portfolio/Lab Implementation**

Major VAPT, SOC, correlation, investigation, reporting and security-hardening workflows have been implemented and manually validated in the authorized lab environment.

The project is suitable for demonstrating practical understanding of:

* VAPT
* Vulnerability Management
* SOC Fundamentals
* Security Monitoring
* Detection Engineering
* Alert Correlation
* Incident Investigation
* Secure API Development
* Docker Security
* Network Security
* Security Reporting

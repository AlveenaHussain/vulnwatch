# VulnWatch Architecture

## 1. Overview

VulnWatch is an authorized cybersecurity lab platform that combines:

* Vulnerability Assessment and Penetration Testing (VAPT)
* Security Operations Center (SOC) monitoring
* Alert correlation
* Security investigations
* Browser-triggered target scanning
* Security assessment reporting

The platform connects vulnerability-management data with SOC monitoring data so that security events can be investigated together with vulnerabilities affecting the same asset.

---

# 2. High-Level Architecture

```text
                         ┌──────────────────────┐
                         │      Web Browser      │
                         │   React + Vite UI     │
                         │      :5173            │
                         └──────────┬───────────┘
                                    │
                                    │ HTTP
                                    ▼
                         ┌──────────────────────┐
                         │       FastAPI        │
                         │       Backend        │
                         │        :8000         │
                         └───────┬──────┬───────┘
                                 │      │
                    ┌────────────┘      └──────────────┐
                    │                                  │
                    ▼                                  ▼
          ┌──────────────────┐               ┌──────────────────┐
          │   PostgreSQL     │               │   Kali Scanner   │
          │      :5432       │               │  Target Scan     │
          │                  │               │     Agent        │
          └──────────────────┘               └────────┬─────────┘
                                                       │
                                                       │ Nmap
                                                       ▼
                                             ┌──────────────────┐
                                             │ Authorized Lab   │
                                             │     Target       │
                                             │ 192.168.57.101   │
                                             └──────────────────┘
```

---

# 3. Main Components

## 3.1 Frontend

Technology:

* React
* Vite
* JavaScript / JSX

The frontend provides the user interface for viewing and interacting with VulnWatch.

Major application areas include:

* Dashboard
* Assets
* Services
* Vulnerabilities
* Findings
* Scans
* Security Events
* Alerts
* Correlations
* Investigations
* Target Scan
* Reports

The frontend communicates with the FastAPI backend through HTTP API requests.

---

# 3.2 FastAPI Backend

The FastAPI backend is the central application layer.

Responsibilities include:

* API routing
* Authentication
* Request validation
* Target authorization
* Scan-job management
* Scan-result ingestion
* Vulnerability management
* Security-event management
* Alert management
* Correlation
* Investigation
* Reporting
* Database interaction

The backend runs on:

```text
http://127.0.0.1:8000
```

Interactive API documentation is available at:

```text
http://127.0.0.1:8000/docs
```

---

# 3.3 PostgreSQL

PostgreSQL stores the platform's security data.

The database connects the VAPT and SOC workflows.

Core data areas include:

```text
Scans
Assets
Services
Vulnerabilities
Service Vulnerabilities
Findings
Security Events
Alerts
Correlations
Scan Jobs
```

The database maintains relationships between:

```text
Asset
  ↓
Service
  ↓
Vulnerability
  ↓
Finding
```

and:

```text
Security Event
  ↓
Alert
  ↓
Correlation
  ↓
Investigation
```

---

# 3.4 Kali Linux

Kali Linux is used as the authorized scanning environment.

Current lab scanner:

```text
192.168.57.102
```

The Kali environment performs Nmap-based service discovery and communicates with the VulnWatch backend for browser-triggered target scans.

---

# 3.5 Nmap

Nmap is the primary network/service discovery tool.

It is used to identify:

* Open ports
* Network services
* Service versions
* Target information

Nmap output is generated in XML format so that VulnWatch can process it programmatically.

---

# 3.6 Metasploitable

The project uses Metasploitable 2 as the authorized vulnerable laboratory target.

Current target:

```text
192.168.57.101
```

Hostname:

```text
metasploitable
```

The target is located inside the isolated lab network:

```text
192.168.57.0/24
```

---

# 4. VAPT Architecture

The VAPT workflow starts with Nmap discovery and ends with vulnerability findings.

```text
┌───────────────┐
│     Nmap      │
└───────┬───────┘
        │
        │ XML
        ▼
┌──────────────────────┐
│ Nmap XML Collector   │
└──────────┬───────────┘
           │
           │ POST
           ▼
┌──────────────────────┐
│ FastAPI Scan Import  │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│      PostgreSQL      │
│                      │
│ Scans                │
│ Assets               │
│ Services             │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ Vulnerabilities      │
│ Service Relations    │
│ Findings             │
└──────────────────────┘
```

---

# 5. Nmap XML Import Flow

Nmap produces XML output.

The collector submits the XML to the backend.

The backend:

1. Receives the scan payload.
2. Validates the request.
3. Parses the XML.
4. Extracts target information.
5. Creates or updates the asset.
6. Extracts discovered services.
7. Creates or updates service records.
8. Stores the scan information.

The XML parser uses `defusedxml`.

This provides safer XML parsing than directly using an unsafe XML parser.

---

# 6. Vulnerability Management Flow

Once services are available, vulnerability information can be associated with the discovered services.

The relationship is:

```text
Asset
  │
  └── Service
        │
        └── Service Vulnerability
                  │
                  └── Vulnerability
                           │
                           └── Finding
```

Vulnerability records can contain information such as:

* CVE
* CVSS
* Severity
* CWE
* Description

Findings represent vulnerabilities associated with affected services/assets.

---

# 7. SOC Architecture

The SOC pipeline processes security-event information and converts relevant activity into alerts.

```text
┌──────────────────────┐
│ Authentication Logs  │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ Auth Log Collector   │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ Security Events      │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ Detection Engine     │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ Alerts               │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ Correlation Engine   │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ Investigations       │
└──────────────────────┘
```

---

# 8. Security Event Collection

Authentication log information is converted into structured security events.

The event information can then be evaluated by the detection engine.

The current project includes authentication-related detection logic.

---

# 9. Detection Engine

The detection engine evaluates security events and generates alerts when configured detection conditions are met.

## SSH Brute Force

Current thresholds:

```text
2+ failed authentication events
        ↓
MEDIUM

5+ failed authentication events
        ↓
HIGH

10+ failed authentication events
        ↓
CRITICAL
```

## Port Scan

The port-scan detection logic evaluates unique destination ports.

Current threshold:

```text
10+ unique destination ports
        ↓
HIGH
```

---

# 10. Alert Management

Detected security activity is represented as alerts.

Examples include:

```text
SSH_BRUTE_FORCE
PORT_SCAN
```

The alert system also prevents duplicate OPEN alerts for the same alert combination through a database uniqueness mechanism.

Alert information can then be consumed by the correlation engine.

---

# 11. Correlation Architecture

The correlation engine connects SOC activity with vulnerability-management information.

```text
                 ┌──────────────────┐
                 │      Alert       │
                 └────────┬─────────┘
                          │
                          │ destination IP
                          ▼
                 ┌──────────────────┐
                 │      Asset       │
                 └────────┬─────────┘
                          │
                          ▼
                 ┌──────────────────┐
                 │     Services     │
                 └────────┬─────────┘
                          │
                          ▼
                 ┌──────────────────┐
                 │  Vulnerability   │
                 └────────┬─────────┘
                          │
                          ▼
                 ┌──────────────────┐
                 │     Finding      │
                 └──────────────────┘
```

The main correlation condition is based on the alert destination and affected asset.

The engine identifies vulnerabilities associated with services on that asset.

---

# 12. Correlation Priority

Correlation priority uses the higher severity between:

* The security alert
* The associated vulnerability

For example:

```text
Alert Severity: HIGH
Vulnerability Severity: CRITICAL

        ↓

Correlation Priority: CRITICAL
```

This provides a simple way to highlight situations where active security activity intersects with a serious known vulnerability.

---

# 13. Investigation Architecture

Investigations provide a connected view of the correlated security information.

The investigation relationship can be represented as:

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

This allows the analyst to move from a security alert toward the affected asset and the underlying vulnerability context.

---

# 14. Browser-Triggered Target Scan Architecture

Target scanning uses an asynchronous job architecture.

The browser does not directly execute Nmap.

Instead:

```text
                  Browser
                     │
                     │ Start Scan
                     ▼
              ┌───────────────┐
              │    FastAPI    │
              └───────┬───────┘
                      │
                      │ Create Job
                      ▼
              ┌───────────────┐
              │   scan_jobs   │
              │    PENDING    │
              └───────┬───────┘
                      │
                      │ Poll
                      ▼
              ┌───────────────┐
              │  Kali Agent   │
              └───────┬───────┘
                      │
                      │ Claim Job
                      ▼
              ┌───────────────┐
              │     Nmap      │
              └───────┬───────┘
                      │
                      │ XML
                      ▼
              ┌───────────────┐
              │    FastAPI    │
              └───────┬───────┘
                      │
                      ▼
              ┌───────────────┐
              │  PostgreSQL   │
              └───────┬───────┘
                      │
                      ▼
                  Browser
```

---

# 15. Scan Job Lifecycle

Target scan jobs use states such as:

```text
PENDING
   ↓
RUNNING
   ↓
COMPLETED
```

A failed scan can move to:

```text
FAILED
```

The backend also supports recovery of stale `RUNNING` jobs.

---

# 16. Safe Job Claiming

The target-scan agent claims jobs using database locking.

The implementation uses:

```sql
FOR UPDATE SKIP LOCKED
```

This allows concurrent workers to safely look for available jobs without claiming the same job simultaneously.

---

# 17. Target Validation

Before a target scan is created, the backend validates the requested target.

The current authorized network is:

```text
192.168.57.0/24
```

The validation process helps ensure that the target belongs to the configured authorized lab range.

The project also performs IP resolution and network checks as part of target validation.

---

# 18. Nmap Execution Security

Nmap is launched using an argument list instead of a shell command string.

Conceptually:

```text
nmap
-sV
-oX
<temporary XML file>
<target IP>
```

The process uses:

```text
shell=False
```

and has a timeout.

This reduces the risk of shell-command injection through the target value and prevents scans from running indefinitely.

---

# 19. Target Scan Result Processing

After Nmap completes:

```text
Nmap
  ↓
XML Output
  ↓
POST Result
  ↓
XML Parsing
  ↓
Scan Import
  ↓
Asset Update
  ↓
Service Update
  ↓
Vulnerability / Finding Processing
  ↓
Job COMPLETED
```

The frontend can then retrieve the updated security information.

---

# 20. Reporting Architecture

The reporting layer converts stored security information into an asset-level security assessment report.

```text
Asset
 │
 ├── Services
 │
 ├── Vulnerabilities
 │
 ├── Findings
 │
 ├── Security Events
 │
 ├── Alerts
 │
 └── Correlations
        │
        ▼
   Report Generator
        │
        ▼
 Security Assessment Report
```

The report includes:

* Header
* Executive Summary
* Scope & Methodology
* Risk Summary
* Target & Asset Information
* Open Ports & Services
* Unique CVEs
* Detailed Findings
* Security Monitoring
* Report Summary

---

# 21. Security Architecture

VulnWatch applies security controls across multiple layers.

```text
┌─────────────────────────────────────────────┐
│                  Frontend                   │
│                                             │
│ React / Vite / User Interface               │
└──────────────────────┬──────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────┐
│               API Security                  │
│                                             │
│ API Key Authentication                      │
│ CORS Restrictions                            │
│ Pydantic Validation                          │
└──────────────────────┬──────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────┐
│             Application Security            │
│                                             │
│ Authorized Network Validation                │
│ SSRF Protection                              │
│ Safe Nmap Execution                          │
│ Generic Error Handling                       │
└──────────────────────┬──────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────┐
│             Database Security               │
│                                             │
│ Parameterized SQL                            │
│ Unique Constraints                           │
│ Job Locking                                  │
└──────────────────────┬──────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────┐
│             Container Security              │
│                                             │
│ Non-root Backend Container                   │
│ Docker Isolation                             │
└─────────────────────────────────────────────┘
```

---

# 22. API Authentication

Protected endpoints use an API key.

The key is configured through environment variables rather than hard-coded into application source code.

Comparison uses:

```python
secrets.compare_digest
```

This provides constant-time comparison behavior for the API key check.

---

# 23. Database Security

Database operations use parameterized queries.

Conceptually:

```text
User Input
    ↓
Validated Request
    ↓
Parameterized SQL
    ↓
PostgreSQL
```

The application does not construct SQL statements by directly concatenating untrusted input.

---

# 24. XML Security

Nmap XML is treated as untrusted input.

The application uses:

```text
defusedxml
```

for XML parsing.

The project also applies an XML size limit to reduce the risk of oversized XML input.

---

# 25. Container Security

The backend container:

* Uses a slim Python base image
* Installs only required system packages
* Creates a dedicated application user
* Runs the backend as a non-root user
* Exposes the FastAPI service on port 8000

---

# 26. CORS Security

The backend uses explicit allowed origins.

Untrusted origins are not automatically accepted.

This reduces the possibility of unauthorized browser-based cross-origin access.

---

# 27. Error Handling

The backend uses generic error responses for unexpected failures rather than exposing internal implementation details or tracebacks through normal API responses.

Unknown routes return standard HTTP errors instead of internal exception information.

---

# 28. Complete Data Flow

The major platform flows can be combined into one model:

```text
                         ┌───────────────┐
                         │    Browser    │
                         └───────┬───────┘
                                 │
                                 ▼
                         ┌───────────────┐
                         │    FastAPI    │
                         └───────┬───────┘
                                 │
               ┌─────────────────┼──────────────────┐
               │                 │                  │
               ▼                 ▼                  ▼
          VAPT Flow          SOC Flow         Target Scan
               │                 │                  │
               ▼                 ▼                  ▼
             Nmap           Auth Logs          Scan Jobs
               │                 │                  │
               ▼                 ▼                  ▼
          Scan Import       Detection           Kali Agent
               │                 │                  │
               ▼                 ▼                  ▼
          Assets/Services     Alerts              Nmap
               │                 │                  │
               ▼                 ▼                  ▼
        Vulnerabilities    Correlations        XML Result
               │                 │                  │
               ▼                 ▼                  ▼
           Findings        Investigations       Scan Import
               │                 │                  │
               └─────────────────┼──────────────────┘
                                 │
                                 ▼
                          ┌───────────────┐
                          │  PostgreSQL   │
                          └───────┬───────┘
                                  │
                                  ▼
                          ┌───────────────┐
                          │   Reporting   │
                          └───────────────┘
```

---

# 29. Technology-to-Component Mapping

| Component    | Technology       | Responsibility                   |
| ------------ | ---------------- | -------------------------------- |
| Frontend     | React + Vite     | Security dashboard and UI        |
| API          | FastAPI          | Application/API layer            |
| Database     | PostgreSQL       | Persistent security data         |
| Scanner      | Nmap             | Service discovery                |
| Scanner Host | Kali Linux       | Authorized scanning environment  |
| XML Parser   | defusedxml       | Safe Nmap XML parsing            |
| Containers   | Docker           | Application/database environment |
| Target       | Metasploitable 2 | Authorized vulnerable lab system |

---

# 30. Deployment Model

The current project is primarily designed for local/isolated lab deployment.

```text
Local Host
│
├── Docker
│   ├── PostgreSQL
│   └── FastAPI
│
├── React Development Server
│
└── Kali Linux
    └── Nmap
         │
         ▼
    Metasploitable 2
```

This architecture keeps the vulnerable target inside an authorized lab environment.

---

# 31. Design Principles

The architecture follows several important principles:

### Separation of Responsibilities

Frontend, API, database, scanner, detection, correlation, and reporting responsibilities are separated into distinct components.

### Authorized Scanning

Target scanning is restricted to the configured authorized network.

### Safe Command Execution

Nmap is executed without shell interpretation.

### Structured Security Data

Scan, vulnerability, event, alert, and investigation information is stored in structured database records.

### Asynchronous Scanning

Browser-triggered scanning uses a job queue instead of making the browser wait for a direct Nmap process.

### Security by Validation

Input validation, authentication, network authorization, database constraints, and safe parsing are applied at multiple layers.

---

# 32. Current Architecture Limitations

The current architecture is suitable for an educational and portfolio security lab but is not positioned as a complete enterprise production platform.

Known areas for future improvement include:

* Automated test coverage
* Rate limiting
* Security response headers
* Production-grade migration management
* More scalable background workers
* Real scan-progress reporting
* Expanded detection rules
* More log-source integrations
* Improved NVD synchronization
* Role-based access control
* More comprehensive audit logging

---

# 33. Security Scope

VulnWatch is intended for:

* Cybersecurity education
* VAPT practice
* SOC learning
* Security engineering practice
* Portfolio demonstration
* Authorized vulnerability assessment labs

It should only be used against systems where testing authorization exists.

---

# 34. Summary

VulnWatch combines VAPT and SOC workflows into a single authorized security-lab platform.

The architecture connects:

```text
Nmap
  ↓
Vulnerability Management
  ↓
Security Findings
  ↓
SOC Events
  ↓
Detection
  ↓
Alerts
  ↓
Correlation
  ↓
Investigation
  ↓
Security Reporting
```

The browser-triggered target-scan system adds an asynchronous scanning architecture in which the FastAPI backend manages jobs while a Kali-based agent performs Nmap scanning against an authorized target.

The result is a portfolio-oriented platform demonstrating practical concepts across:

* Vulnerability Assessment
* Network Scanning
* Vulnerability Management
* SOC Monitoring
* Detection Engineering
* Alert Correlation
* Security Investigation
* API Security
* Secure Database Access
* Container Security
* Security Reporting

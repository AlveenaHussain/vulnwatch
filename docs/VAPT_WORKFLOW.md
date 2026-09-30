# VulnWatch VAPT Workflow

## 1. Overview

VulnWatch implements a structured Vulnerability Assessment and Penetration Testing (VAPT) workflow inside an authorized cybersecurity lab.

The VAPT workflow starts with network and service discovery using Nmap and continues through scan ingestion, asset and service identification, vulnerability management, findings, and security reporting.

The overall flow is:

```text
Authorized Target
       ↓
     Nmap
       ↓
   Nmap XML
       ↓
  Scan Import
       ↓
     Asset
       ↓
    Services
       ↓
 Vulnerabilities
       ↓
    Findings
       ↓
 Risk / Severity
       ↓
 Security Report
```

> **Safety:** This workflow is intended only for systems that are owned by the user or explicitly authorized for security testing.

---

# 2. VAPT Architecture

The VAPT workflow connects the scanning environment with the VulnWatch backend and database.

```text
┌──────────────────┐
│  Authorized Lab  │
│      Target      │
│ 192.168.57.101   │
└────────┬─────────┘
         │
         │ Nmap
         ▼
┌──────────────────┐
│   Kali Linux     │
│ 192.168.57.102   │
└────────┬─────────┘
         │
         │ XML
         ▼
┌──────────────────┐
│ VulnWatch API    │
│    FastAPI       │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│   Scan Import    │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│   PostgreSQL     │
└──────────────────┘
```

---

# 3. Step 1 — Define the Authorized Target

Before scanning, the target must belong to the authorized lab environment.

Current VulnWatch lab:

```text
Authorized Network:
192.168.57.0/24

Target:
192.168.57.101

Scanner:
192.168.57.102
```

The target used for project validation is Metasploitable 2.

The target is intentionally vulnerable and is used only as an isolated security-testing target.

---

# 4. Step 2 — Network and Service Discovery

Nmap is used to discover network services on the authorized target.

The project uses service/version detection.

Conceptually:

```bash
nmap -sV <target-ip>
```

For VulnWatch result ingestion, Nmap output is generated in XML format.

Conceptually:

```bash
nmap -sV -oX <output-file> <target-ip>
```

The XML output allows the application to process the scan programmatically.

---

# 5. Step 3 — Nmap XML

The Nmap scan generates structured XML data.

The XML can contain information such as:

* Target information
* Host state
* Port numbers
* Protocols
* Port states
* Service names
* Service versions
* Product information
* CPE information when available

Example conceptual structure:

```text
Nmap
 │
 └── Host
      │
      ├── Address
      │
      └── Ports
           │
           ├── Port
           │    ├── Protocol
           │    ├── State
           │    └── Service
           │
           └── Port
                ├── Protocol
                ├── State
                └── Service
```

---

# 6. Step 4 — Scan Import

The Nmap XML result is submitted to the VulnWatch backend.

The scan-import workflow processes the XML and stores the discovered information in PostgreSQL.

The major flow is:

```text
Nmap XML
   ↓
POST /api/v1/scans/import
   ↓
XML Validation / Parsing
   ↓
Asset Processing
   ↓
Service Processing
   ↓
Scan Record
```

The XML parser uses `defusedxml`.

---

# 7. Step 5 — Asset Creation / Update

After processing the Nmap XML, VulnWatch identifies the target asset.

The asset contains information such as:

* IP address
* Host information
* Scan relationship

If the asset already exists, the scan can update the existing asset information rather than creating an unrelated duplicate asset.

The current lab target is:

```text
IP:
192.168.57.101

Hostname:
metasploitable
```

---

# 8. Step 6 — Service Discovery

The discovered ports and services are stored against the asset.

For example, a service relationship can conceptually be represented as:

```text
Asset
 │
 ├── Port 21
 │    └── FTP
 │
 ├── Port 22
 │    └── SSH
 │
 ├── Port 80
 │    └── HTTP
 │
 └── Other discovered services
```

During the documented lab validation, the Metasploitable target produced **23 discovered services**.

---

# 9. Step 7 — Vulnerability Management

VulnWatch maintains vulnerability information associated with discovered services.

Vulnerability information can include:

* CVE
* CVSS
* Severity
* CWE
* Description

The relationship is:

```text
Asset
   ↓
Service
   ↓
Service Vulnerability
   ↓
Vulnerability
```

This separates the actual vulnerability record from the specific service affected by that vulnerability.

---

# 10. Step 8 — CVE Information

A vulnerability can be identified through a CVE.

The documented lab contains:

```text
CVE:
CVE-2011-2523

Service:
vsftpd 2.3.4

CVSS:
10.0

Severity:
CRITICAL

CWE:
CWE-78
```

This vulnerability information is part of the authorized Metasploitable lab dataset.

---

# 11. Step 9 — Findings

A finding represents the vulnerability as it applies to an affected service/asset.

The relationship can be represented as:

```text
Vulnerability
      ↓
Affected Service
      ↓
Affected Asset
      ↓
Finding
```

The finding provides a practical security-management record rather than only storing a standalone CVE.

---

# 12. Step 10 — Severity and Risk

Vulnerability severity is stored using the available vulnerability information.

The documented project data includes severity classifications such as:

```text
LOW
MEDIUM
HIGH
CRITICAL
```

CVSS information can be used as part of vulnerability-risk context.

For example:

```text
CVSS 10.0
   ↓
CRITICAL
```

VulnWatch uses this information when presenting vulnerability and finding information.

---

# 13. Step 11 — Finding Status

Findings can have a lifecycle status.

The documented lab validation included findings with:

```text
RESOLVED
```

This allows the platform to distinguish findings that have been addressed from findings that still require attention.

---

# 14. Step 12 — Review the VAPT Results

After the scan and vulnerability information have been processed, the analyst can review:

### Assets

Which systems were discovered?

### Services

Which ports and services are exposed?

### Vulnerabilities

Which known vulnerabilities are associated with the services?

### Findings

Which vulnerabilities affect which assets/services?

### Severity

How severe are the identified vulnerabilities?

---

# 15. VAPT Data Relationship

The complete vulnerability-management relationship is:

```text
                 ┌─────────────┐
                 │    Scan     │
                 └──────┬──────┘
                        │
                        ▼
                 ┌─────────────┐
                 │    Asset    │
                 └──────┬──────┘
                        │
                        ▼
                 ┌─────────────┐
                 │   Service   │
                 └──────┬──────┘
                        │
                        ▼
             ┌─────────────────────┐
             │ Service Vulnerability│
             └──────────┬──────────┘
                        │
                        ▼
                 ┌─────────────┐
                 │ Vulnerability│
                 └──────┬──────┘
                        │
                        ▼
                 ┌─────────────┐
                 │   Finding   │
                 └─────────────┘
```

---

# 16. VAPT and SOC Connection

One of the main features of VulnWatch is that VAPT data does not remain isolated from SOC data.

The VAPT side provides:

```text
Asset
Service
Vulnerability
Finding
```

The SOC side provides:

```text
Security Event
Alert
```

The correlation layer connects them:

```text
Vulnerability
      +
Security Alert
      ↓
Correlation
      ↓
Investigation
```

This allows the platform to provide security context beyond a simple vulnerability list.

---

# 17. Example Security Scenario

Consider the authorized Metasploitable target:

```text
192.168.57.101
```

A vulnerability is associated with one of its services.

Later, a SOC alert identifies suspicious activity involving the same asset.

VulnWatch can connect the two pieces of information:

```text
Known Vulnerability
        +
Security Alert
        ↓
   Same Asset
        ↓
    Correlation
        ↓
   Investigation
```

The purpose is to help an analyst understand whether observed security activity is occurring against an asset that also has known weaknesses.

---

# 18. VAPT Reporting

After reviewing the assessment data, VulnWatch can generate an asset-level security assessment report.

The reporting workflow is:

```text
Scan
 ↓
Asset
 ↓
Services
 ↓
Vulnerabilities
 ↓
Findings
 ↓
SOC Information
 ↓
Report Generator
 ↓
Security Assessment Report
```

The report can include:

* Executive summary
* Scope and methodology
* Risk summary
* Target information
* Open ports and services
* Unique CVEs
* Detailed findings
* Security monitoring information
* Report summary

---

# 19. Evidence Handling

The reporting workflow is designed to use available project data rather than inventing evidence.

Evidence can be derived from:

* Nmap results
* Service information
* CPE information
* CVE information
* Vulnerability descriptions
* Stored security events
* Alerts
* Correlations

The system does not intentionally fabricate:

* Screenshots
* HTTP requests
* Exploit output
* Logs
* Evidence that was never collected

---

# 20. NVD Integration

The project contains an NVD collector under:

```text
collectors/nvd/
```

The collector was intended to support vulnerability/CVE enrichment.

However, the current NVD integration was sidelined because the attempted `/virtualMatchString` integration returned HTTP 404.

Therefore, the current project should not be described as having a fully operational automatic NVD synchronization pipeline.

Current vulnerability data can be imported manually.

---

# 21. Security Controls in the VAPT Workflow

Several controls protect the VAPT workflow.

## Authorized Network Validation

The target must belong to the configured authorized network.

```text
192.168.57.0/24
```

## API Authentication

Protected API endpoints use API-key authentication.

## Input Validation

API requests are validated before processing.

## Secure XML Parsing

Nmap XML is parsed using `defusedxml`.

## Parameterized SQL

Database operations use parameterized SQL.

## Safe Process Execution

Nmap is executed with:

```text
shell=False
```

## Scan Timeout

Nmap execution has a configured timeout.

## Duplicate Scan Protection

Active duplicate target scans are prevented.

---

# 22. VAPT Validation Performed

The project was manually validated during development.

The documented validation included:

| Validation                | Result               |
| ------------------------- | -------------------- |
| Missing API key           | 401 rejected         |
| Incorrect API key         | 401 rejected         |
| Correct API key           | Accepted             |
| Invalid request body      | 422 rejected         |
| SQL-injection-style input | Handled              |
| Untrusted CORS origin     | Rejected             |
| Duplicate target scan     | Prevented            |
| Target scan               | Completed end-to-end |
| Scan import               | Verified             |
| Security report           | Verified             |

These are manual project-validation results and should not be presented as an automated test suite.

---

# 23. End-to-End VAPT Example

The documented lab flow can be summarized as:

```text
Authorized Metasploitable Target
          │
          ▼
       Nmap Scan
          │
          ▼
      Nmap XML
          │
          ▼
    VulnWatch Import
          │
          ▼
        Asset
          │
          ▼
      23 Services
          │
          ▼
 Vulnerability Association
          │
          ▼
      CVE / CVSS
          │
          ▼
       Findings
          │
          ▼
   Risk / Severity Review
          │
          ▼
    Security Report
```

---

# 24. Analyst Perspective

From a VAPT analyst perspective, the workflow answers these questions:

### 1. What is the target?

The asset inventory identifies the system.

### 2. What is exposed?

The service inventory identifies open ports and services.

### 3. What vulnerabilities are associated with those services?

The vulnerability-management layer provides CVE/CVSS/CWE information.

### 4. What needs attention?

Findings provide affected asset/service context and status.

### 5. What evidence is available?

Nmap and stored vulnerability/security data provide the available evidence.

### 6. What should be reported?

The reporting layer converts the assessment data into a structured security assessment report.

---

# 25. VAPT Workflow Summary

The VulnWatch VAPT workflow is:

```text
        AUTHORIZED TARGET
               │
               ▼
          NMAP DISCOVERY
               │
               ▼
            XML DATA
               │
               ▼
          SCAN IMPORT
               │
               ▼
             ASSET
               │
               ▼
            SERVICES
               │
               ▼
         VULNERABILITIES
               │
               ▼
            FINDINGS
               │
               ▼
        SEVERITY / RISK
               │
               ▼
       SECURITY REPORT
```

The workflow can then connect with SOC monitoring:

```text
VAPT DATA ───────────────┐
                         │
                         ▼
                    CORRELATION
                         ▲
                         │
SOC EVENTS → ALERTS ─────┘
                         │
                         ▼
                    INVESTIGATION
```

This combined workflow is the core concept behind VulnWatch's VAPT + SOC architecture.

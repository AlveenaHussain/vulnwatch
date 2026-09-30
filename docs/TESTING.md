# VulnWatch Testing

## 1. Overview

VulnWatch was validated through manual functional, security, VAPT, SOC, and end-to-end testing during development.

The project does not currently contain a formal automated `pytest` test suite.

Therefore, the results in this document should be described as **manual validation results**, not as an automated test report.

---

# 2. Testing Scope

The testing covered the following major areas:

```text id="tst01"
Backend API
     ↓
Authentication
     ↓
Input Validation
     ↓
Database Security
     ↓
VAPT Workflow
     ↓
SOC Workflow
     ↓
Target Scan
     ↓
Correlation
     ↓
Reporting
```

The testing was performed against the authorized VulnWatch laboratory environment.

---

# 3. Test Environment

The documented lab environment includes:

```text id="tst02"
Operating System:
Windows

Virtualization:
WSL2

Container Platform:
Docker Desktop

Backend:
FastAPI

Database:
PostgreSQL

Scanner:
Kali Linux

Target:
Metasploitable 2

Lab Network:
192.168.57.0/24

Target:
192.168.57.101

Scanner:
192.168.57.102
```

---

# 4. Testing Approach

Testing was performed using a combination of:

* Manual API testing
* Swagger UI testing
* Browser-based frontend testing
* Nmap validation
* Database validation
* Target-scan end-to-end testing
* Security negative testing
* VAPT workflow validation
* SOC workflow validation
* Reporting validation

The objective was to verify both expected functionality and important security controls.

---

# 5. Authentication Testing

## Test 1 — Missing API Key

### Objective

Verify that a protected endpoint rejects requests when the API key is missing.

### Test

Send a request to a protected endpoint without:

```text id="tst03"
X-API-Key
```

### Expected Result

```text
401 Unauthorized
```

### Result

**PASS**

The protected endpoint rejected the request.

---

# 6. Wrong API Key Testing

## Test 2 — Invalid API Key

### Objective

Verify that an incorrect API key cannot access protected endpoints.

### Test

Send a request with an incorrect API key.

### Expected Result

```text
401 Unauthorized
```

### Result

**PASS**

The request was rejected.

---

# 7. Correct API Key Testing

## Test 3 — Valid API Key

### Objective

Verify that a valid API key allows access to the protected endpoint.

### Test

Send the correct configured API key using:

```text
X-API-Key
```

### Expected Result

The endpoint processes the request normally.

### Result

**PASS**

The authenticated request was accepted.

---

# 8. Input Validation Testing

## Test 4 — Invalid Request Body

### Objective

Verify that malformed or invalid API input is rejected.

### Test

Submit an invalid request body to an API endpoint requiring structured input.

### Expected Result

```text
422 Unprocessable Entity
```

### Result

**PASS**

FastAPI/Pydantic validation rejected invalid input.

---

# 9. SQL Injection-Style Input Testing

## Test 5 — SQL Injection-Style Input

### Objective

Verify that user-controlled input does not become executable SQL.

### Test

A SQL-injection-style input was supplied during manual validation.

### Expected Behavior

The input should be handled as data rather than being interpreted as SQL syntax.

### Result

**PASS**

The application handled the input through the parameterized database layer without producing an SQL injection result.

---

# 10. CORS Testing

## Test 6 — Untrusted Origin

### Objective

Verify that an untrusted browser origin is not automatically accepted.

### Test

Send a request using an origin that is not included in the configured CORS policy.

### Expected Result

The untrusted origin should not be allowed by the backend CORS policy.

### Result

**PASS**

The untrusted CORS origin was rejected.

---

# 11. Unknown Endpoint Testing

## Test 7 — Invalid Route

### Objective

Verify that an unknown API endpoint returns a normal HTTP error rather than exposing internal application details.

### Test

Request a route that does not exist.

### Expected Result

```text
404 Not Found
```

### Result

**PASS**

The application returned `404` without exposing a traceback.

---

# 12. API Authentication Test Matrix

The authentication validation can be summarized as:

| Test                  | Expected | Result |
| --------------------- | -------- | ------ |
| Missing API key       | 401      | PASS   |
| Wrong API key         | 401      | PASS   |
| Correct API key       | Accepted | PASS   |
| Invalid request body  | 422      | PASS   |
| Unknown endpoint      | 404      | PASS   |
| Untrusted CORS origin | Rejected | PASS   |

---

# 13. VAPT Testing

The VAPT workflow was validated using the authorized Metasploitable laboratory target.

The workflow tested:

```text id="tst04"
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
Reporting
```

---

# 14. Nmap Scan Validation

## Test 8 — Nmap Discovery

### Objective

Verify that the authorized target can be scanned from the Kali environment.

### Target

```text id="tst05"
192.168.57.101
```

### Scanner

```text
192.168.57.102
```

### Result

**PASS**

The authorized target was successfully scanned and the resulting data was available for ingestion.

---

# 15. Nmap XML Import Testing

## Test 9 — XML Import

### Objective

Verify that Nmap XML can be imported into VulnWatch.

### Workflow

```text id="tst06"
Nmap XML
   ↓
Scan Import API
   ↓
XML Parsing
   ↓
Asset
   ↓
Services
```

### Result

**PASS**

The Nmap XML import workflow was validated.

---

# 16. Asset Validation

## Test 10 — Asset Creation / Update

### Objective

Verify that scan results create or update the corresponding asset.

### Result

**PASS**

The documented lab target was represented as an asset:

```text
192.168.57.101
```

with hostname information associated with the Metasploitable system.

---

# 17. Service Discovery Validation

## Test 11 — Service Import

### Objective

Verify that discovered ports and services are stored against the asset.

### Result

**PASS**

The documented target-scan validation identified:

```text
23 services
```

---

# 18. Vulnerability Validation

## Test 12 — Vulnerability Association

### Objective

Verify that vulnerability information can be associated with discovered services.

### Documented Vulnerability

```text id="tst07"
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

### Result

**PASS**

The documented vulnerability information was available in the VulnWatch lab data.

---

# 19. Findings Validation

## Test 13 — Findings

### Objective

Verify that vulnerabilities can be represented as findings associated with the affected asset/service context.

### Result

**PASS**

The documented lab validation contained findings associated with the vulnerability data.

The recorded finding status included:

```text
RESOLVED
```

---

# 20. Target Scan Testing

## Test 14 — Browser-Triggered Target Scan

### Objective

Verify the complete browser-triggered scanning workflow.

### Workflow

```text id="tst08"
Frontend
   ↓
Target Scan API
   ↓
Target Validation
   ↓
Scan Job
   ↓
Kali Agent
   ↓
Nmap
   ↓
XML
   ↓
Import
   ↓
Completed Job
```

### Result

**PASS**

The documented target-scan workflow completed end-to-end.

---

# 21. Duplicate Target Scan Testing

## Test 15 — Duplicate Active Scan

### Objective

Verify that duplicate active scans for the same target are prevented.

### Test

Attempt to create another scan while an active scan for the same target already exists.

### Expected Behavior

The duplicate active scan should be rejected rather than creating unnecessary concurrent work.

### Result

**PASS**

Duplicate target-scan prevention was validated.

---

# 22. Stale Scan Recovery Testing

## Test 16 — Stale RUNNING Job

### Objective

Verify that a scan job does not remain permanently stuck in `RUNNING`.

### Documented Recovery

The project uses a default stale-job recovery threshold of:

```text
15 minutes
```

### Result

**PASS**

Stale `RUNNING` job recovery was implemented and validated during development.

---

# 23. Race-Safe Job Claiming

## Test 17 — Job Claiming

### Objective

Verify that scanner workers can safely claim pending jobs.

### Security Mechanism

The database workflow uses:

```text
FOR UPDATE SKIP LOCKED
```

### Purpose

This prevents multiple workers from unnecessarily processing the same pending job.

### Result

**PASS**

The race-safe job-claiming mechanism was implemented and validated as part of the target-scan architecture.

---

# 24. SOC Testing

The SOC workflow was validated using the documented security-event and detection pipeline.

The workflow is:

```text id="tst09"
Security Log
     ↓
Security Event
     ↓
Detection Engine
     ↓
Alert
     ↓
Correlation
     ↓
Investigation
```

---

# 25. SSH Brute-Force Detection Testing

## Test 18 — SSH Brute Force

### Objective

Verify that repeated SSH authentication failures can trigger the detection engine.

### Documented Thresholds

| Failed Attempts | Severity |
| --------------: | -------- |
|              2+ | MEDIUM   |
|              5+ | HIGH     |
|             10+ | CRITICAL |

### Result

**PASS**

SSH brute-force detection was validated as part of the SOC workflow.

A documented lab alert was generated with:

```text
Alert Type:
SSH_BRUTE_FORCE

Severity:
HIGH
```

---

# 26. Port Scan Detection Testing

## Test 19 — Port Scan

### Objective

Verify that multiple destination ports from a source can trigger the port-scan detection rule.

### Documented Rule

```text
10 or more unique destination ports
                ↓
              HIGH
```

### Result

**PASS**

Port-scan detection was validated.

A documented lab alert was generated with:

```text
Alert Type:
PORT_SCAN

Severity:
HIGH
```

---

# 27. Alert Duplicate Prevention

## Test 20 — Duplicate Open Alert

### Objective

Verify that repeated detections do not unnecessarily create duplicate open alerts for the same condition.

### Database Protection

The documented partial unique index uses:

```text
alert_type
source_ip
destination_ip
```

for open alerts.

### Result

**PASS**

Duplicate-open-alert protection was implemented.

---

# 28. Correlation Testing

## Test 21 — Alert and Vulnerability Correlation

### Objective

Verify that a SOC alert can be correlated with vulnerability information associated with the same asset.

### Workflow

```text id="tst10"
Alert
  ↓
Destination IP
  ↓
Asset
  ↓
Service Vulnerability
  ↓
Correlation
```

### Result

**PASS**

The documented lab validation produced:

```text
2 correlations
```

---

# 29. Correlation Priority Testing

## Test 22 — Severity Priority

### Objective

Verify that correlation priority uses the higher severity between the alert and vulnerability.

### Example

```text id="tst11"
Vulnerability = CRITICAL
Alert = HIGH

Correlation Priority = CRITICAL
```

### Result

**PASS**

The documented correlation logic uses the higher severity.

---

# 30. Investigation Testing

## Test 23 — Investigation Context

### Objective

Verify that correlated security information can be traced through the investigation workflow.

### Investigation Path

```text id="tst12"
Alert
 ↓
Correlation
 ↓
Asset
 ↓
Services
 ↓
Service Vulnerability
 ↓
Vulnerability
 ↓
Finding
 ↓
Security Events
```

### Result

**PASS**

The investigation workflow was implemented and validated as part of the SOC functionality.

---

# 31. Reporting Testing

## Test 24 — Security Report

### Objective

Verify that an asset-level security report can be generated from stored VAPT and SOC data.

### Workflow

```text id="tst13"
Asset
 ↓
Services
 ↓
Vulnerabilities
 ↓
Findings
 ↓
Security Monitoring
 ↓
Report
```

### Result

**PASS**

The report endpoint was validated and returned structured report information.

---

# 32. CVE Deduplication Testing

## Test 25 — CVE Deduplication

### Objective

Verify that repeated references to the same CVE are not unnecessarily represented as separate unique vulnerability entries in the report.

### Result

**PASS**

The report-generation workflow applies CVE deduplication.

---

# 33. Evidence Validation

## Test 26 — Evidence Integrity

### Objective

Verify that reports use available project data rather than fabricated security evidence.

### Evidence Sources

The reporting workflow can derive evidence from:

* Nmap results
* Service information
* CPE information
* CVE data
* Vulnerability descriptions
* Security events
* Alerts
* Correlations

### Result

**PASS**

The report workflow was designed around available stored/project data.

The project does not intentionally fabricate:

* Screenshots
* HTTP requests
* Exploit output
* Logs
* Evidence that was never collected

---

# 34. Container Security Testing

## Test 27 — Backend Container User

### Objective

Verify that the backend container does not run the application as root.

### Result

**PASS**

The backend Docker image uses a non-root application user.

---

# 35. Error Handling Testing

## Test 28 — Internal Error Exposure

### Objective

Verify that invalid routes do not expose application tracebacks.

### Result

**PASS**

Unknown routes returned normal HTTP errors without exposing a traceback.

---

# 36. XML Security Testing

## Test 29 — Secure XML Parser

### Objective

Verify that Nmap XML processing uses a hardened XML parser.

### Implementation

```text
defusedxml
```

### Result

**PASS**

The project uses `defusedxml` for XML parsing.

---

# 37. Nmap Process Security Testing

## Test 30 — Shell Execution

### Objective

Verify that Nmap is not executed through shell interpretation.

### Implementation

```text
shell=False
```

### Result

**PASS**

The target-scan workflow uses `shell=False`.

---

# 38. Testing Summary

The major manually validated areas are:

| Area                               | Result |
| ---------------------------------- | ------ |
| API authentication                 | PASS   |
| Input validation                   | PASS   |
| SQL-injection-style input handling | PASS   |
| CORS restriction                   | PASS   |
| Unknown endpoint handling          | PASS   |
| Nmap scanning                      | PASS   |
| XML import                         | PASS   |
| Asset processing                   | PASS   |
| Service processing                 | PASS   |
| Vulnerability association          | PASS   |
| Findings                           | PASS   |
| Target scan                        | PASS   |
| Duplicate scan prevention          | PASS   |
| Stale job recovery                 | PASS   |
| Race-safe job claiming             | PASS   |
| SSH brute-force detection          | PASS   |
| Port-scan detection                | PASS   |
| Alert handling                     | PASS   |
| Alert duplicate prevention         | PASS   |
| Correlation                        | PASS   |
| Investigation                      | PASS   |
| Reporting                          | PASS   |
| CVE deduplication                  | PASS   |
| Non-root Docker                    | PASS   |
| Secure XML parsing                 | PASS   |
| Safe Nmap execution                | PASS   |

---

# 39. What This Testing Does Not Claim

The current validation should **not** be interpreted as:

* A formal penetration-test certification
* A production security audit
* An automated regression-test suite
* A complete vulnerability assessment of the VulnWatch application itself
* A guarantee that no vulnerabilities exist
* A formal compliance assessment

The results document the functionality and security controls manually validated during project development.

---

# 40. Automated Testing Status

The current project does not contain a formal automated `pytest` test suite.

Therefore:

```text id="tst14"
Manual Validation
        ≠
Automated Test Suite
```

Future development can add automated tests for:

* API authentication
* Request validation
* Database operations
* Detection rules
* Correlation rules
* Target-scan job lifecycle
* Report generation
* Security regressions

---

# 41. Recommended Future Test Structure

A future automated test structure could be:

```text id="tst15"
tests/
├── test_auth.py
├── test_assets.py
├── test_scans.py
├── test_vulnerabilities.py
├── test_findings.py
├── test_security_events.py
├── test_alerts.py
├── test_correlations.py
├── test_target_scan.py
└── test_reporting.py
```

These tests are a future improvement and are not currently part of the project.

---

# 42. Final Testing Status

VulnWatch has undergone manual validation across its major VAPT, SOC, security, target-scanning, correlation, and reporting workflows.

The documented results demonstrate that the main laboratory workflows were exercised successfully.

The next maturity step would be converting important manual checks into repeatable automated tests.

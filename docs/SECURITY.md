# VulnWatch Security

## 1. Overview

VulnWatch is an authorized cybersecurity lab and portfolio project combining Vulnerability Assessment and Penetration Testing (VAPT) with Security Operations Center (SOC) workflows.

Because the platform performs network scanning and processes security-related data, security controls are applied at multiple layers:

```text
API
 ↓
Input Validation
 ↓
Authorization
 ↓
Network Validation
 ↓
Safe Process Execution
 ↓
Secure XML Parsing
 ↓
Parameterized Database Queries
 ↓
Container Security
```

The controls documented in this file describe the security mechanisms implemented in the current project.

---

# 2. Security Scope

VulnWatch is designed for:

* Authorized cybersecurity laboratories
* Systems owned by the user
* Explicitly authorized penetration-testing environments
* Educational security exercises
* Portfolio demonstrations

The project must not be used to scan or test systems without authorization.

The documented lab environment uses:

```text
Authorized Network:
192.168.57.0/24

Target:
192.168.57.101

Scanner:
192.168.57.102
```

---

# 3. API Authentication

Protected API endpoints use an API key.

The API key is configured through an environment variable rather than being hardcoded into application source code.

Example configuration:

```text id="6g7s9w"
VULNWATCH_API_KEY=<secret-value>
```

Clients send the key using:

```text id="t9k6n3"
X-API-Key
```

The backend verifies the supplied key before allowing protected operations.

---

# 4. API Key Comparison

The backend uses constant-time comparison for API-key verification.

The purpose is to avoid directly comparing secrets in a way that unnecessarily exposes timing differences.

Conceptually:

```text id="8y2v4c"
Client API Key
      ↓
Authentication Dependency
      ↓
Constant-Time Comparison
      ↓
Valid?
 ┌────┴────┐
Yes        No
 │          │
 ▼          ▼
Allow      401
```

---

# 5. Fail-Closed Authentication

The authentication mechanism is designed to fail closed.

If the required API key configuration is missing, protected operations should not become publicly accessible simply because authentication configuration is incomplete.

The expected security behavior is:

```text id="r0m7f1"
API Key Configured
       ↓
Validate Request
       ↓
Allow / Reject
```

and not:

```text id="6b9w2k"
API Key Missing
       ↓
Allow Request
```

---

# 6. Input Validation

API requests are validated before being processed.

VulnWatch uses Pydantic-based request schemas for structured API input.

Invalid request data is rejected with a validation response.

During manual validation:

```text id="2f8s1k"
Invalid Request Body
        ↓
Validation
        ↓
HTTP 422
```

This reduces the chance of malformed input reaching deeper application logic.

---

# 7. SQL Injection Protection

VulnWatch uses parameterized SQL queries for database operations.

User-controlled values are passed separately from SQL statements instead of being concatenated directly into SQL strings.

Conceptually:

```text id="1d3z5q"
User Input
    ↓
Parameterized Query
    ↓
PostgreSQL
```

This prevents the input from being interpreted as part of the SQL command structure.

A SQL-injection-style input was included in the project's manual security validation and was handled without producing an SQL injection result.

---

# 8. Database Constraints

Database constraints provide an additional layer of data integrity.

Important documented constraints include:

```text id="7p4x9a"
Assets
 └── Unique IP address

Services
 └── Unique asset + port + protocol

Vulnerabilities
 └── Unique CVE ID

Service Vulnerabilities
 └── Unique service + vulnerability

Correlations
 └── Unique alert + service vulnerability
```

Open alerts also use a partial unique index to reduce duplicate active alerts.

---

# 9. XML Security

Nmap scan results are imported as XML.

XML parsing is performed using `defusedxml`.

This provides protection against common XML parser-related attacks.

The workflow is:

```text id="8z6h2m"
Nmap XML
   ↓
Secure XML Parser
   ↓
Validated Data
   ↓
Database
```

The project also applies a maximum XML payload size to limit excessively large XML input.

The documented maximum is:

```text id="v3p1n8"
5 MB
```

---

# 10. Authorized Network Enforcement

Target scanning is restricted to the configured authorized network.

The project uses:

```text id="k2q7s4"
VULNWATCH_AUTHORIZED_NETWORK
```

The target IP is validated before a scan job is accepted.

The intended flow is:

```text id="m8c2r6"
Requested Target
      ↓
IP Validation
      ↓
Authorized Network Check
      ↓
Allowed?
 ┌────┴────┐
Yes        No
 │          │
 ▼          ▼
Scan       Reject
```

This is a key safety control for the browser-triggered scanning feature.

---

# 11. SSRF Protection

The target-scan workflow validates the target IP before initiating network activity.

The validation is intended to prevent arbitrary external or unauthorized destinations from being supplied to the scanner.

The security flow is:

```text id="w6j1p9"
User-Supplied IP
       ↓
IP Resolution / Validation
       ↓
Authorized Range Check
       ↓
Nmap
```

Only targets permitted by the configured authorization policy should reach the scanning stage.

---

# 12. Safe Nmap Execution

Nmap is executed through `subprocess.run`.

The project uses:

```text id="q9n4s7"
shell=False
```

This is important because the target IP is passed as a process argument rather than being interpreted through a shell command string.

Conceptually:

```text id="u4d8c2"
Validated Target IP
       ↓
subprocess.run(...)
       ↓
Nmap
```

The application does not intentionally construct a shell command from untrusted target input.

---

# 13. Nmap Timeout

Nmap execution has a timeout.

The documented target-scan timeout is:

```text id="c5v8m2"
180 seconds
```

The purpose is to prevent a scan process from remaining active indefinitely.

Conceptually:

```text id="f3n7q1"
Start Nmap
    ↓
Maximum Runtime
    ↓
Completed?
 ┌────┴────┐
Yes       Timeout
 │           │
 ▼           ▼
Result     Failure
```

---

# 14. Temporary Scan Output

Target-scan results are generated as XML and processed by the backend workflow.

The target-scan architecture uses temporary output handling before the result is imported.

This keeps the Nmap result-processing workflow separate from the execution step.

---

# 15. Duplicate Scan Protection

VulnWatch prevents duplicate active target scans for the same target.

The workflow checks for an existing active scan job before creating another one.

Conceptually:

```text id="p1q8s3"
New Scan Request
       ↓
Existing Active Job?
    ┌────┴────┐
   Yes        No
    │          │
    ▼          ▼
 Reject      Create Job
```

This reduces duplicate scanner execution and unnecessary resource consumption.

---

# 16. Scan Job States

Target scans are managed through a job lifecycle.

The documented states are:

```text id="e8t4k2"
PENDING
RUNNING
COMPLETED
FAILED
```

The lifecycle is:

```text id="m4s7d1"
PENDING
   ↓
RUNNING
   ↓
COMPLETED
```

If the scan fails:

```text id="r5w9c3"
PENDING
   ↓
RUNNING
   ↓
FAILED
```

---

# 17. Race-Safe Job Claiming

The Kali target-scan agent claims jobs from the backend.

The documented database workflow uses:

```text id="j7k2v6"
FOR UPDATE SKIP LOCKED
```

This allows workers to claim available jobs without multiple workers simultaneously processing the same job.

Conceptually:

```text id="q1s8h4"
Pending Jobs
     ↓
Database Lock
     ↓
Worker Claims Job
     ↓
RUNNING
```

This is especially useful if multiple scan workers are introduced.

---

# 18. Stale Job Recovery

VulnWatch includes recovery handling for stale `RUNNING` jobs.

If a scan remains in the running state beyond the configured recovery threshold, it can be treated as stale.

The documented default stale threshold is:

```text id="v6n3t9"
15 minutes
```

The purpose is to prevent a failed worker or interrupted process from permanently leaving a scan job in `RUNNING`.

---

# 19. CORS Protection

The backend uses explicit CORS configuration.

Untrusted origins are not automatically accepted.

The project manually validated that an untrusted CORS origin was rejected.

The security model is:

```text id="n4k7x2"
Browser Origin
      ↓
CORS Policy
      ↓
Allowed?
 ┌────┴────┐
Yes        No
 │          │
 ▼          ▼
Allow      Reject
```

---

# 20. Error Handling

The API is designed to avoid unnecessarily exposing internal implementation details.

Errors are returned using appropriate HTTP responses rather than exposing stack traces or internal debugging information to normal API consumers.

The project also manually validated an unknown endpoint and confirmed that it returned a normal `404` response without exposing a traceback.

---

# 21. Frontend Security

The frontend communicates with the FastAPI backend using HTTP API requests.

The frontend provides authentication-related UI elements for protected workflows where required.

The backend remains responsible for enforcing authorization.

Client-side controls should not be considered a replacement for backend authentication.

The security principle is:

```text id="x8c4p6"
Frontend
   ↓
API Request
   ↓
Backend Authentication
   ↓
Authorization Decision
```

---

# 22. Environment Secrets

Sensitive configuration should be stored through environment variables.

The project uses:

```text id="d2r7m9"
.env
.env.example
```

The `.env` file is intended for local secret configuration.

`.env.example` provides a template without exposing actual secret values.

Secret values should never be committed to source control.

---

# 23. Git Protection for Secrets

The project's `.gitignore` is configured to prevent local environment files from being committed.

The important principle is:

```text id="y6k1v8"
Local .env
   ↓
.gitignore
   ↓
Not committed
```

If a secret is accidentally exposed, it should be rotated rather than relying only on removing it from the latest source tree.

---

# 24. Docker Container Security

The backend Docker image uses a Python slim base image and installs the required runtime dependencies.

The application runs using a non-root user.

Conceptually:

```text id="p8m3s5"
Docker Container
      ↓
Non-Root App User
      ↓
FastAPI
```

Running the application as a non-root user reduces the impact of a potential application-level compromise.

---

# 25. PostgreSQL Isolation

PostgreSQL runs as a separate Docker service.

The architecture is:

```text id="k3v7n1"
FastAPI Container
      │
      │ Database Connection
      ▼
PostgreSQL Container
```

The database is not part of the frontend runtime.

The Docker Compose configuration also uses a health check for PostgreSQL before dependent backend startup.

---

# 26. Dependency Security

The project keeps runtime dependencies in:

```text id="f9c2m6"
backend/requirements.txt
collectors/requirements.txt
collectors/nvd/requirements.txt
frontend/package.json
```

Dependencies should be kept updated and reviewed periodically.

The current project should not be described as having an automated dependency-vulnerability scanning pipeline unless one is added.

---

# 27. Authentication Test Matrix

The documented manual security validation included:

| Test                  | Expected Result  |
| --------------------- | ---------------- |
| No API key            | 401              |
| Wrong API key         | 401              |
| Correct API key       | Request accepted |
| Invalid request body  | 422              |
| Unknown endpoint      | 404              |
| Untrusted CORS origin | Rejected         |

These results represent manual validation rather than a formal automated security-test suite.

---

# 28. Input Security Test

A SQL-injection-style input was used during manual validation.

The input was processed through the application's parameterized database layer.

The expected security behavior was maintained:

```text id="n7w2c5"
Malicious-Style Input
        ↓
Parameterized SQL
        ↓
Data Value
        ↓
No SQL Command Injection
```

---

# 29. Reporting Security

The report generator uses data already available within VulnWatch.

Report evidence can be derived from:

* Nmap scan information
* Asset data
* Service data
* CPE information
* CVE information
* Vulnerability descriptions
* Findings
* Security events
* Alerts
* Correlations

The reporting workflow does not intentionally fabricate:

* Screenshots
* HTTP requests
* Exploit output
* Logs
* Security evidence that was never collected

---

# 30. Security Data Flow

The overall security architecture can be summarized as:

```text id="b7m2q9"
                    ┌──────────────────┐
                    │ Authorized Target│
                    └────────┬─────────┘
                             │
                             ▼
                         Nmap Scan
                             │
                             ▼
                        XML Parser
                             │
                             ▼
                         PostgreSQL
                             │
                ┌────────────┴────────────┐
                │                         │
                ▼                         ▼
              VAPT                       SOC
                │                         │
                ▼                         ▼
         Vulnerabilities              Events
                │                         │
                ▼                         ▼
            Findings                  Detection
                │                         │
                │                         ▼
                │                       Alerts
                │                         │
                └──────────┬──────────────┘
                           ▼
                      Correlation
                           │
                           ▼
                     Investigation
                           │
                           ▼
                       Reporting
```

---

# 31. Current Security Limitations

The current project has several known security and engineering limitations.

## Rate Limiting

The project does not currently implement a dedicated API rate-limiting layer.

A production deployment should consider rate limiting for authentication and resource-intensive operations.

---

## Security Headers

The project does not currently document a complete production security-header policy.

A production deployment should consider appropriate HTTP security headers.

---

## Automated Tests

The project does not currently contain a formal automated `pytest` security/test suite.

The documented security verification was primarily manual.

---

## Database Migrations

Database migrations are currently handled manually.

The project does not currently use Alembic for migration management.

---

## NVD Integration

The NVD collector exists, but the current automatic integration is not fully operational.

The attempted `/virtualMatchString` integration returned HTTP 404.

Therefore, automatic NVD synchronization should not be claimed as a completed feature.

---

## Frontend Progress Indicator

The target-scan frontend currently uses a hardcoded visual processing-progress value.

It should not be interpreted as exact scanner execution progress.

---

# 32. Production Security Considerations

VulnWatch is currently a portfolio and authorized-lab project.

Before exposing the application to a production or internet-facing environment, additional controls should be considered, including:

* Strong secret management
* API rate limiting
* HTTPS/TLS
* Security headers
* Centralized logging
* Audit logging
* Automated dependency scanning
* Automated security tests
* Database backup and recovery
* Container image scanning
* Monitoring and alerting
* Formal vulnerability-management processes
* Stronger authentication and authorization controls

These improvements are outside the current documented lab implementation.

---

# 33. Responsible Scanning

The browser-triggered target scanner is intentionally restricted by authorization controls.

The safe scanning principle is:

```text id="w5n8r3"
User Request
    ↓
Target Validation
    ↓
Authorized Network
    ↓
Scan Job
    ↓
Kali Scanner
```

The project should never be used to bypass authorization boundaries.

---

# 34. Security Design Principles

VulnWatch follows these security principles:

### Least Privilege

The backend Docker application runs as a non-root user.

### Defense in Depth

Security is applied across authentication, validation, network restrictions, database access, XML parsing, and process execution.

### Fail Closed

Missing or invalid authentication should result in rejection rather than unrestricted access.

### Secure Input Handling

User-controlled values are validated and passed through parameterized database operations.

### Explicit Authorization

Target scanning is restricted to the configured authorized network.

### Safe Process Execution

Nmap runs without shell interpretation.

### Secure Parsing

Nmap XML is parsed using a hardened XML parser.

### Controlled Errors

Internal implementation details are not intentionally exposed through normal API error responses.

---

# 35. Security Checklist

Before using VulnWatch in the authorized lab, verify:

```text
[ ] .env contains local configuration only
[ ] .env is not committed to Git
[ ] VULNWATCH_API_KEY is configured
[ ] Authorized network is configured correctly
[ ] Target belongs to the authorized lab
[ ] Backend API is running
[ ] PostgreSQL is healthy
[ ] Kali scanner is available
[ ] Nmap is installed
[ ] Target scan agent is configured
[ ] API authentication works
[ ] Untrusted CORS origin is rejected
[ ] Invalid API input is rejected
[ ] Duplicate active scans are prevented
```

---

# 36. Security Verification Summary

The current VulnWatch implementation includes the following documented controls:

| Control                                    | Status                |
| ------------------------------------------ | --------------------- |
| API key authentication                     | Implemented           |
| Constant-time API-key comparison           | Implemented           |
| Fail-closed API authentication             | Implemented           |
| Pydantic input validation                  | Implemented           |
| Parameterized SQL                          | Implemented           |
| Secure XML parsing                         | Implemented           |
| XML size limit                             | Implemented           |
| Authorized network validation              | Implemented           |
| Target IP validation                       | Implemented           |
| `shell=False` Nmap execution               | Implemented           |
| Nmap timeout                               | Implemented           |
| Duplicate scan prevention                  | Implemented           |
| Race-safe job claiming                     | Implemented           |
| Stale scan recovery                        | Implemented           |
| Explicit CORS                              | Implemented           |
| Non-root backend container                 | Implemented           |
| Generic API error handling                 | Implemented           |
| API rate limiting                          | Not implemented       |
| Formal pytest security suite               | Not implemented       |
| Automated NVD synchronization              | Not fully operational |
| Complete production security-header policy | Not documented        |

---

# 37. Security Statement

VulnWatch is designed as an authorized VAPT + SOC laboratory platform.

Its security architecture applies multiple controls to reduce common application, scanning, and data-processing risks.

The project should remain within authorized environments and should not be presented as a production-grade security platform without implementing the additional controls listed under current limitations and production security considerations.

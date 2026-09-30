# VulnWatch — Interview Guide

## 1. 30-Second Project Introduction

### Question:

**Tell me about your VulnWatch project.**

### Answer:

VulnWatch is an authorized cybersecurity lab platform that I built to combine VAPT and basic SOC workflows in one application.

The backend is developed using Python and FastAPI, PostgreSQL is used for storing security data, and the frontend is built using React.

For VAPT, the platform integrates Nmap-based asset and service discovery, vulnerability management and findings.

For the SOC side, it collects security events, detects activities such as SSH brute force and port scans, generates alerts and correlates those alerts with known vulnerabilities.

I also implemented a browser-triggered target scanning workflow using a job queue and Kali Linux scanner agent, along with security controls such as API-key authentication, parameterized SQL, authorized-network validation, safe subprocess execution and secure XML parsing.

---

# 2. One-Minute Explanation

### Question:

**Explain the complete architecture of VulnWatch.**

### Answer:

The frontend is built using React and communicates with the FastAPI backend.

FastAPI handles authentication, input validation, business logic and API requests.

PostgreSQL stores assets, services, vulnerabilities, findings, security events, alerts, correlations and scan jobs.

For VAPT, Nmap runs from the authorized Kali Linux environment. The scan generates XML output, which is collected and imported into VulnWatch.

For browser-triggered scanning, the frontend creates a scan job through FastAPI. The Kali scan agent picks up the job, runs Nmap against the authorized target, uploads the XML result and the backend imports it into PostgreSQL.

For SOC functionality, authentication events are collected, detection rules identify suspicious activity, alerts are generated, and the correlation engine connects security alerts with vulnerabilities affecting the same asset.

---

# 3. Why Did You Build This Project?

### Question:

**Why did you choose this project?**

### Answer:

I wanted to understand how VAPT and SOC processes can work together instead of treating vulnerability scanning and security monitoring as completely separate activities.

A vulnerability scanner can tell us that an asset has a vulnerable service, while a SOC workflow can tell us that suspicious activity is targeting an asset.

So I designed VulnWatch to connect these two types of information through correlation and investigation workflows.

---

# 4. What Technologies Did You Use?

### Answer:

The main technologies are:

* Python
* FastAPI
* PostgreSQL
* React
* Vite
* Docker
* Docker Compose
* Nmap
* Kali Linux
* psycopg
* defusedxml
* Pydantic
* Swagger/OpenAPI

---

# 5. Why FastAPI?

### Question:

**Why did you use FastAPI?**

### Answer:

I used FastAPI because it provides a clean way to build REST APIs using Python.

It also provides request validation through Pydantic and automatically generates OpenAPI/Swagger documentation.

For a security platform like VulnWatch, this made it easier to create structured APIs for scans, assets, vulnerabilities, alerts, correlations and reports.

---

# 6. Why PostgreSQL?

### Question:

**Why PostgreSQL instead of storing everything in files?**

### Answer:

The project contains relational security data.

For example:

```text
Asset
 ↓
Service
 ↓
Service Vulnerability
 ↓
Vulnerability
 ↓
Finding
```

Similarly:

```text
Alert
 ↓
Correlation
 ↓
Vulnerability
```

PostgreSQL allows these relationships to be represented using foreign keys, unique constraints and relational queries.

---

# 7. How Does Nmap Integration Work?

### Question:

**How did you integrate Nmap?**

### Answer:

Nmap performs the actual network/service discovery in the authorized lab environment.

The result is generated as Nmap XML.

The XML is then sent to the VulnWatch backend, where it is parsed and imported.

The basic workflow is:

```text
Nmap
 ↓
XML
 ↓
XML Collector
 ↓
FastAPI Scan Import API
 ↓
XML Parser
 ↓
PostgreSQL
```

The imported information includes assets, ports, protocols, services and service versions.

---

# 8. Why XML?

### Question:

**Why did you use Nmap XML instead of parsing normal terminal output?**

### Answer:

Nmap XML provides structured information.

Instead of trying to parse human-readable terminal output, the application can directly process structured fields such as:

* IP address
* Hostname
* Port
* Protocol
* Service
* Version
* CPE information

This makes the import process more reliable.

---

# 9. How Does Target Scanning Work?

### Question:

**Explain your browser-triggered target scan.**

### Answer:

The frontend sends a request to start a scan.

The backend first validates the target and checks whether it belongs to the authorized network.

If the request is valid, a scan job is created.

The Kali scan agent polls for available jobs.

It claims a job, changes its status to RUNNING and executes Nmap.

After the scan completes, the XML result is sent back to the backend.

The backend imports the result and marks the job as COMPLETED.

The frontend polls the job status and displays the result.

```text
Browser
 ↓
FastAPI
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
FastAPI Import
 ↓
PostgreSQL
 ↓
Frontend
```

---

# 10. How Did You Prevent Unauthorized Scanning?

### Question:

**This is a security-sensitive feature. How did you restrict target scanning?**

### Answer:

I implemented multiple controls.

First, the target-scan endpoint requires API-key authentication.

Second, the target IP is validated against the configured authorized network.

The project uses:

```text
VULNWATCH_AUTHORIZED_NETWORK
```

This prevents the scanner from being treated as a general-purpose scanner for arbitrary external targets.

The project is designed for authorized lab use.

---

# 11. How Did You Execute Nmap Securely?

### Question:

**How did you protect the Nmap subprocess execution?**

### Answer:

Nmap is executed using Python's subprocess functionality with:

```text
shell=False
```

The target is passed as an argument instead of constructing a shell command string.

A timeout is also used so that a scan cannot run indefinitely.

The scan target is validated before execution.

---

# 12. What Is the Job Queue?

### Question:

**Why did you create scan jobs instead of running Nmap directly from the API request?**

### Answer:

A scan can take time, so running it directly inside the HTTP request would keep the request open and make the API less responsive.

Instead, the API creates a scan job.

The scanner agent processes that job separately.

The job has states such as:

```text
PENDING
RUNNING
COMPLETED
FAILED
```

This separates API request handling from the actual scanning operation.

---

# 13. What Is `FOR UPDATE SKIP LOCKED`?

### Question:

**You mentioned race-safe job processing. Explain it.**

### Answer:

The scanner agent needs to claim an available job without two workers processing the same job simultaneously.

`FOR UPDATE SKIP LOCKED` allows a worker to lock the selected database row while other workers skip rows that are already locked.

This helps make job claiming safe when multiple workers are running.

---

# 14. What Is Stale Job Recovery?

### Question:

**What happens if the scanner crashes while a job is RUNNING?**

### Answer:

A job could otherwise remain stuck in the RUNNING state.

VulnWatch includes stale-job recovery logic.

If a RUNNING job remains active beyond the configured stale period, it can be treated as stale so that the system can recover instead of permanently blocking that target.

---

# 15. Explain the Vulnerability Management Flow.

### Answer:

The vulnerability workflow connects discovered services with vulnerability information.

The basic relationship is:

```text
Asset
 ↓
Service
 ↓
Service Vulnerability
 ↓
Vulnerability
 ↓
Finding
```

A vulnerability can contain information such as CVE ID, CVSS score, severity, CWE and description.

A finding represents the security issue associated with the affected service.

---

# 16. What Is CVE?

### Answer:

CVE stands for **Common Vulnerabilities and Exposures**.

It provides a standardized identifier for publicly known vulnerabilities.

For example:

```text
CVE-2011-2523
```

In VulnWatch, CVE information is associated with vulnerability records.

---

# 17. What Is CVSS?

### Answer:

CVSS stands for **Common Vulnerability Scoring System**.

It provides a standardized numerical score that helps describe the severity of a vulnerability.

In the lab data, for example:

```text
CVE-2011-2523
CVSS: 10.0
Severity: CRITICAL
```

---

# 18. Explain the SOC Workflow.

### Answer:

The SOC workflow starts with security events.

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

The detection engine evaluates security events against detection rules.

When a rule is triggered, an alert is created.

The correlation engine then checks whether that alert is related to known vulnerabilities on the affected asset.

---

# 19. What Detections Did You Implement?

### Answer:

The project includes detection logic for:

### SSH Brute Force

Thresholds are used to classify repeated failed SSH authentication attempts:

```text
2+  → MEDIUM
5+  → HIGH
10+ → CRITICAL
```

### Port Scan

The project detects a source connecting to 10 or more unique destination ports as a HIGH-severity port-scan event.

---

# 20. What Is Alert Correlation?

### Question:

**Explain your correlation engine.**

### Answer:

The correlation engine connects security alerts with vulnerabilities.

For example, suppose an alert targets:

```text
192.168.57.101
```

and the same asset has a vulnerable service.

The correlation engine can associate the alert with the vulnerability affecting that service.

The relationship is:

```text
Alert
 ↓
Destination IP
 ↓
Asset
 ↓
Service
 ↓
Vulnerability
```

The correlation priority is based on the higher severity between the vulnerability and the alert.

---

# 21. What Is an Investigation?

### Answer:

An investigation provides a path from a detected security event toward the underlying technical information.

In VulnWatch, the investigation can follow:

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

This gives an analyst context instead of looking at an alert in isolation.

---

# 22. What Security Controls Did You Implement?

### Answer:

The important security controls include:

1. API-key authentication
2. Constant-time API-key comparison
3. Parameterized SQL queries
4. Defused XML parsing
5. Authorized-network validation
6. IP validation
7. `shell=False`
8. Nmap execution timeout
9. Pydantic input validation
10. Explicit CORS configuration
11. Duplicate scan prevention
12. Stale-job recovery
13. Race-safe job claiming
14. Non-root Docker container
15. Generic API error handling
16. XML size limitation

---

# 23. Why `secrets.compare_digest()`?

### Question:

**Why not simply compare API keys using `==`?**

### Answer:

The application uses:

```python
secrets.compare_digest()
```

for API-key comparison.

It is designed for safer comparison of secret values by reducing timing-related information leakage compared with ordinary string comparison.

---

# 24. How Did You Prevent SQL Injection?

### Answer:

I used parameterized SQL queries.

User-controlled values are passed separately as query parameters instead of being concatenated into SQL statements.

Conceptually:

```text
SQL statement
+
parameters
```

rather than:

```text
SQL string + user input
```

This prevents user input from becoming part of the SQL command structure.

---

# 25. How Did You Protect XML Parsing?

### Question:

**Why did you use defusedxml?**

### Answer:

Nmap produces XML, so the application needs to parse XML received from the scanner.

I used `defusedxml` to reduce risks associated with unsafe XML processing.

This is especially important when an application processes XML data rather than treating it only as trusted local text.

---

# 26. What Is CORS?

### Answer:

CORS stands for **Cross-Origin Resource Sharing**.

It controls which browser origins are allowed to make requests to the backend.

In VulnWatch, CORS is explicitly configured instead of allowing arbitrary origins.

---

# 27. Why Run Docker as Non-Root?

### Answer:

Running the application as a non-root user follows the principle of least privilege.

If the application process is compromised, the attacker does not automatically receive root privileges inside the container.

Therefore, the Docker backend uses a dedicated non-root application user.

---

# 28. What Was the Most Interesting Technical Challenge?

### Answer:

One challenging part was implementing the browser-triggered scan workflow safely.

The feature required several components to work together:

```text
Frontend
 ↓
FastAPI
 ↓
Database Job
 ↓
Kali Agent
 ↓
Nmap
 ↓
XML
 ↓
Import
 ↓
Frontend
```

I had to handle authentication, target validation, duplicate scans, job states, stale jobs, Nmap execution, XML processing and result polling.

This helped me understand how a security tool moves from a simple scanner to a complete application workflow.

---

# 29. What Testing Did You Perform?

### Answer:

I performed manual validation of important security and application workflows.

Examples include:

```text
Missing API key
→ 401

Wrong API key
→ 401

Correct API key
→ Successful response

Invalid request body
→ 422

Untrusted CORS origin
→ Rejected

SQL injection-style input
→ Safely handled

Target scan
→ Job created
→ Nmap executed
→ XML imported
→ Result displayed

Report API
→ Structured security report
```

The project does not currently claim a formal automated pytest suite.

---

# 30. What Was the Lab Target?

### Answer:

The project was tested against an authorized **Metasploitable 2** target in an isolated lab network.

```text
Lab Network:
192.168.57.0/24

Kali:
192.168.57.102

Metasploitable:
192.168.57.101
```

The target was used only as an authorized lab environment for testing the platform.

---

# 31. Give an Example Vulnerability From Your Lab.

### Answer:

One of the lab vulnerabilities was:

```text
CVE-2011-2523
Service: vsftpd 2.3.4
CVSS: 10.0
Severity: CRITICAL
CWE: CWE-78
```

The important point for VulnWatch is that the vulnerability information can be associated with the affected service and asset and can then participate in findings, reporting and correlation workflows.

---

# 32. Explain the Security Report.

### Question:

**What does your reporting module provide?**

### Answer:

The reporting module generates an asset-level security report.

It includes:

* Executive summary
* Scope and methodology
* Risk summary
* Asset information
* Open ports and services
* Vulnerabilities
* Detailed findings
* Security monitoring information
* Report summary

The report also deduplicates CVEs and groups related findings.

The evidence is based on information actually available from the scan and security-event data.

---

# 33. What Would You Improve Next?

### Answer:

The next improvements I would consider are:

* Automated pytest coverage
* API rate limiting
* Security headers
* Alembic database migrations
* Environment-based frontend API configuration
* More SOC detection rules
* More correlation rules
* Real scan-progress reporting
* Expanded vulnerability-feed integration
* Role-based access control
* More detailed audit logging

---

# 34. What Are the Current Limitations?

### Answer:

The project is an authorized lab and portfolio implementation rather than a production SOC platform.

Some current limitations are:

* No formal automated pytest suite
* No built-in rate limiting
* No dedicated security-header middleware
* Manual database migration process
* Target-scan UI progress is currently visual rather than true scanner percentage
* NVD collector is present but not the primary CVE ingestion workflow
* Frontend API configuration can be improved

I would clearly mention these limitations rather than claiming production-level capabilities that are not implemented.

---

# 35. If Interviewer Asks: "Is This a Real SOC?"

### Answer:

I would describe it as a **SOC-style security monitoring and investigation workflow implemented in an authorized lab environment**.

It demonstrates concepts such as security-event collection, detection, alerting, correlation and investigation, but it should not be presented as a production enterprise SOC.

---

# 36. If Interviewer Asks: "Did You Build Everything Yourself?"

### Answer:

I built the project architecture and implemented the application workflows, including the FastAPI backend, database integration, frontend workflows, Nmap integration, scan-job processing, detection/correlation logic, reporting and security controls.

I also used established technologies such as Nmap, PostgreSQL, React, Docker and Kali Linux rather than attempting to recreate those tools from scratch.

---

# 37. If Interviewer Asks About Your Contribution

### Answer:

My contribution was focused on designing and implementing the end-to-end cybersecurity workflow.

I worked on:

* Backend APIs
* Database design
* Nmap integration
* Scan import
* Target scan workflow
* Scan job processing
* Vulnerability management
* Security-event processing
* Detection logic
* Alerts
* Correlations
* Investigations
* Reporting
* Frontend integration
* Security hardening
* Manual security validation
* Project documentation

---

# 38. Important Terms to Revise Before Interview

Before discussing VulnWatch, revise these topics:

### VAPT

* Reconnaissance
* Port scanning
* Service enumeration
* Vulnerability identification
* CVE
* CVSS
* CWE
* Findings
* Remediation

### Networking

* TCP/IP
* TCP vs UDP
* Ports
* IP addresses
* CIDR
* DNS
* HTTP/HTTPS
* SSH
* FTP
* Firewalls
* CORS

### Web Security

* OWASP Top 10
* SQL Injection
* XSS
* Authentication
* Authorization
* API security
* Input validation
* SSRF
* Command injection

### SOC

* SIEM
* Security events
* Detection rules
* Alerts
* Severity
* Correlation
* Investigation
* Incident response

### Python/FastAPI

* REST API
* HTTP methods
* Status codes
* Pydantic
* Dependency injection
* Middleware
* Environment variables
* subprocess
* Exception handling

### Database

* Primary key
* Foreign key
* UNIQUE constraint
* Index
* JOIN
* Transactions
* Row locking
* Parameterized queries

### Docker

* Image
* Container
* Dockerfile
* Docker Compose
* Volume
* Network
* Healthcheck
* Non-root container

---

# 39. Best Way to Explain the Project

Use this order during an interview:

```text
1. Problem
      ↓
2. Project purpose
      ↓
3. Architecture
      ↓
4. VAPT workflow
      ↓
5. SOC workflow
      ↓
6. Correlation
      ↓
7. Security controls
      ↓
8. Testing
      ↓
9. Challenges
      ↓
10. Future improvements
```

Do not immediately start explaining every file.

First explain the **big picture**, then go deeper when the interviewer asks.

---

# 40. One Strong Final Answer

If the interviewer says:

**"Anything else you want to tell me about the project?"**

You can say:

> The main thing I wanted to achieve with VulnWatch was to understand the complete security workflow rather than only running a vulnerability scanner.
>
> I wanted the system to go from asset discovery and vulnerability identification to security-event detection, alerting, correlation, investigation and reporting.
>
> I also focused on implementing security controls around the tool itself, such as API authentication, target authorization, parameterized SQL, secure XML parsing, safe subprocess execution and non-root containers.
>
> Because it is an authorized lab project, I have also documented its limitations and separated the implemented capabilities from future production-level improvements.

---

# 41. Interview Golden Rule

Never claim a feature that is not actually implemented.

If the interviewer asks about something that is not currently implemented, say:

> "That is not implemented in the current version. I have identified it as a future improvement."

This is better than guessing.

For example:

```text
❌ "We have complete automated testing."

✅ "The current project has manual validation; automated pytest coverage is a planned improvement."
```

```text
❌ "It is a production SOC."

✅ "It is an authorized lab implementation demonstrating SOC-style workflows."
```

```text
❌ "The scanner can scan anything."

✅ "The scanner is restricted to the configured authorized lab network."
```

---

# 42. Final Project Flow to Memorize

The easiest flow to remember is:

```text
                 VULNWATCH
                     │
        ┌────────────┴────────────┐
        │                         │
       VAPT                      SOC
        │                         │
      Nmap                    Auth Logs
        │                         │
      Assets                Security Events
        │                         │
     Services                Detection
        │                         │
  Vulnerabilities              Alerts
        │                         │
     Findings              Correlation
        │                         │
        └────────────┬────────────┘
                     │
               Investigation
                     │
                  Reporting
```

### One-line summary:

**VulnWatch connects VAPT findings with SOC-style security monitoring so that vulnerabilities, alerts, correlations, investigations and reports can be viewed as one security workflow.**

# VulnWatch Setup Guide

This document explains how to set up and run VulnWatch in the authorized cybersecurity lab environment.

---

# 1. Prerequisites

The current VulnWatch setup uses:

* Windows or Linux host
* Docker Desktop / Docker Engine
* Docker Compose
* Git
* Python 3.12+
* Node.js and npm
* Kali Linux
* Nmap
* An authorized vulnerable lab target such as Metasploitable 2

The project is designed for an isolated and authorized security-testing environment.

---

# 2. Lab Architecture

The current lab uses:

| Component          | Address / Port          |
| ------------------ | ----------------------- |
| VulnWatch Backend  | `127.0.0.1:8000`        |
| Frontend           | `localhost:5173`        |
| PostgreSQL         | Docker internal network |
| Kali Scanner       | `192.168.57.102`        |
| Metasploitable 2   | `192.168.57.101`        |
| Authorized Network | `192.168.57.0/24`       |

---

# 3. Clone the Repository

Clone the VulnWatch repository:

```bash
git clone https://github.com/AlveenaHussain/vulnwatch.git
```

Move into the project directory:

```bash
cd vulnwatch
```

---

# 4. Environment Configuration

VulnWatch uses environment variables for configuration and secrets.

The project includes:

```text
.env.example
```

Create the local environment file from the example configuration.

The `.env` file should contain the required PostgreSQL and VulnWatch configuration values.

Typical configuration areas include:

```text
POSTGRES_USER
POSTGRES_PASSWORD
POSTGRES_DB
POSTGRES_HOST
POSTGRES_PORT
VULNWATCH_API_KEY
VULNWATCH_AUTHORIZED_NETWORK
NVD_API_KEY
```

Do not commit real secrets to Git.

The local `.env` file is intended to remain outside version control.

---

# 5. Authorized Network Configuration

The target-scan feature uses an authorized network configuration.

The current lab network is:

```text
192.168.57.0/24
```

The corresponding configuration variable is:

```text
VULNWATCH_AUTHORIZED_NETWORK
```

The target-scan backend validates the requested target against this authorized range before creating a scan job.

Only authorized lab targets should be used.

---

# 6. Start PostgreSQL and Backend

From the VulnWatch project root:

```bash
docker compose up -d --build
```

This starts the Docker services required by the backend environment.

Check container status:

```bash
docker compose ps
```

The PostgreSQL service should become healthy before the backend starts using the database.

---

# 7. Verify the Backend

The backend runs on:

```text
http://127.0.0.1:8000
```

Open the health endpoint:

```text
http://127.0.0.1:8000/health
```

The database health endpoint is also available:

```text
http://127.0.0.1:8000/health/db
```

Swagger/OpenAPI documentation:

```text
http://127.0.0.1:8000/docs
```

---

# 8. Database Migrations

VulnWatch currently uses SQL migration files located in:

```text
backend/migrations/
```

The migration files include:

```text
001_add_security_events.sql
002_add_alerts.sql
003_add_correlations.sql
004_add_scan_jobs.sql
005_fix_service_state_constraint.sql
```

The current project uses manual migration management rather than Alembic.

When setting up a fresh environment, make sure the database schema and required migrations are applied according to the project's current database setup.

---

# 9. Frontend Setup

Open a terminal in the frontend directory:

```bash
cd frontend
```

Install the Node.js dependencies:

```bash
npm install
```

Start the Vite development server:

```bash
npm run dev
```

The frontend should become available at:

```text
http://localhost:5173
```

---

# 10. Verify the Frontend

Open:

```text
http://localhost:5173
```

The VulnWatch interface provides access to areas including:

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

---

# 11. Kali Linux Setup

Kali Linux is used as the authorized scanning environment.

Current Kali scanner IP:

```text
192.168.57.102
```

Verify the Kali system can reach the authorized target:

```bash
ping 192.168.57.101
```

The target should only be a system that is intentionally placed inside the authorized lab.

---

# 12. Verify Nmap

Check that Nmap is installed:

```bash
nmap --version
```

The target-scan agent uses Nmap for service discovery.

The scan uses service/version detection and XML output.

Conceptually:

```bash
nmap -sV -oX <output-file> <target-ip>
```

---

# 13. Target Scan Agent

The target-scan workflow uses the Kali target-scan agent.

The agent communicates with the FastAPI backend to:

1. Poll for pending scan jobs
2. Claim a scan job
3. Execute Nmap
4. Generate XML output
5. Submit the XML result
6. Mark the scan as completed or failed

The relevant project component is:

```text
collectors/target_scan_agent.py
```

The agent should run from the authorized Kali environment.

---

# 14. Target Scan Workflow

The complete workflow is:

```text
Browser
   ↓
FastAPI
   ↓
Target Validation
   ↓
Scan Job Created
   ↓
PENDING
   ↓
Kali Agent
   ↓
RUNNING
   ↓
Nmap
   ↓
Nmap XML
   ↓
FastAPI Result Endpoint
   ↓
XML Import
   ↓
PostgreSQL
   ↓
COMPLETED
   ↓
Frontend Results
```

---

# 15. Target Authorization Check

Before starting a target scan, confirm that the target belongs to the authorized lab network.

Current target:

```text
192.168.57.101
```

Current authorized network:

```text
192.168.57.0/24
```

Do not modify the authorization configuration to scan systems for which permission has not been granted.

---

# 16. Initial VAPT Workflow

A basic VulnWatch VAPT workflow is:

```text
1. Confirm authorized target
2. Run Nmap
3. Generate XML
4. Import XML
5. Verify asset
6. Verify services
7. Import / review vulnerabilities
8. Review service-vulnerability relationships
9. Review findings
10. Generate report
```

---

# 17. Nmap XML Import

Nmap XML can be processed through the VulnWatch scan-import workflow.

The collector sends scan information to the backend.

The backend processes:

* Target information
* Ports
* Services
* Service versions
* Scan metadata

The imported information is stored in PostgreSQL.

---

# 18. SOC Workflow

The SOC workflow is:

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
Investigations
```

The current detection workflow includes:

* SSH brute-force detection
* Port-scan detection

---

# 19. SSH Brute-Force Detection

Current thresholds are:

```text
2+ events   → MEDIUM
5+ events   → HIGH
10+ events  → CRITICAL
```

The detection engine creates alerts based on these configured thresholds.

---

# 20. Port-Scan Detection

The current port-scan rule evaluates unique destination ports.

The configured threshold is:

```text
10+ unique destination ports → HIGH
```

---

# 21. Correlation Workflow

VulnWatch correlates security alerts with vulnerabilities on the affected asset.

The workflow is:

```text
Alert
  ↓
Destination IP
  ↓
Asset
  ↓
Services
  ↓
Service Vulnerabilities
  ↓
Vulnerability
  ↓
Correlation
```

Correlation priority is based on the higher severity between the alert and associated vulnerability.

---

# 22. Investigation Workflow

After a correlation is created, investigation information can be retrieved.

The investigation chain can include:

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

This allows security activity to be examined together with vulnerability context.

---

# 23. Reporting Workflow

VulnWatch can generate an asset-level security assessment report.

The report uses stored project data including:

* Asset information
* Services
* Vulnerabilities
* Findings
* Security monitoring information
* Alerts
* Correlations

The reporting workflow can be represented as:

```text
Asset Data
    +
Service Data
    +
Vulnerability Data
    +
Finding Data
    +
SOC Data
       ↓
Report Generator
       ↓
Security Assessment Report
```

---

# 24. API Authentication

Protected endpoints use the configured VulnWatch API key.

Requests to protected endpoints must provide the expected API-key authentication.

Security testing during development included:

```text
Missing API key → 401
Wrong API key   → 401
Correct API key → accepted
```

The actual API key should never be placed in documentation or committed to Git.

---

# 25. Stopping the Application

To stop the Docker services:

```bash
docker compose down
```

To stop the services while preserving the PostgreSQL Docker volume, use the normal `docker compose down` command without deleting volumes.

Avoid deleting the database volume unless you intentionally want to reset the lab database.

---

# 26. Useful Docker Commands

Check containers:

```bash
docker compose ps
```

View backend logs:

```bash
docker compose logs backend
```

Follow backend logs:

```bash
docker compose logs -f backend
```

View database logs:

```bash
docker compose logs db
```

Follow all service logs:

```bash
docker compose logs -f
```

Rebuild:

```bash
docker compose up -d --build
```

Stop services:

```bash
docker compose down
```

---

# 27. Useful Frontend Commands

From:

```text
frontend/
```

Install dependencies:

```bash
npm install
```

Start development server:

```bash
npm run dev
```

---

# 28. Useful Git Commands

Check project status:

```bash
git status
```

View recent commits:

```bash
git log --oneline -5
```

Pull the latest repository changes:

```bash
git pull origin main
```

Push committed changes:

```bash
git push origin main
```

---

# 29. Troubleshooting

## Backend Does Not Start

Check:

```bash
docker compose ps
```

Then inspect:

```bash
docker compose logs backend
```

Also verify the environment configuration.

---

## Database Is Not Healthy

Check:

```bash
docker compose ps
```

Then:

```bash
docker compose logs db
```

Verify the PostgreSQL configuration values.

---

## Frontend Cannot Reach Backend

Confirm that the backend is running:

```text
http://127.0.0.1:8000/health
```

Then verify that the frontend is running:

```text
http://localhost:5173
```

Also check the browser developer console for API errors.

---

## Target Is Not Reachable

From Kali:

```bash
ping 192.168.57.101
```

Then verify the lab network configuration.

Only continue with scanning when the target is confirmed to be part of the authorized lab.

---

## Nmap Is Not Available

Check:

```bash
nmap --version
```

If Nmap is unavailable, the Kali environment needs to be configured before target scanning can work.

---

## Scan Job Remains RUNNING

VulnWatch includes stale-job recovery.

Check backend logs and database/job state before manually modifying a scan job.

Avoid repeatedly creating new jobs while an existing job is still active.

---

# 30. Security Notes

VulnWatch is intended for authorized security testing.

Always:

* Use an isolated lab
* Confirm target ownership/authorization
* Keep API keys in environment variables
* Do not commit `.env`
* Do not expose production secrets
* Do not scan unauthorized systems
* Keep vulnerable targets isolated from untrusted networks

---

# 31. Current Lab Target

The documented lab target is:

```text
Metasploitable 2
IP: 192.168.57.101
Hostname: metasploitable
```

The scanner is:

```text
Kali Linux
IP: 192.168.57.102
```

The authorized network is:

```text
192.168.57.0/24
```

---

# 32. Current Project Limitations

The current setup has several known limitations:

* No formal automated pytest/unit-test suite
* No dedicated API rate-limiting layer
* Security headers are not currently implemented
* Database migrations are managed manually
* Target-scan frontend progress is currently visual rather than actual percentage progress
* NVD synchronization is currently sidelined because the attempted `/virtualMatchString` integration returned HTTP 404
* Some production-level deployment features are not implemented

These limitations are documented intentionally because VulnWatch is a portfolio and educational security-lab platform.

---

# 33. Quick Start

For an already-configured environment, the basic startup sequence is:

### Terminal 1 — Backend + Database

```bash
cd C:\Projects\vulnwatch
docker compose up -d --build
```

### Terminal 2 — Frontend

```bash
cd C:\Projects\vulnwatch\frontend
npm install
npm run dev
```

### Browser

Open:

```text
http://localhost:5173
```

### API Documentation

Open:

```text
http://127.0.0.1:8000/docs
```

### Kali

Start the authorized target-scan agent from:

```text
collectors/target_scan_agent.py
```

Then use the Target Scan interface from the VulnWatch frontend.

---

# 34. Setup Verification Checklist

Before testing the complete platform, verify:

```text
[ ] Docker is running
[ ] PostgreSQL container is healthy
[ ] Backend container is running
[ ] /health endpoint works
[ ] /health/db endpoint works
[ ] Swagger opens
[ ] Frontend starts
[ ] Frontend opens on localhost:5173
[ ] Kali can reach the authorized target
[ ] Nmap is installed
[ ] Target belongs to authorized network
[ ] Target-scan agent is running
[ ] Target scan can create a job
[ ] Scan job completes
[ ] Asset/services appear
[ ] Vulnerabilities/findings are visible
[ ] Alerts are visible
[ ] Correlations are visible
[ ] Investigation is accessible
[ ] Security report is generated
```

---

# 35. Final Verification

A successful VulnWatch setup should provide:

```text
Frontend
    ↓
FastAPI
    ↓
PostgreSQL
    ↓
Kali Agent
    ↓
Nmap
    ↓
Authorized Target
```

with the resulting security data available through the VulnWatch frontend and API.

---

# 36. Safety Reminder

VulnWatch is an authorized security-lab platform.

Use it only against systems where you have explicit permission to perform security testing.

The documented Metasploitable environment is intentionally vulnerable and should remain isolated from networks where it could be abused.

# VulnWatch

**A lab-based cybersecurity platform that combines Vulnerability Assessment (VAPT) with Security Monitoring (SOC) — and correlates them.**

> 🚧 **Status: Work in progress.** Currently building the project skeleton (Phase 2).

---

## The Problem

In most organizations, vulnerability data and security monitoring data live in separate tools, owned by separate teams. A server might have a critical vulnerability *and* be under active attack — but nobody connects the two until it's too late.

## What VulnWatch Does

VulnWatch brings both views together for a local lab environment:

- **Asset Discovery** — find lab hosts, open ports, and running services using Nmap
- **Vulnerability Management** — track findings with CVE, CVSS, severity, evidence, and remediation
- **Web Security Testing** — record OWASP-style findings from Burp Suite testing
- **SOC Monitoring** — collect lab logs and detect failed logins, port scans, and suspicious activity
- **Correlation Engine** — raise alert priority when an attacked asset is also vulnerable
- **Dashboard & Investigation** — view assets, alerts, and timelines in one place
- **Reporting** — generate findings with evidence, risk, impact, detection, and remediation

## Architecture
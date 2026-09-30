# VulnWatch SOC Workflow

## 1. Overview

VulnWatch includes a Security Operations Center (SOC) workflow for collecting security events, detecting suspicious activity, generating alerts, correlating alerts with known vulnerabilities, and supporting investigation.

The overall SOC flow is:

```text
Security Log
     ↓
Security Event
     ↓
Detection Engine
     ↓
Alert
     ↓
Correlation Engine
     ↓
Correlation
     ↓
Investigation
```

The SOC workflow is designed for the authorized VulnWatch lab environment.

---

# 2. SOC Architecture

The main SOC components are:

```text
┌──────────────────────┐
│   Security Sources   │
│                      │
│ Authentication Logs  │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ Security Event       │
│ Collector            │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ Security Events      │
│ PostgreSQL           │
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

# 3. Security Event Collection

The SOC workflow begins with security-event collection.

VulnWatch includes an authentication-log collector:

```text
collectors/auth_log_collector.py
```

The collector reads authentication-related log information and converts relevant activity into structured security events.

The basic flow is:

```text
Authentication Log
        ↓
Log Collector
        ↓
Structured Security Event
        ↓
PostgreSQL
```

---

# 4. Security Events

A security event represents an observed activity that may be relevant to security monitoring.

The event can contain information such as:

* Event type
* Source IP
* Destination IP
* Timestamp
* Authentication information
* Related metadata

The important concept is that raw activity is first represented as an event before the detection engine decides whether it represents suspicious behavior.

---

# 5. Event-to-Alert Pipeline

VulnWatch separates events from alerts.

```text
Event
 ↓
Detection Rules
 ↓
Suspicious Pattern
 ↓
Alert
```

This distinction is important because an individual event does not automatically mean that a security incident has occurred.

The detection engine evaluates multiple events and identifies patterns.

---

# 6. Detection Engine

The detection engine analyzes security events and looks for predefined suspicious patterns.

The current documented detection logic includes:

1. SSH brute-force detection
2. Port-scan detection

The detection workflow is:

```text
Security Events
      ↓
Detection Engine
      ↓
Pattern Matching
      ↓
Threshold Reached?
   ┌──┴──┐
  No    Yes
   │      │
   ▼      ▼
Continue  Alert
```

---

# 7. SSH Brute-Force Detection

VulnWatch includes threshold-based SSH brute-force detection.

The documented thresholds are:

| Failed SSH Attempts | Alert Severity |
| ------------------: | -------------- |
|           2 or more | MEDIUM         |
|           5 or more | HIGH           |
|          10 or more | CRITICAL       |

Conceptually:

```text
SSH authentication failures
          ↓
       Count
          ↓
┌─────────────────────┐
│ >= 2  → MEDIUM      │
│ >= 5  → HIGH        │
│ >= 10 → CRITICAL    │
└─────────────────────┘
```

The detection engine therefore does not need to create a high-severity alert from a single authentication failure.

---

# 8. Port-Scan Detection

VulnWatch also detects port-scan-like activity.

The documented rule is:

```text
10 or more unique destination ports
                ↓
             HIGH
```

The conceptual flow is:

```text
Source IP
   ↓
Destination Port Tracking
   ↓
Unique Port Count
   ↓
>= 10 Ports
   ↓
HIGH Alert
```

This helps identify activity where one source attempts connections across multiple destination ports.

---

# 9. Alert Creation

When a detection rule reaches its configured threshold, VulnWatch creates an alert.

The relationship is:

```text
Security Events
       ↓
Detection Rule
       ↓
Threshold
       ↓
Alert
```

An alert provides a higher-level security signal for analyst review.

---

# 10. Alert Information

An alert can contain contextual information such as:

* Alert type
* Severity
* Source IP
* Destination IP
* Status
* Detection information
* Related security events

The documented alert types include:

```text
SSH_BRUTE_FORCE
PORT_SCAN
```

---

# 11. Alert Severity

The project uses severity levels including:

```text
LOW
MEDIUM
HIGH
CRITICAL
```

For example:

```text
SSH brute force
      │
      ├── >= 2 attempts  → MEDIUM
      ├── >= 5 attempts  → HIGH
      └── >= 10 attempts → CRITICAL
```

For port scanning:

```text
10+ unique destination ports
            ↓
           HIGH
```

---

# 12. Duplicate Alert Prevention

VulnWatch includes duplicate prevention for open alerts.

The documented protection uses a partial unique database index for open alerts based on:

```text
alert_type
source_ip
destination_ip
```

The conceptual behavior is:

```text
New Detection
     ↓
Existing OPEN Alert?
   ┌───┴────┐
  Yes      No
   │        │
   ▼        ▼
Avoid      Create
Duplicate  Alert
```

This helps prevent repeated processing from generating unnecessary duplicate open alerts for the same condition.

---

# 13. Alert Lifecycle

An alert has a status that allows it to be managed through the SOC workflow.

Conceptually:

```text
Detection
   ↓
OPEN Alert
   ↓
Analyst Review
   ↓
Investigation / Resolution
```

The alert becomes the entry point for deeper analysis.

---

# 14. Correlation Engine

One of the main features of VulnWatch is the correlation between SOC alerts and VAPT findings.

The correlation engine connects:

```text
SOC Alert
     +
Known Vulnerability
     ↓
Correlation
```

The documented matching logic uses the destination IP of an alert and the target IP associated with vulnerability information on the same asset.

---

# 15. Alert-to-Vulnerability Correlation

The basic flow is:

```text
                 SOC
                  │
                  ▼
                Alert
                  │
                  │ Destination IP
                  ▼
             Asset Match
                  ▲
                  │ Target IP
                  │
             Vulnerability
                  │
                  ▼
             Correlation
```

This gives the analyst additional context about the affected system.

---

# 16. Correlation Priority

When an alert and vulnerability are correlated, VulnWatch calculates correlation priority using the higher severity between the vulnerability and the alert.

Conceptually:

```text
Vulnerability Severity
          +
Alert Severity
          ↓
Higher Severity
          ↓
Correlation Priority
```

For example:

```text
Vulnerability = CRITICAL
Alert         = HIGH
        ↓
Priority      = CRITICAL
```

The purpose is to retain the more severe signal when presenting the correlation.

---

# 17. Correlation Uniqueness

VulnWatch prevents duplicate correlations for the same alert and service-vulnerability relationship.

The database enforces uniqueness for:

```text
alert_id
service_vulnerability_id
```

Conceptually:

```text
Alert + Service Vulnerability
             ↓
      Existing correlation?
         ┌────┴────┐
        Yes       No
         │         │
         ▼         ▼
     Prevent     Create
     Duplicate   Correlation
```

---

# 18. Investigation Workflow

A correlation can lead to an investigation.

The investigation workflow provides a path from the initial security signal to the underlying asset and vulnerability context.

```text
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

This allows the analyst to examine the complete available context.

---

# 19. Investigation Context

During investigation, the analyst can review:

### Alert

What suspicious activity was detected?

### Source

Where did the activity originate?

### Destination

Which asset received the activity?

### Asset

Which system is involved?

### Services

Which services are exposed on that system?

### Vulnerability

Are there known vulnerabilities associated with the affected services?

### Finding

What is the status of the associated vulnerability finding?

### Security Events

What underlying events contributed to the detection?

---

# 20. Example SOC Scenario

Consider the authorized lab target:

```text
192.168.57.101
```

Suppose multiple SSH authentication failures are recorded.

The workflow becomes:

```text
SSH Authentication Failures
             ↓
      Security Events
             ↓
      Detection Engine
             ↓
      SSH Brute Force
             ↓
          Alert
             ↓
      Destination IP
             ↓
       Asset Matching
             ↓
 Known Vulnerability Data
             ↓
        Correlation
             ↓
       Investigation
```

The analyst can then examine both the suspicious activity and the known security weaknesses associated with the asset.

---

# 21. SOC and VAPT Integration

VulnWatch combines two security perspectives.

## VAPT Perspective

```text
What vulnerabilities exist?
```

## SOC Perspective

```text
What suspicious activity was detected?
```

## Correlation Perspective

```text
Is the suspicious activity associated with an asset
that also has known vulnerabilities?
```

The combined architecture is:

```text
             VAPT
              │
              ▼
       Assets / Services
              │
              ▼
        Vulnerabilities
              │
              │
              ▼
          Correlation
              ▲
              │
              │
            Alerts
              ▲
              │
              │
       Detection Engine
              ▲
              │
              │
      Security Events
              ▲
              │
              │
        Security Logs
```

---

# 22. SOC Frontend

The VulnWatch frontend provides dedicated views for SOC information.

The documented pages include:

* Alerts
* Correlations
* Security Events
* Investigations

These views allow the analyst to move from high-level security signals to detailed investigation context.

---

# 23. Alerts View

The Alerts page provides access to generated security alerts.

An analyst can review information such as:

* Alert type
* Severity
* Source
* Destination
* Status
* Detection context

Example alert types:

```text
SSH_BRUTE_FORCE
PORT_SCAN
```

---

# 24. Correlations View

The Correlations page displays relationships between alerts and vulnerability information.

The analyst can use the correlation to understand:

```text
Alert
  ↓
Affected Asset
  ↓
Known Vulnerability
```

This reduces the need to manually connect information across separate security records.

---

# 25. Security Events View

The Security Events page provides visibility into the events that were collected by the SOC pipeline.

The analyst can use events as supporting evidence for alerts.

The relationship is:

```text
Events
  ↓
Detection
  ↓
Alert
```

---

# 26. Investigation View

The Investigation view brings related security information together.

A typical investigation path is:

```text
Investigation
    │
    ├── Alert
    │
    ├── Correlation
    │
    ├── Asset
    │
    ├── Services
    │
    ├── Vulnerability
    │
    ├── Finding
    │
    └── Security Events
```

This provides a structured view for security analysis.

---

# 27. SOC Workflow End-to-End

The complete documented SOC workflow is:

```text
          SECURITY LOG
               │
               ▼
      AUTH LOG COLLECTOR
               │
               ▼
       SECURITY EVENTS
               │
               ▼
       DETECTION ENGINE
               │
       ┌───────┴────────┐
       │                │
       ▼                ▼
 SSH Brute Force    Port Scan
       │                │
       └───────┬────────┘
               │
               ▼
             ALERT
               │
               ▼
      CORRELATION ENGINE
               │
               ▼
       VULNERABILITY
          MATCHING
               │
               ▼
         CORRELATION
               │
               ▼
        INVESTIGATION
```

---

# 28. Documented Lab Results

The documented VulnWatch lab validation included:

```text
Alerts:
2

Alert Types:
SSH_BRUTE_FORCE
PORT_SCAN

Alert Severity:
HIGH
HIGH

Correlations:
2

Correlation Priority:
CRITICAL
```

These results represent the documented authorized lab validation of the project.

---

# 29. Security Controls

The SOC workflow benefits from the security controls implemented in the platform.

## API Authentication

Protected API operations require the configured API key.

## Parameterized SQL

Database queries use parameterized SQL to reduce SQL injection risk.

## Input Validation

API request data is validated before processing.

## Generic Errors

Internal implementation details are not intentionally exposed through API error responses.

## CORS Restriction

Untrusted origins are rejected according to the configured CORS policy.

## Container Security

The backend container runs as a non-root application user.

---

# 30. SOC Workflow Summary

The core VulnWatch SOC workflow is:

```text
LOG
 ↓
EVENT
 ↓
DETECTION
 ↓
ALERT
 ↓
CORRELATION
 ↓
INVESTIGATION
```

The VAPT + SOC combination extends this into:

```text
                    VAPT
                     │
                     ▼
               Vulnerabilities
                     │
                     │
                     ▼
Security Events → Alerts → Correlations
                              │
                              ▼
                        Investigation
                              │
                              ▼
                         Asset Context
```

The goal of the workflow is to provide a structured relationship between observed security activity and known vulnerability information within the authorized VulnWatch lab.

---

# 31. Analyst Interview Explanation

A concise explanation of the VulnWatch SOC workflow is:

> "VulnWatch collects authentication-related security events and stores them as structured events. The detection engine analyzes those events for patterns such as SSH brute force and port scanning. When configured thresholds are reached, it generates alerts. The correlation engine then connects alerts with known vulnerabilities on the same asset using destination and target IP relationships. Finally, the investigation workflow brings together the alert, asset, services, vulnerabilities, findings, and underlying security events so an analyst can investigate the complete available context."

---

# 32. Safety Scope

VulnWatch is an authorized cybersecurity lab and portfolio project.

The SOC workflow should only be used for:

* Systems owned by the user
* Explicitly authorized security-testing environments
* Isolated cybersecurity labs
* Educational security exercises

The documented Metasploitable target is used specifically as an intentionally vulnerable lab system.

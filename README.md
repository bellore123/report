# CyberShield Nexus
### NEDI AI Cyber Command Center - Academic Cybersecurity Demo

CyberShield Nexus is a Spring Boot cybersecurity operations prototype built around a fictional scenario: **NEDI - National Education Digital Infrastructure**. NEDI represents an education technology environment that centrally monitors digital services such as student portals, faculty portals, examination systems, ERP, admissions, digital library, LMS, and mail services across many institutions.

NEDI is a fictional scenario created for this academic cybersecurity demo. No real organization or government body owns or operates this system.

![Java](https://img.shields.io/badge/Java-21-orange?style=flat-square)
![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.2.5-green?style=flat-square)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-blue?style=flat-square)
![OWASP](https://img.shields.io/badge/OWASP-A01%20A02%20A07%20A09-red?style=flat-square)

---

## Scenario

NEDI manages critical education services:

- Student Portal
- Faculty Portal
- Examination Portal
- ERP
- Admission Portal
- Email Services
- Digital Library
- Learning Management System

Each service depends on servers, firewalls, routers/switches, databases, licenses, and hardware. CyberShield Nexus acts as the central SOC-style command center that receives safe simulated telemetry, calculates risk, creates incidents, and helps administrators respond.

---

## Quick Start

```bash
# 1. Start PostgreSQL and create the database
#    Database: cybershield_db
#    User: cybershield_user
#    Password: CyberShield@2024

# 2. Run the application
cd cybershield-nexus
mvn spring-boot:run

# 3. Open browser
http://localhost:8081/index.html

# 4. Login Credentials & Demo Roles
Username: admin        Password: Admin@123  (Full Administrator — CRUD all assets, User & Role Management)
Username: serveradmin  Password: Admin@123  (Infrastructure Admin — Servers, Firewalls, Load Balancers)
Username: viewer       Password: Admin@123  (Read-Only SOC Monitor — Observability & Telemetry)
```

---

## Frontend Pages

| Page | URL |
|------|-----|
| NEDI Home | `http://localhost:8081/index.html` |
| Login | `http://localhost:8081/login.html` |
| Dashboard | `http://localhost:8081/dashboard.html` |
| Servers | `http://localhost:8081/servers.html` |
| Firewalls | `http://localhost:8081/firewalls.html` |
| Licenses | `http://localhost:8081/licenses.html` |
| Hardware | `http://localhost:8081/hardware.html` |
| Incidents | `http://localhost:8081/incidents.html` |
| Risk & BFS | `http://localhost:8081/risk.html` |
| Audit Log | `http://localhost:8081/audit-log.html` |

---

## How The Demo Works

1. Open the NEDI home page and explain that the organization is fictional.
2. Login using one of the seeded accounts.
3. Show the dashboard, asset inventory, incidents, risk page, and audit log.
4. Run safe simulated attack scripts to generate security events.
5. Watch audit logs, account lockout, risk score, and incidents update.
6. Use the BFS attack-path endpoint/page to explain possible lateral movement.
7. Mark incidents as investigating or resolved from the incident workflow.

---

## Run Attack Scripts

```bash
cd attack-scripts

# Run all 3 safe simulations in sequence
python run_all_attacks.py

# Or run individually:
python brute_force.py   # OWASP A07 - Identification and Authentication Failures
python idor_test.py     # OWASP A01 - Broken Access Control
python tamper_jwt.py    # OWASP A02 - Cryptographic Failures
```

These scripts are for controlled local demonstration only.

---

## Risk Engine Formula

```text
Risk Score (0-100) =
  +30  if server is not patched in 90 days
  +25  if a linked license is expired
  +20  if repeated LOGIN_FAIL events appear in the audit log
  +15  if reachable from a low-trust graph node

Score 50+  -> auto-create LOW incident
Score 70+  -> auto-create MEDIUM incident
Score 85+  -> auto-create HIGH incident
Score 95+  -> auto-create CRITICAL incident
```

The current engine is rule-based. In later phases, the project should label recommendations as **AI-assisted** and generate them from the actual risk breakdown.

---

## BFS Attack Path

```text
Seeded graph example:
USER:3 -> FIREWALL:1 -> SERVER:1 -> SERVER:2 -> SERVER:3

API:
GET /api/graph/attack-path?startId=3&startType=USER&targetId=3&targetType=SERVER
```

This demonstrates how CyberShield Nexus can identify a shortest path from a compromised user or low-trust entry point to a critical server.

---

## OWASP Coverage

| ID | Name | Demo | Protection |
|----|------|------|------------|
| A01 | Broken Access Control | `idor_test.py` | `@PreAuthorize` role checks and protected write operations |
| A02 | Cryptographic Failures | `tamper_jwt.py` | HMAC-SHA384 JWT signature validation |
| A07 | Identification and Authentication Failures | `brute_force.py` | Account lockout, audit logging, auto incident creation |
| A09 | Security Logging and Monitoring Failures | Audit Log page | Login and API activity stored with user/IP/timestamp context |

---

## Project Structure

```text
cybershield-nexus/
├── src/main/java/com/cybershield/
│   ├── config/          # Security, web config, data seeders
│   ├── controller/      # REST controllers
│   ├── model/           # JPA entities
│   ├── repository/      # Spring Data repositories
│   ├── service/         # Business logic services
│   └── security/        # JWT filter and token provider
├── src/main/resources/static/
│   ├── css/style.css
│   ├── js/auth.js
│   ├── index.html
│   ├── login.html
│   ├── dashboard.html
│   ├── servers.html
│   ├── firewalls.html
│   ├── licenses.html
│   ├── hardware.html
│   ├── incidents.html
│   ├── risk.html
│   └── audit-log.html
├── attack-scripts/
│   ├── brute_force.py
│   ├── idor_test.py
│   ├── tamper_jwt.py
│   ├── run_all_attacks.py
│   └── CyberShield_Postman_Collection.json
└── PROJECT_REPORT.html
```

---

## Tech Stack

- Java 21 and Spring Boot 3.2.5
- Spring Security and JWT
- PostgreSQL and Hibernate/JPA
- BCrypt password hashing
- BFS algorithm for attack-path traversal
- Vanilla HTML/CSS/JavaScript frontend

---

---

## 🏛️ 10-Phase Implementation Status — ✅ 100% Complete

All 10 phases of the CyberShield Nexus for NEDI roadmap are fully implemented, integrated, and verified:

| Phase | Milestone | Status | Key Deliverables |
|:---:|---|:---:|---|
| **Phase 1** | **Project Identity & Ethics** | ✅ Complete | Fictional NEDI branding, ethical disclaimer, clean SOC theme |
| **Phase 2** | **Backend Domain Models** | ✅ Complete | `Institution`, `DigitalService`, `Server`, `Firewall`, `License`, `Hardware`, `Incident`, `AuditLog`, `AssetRelationship` |
| **Phase 3** | **Realistic NEDI Seed Data** | ✅ Complete | 8 NEDI digital services, 5 multi-tier servers, enterprise firewalls, software licenses, 15 graph edges |
| **Phase 4** | **SOC Operations Dashboard** | ✅ Complete | 8-service health telemetry grid, Exam Portal spotlight (92% risk), operations overview (`dashboard.html`) |
| **Phase 5** | **AI-Assisted Risk Engine** | ✅ Complete | 0–100 risk scoring, explainable AI recommendation service with MITRE ATT&CK (T1110, T1190, T1021) and NIST CSF 2.0 mapping |
| **Phase 6** | **Digital Twin & BFS Attack Path** | ✅ Complete | Interactive SVG network topology map, Breadth-First Search shortest path lateral movement visualizer (`risk.html`) |
| **Phase 7** | **NIST Incident Response Workflow**| ✅ Complete | NIST SP 800-61 Rev. 3 lifecycle (`OPEN` → `INVESTIGATING` → `CONTAINED` → `RESOLVED`), containment actions & forensic notes (`incidents.html`) |
| **Phase 8** | **Dynamic Live Report Generator** | ✅ Complete | `ReportService` & `ReportController`: `/api/reports/incident/{id}` (JSON) & `/api/reports/incident/{id}/html` (Printable SOC document) |
| **Phase 9** | **Automated Test Suite** | ✅ Complete | 14 Unit & Integration tests passing 100% across security, risk, BFS, and reporting |
| **Phase 10**| **Presentation Polish & Demos** | ✅ Complete | OWASP attack scripts (`attack-scripts/`), verified navigation across all 10 frontend pages |

---

## 🧪 Verification & Automated Testing

Run the full suite of automated unit and integration tests:
```bash
mvn test
```
**Results: 14/14 tests passing green** (`AuthAndSecurityTests`, `RiskEngineAndAttackPathTests`, `IncidentAndReportTests`, `CyberShieldNexusApplicationTests`).
"# cyber-project" 

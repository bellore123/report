# CyberShield Nexus — Enhancements Added

This document covers the 3 enhancements implemented in this pass, plus a
list of remaining ideas from the original menu that are not yet built.

## 1. Docker Support (one-command startup)

**Files added:** `Dockerfile`, `docker-compose.yml`, `.dockerignore`

```bash
docker compose up --build
# then open http://localhost:8081/index.html
```

- Multi-stage build (Maven build stage → slim JRE runtime stage), runs as
  a non-root user.
- Uses the existing embedded H2 file DB by default — zero external setup.
- Data persists across container restarts via the `cybershield_data`
  named volume.
- A commented-out `postgres` service + datasource env vars are included
  in `docker-compose.yml` if you want to switch to real PostgreSQL later.

## 2. Email Alerting on HIGH / CRITICAL Incidents

**Files added:** `AlertService.java`
**Files changed:** `IncidentService.java` (calls the alert after every
incident is saved), `application.properties` (new `alert.email.*` and
`spring.mail.*` keys)

- Off by default (`alert.email.enabled=false`) — the app still runs with
  zero setup; disabled alerts are simply logged instead of sent, so you
  can see the message it *would* have sent in the console.
- To activate: set `alert.email.enabled=true` in
  `application.properties` (or via env vars in Docker), and fill in
  `spring.mail.username` / `spring.mail.password` with real SMTP creds
  (Gmail example is pre-filled — use an **App Password**, not your real
  Gmail password).
- Only fires for `HIGH` and `CRITICAL` severity, to avoid alert fatigue
  from routine `LOW`/`MEDIUM` events.
- **To test:** run `brute_force.py` from `attack-scripts/` until an
  incident reaches HIGH/CRITICAL, then check the console log for the
  `[ALERT-SIMULATED]` or `Email alert sent` line.

## 3. PDF Incident Report Export

**Files changed:** `pom.xml` (added `openhtmltopdf-core` +
`openhtmltopdf-pdfbox`), `ReportService.java` (new
`generateIncidentReportPdf()` + a print-safe HTML builder),
`ReportController.java` (new `GET /api/reports/incident/{id}/pdf`),
`incidents.html` (new "⬇️ Download PDF" buttons)

- The existing `/html` report uses modern CSS (flexbox/grid/CSS
  variables) meant for the browser — the pure-Java PDF renderer only
  supports a CSS 2.1-level subset, so the PDF uses a separate,
  simpler table-based layout built from the same underlying report
  data (same numbers, same breakdown, same compliance attestations).
- Click "⬇️ Download PDF" on any incident (list view or detail modal)
  to get `incident-report-{id}.pdf`.

## 4. Phishing & Scam Link Detector (new module, built INTO this project)

**Files added:** `service/PhishingDetectionService.java`,
`controller/PhishingController.java`, `static/phishing-detector.html`
**Files changed:** `SecurityConfig.java` (permit the new static page),
`style.css` (added `.info-box`), nav sidebar added to every existing
page

- Same offline, heuristic scoring engine as the standalone version
  (12 checks: IP hostname, `@` symbol, long URLs, excessive subdomains,
  shorteners, suspicious TLDs, punycode, hyphens, no-HTTPS, lure
  keywords, non-standard ports, typosquatting) — ported from Python to
  Java so it runs as part of the same Spring Boot app, no separate
  server or port.
- Uses the exact same login/JWT session as the rest of CyberShield
  Nexus — click **Phishing Detector** in the sidebar after logging in.
- Endpoints: `POST /api/phishing/analyze` and
  `POST /api/phishing/analyze-batch`, open to any authenticated role
  (ADMIN/SERVER_ADMIN/VIEWER) since it's a personal-safety tool, not an
  asset-management action.

## Not yet built (from the original enhancement menu)

These remain open for a future pass — happy to build any of them next:

| # | Idea |
|---|---|
| 1 | Real AI/ML risk scoring (replace rule-based engine) |
| 3 | Real-time dashboard via WebSocket |
| 5 | More OWASP coverage (A03, A05, A08) |
| 8 | 2FA/MFA login |
| 9 | Live threat-intel feed integration |
| 10 | React frontend rebuild |

---

## Round 2: PS-Compliance Modules (matching PYHack02 problem statement)

The project's actual PS (AICTE Data Center Management Portal) lists 6
required features (points 5–10). Cross-checking against what existed
found 3 real gaps — these close them:

### 5. Firewall Rule Management (PS point 6)
**Added:** `model/FirewallRule.java`, `repository/FirewallRuleRepository.java`,
`service/FirewallRuleService.java`, `controller/FirewallRuleController.java`
**Changed:** `firewalls.html` (new "🛡 Rules" button + modal per firewall)

- Previously `Firewall.activeRulesCount` was just a manually-typed
  number — now each firewall has real, individually manageable rules
  (source/dest IP, port, protocol, ALLOW/DENY, priority, enabled toggle).
- `activeRulesCount` is now auto-synced from the real rule count
  whenever a rule is added/removed, so old dashboard/risk logic that
  reads that field keeps working unchanged.
- Endpoints: `GET/POST /api/firewalls/{firewallId}/rules`,
  `PUT/DELETE /api/firewall-rules/{id}`.

### 6. Load Balancer Management (PS point 7)
**Added:** `model/LoadBalancer.java`, `model/LoadBalancerBackend.java`,
repositories, `service/LoadBalancerService.java`,
`controller/LoadBalancerController.java`, `loadbalancers.html`

- Previously load balancers only existed as one tag inside generic
  Hardware inventory. Now they're a first-class module: distribution
  algorithm (Round Robin / Least Connections / IP Hash / Weighted),
  health-check config, status, and a manageable backend server pool
  with per-backend health toggling (Healthy/Unhealthy).
- New sidebar page under **Assets → Load Balancers**.
- Endpoints: `GET/POST/PUT/DELETE /api/loadbalancers`,
  `GET/POST /api/loadbalancers/{id}/backends`,
  `PUT /api/loadbalancer-backends/{id}/health`,
  `DELETE /api/loadbalancer-backends/{id}`.

### 7. User & Role Management (PS point 9)
**Added:** `dto/UserRequest.java`, `service/UserService.java`,
`controller/UserController.java`, `users.html`
**Changed:** `User.java` (`@JsonIgnore` on `passwordHash` — defense in
depth now that user objects are returned over the API)

- Previously user accounts only existed via the DB seed script — no
  admin UI to create accounts, change roles, or deactivate access.
  Now ADMIN accounts get a full **Users & Roles** page: create users,
  assign ADMIN/SERVER_ADMIN/VIEWER, edit department, activate/
  deactivate, optional password reset. Self-deletion is blocked.
- Every action logged to the audit trail like all other modules.
- ADMIN-only at both the API (`@PreAuthorize("hasRole('ADMIN')")`)
  and page level (non-admins are redirected off `users.html`).
- Endpoints: `GET/POST/PUT/DELETE /api/users`.

### 8. Role-Based Access Control (RBAC) & Real-Time Sync
**Files changed:** `JwtAuthenticationFilter.java`, `SecurityConfig.java`, `auth.js`, `style.css`, `AuthAndSecurityTests.java`, and all frontend pages (`servers.html`, `firewalls.html`, `loadbalancers.html`, `hardware.html`, `licenses.html`, `incidents.html`, `risk.html`, `users.html`, `login.html`).

- **Real-Time Role Sync & Deactivation**: `JwtAuthenticationFilter` dynamically queries `UserRepository` for every request. Admin role updates take effect immediately without requiring user re-login or 24h JWT expiration. Deactivated accounts (`isActive=false`) are instantly rejected with HTTP 401.
- **Custom AccessDeniedHandler**: Replaced raw whitelabel HTML error pages with clean JSON: `{"error": "Access Denied: You do not have permission to perform this action"}` on HTTP 403.
- **Role-Adaptive Frontend UI**:
  - Automatically hides `👤 Users & Roles` in the sidebar navigation for non-admin accounts.
  - Buttons for mutating operations (Add, Edit, Delete, Investigate, Contain, Resolve, Evaluate) adapt dynamically based on whether the logged-in user is `ADMIN`, `SERVER_ADMIN`, or `VIEWER`.
  - Color-coded topbar badges for easy identification of operator privilege level.
- **Test Suite**: Fully verified with 19 passing unit and integration tests (`mvn test`).

### 9. Ingress & Load Balancer Infrastructure Expansion
**Files changed:** `LoadBalancer.java`, `AssetDataSeeder.java`, `loadbalancers.html`, `style.css`.
- Seeded 6 comprehensive load balancers and ingress gateways with 14 backend server targets:
  1. `NEDI-INGRESS-LB-01 (External Edge Ingress)` — Dual-stack L7 public ingress fronting Student & Admission portals, TLS 1.3 termination, WAF filtering, rate-limiting.
  2. `NEDI-EXAM-INGRESS-LB-02 (Exam Portal Edge Ingress)` — Session-sticky edge ingress gateway for National Examination platform (marked DEGRADED due to unpatched app node contention).
  3. `NEDI-FACULTY-ERP-LB-01 (Administrative ERP & Faculty Cluster)` — Internal L7 application load balancer.
  4. `NEDI-DB-CLUSTER-LB-01 (Database Read-Replica Proxy)` — High-availability L4 TCP query distributor across database read-replicas.
  5. `NEDI-AUTH-SSO-LB-01 (Identity & SSO Ingress Gateway)` — Zero-trust client IP hashed SSO gateway.
  6. `NEDI-LMS-STREAM-LB-01 (Learning Management & Media CDN)` — High-throughput video streaming and quiz CDN balancer.
- Enhanced `loadbalancers.html` with real-time KPI overview metrics, Ingress vs Internal type pill tags, search and multi-state filter buttons (`Ingress Only`, `Active`, `Degraded/Maint`), and detailed backend health monitoring.

### 10. User Directory Expansion & NIST SP 800-162 RBAC Matrix
**Files changed:** `DataInitializer.java`, `users.html`, `style.css`.
- Expanded user repository from 1–3 accounts to 11+ realistic multi-department enterprise users:
  - `admin`, `soc_lead` (ADMIN — IT Security & Cyber Defense SOC)
  - `serveradmin`, `net_admin`, `db_admin`, `incident_responder`, `cloud_engineer` (SERVER_ADMIN — Infrastructure, DB, Network, IR Ops)
  - `viewer`, `compliance_auditor`, `academic_lead`, `exam_coordinator`, `guest_auditor` (VIEWER — Monitoring, Audit, Academics, Examination)
- Implemented an interactive Role Definitions & Access Control Matrix (RBAC) in `users.html` outlining entitlements (CRUD, user administration, incident containment, audit trails) and live role counts.

### 11. Audit Log Request URL Telemetry & Multi-User Traceability
**Files changed:** `AuditLog.java`, `AuditLogRepository.java`, `AuditLogService.java`, `AssetDataSeeder.java`, `audit-log.html`, `dashboard.html`.
- Added persistent `requestUrl` tracking to `AuditLog` model and repository.
- Seeded 32+ rich, diverse audit records with request endpoints (e.g. `POST /api/auth/login`, `GET /api/loadbalancers`, `PUT /api/incidents/1/contain`, `POST /api/firewall-rules`, `GET /api/reports/incident/1/pdf`) across 10 distinct user identities and external IPs.
- Updated `audit-log.html` and `dashboard.html` with styled HTTP method pills, URL badges, KPI metric summaries, and search filter by URL/User/IP/Action.

### 12. Security Incident Command Center Data Population
**Files changed:** `IncidentRepository.java`, `IncidentService.java`, `AssetDataSeeder.java`, `incidents.html`, `style.css`.
- Seeded 8 comprehensive real-world security incidents spanning all NIST SP 800-61 lifecycle stages:
  - `[CRITICAL] Lateral Movement Pivot: Student Portal Web to Exam Database` (OPEN — Risk Score 96)
  - `[HIGH] Multi-Source Credential Stuffing on Single Sign-On Ingress` (OPEN — Risk Score 88)
  - `[HIGH] Exploitation Probe on Unpatched Exam App Server (CentOS 7.9)` (INVESTIGATING — Risk Score 85)
  - `[HIGH] Insecure Direct Object Reference (IDOR) on Student Gradebook API` (INVESTIGATING — Risk Score 82)
  - `[MEDIUM] Slowloris DoS Attack on NEDI-INGRESS-LB-01 Pool` (CONTAINED — Risk Score 74)
  - `[MEDIUM] SQL Injection Beacon Detected — College A - South Campus` (CONTAINED — Risk Score 72)
  - `[LOW] Compliance Violation: Critical Database Software License Expired` (RESOLVED — Risk Score 58)
  - `[MEDIUM] Rogue SSH Brute-Force Attempt via Admin Management Subnet` (RESOLVED — Risk Score 70)
- Enhanced `incidents.html` with real-time KPI overview counters, lifecycle filter buttons (`Open`, `Investigating`, `Contained`, `Resolved`, `All`), live text search, MITRE ATT&CK traversal graphs, and forensic remediation log notes.

## Build & Test Status

The entire project builds and tests cleanly with Java 21 and Spring Boot 3.2.5:
```bash
mvn test
# Tests run: 19, Failures: 0, Errors: 0, Skipped: 0
```


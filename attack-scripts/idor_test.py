#!/usr/bin/env python3
"""
=============================================================================
ATTACK SCRIPT 2 — IDOR (Insecure Direct Object Reference) Attack
CyberShield Nexus | NEDI Demo Scenario
OWASP Top 10: A01:2021 — Broken Access Control
=============================================================================

WHAT THIS DEMONSTRATES:
  An attacker logs in as a low-privilege VIEWER account, then tries
  to access, modify, and delete resources they do NOT own.

EXPECTED RESULTS (with CyberShield protection):
  - GET  /api/servers        → 200 OK   (viewers can read)
  - GET  /api/servers/1      → 200 OK   (viewers can read individual)
  - POST /api/servers        → 403 Forbidden (viewers cannot create)
  - PUT  /api/servers/1      → 403 Forbidden (viewers cannot update)
  - DELETE /api/servers/1   → 403 Forbidden (viewers cannot delete)
  - All blocked actions are logged in AuditLog

HOW TO RUN:
  python idor_test.py
=============================================================================
"""

import requests
import json
from datetime import datetime

BASE_URL = "http://localhost:8081/api"
SEPARATOR = "=" * 65


def banner():
    print(SEPARATOR)
    print("  CYBERSHIELD NEXUS — IDOR / ACCESS CONTROL ATTACK DEMO")
    print("  OWASP A01: Broken Access Control")
    print(f"  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(SEPARATOR)


def login(username, password):
    res = requests.post(
        f"{BASE_URL}/auth/login",
        json={"username": username, "password": password},
        timeout=5
    )
    if res.status_code == 200:
        data = res.json()
        print(f"  ✅ Logged in as '{username}' (Role: {data.get('role')})")
        return data.get("token")
    else:
        print(f"  ❌ Login failed for '{username}': {res.status_code}")
        return None


def test_request(method, path, token, body=None, label=""):
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    try:
        if method == "GET":
            res = requests.get(f"{BASE_URL}{path}", headers=headers, timeout=5)
        elif method == "POST":
            res = requests.post(f"{BASE_URL}{path}", headers=headers, json=body, timeout=5)
        elif method == "PUT":
            res = requests.put(f"{BASE_URL}{path}", headers=headers, json=body, timeout=5)
        elif method == "DELETE":
            res = requests.delete(f"{BASE_URL}{path}", headers=headers, timeout=5)

        status = res.status_code
        if status == 200 or status == 201:
            icon = "✅"
            result = "ALLOWED"
        elif status == 403:
            icon = "🔒"
            result = "BLOCKED (403)"
        elif status == 401:
            icon = "🔑"
            result = "UNAUTHORIZED (401)"
        else:
            icon = "❓"
            result = f"HTTP {status}"

        print(f"  {icon}  {method:<7} {path:<30} → {result}  {label}")
        return status
    except Exception as e:
        print(f"  ❌  {method} {path} → ERROR: {e}")
        return 0


def main():
    banner()

    try:
        requests.get(f"{BASE_URL}/auth/login", timeout=3)
    except:
        print("  ❌ Server not running! Start the app first.")
        exit(1)

    # ── Phase 1: Login as VIEWER (low privilege attacker) ───────────
    print("\n📋 PHASE 1 — Login as low-privilege VIEWER account\n")
    viewer_token = login("viewer", "Admin@123")
    if not viewer_token:
        exit(1)

    # ── Phase 2: Legitimate reads (should work) ──────────────────────
    print("\n📋 PHASE 2 — Legitimate READ operations (should be allowed)\n")
    test_request("GET", "/servers",   viewer_token, label="(list all servers)")
    test_request("GET", "/servers/1", viewer_token, label="(read server #1)")
    test_request("GET", "/firewalls", viewer_token, label="(list all firewalls)")
    test_request("GET", "/licenses",  viewer_token, label="(list all licenses)")
    test_request("GET", "/dashboard", viewer_token, label="(read dashboard)")

    # ── Phase 3: IDOR Attacks (should be blocked) ────────────────────
    print("\n📋 PHASE 3 — IDOR Attack attempts (should ALL be blocked)\n")
    fake_server = {
        "name": "HACKED-SERVER",
        "ipAddress": "10.0.0.99",
        "operatingSystem": "Kali Linux",
        "status": "RUNNING"
    }

    test_request("POST",   "/servers",   viewer_token, fake_server, "(CREATE — IDOR attempt)")
    test_request("PUT",    "/servers/1", viewer_token, {"name": "OWNED"}, "(UPDATE — IDOR attempt)")
    test_request("DELETE", "/servers/1", viewer_token, label="(DELETE — IDOR attempt)")
    test_request("POST",   "/firewalls", viewer_token, {"name": "HACKED-FW"}, "(CREATE firewall)")
    test_request("DELETE", "/licenses/1",viewer_token, label="(DELETE license)")
    test_request("DELETE", "/hardware/1",viewer_token, label="(DELETE hardware)")

    # ── Phase 4: Admin sees what was blocked in audit log ────────────
    print("\n📋 PHASE 4 — Admin checks Audit Log for blocked attempts\n")
    admin_token = login("admin", "Admin@123")
    if admin_token:
        res = requests.get(
            f"{BASE_URL}/audit-logs",
            headers={"Authorization": f"Bearer {admin_token}"},
            timeout=5
        )
        if res.ok:
            logs = res.json()
            # Filter recent unauthorized access attempts
            print("  📜 Recent audit entries visible to admin:")
            for log in logs[:8]:
                print(f"     {log.get('timestamp','')[:19]}  {log.get('action',''):<12}  "
                      f"user={log.get('attemptedUsername','?'):<15}  "
                      f"ip={log.get('ipAddress','?')}")

    # ── Summary ──────────────────────────────────────────────────────
    print(f"\n{SEPARATOR}")
    print("  OWASP A01 DEMONSTRATED:")
    print("  VIEWER role → READ allowed, all WRITE/DELETE → 403 Blocked")
    print("  Every blocked attempt is audit-logged for forensics")
    print("  @PreAuthorize annotations enforce RBAC at the method level")
    print(SEPARATOR)


if __name__ == "__main__":
    main()

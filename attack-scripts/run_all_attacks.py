#!/usr/bin/env python3
"""
=============================================================================
RUN ALL ATTACKS — CyberShield Nexus Demo Runner
NEDI Demo Scenario
=============================================================================
Runs all 3 attack scripts in sequence with clear section headers.
Usage:  python run_all_attacks.py
=============================================================================
"""

import subprocess
import sys
import time

SCRIPTS = [
    ("ATTACK 1: Brute Force (OWASP A07)", "brute_force.py"),
    ("ATTACK 2: IDOR Access Control (OWASP A01)", "idor_test.py"),
    ("ATTACK 3: JWT Tampering (OWASP A02)", "tamper_jwt.py"),
    ("ATTACK 4: Multi-Tenant College Attack Suite (College A & College E)", "attack_colleges.py"),
]

SEP = "=" * 65

print(SEP)
print("  CYBERSHIELD NEXUS — FULL ATTACK DEMO SUITE")
print("  NEDI Demo Scenario | All 3 OWASP attacks in sequence")
print(SEP)
print()

for title, script in SCRIPTS:
    print(f"\n{'#' * 65}")
    print(f"  {title}")
    print(f"{'#' * 65}\n")
    time.sleep(1)
    result = subprocess.run([sys.executable, script], cwd=".")
    if result.returncode != 0:
        print(f"\n  ⚠️  Script {script} exited with code {result.returncode}")
    time.sleep(2)

print(f"\n{SEP}")
print("  ALL ATTACKS DEMONSTRATED SUCCESSFULLY")
print("  Open http://localhost:8081/incidents.html to see auto-created incidents")
print("  Open http://localhost:8081/audit-log.html to see all logged events")
print(SEP)

#!/usr/bin/env python3
"""
=============================================================================
ATTACK SCRIPT 3 — JWT Tampering Attack
CyberShield Nexus | NEDI Demo Scenario
OWASP Top 10: A02:2021 — Cryptographic Failures
=============================================================================

WHAT THIS DEMONSTRATES:
  An attacker obtains a valid VIEWER JWT token, then tries to:
  1. Decode the token (no secret needed — base64 encoded)
  2. Modify the payload (change role from VIEWER → ADMIN)
  3. Re-encode and replay the forged token
  4. CyberShield rejects it because HMAC-SHA384 signature doesn't match

HOW TO RUN:
  pip install requests
  python tamper_jwt.py

EXPECTED RESULT:
  - Forged token → 401 Unauthorized (signature invalid)
  - Valid token  → 200 OK
  - Demonstrates why JWT secret must NEVER be exposed
=============================================================================
"""

import requests
import base64
import json
import hmac
import hashlib
import time
from datetime import datetime

BASE_URL = "http://localhost:8081/api"
SEPARATOR = "=" * 65


def banner():
    print(SEPARATOR)
    print("  CYBERSHIELD NEXUS — JWT TAMPER ATTACK DEMO")
    print("  OWASP A02: Cryptographic Failures")
    print(f"  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(SEPARATOR)


def b64_decode_padding(s):
    """JWT uses URL-safe base64 without padding."""
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def b64_encode_nopad(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def decode_jwt(token):
    """Decode JWT without verifying signature."""
    parts = token.split(".")
    if len(parts) != 3:
        return None, None, None
    header  = json.loads(b64_decode_padding(parts[0]))
    payload = json.loads(b64_decode_padding(parts[1]))
    return header, payload, parts[2]


def forge_token(original_token, new_role="ADMIN"):
    """
    Forge a JWT by modifying the payload.
    The signature will be invalid because we don't know the secret.
    """
    parts = original_token.split(".")
    header, payload, original_sig = decode_jwt(original_token)

    print(f"\n  🔍 Original token decoded:")
    print(f"     Header  : {json.dumps(header)}")
    print(f"     Subject : {payload.get('sub')}")
    print(f"     Role    : {payload.get('role')}")
    print(f"     Expires : {datetime.fromtimestamp(payload.get('exp', 0))}")

    # Modify the payload — change role to ADMIN
    forged_payload = payload.copy()
    forged_payload["role"] = new_role
    forged_payload["ROLE"] = f"ROLE_{new_role}"  # Try both formats

    # Re-encode header and new payload
    forged_header_enc  = b64_encode_nopad(json.dumps(header, separators=(",", ":")).encode())
    forged_payload_enc = b64_encode_nopad(json.dumps(forged_payload, separators=(",", ":")).encode())

    # Attach original signature (it won't match the new payload)
    forged_token = f"{forged_header_enc}.{forged_payload_enc}.{original_sig}"

    print(f"\n  ✏️  Forged token payload:")
    print(f"     Role changed : {payload.get('role')} → {new_role}")
    print(f"     Signature    : UNCHANGED (attacker doesn't know the secret)")

    return forged_token


def test_endpoint(token, label, server_id=1):
    """Try to access an ADMIN-only endpoint."""
    try:
        res = requests.delete(
            f"{BASE_URL}/servers/{server_id}",
            headers={"Authorization": f"Bearer {token}"},
            timeout=5
        )
        return res.status_code
    except Exception as e:
        return 0


def main():
    banner()

    try:
        requests.get(f"{BASE_URL}/auth/login", timeout=3)
    except:
        print("  ❌ Server not running! Start the app first.")
        exit(1)

    # ── Step 1: Get legitimate VIEWER token ──────────────────────────
    print("\n📋 STEP 1 — Attacker logs in as VIEWER (legitimate)\n")
    res = requests.post(
        f"{BASE_URL}/auth/login",
        json={"username": "viewer", "password": "Admin@123"},
        timeout=5
    )
    if res.status_code != 200:
        print(f"  ❌ Login failed: {res.status_code}")
        exit(1)

    viewer_token = res.json().get("token")
    print(f"  ✅ VIEWER token obtained: {viewer_token[:50]}...")

    # ── Step 2: Prove VIEWER is blocked ──────────────────────────────
    print("\n📋 STEP 2 — Confirm VIEWER is blocked from ADMIN endpoint\n")
    status = test_endpoint(viewer_token, "VIEWER tries DELETE /servers/1")
    icon = "🔒" if status == 403 else ("✅" if status < 300 else "❓")
    print(f"  {icon}  DELETE /api/servers/1 with VIEWER token → HTTP {status}")

    # ── Step 3: Forge the token ───────────────────────────────────────
    print("\n📋 STEP 3 — Forging JWT: change role to ADMIN\n")
    forged_token = forge_token(viewer_token, "ADMIN")
    print(f"\n  🔧 Forged token: {forged_token[:60]}...")

    # ── Step 4: Replay forged token ───────────────────────────────────
    print("\n📋 STEP 4 — Replaying forged token against ADMIN endpoint\n")

    # Try multiple admin-only endpoints
    endpoints = [
        ("DELETE", f"{BASE_URL}/servers/5", "DELETE /api/servers/5"),
        ("POST",   f"{BASE_URL}/servers",   "POST   /api/servers"),
        ("GET",    f"{BASE_URL}/dashboard", "GET    /api/dashboard"),
    ]

    for method, url, label in endpoints:
        try:
            if method == "GET":
                r = requests.get(url, headers={"Authorization": f"Bearer {forged_token}"}, timeout=5)
            elif method == "DELETE":
                r = requests.delete(url, headers={"Authorization": f"Bearer {forged_token}"}, timeout=5)
            else:
                r = requests.post(url, headers={"Authorization": f"Bearer {forged_token}"},
                                  json={"name": "FORGED", "ipAddress": "1.1.1.1", "status": "RUNNING"},
                                  timeout=5)

            icon = "🔒" if r.status_code == 401 else ("✅" if r.status_code < 300 else "❓")
            print(f"  {icon}  {label} → HTTP {r.status_code}")
        except Exception as e:
            print(f"  ❌  {label} → ERROR: {e}")

    # ── Step 5: Verify real admin token still works ───────────────────
    print("\n📋 STEP 5 — Verify REAL admin token still works correctly\n")
    real_res = requests.post(
        f"{BASE_URL}/auth/login",
        json={"username": "admin", "password": "Admin@123"},
        timeout=5
    )
    if real_res.status_code == 200:
        real_token = real_res.json().get("token")
        r2 = requests.get(
            f"{BASE_URL}/dashboard",
            headers={"Authorization": f"Bearer {real_token}"},
            timeout=5
        )
        print(f"  ✅  Real ADMIN token → GET /api/dashboard → HTTP {r2.status_code}")

    # ── Summary ───────────────────────────────────────────────────────
    print(f"\n{SEPARATOR}")
    print("  OWASP A02 DEMONSTRATED:")
    print("  JWT payload CAN be decoded (base64 — not encrypted)")
    print("  JWT payload CAN be modified (role: VIEWER → ADMIN)")
    print("  But SIGNATURE verification FAILS → 401 Unauthorized")
    print("  Fix: Strong HMAC-SHA384 secret + token expiry + JWKs")
    print(SEPARATOR)


if __name__ == "__main__":
    main()

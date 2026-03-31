"""
probe_api.py
------------
Discovers working endpoints on the connected Pineapple.
Run this to map what's actually available on firmware 2.1.3.

Usage:
    python probe_api.py
"""

import sys
import json
import requests

sys.path.insert(0, ".")
from core.config import load_config
from core.logger import get_logger

logger = get_logger("probe_api", log_dir="./logs")

def main():
    cfg    = load_config()
    base   = f"http://{cfg.pineapple.host}:{cfg.pineapple.port}/api"

    # Step 1: Authenticate
    r = requests.post(f"{base}/login", json={
        "username": cfg.pineapple.username,
        "password": cfg.pineapple.password,
    })
    token   = r.json().get("token") or r.json().get("api_token")
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    print(f"\n✓ Authenticated — token: {token[:12]}...\n")

    # Step 2: Probe GET endpoints
    get_endpoints = [
        "device",
        "modules",
        "pineap/settings",
        "pineap/ssids",
        "pineap/clients",
        "pineap/handshakes",
        "pineap/handshakes/list",
        "pineap/filters",
        "notifications",
        "campaigns",
        "recon",
        "recon/networks",
        "recon/clients",
        "system/stats",
        "system/info",
    ]

    print("═" * 60)
    print("GET ENDPOINT PROBE")
    print("═" * 60)
    for ep in get_endpoints:
        try:
            r = requests.get(f"{base}/{ep}", headers=headers, timeout=5)
            status = r.status_code
            body   = r.text[:120].replace("\n", " ")
            marker = "✓" if status == 200 else "✗"
            print(f"  {marker} [{status}] GET /{ep}")
            if status == 200:
                print(f"         → {body}")
        except Exception as e:
            print(f"  ! ERROR GET /{ep}: {e}")

    # Step 3: Probe POST endpoints relevant to deauth/handshake
    post_endpoints = [
        ("pineap/deauth",                    {"bssid": "00:00:00:00:00:00", "client": "FF:FF:FF:FF:FF:FF"}),
        ("pineap/handshakes/deauth",         {"bssid": "00:00:00:00:00:00", "client": "FF:FF:FF:FF:FF:FF"}),
        ("pineap/handshake/deauth",          {"bssid": "00:00:00:00:00:00", "client": "FF:FF:FF:FF:FF:FF"}),
        ("pineap/settings/deauth",           {"bssid": "00:00:00:00:00:00"}),
        ("campaign/deauth",                  {"bssid": "00:00:00:00:00:00"}),
        ("pineap/handshakes/capture",        {"bssid": "00:00:00:00:00:00"}),
        ("pineap/capture",                   {"bssid": "00:00:00:00:00:00"}),
    ]

    print("\n" + "═" * 60)
    print("POST ENDPOINT PROBE (deauth candidates)")
    print("═" * 60)
    for ep, payload in post_endpoints:
        try:
            r = requests.post(f"{base}/{ep}", headers=headers, json=payload, timeout=5)
            status = r.status_code
            body   = r.text[:120].replace("\n", " ")
            marker = "✓" if status in (200, 201) else "✗"
            print(f"  {marker} [{status}] POST /{ep}")
            if status in (200, 201):
                print(f"         → {body}")
        except Exception as e:
            print(f"  ! ERROR POST /{ep}: {e}")

    # Step 4: Dump full handshake list so we can see the real structure
    print("\n" + "═" * 60)
    print("HANDSHAKE LIST (raw structure)")
    print("═" * 60)
    r = requests.get(f"{base}/pineap/handshakes", headers=headers, timeout=10)
    print(json.dumps(r.json(), indent=2)[:2000])

    # Step 5: Dump PineAP settings so we can see all available fields
    print("\n" + "═" * 60)
    print("PINEAP SETTINGS (raw structure)")
    print("═" * 60)
    r = requests.get(f"{base}/pineap/settings", headers=headers, timeout=10)
    print(json.dumps(r.json(), indent=2)[:2000])

if __name__ == "__main__":
    main()
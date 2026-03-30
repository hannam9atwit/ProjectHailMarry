"""
Simulates a full pipeline run WITHOUT a real WiFi Pineapple or tshark.

Injects realistic mock data at every stage:
  - Fake recon results (networks + clients)
  - Fake handshake capture metadata
  - Fake pcap statistics
  - Fake log file (auto-generated)

Then runs the REAL report generator on that data, so you can verify
the entire reporting pipeline works before the Pineapple is ready.

Usage:
    python mock_run.py
    python mock_run.py --open   # auto-open the report in browser
"""

import os
import sys
import argparse
import webbrowser
from pathlib import Path
from datetime import datetime

# Make sure imports work from project root
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from reporting.report_gen import ReportGenerator
from parsers.log_parser import LogParser
from core.logger import get_logger

logger = get_logger("mock_run", log_dir="./logs")


# ── Mock data ────────────────────────────────────────────────────────

MOCK_NETWORKS = [
    {"ssid": "LabRouter_2G",    "bssid": "AA:BB:CC:DD:EE:01", "channel": 6,  "signal": -42, "encryption": "WPA2"},
    {"ssid": "LabRouter_5G",    "bssid": "AA:BB:CC:DD:EE:02", "channel": 36, "signal": -55, "encryption": "WPA2"},
    {"ssid": "NETGEAR_GUEST",   "bssid": "11:22:33:44:55:01", "channel": 1,  "signal": -68, "encryption": "OPEN"},
    {"ssid": "ATT-WIFI-3F92",   "bssid": "11:22:33:44:55:02", "channel": 11, "signal": -74, "encryption": "WPA2"},
    {"ssid": "xfinitywifi",     "bssid": "DE:AD:BE:EF:00:01", "channel": 6,  "signal": -80, "encryption": "OPEN"},
    {"ssid": "DIRECT-Printer",  "bssid": "DE:AD:BE:EF:00:02", "channel": 1,  "signal": -77, "encryption": "WPA2"},
]

MOCK_CLIENTS = [
    {"mac": "C0:FF:EE:00:00:01", "ssid": "LabRouter_2G",  "signal": -38, "packets": 1420},
    {"mac": "C0:FF:EE:00:00:02", "ssid": "LabRouter_2G",  "signal": -51, "packets": 302},
    {"mac": "C0:FF:EE:00:00:03", "ssid": "LabRouter_5G",  "signal": -60, "packets": 88},
    {"mac": "C0:FF:EE:00:00:04", "ssid": "xfinitywifi",   "signal": -79, "packets": 14},
    {"mac": "C0:FF:EE:00:00:05", "ssid": None,            "signal": -85, "packets": 6},   # unassociated
]

MOCK_CAPTURES = [
    {
        "filename":   "LabRouter_2G_handshake.cap",
        "ssid":       "LabRouter_2G",
        "bssid":      "AA:BB:CC:DD:EE:01",
        "timestamp":  datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "local_path": "./captures/LabRouter_2G_handshake.cap",
    }
]

MOCK_PCAP_STATS = {
    "file":            "./captures/LabRouter_2G_handshake.cap",
    "file_size_kb":    87.4,
    "total_frames":    512,
    "eapol_frames":    4,
    "mgmt_frames":     134,
    "unique_macs":     8,
    "handshake_found": True,
}

MOCK_LOG_LINES = [
    "2026-03-30 10:00:01 [INFO] Pineapple booted. Firmware 2.1.0",
    "2026-03-30 10:00:05 [INFO] PineAP daemon started",
    "2026-03-30 10:00:10 [INFO] Recon module started on wlan1mon",
    "2026-03-30 10:00:12 [INFO] Found SSID: LabRouter_2G BSSID: AA:BB:CC:DD:EE:01 CH: 6",
    "2026-03-30 10:00:14 [INFO] Found SSID: LabRouter_5G BSSID: AA:BB:CC:DD:EE:02 CH: 36",
    "2026-03-30 10:00:16 [INFO] Client C0:FF:EE:00:00:01 associated with LabRouter_2G",
    "2026-03-30 10:00:18 [WARN] Weak signal from client C0:FF:EE:00:00:04 (-79 dBm)",
    "2026-03-30 10:00:20 [INFO] Deauth sent to BSSID AA:BB:CC:DD:EE:01",
    "2026-03-30 10:00:22 [INFO] EAPOL frame 1/4 captured from AA:BB:CC:DD:EE:01",
    "2026-03-30 10:00:22 [INFO] EAPOL frame 2/4 captured from C0:FF:EE:00:00:01",
    "2026-03-30 10:00:23 [INFO] EAPOL frame 3/4 captured from AA:BB:CC:DD:EE:01",
    "2026-03-30 10:00:23 [INFO] EAPOL frame 4/4 captured from C0:FF:EE:00:00:01",
    "2026-03-30 10:00:24 [INFO] Handshake capture complete: LabRouter_2G_handshake.cap",
    "2026-03-30 10:00:30 [ERROR] Module evil_portal failed to load: missing dependency",
    "2026-03-30 10:00:35 [WARN] USB storage 80% full",
    "2026-03-30 10:00:40 [INFO] Recon module stopped",
]


# ── Helpers ──────────────────────────────────────────────────────────

def write_mock_log(log_path: str):
    """Write the mock log lines to a temporary log file."""
    Path(log_path).parent.mkdir(parents=True, exist_ok=True)
    with open(log_path, "w") as f:
        f.write("\n".join(MOCK_LOG_LINES))
    logger.info(f"Mock log written to {log_path}")


def run_log_analysis(log_path: str) -> dict:
    """Run the real LogParser against the mock log file."""
    parser   = LogParser()
    os.makedirs("./logs", exist_ok=True)
    entries  = parser.normalize_to_json(log_path, "./logs/mock_parsed.json")

    errors   = parser.filter_by_level(entries, "ERROR")
    warnings = parser.filter_by_level(entries, "WARN")
    macs     = parser.get_unique_macs(entries)
    ssids    = parser.get_unique_ssids(entries)

    logger.info(f"Log analysis — {len(entries)} entries, {len(errors)} error(s), {len(warnings)} warning(s)")
    logger.info(f"Unique MACs in logs: {macs}")
    logger.info(f"Unique SSIDs in logs: {ssids}")

    return {
        "total":       len(entries),
        "errors":      len(errors),
        "warnings":    len(warnings),
        "unique_macs": len(macs),
        "json_output": "./logs/mock_parsed.json",
    }


# ── Main mock run ────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="Mock pipeline run — no Pineapple required")
    ap.add_argument("--open", action="store_true", help="Open report in browser when done")
    ap.add_argument("--no-pdf", action="store_true", help="Skip PDF generation")
    args = ap.parse_args()

    logger.info("╔══════════════════════════════════════════════╗")
    logger.info("║  MOCK RUN — No Pineapple Required            ║")
    logger.info("║  Testing full pipeline with simulated data   ║")
    logger.info("╚══════════════════════════════════════════════╝")

    # ── Step 1: Inject mock recon ────────────────────────────────────
    logger.info("─" * 48)
    logger.info("MOCK PHASE 1 — Recon (simulated)")
    logger.info(f"  {len(MOCK_NETWORKS)} networks, {len(MOCK_CLIENTS)} clients")

    # ── Step 2: Inject mock handshake ────────────────────────────────
    logger.info("─" * 48)
    logger.info("MOCK PHASE 2 — Handshake capture (simulated)")
    logger.info(f"  {len(MOCK_CAPTURES)} capture(s) — handshake_found=True")

    # ── Step 3: Inject mock pcap stats ───────────────────────────────
    logger.info("─" * 48)
    logger.info("MOCK PHASE 3 — pcap analysis (simulated)")
    logger.info(
        f"  {MOCK_PCAP_STATS['total_frames']} frames, "
        f"{MOCK_PCAP_STATS['eapol_frames']} EAPOL, "
        f"{MOCK_PCAP_STATS['unique_macs']} unique MACs"
    )

    # ── Step 4: Real log parser on mock log file ──────────────────────
    logger.info("─" * 48)
    logger.info("MOCK PHASE 4 — Log analysis (REAL parser, mock log file)")
    mock_log_path = "./logs/mock_pineapple.log"
    write_mock_log(mock_log_path)
    log_stats = run_log_analysis(mock_log_path)

    # ── Step 5: Real report generator ────────────────────────────────
    logger.info("─" * 48)
    logger.info("MOCK PHASE 5 — Report generation (REAL generator)")

    os.makedirs("./reports", exist_ok=True)
    reporter = ReportGenerator(
        template_dir="./reporting/templates",
        output_dir="./reports",
    )

    results = {
        "tester":       "Mock Student / Lab Test",
        "target_scope": "Simulated Lab Environment (No real devices)",
        "networks":     MOCK_NETWORKS,
        "clients":      MOCK_CLIENTS,
        "captures":     MOCK_CAPTURES,
        "pcap_stats":   MOCK_PCAP_STATS,
        "log_stats":    log_stats,
        "errors":       [],
    }

    # Save raw JSON
    json_path = reporter.save_json(results, filename="mock_results")
    logger.info(f"Raw JSON saved: {json_path}")

    # Generate report
    output = reporter.generate(results, filename="mock_report", pdf=not args.no_pdf)

    # ── Done ──────────────────────────────────────────────────────────
    logger.info("─" * 48)
    logger.info("MOCK RUN COMPLETE")
    logger.info(f"  HTML report : {output['html']}")
    if "pdf" in output:
        logger.info(f"  PDF  report : {output['pdf']}")
    logger.info(f"  JSON results: {json_path}")
    logger.info(f"  Parsed logs : ./logs/mock_parsed.json")
    logger.info("─" * 48)

    if args.open:
        html_abs = str(Path(output["html"]).resolve())
        logger.info(f"Opening report in browser...")
        webbrowser.open(f"file://{html_abs}")


if __name__ == "__main__":
    main()
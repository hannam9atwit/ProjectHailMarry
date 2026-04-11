"""
main.py
-------
Python-Based Pineapple Automation Suite — COMP4500 Offensive Security

ONE COMMAND does everything:

    python main.py

Full automated workflow:
    1. Connect + authenticate to the Pineapple REST API
    2. Recon  — pull all SSIDs + clients passively captured by PineAP
    3. Sync   — automatically SCP every .pcap/.22000 from the Pineapple
    4. Analyse — run tshark on the best available capture
    5. Logs   — normalize the suite log to JSON
    6. Report — generate HTML (+ optional PDF) pentest report

No manual SCP. No flags required. Just:  python main.py

Optional flags:
    --no-pdf            Skip PDF generation (faster)
    --tester NAME       Your name for the report header
    --scope TEXT        Scope description
    --config PATH       Use a different config file
    --skip-recon        Skip recon phase
    --skip-handshake    Skip handshake sync phase
    --pcap PATH         Analyse a specific pcap instead of auto-selecting
"""

import argparse
import shutil
import subprocess
import sys
import os
from pathlib import Path
from datetime import datetime

from core.config import load_config, AppConfig
from core.logger import get_logger
from core.api_client import PineappleClient, PineappleAPIError
from modules.recon import ReconModule
from parsers.log_parser import LogParser
from parsers.pcap_parser import PcapParser, TsharkError
from reporting.report_gen import ReportGenerator


# ── CLI ───────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description="Python-Based Pineapple Automation Suite · COMP4500",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Basic usage:  python main.py\nDemo:          python main.py --tester 'Your Name' --no-pdf"
    )
    p.add_argument("--config",         default="config.yaml")
    p.add_argument("--tester",         default="Student Researcher",
                   help="Your name for the report header")
    p.add_argument("--scope",          default="Lab Environment (Authorized)")
    p.add_argument("--no-pdf",         action="store_true",
                   help="Skip PDF export")
    p.add_argument("--skip-recon",     action="store_true")
    p.add_argument("--skip-handshake", action="store_true")
    p.add_argument("--pcap",           default=None,
                   help="Analyse a specific pcap instead of auto-selecting")
    return p.parse_args()


# ── Helpers ───────────────────────────────────────────────────────────────────

def phase_banner(logger, n: int, title: str):
    logger.info("═" * 52)
    logger.info(f"PHASE {n} — {title}")
    logger.info("═" * 52)


def _ssh_cmd(cfg: AppConfig) -> list[str]:
    """
    Build the base SSH/SCP command prefix.
    Uses sshpass with the password from config.yaml so no interactive
    prompt appears. Installs sshpass automatically if missing.
    """
    password = cfg.pineapple.password
    if not shutil.which("sshpass"):
        subprocess.run(
            ["sudo", "apt-get", "install", "-y", "-q", "sshpass"],
            capture_output=True
        )
    return [
        "sshpass", "-p", password,
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "ConnectTimeout=10",
        "-o", "BatchMode=no",
        "-o", "LogLevel=ERROR",
    ]


def _scp_cmd(cfg: AppConfig) -> list[str]:
    """Build the base SCP command prefix with sshpass."""
    password = cfg.pineapple.password
    return [
        "sshpass", "-p", password,
        "scp",
        "-o", "StrictHostKeyChecking=no",
        "-o", "ConnectTimeout=10",
        "-o", "LogLevel=ERROR",
    ]


# ── Phases ────────────────────────────────────────────────────────────────────

def phase_connect(cfg: AppConfig, logger) -> PineappleClient:
    """Authenticate to the Pineapple API. Exit on failure."""
    client = PineappleClient(cfg.pineapple)
    try:
        info = client.get_info()
        logger.info(f"Pineapple connected — device: {info.get('device', 'standard')}")
    except PineappleAPIError as e:
        logger.error(f"Cannot connect to Pineapple: {e}")
        sys.exit(1)
    return client


def phase_recon(client: PineappleClient, cfg: AppConfig, logger) -> dict:
    """
    Phase 1 — Passive recon.
    Pulls the full SSID pool and connected clients from PineAP.
    PineAP passively accumulates SSIDs — we wait briefly then fetch.
    """
    phase_banner(logger, 1, "RECON")
    recon = ReconModule(
        client=client,
        scan_time=cfg.tshark.capture_duration,
        log_dir=cfg.logging.log_dir,
    )
    recon.run()
    result = recon.get_results()
    logger.info(recon.summary())
    return result


def phase_sync_handshakes(cfg: AppConfig, logger) -> list[dict]:
    """
    Phase 2 — Auto-sync all handshake captures from the Pineapple.

    Uses sshpass + ssh/scp with the password from config.yaml.
    No manual SCP, no password prompts.
    Skips files already present in ./captures/.
    """
    phase_banner(logger, 2, "HANDSHAKE SYNC")

    host       = cfg.pineapple.host
    user       = cfg.pineapple.username
    remote_dir = "/root/handshakes/"
    local_dir  = "./captures"
    os.makedirs(local_dir, exist_ok=True)

    # ── List remote handshake files ───────────────────────────────────
    logger.info(f"Connecting to Pineapple via SSH ({user}@{host})...")
    try:
        ls = subprocess.run(
            _ssh_cmd(cfg) + [f"{user}@{host}", f"ls {remote_dir}"],
            capture_output=True, text=True, timeout=20
        )
        if ls.returncode != 0:
            logger.warning(
                f"SSH ls failed: {ls.stderr.strip() or 'check SSH access'}"
            )
            return []
    except subprocess.TimeoutExpired:
        logger.warning(f"SSH timed out — is the Pineapple reachable at {host}?")
        return []
    except FileNotFoundError:
        logger.warning(
            "sshpass not found and could not be installed. "
            "Run manually: sudo apt-get install sshpass"
        )
        return []
    except Exception as e:
        logger.warning(f"SSH error: {e}")
        return []

    # Filter to capture files only (skip README etc.)
    remote_files = [
        f.strip() for f in ls.stdout.splitlines()
        if f.strip() and not f.strip().startswith("README")
        and any(f.strip().endswith(ext) for ext in (".pcap", ".22000", ".cap"))
    ]

    if not remote_files:
        logger.warning("No capture files found on device yet.")
        return []

    logger.info(f"Found {len(remote_files)} capture(s) on device")

    # ── SCP each file ─────────────────────────────────────────────────
    downloaded = []
    for fname in remote_files:
        local_path = os.path.join(local_dir, fname)

        if os.path.exists(local_path):
            logger.info(f"  ✓ Already synced: {fname}")
        else:
            logger.info(f"  ↓ Downloading: {fname}")
            try:
                result = subprocess.run(
                    _scp_cmd(cfg) + [
                        f"{user}@{host}:{remote_dir}{fname}",
                        local_path
                    ],
                    capture_output=True, text=True, timeout=60
                )
                if result.returncode != 0:
                    logger.error(f"  ✗ SCP failed: {result.stderr.strip()}")
                    continue
                kb = round(os.path.getsize(local_path) / 1024, 1)
                logger.info(f"  ✓ Saved: {local_path} ({kb} KB)")
            except Exception as e:
                logger.error(f"  ✗ SCP error for {fname}: {e}")
                continue

        if not os.path.exists(local_path):
            continue

        # Derive BSSID from filename: e.g. 74-df-bf-04-e2-eb_eviltwin.pcap
        bssid = fname.split("_")[0].replace("-", ":") if "_" in fname else ""
        downloaded.append({
            "filename":   fname,
            "local_path": local_path,
            "bssid":      bssid,
            "ssid":       "Evil Twin Capture",
            "source":     "Evil WPA/2 Twin",
            "timestamp":  datetime.fromtimestamp(
                              os.path.getmtime(local_path)
                          ).strftime("%Y-%m-%d %H:%M:%S"),
        })

    logger.info(f"Sync complete — {len(downloaded)} file(s) ready in {local_dir}/")
    return downloaded


def phase_pcap_analysis(cfg: AppConfig, captures: list, pcap_override: str,
                         logger) -> tuple[str | None, dict]:
    """
    Phase 3 — tshark analysis.
    Auto-selects the best .pcap (prefers .pcap over .22000).
    """
    phase_banner(logger, 3, "PCAP ANALYSIS")

    pcap_file = pcap_override
    if not pcap_file:
        pcaps   = [c["local_path"] for c in captures
                   if c["local_path"].endswith(".pcap")
                   and os.path.exists(c["local_path"])]
        others  = [c["local_path"] for c in captures
                   if not c["local_path"].endswith(".pcap")
                   and os.path.exists(c["local_path"])]
        pcap_file = (pcaps or others or [None])[0]

    if not pcap_file or not Path(pcap_file).exists():
        logger.warning("No pcap file available — skipping tshark analysis.")
        return None, {}

    logger.info(f"Analysing: {pcap_file}")
    try:
        parser = PcapParser(cfg.tshark)
        stats  = parser.get_summary_stats(pcap_file)
        logger.info(
            f"tshark complete — {stats['total_frames']} frames, "
            f"{stats['eapol_frames']} EAPOL, "
            f"handshake={'YES ✓' if stats['handshake_found'] else 'NO'}"
        )
        return pcap_file, stats
    except (TsharkError, FileNotFoundError) as e:
        logger.error(f"tshark failed: {e}")
        return pcap_file, {}


def phase_log_analysis(cfg: AppConfig, logger) -> dict:
    """
    Phase 4 — Parse today's suite log into JSON for the report.
    """
    phase_banner(logger, 4, "LOG ANALYSIS")

    log_file = os.path.join(
        cfg.logging.log_dir,
        f"suite_{datetime.now().strftime('%Y%m%d')}.log"
    )
    if not Path(log_file).exists():
        logger.warning(f"Log file not found: {log_file}")
        return {}

    os.makedirs(cfg.reporting.output_dir, exist_ok=True)
    parser   = LogParser()
    json_out = os.path.join(cfg.reporting.output_dir, "parsed_logs.json")
    entries  = parser.normalize_to_json(log_file, json_out)
    errors   = parser.filter_by_level(entries, "ERROR")
    warnings = parser.filter_by_level(entries, "WARNING")
    macs     = parser.get_unique_macs(entries)

    stats = {
        "total":       len(entries),
        "errors":      len(errors),
        "warnings":    len(warnings),
        "unique_macs": len(macs),
        "json_output": json_out,
    }
    logger.info(
        f"Log analysis — {len(entries)} entries, "
        f"{len(errors)} error(s), {len(warnings)} warning(s)"
    )
    return stats


def phase_report(cfg: AppConfig, results: dict, args, logger) -> dict:
    """Phase 5 — Generate HTML + optional PDF report."""
    phase_banner(logger, 5, "REPORT GENERATION")
    os.makedirs(cfg.reporting.output_dir, exist_ok=True)
    reporter = ReportGenerator(
        template_dir=cfg.reporting.template_dir,
        output_dir=cfg.reporting.output_dir,
    )
    reporter.save_json(results)
    output = reporter.generate(results, pdf=not args.no_pdf)
    logger.info(f"HTML report → {output['html']}")
    if "pdf" in output:
        logger.info(f"PDF  report → {output['pdf']}")
    return output


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    args = parse_args()

    try:
        cfg = load_config(args.config)
    except Exception as e:
        print(f"[FATAL] Config error: {e}")
        sys.exit(1)

    logger = get_logger("main", log_dir=cfg.logging.log_dir, level=cfg.logging.level)

    logger.info("╔══════════════════════════════════════════════════╗")
    logger.info("║  Python-Based Pineapple Automation Suite         ║")
    logger.info("║  COMP4500 · Offensive Security                   ║")
    logger.info("╚══════════════════════════════════════════════════╝")
    logger.info(f"Tester: {args.tester}  |  Scope: {args.scope}")

    results = {
        "tester":       args.tester,
        "target_scope": args.scope,
        "networks":     [],
        "clients":      [],
        "captures":     [],
        "pcap_stats":   {},
        "log_stats":    {},
        "errors":       [],
    }

    # ── Connect ───────────────────────────────────────────────────────
    client = phase_connect(cfg, logger)

    # ── Phase 1: Recon ────────────────────────────────────────────────
    if not args.skip_recon:
        try:
            recon               = phase_recon(client, cfg, logger)
            results["networks"] = recon.get("networks", [])
            results["clients"]  = recon.get("clients",  [])
        except Exception as e:
            logger.error(f"Recon failed: {e}")
            results["errors"].append(f"Recon: {e}")

    # ── Phase 2: Auto-sync handshakes ─────────────────────────────────
    if not args.skip_handshake:
        try:
            results["captures"] = phase_sync_handshakes(cfg, logger)
        except Exception as e:
            logger.error(f"Handshake sync failed: {e}")
            results["errors"].append(f"Handshake sync: {e}")

    # ── Phase 3: tshark analysis ──────────────────────────────────────
    pcap_file, pcap_stats = phase_pcap_analysis(
        cfg, results["captures"], args.pcap, logger
    )
    results["pcap_stats"] = pcap_stats

    # ── Phase 4: Log analysis ─────────────────────────────────────────
    results["log_stats"] = phase_log_analysis(cfg, logger)

    # ── Phase 5: Report ───────────────────────────────────────────────
    try:
        output = phase_report(cfg, results, args, logger)
    except Exception as e:
        logger.error(f"Report failed: {e}")
        results["errors"].append(f"Report: {e}")
        output = {}

    # ── Final summary ─────────────────────────────────────────────────
    logger.info("═" * 52)
    logger.info("SUITE COMPLETE")
    logger.info("═" * 52)
    logger.info(f"  Networks found  : {len(results['networks'])}")
    logger.info(f"  Clients seen    : {len(results['clients'])}")
    logger.info(f"  Captures synced : {len(results['captures'])}")
    logger.info(f"  EAPOL frames    : {results['pcap_stats'].get('eapol_frames', 0)}")
    logger.info(f"  Handshake found : {'YES ✓' if results['pcap_stats'].get('handshake_found') else 'NO'}")
    if output.get("html"):
        logger.info(f"  Report          : {output['html']}")

    if results["errors"]:
        logger.warning(f"  {len(results['errors'])} non-fatal error(s):")
        for err in results["errors"]:
            logger.warning(f"    · {err}")

    if output.get("html"):
        print(f"\n✓ Report ready: {Path(output['html']).resolve()}\n")


if __name__ == "__main__":
    main()
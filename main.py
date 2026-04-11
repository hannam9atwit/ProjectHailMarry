"""
main.py
-------
Python-Based Pineapple Automation Suite — COMP4500 Offensive Security

ONE COMMAND does everything:

    python main.py

Full automated workflow:
    1. Connect + authenticate to the Pineapple
    2. Run recon  — pull all SSIDs + clients passively captured by PineAP
    3. Sync handshakes — SCP every .pcap/.22000 from the Pineapple automatically
    4. Analyse pcap — run tshark on the best available capture
    5. Parse logs  — normalize the Pineapple suite log to JSON
    6. Generate report — produce HTML (+ optional PDF) pentest report

No manual SCP. No --flags required. Just run it.

Optional flags for advanced use:
    --no-pdf            Skip PDF generation (faster)
    --tester NAME       Your name for the report header
    --scope TEXT        Scope description for the report header
    --config PATH       Use a different config file
    --skip-recon        Skip the recon phase
    --skip-handshake    Skip the handshake sync phase
    --pcap PATH         Analyse a specific pcap instead of auto-selecting
"""

import argparse
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
        epilog="Basic usage:  python main.py\nFull demo:    python main.py --tester 'Your Name'"
    )
    p.add_argument("--config",          default="config.yaml")
    p.add_argument("--tester",          default="Student Researcher",
                   help="Your name for the report header")
    p.add_argument("--scope",           default="Lab Environment (Authorized)",
                   help="Scope description")
    p.add_argument("--no-pdf",          action="store_true",
                   help="Skip PDF export (faster)")
    p.add_argument("--skip-recon",      action="store_true")
    p.add_argument("--skip-handshake",  action="store_true")
    p.add_argument("--pcap",            default=None,
                   help="Analyse a specific pcap instead of auto-selecting")
    return p.parse_args()


# ── Phase helpers ─────────────────────────────────────────────────────────────

def phase_banner(logger, n: int, title: str):
    logger.info("═" * 52)
    logger.info(f"PHASE {n} — {title}")
    logger.info("═" * 52)


def phase_connect(cfg: AppConfig, logger) -> PineappleClient:
    """Authenticate to the Pineapple. Exit on failure."""
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
    On firmware 2.1.3 there is no active scan endpoint; PineAP
    captures SSIDs passively as long as it's running.
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
    Phase 2 — Automatically SCP every handshake capture from the
    Pineapple to ./captures/ using the SSH credentials in config.yaml.

    Uses subprocess to call scp directly — no manual copy needed.
    Returns a list of metadata dicts for each downloaded file.
    """
    phase_banner(logger, 2, "HANDSHAKE SYNC")

    host       = cfg.pineapple.host
    user       = cfg.pineapple.username
    remote_dir = "/root/handshakes/"
    local_dir  = "./captures"
    os.makedirs(local_dir, exist_ok=True)

    # ── Step 1: list remote files via SSH ────────────────────────────
    logger.info(f"Listing handshakes on Pineapple ({host})...")
    try:
        ls_result = subprocess.run(
            ["ssh", "-o", "StrictHostKeyChecking=no",
             "-o", "ConnectTimeout=8",
             f"{user}@{host}",
             f"ls {remote_dir}"],
            capture_output=True, text=True, timeout=15
        )
        if ls_result.returncode != 0:
            logger.warning(
                f"SSH ls failed (returncode {ls_result.returncode}): "
                f"{ls_result.stderr.strip()}\n"
                "Tip: run 'ssh-copy-id root@172.16.42.1' once to set up key auth."
            )
            return []
    except Exception as e:
        logger.warning(f"SSH connection failed: {e}")
        return []

    remote_files = [
        f.strip() for f in ls_result.stdout.splitlines()
        if f.strip() and f.strip() != "README"
        and any(f.strip().endswith(ext) for ext in (".pcap", ".22000", ".cap"))
    ]

    if not remote_files:
        logger.warning("No handshake files found on device.")
        return []

    logger.info(f"Found {len(remote_files)} capture(s) on device — syncing...")

    # ── Step 2: SCP each file ─────────────────────────────────────────
    downloaded = []
    for fname in remote_files:
        local_path = os.path.join(local_dir, fname)

        if os.path.exists(local_path):
            logger.info(f"  Already have: {fname} — skipping download")
        else:
            logger.info(f"  Downloading: {fname}")
            try:
                scp = subprocess.run(
                    ["scp", "-o", "StrictHostKeyChecking=no",
                     "-o", "ConnectTimeout=8",
                     f"{user}@{host}:{remote_dir}{fname}",
                     local_path],
                    capture_output=True, text=True, timeout=60
                )
                if scp.returncode != 0:
                    logger.error(f"  SCP failed for {fname}: {scp.stderr.strip()}")
                    continue
                size_kb = round(os.path.getsize(local_path) / 1024, 1)
                logger.info(f"  Saved: {local_path} ({size_kb} KB)")
            except Exception as e:
                logger.error(f"  SCP exception for {fname}: {e}")
                continue

        # Parse metadata from filename: MAC-addr_type.ext
        parts = fname.replace("-", ":").split("_")
        bssid = parts[0] if parts else ""
        downloaded.append({
            "filename":   fname,
            "local_path": local_path,
            "bssid":      bssid,
            "ssid":       "captured",
            "source":     "Evil WPA/2 Twin",
            "timestamp":  datetime.fromtimestamp(
                              os.path.getmtime(local_path)
                          ).strftime("%Y-%m-%d %H:%M:%S")
                          if os.path.exists(local_path) else "",
        })

    logger.info(f"Handshake sync complete — {len(downloaded)} file(s) ready")
    return downloaded


def phase_pcap_analysis(cfg: AppConfig, captures: list, pcap_override: str,
                         logger) -> tuple[str | None, dict]:
    """
    Phase 3 — tshark analysis.
    Picks the best available .pcap file and runs full analysis.
    Prefers .pcap over .22000 (better tshark compatibility).
    Returns (pcap_path, stats_dict).
    """
    phase_banner(logger, 3, "PCAP ANALYSIS")

    # Determine which file to analyse
    pcap_file = pcap_override

    if not pcap_file:
        # Auto-select: prefer .pcap files, then .22000
        pcap_files  = [c["local_path"] for c in captures
                       if c["local_path"].endswith(".pcap")
                       and os.path.exists(c["local_path"])]
        other_files = [c["local_path"] for c in captures
                       if not c["local_path"].endswith(".pcap")
                       and os.path.exists(c["local_path"])]
        candidates  = pcap_files or other_files
        pcap_file   = candidates[0] if candidates else None

    if not pcap_file or not Path(pcap_file).exists():
        logger.warning("No pcap file available for analysis — skipping.")
        return None, {}

    logger.info(f"Analysing: {pcap_file}")
    try:
        parser = PcapParser(cfg.tshark)
        stats  = parser.get_summary_stats(pcap_file)
        logger.info(
            f"Analysis complete — {stats['total_frames']} frames, "
            f"{stats['eapol_frames']} EAPOL, "
            f"handshake={'YES ✓' if stats['handshake_found'] else 'NO'}"
        )
        return pcap_file, stats
    except (TsharkError, FileNotFoundError) as e:
        logger.error(f"tshark analysis failed: {e}")
        return pcap_file, {}


def phase_log_analysis(cfg: AppConfig, logger) -> dict:
    """
    Phase 4 — Log parsing.
    Normalizes the suite's own run log into JSON for the report.
    """
    phase_banner(logger, 4, "LOG ANALYSIS")

    # Use today's suite log — it was written by the logger during this run
    log_file = os.path.join(
        cfg.logging.log_dir,
        f"suite_{datetime.now().strftime('%Y%m%d')}.log"
    )

    if not Path(log_file).exists():
        logger.warning(f"Log file not found: {log_file}")
        return {}

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

    # Load + validate config
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

    # Accumulated results dict — every phase writes into this
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
            recon              = phase_recon(client, cfg, logger)
            results["networks"] = recon.get("networks", [])
            results["clients"]  = recon.get("clients",  [])
        except Exception as e:
            logger.error(f"Recon failed: {e}")
            results["errors"].append(f"Recon: {e}")

    # ── Phase 2: Auto-sync handshakes via SCP ─────────────────────────
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

    # Enrich capture metadata with pcap analysis result
    if pcap_file and results["captures"]:
        for cap in results["captures"]:
            if cap["local_path"] == pcap_file:
                cap["analysed"] = True

    # ── Phase 4: Log analysis ─────────────────────────────────────────
    os.makedirs(cfg.reporting.output_dir, exist_ok=True)
    results["log_stats"] = phase_log_analysis(cfg, logger)

    # ── Phase 5: Report ───────────────────────────────────────────────
    try:
        output = phase_report(cfg, results, args, logger)
    except Exception as e:
        logger.error(f"Report failed: {e}")
        results["errors"].append(f"Report: {e}")
        output = {}

    # ── Summary ───────────────────────────────────────────────────────
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
        logger.warning(f"  {len(results['errors'])} non-fatal error(s) during run:")
        for err in results["errors"]:
            logger.warning(f"    · {err}")

    # Print the report path cleanly at the very end so it's easy to find
    if output.get("html"):
        print(f"\n✓ Report ready: {Path(output['html']).resolve()}\n")


if __name__ == "__main__":
    main()
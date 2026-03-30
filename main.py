"""
Main for the Python-Based Pineapple Automation Suite.

Ties together all modules into a single scriptable, reproducible workflow:
  1. Load config + set up logging
  2. Verify Pineapple API connection
  3. Run recon (networks + clients)
  4. Run handshake capture (optional, requires target BSSID)
  5. Parse downloaded .cap file with tshark
  6. Parse Pineapple log file
  7. Generate HTML + PDF report

Usage:
    python main.py                          # Full run (prompts for BSSID)
    python main.py --skip-handshake         # Recon + report only
    python main.py --pcap captures/lab.cap  # Analyse existing pcap only
    python main.py --help                   # Show all options
"""

import argparse
import sys
import os
from pathlib import Path

from core.config import load_config
from core.logger import get_logger
from core.api_client import PineappleClient, PineappleAPIError
from modules.recon import ReconModule
from modules.handshake import HandshakeModule
from parsers.log_parser import LogParser
from parsers.pcap_parser import PcapParser, TsharkError
from reporting.report_gen import ReportGenerator


def parse_args():
    parser = argparse.ArgumentParser(
        description="Python-Based Pineapple Automation Suite · COMP4500"
    )
    parser.add_argument(
        "--config", default="config.yaml",
        help="Path to config YAML file (default: config.yaml)"
    )
    parser.add_argument(
        "--skip-handshake", action="store_true",
        help="Skip the handshake capture step (recon + report only)"
    )
    parser.add_argument(
        "--skip-recon", action="store_true",
        help="Skip the recon step (useful if re-running report on existing data)"
    )
    parser.add_argument(
        "--target-bssid", default=None,
        help="BSSID of the target AP for deauth+handshake (e.g. AA:BB:CC:DD:EE:FF)"
    )
    parser.add_argument(
        "--client-mac", default="FF:FF:FF:FF:FF:FF",
        help="Client MAC to deauth (default: broadcast all clients)"
    )
    parser.add_argument(
        "--pcap", default=None,
        help="Path to an existing .cap/.pcap file to analyse (skips live capture)"
    )
    parser.add_argument(
        "--log-file", default=None,
        help="Path to a Pineapple log file to parse"
    )
    parser.add_argument(
        "--no-pdf", action="store_true",
        help="Generate HTML report only, skip PDF conversion"
    )
    parser.add_argument(
        "--tester", default="Student Researcher",
        help="Tester name for the report header"
    )
    parser.add_argument(
        "--scope", default="Lab Environment (Authorized)",
        help="Scope description for the report header"
    )
    return parser.parse_args()


def verify_connection(client: PineappleClient, logger) -> bool:
    """Ping the Pineapple API and confirm it's reachable."""
    try:
        info = client.get_info()
        logger.info(
            f"Pineapple connected — firmware: {info.get('firmware', 'unknown')}, "
            f"hostname: {info.get('hostname', 'unknown')}"
        )
        return True
    except PineappleAPIError as e:
        logger.error(f"Cannot connect to Pineapple: {e}")
        return False


def run_recon(client: PineappleClient, cfg, logger) -> dict:
    """Run the recon module and return its results."""
    logger.info("═" * 50)
    logger.info("PHASE 1 — RECON")
    logger.info("═" * 50)
    recon = ReconModule(
        client=client,
        scan_time=cfg.tshark.capture_duration,
        log_dir=cfg.logging.log_dir,
    )
    recon.run()
    logger.info(recon.summary())
    return recon.get_results()


def run_handshake(client: PineappleClient, cfg, args, logger) -> dict:
    """Run the handshake capture module and return its results."""
    logger.info("═" * 50)
    logger.info("PHASE 2 — HANDSHAKE CAPTURE")
    logger.info("═" * 50)

    bssid = args.target_bssid
    if not bssid:
        bssid = input("  Enter target AP BSSID (e.g. AA:BB:CC:DD:EE:FF): ").strip()
        if not bssid:
            logger.warning("No BSSID provided — skipping handshake capture.")
            return {"captures": []}

    hs = HandshakeModule(
        client=client,
        target_bssid=bssid,
        client_mac=args.client_mac,
        capture_dir="./captures",
        poll_wait=cfg.tshark.capture_duration,
        log_dir=cfg.logging.log_dir,
    )
    hs.run()
    logger.info(hs.summary())
    return hs.get_results()


def run_pcap_analysis(cfg, pcap_file: str, logger) -> dict:
    """Parse a pcap file with tshark and return summary stats."""
    logger.info("═" * 50)
    logger.info("PHASE 3 — PCAP ANALYSIS")
    logger.info("═" * 50)

    try:
        pcap_parser = PcapParser(cfg.tshark)
        stats = pcap_parser.get_summary_stats(pcap_file)
        logger.info(
            f"pcap analysis complete — {stats['total_frames']} frames, "
            f"{stats['eapol_frames']} EAPOL, handshake={'YES' if stats['handshake_found'] else 'NO'}"
        )
        return stats
    except (TsharkError, FileNotFoundError) as e:
        logger.error(f"pcap analysis failed: {e}")
        return {}


def run_log_analysis(log_file: str, output_dir: str, logger) -> dict:
    """Parse a Pineapple log file and return summary stats."""
    logger.info("═" * 50)
    logger.info("PHASE 4 — LOG ANALYSIS")
    logger.info("═" * 50)

    parser = LogParser()
    json_out = os.path.join(output_dir, "parsed_logs.json")
    entries  = parser.normalize_to_json(log_file, json_out)

    errors   = parser.filter_by_level(entries, "ERROR")
    warnings = parser.filter_by_level(entries, "WARN")
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
        f"{len(errors)} errors, {len(warnings)} warnings"
    )
    return stats


def main():
    args = parse_args()

    # ── Load config ──────────────────────────────────────────────────
    try:
        cfg = load_config(args.config)
    except (FileNotFoundError, Exception) as e:
        print(f"[FATAL] Config error: {e}")
        sys.exit(1)

    logger = get_logger("main", log_dir=cfg.logging.log_dir, level=cfg.logging.level)

    logger.info("╔══════════════════════════════════════════════════╗")
    logger.info("║  Python-Based Pineapple Automation Suite         ║")
    logger.info("║  COMP4500 · Offensive Security                   ║")
    logger.info("╚══════════════════════════════════════════════════╝")

    # ── Connect to Pineapple ─────────────────────────────────────────
    client = PineappleClient(cfg.pineapple)
    if not verify_connection(client, logger):
        logger.error("Aborting — Pineapple is not reachable.")
        sys.exit(1)

    # ── Accumulated results ──────────────────────────────────────────
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

    # ── Phase 1: Recon ───────────────────────────────────────────────
    if not args.skip_recon:
        try:
            recon_results          = run_recon(client, cfg, logger)
            results["networks"]    = recon_results.get("networks", [])
            results["clients"]     = recon_results.get("clients", [])
        except Exception as e:
            logger.error(f"Recon phase failed: {e}")
            results["errors"].append(f"Recon failed: {e}")

    # ── Phase 2: Handshake capture ───────────────────────────────────
    if not args.skip_handshake:
        try:
            hs_results           = run_handshake(client, cfg, args, logger)
            results["captures"]  = hs_results.get("captures", [])
        except Exception as e:
            logger.error(f"Handshake phase failed: {e}")
            results["errors"].append(f"Handshake capture failed: {e}")

    # ── Phase 3: pcap analysis ───────────────────────────────────────
    pcap_file = args.pcap
    if not pcap_file and results["captures"]:
        # Auto-use first downloaded capture
        pcap_file = results["captures"][0].get("local_path")

    if pcap_file and Path(pcap_file).exists():
        results["pcap_stats"] = run_pcap_analysis(cfg, pcap_file, logger)
    else:
        logger.warning("No pcap file available for analysis — skipping.")

    # ── Phase 4: Log analysis ────────────────────────────────────────
    log_file = args.log_file or os.path.join(cfg.logging.log_dir, "pineapple.log")
    if Path(log_file).exists():
        results["log_stats"] = run_log_analysis(
            log_file, cfg.reporting.output_dir, logger
        )
    else:
        logger.warning(f"No log file found at {log_file} — skipping log analysis.")

    # ── Phase 5: Report generation ───────────────────────────────────
    logger.info("═" * 50)
    logger.info("PHASE 5 — REPORT GENERATION")
    logger.info("═" * 50)

    reporter = ReportGenerator(
        template_dir=cfg.reporting.template_dir,
        output_dir=cfg.reporting.output_dir,
    )

    # Save raw JSON results for archival
    reporter.save_json(results)

    # Generate HTML (and optionally PDF) report
    try:
        output = reporter.generate(results, pdf=not args.no_pdf)
        logger.info(f"HTML report: {output['html']}")
        if "pdf" in output:
            logger.info(f"PDF  report: {output['pdf']}")
    except Exception as e:
        logger.error(f"Report generation failed: {e}")
        results["errors"].append(f"Report generation failed: {e}")

    # ── Done ─────────────────────────────────────────────────────────
    logger.info("═" * 50)
    logger.info("SUITE COMPLETE")
    logger.info("═" * 50)

    if results["errors"]:
        logger.warning(f"{len(results['errors'])} error(s) occurred during run:")
        for err in results["errors"]:
            logger.warning(f"  · {err}")


if __name__ == "__main__":
    main()
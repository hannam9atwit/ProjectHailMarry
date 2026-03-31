"""
log_parser.py
-------------
Normalizes raw Pineapple log files (which can be inconsistent/messy)
into clean JSON structures for analysis and reporting.

Strategy:
  - Multi-pattern regex matching against each log line
  - Lines that match nothing are stored as raw entries (not discarded)
  - Output is always a list of dicts — one per log line
"""

import re
import json
from pathlib import Path
from core.logger import get_logger

logger = get_logger(__name__)


class LogParser:
    """
    Parses raw Pineapple log files into normalized JSON.

    Supports several common Pineapple log formats including
    module logs, recon logs, and system event logs.
    """

    PATTERNS = {
        "timestamp": r"(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2})",
        "level":     r"\[(INFO|WARN(?:ING)?|ERROR|DEBUG|CRITICAL)\]",
        "mac":       r"\b([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\b",
        "ssid":      r"(?:SSID|ssid)[:\s=]+['\"]?([^\s,'\"]+)['\"]?",
        "bssid":     r"(?:BSSID|bssid)[:\s=]+([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})",
        "channel":   r"(?:CH|channel|chan)[:\s=]+(\d{1,3})",
        "signal":    r"(?:signal|rssi|dBm)[:\s=]+([-\d]+)",
        "ip":        r"\b(\d{1,3}(?:\.\d{1,3}){3})\b",
        "module":    r"(?:module|Module)[:\s=]+([A-Za-z0-9_\-]+)",
    }

    def parse_line(self, line: str) -> dict:
        """
        Parse a single log line into a structured dict.
        Unmatched fields are None. Raw line always preserved.
        """
        entry = {"raw": line}
        for field, pattern in self.PATTERNS.items():
            match = re.search(pattern, line, re.IGNORECASE)
            entry[field] = match.group(1) if match else None
        return entry

    def parse_file(self, filepath: str) -> list[dict]:
        """Parse all non-blank lines from a log file."""
        path = Path(filepath)
        if not path.exists():
            logger.warning(f"Log file not found: {filepath}")
            return []

        entries = []
        with open(path, "r", errors="replace") as f:
            for i, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                entry = self.parse_line(line)
                entry["line_number"] = i
                entries.append(entry)

        logger.info(f"Parsed {len(entries)} entries from {filepath}")
        return entries

    def normalize_to_json(self, input_path: str, output_path: str) -> list[dict]:
        """Parse a log file and write the result as JSON."""
        entries = self.parse_file(input_path)
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(entries, f, indent=2)
        logger.info(f"Normalized log saved to {output_path} ({len(entries)} entries)")
        return entries

    def filter_by_level(self, entries: list[dict], level: str) -> list[dict]:
        """
        Filter parsed entries by log level (INFO, ERROR, WARN, etc.).
        Safely handles entries where 'level' is None.
        """
        target = level.upper()
        return [
            e for e in entries
            if e.get("level") is not None and e["level"].upper() == target
        ]

    def filter_by_mac(self, entries: list[dict], mac: str) -> list[dict]:
        """Filter entries referencing a specific MAC address."""
        return [e for e in entries if e.get("mac") == mac.upper()]

    def get_unique_macs(self, entries: list[dict]) -> list[str]:
        """Return all unique MAC addresses seen across all log entries."""
        return list({e["mac"] for e in entries if e.get("mac")})

    def get_unique_ssids(self, entries: list[dict]) -> list[str]:
        """Return all unique SSIDs seen across all log entries."""
        return list({e["ssid"] for e in entries if e.get("ssid")})
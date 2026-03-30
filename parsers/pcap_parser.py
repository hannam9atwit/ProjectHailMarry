"""
Integrates with tshark (Wireshark CLI) via Python's subprocess module
to capture, parse, and analyse pcap files.

Key capabilities:
  - Live packet capture on a monitor-mode interface
  - Parse pcap files to structured JSON
  - Filter for EAPOL (WPA handshake) frames specifically
  - Extract 802.11 management frame summaries
"""

import subprocess
import json
import os
from pathlib import Path
from core.config import TsharkConfig
from core.logger import get_logger

logger = get_logger(__name__)


class TsharkError(Exception):
    """Raised when tshark exits with an error or is not found."""
    pass


class PcapParser:
    """
    Wrapper around tshark for packet capture and analysis.

    Uses subprocess to call tshark with JSON output mode (-T json),
    then parses and returns the results as Python structures.
    """

    def __init__(self, config: TsharkConfig):
        self.tshark_bin = config.binary_path
        self.interface  = config.capture_interface
        self.duration   = config.capture_duration
        self._verify_tshark()

    def _verify_tshark(self):
        """Check tshark is installed and accessible."""
        try:
            result = subprocess.run(
                [self.tshark_bin, "--version"],
                capture_output=True, text=True, timeout=5
            )
            version_line = result.stdout.split("\n")[0]
            logger.info(f"tshark found: {version_line}")
        except FileNotFoundError:
            raise TsharkError(
                f"tshark not found at {self.tshark_bin}. "
                "Install with: sudo apt install tshark"
            )

    def _run_tshark(self, args: list[str]) -> str:
        """
        Run tshark with the given arguments and return stdout.

        Args:
            args: List of tshark command-line arguments.

        Returns:
            Raw stdout string from tshark.

        Raises:
            TsharkError on non-zero exit.
        """
        cmd = [self.tshark_bin] + args
        logger.debug(f"Running: {' '.join(cmd)}")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=self.duration + 30
        )

        if result.returncode not in (0, 1):  # tshark exits 1 on partial captures
            raise TsharkError(
                f"tshark exited with code {result.returncode}:\n{result.stderr}"
            )

        return result.stdout

    # ------------------------------------------------------------------
    # Capture
    # ------------------------------------------------------------------

    def capture(self, output_file: str, duration: int = None, interface: str = None):
        """
        Capture packets live on a wireless interface.

        Args:
            output_file: Path to save the .pcap file.
            duration:    Override default capture duration (seconds).
            interface:   Override default capture interface.
        """
        iface    = interface or self.interface
        dur      = duration  or self.duration
        out_path = Path(output_file)
        out_path.parent.mkdir(parents=True, exist_ok=True)

        logger.info(f"Capturing on {iface} for {dur}s → {output_file}")

        self._run_tshark([
            "-i", iface,
            "-a", f"duration:{dur}",
            "-w", str(out_path)
        ])

        logger.info(f"Capture complete: {output_file}")

    # ------------------------------------------------------------------
    # Parse
    # ------------------------------------------------------------------

    def parse_pcap(self, pcap_file: str) -> list[dict]:
        """
        Parse a .pcap file and return all frames as structured JSON.

        Extracts: frame number, timestamp, source MAC, dest MAC,
        802.11 frame type/subtype, and packet length.

        Args:
            pcap_file: Path to the pcap file.

        Returns:
            List of frame dicts.
        """
        if not Path(pcap_file).exists():
            raise FileNotFoundError(f"pcap file not found: {pcap_file}")

        logger.info(f"Parsing pcap: {pcap_file}")

        stdout = self._run_tshark([
            "-r", pcap_file,
            "-T", "json",
            "-e", "frame.number",
            "-e", "frame.time",
            "-e", "frame.len",
            "-e", "wlan.sa",
            "-e", "wlan.da",
            "-e", "wlan.bssid",
            "-e", "wlan.ssid",
            "-e", "wlan.fc.type_subtype",
        ])

        try:
            frames = json.loads(stdout) if stdout.strip() else []
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse tshark JSON output: {e}")
            frames = []

        logger.info(f"Parsed {len(frames)} frames from {pcap_file}")
        return frames

    def filter_handshakes(self, pcap_file: str) -> list[dict]:
        """
        Extract only EAPOL frames (WPA 4-way handshake) from a pcap.

        EAPOL frames are the 4-packet sequence that proves a client
        knows the PSK during the WPA authentication process.

        Args:
            pcap_file: Path to the pcap file.

        Returns:
            List of EAPOL frame dicts.
        """
        if not Path(pcap_file).exists():
            raise FileNotFoundError(f"pcap file not found: {pcap_file}")

        logger.info(f"Filtering EAPOL frames from: {pcap_file}")

        stdout = self._run_tshark([
            "-r", pcap_file,
            "-Y", "eapol",        # Display filter: only EAPOL packets
            "-T", "json",
        ])

        try:
            frames = json.loads(stdout) if stdout.strip() else []
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse EAPOL JSON: {e}")
            frames = []

        logger.info(f"Found {len(frames)} EAPOL frame(s) in {pcap_file}")
        return frames

    def filter_management_frames(self, pcap_file: str) -> list[dict]:
        """
        Extract 802.11 management frames (beacons, probes, auth frames).

        Useful for identifying APs and clients in a capture.

        Args:
            pcap_file: Path to the pcap file.

        Returns:
            List of management frame dicts.
        """
        logger.info(f"Filtering 802.11 management frames: {pcap_file}")

        stdout = self._run_tshark([
            "-r", pcap_file,
            "-Y", "wlan.fc.type == 0",   # Type 0 = management frames
            "-T", "json",
            "-e", "frame.number",
            "-e", "frame.time",
            "-e", "wlan.ssid",
            "-e", "wlan.sa",
            "-e", "wlan.bssid",
            "-e", "wlan.fc.type_subtype",
        ])

        try:
            frames = json.loads(stdout) if stdout.strip() else []
        except json.JSONDecodeError:
            frames = []

        logger.info(f"Found {len(frames)} management frame(s)")
        return frames

    def get_summary_stats(self, pcap_file: str) -> dict:
        """
        Return a high-level statistical summary of a pcap file.

        Includes: total frames, unique MACs, EAPOL count,
        management frame count, and file size.

        Args:
            pcap_file: Path to the pcap file.

        Returns:
            Dict of summary statistics.
        """
        all_frames    = self.parse_pcap(pcap_file)
        eapol_frames  = self.filter_handshakes(pcap_file)
        mgmt_frames   = self.filter_management_frames(pcap_file)
        file_size_kb  = round(os.path.getsize(pcap_file) / 1024, 2) if Path(pcap_file).exists() else 0

        # Extract unique MAC addresses from all frames
        unique_macs = set()
        for frame in all_frames:
            layers = frame.get("_source", {}).get("layers", {})
            for key in ("wlan.sa", "wlan.da", "wlan.bssid"):
                mac = layers.get(key)
                if mac:
                    unique_macs.add(mac if isinstance(mac, str) else mac[0])

        return {
            "file":            pcap_file,
            "file_size_kb":    file_size_kb,
            "total_frames":    len(all_frames),
            "eapol_frames":    len(eapol_frames),
            "mgmt_frames":     len(mgmt_frames),
            "unique_macs":     len(unique_macs),
            "handshake_found": len(eapol_frames) >= 2,  # min 2 EAPOL = partial handshake
        }
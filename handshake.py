"""
handshake.py
------------
WPA handshake capture module for Pineapple firmware 2.1.3.

On this firmware handshakes are captured by the Evil Twin module,
NOT by a deauth API endpoint (which doesn't exist). Workflow:

  1. Snapshot existing handshakes on device
  2. Log a clear message about how to trigger a new capture via Evil Twin
  3. Wait poll_wait seconds for a new capture to appear
  4. Download any NEW captures that appeared during the wait
  5. If no new captures, fall back to downloading existing captures
     that match the target BSSID (--download-all mode)

The 'mac' field in the API response = the AP MAC address.
The 'bssid' key is normalized from 'mac' by api_client.get_handshakes().

IMPORTANT: Only use against your own authorized lab AP.
"""

import time
import os
from modules.base_module import BaseModule
from core.api_client import PineappleClient, PineappleAPIError


class HandshakeModule(BaseModule):
    """
    Downloads WPA handshake captures from the Pineapple.

    Args:
        client:        PineappleClient instance.
        target_bssid:  MAC of the target AP — used to filter captures.
        client_mac:    Client MAC (unused on 2.1.3, kept for API compat).
        capture_dir:   Local dir to save .pcap/.22000 files.
        poll_wait:     Seconds to wait for a new capture to appear.
        download_all:  Also grab existing captures matching target_bssid
                       if no new ones appear during poll_wait.
        log_dir:       Log output directory.
    """

    def __init__(
        self,
        client:        PineappleClient,
        target_bssid:  str,
        client_mac:    str  = "FF:FF:FF:FF:FF:FF",
        capture_dir:   str  = "./captures",
        poll_wait:     int  = 20,
        download_all:  bool = False,
        log_dir:       str  = "./logs",
    ):
        super().__init__(client, log_dir)
        self.target_bssid = target_bssid.lower().strip()
        self.client_mac   = client_mac
        self.capture_dir  = capture_dir
        self.poll_wait    = poll_wait
        self.download_all = download_all
        os.makedirs(capture_dir, exist_ok=True)

    def _match_bssid(self, h: dict) -> bool:
        """Check if a handshake entry matches the target BSSID."""
        return h.get("bssid", "").lower().strip() == self.target_bssid

    def run(self):
        self.logger.info(f"HandshakeModule targeting BSSID={self.target_bssid}")

        # ── Step 1: Snapshot existing captures ───────────────────────
        before     = self.client.get_handshakes()
        before_set = {h["filename"] for h in before}
        self.logger.info(f"{len(before_set)} capture(s) on device before poll")

        # ── Step 2: Inform about Evil Twin (no API deauth) ────────────
        self.logger.warning(
            "Firmware 2.1.3 has no deauth API — handshakes are captured via Evil Twin. "
            "To trigger a new handshake: Pineapple web UI → PineAP → Evil Twin → "
            f"enter target BSSID {self.target_bssid} → Start. "
            f"Waiting {self.poll_wait}s for a new capture to appear..."
        )

        # ── Step 3: Poll for new captures ─────────────────────────────
        time.sleep(self.poll_wait)

        after      = self.client.get_handshakes()
        new_caps   = [h for h in after if h["filename"] not in before_set]
        self.logger.info(f"{len(new_caps)} new capture(s) appeared during poll window")

        # ── Step 4: Fall back to existing captures if --download-all ──
        if not new_caps and self.download_all:
            matching = [h for h in after if self._match_bssid(h)]
            if matching:
                self.logger.info(
                    f"--download-all: found {len(matching)} existing capture(s) "
                    f"matching BSSID {self.target_bssid}"
                )
                new_caps = matching
            else:
                self.logger.warning(
                    f"No captures found matching BSSID {self.target_bssid}. "
                    "Available BSSIDs on device: "
                    + ", ".join({h.get('bssid','?') for h in after})
                )

        # ── Step 5: Download ──────────────────────────────────────────
        downloaded = []
        for h in new_caps:
            fname      = h["filename"]
            local_path = os.path.join(self.capture_dir, fname)

            if os.path.exists(local_path):
                self.logger.info(f"Already downloaded: {fname} — using cached copy")
                downloaded.append(self._build_result(h, local_path))
                continue

            try:
                self.client.download_handshake(fname, local_path)
                downloaded.append(self._build_result(h, local_path))
            except PineappleAPIError as e:
                self.logger.error(f"Failed to download {fname}: {e}")

        self.results = {"captures": downloaded}
        self.logger.info(
            f"HandshakeModule complete — {len(downloaded)} capture(s) ready."
        )

    def _build_result(self, h: dict, local_path: str) -> dict:
        return {
            "filename":   h["filename"],
            "local_path": local_path,
            "bssid":      h.get("bssid", self.target_bssid),
            "ssid":       h.get("ssid", "unknown"),
            "source":     h.get("source", ""),
            "type":       h.get("type", ""),
            "timestamp":  h.get("timestamp", ""),
        }

    def get_results(self) -> dict:
        return self.results

    def summary(self) -> str:
        n = len(self.results.get("captures", []))
        return f"HandshakeModule: {n} capture(s) downloaded"
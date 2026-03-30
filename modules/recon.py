"""
Recon module — triggers a scan on the Pineapple, collects
detected networks and clients, and stores structured results.
"""

import time
from modules.base_module import BaseModule
from core.api_client import PineappleClient


class ReconModule(BaseModule):
    """
    Runs passive/active network reconnaissance via the Pineapple recon API.

    Results include:
        - networks: list of detected SSIDs with BSSID, channel, encryption, signal
        - clients:  list of detected client MACs and their associated SSID
    """

    def __init__(self, client: PineappleClient, scan_time: int = 15, log_dir: str = "./logs"):
        super().__init__(client, log_dir)
        self.scan_time = scan_time

    def run(self):
        self.logger.info(f"Starting recon scan (duration={self.scan_time}s)...")

        try:
            self.client.start_recon(self.scan_time)
        except Exception as e:
            self.logger.error(f"Failed to start recon: {e}")
            return

        # Wait for scan to complete
        self.logger.info(f"Waiting {self.scan_time}s for scan to complete...")
        time.sleep(self.scan_time + 2)

        try:
            networks = self.client.get_networks()
            clients  = self.client.get_clients()
        except Exception as e:
            self.logger.error(f"Failed to retrieve recon data: {e}")
            return

        self.results = {
            "networks": networks if isinstance(networks, list) else [],
            "clients":  clients  if isinstance(clients,  list) else [],
        }

        self.logger.info(
            f"Recon complete — {len(self.results['networks'])} networks, "
            f"{len(self.results['clients'])} clients found."
        )

    def get_results(self) -> dict:
        return self.results

    def summary(self) -> str:
        n = len(self.results.get("networks", []))
        c = len(self.results.get("clients",  []))
        return f"ReconModule: {n} network(s), {c} client(s) detected"
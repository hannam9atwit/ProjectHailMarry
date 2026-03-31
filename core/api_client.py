"""
Wrapper around the WiFi Pineapple REST API.
Handles authentication, request/response lifecycle, and all endpoint calls.

Confirmed working endpoints for Mark VII firmware 2.1.3:
    POST /api/login                  → authenticate
    GET  /api/device                 → device info
    GET  /api/modules                → list modules
    GET  /api/pineap/settings        → PineAP config
    POST /api/pineap/settings        → update PineAP config
    GET  /api/pineap/handshakes      → list captured handshakes
    GET  /api/pineap/clients         → connected clients
    GET  /api/pineap/ssids           → SSID pool
"""

import requests
from requests.exceptions import ConnectionError, Timeout, HTTPError
from core.config import PineappleConfig
from core.logger import get_logger

logger = get_logger(__name__)


class PineappleAPIError(Exception):
    """Raised when the Pineapple API returns an error or is unreachable."""
    pass


class PineappleClient:
    """
    REST API client for the WiFi Pineapple Mark VII firmware 2.1.3.

    Authenticates on construction via username/password, then uses
    the returned Bearer token for all subsequent requests.

    All methods return parsed JSON as Python dicts/lists.
    Raises PineappleAPIError on any network or HTTP failure.
    """

    def __init__(self, config: PineappleConfig):
        self.base_url = f"http://{config.host}:{config.port}/api"
        self.username = config.username
        self.password = config.password
        self.token    = None
        self.headers  = {"Content-Type": "application/json"}
        self.timeout  = 10
        logger.info(f"PineappleClient initialized → {self.base_url}")
        self.authenticate()

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    def authenticate(self) -> bool:
        """
        Log in to the Pineapple and store the session token.
        Called automatically on construction.
        """
        url = f"{self.base_url}/login"
        try:
            logger.info(f"Authenticating with Pineapple at {url}")
            r = requests.post(
                url,
                json={"username": self.username, "password": self.password},
                timeout=self.timeout
            )
            r.raise_for_status()
            data = r.json()

            token = data.get("token") or data.get("api_token")
            if not token:
                raise PineappleAPIError(
                    f"Auth response did not contain a token. Response: {data}"
                )

            self.token = token
            self.headers["Authorization"] = f"Bearer {self.token}"
            logger.info("Authenticated with Pineapple successfully")
            return True

        except ConnectionError:
            raise PineappleAPIError(
                f"Cannot reach Pineapple at {url}. "
                "Is it powered on and is your Kali VM on the right network interface?"
            )
        except Timeout:
            raise PineappleAPIError(f"Authentication timed out: {url}")
        except HTTPError as e:
            raise PineappleAPIError(
                f"HTTP {r.status_code} during auth — wrong password? {e}"
            )

    # ------------------------------------------------------------------
    # Internal HTTP helpers
    # ------------------------------------------------------------------

    def _get(self, endpoint: str) -> dict | list:
        url = f"{self.base_url}/{endpoint}"
        try:
            logger.debug(f"GET {url}")
            r = requests.get(url, headers=self.headers, timeout=self.timeout)
            r.raise_for_status()
            return r.json()
        except ConnectionError:
            raise PineappleAPIError(f"Cannot reach Pineapple at {url}.")
        except Timeout:
            raise PineappleAPIError(f"Request timed out: GET {url}")
        except HTTPError as e:
            raise PineappleAPIError(f"HTTP error {r.status_code}: {e}")

    def _post(self, endpoint: str, data: dict = None) -> dict | list:
        url = f"{self.base_url}/{endpoint}"
        try:
            logger.debug(f"POST {url} | payload={data}")
            r = requests.post(
                url,
                headers=self.headers,
                json=data or {},
                timeout=self.timeout
            )
            r.raise_for_status()
            return r.json()
        except ConnectionError:
            raise PineappleAPIError(f"Cannot reach Pineapple at {url}.")
        except Timeout:
            raise PineappleAPIError(f"Request timed out: POST {url}")
        except HTTPError as e:
            raise PineappleAPIError(f"HTTP error {r.status_code}: {e}")

    # ------------------------------------------------------------------
    # System endpoints
    # ------------------------------------------------------------------

    def get_info(self) -> dict:
        """Return device info."""
        return self._get("device")

    def get_status(self) -> dict:
        """Return device info (alias for get_info on 2.1.3)."""
        return self._get("device")

    # ------------------------------------------------------------------
    # Module endpoints
    # ------------------------------------------------------------------

    def get_modules(self) -> list:
        """List all installed modules and their status."""
        return self._get("modules")

    def start_module(self, module_name: str) -> dict:
        """Start a named module."""
        logger.info(f"Starting module: {module_name}")
        return self._post(f"module/{module_name}/start")

    def stop_module(self, module_name: str) -> dict:
        """Stop a named module."""
        logger.info(f"Stopping module: {module_name}")
        return self._post(f"module/{module_name}/stop")

    def get_module_log(self, module_name: str) -> dict:
        """Fetch the log output of a running or completed module."""
        return self._get(f"module/{module_name}/log")

    # ------------------------------------------------------------------
    # Recon — firmware 2.1.3 does not expose a dedicated recon REST API.
    # Recon results are written to /root/recon.db on the device.
    # We return the clients and SSID pool from PineAP instead, which
    # reflects live association and probe data.
    # ------------------------------------------------------------------

    def get_networks(self) -> list:
        """
        Return detected networks from the PineAP SSID pool.
        On firmware 2.1.3 there is no dedicated recon/networks endpoint —
        the SSID pool is the closest equivalent.
        """
        logger.info("Fetching SSID pool from PineAP (recon equivalent)")
        try:
            data = self._get("pineap/ssids")
            raw  = data.get("ssids", "")
            # SSIDs are returned as a newline-delimited string
            ssids = [s.strip() for s in raw.split("\n") if s.strip() and not s.startswith("#")]
            return [{"ssid": s, "bssid": "—", "channel": "—",
                     "signal": "—", "encryption": "—"} for s in ssids]
        except PineappleAPIError as e:
            logger.warning(f"Could not fetch SSID pool: {e}")
            return []

    def get_clients(self) -> list:
        """Return list of clients currently seen by PineAP."""
        logger.info("Fetching clients from PineAP")
        try:
            data = self._get("pineap/clients")
            # Response is a list of client dicts
            if isinstance(data, list):
                return [
                    {
                        "mac":     c.get("mac", "—"),
                        "ssid":    c.get("ssid", "—"),
                        "signal":  c.get("tx_bytes", "—"),
                        "packets": c.get("rx_bytes", "—"),
                    }
                    for c in data
                ]
            return []
        except PineappleAPIError as e:
            logger.warning(f"Could not fetch clients: {e}")
            return []

    def start_recon(self, scan_time: int = 15) -> dict:
        """
        Firmware 2.1.3 has no recon start endpoint.
        PineAP passively captures SSIDs continuously when enabled.
        This is a no-op that logs a warning and returns gracefully.
        """
        logger.warning(
            "start_recon() called but firmware 2.1.3 has no recon/start endpoint. "
            "PineAP captures SSIDs passively — ensure PineAP is enabled in the web UI."
        )
        return {"status": "passive — no action needed"}

    def stop_recon(self) -> dict:
        """No-op on firmware 2.1.3."""
        return {"status": "passive — no action needed"}

    # ------------------------------------------------------------------
    # PineAP endpoints
    # ------------------------------------------------------------------

    def get_pineap_settings(self) -> dict:
        """Return current PineAP configuration."""
        return self._get("pineap/settings")

    def set_pineap_settings(self, settings: dict) -> dict:
        """Update PineAP settings."""
        logger.info(f"Updating PineAP settings: {settings}")
        return self._post("pineap/settings", settings)

    def enable_pineap(self) -> dict:
        """Enable PineAP by setting enablePineAP to true."""
        logger.info("Enabling PineAP")
        current = self.get_pineap_settings()
        current_settings = current.get("settings", {})
        current_settings["enablePineAP"] = True
        return self._post("pineap/settings", {"settings": current_settings})

    def disable_pineap(self) -> dict:
        """Disable PineAP by setting enablePineAP to false."""
        logger.info("Disabling PineAP")
        current = self.get_pineap_settings()
        current_settings = current.get("settings", {})
        current_settings["enablePineAP"] = False
        return self._post("pineap/settings", {"settings": current_settings})

    # ------------------------------------------------------------------
    # Handshake endpoints
    # ------------------------------------------------------------------

    def get_handshakes(self) -> list:
        """
        List all captured WPA handshakes stored on the device.
        Returns the handshakes list from /api/pineap/handshakes.
        """
        data = self._get("pineap/handshakes")
        return data.get("handshakes", [])

    def download_handshake(self, filename: str, dest_path: str):
        """
        Download a handshake file from the Pineapple to local disk.
        Uses the location field returned by get_handshakes().

        Args:
            filename:  The filename on the Pineapple (e.g. 74-df-bf-04-e2-eb_eviltwin.pcap)
            dest_path: Local path to save the file.
        """
        url = f"{self.base_url}/pineap/handshakes/{filename}/download"
        logger.info(f"Downloading handshake: {filename} → {dest_path}")
        try:
            r = requests.get(url, headers=self.headers, timeout=30, stream=True)
            r.raise_for_status()
            with open(dest_path, "wb") as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
            logger.info(f"Handshake saved to {dest_path}")
        except Exception as e:
            raise PineappleAPIError(f"Failed to download handshake {filename}: {e}")

    # ------------------------------------------------------------------
    # Deauth
    # ------------------------------------------------------------------

    def send_deauth(self, bssid: str, client_mac: str = "FF:FF:FF:FF:FF:FF") -> dict:
        """
        Send deauthentication frames via PineAP settings target_mac field.

        IMPORTANT: Only use against your own lab AP with written authorization.
        """
        logger.warning(f"Sending deauth → BSSID={bssid}, Client={client_mac}")
        current = self.get_pineap_settings()
        current_settings = current.get("settings", {})
        current_settings["target_mac"] = client_mac
        return self._post("pineap/settings", {"settings": current_settings})
"""
Wrapper around the WiFi Pineapple REST API.
Handles authentication, request/response lifecycle, and all endpoint calls.

Pineapple Mark VII firmware 2.1.x uses session-based auth:
    POST /api/auth/login  →  returns Bearer token
    All subsequent requests use: Authorization: Bearer <token>
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
    REST API client for the WiFi Pineapple Mark VII.

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

        Returns:
            True on success.

        Raises:
            PineappleAPIError if login fails or Pineapple is unreachable.
        """
        url = f"{self.base_url}/auth/login"
        try:
            logger.info(f"Authenticating with Pineapple at {url}")
            r = requests.post(
                url,
                json={"username": self.username, "password": self.password},
                timeout=self.timeout
            )
            r.raise_for_status()
            data = r.json()

            # Firmware 2.1.x returns either 'token' or 'api_token'
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
            raise PineappleAPIError(f"Cannot reach Pineapple at {url}. Is it connected?")
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
            raise PineappleAPIError(f"Cannot reach Pineapple at {url}. Is it connected?")
        except Timeout:
            raise PineappleAPIError(f"Request timed out: POST {url}")
        except HTTPError as e:
            raise PineappleAPIError(f"HTTP error {r.status_code}: {e}")

    # ------------------------------------------------------------------
    # System endpoints
    # ------------------------------------------------------------------

    def get_info(self) -> dict:
        """Return firmware version, hostname, uptime."""
        return self._get("info")

    def get_status(self) -> dict:
        """Return current system status."""
        return self._get("status")

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
    # Recon endpoints
    # ------------------------------------------------------------------

    def get_networks(self) -> list:
        """Return list of detected networks from recon module."""
        logger.info("Fetching detected networks from Pineapple recon")
        return self._get("recon/networks")

    def get_clients(self) -> list:
        """Return list of detected clients from recon module."""
        logger.info("Fetching detected clients from Pineapple recon")
        return self._get("recon/clients")

    def start_recon(self, scan_time: int = 15) -> dict:
        """Trigger a recon scan for a given duration in seconds."""
        logger.info(f"Starting recon scan ({scan_time}s)")
        return self._post("recon/start", {"scanTime": scan_time})

    def stop_recon(self) -> dict:
        """Stop an ongoing recon scan."""
        return self._post("recon/stop")

    # ------------------------------------------------------------------
    # PineAP endpoints
    # ------------------------------------------------------------------

    def get_pineap_settings(self) -> dict:
        """Return current PineAP configuration."""
        return self._get("pineap/settings")

    def set_pineap_settings(self, settings: dict) -> dict:
        """Update PineAP settings (beacon flood, associations, etc.)."""
        logger.info(f"Updating PineAP settings: {settings}")
        return self._post("pineap/settings", settings)

    def enable_pineap(self) -> dict:
        """Enable PineAP daemon."""
        logger.info("Enabling PineAP")
        return self._post("pineap/enable")

    def disable_pineap(self) -> dict:
        """Disable PineAP daemon."""
        logger.info("Disabling PineAP")
        return self._post("pineap/disable")

    # ------------------------------------------------------------------
    # Handshake endpoints
    # ------------------------------------------------------------------

    def get_handshakes(self) -> list:
        """List all captured WPA handshakes stored on the device."""
        return self._get("handshakes")

    def download_handshake(self, filename: str, dest_path: str):
        """
        Download a handshake .cap file from the Pineapple to local disk.

        Args:
            filename:  Name of the handshake file on the Pineapple.
            dest_path: Local path to save the file.
        """
        url = f"{self.base_url}/handshakes/{filename}"
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
    # Deauth endpoints (lab/authorized use only)
    # ------------------------------------------------------------------

    def send_deauth(self, bssid: str, client_mac: str = "FF:FF:FF:FF:FF:FF") -> dict:
        """
        Send deauthentication frames to force a client to reconnect,
        triggering a WPA handshake capture.

        Args:
            bssid:      Target AP MAC address.
            client_mac: Client to deauth. Defaults to broadcast (all clients).

        IMPORTANT: Only use against your own lab AP with written authorization.
        """
        logger.warning(f"Sending deauth → BSSID={bssid}, Client={client_mac}")
        return self._post("deauth", {"bssid": bssid, "client": client_mac})
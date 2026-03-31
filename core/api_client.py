"""
api_client.py
-------------
Wrapper around the WiFi Pineapple REST API.

Confirmed working endpoints for Mark VII firmware 2.1.3:
    POST /api/login                       → authenticate, returns token
    GET  /api/device                      → device info
    GET  /api/modules                     → list modules
    GET  /api/pineap/settings             → PineAP config
    POST /api/pineap/settings             → update PineAP config
    GET  /api/pineap/handshakes           → list captured handshakes
    POST /api/pineap/handshakes/deauth    → send deauth frames
    GET  /api/pineap/clients              → connected clients
    GET  /api/pineap/ssids                → SSID pool

Notes on firmware 2.1.3 quirks:
    - Auth uses POST /api/login with username/password JSON body
    - Handshakes list returns objects with 'location' not 'filename'
    - filename is derived from the basename of 'location'
    - Deauth is POST /api/pineap/handshakes/deauth, NOT via settings
    - No dedicated recon/start endpoint — PineAP passively captures
"""

import os
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

    Authenticates on construction via username/password POST,
    then uses the returned Bearer token for all subsequent requests.
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
        POST /api/login with username+password, store Bearer token.
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
                    f"Auth response did not contain a token. "
                    f"Response keys: {list(data.keys())}"
                )

            self.token = token
            self.headers["Authorization"] = f"Bearer {self.token}"
            logger.info("Authenticated with Pineapple successfully")
            return True

        except ConnectionError:
            raise PineappleAPIError(
                f"Cannot reach Pineapple at {url}. "
                "Is it powered on and is your Kali machine on the right network?"
            )
        except Timeout:
            raise PineappleAPIError(f"Authentication timed out: {url}")
        except HTTPError as e:
            raise PineappleAPIError(
                f"HTTP {r.status_code} during auth — check username/password. {e}"
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
            raise PineappleAPIError(f"HTTP error {r.status_code} on GET {endpoint}: {e}")

    def _post(self, endpoint: str, data: dict = None) -> dict | list:
        url = f"{self.base_url}/{endpoint}"
        try:
            logger.debug(f"POST {url} payload={data}")
            r = requests.post(
                url,
                headers=self.headers,
                json=data or {},
                timeout=self.timeout
            )
            r.raise_for_status()
            return r.json() if r.content else {}
        except ConnectionError:
            raise PineappleAPIError(f"Cannot reach Pineapple at {url}.")
        except Timeout:
            raise PineappleAPIError(f"Request timed out: POST {url}")
        except HTTPError as e:
            raise PineappleAPIError(f"HTTP error {r.status_code} on POST {endpoint}: {e}")

    # ------------------------------------------------------------------
    # System
    # ------------------------------------------------------------------

    def get_info(self) -> dict:
        """GET /api/device — returns device type, firmware, uptime."""
        return self._get("device")

    # ------------------------------------------------------------------
    # Modules
    # ------------------------------------------------------------------

    def get_modules(self) -> list:
        return self._get("modules")

    def start_module(self, module_name: str) -> dict:
        logger.info(f"Starting module: {module_name}")
        return self._post(f"module/{module_name}/start")

    def stop_module(self, module_name: str) -> dict:
        logger.info(f"Stopping module: {module_name}")
        return self._post(f"module/{module_name}/stop")

    def get_module_log(self, module_name: str) -> dict:
        return self._get(f"module/{module_name}/log")

    # ------------------------------------------------------------------
    # Recon
    # Firmware 2.1.3 has no recon/start REST endpoint.
    # PineAP captures SSIDs passively when enabled.
    # ------------------------------------------------------------------

    def start_recon(self, scan_time: int = 15) -> dict:
        """
        No-op on firmware 2.1.3 — PineAP captures passively.
        Returns immediately; caller should sleep then call get_networks().
        """
        logger.warning(
            "start_recon() called but firmware 2.1.3 has no recon/start endpoint. "
            "PineAP captures SSIDs passively — ensure PineAP is enabled in the web UI."
        )
        return {"status": "passive — no action needed"}

    def stop_recon(self) -> dict:
        return {"status": "passive — no action needed"}

    def get_networks(self) -> list:
        """
        GET /api/pineap/ssids — returns PineAP SSID pool.

        Response format on 2.1.3:
            {"ssids": "SSID1\\nSSID2\\n#comment\\n..."}

        Returns a normalized list of dicts for the report.
        """
        logger.info("Fetching SSID pool from PineAP (recon equivalent)")
        try:
            data  = self._get("pineap/ssids")
            raw   = data.get("ssids", "")
            ssids = [
                s.strip() for s in raw.split("\n")
                if s.strip() and not s.startswith("#")
            ]
            return [
                {
                    "ssid":       s,
                    "bssid":      "—",
                    "channel":    "—",
                    "signal":     "—",
                    "encryption": "—",
                }
                for s in ssids
            ]
        except PineappleAPIError as e:
            logger.warning(f"Could not fetch SSID pool: {e}")
            return []

    def get_clients(self) -> list:
        """
        GET /api/pineap/clients — returns clients seen by PineAP.
        Normalizes field names for the report.
        """
        logger.info("Fetching clients from PineAP")
        try:
            data    = self._get("pineap/clients")
            clients = data if isinstance(data, list) else data.get("clients", [])
            return [
                {
                    "mac":     c.get("mac", "—"),
                    "ssid":    c.get("ssid", "—"),
                    "signal":  c.get("signal", c.get("tx_bytes", "—")),
                    "packets": c.get("packets", c.get("rx_bytes", "—")),
                }
                for c in clients
            ]
        except PineappleAPIError as e:
            logger.warning(f"Could not fetch clients: {e}")
            return []

    # ------------------------------------------------------------------
    # PineAP settings
    # ------------------------------------------------------------------

    def get_pineap_settings(self) -> dict:
        return self._get("pineap/settings")

    def set_pineap_settings(self, settings: dict) -> dict:
        logger.info("Updating PineAP settings")
        return self._post("pineap/settings", settings)

    def enable_pineap(self) -> dict:
        logger.info("Enabling PineAP")
        current = self.get_pineap_settings()
        s       = current.get("settings", current)
        s["enablePineAP"] = True
        return self._post("pineap/settings", {"settings": s})

    def disable_pineap(self) -> dict:
        logger.info("Disabling PineAP")
        current = self.get_pineap_settings()
        s       = current.get("settings", current)
        s["enablePineAP"] = False
        return self._post("pineap/settings", {"settings": s})

    # ------------------------------------------------------------------
    # Handshakes
    # FIXED: firmware 2.1.3 returns 'location' (full path), not 'filename'.
    # We derive filename from os.path.basename(location).
    # ------------------------------------------------------------------

    def get_handshakes(self) -> list:
        """
        GET /api/pineap/handshakes

        Firmware 2.1.3 returns objects like:
            {"location": "/root/handshakes/74-df-bf-04-e2-eb_lab.pcap",
             "ssid": "lab", "bssid": "74:df:bf:04:e2:eb", ...}

        We normalize so every returned dict has a 'filename' key
        (basename of location) so downstream code works uniformly.
        """
        try:
            data = self._get("pineap/handshakes")
        except PineappleAPIError as e:
            logger.warning(f"Could not fetch handshakes: {e}")
            return []

        raw = data.get("handshakes", data) if isinstance(data, dict) else data
        if not isinstance(raw, list):
            logger.warning(f"Unexpected handshakes response type: {type(raw)}")
            return []

        normalized = []
        for h in raw:
            if not isinstance(h, dict):
                continue
            # 'location' is the full path on device, e.g. /root/handshakes/foo.pcap
            location = h.get("location", h.get("path", ""))
            filename = os.path.basename(location) if location else h.get("filename", "")
            if not filename:
                logger.debug(f"Skipping handshake entry with no filename: {h}")
                continue
            normalized.append({
                "filename":  filename,
                "location":  location,
                "ssid":      h.get("ssid", ""),
                "bssid":     h.get("bssid", ""),
                "timestamp": h.get("date", h.get("timestamp", "")),
            })

        logger.info(f"Found {len(normalized)} handshake(s) on device")
        return normalized

    def download_handshake(self, filename: str, dest_path: str):
        """
        Download a handshake pcap from the Pineapple to local disk.

        Tries two URL patterns used across firmware versions:
            1. /api/pineap/handshakes/<filename>/download  (2.1.3 primary)
            2. /api/pineap/handshakes/<filename>           (fallback)

        If both fail, raises PineappleAPIError with SSH fallback instructions.
        """
        endpoints = [
            f"{self.base_url}/pineap/handshakes/{filename}/download",
            f"{self.base_url}/pineap/handshakes/{filename}",
        ]

        for url in endpoints:
            try:
                logger.info(f"Trying download: {url} → {dest_path}")
                r = requests.get(
                    url, headers=self.headers, timeout=30, stream=True
                )
                r.raise_for_status()
                os.makedirs(os.path.dirname(dest_path) or ".", exist_ok=True)
                with open(dest_path, "wb") as f:
                    for chunk in r.iter_content(chunk_size=8192):
                        f.write(chunk)
                logger.info(f"Handshake saved → {dest_path}")
                return
            except Exception as e:
                logger.debug(f"Download attempt failed ({url}): {e}")
                continue

        raise PineappleAPIError(
            f"Could not download '{filename}' via API. "
            "Both URL patterns returned errors.\n"
            "Manual fallback: scp root@172.16.42.1:/root/handshakes/ ./captures/"
        )

    # ------------------------------------------------------------------
    # Deauth
    # FIXED: dedicated endpoint POST /api/pineap/handshakes/deauth
    # The old code used pineap/settings which returns 404.
    # ------------------------------------------------------------------

    def send_deauth(self, bssid: str, client_mac: str = "FF:FF:FF:FF:FF:FF") -> dict:
        """
        POST /api/pineap/handshakes/deauth

        Sends 802.11 deauth frames to force a WPA reconnect/handshake.

        Args:
            bssid:      Target AP MAC (your lab AP).
            client_mac: Client to deauth. FF:FF:FF:FF:FF:FF = all clients.

        IMPORTANT: Only use against your own authorized lab AP.
        """
        logger.warning(f"Sending deauth → BSSID={bssid}, Client={client_mac}")
        return self._post("pineap/handshakes/deauth", {
            "bssid":  bssid,
            "client": client_mac,
        })
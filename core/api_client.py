"""
api_client.py
-------------
WiFi Pineapple Mark VII REST API client — firmware 2.1.3 confirmed.

Confirmed working endpoints:
    POST /api/login                  → auth, returns {"token": "..."}
    GET  /api/device                 → {"device": "standard"}
    GET  /api/modules                → list of installed modules
    GET  /api/pineap/settings        → full PineAP config dict
    POST /api/pineap/settings        → update PineAP config
    GET  /api/pineap/ssids           → {"ssids": "SSID1\nSSID2\n..."}
    GET  /api/pineap/clients         → list of client dicts
    GET  /api/pineap/handshakes      → {"handshakes": [...]}
    GET  /api/notifications          → notification list

Confirmed NOT available on 2.1.3:
    - Any deauth REST endpoint (Evil Twin module handles this via web UI)
    - /recon/*, /system/stats, /system/info

Handshake object structure (from probe):
    {
        "file_exists": true,
        "mac":         "74:df:bf:04:e2:eb",   ← AP MAC, key is 'mac' not 'bssid'
        "client":      "eviltwin.pcap",         ← original client filename
        "source":      "Evil WPA/2 Twin",
        "type":        "eviltwin",
        "timestamp":   "2025-08-05T01:19:06Z",
        "extension":   "pcap",
        "location":    "/root/handshakes/74-df-bf-04-e2-eb_eviltwin.pcap"
    }

Download URL pattern:
    GET /api/pineap/handshakes/<basename-of-location>/download
    e.g. /api/pineap/handshakes/74-df-bf-04-e2-eb_eviltwin.pcap/download
"""

import os
import requests
from requests.exceptions import ConnectionError, Timeout, HTTPError
from core.config import PineappleConfig
from core.logger import get_logger

logger = get_logger(__name__)


class PineappleAPIError(Exception):
    pass


class PineappleClient:

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
    # Auth
    # ------------------------------------------------------------------

    def authenticate(self) -> bool:
        url = f"{self.base_url}/login"
        try:
            logger.info(f"Authenticating with Pineapple at {url}")
            r = requests.post(
                url,
                json={"username": self.username, "password": self.password},
                timeout=self.timeout
            )
            r.raise_for_status()
            data  = r.json()
            token = data.get("token") or data.get("api_token")
            if not token:
                raise PineappleAPIError(
                    f"Auth response missing token. Keys: {list(data.keys())}"
                )
            self.token = token
            self.headers["Authorization"] = f"Bearer {self.token}"
            logger.info("Authenticated with Pineapple successfully")
            return True
        except ConnectionError:
            raise PineappleAPIError(
                f"Cannot reach Pineapple at {url}. "
                "Is it powered on and connected?"
            )
        except Timeout:
            raise PineappleAPIError(f"Auth timed out: {url}")
        except HTTPError as e:
            raise PineappleAPIError(f"HTTP {r.status_code} during auth: {e}")

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------

    def _get(self, endpoint: str) -> dict | list:
        url = f"{self.base_url}/{endpoint}"
        try:
            r = requests.get(url, headers=self.headers, timeout=self.timeout)
            r.raise_for_status()
            return r.json()
        except ConnectionError:
            raise PineappleAPIError(f"Cannot reach Pineapple at {url}.")
        except Timeout:
            raise PineappleAPIError(f"Timed out: GET {url}")
        except HTTPError as e:
            raise PineappleAPIError(f"HTTP {r.status_code} on GET {endpoint}: {e}")

    def _post(self, endpoint: str, data: dict = None) -> dict | list:
        url = f"{self.base_url}/{endpoint}"
        try:
            r = requests.post(
                url, headers=self.headers,
                json=data or {}, timeout=self.timeout
            )
            r.raise_for_status()
            return r.json() if r.content else {}
        except ConnectionError:
            raise PineappleAPIError(f"Cannot reach Pineapple at {url}.")
        except Timeout:
            raise PineappleAPIError(f"Timed out: POST {url}")
        except HTTPError as e:
            raise PineappleAPIError(f"HTTP {r.status_code} on POST {endpoint}: {e}")

    # ------------------------------------------------------------------
    # System
    # ------------------------------------------------------------------

    def get_info(self) -> dict:
        """GET /api/device"""
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
    # Recon (passive only on 2.1.3)
    # ------------------------------------------------------------------

    def start_recon(self, scan_time: int = 15) -> dict:
        """No-op on 2.1.3 — PineAP captures SSIDs passively."""
        logger.warning(
            "start_recon() called but firmware 2.1.3 has no recon/start endpoint. "
            "PineAP captures SSIDs passively — ensure PineAP is enabled in the web UI."
        )
        return {"status": "passive — no action needed"}

    def stop_recon(self) -> dict:
        return {"status": "passive — no action needed"}

    def get_networks(self) -> list:
        """
        Try three approaches in order, returning the richest result available:

        1. SSH → sqlite3 recon.db  (full: SSID, BSSID, channel, signal, encryption)
        2. /api/pineap/clients     (partial: cross-reference BSSID + signal)
        3. /api/pineap/ssids       (names only — last resort)

        FIX: The original code fell back to names-only whenever SSH failed,
        leaving BSSID/channel/signal/encryption blank in the report.
        This version adds a client-enrichment step between SSH and names-only.
        """
        # ── Attempt 1: SSH recon.db ───────────────────────────────────
        logger.info("Attempting recon.db query via SSH...")
        try:
            networks = self._query_recon_db()
            if networks:
                logger.info(f"recon.db: got {len(networks)} network(s) with full details")
                return networks
            else:
                logger.warning("recon.db query returned 0 rows")
        except Exception as e:
            logger.warning(f"recon.db SSH query failed: {e}")

        # ── Attempt 2: enrich from /api/pineap/clients ────────────────
        # The clients endpoint on 2.1.3 includes bssid/signal per entry,
        # letting us build a richer network list than SSIDs alone.
        logger.info("Falling back: enriching network list from /api/pineap/clients...")
        try:
            client_data = self._get("pineap/clients")
            clients = (
                client_data if isinstance(client_data, list)
                else (client_data or {}).get("clients", []) or []
            )

            # Build ssid → best-signal network entry map
            ssid_map: dict[str, dict] = {}
            for c in clients:
                if not isinstance(c, dict):
                    continue
                ssid = c.get("ssid") or c.get("ap_ssid") or ""
                if not ssid:
                    continue

                # Normalise signal to int for comparison
                raw_sig = c.get("signal", c.get("rssi", "—"))
                try:
                    sig_int = int(str(raw_sig).replace("dBm", "").strip())
                    sig_str = str(sig_int)
                except (ValueError, TypeError):
                    sig_int = -999
                    sig_str = "—"

                existing = ssid_map.get(ssid)
                if existing is None or sig_int > existing.get("_sig", -999):
                    ssid_map[ssid] = {
                        "ssid":       ssid,
                        "bssid":      (c.get("bssid") or c.get("ap_bssid") or "—"),
                        "channel":    str(c.get("channel", "—") or "—"),
                        "signal":     sig_str,
                        "encryption": (c.get("encryption") or c.get("auth") or "—"),
                        "_sig":       sig_int,
                    }

            if ssid_map:
                # Strip internal sort key before returning
                networks = [
                    {k: v for k, v in entry.items() if k != "_sig"}
                    for entry in ssid_map.values()
                ]

                # Overlay any extra SSIDs from the SSID pool not seen in clients
                try:
                    pool_data = self._get("pineap/ssids")
                    raw = (pool_data or {}).get("ssids", "") or ""
                    pool_ssids = [
                        s.strip() for s in raw.split("\n")
                        if s.strip() and not s.startswith("#")
                    ]
                    for ssid in pool_ssids:
                        if ssid not in ssid_map:
                            networks.append({
                                "ssid": ssid, "bssid": "—",
                                "channel": "—", "signal": "—", "encryption": "—",
                            })
                except Exception:
                    pass  # pool overlay is best-effort

                logger.info(
                    f"Client enrichment: {len(networks)} network(s) "
                    f"({len(ssid_map)} with BSSID/signal data)"
                )
                return networks

        except Exception as e:
            logger.warning(f"Client enrichment failed: {e}")

        # ── Attempt 3: SSID names only (last resort) ──────────────────
        logger.info("Last resort: fetching SSID name pool only...")
        try:
            data = self._get("pineap/ssids")
            raw   = (data or {}).get("ssids", "") or ""
            ssids = [
                s.strip() for s in raw.split("\n")
                if s.strip() and not s.startswith("#")
            ]
            logger.warning(
                f"Only SSID names available ({len(ssids)} SSIDs). "
                "BSSID/channel/signal/encryption will show '—'. "
                "For full data ensure SSH is enabled on the Pineapple and "
                "sshpass is installed (sudo apt install sshpass)."
            )
            return [
                {"ssid": s, "bssid": "—", "channel": "—",
                 "signal": "—", "encryption": "—"}
                for s in ssids
            ]
        except PineappleAPIError as e:
            logger.warning(f"Could not fetch SSID pool: {e}")
            return []

    def _query_recon_db(self) -> list:
        """
        SSH into the Pineapple and query /root/recon.db with sqlite3.
        Returns full network rows with BSSID, channel, signal, encryption.

        Improved: raises a descriptive RuntimeError on failure instead of
        silently returning [], so get_networks() can log the real reason.
        """
        import subprocess as _sp, shutil as _sh, json as _json

        host     = self.base_url.split("//")[1].split(":")[0]
        username = self.username
        password = self.password

        if not _sh.which("sshpass"):
            raise RuntimeError(
                "sshpass not installed — run: sudo apt install sshpass. "
                "Without it, SSH-based recon.db queries are unavailable."
            )

        # Try multiple column-name variants to handle schema differences
        queries = [
            "SELECT ssid,bssid,channel,rssi,encryption FROM ssids ORDER BY rssi DESC LIMIT 500",
            "SELECT ssid,bssid,channel,rssi,crypto AS encryption FROM ssids ORDER BY rssi DESC LIMIT 500",
            "SELECT ssid,bssid,channel,signal AS rssi,crypto AS encryption FROM ssids ORDER BY signal DESC LIMIT 500",
            "SELECT ssid,bssid,channel,rssi,encryption FROM networks ORDER BY rssi DESC LIMIT 500",
        ]

        ssh_prefix = [
            "sshpass", "-p", password,
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=10",
            "-o", "BatchMode=no",
            "-o", "LogLevel=ERROR",
            f"{username}@{host}",
        ]

        last_error = "no queries attempted"
        for q in queries:
            try:
                result = _sp.run(
                    ssh_prefix + [f"sqlite3 -json /root/recon.db '{q}'"],
                    capture_output=True, text=True, timeout=20
                )
                stdout = result.stdout.strip()
                stderr = result.stderr.strip()

                if result.returncode != 0:
                    last_error = stderr or f"exit code {result.returncode}"
                    continue

                if not stdout:
                    last_error = "empty result (DB not populated yet or table empty)"
                    continue

                if not stdout.startswith("["):
                    last_error = f"unexpected output: {stdout[:80]}"
                    continue

                rows = _json.loads(stdout)
                return [
                    {
                        "ssid":       r.get("ssid", "—") or "—",
                        "bssid":      r.get("bssid", "—") or "—",
                        "channel":    str(r.get("channel", "—") or "—"),
                        "signal":     str(r.get("rssi",    "—") or "—"),
                        "encryption": r.get("encryption", "—") or "—",
                    }
                    for r in rows if r.get("ssid")
                ]

            except _sp.TimeoutExpired:
                last_error = "SSH connection timed out"
            except Exception as e:
                last_error = str(e)

        raise RuntimeError(
            f"All recon.db query variants failed. Last error: {last_error}\n"
            "Check: 1) SSH enabled on Pineapple  2) correct password in config.yaml  "
            "3) recon has run long enough to populate the DB."
        )

    def get_clients(self) -> list:
        """
        GET /api/pineap/clients
        Returns list of client dicts. Normalizes field names.
        """
        logger.info("Fetching clients from PineAP")
        try:
            data = self._get("pineap/clients")
            # API may return None, a bare list, or {"clients": [...]}
            if not data:
                return []
            clients = data if isinstance(data, list) else data.get("clients", []) or []
            return [
                {
                    "mac":     c.get("mac", "—"),
                    "ssid":    c.get("ssid", "—"),
                    "signal":  c.get("signal", c.get("tx_bytes", "—")),
                    "packets": c.get("packets", c.get("rx_bytes", "—")),
                }
                for c in clients if isinstance(c, dict)
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
        return self._post("pineap/settings", settings)

    def enable_pineap(self) -> dict:
        current = self.get_pineap_settings()
        s = current.get("settings", current)
        s["enablePineAP"] = True
        return self._post("pineap/settings", {"settings": s})

    def disable_pineap(self) -> dict:
        current = self.get_pineap_settings()
        s = current.get("settings", current)
        s["enablePineAP"] = False
        return self._post("pineap/settings", {"settings": s})

    # ------------------------------------------------------------------
    # Handshakes
    # ------------------------------------------------------------------

    def get_handshakes(self) -> list:
        """
        GET /api/pineap/handshakes
        Normalizes all objects to have consistent 'filename' and 'bssid' keys.
        On 2.1.3 the AP MAC is in 'mac', not 'bssid'.
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
            if not h.get("file_exists", True):
                continue  # skip deleted captures

            location = h.get("location", "")
            filename = os.path.basename(location) if location else ""
            if not filename:
                continue

            normalized.append({
                "filename":  filename,
                "location":  location,
                # 2.1.3 uses 'mac' for the AP MAC — normalize to 'bssid' for report
                "bssid":     h.get("mac", h.get("bssid", "")),
                "ssid":      h.get("client", h.get("ssid", "")),
                "source":    h.get("source", ""),
                "type":      h.get("type", ""),
                "extension": h.get("extension", ""),
                "timestamp": h.get("timestamp", ""),
            })

        logger.info(f"Found {len(normalized)} handshake(s) on device")
        return normalized

    def download_handshake(self, filename: str, dest_path: str):
        """
        GET /api/pineap/handshakes/<filename>/download
        Streams the file to dest_path.
        """
        url = f"{self.base_url}/pineap/handshakes/{filename}/download"
        logger.info(f"Downloading: {filename} → {dest_path}")
        try:
            r = requests.get(url, headers=self.headers, timeout=60, stream=True)
            r.raise_for_status()
            os.makedirs(os.path.dirname(dest_path) or ".", exist_ok=True)
            with open(dest_path, "wb") as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
            size_kb = round(os.path.getsize(dest_path) / 1024, 1)
            logger.info(f"Saved {dest_path} ({size_kb} KB)")
        except Exception as e:
            raise PineappleAPIError(
                f"Download failed for '{filename}': {e}\n"
                "Manual fallback: scp root@172.16.42.1:/root/handshakes/ ./captures/"
            )

    def send_deauth(self, bssid: str, client_mac: str = "FF:FF:FF:FF:FF:FF") -> dict:
        """
        Firmware 2.1.3 has NO deauth REST endpoint.
        Deauth is handled by the Evil Twin module via the web UI.
        """
        logger.warning(
            f"send_deauth() called (BSSID={bssid}) — "
            "firmware 2.1.3 has no deauth API endpoint. "
            "Handshakes are captured via Evil Twin (web UI → PineAP → Evil Twin). "
            "Continuing to poll for existing captures..."
        )
        return {"status": "no_deauth_endpoint", "bssid": bssid}
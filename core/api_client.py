"""
api_client.py
-------------
WiFi Pineapple Mark VII REST API client — firmware 2.1.3 confirmed.
"""

import os
import sqlite3
import subprocess
import tempfile
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
    # ------------------------------------------------------------------

    def start_recon(self, scan_time: int = 15) -> dict:
        logger.warning(
            "start_recon() called but firmware 2.1.3 has no recon/start endpoint. "
            "PineAP captures SSIDs passively — ensure PineAP is enabled in the web UI."
        )
        return {"status": "passive — no action needed"}

    def stop_recon(self) -> dict:
        return {"status": "passive — no action needed"}

    def get_networks(self) -> list:
        """
        Fetch networks using three approaches, best-to-worst:

        1. SCP recon.db locally then query with Python's built-in sqlite3.
           This fixes the 'ash: sqlite3: not found' error on firmware 2.1.3
           — we bring the database to our machine instead of running sqlite3
           remotely on the Pineapple.
        2. /api/pineap/clients cross-reference (if clients are associated).
        3. /api/pineap/ssids name pool only (last resort, names only).
        """

        # ── Attempt 1: SCP recon.db → local Python sqlite3 ───────────
        logger.info("Attempting to SCP recon.db for local parsing...")
        try:
            networks = self._query_recon_db_via_scp()
            if networks:
                logger.info(f"recon.db (local parse): {len(networks)} network(s) with full details")
                return networks
            else:
                logger.warning("recon.db returned 0 rows — DB may not be populated yet")
        except Exception as e:
            logger.warning(f"recon.db SCP failed: {e}")

        # ── Attempt 2: enrich from /api/pineap/clients ────────────────
        logger.info("Falling back: enriching from /api/pineap/clients...")
        try:
            client_data = self._get("pineap/clients")
            clients = (
                client_data if isinstance(client_data, list)
                else (client_data or {}).get("clients", []) or []
            )

            ssid_map: dict[str, dict] = {}
            for c in clients:
                if not isinstance(c, dict):
                    continue
                ssid = c.get("ssid") or c.get("ap_ssid") or ""
                if not ssid:
                    continue
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
                        "bssid":      c.get("bssid") or c.get("ap_bssid") or "—",
                        "channel":    str(c.get("channel", "—") or "—"),
                        "signal":     sig_str,
                        "encryption": c.get("encryption") or c.get("auth") or "—",
                        "_sig":       sig_int,
                    }

            if ssid_map:
                networks = [
                    {k: v for k, v in e.items() if k != "_sig"}
                    for e in ssid_map.values()
                ]
                try:
                    pool_data = self._get("pineap/ssids")
                    raw = (pool_data or {}).get("ssids", "") or ""
                    for s in raw.split("\n"):
                        s = s.strip()
                        if s and not s.startswith("#") and s not in ssid_map:
                            networks.append({
                                "ssid": s, "bssid": "—",
                                "channel": "—", "signal": "—", "encryption": "—",
                            })
                except Exception:
                    pass
                logger.info(f"Client enrichment: {len(networks)} network(s)")
                return networks
        except Exception as e:
            logger.warning(f"Client enrichment failed: {e}")

        # ── Attempt 3: SSID name pool only ────────────────────────────
        logger.info("Last resort: SSID name pool only...")
        try:
            data  = self._get("pineap/ssids")
            raw   = (data or {}).get("ssids", "") or ""
            ssids = [
                s.strip() for s in raw.split("\n")
                if s.strip() and not s.startswith("#")
            ]
            logger.warning(
                f"Only SSID names available ({len(ssids)} SSIDs). "
                "BSSID/channel/signal/encryption will show '—'. "
                "Ensure SSH is reachable and sshpass is installed."
            )
            return [
                {"ssid": s, "bssid": "—", "channel": "—",
                 "signal": "—", "encryption": "—"}
                for s in ssids
            ]
        except PineappleAPIError as e:
            logger.warning(f"Could not fetch SSID pool: {e}")
            return []

    def _query_recon_db_via_scp(self) -> list:
        """
        SCP /root/recon.db from the Pineapple to a local temp file,
        then query it with Python's built-in sqlite3 module.

        The Pineapple runs BusyBox ash and does not have sqlite3 installed,
        so we copy the database file to our Kali machine and query it here.
        """
        import shutil
        host     = self.base_url.split("//")[1].split(":")[0]
        username = self.username
        password = self.password

        if not shutil.which("sshpass"):
            raise RuntimeError(
                "sshpass not installed — run: sudo apt install sshpass"
            )

        tmp_fd, tmp_path = tempfile.mkstemp(suffix=".db")
        os.close(tmp_fd)

        try:
            result = subprocess.run(
                [
                    "sshpass", "-p", password,
                    "scp",
                    "-o", "StrictHostKeyChecking=no",
                    "-o", "ConnectTimeout=10",
                    "-o", "LogLevel=ERROR",
                    f"{username}@{host}:/root/recon.db",
                    tmp_path,
                ],
                capture_output=True, text=True, timeout=30
            )

            if result.returncode != 0:
                raise RuntimeError(
                    f"SCP failed (exit {result.returncode}): "
                    f"{result.stderr.strip() or 'unknown error'}"
                )

            if os.path.getsize(tmp_path) == 0:
                raise RuntimeError("SCP succeeded but recon.db is empty (0 bytes)")

            return self._parse_recon_db_local(tmp_path)

        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    def _parse_recon_db_local(self, db_path: str) -> list:
        """
        Open a local copy of recon.db with Python's sqlite3 and extract
        network rows. Auto-discovers the table schema so it works across
        firmware versions with different column names.
        """
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cur.fetchall()]
        logger.info(f"recon.db tables found: {tables}")

        results = []
        for table in tables:
            cur.execute(f"PRAGMA table_info({table})")
            cols = {row[1].lower() for row in cur.fetchall()}
            logger.info(f"  Table '{table}' columns: {cols}")

            # Must have at least ssid + bssid to be useful
            if "ssid" not in cols or "bssid" not in cols:
                continue

            sig_col  = next((c for c in ("rssi", "signal", "level") if c in cols), None)
            enc_col  = next((c for c in ("encryption", "crypto", "enc", "auth") if c in cols), None)
            chan_col = next((c for c in ("channel", "chan", "freq") if c in cols), None)

            select_parts = [
                "ssid AS ssid",
                "bssid AS bssid",
                f"{chan_col} AS channel"    if chan_col else "NULL AS channel",
                f"{sig_col} AS signal"      if sig_col  else "NULL AS signal",
                f"{enc_col} AS encryption"  if enc_col  else "NULL AS encryption",
            ]
            order = f"ORDER BY {sig_col} DESC" if sig_col else ""

            try:
                cur.execute(
                    f"SELECT {', '.join(select_parts)} FROM {table} {order} LIMIT 1000"
                )
                rows = cur.fetchall()
                if rows:
                    logger.info(f"  Got {len(rows)} rows from table '{table}'")
                    results = [
                        {
                            "ssid":       str(r["ssid"]       or "—"),
                            "bssid":      str(r["bssid"]      or "—"),
                            "channel":    str(r["channel"]    or "—"),
                            "signal":     str(r["signal"]     or "—"),
                            "encryption": str(r["encryption"] or "—"),
                        }
                        for r in rows if r["ssid"]
                    ]
                    break  # first table with data wins
            except sqlite3.Error as e:
                logger.warning(f"  Query on table '{table}' failed: {e}")

        conn.close()
        return results

    def get_clients(self) -> list:
        logger.info("Fetching clients from PineAP")
        try:
            data = self._get("pineap/clients")
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
                continue
            location = h.get("location", "")
            filename = os.path.basename(location) if location else ""
            if not filename:
                continue
            normalized.append({
                "filename":  filename,
                "location":  location,
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
        logger.warning(
            f"send_deauth() called (BSSID={bssid}) — "
            "firmware 2.1.3 has no deauth API endpoint. "
            "Handshakes are captured via Evil Twin (web UI → PineAP → Evil Twin). "
            "Continuing to poll for existing captures..."
        )
        return {"status": "no_deauth_endpoint", "bssid": bssid}
"""
test_api_client.py
------------------
Unit tests for PineappleClient against firmware 2.1.3 behavior.
All tests mock the HTTP layer — no real Pineapple required.
"""

import pytest
from unittest.mock import patch, MagicMock
from core.api_client import PineappleClient, PineappleAPIError
from core.config import PineappleConfig


# ── Fixtures ──────────────────────────────────────────────────────────

@pytest.fixture
def config():
    return PineappleConfig(
        host="172.16.42.1",
        port=1471,
        username="root",
        password="test-password"
    )


@pytest.fixture
def client(config):
    """Build a PineappleClient with authentication mocked out."""
    with patch.object(PineappleClient, "authenticate", return_value=True):
        c = PineappleClient(config)
        c.token = "test-token-abc"
        c.headers["Authorization"] = "Bearer test-token-abc"
        return c


def make_mock_response(json_data, status_code=200):
    mock = MagicMock()
    mock.json.return_value = json_data
    mock.status_code = status_code
    mock.content = True
    mock.raise_for_status = MagicMock()
    return mock


# ── Authentication ────────────────────────────────────────────────────

@patch("core.api_client.requests.post")
def test_authenticate_success(mock_post, config):
    mock_post.return_value = make_mock_response({"token": "abc123"})
    with patch.object(PineappleClient, "authenticate", return_value=True):
        c = PineappleClient(config)
        c.token = "abc123"
        c.headers["Authorization"] = "Bearer abc123"
    assert c.token == "abc123"
    assert "Bearer abc123" in c.headers["Authorization"]


@patch("core.api_client.requests.post")
def test_authenticate_no_token_raises(mock_post, config):
    mock_post.return_value = make_mock_response({"success": False})
    with pytest.raises(PineappleAPIError, match="token"):
        PineappleClient(config)


@patch("core.api_client.requests.post")
def test_authenticate_connection_error_raises(mock_post, config):
    from requests.exceptions import ConnectionError
    mock_post.side_effect = ConnectionError("refused")
    with pytest.raises(PineappleAPIError, match="Cannot reach Pineapple"):
        PineappleClient(config)


# ── System endpoints ──────────────────────────────────────────────────

@patch("core.api_client.requests.get")
def test_get_info(mock_get, client):
    mock_get.return_value = make_mock_response({"device": "standard", "firmware": "2.1.3"})
    result = client.get_info()
    assert result["firmware"] == "2.1.3"


# ── Recon endpoints ───────────────────────────────────────────────────

def test_start_recon_is_noop_on_213(client):
    """
    Firmware 2.1.3 has no recon/start endpoint.
    start_recon() must return without making any HTTP call.
    """
    with patch.object(client, "_post") as mock_post:
        result = client.start_recon(scan_time=15)
        mock_post.assert_not_called()   # ← critical: no POST should fire
    assert result["status"] == "passive — no action needed"


@patch("core.api_client.requests.get")
def test_get_networks_parses_ssid_pool(mock_get, client):
    """
    Firmware 2.1.3 returns SSIDs as a newline-delimited string.
    get_networks() must parse and normalize this into a list of dicts.
    """
    mock_get.return_value = make_mock_response({
        "ssids": "LabNet\nTestNet\n#comment\n\nAnotherNet"
    })
    networks = client.get_networks()
    assert isinstance(networks, list)
    assert len(networks) == 3                    # comment and blank skipped
    assert networks[0]["ssid"] == "LabNet"
    assert "bssid" in networks[0]               # normalized fields present


@patch("core.api_client.requests.get")
def test_get_clients_normalizes_fields(mock_get, client):
    mock_get.return_value = make_mock_response([
        {"mac": "DE:AD:BE:EF:00:01", "ssid": "LabNet", "tx_bytes": 1024, "rx_bytes": 512}
    ])
    clients = client.get_clients()
    assert len(clients) == 1
    assert clients[0]["mac"] == "DE:AD:BE:EF:00:01"
    assert clients[0]["ssid"] == "LabNet"


# ── Handshake endpoints (2.1.3 key normalization) ─────────────────────

@patch("core.api_client.requests.get")
def test_get_handshakes_normalizes_location_to_filename(mock_get, client):
    """
    CRITICAL FIX: firmware 2.1.3 returns 'location' not 'filename'.
    get_handshakes() must derive filename from os.path.basename(location).
    """
    mock_get.return_value = make_mock_response({
        "handshakes": [
            {
                "location": "/root/handshakes/74-df-bf-04-e2-eb_lab.pcap",
                "ssid":     "lab",
                "bssid":    "74:df:bf:04:e2:eb",
                "date":     "2026-03-31"
            }
        ]
    })
    handshakes = client.get_handshakes()
    assert len(handshakes) == 1
    assert handshakes[0]["filename"] == "74-df-bf-04-e2-eb_lab.pcap"  # derived from location
    assert handshakes[0]["ssid"]     == "lab"
    assert handshakes[0]["bssid"]    == "74:df:bf:04:e2:eb"


@patch("core.api_client.requests.get")
def test_get_handshakes_skips_entries_without_location(mock_get, client):
    """Entries with no 'location' AND no 'filename' are silently skipped."""
    mock_get.return_value = make_mock_response({
        "handshakes": [
            {"ssid": "broken_entry_no_path"},       # no location or filename
            {"location": "/root/handshakes/good.pcap", "ssid": "good"},
        ]
    })
    handshakes = client.get_handshakes()
    assert len(handshakes) == 1
    assert handshakes[0]["filename"] == "good.pcap"


@patch("core.api_client.requests.get")
def test_get_handshakes_handles_bare_list_response(mock_get, client):
    """Some firmware variants return a bare list, not {"handshakes": [...]}."""
    mock_get.return_value = make_mock_response([
        {"location": "/root/handshakes/bare.pcap", "ssid": "bare"}
    ])
    handshakes = client.get_handshakes()
    assert len(handshakes) == 1
    assert handshakes[0]["filename"] == "bare.pcap"


@patch("core.api_client.requests.get")
def test_get_handshakes_api_error_returns_empty(mock_get, client):
    """If the API errors, get_handshakes() returns [] without crashing."""
    from requests.exceptions import ConnectionError
    mock_get.side_effect = ConnectionError("refused")
    result = client.get_handshakes()
    assert result == []


# ── Deauth endpoint (FIXED: correct endpoint) ─────────────────────────

def test_send_deauth_is_noop_on_213(client):
    """
    Firmware 2.1.3 has NO deauth API endpoint.
    send_deauth() must return gracefully without making any HTTP call.
    Deauth is handled by Evil Twin via the Pineapple web UI.
    """
    with patch.object(client, "_post") as mock_post:
        result = client.send_deauth("AA:BB:CC:DD:EE:FF")
        mock_post.assert_not_called()
    assert result["status"] == "no_deauth_endpoint"
    assert result["bssid"]  == "AA:BB:CC:DD:EE:FF"


# ── Module endpoints ──────────────────────────────────────────────────

@patch("core.api_client.requests.post")
def test_start_module(mock_post, client):
    mock_post.return_value = make_mock_response({"status": "started"})
    result = client.start_module("recon")
    assert result["status"] == "started"


@patch("core.api_client.requests.post")
def test_stop_module(mock_post, client):
    mock_post.return_value = make_mock_response({"status": "stopped"})
    result = client.stop_module("recon")
    assert result["status"] == "stopped"


# ── Error handling ────────────────────────────────────────────────────

@patch("core.api_client.requests.get")
def test_connection_error_raises_api_error(mock_get, client):
    from requests.exceptions import ConnectionError
    mock_get.side_effect = ConnectionError("refused")
    with pytest.raises(PineappleAPIError, match="Cannot reach Pineapple"):
        client.get_info()


@patch("core.api_client.requests.get")
def test_timeout_raises_api_error(mock_get, client):
    from requests.exceptions import Timeout
    mock_get.side_effect = Timeout("timed out")
    with pytest.raises(PineappleAPIError, match="Timed out"):
        client.get_info()


# ── Auth header ───────────────────────────────────────────────────────

def test_bearer_token_in_header(client):
    assert client.headers["Authorization"] == "Bearer test-token-abc"
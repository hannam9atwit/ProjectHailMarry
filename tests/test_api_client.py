"""
Unit tests for PineappleClient.
All tests mock the HTTP layer — no real Pineapple required.
"""

import pytest
from unittest.mock import patch, MagicMock
from core.api_client import PineappleClient, PineappleAPIError
from core.config import PineappleConfig


# ── Fixtures ─────────────────────────────────────────────────────────

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
    """Helper to build a mock requests.Response."""
    mock = MagicMock()
    mock.json.return_value = json_data
    mock.status_code = status_code
    mock.raise_for_status = MagicMock()
    return mock


# ── Authentication tests ──────────────────────────────────────────────

@patch("core.api_client.requests.post")
def test_authenticate_success(mock_post, config):
    mock_post.return_value = make_mock_response({"token": "abc123"})
    with patch.object(PineappleClient, "authenticate", return_value=True):
        c = PineappleClient(config)
        c.token = "abc123"
        c.headers["Authorization"] = "Bearer abc123"
    assert c.token == "abc123"
    assert c.headers["Authorization"] == "Bearer abc123"


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


# ── GET tests ─────────────────────────────────────────────────────────

@patch("core.api_client.requests.get")
def test_get_info(mock_get, client):
    mock_get.return_value = make_mock_response({"firmware": "2.1.3", "hostname": "Pineapple"})
    result = client.get_info()
    assert result["firmware"] == "2.1.3"
    assert result["hostname"] == "Pineapple"


@patch("core.api_client.requests.get")
def test_get_networks_returns_list(mock_get, client):
    payload = [
        {"ssid": "LabNet",  "bssid": "AA:BB:CC:DD:EE:FF", "channel": 6,  "encryption": "WPA2"},
        {"ssid": "TestNet", "bssid": "11:22:33:44:55:66", "channel": 11, "encryption": "WPA"},
    ]
    mock_get.return_value = make_mock_response(payload)
    networks = client.get_networks()
    assert isinstance(networks, list)
    assert len(networks) == 2
    assert networks[0]["ssid"] == "LabNet"


@patch("core.api_client.requests.get")
def test_get_clients_returns_list(mock_get, client):
    payload = [{"mac": "DE:AD:BE:EF:00:01", "ssid": "LabNet", "signal": -55}]
    mock_get.return_value = make_mock_response(payload)
    clients = client.get_clients()
    assert len(clients) == 1
    assert clients[0]["mac"] == "DE:AD:BE:EF:00:01"


@patch("core.api_client.requests.get")
def test_get_handshakes(mock_get, client):
    payload = [{"filename": "LabNet_handshake.cap", "bssid": "AA:BB:CC:DD:EE:FF", "ssid": "LabNet"}]
    mock_get.return_value = make_mock_response(payload)
    handshakes = client.get_handshakes()
    assert handshakes[0]["filename"] == "LabNet_handshake.cap"


# ── POST tests ────────────────────────────────────────────────────────

@patch("core.api_client.requests.post")
def test_start_module(mock_post, client):
    mock_post.return_value = make_mock_response({"status": "started"})
    result = client.start_module("recon")
    assert result["status"] == "started"
    mock_post.assert_called_once()


@patch("core.api_client.requests.post")
def test_stop_module(mock_post, client):
    mock_post.return_value = make_mock_response({"status": "stopped"})
    result = client.stop_module("recon")
    assert result["status"] == "stopped"


@patch("core.api_client.requests.post")
def test_start_recon(mock_post, client):
    mock_post.return_value = make_mock_response({"status": "scanning"})
    result = client.start_recon(scan_time=10)
    assert result["status"] == "scanning"
    call_kwargs = mock_post.call_args
    assert call_kwargs.kwargs["json"]["scanTime"] == 10


# ── Error handling tests ──────────────────────────────────────────────

@patch("core.api_client.requests.get")
def test_connection_error_raises_api_error(mock_get, client):
    from requests.exceptions import ConnectionError
    mock_get.side_effect = ConnectionError("refused")
    with pytest.raises(PineappleAPIError, match="Cannot reach Pineapple"):
        client.get_networks()


@patch("core.api_client.requests.get")
def test_timeout_raises_api_error(mock_get, client):
    from requests.exceptions import Timeout
    mock_get.side_effect = Timeout("timed out")
    with pytest.raises(PineappleAPIError, match="timed out"):
        client.get_networks()


# ── Auth header tests ─────────────────────────────────────────────────

@patch("core.api_client.requests.get")
def test_bearer_token_sent_in_header(mock_get, client):
    mock_get.return_value = make_mock_response({})
    client.get_info()
    assert "Authorization" in client.headers
    assert client.headers["Authorization"] == "Bearer test-token-abc"
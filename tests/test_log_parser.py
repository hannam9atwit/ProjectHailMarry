"""
Unit tests for LogParser.
Tests pattern matching, filtering, and JSON normalization.
"""

import json
import pytest
import tempfile
import os
from parsers.log_parser import LogParser


@pytest.fixture
def parser():
    return LogParser()


@pytest.fixture
def sample_log_file():
    """Create a temp log file with mixed-format entries."""
    lines = [
        "2024-03-15 14:22:01 [INFO] Recon started on wlan1mon",
        "2024-03-15 14:22:05 [INFO] Found SSID: LabNet BSSID: AA:BB:CC:DD:EE:FF CH: 6",
        "2024-03-15 14:22:10 [WARN] Client DE:AD:BE:EF:00:01 probe request detected",
        "2024-03-15 14:22:15 [ERROR] Module handshake failed to start",
        "This is a malformed line with no structure at all !!!",
        "",  # blank line — should be skipped
        "2024-03-15 14:22:30 [INFO] EAPOL frame captured from AA:BB:CC:DD:EE:FF",
    ]
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        f.write("\n".join(lines))
        return f.name


# ── parse_line tests ──────────────────────────────────────────────────

def test_parse_line_extracts_timestamp(parser):
    line = "2024-03-15 14:22:01 [INFO] Something happened"
    result = parser.parse_line(line)
    assert result["timestamp"] == "2024-03-15 14:22:01"


def test_parse_line_extracts_level(parser):
    for level in ["INFO", "WARN", "ERROR", "DEBUG"]:
        line = f"[{level}] some message"
        result = parser.parse_line(line)
        assert result["level"] == level


def test_parse_line_extracts_mac(parser):
    line = "Client AA:BB:CC:DD:EE:FF connected"
    result = parser.parse_line(line)
    assert result["mac"] == "AA:BB:CC:DD:EE:FF"


def test_parse_line_extracts_ssid(parser):
    line = "SSID: MyNetwork detected"
    result = parser.parse_line(line)
    assert result["ssid"] == "MyNetwork"


def test_parse_line_no_match_returns_none_fields(parser):
    line = "this line has nothing useful in it"
    result = parser.parse_line(line)
    assert result["timestamp"] is None
    assert result["mac"] is None
    assert result["raw"] == line  # raw always preserved


# ── parse_file tests ──────────────────────────────────────────────────

def test_parse_file_skips_blank_lines(parser, sample_log_file):
    entries = parser.parse_file(sample_log_file)
    # blank lines are skipped
    assert all(e["raw"] != "" for e in entries)
    os.unlink(sample_log_file)


def test_parse_file_correct_count(parser, sample_log_file):
    entries = parser.parse_file(sample_log_file)
    assert len(entries) == 6  # 7 lines minus 1 blank
    os.unlink(sample_log_file)


def test_parse_file_missing_file(parser):
    result = parser.parse_file("/nonexistent/path/file.log")
    assert result == []


# ── normalize_to_json tests ───────────────────────────────────────────

def test_normalize_to_json_creates_file(parser, sample_log_file):
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as out:
        out_path = out.name

    parser.normalize_to_json(sample_log_file, out_path)
    assert os.path.exists(out_path)

    with open(out_path) as f:
        data = json.load(f)
    assert isinstance(data, list)
    assert len(data) > 0

    os.unlink(sample_log_file)
    os.unlink(out_path)


# ── filter tests ─────────────────────────────────────────────────────

def test_filter_by_level(parser, sample_log_file):
    entries = parser.parse_file(sample_log_file)
    errors  = parser.filter_by_level(entries, "ERROR")
    assert all(e["level"] == "ERROR" for e in errors)
    assert len(errors) == 1
    os.unlink(sample_log_file)


def test_get_unique_macs(parser):
    entries = [
        {"mac": "AA:BB:CC:DD:EE:FF"},
        {"mac": "11:22:33:44:55:66"},
        {"mac": "AA:BB:CC:DD:EE:FF"},  # duplicate
        {"mac": None},
    ]
    macs = parser.get_unique_macs(entries)
    assert len(macs) == 2


def test_get_unique_ssids(parser):
    entries = [
        {"ssid": "LabNet"},
        {"ssid": "TestNet"},
        {"ssid": "LabNet"},
        {"ssid": None},
    ]
    ssids = parser.get_unique_ssids(entries)
    assert len(ssids) == 2
    assert "LabNet" in ssids
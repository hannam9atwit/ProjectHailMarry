"""
test_log_parser.py
------------------
Unit tests for LogParser.
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
    lines = [
        "2024-03-15 14:22:01 [INFO] Recon started on wlan1mon",
        "2024-03-15 14:22:05 [INFO] Found SSID: LabNet BSSID: AA:BB:CC:DD:EE:FF CH: 6",
        "2024-03-15 14:22:10 [WARN] Client DE:AD:BE:EF:00:01 probe request detected",
        "2024-03-15 14:22:15 [ERROR] Module handshake failed to start",
        "This is a malformed line with no structure at all !!!",
        "",  # blank — should be skipped
        "2024-03-15 14:22:30 [INFO] EAPOL frame captured from AA:BB:CC:DD:EE:FF",
    ]
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        f.write("\n".join(lines))
        return f.name


# ── parse_line ────────────────────────────────────────────────────────

def test_parse_line_extracts_timestamp(parser):
    line = "2024-03-15 14:22:01 [INFO] Something happened"
    assert parser.parse_line(line)["timestamp"] == "2024-03-15 14:22:01"


def test_parse_line_extracts_level(parser):
    for level in ["INFO", "WARN", "ERROR", "DEBUG"]:
        assert parser.parse_line(f"[{level}] msg")["level"] == level


def test_parse_line_extracts_mac(parser):
    assert parser.parse_line("Client AA:BB:CC:DD:EE:FF connected")["mac"] == "AA:BB:CC:DD:EE:FF"


def test_parse_line_extracts_ssid(parser):
    assert parser.parse_line("SSID: MyNetwork detected")["ssid"] == "MyNetwork"


def test_parse_line_no_match_returns_none_fields(parser):
    result = parser.parse_line("nothing useful here")
    assert result["timestamp"] is None
    assert result["mac"] is None
    assert result["raw"] == "nothing useful here"


# ── parse_file ────────────────────────────────────────────────────────

def test_parse_file_skips_blank_lines(parser, sample_log_file):
    entries = parser.parse_file(sample_log_file)
    assert all(e["raw"] != "" for e in entries)
    os.unlink(sample_log_file)


def test_parse_file_correct_count(parser, sample_log_file):
    entries = parser.parse_file(sample_log_file)
    assert len(entries) == 6   # 7 lines minus 1 blank
    os.unlink(sample_log_file)


def test_parse_file_missing_file(parser):
    assert parser.parse_file("/nonexistent/file.log") == []


# ── normalize_to_json ─────────────────────────────────────────────────

def test_normalize_to_json_creates_file(parser, sample_log_file):
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as out:
        out_path = out.name
    parser.normalize_to_json(sample_log_file, out_path)
    with open(out_path) as f:
        data = json.load(f)
    assert isinstance(data, list) and len(data) > 0
    os.unlink(sample_log_file)
    os.unlink(out_path)


# ── filter_by_level ───────────────────────────────────────────────────

def test_filter_by_level(parser, sample_log_file):
    entries = parser.parse_file(sample_log_file)
    errors  = parser.filter_by_level(entries, "ERROR")
    assert len(errors) == 1
    assert all(e["level"] == "ERROR" for e in errors)
    os.unlink(sample_log_file)


def test_filter_by_level_handles_none_level(parser):
    """Entries where level is None must not crash filter_by_level."""
    entries = [
        {"level": "INFO",  "raw": "a"},
        {"level": None,    "raw": "b"},   # malformed line — level not found
        {"level": "ERROR", "raw": "c"},
    ]
    errors = parser.filter_by_level(entries, "ERROR")
    assert len(errors) == 1
    assert errors[0]["raw"] == "c"


# ── unique helpers ────────────────────────────────────────────────────

def test_get_unique_macs(parser):
    entries = [
        {"mac": "AA:BB:CC:DD:EE:FF"},
        {"mac": "11:22:33:44:55:66"},
        {"mac": "AA:BB:CC:DD:EE:FF"},  # duplicate
        {"mac": None},
    ]
    assert len(parser.get_unique_macs(entries)) == 2


def test_get_unique_ssids(parser):
    entries = [
        {"ssid": "LabNet"}, {"ssid": "TestNet"},
        {"ssid": "LabNet"}, {"ssid": None},
    ]
    ssids = parser.get_unique_ssids(entries)
    assert len(ssids) == 2
    assert "LabNet" in ssids
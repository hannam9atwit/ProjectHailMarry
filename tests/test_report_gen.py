"""
Unit tests for ReportGenerator.
Verifies context building, HTML output, and JSON saving.
"""

import os
import json
import pytest
import tempfile
from reporting.report_gen import ReportGenerator


SAMPLE_DATA = {
    "tester":       "Test Student",
    "target_scope": "Lab Router (Authorized)",
    "networks": [
        {"ssid": "LabNet",  "bssid": "AA:BB:CC:DD:EE:FF", "channel": 6,  "signal": -45, "encryption": "WPA2"},
        {"ssid": "OpenNet", "bssid": "11:22:33:44:55:66", "channel": 1,  "signal": -70, "encryption": "OPEN"},
    ],
    "clients": [
        {"mac": "DE:AD:BE:EF:00:01", "ssid": "LabNet", "signal": -55, "packets": 120},
    ],
    "captures": [
        {
            "filename":   "LabNet_handshake.cap",
            "ssid":       "LabNet",
            "bssid":      "AA:BB:CC:DD:EE:FF",
            "timestamp":  "2024-03-15 14:30:00",
            "local_path": "./captures/LabNet_handshake.cap",
        }
    ],
    "pcap_stats": {
        "file":            "./captures/LabNet_handshake.cap",
        "file_size_kb":    42.0,
        "total_frames":    350,
        "eapol_frames":    4,
        "mgmt_frames":     80,
        "unique_macs":     5,
        "handshake_found": True,
    },
    "log_stats": {
        "total":       150,
        "errors":      2,
        "warnings":    8,
        "unique_macs": 3,
    },
    "errors": [],
}


@pytest.fixture
def report_gen(tmp_path):
    template_dir = str((tmp_path / "templates"))
    output_dir   = str((tmp_path / "reports"))
    os.makedirs(template_dir)
    os.makedirs(output_dir)

    # Write a minimal template
    template_path = os.path.join(template_dir, "report.html")
    with open(template_path, "w") as f:
        f.write("""<!DOCTYPE html><html><body>
<p>Networks: {{ network_count }}</p>
<p>Clients: {{ client_count }}</p>
<p>Handshake: {{ handshake_found }}</p>
<p>Generated: {{ generated_at }}</p>
</body></html>""")

    return ReportGenerator(template_dir=template_dir, output_dir=output_dir)


# ── context building ──────────────────────────────────────────────────

def test_build_context_counts(report_gen):
    ctx = report_gen._build_context(SAMPLE_DATA)
    assert ctx["network_count"] == 2
    assert ctx["client_count"]  == 1
    assert ctx["capture_count"] == 1


def test_build_context_handshake_flag(report_gen):
    ctx = report_gen._build_context(SAMPLE_DATA)
    assert ctx["handshake_found"] is True
    assert ctx["eapol_count"] == 4


def test_build_context_defaults_for_missing_data(report_gen):
    ctx = report_gen._build_context({})
    assert ctx["network_count"]  == 0
    assert ctx["client_count"]   == 0
    assert ctx["capture_count"]  == 0
    assert ctx["handshake_found"] is False


# ── HTML generation ───────────────────────────────────────────────────

def test_generate_html_creates_file(report_gen):
    path = report_gen.generate_html(SAMPLE_DATA, filename="test_report")
    assert os.path.exists(path)
    assert path.endswith(".html")


def test_generate_html_contains_data(report_gen):
    path = report_gen.generate_html(SAMPLE_DATA, filename="test_report2")
    with open(path) as f:
        content = f.read()
    assert "2" in content          # network count
    assert "True" in content       # handshake found


def test_generate_html_missing_template_raises(tmp_path):
    rg = ReportGenerator(template_dir=str(tmp_path / "empty"), output_dir=str(tmp_path / "out"))
    os.makedirs(str(tmp_path / "empty"))
    os.makedirs(str(tmp_path / "out"))
    with pytest.raises(FileNotFoundError):
        rg.generate_html(SAMPLE_DATA)


# ── JSON save ─────────────────────────────────────────────────────────

def test_save_json_creates_file(report_gen):
    path = report_gen.save_json(SAMPLE_DATA, filename="test_results")
    assert os.path.exists(path)
    with open(path) as f:
        data = json.load(f)
    assert data["tester"] == "Test Student"
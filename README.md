# Python-Based Pineapple Automation Suite
**COMP4500 · Offensive Security · Spring 2026**

A modular Python automation suite for scripted wireless penetration testing workflows using the WiFi Pineapple. Automates module deployment, WPA handshake capture, packet analysis via tshark, and professional report generation.

> **Ethical Notice:** All testing performed exclusively in authorized lab environments. No real-world networks or users were affected.

---

## Project Structure

```
pineapple_suite/
├── core/
│   ├── api_client.py       # WiFi Pineapple REST API wrapper
│   ├── config.py           # Config loader + pydantic validation
│   └── logger.py           # Centralised color + file logging
├── modules/
│   ├── base_module.py      # Abstract plugin base class
│   ├── recon.py            # Network/client recon module
│   └── handshake.py        # WPA handshake capture module
├── parsers/
│   ├── log_parser.py       # Log normalization → JSON
│   └── pcap_parser.py      # tshark integration + EAPOL filtering
├── reporting/
│   ├── report_gen.py       # HTML + PDF report generator
│   └── templates/
│       └── report.html     # Jinja2 report template
├── tests/
│   ├── test_api_client.py
│   ├── test_log_parser.py
│   └── test_report_gen.py
├── logs/                   # Runtime logs (git-ignored)
├── captures/               # Downloaded .cap files (git-ignored)
├── reports/                # Generated reports (git-ignored)
├── config.example.yaml     # Template config (copy → config.yaml)
├── requirements.txt
└── main.py                 # Main orchestrator
```

---

## Setup

### 1. Clone and create virtual environment
```bash
git clone https://github.com/hannam9atwit/ProjectHailMarry/
cd pineapple_suite
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Install system dependencies
```bash
sudo apt install tshark wireshark aircrack-ng -y
sudo usermod -aG wireshark $USER && newgrp wireshark
```

### 3. Configure
```bash
cp config.example.yaml config.yaml
# Edit config.yaml — paste your Pineapple API token
```

---

## Usage

```bash
# Full run (recon → handshake → pcap analysis → report)
python main.py

# Recon + report only (no handshake capture)
python main.py --skip-handshake

# Specify target BSSID directly (no interactive prompt)
python main.py --target-bssid AA:BB:CC:DD:EE:FF

# Analyse an existing pcap file (skip live stages)
python main.py --skip-recon --skip-handshake --pcap captures/lab.cap

# HTML report only (no PDF)
python main.py --no-pdf

# See all options
python main.py --help
```

---

## Running Tests

```bash
pytest tests/ -v
```

All tests mock the network layer — no live Pineapple required.

---

## Key Design Decisions

| Decision | Rationale |
|---|---|
| `BaseModule` abstract class | Plugin architecture — add new modules without touching core |
| `pydantic` config validation | Config errors fail fast with clear messages |
| `colorlog` + file logging | Readable console output + persistent audit trail |
| `subprocess` + tshark JSON mode | Clean integration with Wireshark ecosystem |
| Jinja2 HTML → weasyprint PDF | Fully customizable reports, no external API needed |

---

## References
- WiFi Pineapple API documentation — hak5.org/pages/pineapple
- Python `requests` library — docs.python-requests.org
- Wireshark/tshark documentation — wireshark.org/docs/man-pages/tshark.html
- Jinja2 templating — jinja.palletsprojects.com
- WeasyPrint PDF — weasyprint.org

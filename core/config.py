"""
config.py
---------
Loads and validates project configuration from config.yaml.
Uses pydantic v2 for strict type checking — bad configs fail fast.
"""

import yaml
from pydantic import BaseModel
from pathlib import Path


class PineappleConfig(BaseModel):
    host:     str = "172.16.42.1"
    port:     int = 1471
    username: str = "root"
    password: str            # required — no default


class TsharkConfig(BaseModel):
    binary_path:       str = "/usr/bin/tshark"
    capture_interface: str = "wlan1mon"
    capture_duration:  int = 30


class ReportingConfig(BaseModel):
    output_dir:   str = "./reports"
    template_dir: str = "./reporting/templates"


class LoggingConfig(BaseModel):
    level:   str = "INFO"
    log_dir: str = "./logs"


class AppConfig(BaseModel):
    pineapple: PineappleConfig
    tshark:    TsharkConfig
    reporting: ReportingConfig
    logging:   LoggingConfig


def load_config(config_path: str = "config.yaml") -> AppConfig:
    """
    Load and validate configuration from a YAML file.

    Args:
        config_path: Path to the config YAML file.

    Returns:
        Validated AppConfig object.

    Raises:
        FileNotFoundError: If config file does not exist.
        ValidationError:   If any config values are invalid.
    """
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(
            f"Config file not found: {config_path}\n"
            "Copy config.example.yaml to config.yaml and fill in your password."
        )

    with open(path) as f:
        raw = yaml.safe_load(f)

    return AppConfig(**raw)
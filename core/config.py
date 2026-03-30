"""
Loads and validates the project configuration from config.yaml.
Uses pydantic for strict type checking so bad configs fail fast with clear errors.
"""

import yaml
from pydantic import BaseModel, Field
from pathlib import Path


class PineappleConfig(BaseModel):
    host: str = "172.16.42.1"
    port: int = 1471
    token: str


class TsharkConfig(BaseModel):
    binary_path: str = "/usr/bin/tshark"
    capture_interface: str = "wlan1mon"
    capture_duration: int = 30


class ReportingConfig(BaseModel):
    output_dir: str = "./reports"
    template_dir: str = "./reporting/templates"


class LoggingConfig(BaseModel):
    level: str = "INFO"
    log_dir: str = "./logs"


class AppConfig(BaseModel):
    pineapple: PineappleConfig
    tshark: TsharkConfig
    reporting: ReportingConfig
    logging: LoggingConfig


def load_config(config_path: str = "config.yaml") -> AppConfig:
    """
    Load and validate configuration from a YAML file.

    Args:
        config_path: Path to the config YAML file.

    Returns:
        Validated AppConfig object.

    Raises:
        FileNotFoundError: If config file does not exist.
        ValidationError: If any config values are invalid.
    """
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(
            f"Config file not found: {config_path}\n"
            "Copy config.example.yaml to config.yaml and fill in your token."
        )

    with open(path) as f:
        raw = yaml.safe_load(f)

    return AppConfig(**raw)
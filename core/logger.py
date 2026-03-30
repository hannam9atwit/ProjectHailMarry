"""
Centralised logging setup for the entire suite.
Outputs color-coded logs to console and plain logs to file.
"""

import logging
import colorlog
from pathlib import Path
from datetime import datetime


def get_logger(name: str, log_dir: str = "./logs", level: str = "INFO") -> logging.Logger:
    """
    Create and return a named logger with console + file handlers.

    Args:
        name:    Logger name (usually __name__ of the calling module).
        log_dir: Directory where log files are written.
        level:   Logging level string e.g. 'INFO', 'DEBUG'.

    Returns:
        Configured Logger instance.
    """
    Path(log_dir).mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Avoid adding duplicate handlers if logger already configured
    if logger.handlers:
        return logger

    # --- Console handler (color) ---
    console_handler = colorlog.StreamHandler()
    console_handler.setFormatter(colorlog.ColoredFormatter(
        "%(log_color)s[%(asctime)s] [%(name)s] [%(levelname)s]%(reset)s %(message)s",
        datefmt="%H:%M:%S",
        log_colors={
            "DEBUG":    "cyan",
            "INFO":     "green",
            "WARNING":  "yellow",
            "ERROR":    "red",
            "CRITICAL": "bold_red",
        }
    ))

    # --- File handler (plain text) ---
    log_file = Path(log_dir) / f"suite_{datetime.now().strftime('%Y%m%d')}.log"
    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(logging.Formatter(
        "[%(asctime)s] [%(name)s] [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    ))

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    return logger
"""
Abstract base class for all attack/recon modules.
Every module must implement run() and get_results().
This plugin-style architecture lets you add new modules
without touching any other part of the codebase.
"""

from abc import ABC, abstractmethod
from core.api_client import PineappleClient
from core.logger import get_logger


class BaseModule(ABC):
    """
    Abstract base for all Pineapple automation modules.

    Subclass this and implement:
        - run()         → executes the module's primary task
        - get_results() → returns structured dict for reporting
    """

    def __init__(self, client: PineappleClient, log_dir: str = "./logs"):
        self.client = client
        self.results: dict = {}
        self.logger = get_logger(self.__class__.__name__, log_dir=log_dir)

    @abstractmethod
    def run(self):
        """Execute the module's primary task."""
        pass

    @abstractmethod
    def get_results(self) -> dict:
        """Return structured results consumed by the report generator."""
        pass

    def summary(self) -> str:
        """
        Human-readable one-line summary of results.
        Override in subclasses for custom summaries.
        """
        return f"{self.__class__.__name__}: {len(self.results)} result(s)"
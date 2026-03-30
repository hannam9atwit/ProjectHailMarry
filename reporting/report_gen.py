"""
Generates automated penetration test reports from collected module results.

Supports:
  - HTML report via Jinja2 template
  - PDF export via weasyprint (from the HTML output)

The report aggregates:
  - Recon results (networks + clients)
  - Handshake capture metadata
  - Log analysis summary
  - Pcap statistics
"""

import os
import json
from pathlib import Path
from datetime import datetime
from jinja2 import Environment, FileSystemLoader, TemplateNotFound
from core.logger import get_logger

logger = get_logger(__name__)


class ReportGenerator:
    """
    Produces HTML and PDF penetration test reports from structured data.

    Args:
        template_dir: Directory containing Jinja2 HTML templates.
        output_dir:   Directory where reports are saved.
    """

    def __init__(self, template_dir: str = "./reporting/templates", output_dir: str = "./reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.env = Environment(loader=FileSystemLoader(template_dir))
        logger.info(f"ReportGenerator ready — output dir: {output_dir}")

    def _build_context(self, data: dict) -> dict:
        """
        Build the full template context from raw module result data.
        Adds computed fields like counts, timestamps, and flags.
        """
        networks   = data.get("networks", [])
        clients    = data.get("clients", [])
        captures   = data.get("captures", [])
        log_stats  = data.get("log_stats", {})
        pcap_stats = data.get("pcap_stats", {})

        return {
            "generated_at":     datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "tester":           data.get("tester", "Student Researcher"),
            "target_scope":     data.get("target_scope", "Lab Environment (Authorized)"),
            "networks":         networks,
            "clients":          clients,
            "captures":         captures,
            "log_stats":        log_stats,
            "pcap_stats":       pcap_stats,
            "network_count":    len(networks),
            "client_count":     len(clients),
            "capture_count":    len(captures),
            "handshake_found":  pcap_stats.get("handshake_found", False),
            "eapol_count":      pcap_stats.get("eapol_frames", 0),
            "total_frames":     pcap_stats.get("total_frames", 0),
            "unique_macs":      pcap_stats.get("unique_macs", 0),
            "errors":           data.get("errors", []),
        }

    def generate_html(self, data: dict, filename: str = None) -> str:
        """
        Render HTML report from collected data.

        Args:
            data:     Dict of results from all modules.
            filename: Output filename (without extension). Auto-generated if None.

        Returns:
            Path to the saved HTML file.
        """
        try:
            template = self.env.get_template("report.html")
        except TemplateNotFound:
            raise FileNotFoundError(
                "report.html template not found in template directory. "
                "Make sure reporting/templates/report.html exists."
            )

        context = self._build_context(data)
        html    = template.render(**context)

        fname    = filename or f"pentest_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        out_path = self.output_dir / f"{fname}.html"

        with open(out_path, "w", encoding="utf-8") as f:
            f.write(html)

        logger.info(f"HTML report saved: {out_path}")
        return str(out_path)

    def generate_pdf(self, html_path: str) -> str:
        """
        Convert an HTML report to PDF using weasyprint.

        Args:
            html_path: Path to the HTML report file.

        Returns:
            Path to the saved PDF file.
        """
        try:
            from weasyprint import HTML
        except ImportError:
            raise ImportError("weasyprint is not installed. Run: pip install weasyprint")

        pdf_path = html_path.replace(".html", ".pdf")
        logger.info(f"Converting HTML → PDF: {pdf_path}")
        HTML(filename=html_path).write_pdf(pdf_path)
        logger.info(f"PDF report saved: {pdf_path}")
        return pdf_path

    def generate(self, data: dict, filename: str = None, pdf: bool = True) -> dict:
        """
        Full report generation — HTML and optionally PDF.

        Args:
            data:     Aggregated results dict from all modules.
            filename: Base filename (no extension).
            pdf:      Whether to also produce a PDF.

        Returns:
            Dict with keys 'html' and optionally 'pdf' pointing to output paths.
        """
        html_path = self.generate_html(data, filename)
        result    = {"html": html_path}

        if pdf:
            try:
                pdf_path       = self.generate_pdf(html_path)
                result["pdf"]  = pdf_path
            except Exception as e:
                logger.warning(f"PDF generation failed (HTML still saved): {e}")

        return result

    def save_json(self, data: dict, filename: str = None) -> str:
        """
        Save raw results data as JSON for archival/debugging.

        Args:
            data:     The results dict.
            filename: Output filename (without extension).

        Returns:
            Path to saved JSON file.
        """
        fname    = filename or f"results_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        out_path = self.output_dir / f"{fname}.json"

        with open(out_path, "w") as f:
            json.dump(data, f, indent=2, default=str)

        logger.info(f"Raw results saved: {out_path}")
        return str(out_path)
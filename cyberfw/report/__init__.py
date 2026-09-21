"""Report generation subsystem (HTML / JSON)."""

from cyberfw.report.html_report import generate_html_report
from cyberfw.report.json_report import generate_json_report

__all__ = ["generate_json_report", "generate_html_report"]

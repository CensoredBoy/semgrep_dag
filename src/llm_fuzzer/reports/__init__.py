"""
Reports module - генераторы отчётов.
"""

from .json_report import JSONReportGenerator
from .markdown_report import MarkdownReportGenerator

__all__ = [
    "JSONReportGenerator",
    "MarkdownReportGenerator",
]

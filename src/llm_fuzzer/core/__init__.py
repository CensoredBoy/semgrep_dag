"""
Core module - базовые контракты и абстракции.
"""

from .contracts import ScannerAdapter, ReportGenerator
from .target import TargetConfig, TargetType
from .check import CheckConfig, CheckResult, CheckStatus, Finding, Severity

__all__ = [
    "ScannerAdapter",
    "ReportGenerator",
    "TargetConfig",
    "TargetType",
    "CheckConfig",
    "CheckResult",
    "CheckStatus",
    "Finding",
    "Severity",
]

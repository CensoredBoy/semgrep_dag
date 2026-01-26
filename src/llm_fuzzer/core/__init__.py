"""
Core module - базовые контракты и абстракции.
"""

from .contracts import ScannerAdapter, ReportGenerator
from .target import TargetConfig, TargetType
from .check import CheckConfig, CheckResult, CheckStatus, Finding, Severity
from .attack_catalog import (
    AttackInfo,
    get_attack_info,
    get_attacks_by_category,
    get_all_categories,
    get_all_attacks_as_dicts,
    ALL_ATTACKS,
)
from .detector_catalog import (
    DetectorInfo,
    ScorerInfo,
    DetectorType,
    ScorerType,
    get_detector,
    get_scorer,
    get_detectors_for_category,
    get_scorers_for_category,
    get_all_detectors_as_dicts,
    get_all_scorers_as_dicts,
    get_llm_judge_prompt,
    ALL_DETECTORS,
    ALL_SCORERS,
)

__all__ = [
    # Contracts
    "ScannerAdapter",
    "ReportGenerator",
    # Target
    "TargetConfig",
    "TargetType",
    # Check
    "CheckConfig",
    "CheckResult",
    "CheckStatus",
    "Finding",
    "Severity",
    # Attack Catalog
    "AttackInfo",
    "get_attack_info",
    "get_attacks_by_category",
    "get_all_categories",
    "get_all_attacks_as_dicts",
    "ALL_ATTACKS",
    # Detector & Scorer Catalog
    "DetectorInfo",
    "ScorerInfo",
    "DetectorType",
    "ScorerType",
    "get_detector",
    "get_scorer",
    "get_detectors_for_category",
    "get_scorers_for_category",
    "get_all_detectors_as_dicts",
    "get_all_scorers_as_dicts",
    "get_llm_judge_prompt",
    "ALL_DETECTORS",
    "ALL_SCORERS",
]

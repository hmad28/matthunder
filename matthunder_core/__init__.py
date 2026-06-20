"""Shared service layer for CLI, Web, and Telegram surfaces."""

from .registry import SCAN_DEFINITIONS, ScannerDefinition, list_scanners
from .scope import ScopeError, normalize_target, validate_target
from .service import ProgressEvent, ScanRequest, ScanResult, run_scan

__all__ = [
    "ProgressEvent",
    "SCAN_DEFINITIONS",
    "ScanRequest",
    "ScanResult",
    "ScannerDefinition",
    "ScopeError",
    "list_scanners",
    "normalize_target",
    "run_scan",
    "validate_target",
]

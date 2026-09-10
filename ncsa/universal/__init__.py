"""Vendor-agnostic detection: what we can say about a device nobody described."""
from .detectors import (DETECTORS, UNIVERSAL_CONFIDENCE, UniversalFinding,
                        scan, summarise)

__all__ = ["scan", "summarise", "DETECTORS", "UniversalFinding",
           "UNIVERSAL_CONFIDENCE"]

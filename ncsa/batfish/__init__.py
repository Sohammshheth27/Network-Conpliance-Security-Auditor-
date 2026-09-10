"""Batfish as an optional second opinion. Never a dependency."""
from .adapter import (SUPPORTED, BatfishReport, BatfishStatus, CrossCheck,
                      analyse, cross_check, start, status, supports)

__all__ = ["status", "start", "supports", "analyse", "cross_check",
           "BatfishStatus", "BatfishReport", "CrossCheck", "SUPPORTED"]

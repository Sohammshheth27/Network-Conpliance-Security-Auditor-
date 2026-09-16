"""Extended checks -- VPN, wireless, known vulnerabilities.

Reported beside the 88-control compliance score, never inside it; see
`model.py` for why.
"""
from .model import DomainResult, ExtendedFinding, roll_up

__all__ = ["DomainResult", "ExtendedFinding", "roll_up"]

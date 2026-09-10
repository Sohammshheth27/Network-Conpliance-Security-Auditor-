"""AI layer -- guardrails, tiered interpretation, approval registry."""
from .guardrails import InjectionReport, Proposal, prescan, validate
from .interpret import OllamaInterpreter
from .registry import ApprovedMapping, MappingRegistry, semantic_sanity
from .regression import GoldenCase, RegressionGuard, RegressionResult
from .router import TierRouter
__all__ = ["Proposal","prescan","validate","InjectionReport","OllamaInterpreter",
           "MappingRegistry","ApprovedMapping","semantic_sanity","TierRouter",
           "RegressionGuard","GoldenCase","RegressionResult"]

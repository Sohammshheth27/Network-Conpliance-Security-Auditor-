"""The Dynamic Adaptation loop: collect what we could not interpret, and learn it.

    unmapped records -> classify -> queue (by setting NAME) -> suggest by
    analogy -> human approves -> pack mapping -> device reassessed

No code is written to add a vendor; the output is data.
"""
from .classify import CAT_SECURITY, base_name, classify
from .queue import (TrainingCandidate, build_queue, load_queue, save_queue)

__all__ = ["classify", "base_name", "CAT_SECURITY", "TrainingCandidate",
           "build_queue", "save_queue", "load_queue"]

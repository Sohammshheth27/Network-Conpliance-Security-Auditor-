"""Cross-checking independent methods -- n-version programming for compliance.

NCSA can answer the same question three ways, and the ways fail differently:

    pack mapping        vendor-specific, precise, blind outside its mappings
    universal detector  vendor-agnostic, broad, prone to lexical false positives
    NLP analogy         proposals only; never a finding

Running them independently and comparing is worth more than any single one
being improved, because their errors are uncorrelated. A pack mapping is wrong
when the author misread a grammar; a universal detector is wrong when a word
means something else in context. Both being wrong the same way about the same
line is rare.

Three outcomes, and none of them is "silently pick a winner":

  CONFIRMED       both methods say the same thing. Confidence 1.0, and this is
                  the finding you put at the top of a report.

  DISPUTED        they disagree. NOT auto-resolved, because in this project's
                  own data the dispute went both ways within one run -- once
                  the detector's field hint was wrong, and once the PACK had a
                  coverage gap and the detector was right. Suppressing either
                  side by rule would have hidden a real weakness.

  UNCORROBORATED  only one method saw it. Still reported; the second method
                  simply has no vocabulary for that setting. When it is the
                  universal layer that saw it and the pack that did not, that
                  is a pack coverage gap with a line number attached -- which
                  is the most actionable thing this module produces.

The dispute rate is a quality metric in its own right. Rising disputes mean one
of the layers has drifted, and it is visible before any customer sees a report.
"""
from .parsers import ParserAgreement, crosscheck_braces
from .reconcile import (Consensus, ConsensusReport, CONFIRMED, DISPUTED,
                        UNCORROBORATED, reconcile)

__all__ = ["reconcile", "Consensus", "ConsensusReport",
           "CONFIRMED", "DISPUTED", "UNCORROBORATED",
           "crosscheck_braces", "ParserAgreement"]

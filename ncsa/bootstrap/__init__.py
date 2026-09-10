"""Bootstrap a vendor we have never seen.

The problem statement's hardest sentence: "traditional parsers fail because
they cannot predict or interpret the configuration structures of newly acquired
or proprietary hardware." A signature table cannot answer that -- by definition
the signature is missing.

So this package does not ask "which vendor is this?". It asks three questions
that can be answered about a file nobody has ever described:

    detect   what SHAPE is this file?      (indented / braces / block / xml /
                                            json / key=value)
    harvest  which lines carry settings?   (as opposed to comments, banners,
                                            certificates and prose)
    propose  what does each line MEAN?     (by analogy to the vendors we do
                                            know, via the cross-vendor corpus)

The output is a DRAFT pack: `packs/<vendor>.draft.yaml`, every mapping marked
PROPOSED with its confidence and the known-vendor line it was reasoned from.
A human approves it into a real pack. No code is written to add a vendor --
which is the requirement.
"""
from .detect import Grammar, detect_grammar
from .harvest import Candidate, harvest
from .propose import propose_pack, write_draft

__all__ = ["Grammar", "detect_grammar", "Candidate", "harvest",
           "propose_pack", "write_draft"]

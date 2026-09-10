"""MITRE ATLAS + NIST AI RMF -- the governance knowledge base for OUR AI.

Plan 10.4. These frameworks apply to the AI *we* run, not to the devices we
audit, and they serve three concrete purposes:

  1. Label each of our guardrails with the ATLAS technique it defends against
     -> the 10.4 coverage matrix (our guardrails x these frameworks).
  2. Feed known injection signatures into the 10.1 defence-6 pre-scan, which
     is a real runtime control.
  3. Structure the guardrail narrative around the AI RMF's four functions
     (GOVERN / MAP / MEASURE / MANAGE).

WHY THIS IS A SEPARATE INDEX -- read before wiring it anywhere
--------------------------------------------------------------
This content must NEVER enter the parser RAG corpus (knowledge/examples.jsonl).

Plan 13.1 keeps Parser RAG ("how is this vendor's config structured?") separate
from Security RAG ("what does this property mean?"). ATLAS belongs to neither.
It is a catalogue of *attack descriptions*. Retrieval works by similarity, so
putting attack text into the corpus that classifies config lines means a line
mentioning "inject" or "prompt" could retrieve an attack description as a
"similar example" -- corpus poisoning by our own hand, and precisely the
failure mode plan 10.2 exists to prevent.

Retrieval also does not prevent injection. Prompt injection is stopped by the
structural defences in 10.1 -- single-line scope, data/instruction separation,
the field enum as a decoder constraint, evidence anchoring, type validation --
all of which hold whether or not the model has ever read about ATLAS. What this
module adds is *detection signatures* and *provable coverage*, which is the part
retrieval genuinely can contribute.
"""
import json
import re
from pathlib import Path

from pydantic import BaseModel, Field


class AtlasTechnique(BaseModel):
    model_config = {"frozen": True}

    id: str                       # AML.T0051.001
    name: str
    description: str = ""
    tactics: list[str] = Field(default_factory=list)
    is_subtechnique: bool = False


class AtlasMitigation(BaseModel):
    model_config = {"frozen": True}

    id: str                       # AML.M00xx
    name: str
    description: str = ""


class AiSecurityKB(BaseModel):
    """Separate from every other index. See the module docstring."""

    techniques: dict[str, AtlasTechnique] = Field(default_factory=dict)
    mitigations: dict[str, AtlasMitigation] = Field(default_factory=dict)
    tactics: dict[str, str] = Field(default_factory=dict)
    ai_rmf_functions: dict[str, str] = Field(default_factory=dict)

    def injection_techniques(self) -> list[AtlasTechnique]:
        """Everything under AML.T0051 (LLM Prompt Injection) plus tool poisoning."""
        return [
            t for t in self.techniques.values()
            if t.id.startswith("AML.T0051") or "prompt injection" in t.name.lower()
        ]

    def poisoning_techniques(self) -> list[AtlasTechnique]:
        """Relevant to plan 10.2 -- a bad approval poisoning the registry."""
        return [
            t for t in self.techniques.values()
            if "poison" in (t.name + t.description).lower()
        ]


def _external_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []) or []:
        if str(ref.get("source_name", "")).startswith("mitre-atlas"):
            return ref.get("external_id")
    return None


def load_atlas(stix_path: str | Path) -> AiSecurityKB:
    p = Path(stix_path)
    with p.open(encoding="utf-8") as fh:
        doc = json.load(fh)
    objs = doc.get("objects", doc if isinstance(doc, list) else [])

    kb = AiSecurityKB()
    tactic_by_shortname: dict[str, str] = {}

    for o in objs:
        if o.get("type") == "x-mitre-tactic":
            tid = _external_id(o) or o.get("id", "")
            kb.tactics[tid] = o.get("name", "")
            if o.get("x_mitre_shortname"):
                tactic_by_shortname[o["x_mitre_shortname"]] = o.get("name", "")

    for o in objs:
        t = o.get("type")
        if t == "attack-pattern":
            tid = _external_id(o)
            if not tid:
                continue
            phases = [
                tactic_by_shortname.get(ph.get("phase_name", ""), ph.get("phase_name", ""))
                for ph in o.get("kill_chain_phases", []) or []
            ]
            kb.techniques[tid] = AtlasTechnique(
                id=tid,
                name=o.get("name", ""),
                description=(o.get("description") or "")[:2000],
                tactics=phases,
                is_subtechnique=bool(o.get("x_mitre_is_subtechnique")),
            )
        elif t == "course-of-action":
            mid = _external_id(o)
            if not mid:
                continue
            kb.mitigations[mid] = AtlasMitigation(
                id=mid,
                name=o.get("name", ""),
                description=(o.get("description") or "")[:2000],
            )

    kb.ai_rmf_functions = {
        "GOVERN": "Roles, separation of duties, approval policy (plan 10.2 #6, #7)",
        "MAP": "Threat model: injection in config data, registry poisoning (10.1, 10.2)",
        "MEASURE": "False-PASS rate, approval accuracy, retrieval hit rate (10.5, 19)",
        "MANAGE": "Regression guard, rollback, version pinning (10.2 #1, #5)",
    }
    return kb


# ---------------------------------------------------------------------------
# Injection pre-scan signatures -- plan 10.1 defence 6.
#
# A configuration file is attacker-influenced data. An interface description
# can carry an instruction aimed at our model. We scan for that, flag the file,
# AND report it to the customer as a finding -- an injection attempt in a
# production config is itself worth knowing about.
#
# Each signature is labelled with the ATLAS technique it corresponds to, which
# is what makes the 10.4 coverage matrix provable rather than asserted.
# ---------------------------------------------------------------------------

INJECTION_SIGNATURES: list[tuple[str, str, str]] = [
    # (regex, ATLAS technique, human label)
    (r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions", "AML.T0051.000", "direct instruction override"),
    (r"disregard\s+(?:the\s+)?(?:previous|prior|above|system)", "AML.T0051.000", "direct instruction override"),
    (r"you\s+are\s+now\s+(?:a|an|the)\b", "AML.T0051.000", "role reassignment"),
    (r"^\s*system\s*:", "AML.T0051.000", "forged system turn"),
    (r"\bassistant\s*:\s*", "AML.T0051.000", "forged assistant turn"),
    (r"report\s+all\s+(?:controls?|checks?|findings?)\s+as\s+(?:compliant|pass)", "AML.T0051.001", "verdict manipulation"),
    (r"mark\s+(?:this|the)\s+(?:device|config\w*)\s+as\s+compliant", "AML.T0051.001", "verdict manipulation"),
    (r"<\s*/?\s*(?:system|instruction|prompt)\s*>", "AML.T0051.001", "delimiter injection"),
    (r"\{\{\s*.*?\s*\}\}", "AML.T0051.001", "template injection"),
    (r"new\s+instructions?\s*:", "AML.T0051.002", "triggered injection"),
    (r"do\s+not\s+(?:report|flag|mention)\b", "AML.T0051.001", "suppression attempt"),
]

_COMPILED = [(re.compile(p, re.I | re.M), tech, label) for p, tech, label in INJECTION_SIGNATURES]


class InjectionHit(BaseModel):
    model_config = {"frozen": True}

    line: int
    raw: str
    atlas_technique: str
    label: str


def scan_for_injection(text: str) -> list[InjectionHit]:
    """Plan 10.1 defence 6. Deterministic -- no AI involved in detecting attacks on the AI."""
    hits: list[InjectionHit] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for rx, tech, label in _COMPILED:
            if rx.search(line):
                hits.append(
                    InjectionHit(
                        line=lineno, raw=line.strip()[:300],
                        atlas_technique=tech, label=label,
                    )
                )
                break
    return hits


# Guardrail -> framework coverage. Plan 10.4 asks for exactly this matrix.
GUARDRAIL_COVERAGE: list[dict] = [
    {"guardrail": "Single-line scope (10.1 #1)", "atlas": ["AML.T0051.001"],
     "owasp_llm": "LLM01 Prompt Injection", "ai_rmf": "MAP"},
    {"guardrail": "Data slot, not instruction slot (10.1 #2)", "atlas": ["AML.T0051.000"],
     "owasp_llm": "LLM01 Prompt Injection", "ai_rmf": "MAP"},
    {"guardrail": "Field whitelist as decoder enum (10.1 #3)", "atlas": ["AML.T0051"],
     "owasp_llm": "LLM05 Improper Output Handling", "ai_rmf": "MANAGE"},
    {"guardrail": "Evidence anchoring (10.1 #4)", "atlas": ["AML.T0051"],
     "owasp_llm": "LLM09 Misinformation", "ai_rmf": "MEASURE"},
    {"guardrail": "Type validation (10.1 #5)", "atlas": ["AML.T0051"],
     "owasp_llm": "LLM05 Improper Output Handling", "ai_rmf": "MANAGE"},
    {"guardrail": "Injection pre-scan (10.1 #6)", "atlas": ["AML.T0051.000", "AML.T0051.001", "AML.T0051.002"],
     "owasp_llm": "LLM01 Prompt Injection", "ai_rmf": "MAP"},
    {"guardrail": "Regression guard (10.2 #1)", "atlas": ["AML.T0020", "AML.T0059"],
     "owasp_llm": "LLM04 Data and Model Poisoning", "ai_rmf": "MANAGE"},
    {"guardrail": "Direction-of-change alert (10.2 #2)", "atlas": ["AML.T0020"],
     "owasp_llm": "LLM04 Data and Model Poisoning", "ai_rmf": "MEASURE"},
    {"guardrail": "Version pinning (10.2 #5)", "atlas": ["AML.T0020"],
     "owasp_llm": "LLM04 Data and Model Poisoning", "ai_rmf": "GOVERN"},
    {"guardrail": "Separation of duties (10.2 #6)", "atlas": [],
     "owasp_llm": "LLM06 Excessive Agency", "ai_rmf": "GOVERN"},
    {"guardrail": "Two-person rule (10.2 #7)", "atlas": [],
     "owasp_llm": "LLM06 Excessive Agency", "ai_rmf": "GOVERN"},
    {"guardrail": "Tamper-evident log (10.2 #8)", "atlas": [],
     "owasp_llm": "LLM04 Data and Model Poisoning", "ai_rmf": "GOVERN"},
    {"guardrail": "Scoped approvals (10.2 #9)", "atlas": ["AML.T0020"],
     "owasp_llm": "LLM04 Data and Model Poisoning", "ai_rmf": "MANAGE"},
    {"guardrail": "Confidence floor (10.2 #10)", "atlas": [],
     "owasp_llm": "LLM09 Misinformation", "ai_rmf": "MEASURE"},
]

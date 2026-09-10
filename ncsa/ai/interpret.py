"""Tier 3 -- the local model. Plan 9.

Fully local, no external API, ever. Prove it on demo day by turning off Wi-Fi.

The three settings in plan 9.3 matter more than the model choice:
  think=False       Qwen3.5 is a hybrid reasoning model; thinking tokens cost
                    ~10x the time and buy nothing on a pattern-copy task.
  format=<schema>   JSON schema with the field ENUM -- guardrail 3.
  temperature=0     Reproducibility is mandatory for an audit tool. The same
                    config must produce the same report twice.

Measured on this hardware (16 GB RAM, no GPU): ~10 tok/s, ~4 s warm per line,
~15 s cold. That is why tier 2 exists.
"""
from __future__ import annotations

import json

from .guardrails import (SYSTEM_PROMPT, Proposal, build_prompt_context,
                         build_user_prompt, response_schema, validate)

MODEL = "qwen3.5:4b"
HOST = "http://127.0.0.1:11434"


class OllamaInterpreter:
    """Ask the local model to classify one unrecognised line."""

    def __init__(self, model: str = MODEL, host: str = HOST, timeout: int = 120):
        self.model = model
        self.host = host
        self.timeout = timeout

    def available(self) -> bool:
        import urllib.request

        try:
            with urllib.request.urlopen(self.host, timeout=3) as r:
                return r.status == 200
        except Exception:
            return False

    def interpret(
        self,
        line: str,
        *,
        lines: list[str] | None = None,
        index: int = 0,
        examples: list[tuple[str, str]] | None = None,
        allowed_fields: list[str] | None = None,
    ) -> Proposal:
        import urllib.error
        import urllib.request

        context = build_prompt_context(lines or [line], index)
        payload = {
            "model": self.model,
            "think": False,                       # plan 9.3 #1
            "stream": False,
            "format": response_schema(allowed_fields),   # plan 9.3 #2 / guardrail 3
            "options": {"temperature": 0, "num_predict": 120, "num_ctx": 2048},  # #3
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": build_user_prompt(line, context, examples or [])},
            ],
        }
        req = urllib.request.Request(
            f"{self.host}/api/chat",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                body = json.loads(r.read().decode("utf-8"))
        except Exception as exc:
            # A model failure must never become a compliance verdict.
            return Proposal(line=line, tier="llm",
                            rejected_reason=f"model unavailable: {type(exc).__name__}")

        try:
            out = json.loads(body["message"]["content"])
        except (KeyError, json.JSONDecodeError):
            return Proposal(line=line, tier="llm",
                            rejected_reason="model returned unparseable output")

        proposal = Proposal(
            line=line,
            field=out.get("field"),
            value=out.get("value"),
            evidence=out.get("evidence") or "",
            confidence=0.0,       # an unapproved suggestion carries NO confidence
            tier="llm",
        )
        return validate(proposal, line)

"""The regression guard -- plan 10.2 defence #1. BUILD THIS FIRST.

This is CI for compliance knowledge.

A golden set of configs with known-correct results. Every proposed registry
change re-runs the whole set BEFORE commit. If an approval would flip a known
FAIL to PASS, the approval is BLOCKED and the approver is shown exactly what
changed.

Why it outranks the other nine defences: poisoning always makes things look
BETTER. A wrong approval does not crash anything and does not look wrong -- it
quietly converts failures into passes, permanently, across every future scan.
Nothing else in the system would notice. This does.

Defence #2 (direction-of-change alert) falls out of the same machinery: any net
rise in PASS rate across the corpus is worth a human look, even when no
individual golden case broke.
"""
from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field

from ..schema.enums import ResultState


class GoldenCase(BaseModel):
    """One config with results we have verified by hand."""

    name: str
    config_path: str
    pack_path: str
    platform: str
    expected: dict[str, str] = Field(
        default_factory=dict, description="control_id -> expected ResultState"
    )


class RegressionResult(BaseModel):
    allowed: bool
    broken: list[str] = Field(default_factory=list)
    pass_rate_before: float = 0.0
    pass_rate_after: float = 0.0
    direction_alert: bool = False
    detail: list[str] = Field(default_factory=list)

    def explain(self) -> str:
        if self.allowed and not self.direction_alert:
            return "Regression guard: no golden result changed. Approval permitted."
        lines = []
        if self.broken:
            lines.append(f"BLOCKED -- {len(self.broken)} golden result(s) would change:")
            lines += [f"  {d}" for d in self.detail]
        if self.direction_alert:
            lines.append(
                f"DIRECTION ALERT -- corpus pass rate rises "
                f"{self.pass_rate_before:.1f}% -> {self.pass_rate_after:.1f}%. "
                "Poisoning always makes things look better; confirm this is real."
            )
        return "\n".join(lines)


class RegressionGuard:
    def __init__(self, cases: list[GoldenCase], runner):
        """``runner(case, registry) -> {control_id: ResultState}``."""
        self.cases = cases
        self.runner = runner

    # ------------------------------------------------------------------ core
    def _snapshot(self, registry) -> dict[str, dict[str, ResultState]]:
        return {c.name: self.runner(c, registry) for c in self.cases}

    @staticmethod
    def _pass_rate(snapshot: dict[str, dict[str, ResultState]]) -> float:
        total = passed = 0
        for results in snapshot.values():
            for state in results.values():
                if state in (ResultState.PASS, ResultState.FAIL, ResultState.PARTIAL):
                    total += 1
                    if state is ResultState.PASS:
                        passed += 1
        return 100.0 * passed / total if total else 0.0

    def check(self, registry, proposal, *, approver: str = "", **approve_kw) -> RegressionResult:
        """Run the corpus before and after a hypothetical approval.

        The approval is applied to a COPY of the registry -- a blocked approval
        must leave no trace, or the guard itself becomes a way to poison.
        """
        import copy

        before = self._snapshot(registry)

        trial = copy.deepcopy(registry)
        trial.path = None                      # never write during a trial
        ok, _ = trial.approve(proposal, approved_by=approver or "regression-trial",
                              force=True, **approve_kw)
        if not ok:
            return RegressionResult(allowed=False, detail=["proposal could not be applied"])

        after = self._snapshot(trial)

        broken, detail = [], []
        for case in self.cases:
            b, a = before.get(case.name, {}), after.get(case.name, {})
            for cid, expected in case.expected.items():
                exp = ResultState(expected)
                got_before = b.get(cid)
                got_after = a.get(cid)
                if got_after != exp and got_before == exp:
                    broken.append(f"{case.name}:{cid}")
                    detail.append(
                        f"{case.name} / {cid}: {exp.value} -> {got_after.value if got_after else 'MISSING'}"
                        + ("   <-- FAIL flipped to PASS" if exp is ResultState.FAIL
                           and got_after is ResultState.PASS else "")
                    )

        pr_before, pr_after = self._pass_rate(before), self._pass_rate(after)
        return RegressionResult(
            allowed=not broken,
            broken=broken,
            pass_rate_before=pr_before,
            pass_rate_after=pr_after,
            # Defence #2: any net rise deserves a look, even with nothing broken.
            direction_alert=pr_after > pr_before + 0.01,
            detail=detail,
        )

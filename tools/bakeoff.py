"""Model bake-off -- plan 9.2: "decide by measurement, not reputation".

Compares local models on OUR task, not on a public benchmark: read one config
line from a vendor the system has never parsed, and name the SBM field it sets.

METHOD (this is the part that makes the numbers mean something)
---------------------------------------------------------------
* Tier 2 is BYPASSED. The router normally answers ~89% of these without the
  model at all, so routing normally would measure the router, not the model.
  Every line here is forced to tier 3.
* Both models get an IDENTICAL prompt, identical retrieved examples, identical
  field enum, and temperature 0. The only variable is the model.
* The gold set includes lines with NO correct field. Getting those right means
  ABSTAINING. A model that never abstains scores well on accuracy and is
  dangerous, so abstention is scored separately -- plan 10.5's false-PASS rate
  is exactly this failure.
* Each model is warmed with one throwaway call before timing, so we measure
  steady-state latency rather than model load.
"""
from __future__ import annotations

import json
import statistics
import sys
import time
from dataclasses import dataclass

sys.path.insert(0, r"E:\NCSA")

from ncsa.ai.interpret import OllamaInterpreter
from ncsa.frameworks import load_all
from ncsa.nlp import NlpMatcher, corpus_from_packs, corpus_from_stig


@dataclass
class Case:
    line: str
    expect: str | None          # None means "must abstain"
    vendor: str


GOLD: list[Case] = [
    # --- FortiOS / SonicWall style, never parsed by our packs ---------------
    Case("set admintimeout 10", "management.vty.exec_timeout", "fortios"),
    Case("set admin-ssh-v1 disable", "management.ssh.version", "fortios"),
    Case("set strong-crypto enable", "crypto.weak_ciphers", "fortios"),
    Case("set admin-lockout-threshold 3", "authentication.lockout.enabled", "fortios"),
    Case("set snmp-index 4", None, "fortios"),
    # --- Junos style --------------------------------------------------------
    Case("set system services ssh protocol-version v2", "management.ssh.version", "junos"),
    Case("set system syslog host 10.0.0.5 any notice", "logging.servers", "junos"),
    Case("set system ntp server 10.0.0.9", "time.servers", "junos"),
    Case("set system login message \"authorized use only\"", "banner.login", "junos"),
    Case("set system login password minimum-length 15",
         "authentication.min_password_length", "junos"),
    Case("set system services telnet", "management.telnet.enabled", "junos"),
    Case("set chassis aggregated-devices ethernet device-count 4", None, "junos"),
    # --- Arista / HP style --------------------------------------------------
    Case("ip ssh server algorithm mac hmac-sha2-256", "management.ssh.macs", "eos"),
    Case("management api http-commands", "management.http.enabled", "eos"),
    Case("aaa authentication login default group tacacs+",
         "authentication.aaa_enabled", "eos"),
    Case("banner login Unauthorized access prohibited", "banner.login", "eos"),
    Case("spanning-tree mode mstp", None, "eos"),
    # --- lines with no correct SBM field: MUST abstain ----------------------
    Case("config wireless-controller hotspot20 anqp-venue-name", None, "fortios"),
    Case("description link to building 4 riser", None, "generic"),
    Case("set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24", None, "junos"),
]


def run_model(model: str, matcher: NlpMatcher) -> dict:
    interp = OllamaInterpreter(model=model)
    if not interp.available():
        return {"model": model, "error": "ollama not reachable"}

    # warm-up: excluded from timings so we measure steady state, not model load
    interp.interpret("ip ssh version 2", lines=["ip ssh version 2"], index=0,
                     examples=[("ip ssh version 1", "management.ssh.version")],
                     allowed_fields=["management.ssh.version"])

    rows, times = [], []
    correct = wrong = abstain_right = abstain_wrong = invalid = 0

    for c in GOLD:
        cands = matcher.match(c.line, k=5)
        examples = [(m.example.line, m.field) for m in cands]
        allowed = sorted({m.field for m in cands}) or None

        t0 = time.time()
        p = interp.interpret(c.line, lines=[c.line], index=0,
                             examples=examples, allowed_fields=allowed)
        dt = time.time() - t0
        times.append(dt)

        got = p.field if p.is_usable else None
        schema_ok = p.rejected_reason not in ("model returned unparseable output",)
        if not schema_ok:
            invalid += 1

        if c.expect is None:
            if got is None:
                abstain_right += 1
                verdict = "abstained (correct)"
            else:
                abstain_wrong += 1
                verdict = f"FALSE ANSWER -> {got}"
        else:
            if got == c.expect:
                correct += 1
                verdict = "correct"
            elif got is None:
                wrong += 1
                verdict = "abstained (missed)"
            else:
                wrong += 1
                verdict = f"WRONG -> {got}"
        rows.append((c.line, c.expect, got, verdict, dt))

    answerable = [c for c in GOLD if c.expect is not None]
    unanswerable = [c for c in GOLD if c.expect is None]
    return {
        "model": model,
        "rows": rows,
        "accuracy": 100.0 * correct / len(answerable),
        "abstain_rate": 100.0 * abstain_right / len(unanswerable),
        "false_answer": abstain_wrong,
        "schema_invalid": invalid,
        "median_s": statistics.median(times),
        "total_s": sum(times),
    }


def main() -> None:
    reg = load_all()
    corpus = corpus_from_packs(r"E:\NCSA\packs", r"E:\NCSA\samples") + corpus_from_stig(reg)
    matcher = NlpMatcher(corpus).fit()

    models = sys.argv[1:] or ["qwen3.5:4b", "qwen3.5:9b"]
    results = []
    for m in models:
        print(f"running {m} over {len(GOLD)} lines ...", flush=True)
        r = run_model(m, matcher)
        if "error" in r:
            print(f"  {r['error']}")
            continue
        results.append(r)
        print(f"  done in {r['total_s']:.0f}s")

    print()
    print(f"{'MODEL':<16}{'ACCURACY':>10}{'ABSTAIN':>10}{'FALSE ANS':>11}"
          f"{'MED s/line':>12}{'TOTAL s':>10}")
    print("-" * 69)
    for r in results:
        print(f"{r['model']:<16}{r['accuracy']:>9.0f}%{r['abstain_rate']:>9.0f}%"
              f"{r['false_answer']:>11}{r['median_s']:>12.1f}{r['total_s']:>10.0f}")
    print("-" * 69)
    print("ACCURACY  = correct field, on lines that HAVE a correct field")
    print("ABSTAIN   = correctly declined, on lines with NO correct field")
    print("FALSE ANS = confidently answered a line it should have declined")
    print("            (this is the plan 10.5 false-PASS path -- lower is better)")

    with open(r"E:\NCSA\tools\bakeoff_results.json", "w", encoding="utf-8") as fh:
        json.dump([{k: v for k, v in r.items() if k != "rows"} for r in results],
                  fh, indent=1)

    for r in results:
        print()
        print(f"=== {r['model']} detail ===")
        for line, exp, got, verdict, dt in r["rows"]:
            flag = " " if verdict in ("correct", "abstained (correct)") else "!"
            print(f" {flag} {line[:44]:<46}{(exp or '(abstain)'):<34}{verdict[:26]:<28}{dt:>5.1f}s")


if __name__ == "__main__":
    main()

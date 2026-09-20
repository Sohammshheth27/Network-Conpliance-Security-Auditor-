# Remediation: hardened configuration an administrator can apply

**Date:** 2026-09-20
**Status:** approved, implementing
**Deliverable:** PS155 #4 — *"Remediation Paths: device-specific, step-by-step CLI
command sequences to resolve non-compliance and harden the device."*

## What already exists

Remediation is not missing. `ncsa/engine/remediate.py` builds an ordered,
lockout-checked plan; the rule YAML carries per-platform `remediation:` blocks
with `commands`, `phase` and `verify`; `GET /assessment/{aid}/remediation`
serves it; report §8 renders a consolidated script.

What is missing is **coverage and an artefact**. Measured on the reference
NSA 3700:

| Device | Reportable failures | Steps emitted | No fix available |
|---|---|---|---|
| SonicWall NSA 3700 | 30 | 12 | **16** |
| Cisco IOS-XE | 46 | 13 | **31** |

So 40% of the SonicWall findings have a fix, and the engine never says which
ones it could not fix.

## Decision

**Deterministic, evidence-anchored rewriting.** Every finding already carries
the record that proves it:

    NCSA-PLT-002  record_id='setting[181]'    raw='encUsernamePassword=off'
    NCSA-TIME-001 record_id='setting[21204]'  raw='adminLoginTimeout=120'

A fix therefore rewrites *the record the evidence cites*. No pack inversion, no
synthesis: the emitter can only change settings the engine actually observed
and can point at. Values that must be supplied (a syslog collector, a
management subnet) are resolved from the device's own parsed facts — the object
graph, topology, address objects — so each substituted value also carries
evidence.

### Rejected: a learned model that writes configuration

Considered and declined, with reasons, because the option will recur:

1. **No training set.** One real device and one hardened variant. A model fitted
   on that learns one appliance's noise.
2. **The target is exact, not statistical.** `minPasswordLength=1` must become
   `15`. A prediction replaces an exact answer with a confident one, and a
   firewall configuration that is 95% right is not 95% safe.
3. **It breaks the project's invariant.** Every finding cites evidence; a
   generated line would cite a probability. The vendor packs already warn that
   "a mapping that cannot fire is worse than an absent one" — an invented
   configuration value is the same error with a larger blast radius.
4. **Ranking is already deterministic.** `plan.steps.sort(key=(phase,
   -risk_score))` orders by real risk and safety phase. A model would predict
   an ordering the engine computes exactly.
5. **Measurement beats prediction.** Compliance gain does not need regressing:
   patch the configuration, re-assess the patch, report the delta. Measured on
   assessments already on disk — same hardware, same hostname:

   | | Real export | Hardened | Δ |
   |---|---|---|---|
   | Score | 40.0% | 59.2% | +19.2 |
   | FAIL | 28 | 18 | −10 |
   | PASS | 20 | 29 | +9 |
   | **UNKNOWN** | **17** | **16** | **−1** |

Deterministic work is also the **prerequisite** for any future learned layer:
each emitted file, sandbox import and apply-or-rollback outcome is a labelled
example. The dataset does not exist until this is built.

## Safety invariants

These are not preferences. Each is a way the emitter could confidently damage a
production firewall.

1. **FAIL only.** Never `PASS` (minimal diff — a passing setting is never
   touched) and never `UNKNOWN`.
2. **UNKNOWN is excluded by definition.** `UNKNOWN` means the setting was never
   read. Changing a value we never observed cannot be predicted or rolled back.
   The measured evidence supports this: hardening moved FAIL by 10 and PASS by
   9 while UNKNOWN moved by 1 — UNKNOWNs are our blind spots, not device faults.
3. **No fix without evidence.** A control whose mapping matched nothing must not
   be remediated. On the reference device `NCSA-CAT-006` (`policyNgName*`),
   `NCSA-EXT-039` (`uuidIpsObjEnable`) and `NCSA-EXT-040` (`uuidGavObjEnable`)
   all report `FAIL` from `observed=None` against mappings matching **zero** of
   92,635 records — and EXT-039/040 are already in the remediation set. The
   engine would emit commands toggling IPS and gateway anti-virus on a device
   whose state it has never read.
4. **The lockout guard must not fail open.** Proven: same device, same plan —
   `sbm=None` yields 4 transport-affecting steps with **0** warnings;
   `sbm=REAL` yields the same steps with **3**. `_sbm_for` currently returns
   `None` on three silent paths.
5. **Nothing is "ready to import" until it is.** The `.exp` carries
   `checksumVersion=1` with no checksum key, so importability is unverified.
   Until a sandbox import succeeds, the CLI script is the guaranteed artefact
   and the file is labelled unverified.

## Architecture

    rule YAML  ──  remediation: {platform: {commands, config, phase, verify}}
                           │
                           ▼
                   build_plan()  ── existing: ordering, lockout, rollback
                           │
                   ┌───────┴───────┐
                   ▼               ▼
            CLI emitter      file emitter
          (Plan.script)   (rewrite cited records)
                   │               │
                   └───────┬───────┘
                           ▼
                  re-assess emitted file
                   → measured before/after

One fix model, two thin emitters. The `config:` block is new: a declarative
`{key: value}` per platform, alongside the existing `commands:`, so adding a
vendor stays a YAML edit (requirement 5).

## Phases

**Phase 0 — safety, before any emitter.**
- Fix `_sbm_for`: remove the dead `if False` branch, stop matching by object
  identity, and fail loudly rather than returning `None`.
- Expose `plan.unavailable` through the API and UI as "NOT REMEDIATED".
- Decide the evidence-free FAILs (below).

**Phase 1 — SonicOS coverage.** Author the missing fix blocks. Of the 16
uncovered: 9 map to real scalar keys verified present in the export
(`cli_idleTimeout`, `wseIsHttpsEnabled`, `adminLoginOtpRequire`,
`loginFailLockoutLog`, `Snmp3_Mand_Required`, `cli_connectionBanner`,
`loginAttemptCLI`, and two per-interface globs); 2 are the
`sshCipherControlConfig` JSON crypto policy; 3 are firewall-policy edits;
2 are excluded by invariant 3.

**Phase 2 — emitters.** File and CLI from the same plan, with the context
resolver filling `<SYSLOG-IP>`-style placeholders from parsed facts.

**Phase 3 — closed loop.** Re-assess the emitted file; report measured
before/after.

**Phase 4 — sandbox.** Import verification before any live guidance.

## Open decision

Invariant 3 changes a pinned number. Suppressing the three evidence-free FAILs
moves decided controls 50 → 47, computing to **score 40.0% → 42.6%** and
**coverage 74.6% → 70.1%**. That is arithmetic from the current state and must
be confirmed by a run. The 40.0%/74.6% figure was set deliberately on
2026-09-20 and is not to be changed casually — this is the deliberate intent.

# Meridian — Network Compliance & Security Auditor

Multi-vendor firewall and network configuration auditing. A configuration file
goes in; a compliance assessment comes out, with the exact line of the exact
file behind every claim.

**661 tests passing.** Validated against real device exports — a 92,635-setting
SonicWall NSA 3700 backup and a genuine PAN-OS running-config — not only against
fixtures written alongside the code.

---

## The design commitment

**Absence is never reported as a positive result.**

That single rule shapes everything else. A control we could not evaluate says
so; it never becomes a PASS, and it never becomes a silent zero.

Most tools report two states. NCSA reports seven:

| State | Meaning |
|---|---|
| `PASS` | Checked, and the device is configured correctly. |
| `FAIL` | Checked, and it is not. |
| `PARTIAL` | Some scoped instances comply, others do not. |
| `NOT_APPLICABLE` | The control does not apply here — **and the reason is recorded**. |
| `UNKNOWN` | We could **not** check this. Not a pass, and not a failure. |
| `MANUAL_REVIEW` | Needs a human; no automated verdict would be honest. |
| `ERROR` | The check itself failed. Our fault, not the device's. |

### Honest coverage

`score_pct` is computed over **decided controls only**, and is never published
without `assessed_pct` beside it. A device where we could read 40% of the
settings and all of them passed scores *100% on 40% coverage* — never "100%".

### Why NOT_APPLICABLE is the strictest invariant

`UNKNOWN` stays in the denominator and depresses coverage. `NOT_APPLICABLE` is
excluded from scoring entirely — so a wrong one silently **raises** the score by
removing a hard control from the denominator. Inflating N/A is the easiest way
to make a tool like this lie.

Every N/A must therefore answer one of three questions with evidence:

1. **The platform cannot do this** — declared per field or per domain, with a
   written reason.
2. **The feature is not in use** — gated on an observed setting, which is cited
   as the evidence.
3. Neither — then it is `UNKNOWN`, and it stays in the denominator.

100% of N/A verdicts across every bundled config carry a justification. A test
walks all of them and fails on the first that cannot say why.

---

## What it does

| Capability | Notes |
|---|---|
| Multi-vendor parsing | 11 mapping packs, 10 platforms, 6 grammar families |
| Compliance evaluation | 88 controls, evidence-backed |
| Rule hygiene | Dead, shadowed, redundant, over-broad policy |
| Reachability | "Would this traffic pass?" — names the deciding rule |
| Multi-device topology | Fabric built from several assessed devices |
| Change tracking | Snapshot and diff; device change vs analysis change kept apart |
| Recertification | Rules due for review; deletion needs 3 independent signals |
| Log correlation | Is a rule genuinely unused, or was its counter reset? |
| Parser cross-check | Two independent methods over the same device |
| Host firewall | Windows / iptables through the same appliance analysers |
| Remediation | Fix commands, lockout-checked |
| Blast radius | From a foothold zone, every zone reachable on lateral-movement ports, with the permitting rule; marks paths LATENT when nothing sits in the zone |
| What-if remediation | Re-scores a copy with fixes applied or rules disabled; warns when an IPv6 twin still permits the traffic |
| VPN checks | Per-tunnel PFS, anti-replay, SA lifetimes, management over the tunnel |
| Wireless checks | Open/WEP/TKIP, PMF, guest isolation, cleartext PSK (Catalyst 9800; SonicWall access-point provisioning) |
| Known vulnerabilities | Firmware against a dated NVD snapshot + CISA KEV; version **and** hardware model must match |
| MITRE ATT&CK tags | The adversary technique each control stands in front of, verified against ATT&CK v19.2 |
| Cloud firewalls | AWS security groups, Azure NSGs, GCP VPC firewall rules |
| Learning loop | Unmapped settings queued, ranked by a calibrated confidence |

### Extended checks sit beside the score, never inside it

VPN, wireless and CVE results are reported next to the compliance score and do
not change it. Adding them to the 88-control catalogue would have moved every
device's score and coverage, including results already reported. They follow
the same rules as the controls: a failure cites the setting behind it, and a
value that cannot be decoded (SonicOS's private VPN algorithm codes, for
example) is reported as not decided rather than guessed.

Frameworks: **5,785 controls** across NIST 800-53, DISA STIG, CIS, ISO 27001,
NIST 800-171 r3, PCI DSS 4.0, CMMC and NERC CIP — with provenance chained
STIG → CCI → 800-53 → ISO / 800-171.

---

## Quick start

```bash
python -m venv .venv && .venv/Scripts/activate      # Windows
pip install -r requirements.txt

# engine
python -m uvicorn ncsa.api.app:app --port 8000

# UI (separate terminal)
cd frontend && npm install && npm run dev
```

Open **http://localhost:5173**. The UI proxies `/api` to the engine, so one URL
is enough.

```bash
python -m pytest -q          # 661 tests
```

### Refreshing threat data

The CVE lookup and ATT&CK tags run offline from local files, so every result
is reproducible and states the date of its data.

```bash
python -m tools.fetch_cve        # NVD snapshot + CISA KEV -> reference/cve/
curl -L https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json \
     -o reference/attack/enterprise-attack.json
```

A CVE result older than 30 days says so first.

---

## Adding a vendor

A new vendor is **a YAML file, not a code change**. Packs are data:

```yaml
vendor: acme
platform: acme_os
reader: indented
mappings:
  - field: management.ssh.enabled
    regex: '^ip ssh server$'
    value: {const: true}
not_applicable_fields:
  authentication.enable_secret: "AcmeOS has no enable-secret concept"
```

A pack validated only against a fixture written beside it carries version
`0.9`, and a test refuses to let it reach `1.0` until it has been checked
against real device output. **Real configs find bugs constructed fixtures
cannot** — a downloaded PAN-OS export exposed an XML reader bug within minutes
of first use.

---

## What is deliberately not in this repository

- **CIS Benchmarks and ISO/IEC 27001 text.** Copyrighted. Cited by identifier
  and short title only; the prose never leaves the machine it was licensed on.
  Licence handling is enforced in the type system, not by policy.
- **Vendor documentation** (Check Point, Juniper, Fortinet, F5, A10, Arista).
  Keeping a local copy to write mappings against is fair use; republishing a
  vendor's CLI reference is not. `reference/vendor_docs/SOURCES.md` records
  where each came from, and `tools/fetch_vendor_docs.py` re-downloads them.
- **Real device configurations and assessment history.** The change-tracking
  store keys on hostname, serial number and config hash — publishing it would
  disclose live appliances.
- **NIST OSCAL catalogues** — public domain, but 121 MB that `tools/` re-fetches
  on demand.

Everything above is enforced by `.gitignore` and, for the licensed content, by
`ncsa/rag/guard.py`.

---

## Status

Built for SIH 2026. Packs for Arista, Aruba, FortiOS, Azure and GCP are at
version `0.9` — validated against constructed fixtures only, pending real
exports. The SonicWall, PAN-OS, Cisco IOS-XE, ASA and Juniper paths are
validated against real or captured configurations.

Of the extended checks, VPN, CVE and the no-access-point wireless result are
validated on the real SonicWall NSA 3700. The Catalyst 9800 wireless adapter is
validated on a fixture built from Cisco's published commands, and says so in
every result.

# Real configurations wanted — and how to hand them over safely

Coverage on four platforms is limited by the configs their packs were built
from, not by the engine:

| Platform | Current sample | Why it limits us |
|---|---|---|
| Arista EOS | constructed from Arista's CLI guide | pack agrees with it by construction |
| HPE Aruba AOS-CX | constructed | same |
| Palo Alto PAN-OS | a genuine export, but PAN-OS 5.0 | modern releases rename/move settings |
| FortiOS | synthetic | no version line, so no CVE matching |
| Cisco ASA (version) | real config pasted without its header | `ASA Version` line missing |

One real, sanitised configuration per platform is enough to ground the
mappings properly (every regex/path checked against a line that exists).

## What to export

| Platform | Command |
|---|---|
| Arista EOS | `show running-config` |
| Aruba AOS-CX | `show running-config` |
| PAN-OS | `set cli config-output-format xml` then `show config running` |
| FortiOS | `show full-configuration` (or a GUI backup) — keep the `#config-version=` first line |
| Cisco ASA | `show running-config` — keep the `: Saved` / `ASA Version` header |

## Sanitise it first — always

```
python -m tools.sanitise_config running.cfg running_sanitised.cfg --words my_sites.txt
```

`my_sites.txt` lists site names, hostnames and serial numbers, one per line.
Keep it OUT of the repository. The tool anonymises IPs and secrets but keeps
default SNMP community strings (`public`, `private`, …) visible, because the
audit has to be able to find them.

Then check the output by eye: search it for your site names, serials and
public IP ranges before sharing. Never commit a raw production config.

## Where to put it

`samples/<vendor>/` for sanitised files that may be committed; anything
un-sanitised belongs only in `data/` (git-ignored).

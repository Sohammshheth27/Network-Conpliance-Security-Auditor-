"""The Security Baseline Model -- one common language for every vendor.

Plan 2.3.1 (core fields) and 15.3 (extended fields).

Everything downstream of the SBM is identical for all vendors. If a rule or a
report ever needs to know what vendor it is looking at, something upstream has
leaked -- see plan 2.2's golden rule.

Design note: the SBM is a *flat dotted namespace*, not a deep object tree. A
tree looks tidier but every rule would then need to walk it defensively, and
scoped paths like ``management.vty[0-4].transport_input`` do not fit a fixed
tree anyway. Flat paths keep rule files trivial and make 14.1's accounting a
matter of counting keys.
"""
from pydantic import BaseModel, Field

from .enums import ObservationState, RecordState
from .evidence import EvidenceRef
from .observation import Observation

# ---------------------------------------------------------------------------
# The field whitelist.
#
# This list is load-bearing in three places, which is why it lives here and
# nowhere else:
#   1. Plan 10.1 defence 3 -- it becomes the JSON-schema ``enum`` handed to the
#      local model, so the model *cannot physically emit* an off-list name.
#   2. Plan 12.5 -- the TF-IDF matcher scores an unknown line against these.
#   3. Plan 14.2 -- control coverage is measured against it.
#
# A caveat learned on the bench: the enum guarantees a *valid* field name, not a
# *correct* one. Given a line whose true field is absent from the list, the model
# did not abstain -- it confidently picked the nearest member. The enum is a
# containment boundary, not a correctness check. Abstention is the retrieval
# layer's job (plan 10.2 defence 10, the confidence floor).
# ---------------------------------------------------------------------------

FIELD_TYPES: dict[str, str] = {
    # --- device identity (plan 16.4: serial usually needs `show version`) ---
    "device.vendor": "str",
    "device.platform": "str",
    "device.os": "str",
    "device.version": "str",
    "device.hostname": "str",
    "device.serial": "str",
    # --- management plane: SSH ---
    "management.ssh.enabled": "bool",
    "management.ssh.version": "int",
    "management.ssh.ciphers": "list",
    "management.ssh.kex": "list",
    "management.ssh.macs": "list",
    "management.ssh.timeout": "int",
    "management.ssh.max_auth_tries": "int",
    # --- management plane: cleartext + web ---
    "management.telnet.enabled": "bool",
    "management.http.enabled": "bool",
    "management.http.redirect_https": "bool",
    "management.https.enabled": "bool",
    "management.https.tls_version": "str",
    "management.https.cert_source": "str",
    "management.https.source_restriction": "bool",
    # --- vty lines (scoped: management.vty[0-4].* at runtime) ---
    "management.vty.transport_input": "list",
    "management.vty.access_class": "str",
    "management.vty.exec_timeout": "int",
    # --- authentication / authorization ---
    "authentication.min_password_length": "int",
    "authentication.complexity": "bool",
    "authentication.aaa_enabled": "bool",
    "authentication.local_accounts": "list",
    "authentication.mfa.admin_required": "bool",
    "authentication.lockout.enabled": "bool",
    "authorization.privilege_levels": "list",
    "authorization.role_based": "bool",
    # --- added after grounding against Cisco's official hardening guide -----
    # Each of these is a documented hardening command the pack could not read.
    "authentication.enable_secret": "bool",
    # Are stored credentials hashed rather than reversibly encoded? On IOS this
    # is `service password-encryption` plus `enable secret`; on ASA it is the
    # `encrypted`/`pbkdf2` keyword on the stored value.
    "authentication.password_encryption": "bool",      # `enable secret` vs `enable password`
    "authentication.aaa_authentication": "list", # login method list
    "authorization.aaa_authorization": "list",   # exec/commands authorization
    "logging.command_accounting": "bool",        # aaa accounting commands
    "management.ssh.strict_host_key": "bool",
    "management.ssh.source_interface": "str",
    "management.ssh.pubkey_auth": "bool",
    "crypto.rsa_modulus": "int",                 # key strength
    "logging.persistent": "bool",
    "logging.source_interface": "str",
    "snmp.views": "list",                        # restricted MIB views
    "snmp.community_acl": "bool",                # community bound to an ACL
    "management.aux.exec_disabled": "bool",      # `no exec` on line aux
    # Console idle timeout. Distinct from vty: an unattended console session
    # is a physical-access risk, and on ASA `console timeout 0` means NEVER,
    # which is an explicitly configured weakness rather than an unset value.
    "management.console.exec_timeout": "int",
    "management.vty.transport_output": "list",
    "time.timezone": "str",
    # --- ACL / L2 / routing hardening, all documented by Cisco's guide ------
    "firewall.acls": "list",              # named + numbered ACL definitions
    "firewall.acl_applied": "list",       # ip access-group / ip receive access-list
    "l2.arp_inspection": "bool",
    "l2.dhcp_snooping": "bool",
    "l2.ip_source_guard": "bool",
    "routing.prefix_filtering": "list",   # prefix-list / as-path filters
    "logging.netflow": "bool",
    "management.icmp_ratelimit": "bool",
    "platform.memory_thresholds": "bool",
    "platform.config_archive": "bool",
    # --- logging / time ---
    "logging.enabled": "bool",
    "logging.remote_syslog": "bool",
    "logging.servers": "list",
    "logging.severity": "str",
    "logging.log_denied": "bool",
    "time.ntp_enabled": "bool",
    "time.servers": "list",
    "time.authenticated": "bool",
    # --- snmp ---
    "snmp.version": "str",
    "snmp.communities": "list",
    "snmp.v3_auth": "bool",
    "snmp.v3_priv": "bool",
    # --- banner ---
    "banner.login": "str",
    "banner.motd": "str",
    "banner.enabled": "bool",
    # --- crypto ---
    "crypto.tls.minimum_version": "str",
    "crypto.tls_versions": "list",
    "crypto.weak_ciphers": "list",
    "crypto.ipsec_proposals": "list",
    # --- routing ---
    "routing.bgp_auth": "bool",
    "routing.ospf_auth": "bool",
    # --- services ---
    "services.unused_enabled": "list",
    # --- platform (appliance) ---
    "platform.firmware.version": "str",
    "platform.api.enabled": "bool",
    # The management API's own authentication surface. An enabled REST API is
    # remote administrative access by another name, and it carries a full set
    # of auth choices that nothing was auditing: these were parsed on every
    # SonicWall run and mapped to nothing.
    #
    # Every one of these is conditional on `platform.api.enabled`. A weak
    # setting on a disabled API is not a finding, and the rules below say so
    # via `applies_when` rather than by being silently skipped.
    "platform.api.basic_auth": "bool",
    "platform.api.digest_md5": "bool",
    "platform.api.pubkey_bits": "int",
    "platform.api.cors": "bool",
    "platform.api.session_security": "bool",
    "platform.api.logging": "bool",
    # How stored credentials and configuration parameters are protected.
    "platform.stored_credentials_encrypted": "bool",
    # --- appliance security services (NOT_APPLICABLE on routers/switches) ---
    "security.ips.enabled": "bool",
    "security.gav.enabled": "bool",
    "security.cfs.enabled": "bool",
    "security.dpi_ssl.enabled": "bool",
    # --- interfaces (scoped at runtime: interfaces[Gi0/1].shutdown) ---
    "interfaces.name": "str",
    "interfaces.shutdown": "bool",
    "interfaces.description": "str",
    "interfaces.zone": "str",
    "interfaces.port_security": "bool",
    "interfaces.address": "str",
    # --- firewall / access rules (scoped: firewall.rules[sg-123/in/0].source) ---
    "firewall.default_action": "str",
    "firewall.zones": "list",
    "firewall.rules.id": "str",
    "firewall.rules.action": "str",
    "firewall.rules.source": "list",
    "firewall.rules.destination": "list",
    "firewall.rules.service": "list",
    "firewall.rules.protocol": "str",
    "firewall.rules.ports": "list",
    "firewall.rules.direction": "str",
    "firewall.rules.log": "bool",
    "firewall.rules.position": "int",
    "firewall.rules.description": "str",
    "firewall.nat_rules": "list",
    # how much of the policy we could NOT evaluate -- plan 14.1 applies to
    # semantics, not only to lines
    "firewall.rules_unevaluable": "list",
    # --- cloud security groups (plan 2.3.1) ---
    "cloud.provider": "str",
    "cloud.region": "str",
    "cloud.account_id": "str",
    "cloud.security_groups.id": "str",
    "cloud.security_groups.name": "str",
    "cloud.security_groups.vpc": "str",
    "cloud.security_groups.ingress": "list",
    "cloud.security_groups.egress": "list",
    "cloud.security_groups.is_default": "bool",
    # --- derived exposure facts (plan 15.2) ---
    "exposure.admin_ports_open_to_internet": "list",
    "exposure.any_any_rules": "list",
    "exposure.unrestricted_ingress": "list",
}

FIELD_NAMES: list[str] = sorted(FIELD_TYPES)


class SourceAccounting(BaseModel):
    """Plan 14.1 -- no silent loss.

    Invariant: total == parsed + mapped + quarantined + unknown.
    """

    total: int = 0
    parsed: int = 0
    mapped: int = 0
    quarantined: int = 0
    unknown: int = 0

    def record(self, state: RecordState, n: int = 1) -> None:
        setattr(self, state.value.lower(), getattr(self, state.value.lower()) + n)

    @property
    def balances(self) -> bool:
        return self.total == self.parsed + self.mapped + self.quarantined + self.unknown

    @property
    def coverage_pct(self) -> float:
        if not self.total:
            return 0.0
        return 100.0 * (self.parsed + self.mapped) / self.total


class SecurityBaselineModel(BaseModel):
    """Everything we know about one device, in vendor-neutral form."""

    assessment_id: str
    source_file: str
    source_sha256: str
    observations: dict[str, Observation] = Field(default_factory=dict)
    accounting: SourceAccounting = Field(default_factory=SourceAccounting)
    unrecognised: list[EvidenceRef] = Field(default_factory=list)

    # ------------------------------------------------------------------ access
    def set(self, path: str, obs: Observation) -> None:
        """Record an observation. Unknown paths are rejected, not silently kept.

        Silently accepting an off-list path would let a typo in a vendor pack
        create a field no rule ever reads -- a control that can never fire and
        never warns. Better to fail at load time.
        """
        base = _unscope(path)
        if base not in FIELD_TYPES:
            raise KeyError(
                f"{path!r} is not a known SBM field. Add it to FIELD_TYPES "
                "(it also feeds the LLM field enum and the coverage matrix)."
            )
        self.observations[path] = obs

    def get(self, path: str) -> Observation | None:
        return self.observations.get(path)

    def value(self, path: str, default=None):
        obs = self.observations.get(path)
        return obs.value if obs is not None and obs.is_known else default

    def is_provable(self, path: str) -> bool:
        obs = self.observations.get(path)
        return obs is not None and obs.is_provable

    def scoped_instances(self, unscoped_field: str) -> dict[str, Observation]:
        """All scoped observations that correspond to an unscoped field name.

        ``management.vty.transport_input`` ->
            {"management.vty[line vty 0 4].transport_input": Observation, ...}
        """
        return {
            p: o for p, o in self.observations.items()
            if p != unscoped_field and _unscope(p) == unscoped_field
        }

    def scoped(self, prefix: str) -> dict[str, Observation]:
        """All observations under a scoped prefix, e.g. ``management.vty``."""
        return {
            p: o for p, o in self.observations.items()
            if p == prefix or p.startswith(prefix + "[") or p.startswith(prefix + ".")
        }

    # -------------------------------------------------------------- reporting
    @property
    def unparsed_count(self) -> int:
        return sum(
            1 for o in self.observations.values()
            if o.state is ObservationState.UNPARSED
        )

    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {s.value: 0 for s in ObservationState}
        for o in self.observations.values():
            counts[o.state.value] += 1
        return counts


def _unscope(path: str) -> str:
    """``management.vty[0-4].transport_input`` -> ``management.vty.transport_input``."""
    out, depth = [], 0
    for ch in path:
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
        elif depth == 0:
            out.append(ch)
    return "".join(out)

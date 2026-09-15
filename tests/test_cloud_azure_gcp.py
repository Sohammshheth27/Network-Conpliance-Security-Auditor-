"""Azure NSG and GCP VPC firewall support.

Both validated on FIXTURES (samples/azure, samples/gcp) built in the documented
CLI output shapes -- not on real exports, and the packs say so.

Each test pins a way cloud rules differ from an AWS security group, because
reading one with the other's semantics produces confident, wrong findings:

  * Azure and GCP are ORDERED and have DENY rules. A deny at priority 120 must
    beat an allow at 200.
  * Service tags are not addresses. `Internet` is exposure; `VirtualNetwork`
    is never the internet; `AzureCloud` is neither known-internal nor
    known-public and must stay unknown.
  * GCP's implied egress is ALLOW, so unmatched traffic is undecidable, not
    denied.
"""
import json

import pytest

from ncsa.engine.fingerprint import fingerprint_file, fingerprint_json
from ncsa.graph import azure_builder, gcp_builder
from ncsa.graph.facts import (admin_mgmt_public_exposure, policy_broad_any_any,
                              sensitive_service_exposed)
from ncsa.graph.reach import Query, ask
from ncsa.pipeline import assess
from ncsa.readers.json_reader import loads

AZ = "samples/azure/nsg-list.json"
GCP = "samples/gcp/firewall-rules.json"
INTERNET_HOST = "203.0.113.10"      # TEST-NET-3, documentation range


@pytest.fixture(scope="module")
def az():
    return assess(AZ, redact=False, assessment_id="TEST-AZ")


@pytest.fixture(scope="module")
def gcp():
    return assess(GCP, redact=False, assessment_id="TEST-GCP")


def _flat(hits) -> str:
    return " ".join(str(h) for h in hits)


# ------------------------------------------------------------- recognition

def test_both_exports_are_recognised():
    assert fingerprint_file(AZ).platform == "network_security_groups"
    assert fingerprint_file(GCP).platform == "gcp_firewall"
    assert fingerprint_file("samples/aws/describe-security-groups.json").platform == "security_groups"


def test_an_arbitrary_azure_resource_list_is_not_an_nsg():
    """The old fingerprint accepted anything with `properties` -- half of ARM."""
    fp = fingerprint_json([{"name": "vm1", "properties": {"hardwareProfile": {}}}])
    assert fp.platform != "network_security_groups"


def test_both_are_assessed_with_a_policy_graph(az, gcp):
    for da in (az, gcp):
        assert da.supported
        assert da.graph is not None and da.graph.rules
        assert da.coverage()["controls_decided"] > 0


# ------------------------------------------------------------------- Azure

def test_azure_first_match_lets_a_deny_shadow_a_later_allow(az):
    """DenyRDPInbound (120) beats AllowRDPFromInternet (200)."""
    a = ask(az.graph, Query(source=INTERNET_HOST, destination="any", port=3389,
                            protocol="tcp", destination_zone="web-nsg"))
    assert a.permitted is False
    assert "DenyRDPInbound" in a.decided_by


def test_azure_ssh_from_anywhere_is_permitted(az):
    a = ask(az.graph, Query(source=INTERNET_HOST, destination="any", port=22,
                            protocol="tcp", destination_zone="web-nsg"))
    assert a.permitted is True
    assert "AllowSSHFromAnywhere" in a.decided_by


def test_azure_internet_exposure_is_reported_with_its_json_path(az):
    f = next(x for x in az.assessment.findings if x.control_id == "NCSA-CLD-001")
    assert f.state.value == "FAIL"
    assert f.evidence and "securityRules" in (f.evidence[0].record_id or "")


def test_internal_service_tags_are_never_the_internet(az):
    hits, _ev, _skipped = admin_mgmt_public_exposure(az.graph)
    joined = _flat(hits)
    assert "AllowVnetInBound" not in joined
    assert "AllowAzureLoadBalancerInBound" not in joined


def test_an_opaque_service_tag_stays_unknown_not_internal():
    """AzureCloud includes every Azure tenant's public IPs."""
    nsg = [{"name": "t", "securityRules": [
        {"name": "FromAzureCloud", "priority": 100, "direction": "Inbound",
         "access": "Allow", "protocol": "Tcp", "sourceAddressPrefix": "AzureCloud",
         "destinationAddressPrefix": "*", "destinationPortRange": "22"}]}]
    g = azure_builder.build(loads(json.dumps(nsg), "t.json"))
    hits, _ev, skipped = admin_mgmt_public_exposure(g)
    assert not hits, "an opaque tag must not be asserted as exposure"
    assert skipped, "and must not be silently treated as internal either"


def test_azure_default_deny_is_read_from_the_file(az):
    ev = az.graph.default_action_evidence
    assert ev and "DenyAllInBound" in ev[0].raw
    obs = az.sbm.observations["firewall.default_action"]
    assert obs.state.value == "OBSERVED"


def test_azure_egress_is_not_passed_on_the_strength_of_the_defaults(az):
    """AllowInternetOutBound restricts nothing; it must not satisfy CAT-009."""
    f = next(x for x in az.assessment.findings if x.control_id == "NCSA-CAT-009")
    assert f.state.value != "PASS"


# --------------------------------------------------------------------- GCP

def test_gcp_disabled_rules_do_not_count(gcp):
    legacy = next(r for r in gcp.graph.rules if r.name.startswith("legacy-allow-all"))
    assert legacy.enabled is False
    hits, _ev, _sk = policy_broad_any_any(gcp.graph)
    assert "legacy-allow-all" not in _flat(hits)


def test_gcp_target_tag_exposure_is_reported_not_dropped(gcp):
    """0.0.0.0/0 -> tag:db on 5432 is exposure, whichever instances carry the tag."""
    hits, _ev, _sk = sensitive_service_exposed(gcp.graph)
    joined = _flat(hits)
    assert "5432" in joined or "postgres" in joined.lower()


def test_gcp_deny_wins_at_equal_priority():
    rules = [
        {"name": "allow-ssh", "network": "n/default", "direction": "INGRESS",
         "priority": 1000, "sourceRanges": ["0.0.0.0/0"],
         "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}]},
        {"name": "deny-ssh", "network": "n/default", "direction": "INGRESS",
         "priority": 1000, "sourceRanges": ["0.0.0.0/0"],
         "denied": [{"IPProtocol": "tcp", "ports": ["22"]}]},
    ]
    g = gcp_builder.build(loads(json.dumps(rules), "g.json"))
    # The rules target the NETWORK (no targetTags), which resolves to its
    # identifier -- so the question names it, as AWS questions name a group.
    a = ask(g, Query(source=INTERNET_HOST, destination="default", port=22,
                     protocol="tcp", destination_zone="default"))
    assert a.permitted is False and "deny-ssh" in a.decided_by


def test_gcp_unmatched_traffic_is_undecidable_not_denied(gcp):
    """The implied rules are not in the export, and egress defaults to ALLOW."""
    a = ask(gcp.graph, Query(source=INTERNET_HOST, destination="default", port=8080,
                             protocol="tcp", destination_zone="default"))
    assert a.permitted is None
    # And the same question on a port a rule DOES answer is decided -- so the
    # None above is the missing implied rule, not a query that matched nothing.
    ssh = ask(gcp.graph, Query(source=INTERNET_HOST, destination="default", port=22,
                               protocol="tcp", destination_zone="default"))
    assert ssh.permitted is True


def test_gcp_logging_is_read_per_rule(gcp):
    obs = gcp.sbm.observations
    pg = next(v for k, v in obs.items()
              if k.startswith("firewall.rules[allow-postgres-public") and k.endswith(".log"))
    ssh = next(v for k, v in obs.items()
               if k.startswith("firewall.rules[default-allow-ssh") and k.endswith(".log"))
    assert pg.value is True and ssh.value is False


def test_gcp_ingress_with_no_source_is_not_assumed_open():
    rules = [{"name": "nosrc", "network": "n/default", "direction": "INGRESS",
              "priority": 1000, "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}]}]
    g = gcp_builder.build(loads(json.dumps(rules), "g.json"))
    hits, _ev, skipped = admin_mgmt_public_exposure(g)
    assert not hits and skipped


# ------------------------------------------------------------ shared rules

def test_cloud_platforms_get_honest_extended_answers(az, gcp):
    from ncsa.extended.run import run_extended

    for da in (az, gcp):
        doms = run_extended(da)["domains"]
        for name in ("vpn", "wireless", "cve"):
            assert doms[name]["present"] is False, (
                f"{da.identity.platform} {name}: a cloud rule export has none")


def test_the_fixtures_say_they_are_fixtures():
    assert "_fixture" in open(AZ, encoding="utf-8").read()
    assert "FIXTURE" in open(GCP, encoding="utf-8").read()


def test_the_aws_result_is_unchanged():
    da = assess("samples/aws/describe-security-groups.json", redact=False,
                assessment_id="TEST-AWS-STILL")
    cov = da.coverage()
    assert (cov["score_pct"], cov["assessed_pct"]) == (77.8, 10.2)

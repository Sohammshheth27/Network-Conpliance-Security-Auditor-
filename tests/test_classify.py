"""Triage of parsed-but-unmapped settings.

The queue this feeds is the work-list a human actually works through, so its
precision decides whether anyone finishes it. Two failure directions, and they
are not symmetric:

  * a FALSE NEGATIVE silently drops a real security setting, and nobody will
    ever look at it again. This is the worse error.
  * a FALSE POSITIVE costs a reviewer one glance -- but at scale it buries the
    real settings. On the real SonicWall export, 271 of 805 queue entries were
    object-table columns, and ranked by occurrence they sat ABOVE every genuine
    setting.

Both lists below are drawn from that export.
"""
import pytest

from ncsa.training.classify import (CAT_COSMETIC, CAT_EMPTY, CAT_OTHER,
                                    CAT_SECURITY, base_name, classify)

#: Must remain security-relevant. Each was verified present in the real export.
MUST_KEEP = [
    # The REST API's authentication surface -- remote management, and until
    # this was mapped it was neither audited nor even queued.
    "sonicOsApi_basicAuth", "sonicOsApi_tokenAuth", "sonicOsApi_dgstMD5",
    "sonicOsApi_dgstSHA256", "sonicOsApi_pubKeyBits", "sonicOsApi_CORS",
    # Stored-credential protection. `prefsParamEncryptMethod` begins "prefs",
    # which the cosmetic filter used to swallow.
    "prefsParamEncryptMethod", "cliParamEncryptMethod", "encUsernamePassword",
    # Ordinary security settings that must never be filtered out.
    "snmpStateEnable", "syslogServerName", "sshCipherControlConfig",
    "Snmp3_acc_secLevel", "Snmp3_View_Name", "iface_pppoe_password",
    "adminLoginTimeout", "allowHttpMgmt", "enableCfgAuditing",
    "macIpSpoofMgmt", "ldapSrvrHostName", "radiusAcctAuthEnabled",
    "userGroupObjPrivMask", "sslVpnEnable", "tlsVersionMin",
    "geoIpBlockEnable", "idleTimeout", "ipsecPh1CryptAlg",
]

#: Must be excluded. Object-table columns and substring collisions.
MUST_DROP = [
    # Object-table structure. SonicOS repeats the owning feature in the column
    # name, so the adjacency `ObjType` is not enough -- `gavObjGavType`.
    "gavObjId", "gavObjType", "gavObjGavType", "gavObjProperties",
    "cfsProfileObjId", "schedObjInstanceId", "policyInstanceId",
    "uuidAtomTableName", "uuid_InternalInstanceId", "uuidAtomTableIntInsId",
    # Substring collisions: "ssl" inside SessLife, "ips" inside ZRipS.
    "guestProfileObjSessLife", "userObjGuestSessLife", "ZRipSMode",
    "ZRipSplitH",
    # Security association state, not configuration.
    "ipsecInSPI", "ipsecOutSPI",
]


@pytest.mark.parametrize("name", MUST_KEEP)
def test_real_security_settings_are_not_filtered_out(name):
    """A dropped setting is invisible forever; this is the worse failure."""
    assert classify(name, "1") == CAT_SECURITY, (
        f"{name} is a genuine security setting and must reach the queue")


@pytest.mark.parametrize("name", MUST_DROP)
def test_bookkeeping_is_kept_out_of_the_queue(name):
    assert classify(name, "1") != CAT_SECURITY, (
        f"{name} is bookkeeping; queueing it buries the real settings")


def test_the_camelcase_boundary_is_case_sensitive():
    """The boundary guard must not be neutered by the ignore-case flag.

    `re.I` applied to the whole pattern makes `[A-Z]` match lowercase too, so
    a camelCase-hump lookaround matches at EVERY position and stops guarding
    anything. That is exactly how "ssl" kept matching inside "SessLife".
    """
    assert classify("guestProfileObjSessLife", "1") != CAT_SECURITY
    # ...while a real boundary still matches.
    assert classify("ifaceSslEnable", "1") == CAT_SECURITY
    assert classify("iface_ssl_enable", "1") == CAT_SECURITY


def test_a_strong_keyword_overrules_the_cosmetic_filter():
    """`prefsParamEncryptMethod` is how stored parameters are encrypted.

    It begins "prefs", and the cosmetic filter was classifying it as display
    state on that basis alone.
    """
    assert classify("prefsParamEncryptMethod", "aes") == CAT_SECURITY
    # A genuinely cosmetic name is still filtered.
    assert classify("prefsColumnLayout", "3") == CAT_COSMETIC


def test_an_unset_value_is_not_queued_whatever_its_name():
    """An empty setting carries no information to map."""
    assert classify("sshCipherControlConfig", "") == CAT_EMPTY
    assert classify("adminLoginTimeout", "0") == CAT_EMPTY


def test_the_instance_index_is_stripped():
    """`policyName_68` and `policyName_71` are one setting seen twice."""
    assert base_name("policyName_68") == "policyName"
    assert base_name("Snmp3_View_Name") == "Snmp3_View_Name"


def test_timestamps_are_bookkeeping_whatever_word_they_contain():
    assert classify("addrObjTimeCreated", "123") == CAT_OTHER
    assert classify("policyTimeUpdated", "123") == CAT_OTHER

"""A mapping must read the setting a control asks about, in the unit it asks in.

Both defects below produced a false PASS, the error that matters most (plan
10.5), and neither was visible in a score: the number was plausible, it was
just the wrong number.
"""
from pathlib import Path

from ncsa.pipeline import assess

ASA = """hostname fw1
interface GigabitEthernet1/1
 nameif outside
 security-level 0
ssh 10.0.0.0 255.255.255.0 inside
ssh timeout {t}
"""

JUNOS = """system {{
    host-name r1;
    login {{
{login}
    }}
    services {{
        ssh {{
            protocol-version v2;
            connection-limit 3;
        }}
    }}
}}
"""


def _finding(da, cid):
    return next(f for f in da.assessment.findings if f.control_id == cid)


def test_asa_ssh_timeout_is_minutes_not_seconds(tmp_path: Path):
    """`ssh timeout 15` is fifteen MINUTES. Read as 15 seconds it passed a
    120-second control; read correctly it is 900 seconds and fails it."""
    p = tmp_path / "asa.cfg"
    p.write_text(ASA.format(t=15))
    da = assess(str(p), redact=False, assessment_id="T-ASA-UNIT")
    assert da.identity.platform == "cisco_asa"
    f = _finding(da, "NCSA-EXT-006")
    assert (f.observed, f.state.value) == (900, "FAIL")

    p.write_text(ASA.format(t=1))
    f = _finding(assess(str(p), redact=False, assessment_id="T-ASA-UNIT2"), "NCSA-EXT-006")
    assert (f.observed, f.state.value) == (60, "PASS")


def test_junos_connection_limit_is_not_a_login_attempt_limit(tmp_path: Path):
    """`connection-limit 3` caps concurrent SSH sessions. It says nothing about
    failed logins, so on its own the lockout control cannot be decided."""
    p = tmp_path / "srx.conf"
    p.write_text(JUNOS.format(login="""        class ops {
            idle-timeout 10;
        }"""))
    da = assess(str(p), redact=False, assessment_id="T-JUN-CL")
    assert _finding(da, "NCSA-SSH-004").state.value == "UNKNOWN"
    assert _finding(da, "NCSA-VTY-002").observed is None, \
        "connection-limit is not a source restriction either"


def test_thresholds_over_several_instances_need_every_one():
    from ncsa.engine.operators import op_gte, op_lte
    from ncsa.schema.enums import ResultState as S

    assert op_lte([5, 10], 10) is S.PASS
    assert op_lte([5, 60], 10) is S.FAIL, "one lax instance fails the control"
    assert op_lte(["10"], 10) is S.PASS, "collected text values are numbers"
    assert op_lte([], 10) is S.UNKNOWN, "nothing observed decides nothing"
    assert op_lte([5, "never"], 10) is S.UNKNOWN
    assert op_gte(16, 15) is S.PASS and op_gte(8, 15) is S.FAIL


def test_junos_idle_timeout_is_judged_per_class(tmp_path: Path):
    """Junos has no system-wide idle timeout. One lax class leaves sessions
    open, so the worst class decides -- in both export forms."""
    p = tmp_path / "srx.conf"
    # `show configuration` layout: Junos never prints a block on one line.
    p.write_text(JUNOS.format(login="""        class ops {
            idle-timeout 5;
        }
        class audit {
            idle-timeout 60;
        }"""))
    f = _finding(assess(str(p), redact=False, assessment_id="T-JUN-IT"), "NCSA-TIME-001")
    assert f.state.value == "FAIL" and "audit" in f.reason

    x = tmp_path / "srx.xml"
    x.write_text("""<rpc-reply><configuration><version>21.4R3</version><system>
<host-name>r1</host-name><login>
<class><name>ops</name><idle-timeout>5</idle-timeout></class>
<class><name>audit</name><idle-timeout>60</idle-timeout></class>
</login><services><ssh><protocol-version>v2</protocol-version></ssh></services>
</system></configuration></rpc-reply>""")
    f = _finding(assess(str(x), redact=False, assessment_id="T-JUN-ITX"), "NCSA-TIME-001")
    assert f.state.value == "FAIL"
    assert [int(v) for v in f.observed] == [5, 60], "every class is collected"


def test_junos_retry_options_decide_the_lockout_control(tmp_path: Path):
    p = tmp_path / "srx.conf"
    p.write_text(JUNOS.format(login="""        retry-options {
            tries-before-disconnect 3;
        }"""))
    f = _finding(assess(str(p), redact=False, assessment_id="T-JUN-RO"), "NCSA-SSH-004")
    assert (f.observed, f.state.value) == (3, "PASS")

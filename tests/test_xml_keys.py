"""XML repeated elements keep their own identity (ncsa/readers/xml_reader.py).

Before this, Junos elements named by a <name> CHILD shared one path, so a
policy graph gave every rule the first rule's action and the union of all
rules' addresses, and refused any device with more than one zone pair.
"""
from pathlib import Path

from ncsa.graph.junos_xml_builder import build
from ncsa.readers.xml_reader import loads

JUNOS = """<rpc-reply><configuration><security>
<policies>
  <policy>
    <from-zone-name>trust</from-zone-name><to-zone-name>untrust</to-zone-name>
    <policy><name>web-out</name>
      <match><source-address>LAN</source-address><destination-address>any</destination-address>
             <application>junos-https</application></match>
      <then><permit/><log><session-close/></log></then></policy>
    <policy><name>block-telnet</name>
      <match><source-address>any</source-address><destination-address>any</destination-address>
             <application>junos-telnet</application></match>
      <then><deny/></then></policy>
  </policy>
  <policy>
    <from-zone-name>untrust</from-zone-name><to-zone-name>dmz</to-zone-name>
    <policy><name>web-in</name>
      <match><source-address>any</source-address><destination-address>WEB01</destination-address>
             <application>junos-http</application></match>
      <then><permit/></then></policy>
  </policy>
</policies>
<address-book><name>global</name>
  <address><name>WEB01</name><ip-prefix>10.10.20.50/32</ip-prefix></address>
</address-book>
</security>
<system><login>
  <class><name>ops</name><idle-timeout>5</idle-timeout></class>
  <class><name>audit</name><idle-timeout>60</idle-timeout></class>
</login></system>
</configuration></rpc-reply>"""


def test_each_junos_list_item_is_keyed_by_its_name():
    cfg = loads(JUNOS)
    assert cfg.get("configuration/system/login/class[ops]/idle-timeout")[0] == "5"
    assert cfg.get("configuration/system/login/class[audit]/idle-timeout")[0] == "60"


def test_exact_lookups_without_keys_still_work():
    """Packs written against the old collapsed paths keep working."""
    cfg = loads(JUNOS)
    assert [v for v, *_ in cfg.get_all("configuration/system/login/class/idle-timeout")] \
        == ["5", "60"]


def test_every_rule_is_read_from_its_own_path_across_zone_pairs():
    g = build(loads(JUNOS))
    assert g is not None, "several zone pairs no longer make the builder refuse"
    rules = {r.name: r for r in g.rules}
    assert [r.name for r in g.rules] == ["web-out", "block-telnet", "web-in"], "device order"
    assert rules["web-out"].action == "allow" and rules["web-out"].logging is True
    assert rules["block-telnet"].action == "deny" and not rules["block-telnet"].logging
    assert rules["web-out"].source == ["LAN"], "not the union of every rule's sources"
    assert rules["web-in"].destination == ["WEB01"]
    assert rules["web-in"].source_zones == ["untrust"] and rules["web-in"].destination_zones == ["dmz"]
    assert g.lookup("WEB01") is not None and g.lookup("WEB01").values == ["10.10.20.50/32"]
    assert "untrust" in g.untrusted_zones


def test_root_attributes_are_readable():
    cfg = loads(Path("tests/fixtures/panos_running_config.xml").read_text())
    assert cfg.get("config/@version")[0] == "5.0.0"


def test_panos_entries_keep_their_name_key():
    cfg = loads('<config><devices><entry name="localhost.localdomain">'
                '<deviceconfig><system><hostname>fw1</hostname></system></deviceconfig>'
                '</entry></devices></config>')
    assert cfg.get("devices/entry[localhost.localdomain]/deviceconfig/system/hostname")[0] == "fw1"
    assert cfg.glob("devices/*/deviceconfig/system/hostname")[0][1] == "fw1"

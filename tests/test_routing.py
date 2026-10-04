import pytest

from mqtt_split_proxy.config import ConfigError, from_dict
from mqtt_split_proxy.routing import Router


def cfg(**kw):
    return from_dict(kw)


def multi(default=None):
    data = {"upstreams": [
        {"name": "a", "host": "mqtt.vendor-a.example", "match": {"sni": "*.vendor-a.example"}},
        {"name": "b", "host": "broker.vendor-b.example",
         "match": [{"sni": "broker.vendor-b.example"}, {"client_id": "^VB-"}]},
        {"name": "c", "host": "c.example",
         "match": {"sni": "shared.example", "username": "^c-user$"}},
    ]}
    if default:
        data["default"] = default
    return from_dict(data)


# --- config -----------------------------------------------------------------

def test_legacy_single_upstream_becomes_default():
    c = cfg(upstream={"host": "mqtt.vendor.example"})
    assert c.upstream is None
    assert [u.name for u in c.upstreams] == ["mqtt.vendor.example"]
    assert c.default == "mqtt.vendor.example"
    r = Router(c)
    assert r.select(None, "anything", None).name == "mqtt.vendor.example"


def test_single_mapping_match_is_list_and_sni_normalized():
    c = multi()
    assert len(c.upstreams[0].match) == 1
    assert c.upstreams[0].match[0].sni == ["*.vendor-a.example"]
    assert len(c.upstreams[1].match) == 2
    assert c.default is None


@pytest.mark.parametrize("data,msg", [
    ({}, "no upstream"),
    ({"upstream": {"host": "a"}, "upstreams": [{"host": "b"}]}, "not both"),
    ({"upstreams": [{"host": "a"}, {"host": "a"}]}, "duplicate"),
    ({"upstreams": [{"host": "a"}], "default": "x"}, "unknown upstream"),
    ({"upstreams": [{"host": "a", "match": {}}]}, "empty rule"),
    ({"upstreams": [{"host": "a", "match": {"client_id": "("}}]}, "bad regex"),
    ({"upstreams": [{"host": "a", "match": {"bogus": 1}}]}, "unknown keys"),
    ({"upstreams": [{"host": "a", "cert": "x.crt"}]}, "together"),
    ({"upstreams": [{"port": 1}]}, "host is required"),
    ({"upstream": {"host": "a"}, "local_broker": {"topic_prefix": "{vendr}/"}}, "placeholder"),
])
def test_config_errors(data, msg):
    with pytest.raises(ConfigError, match=msg):
        from_dict(data)


def test_relative_cert_paths_resolved(tmp_path):
    c = from_dict({"upstreams": [{"host": "a", "cert": "a.crt", "key": "/abs/a.key"}]}, tmp_path)
    assert c.upstreams[0].cert == str(tmp_path / "a.crt")
    assert c.upstreams[0].key == "/abs/a.key"


# --- router -----------------------------------------------------------------

@pytest.mark.parametrize("sni,client_id,username,expected", [
    ("mqtt.vendor-a.example", "x", None, "a"),
    ("MQTT.Vendor-A.example", "x", None, "a"),        # SNI is case-insensitive
    ("broker.vendor-b.example", "x", None, "b"),
    (None, "VB-1234", None, "b"),                     # no SNI, client_id rule
    ("mqtt.vendor-a.example", "VB-1", None, "a"),     # first upstream wins
    ("shared.example", "x", "c-user", "c"),           # AND: sni + username
    ("shared.example", "x", "other", None),
    ("shared.example", "x", None, None),
    (None, "x", "c-user", None),
    ("unknown.example", "x", None, None),
    (None, "x", None, None),
])
def test_select(sni, client_id, username, expected):
    up = Router(multi()).select(sni, client_id, username)
    assert (up.name if up else None) == expected


def test_select_default_fallback():
    r = Router(multi(default="b"))
    assert r.select("unknown.example", "x", None).name == "b"
    assert r.select("mqtt.vendor-a.example", "x", None).name == "a"


def test_for_sni_ignores_non_sni_rules():
    r = Router(multi())
    assert r.for_sni("x.vendor-a.example").name == "a"
    assert r.for_sni("broker.vendor-b.example").name == "b"
    assert r.for_sni("shared.example").name == "c"   # SNI part of an AND rule
    assert r.for_sni("VB-1") is None                  # client_id rule is not an SNI rule

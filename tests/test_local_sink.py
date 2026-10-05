import pytest

from mqtt_split_proxy.config import LocalBrokerConfig
from mqtt_split_proxy.local_sink import LocalSink


@pytest.mark.parametrize("strip,topic,expected", [
    (False, "/a/b", "vendor/dev//a/b"),
    (False, "a/b", "vendor/dev/a/b"),
    (True, "/a/b", "vendor/dev/a/b"),
    (True, "//a/b", "vendor/dev/a/b"),
    (True, "a/b", "vendor/dev/a/b"),
])
def test_strip_leading_slash(strip, topic, expected):
    sink = LocalSink(LocalBrokerConfig(topic_prefix="vendor/{client_id}/",
                                       strip_leading_slash=strip))
    assert sink.topic_for("v", "dev", None, topic) == expected
    assert sink.topic_for("v", "dev", None, topic, down=True).startswith("vendor-down/dev/")

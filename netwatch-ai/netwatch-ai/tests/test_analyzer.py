import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from netwatch.analyzer import Analyzer  # noqa: E402
from netwatch.capture import make_packet  # noqa: E402


def titles(a):
    return [x["title"] for x in a.get_alerts()]


def test_port_scan_detected():
    a = Analyzer()
    for i in range(25):
        a.ingest(make_packet("TCP", "10.0.0.9", "10.0.0.1", 4000, 1000 + i, flags="S", ts=1000 + i * 0.1))
    assert any("Scan" in t for t in titles(a))


def test_normal_traffic_no_alert():
    a = Analyzer()
    for i in range(5):
        a.ingest(make_packet("TCP", "10.0.0.2", "10.0.0.1", 4000, 443, flags="S", ts=1000 + i))
    assert titles(a) == []


def test_arp_spoof_detected():
    a = Analyzer()
    a.ingest(make_packet("ARP", "10.0.0.1", "10.0.0.2", info="is-at", mac="aa:aa:aa:aa:aa:aa", ts=1000))
    a.ingest(make_packet("ARP", "10.0.0.1", "10.0.0.2", info="is-at", mac="bb:bb:bb:bb:bb:bb", ts=1001))
    assert any("ARP" in t for t in titles(a))


def test_dns_tunnel_detected():
    a = Analyzer()
    a.ingest(make_packet("DNS", "10.0.0.2", "10.0.0.1", info="a" * 60 + ".example.com", ts=1000))
    assert any("DNS" in t for t in titles(a))


def test_cooldown_avoids_duplicates():
    a = Analyzer()
    for i in range(60):
        a.ingest(make_packet("TCP", "10.0.0.9", "10.0.0.1", 4000, 1000 + i, flags="S", ts=1000 + i * 0.05))
    assert len(a.get_alerts()) == 1

"""Firewall (nftables role), probed from the other instances.

dns is listed in monitoring_sources, pebble is not.
"""

import pytest

from conftest import probe

testinfra_hosts = ["dns", "pebble"]

OPEN_PORTS = [22, 25, 80, 143, 443, 587, 993, 4190]
CLOSED_PORTS = [23, 110, 3306, 5432, 8080]
EXPORTER_PORTS = [9100]


@pytest.fixture(scope="module")
def mail_ip(sovtest_vars):
    return sovtest_vars["sovtest_ips"]["mail"]


@pytest.mark.parametrize("port", OPEN_PORTS)
def test_open_ports_are_reachable(host, mail_ip, port):
    # Nothing listens on most of these ports yet; "refused" proves the firewall
    # let the connection through.
    assert probe(host, mail_ip, port) in ("open", "refused")


def test_ssh_is_listening(host, mail_ip):
    assert probe(host, mail_ip, 22) == "open"


@pytest.mark.parametrize("port", CLOSED_PORTS)
def test_other_ports_are_dropped(host, mail_ip, port):
    assert probe(host, mail_ip, port) == "timeout"


@pytest.mark.parametrize("port", EXPORTER_PORTS)
def test_exporters_only_reachable_from_monitoring_sources(host, mail_ip, port):
    expected = "open" if host.backend.get_hostname() == "dns" else "timeout"
    assert probe(host, mail_ip, port) == expected

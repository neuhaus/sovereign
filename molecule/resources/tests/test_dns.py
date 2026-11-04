"""Smoke tests for the mock DNS instance."""

testinfra_hosts = ["dns"]


def test_knot_running(host):
    knot = host.service("knot")
    assert knot.is_running
    assert knot.is_enabled


def test_knot_listens_on_port_53(host):
    assert host.socket("udp://53").is_listening
    assert host.socket("tcp://53").is_listening

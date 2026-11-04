"""Smoke tests for the Pebble ACME instance."""

testinfra_hosts = ["pebble"]


def test_pebble_running(host):
    pebble = host.service("pebble")
    assert pebble.is_running
    assert pebble.is_enabled


def test_pebble_listens(host):
    assert host.socket("tcp://14000").is_listening
    assert host.socket("tcp://15000").is_listening

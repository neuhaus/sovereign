"""Smoke tests for the mock DNS instance."""

testinfra_hosts = ["dns"]


def test_knot_running(host):
    knot = host.service("knot")
    assert knot.is_running
    assert knot.is_enabled


def test_knot_listens_on_test_address(host):
    ip = host.ansible.get_variables()["sovtest_ips"]["dns"]
    assert host.socket(f"udp://{ip}:53").is_listening
    assert host.socket(f"tcp://{ip}:53").is_listening

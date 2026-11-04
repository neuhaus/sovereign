"""Phase 0 smoke tests for the system under test."""

import json

import pytest

testinfra_hosts = ["mail"]


@pytest.fixture(scope="module")
def sovtest(host):
    """Molecule inventory variables (sovtest_*) for the mail instance."""
    return host.ansible.get_variables()


def test_no_failed_units(host):
    state = host.run("systemctl is-system-running --wait").stdout.strip()
    failed = host.run("systemctl --failed --no-legend --plain").stdout
    assert state == "running", f"system state is {state!r}, failed units:\n{failed}"


def test_debian_track(host, sovtest):
    version = host.file("/etc/debian_version").content_string.strip()
    if sovtest["sovtest_target"] == "trixie":
        assert version.startswith("13"), version
    else:
        assert version.endswith("/sid"), version


def test_mock_dns_resolves_mail_host(host, sovtest):
    ips = sovtest["sovtest_ips"]
    answer = host.check_output(
        "kdig +short @%s mail.%s A", ips["dns"], sovtest["sovtest_domain"]
    )
    assert answer.strip() == ips["mail"]


def test_mock_dns_serves_mx(host, sovtest):
    ips = sovtest["sovtest_ips"]
    domain = sovtest["sovtest_domain"]
    answer = host.check_output("kdig +short @%s %s MX", ips["dns"], domain)
    assert answer.strip() == f"10 mail.{domain}."


def test_pebble_directory_reachable_over_trusted_tls(host, sovtest):
    # curl verifies against the system store, so this also checks that
    # prepare.yml installed the Pebble API CA.
    pebble = sovtest["sovtest_ips"]["pebble"]
    directory = json.loads(host.check_output("curl -fsS https://%s:14000/dir", pebble))
    assert "newAccount" in directory
    assert "newOrder" in directory


def test_pebble_issuance_root_trusted(host):
    root = host.file("/usr/local/share/ca-certificates/sovereign-test-pebble-root.crt")
    assert root.exists
    assert "BEGIN CERTIFICATE" in root.content_string

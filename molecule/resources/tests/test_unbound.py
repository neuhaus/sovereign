"""Local DNSSEC-validating resolver (unbound role) on the mail instance."""

import pytest

testinfra_hosts = ["mail"]


def query(host, name, rtype="A"):
    """Ask the local Unbound with DNSSEC OK; returns kdig's full output."""
    return host.check_output("kdig @127.0.0.1 +dnssec +timeout=5 +retry=2 %s %s", name, rtype)


def test_unbound_running(host):
    service = host.service("unbound")
    assert service.is_running
    assert service.is_enabled
    assert host.socket("udp://127.0.0.1:53").is_listening
    assert host.socket("tcp://127.0.0.1:53").is_listening


def test_unbound_not_reachable_from_outside(host):
    # Only loopback: nothing on the instance's network address.
    listening = host.check_output("ss --listening --numeric --tcp --udp")
    for line in listening.splitlines():
        if line.split()[4:5] and line.split()[4].endswith(":53"):
            assert line.split()[4].startswith(("127.", "[::1]")), line


def test_system_resolver_uses_unbound(host):
    resolv = host.file("/etc/resolv.conf")
    assert not resolv.is_symlink
    assert resolv.content_string.splitlines()[-2:] == [
        "nameserver 127.0.0.1",
        "options edns0 trust-ad",
    ]
    assert not host.service("systemd-resolved").is_running


def test_stub_zone_resolves_test_domain(host, sovtest_vars):
    domain = sovtest_vars["sovtest_domain"]
    mail_ip = sovtest_vars["sovtest_ips"]["mail"]
    # Through glibc, i.e. the path every service on the host takes.
    assert host.check_output("getent ahostsv4 mail.%s", domain).split()[0] == mail_ip


@pytest.mark.parametrize("name", ["signed.test", "debian.org"])
def test_dnssec_validated_answers_have_ad_flag(host, name):
    # signed.test: mock zone with a test trust anchor; debian.org: real
    # internet zone, validated from the root trust anchor.
    answer = query(host, name, "SOA")
    assert "status: NOERROR" in answer, answer
    flags = answer.split("Flags:", 1)[1].split(";", 1)[0]
    assert " ad" in flags, answer


def test_dnssec_bogus_zone_returns_servfail(host):
    answer = query(host, "broken.test", "SOA")
    assert "status: SERVFAIL" in answer, answer


def test_unsigned_test_domain_is_insecure_not_bogus(host, sovtest_vars):
    answer = query(host, "mail." + sovtest_vars["sovtest_domain"])
    assert "status: NOERROR" in answer, answer
    flags = answer.split("Flags:", 1)[1].split(";", 1)[0]
    assert " ad" not in flags

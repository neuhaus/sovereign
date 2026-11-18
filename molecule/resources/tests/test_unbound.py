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
    # Every socket Unbound has open is DNS on loopback, over UDP and TCP:
    # nothing on the instance's network address, and no TCP control port
    # (8953). Also nothing else on port 53.
    listening = host.check_output("ss --listening --numeric --tcp --udp --processes").splitlines()[1:]
    unbound = sorted({(line.split()[0], line.split()[4]) for line in listening if '"unbound"' in line})
    assert unbound == [("tcp", "127.0.0.1:53"), ("udp", "127.0.0.1:53")], unbound
    others = [line for line in listening if line.split()[4].endswith(":53") and '"unbound"' not in line]
    assert not others, others


def test_unbound_control_only_on_root_socket(host):
    # unbound-control can flush the cache, add local zones and change
    # forwarders, so it is a Unix socket for root and the unbound group only.
    assert host.check_output("unbound-checkconf -o control-interface") == "/run/unbound.ctl"
    sock = host.file("/run/unbound.ctl")
    assert sock.is_socket and (sock.user, sock.group, sock.mode) == ("root", "unbound", 0o660)
    assert "is running" in host.check_output("unbound-control status")
    assert host.run("runuser -u nobody -- unbound-control status").rc != 0


def test_system_resolver_uses_unbound(host):
    resolv = host.file("/etc/resolv.conf")
    assert not resolv.is_symlink
    assert resolv.content_string.splitlines()[-2:] == [
        "nameserver 127.0.0.1",
        "options edns0 trust-ad",
    ]
    assert not host.service("systemd-resolved").is_running


def test_resolved_sockets_masked(host):
    # Since systemd 262 (Testing): an enabled socket would try to start the masked
    # service and fail. Debian 13 has no such sockets, so the list may be empty.
    # Exit code 1 when nothing matches, as on Debian 13.
    listing = host.run("systemctl list-unit-files --no-legend --plain --type=socket 'systemd-resolved*'").stdout
    for line in listing.splitlines():
        unit, state = line.split()[:2]
        assert state == "masked", line
        assert host.run(f"systemctl is-failed --quiet {unit}").rc != 0, unit


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


def test_unbound_sandboxed(host):
    props = dict(
        line.split("=", 1)
        for line in host.check_output(
            "systemctl show -p NoNewPrivileges,ProtectSystem,MemoryDenyWriteExecute,RestrictNamespaces,CapabilityBoundingSet unbound"
        ).splitlines()
    )
    assert props["NoNewPrivileges"] == "yes" and props["ProtectSystem"] == "strict", props
    assert props["MemoryDenyWriteExecute"] == "yes" and props["RestrictNamespaces"] == "yes", props
    # Of the eight capabilities its AppArmor profile allows, only these.
    assert sorted(props["CapabilityBoundingSet"].split()) == ["cap_chown", "cap_net_bind_service", "cap_setgid", "cap_setuid"], props


def test_unbound_runs_as_unbound_under_its_apparmor_profile(host):
    pid = host.check_output("systemctl show -p MainPID --value unbound")
    assert host.check_output("ps -o user= -p %s", pid) == "unbound"
    # The profile confines its file access; the sandbox adds no path rules,
    # so notice if it ever stops being enforced.
    if not host.file("/sys/kernel/security/apparmor").exists:
        pytest.skip("no AppArmor here (container)")
    label = host.run("cat /proc/%s/attr/apparmor/current", pid).stdout or host.check_output("cat /proc/%s/attr/current", pid)
    assert label.strip() == "unbound (enforce)", label

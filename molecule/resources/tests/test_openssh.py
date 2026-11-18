"""SSH with keys only (openssh role). Clients run on dns, which fail2ban ignores."""

import pathlib

import pytest

from conftest import run_playbook

testinfra_hosts = ["mail"]

TESTS = pathlib.Path(__file__).parent
OPTIONS = "-o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"


@pytest.fixture(scope="module")
def mail_ip(sovtest_vars):
    return sovtest_vars["sovtest_ips"]["mail"]


@pytest.fixture(scope="module")
def dns(peer):
    return peer("dns")


def test_effective_configuration(host):
    # OpenSSH 10.6 prints the original spelling, older versions lower case.
    settings = host.check_output("sshd -T").lower().splitlines()
    assert "passwordauthentication no" in settings
    assert "kbdinteractiveauthentication no" in settings
    [macs] = [line.split()[1].split(",") for line in settings if line.startswith("macs ")]
    # Only ETM, no SHA-1, no 64-bit tags; whatever else OpenSSH adds later.
    assert macs and all(mac.endswith("-etm@openssh.com") for mac in macs), macs
    assert not [mac for mac in macs if "sha1" in mac or "umac-64" in mac], macs
    assert "hmac-sha2-256-etm@openssh.com" in macs, macs
    assert "requiredrsasize 3072" in settings


@pytest.mark.parametrize("mac", ["hmac-sha1", "umac-64-etm@openssh.com", "umac-64@openssh.com", "hmac-sha2-256"])
def test_weak_mac_refused(dns, mail_ip, mac):
    # AES-CTR needs a separate MAC; a client that offers only this one gets none.
    result = dns.run("ssh %s -c aes128-ctr -m %s -i /root/.ssh/sovtest_ed25519 root@%s true" % (OPTIONS, mac, mail_ip))
    assert result.rc != 0 and "no matching MAC found" in result.stderr, result.stderr


@pytest.mark.parametrize("bits, accepted", [(2048, False), (3072, True)])
def test_rsa_key_minimum(host, dns, mail_ip, bits, accepted):
    key = "/root/.ssh/sovtest_rsa%d" % bits
    dns.run("test -f %s || ssh-keygen -q -t rsa -b %d -N '' -f %s" % (key, bits, key))
    host.run("userdel -r sshrsa")
    host.check_output("useradd -m -s /bin/sh sshrsa")
    try:
        host.check_output(
            "install -d -o sshrsa -m 0700 ~sshrsa/.ssh && echo %s > ~sshrsa/.ssh/authorized_keys", dns.check_output("cat %s.pub", key)
        )
        result = dns.run("ssh %s -o IdentitiesOnly=yes -i %s sshrsa@%s echo logged-in" % (OPTIONS, key, mail_ip))
        assert (result.rc == 0 and "logged-in" in result.stdout) == accepted, result.stderr
    finally:
        host.run("userdel -r sshrsa")


def test_server_offers_only_public_keys(dns, mail_ip):
    # The server's answer names what it accepts: no "password" in there.
    result = dns.run("ssh %s -o PubkeyAuthentication=no root@%s true" % (OPTIONS, mail_ip))
    assert result.rc != 0
    assert "Permission denied (publickey)" in result.stderr, result.stderr


def test_key_login_still_works(dns, mail_ip):
    result = dns.run("ssh %s -i /root/.ssh/sovtest_ed25519 root@%s echo logged-in" % (OPTIONS, mail_ip))
    assert result.rc == 0 and "logged-in" in result.stdout, result.stderr


def test_no_key_stops_the_run_before_anything_changes(host):
    # daemon has no authorized_keys: this must fail rather than lock someone out.
    variables = {"sovtest_role": "openssh", "openssh_login_user": "daemon"}
    output = run_playbook(host, TESTS / "assert_role.yml", variables, expect_failure=True)
    assert "locked out" in output, output


def test_refuses_with_only_short_rsa_keys(host):
    host.run("userdel -r sshtest")
    host.check_output("useradd -m sshtest")
    try:
        host.check_output("install -d -o sshtest -m 0700 ~sshtest/.ssh && ssh-keygen -q -t rsa -b 2048 -N '' -f /tmp/sshtest-rsa")
        host.check_output("cp /tmp/sshtest-rsa.pub ~sshtest/.ssh/authorized_keys")
        variables = {"sovtest_role": "openssh", "openssh_login_user": "sshtest"}
        output = run_playbook(host, TESTS / "assert_role.yml", variables, expect_failure=True)
        assert "shorter than" in output, output
    finally:
        host.run("userdel -r sshtest; rm -f /tmp/sshtest-rsa /tmp/sshtest-rsa.pub")


def test_refuses_without_a_valid_key(host):
    # A non-empty authorized_keys with no usable key (here only a comment).
    host.run("userdel -r sshtest")
    host.check_output("useradd -m sshtest")
    host.check_output(
        "install -d -o sshtest -m 0700 ~sshtest/.ssh && echo '# key goes here' > ~sshtest/.ssh/authorized_keys"
    )
    try:
        variables = {"sovtest_role": "openssh", "openssh_login_user": "sshtest"}
        output = run_playbook(host, TESTS / "assert_role.yml", variables, expect_failure=True)
        assert "valid keys" in output, output
    finally:
        host.run("userdel -r sshtest")

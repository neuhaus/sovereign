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

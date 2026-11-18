"""The server comes back from a reboot (Phase 5.5, step 4).

Reboots the mail instance once, then checks that everything starts by itself:
no failed units, the services, the firewall, the resolver, time sync (outside
containers), mail and metrics. The tests after this file run on the rebooted
system, which is intended: nothing may depend on state from before a reboot.
Works for containers and VMs alike, as each command is its own incus exec.
"""

import time

import pytest

from conftest import mail_client, skip_without_restic

testinfra_hosts = ["mail"]

ALICE = "sovtest-alice-pass"


def boot_id(host):
    return host.check_output("cat /proc/sys/kernel/random/boot_id")


@pytest.fixture(scope="module")
def rebooted(host):
    before = boot_id(host)
    # Delayed, so this command returns before the system goes down.
    host.check_output("systemd-run --on-active=2 --unit=sovtest-reboot systemctl reboot")
    deadline = time.time() + 600
    while time.time() < deadline:
        time.sleep(5)
        try:
            after = boot_id(host)
        except Exception:  # the instance is down or still starting
            continue
        if after != before:
            break
    else:
        pytest.fail("the instance did not come back within 10 minutes")
    state = host.run("timeout 300 systemctl is-system-running --wait").stdout.strip()
    return {"state": state, "failed": host.run("systemctl --failed --no-legend --plain").stdout}


def test_system_running_without_failed_units(rebooted):
    assert rebooted["state"] == "running", "state %r, failed units:\n%s" % (rebooted["state"], rebooted["failed"])


@pytest.mark.parametrize(
    "service",
    [
        "postfix",
        "dovecot",
        "nginx",
        "rspamd",
        "redis-server",
        "unbound",
        "fail2ban",
        "postsrsd",
        "radicale",
        "prometheus-node-exporter",
        "sovereign-tls-policy",
        "postfix-mta-sts-resolver",
    ],
)
def test_service_started(host, rebooted, service):
    assert host.service(service).is_running


@pytest.mark.parametrize(
    "timer",
    ["certbot.timer", "sovereign-backup.timer", "sovereign-support-status.timer", "sovereign-mailqueue-metrics.timer"],
)
def test_timer_active(host, rebooted, sovtest_vars, timer):
    if timer.startswith("sovereign-backup"):
        skip_without_restic(sovtest_vars)
    assert host.service(timer).is_running


def test_firewall_loaded(host, rebooted):
    ruleset = host.check_output("nft list ruleset")
    assert "policy drop" in ruleset, ruleset[:2000]


def test_resolver_validates(host, sovtest_vars, rebooted):
    answer = host.check_output("kdig @127.0.0.1 +dnssec +timeout=5 +retry=2 signed.test SOA")
    assert "status: NOERROR" in answer and " ad" in answer.split("Flags:", 1)[1].split(";", 1)[0], answer
    # The system resolver goes through Unbound.
    assert host.check_output("getent hosts mail.%s", sovtest_vars["sovtest_domain"])


def test_time_sync_outside_containers(host, rebooted):
    if host.run("systemd-detect-virt --container --quiet").rc == 0:
        pytest.skip("in a container the host keeps the time")
    assert host.service("systemd-timesyncd").is_running


def test_mail_login_after_reboot(peer, sovtest_vars, rebooted):
    client = mail_client(peer("dns"))
    alice = "alice@" + sovtest_vars["sovtest_domain"]
    assert client("imap-login", sovtest_vars["sovtest_ips"]["mail"], "993", alice, ALICE)["ok"]


def test_metrics_after_reboot(host, rebooted):
    assert "node_exporter_build_info" in host.check_output("curl --silent --fail http://127.0.0.1:9100/metrics")

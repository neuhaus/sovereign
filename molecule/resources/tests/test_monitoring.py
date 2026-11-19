"""Metrics on the mail instance and the example alert rules (monitoring/).

promtool runs on the dns instance (installed in prepare.yml).
"""

import base64
import pathlib
import re
import time

import pytest
import yaml

from conftest import skip_without_restic, without_restic

testinfra_hosts = ["mail"]

MONITORING = pathlib.Path(__file__).parents[3] / "monitoring"
WORK = "/tmp/sovtest-monitoring"


def push(instance, name):
    data = base64.b64encode((MONITORING / name).read_bytes()).decode()
    instance.check_output("mkdir -p %s && echo %s | base64 -d > %s/%s", WORK, data, WORK, name)


def metrics(host):
    return host.check_output("curl --silent --fail http://127.0.0.1:9100/metrics")


def test_alert_rules_valid_and_tested(peer):
    dns = peer("dns")
    push(dns, "alerts.yml")
    push(dns, "alerts.test.yml")
    result = dns.run("cd %s && promtool check rules alerts.yml && promtool test rules alerts.test.yml", WORK)
    assert result.rc == 0, result.stdout + result.stderr


def test_every_metric_in_the_rules_exists(host, sovtest_vars):
    # Run every job that writes a textfile metric once, so the test does not
    # depend on timers or on the order of the test files.
    backups = not without_restic(sovtest_vars)
    for unit in ("sovereign-mailqueue-metrics", "sovereign-support-status", "sovereign-reboot-pending", "sovereign-dane-check", "sovereign-integrity-check") + (("sovereign-backup", "sovereign-backup-check") if backups else ()):
        host.check_output("systemctl start %s.service", unit)
    rules = yaml.safe_load((MONITORING / "alerts.yml").read_text())
    used = set()
    for group in rules["groups"]:
        for rule in group["rules"]:
            used |= set(re.findall(r"\b((?:sovereign|node)_[a-zA-Z0-9_]+)\b", rule["expr"]))
    exported = {line.split("{")[0].split(" ")[0] for line in metrics(host).splitlines() if not line.startswith("#")}
    if not backups:
        used = {name for name in used if not name.startswith("sovereign_backup_")}
    assert used - exported == set()


@pytest.mark.parametrize("unit", ["postfix.service", "dovecot.service", "sovereign-backup.timer"])
def test_unit_states_exported(host, sovtest_vars, unit):
    if unit.startswith("sovereign-backup"):
        skip_without_restic(sovtest_vars)
    assert 'node_systemd_unit_state{name="%s",state="active",type=' % unit in metrics(host)


def test_mail_queue_metrics(host):
    host.check_output("systemctl start sovereign-mailqueue-metrics.service")
    text = metrics(host)
    for queue in ("incoming", "active", "deferred", "hold"):
        assert re.search(r'^sovereign_postfix_queue_messages\{queue="%s"\} \d+$' % queue, text, re.M), queue
    assert re.search(r"^sovereign_postfix_queue_oldest_deferred_seconds \d+$", text, re.M)


def test_mail_queue_counts_files(host):
    # Postfix leaves files in the hold queue alone, and the measurement only
    # counts files: a dummy file there is counted and gone again afterwards.
    hold = host.check_output("postconf -h queue_directory") + "/hold/SOVTEST0000"
    host.check_output("touch %s", hold)
    try:
        host.check_output("systemctl start sovereign-mailqueue-metrics.service")
        assert re.search(r'^sovereign_postfix_queue_messages\{queue="hold"\} 1$', metrics(host), re.M)
    finally:
        host.run("rm -f %s", hold)
    host.check_output("systemctl start sovereign-mailqueue-metrics.service")
    assert re.search(r'^sovereign_postfix_queue_messages\{queue="hold"\} 0$', metrics(host), re.M)


def test_certificate_expiry_metric(host, ansible_var):
    name = ansible_var("certbot_domains")[0]
    expiry = host.check_output(
        "date -d \"$(openssl x509 -in /etc/letsencrypt/live/%s/cert.pem -noout -enddate | cut -d= -f2)\" +%%s", name
    )
    line = 'sovereign_certificate_expiry_timestamp_seconds{name="%s"} ' % name
    values = [entry[len(line):] for entry in metrics(host).splitlines() if entry.startswith(line)]
    assert len(values) == 1 and float(values[0]) == float(expiry), values


# --- Sandbox -----------------------------------------------------------------


def test_node_exporter_sandboxed(host, sovtest_vars):
    props = dict(
        line.split("=", 1)
        for line in host.check_output(
            "systemctl show -p NoNewPrivileges,ProtectSystem,CapabilityBoundingSet,IPAddressDeny,IPAddressAllow,ActiveState"
            " prometheus-node-exporter"
        ).splitlines()
    )
    assert props["NoNewPrivileges"] == "yes" and props["ProtectSystem"] == "strict", props
    assert props["CapabilityBoundingSet"] == "" and props["ActiveState"] == "active", props
    assert set(props["IPAddressDeny"].split()) == {"0.0.0.0/0", "::/0"}, props
    allowed = props["IPAddressAllow"].split()
    assert {"127.0.0.0/8", "::1/128"} <= set(allowed), allowed
    assert any(a.startswith(sovtest_vars["sovtest_ips"]["dns"] + "/") for a in allowed), allowed


def test_node_exporter_collects_without_crashing(host):
    # The system call filter once killed it on the first scrape (adjtimex,
    # timex collector), and systemd's restarts hid it between tests.
    text = metrics(host)
    assert 'node_scrape_collector_success{collector="timex"} 1' in text
    assert host.check_output("systemctl show -p NRestarts --value prometheus-node-exporter") == "0"


def test_node_exporter_reports_the_real_disk(host):
    # The sandbox must not replace a mount point: the exporter would then
    # report the replacement's free space and the disk alerts would be wrong.
    m = re.search(r'^node_filesystem_size_bytes\{[^}]*mountpoint="/"[^}]*\} (\S+)$', metrics(host), re.M)
    assert m, "no size for /"
    real = int(host.check_output("df -B1 --output=size / | tail -1").strip())
    assert abs(float(m.group(1)) - real) <= real * 0.01, (m.group(1), real)


def test_node_exporter_drops_other_addresses_itself(host, sovtest_vars):
    # From the instance's own address to itself the firewall lets everything
    # through (lo); only the sandbox's IP filter can refuse it.
    if host.run("systemd-detect-virt --container --quiet").rc == 0:
        pytest.skip("cgroup IP filtering needs a VM")
    mail = sovtest_vars["sovtest_ips"]["mail"]
    assert host.run("curl --silent --fail --max-time 5 http://127.0.0.1:9100/metrics -o /dev/null").rc == 0
    blocked = host.run("curl --silent --max-time 5 --interface %s http://%s:9100/metrics -o /dev/null", mail, mail)
    assert blocked.rc != 0, "the exporter answered a non-monitoring address"


def test_pending_reboot_mails_the_postmaster_once(host, sovtest_vars):
    # A pending kernel update: one mail to root (-> postmaster -> alice in
    # Molecule) right away, and the time it was first seen, which stays until
    # the reboot; then the metric drops to 0.
    kernel = "sovtest-%d" % int(time.time())
    status = "NEEDRESTART-KSTA: 3\nNEEDRESTART-KCUR: 1.0-old\nNEEDRESTART-KEXP: %s\n" % kernel
    check = "SOVEREIGN_REBOOT_STATUS=\"$(printf %%b %s)\" /usr/local/sbin/sovereign-reboot-pending"
    # node_exporter writes large values in exponent notation (1.795e+09).
    since = r"^sovereign_reboot_pending_since_timestamp_seconds (\S+)$"
    alice = "alice@" + sovtest_vars["sovtest_domain"]

    def mails():
        return host.run("doveadm search -u %s mailbox INBOX header subject %s", alice, kernel).stdout.splitlines()

    try:
        host.check_output(check, status)
        first = float(re.search(since, metrics(host), re.M).group(1))
        assert first > 0
        for _ in range(30):
            if mails():
                break
            time.sleep(2)
        host.check_output(check, status)
        assert float(re.search(since, metrics(host), re.M).group(1)) == first
        time.sleep(5)
        assert len(mails()) == 1, mails()
        host.check_output(check, "NEEDRESTART-KSTA: 1")
        assert float(re.search(since, metrics(host), re.M).group(1)) == 0
    finally:
        host.run("rm -f /var/lib/sovereign/reboot-pending-since")
        host.run("systemctl start sovereign-reboot-pending.service")


def test_no_reboot_pending_after_converge(host):
    # The test VMs run the newest installed kernel; a container reports 0.
    host.check_output("systemctl start sovereign-reboot-pending.service")
    assert re.search(r"^sovereign_reboot_pending_since_timestamp_seconds 0$", metrics(host), re.M)

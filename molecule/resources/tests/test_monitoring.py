"""Metrics on the mail instance and the example alert rules (monitoring/).

promtool runs on the dns instance (installed in prepare.yml).
"""

import base64
import pathlib
import re

import pytest
import yaml

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


def test_every_metric_in_the_rules_exists(host):
    # Run every job that writes a textfile metric once, so the test does not
    # depend on timers or on the order of the test files.
    for unit in ("sovereign-mailqueue-metrics", "sovereign-support-status", "sovereign-backup", "sovereign-backup-check"):
        host.check_output("systemctl start %s.service", unit)
    rules = yaml.safe_load((MONITORING / "alerts.yml").read_text())
    used = set()
    for group in rules["groups"]:
        for rule in group["rules"]:
            used |= set(re.findall(r"\b((?:sovereign|node)_[a-zA-Z0-9_]+)\b", rule["expr"]))
    exported = {line.split("{")[0].split(" ")[0] for line in metrics(host).splitlines() if not line.startswith("#")}
    assert used - exported == set()


@pytest.mark.parametrize("unit", ["postfix.service", "dovecot.service", "sovereign-backup.timer"])
def test_unit_states_exported(host, unit):
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

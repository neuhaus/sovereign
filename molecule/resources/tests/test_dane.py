"""Outbound DANE verification by Postfix against a real TLS server, Phase 4.

The SMTP sink on dns offers STARTTLS with a self-signed certificate, so only a
matching TLSA record makes it trustworthy. dane-ok.test publishes its key,
dane-bad.test a wrong one. Both zones are DNSSEC-signed and validated by Unbound.
"""

import json
import time
import uuid

import pytest

from conftest import mail_client

testinfra_hosts = ["mail"]

CAROL_APP = "CarolPh1-sovtest-app-phone"
SINK_LOG = "/tmp/sink-dane.jsonl"


@pytest.fixture(scope="module")
def ctx(sovtest_vars):
    return {"ip": sovtest_vars["sovtest_ips"]["mail"], "carol": "carol@" + sovtest_vars["sovtest_domain"]}


@pytest.fixture(scope="module")
def dns(peer):
    return peer("dns")


@pytest.fixture(scope="module")
def client(dns):
    return mail_client(dns)


@pytest.fixture(scope="module")
def sink(dns, client):
    dns.run("pkill -f 'mailclient.py sink' || true; rm -f %s", SINK_LOG)
    dns.check_output(
        "nohup python3 /tmp/mailclient.py sink 25 %s /etc/sovtest/sink.crt /etc/sovtest/sink.key >/dev/null 2>&1 &", SINK_LOG
    )
    time.sleep(1)
    yield
    dns.run("pkill -f 'mailclient.py sink' || true")


def received(dns):
    if not dns.file(SINK_LOG).exists:
        return []
    return [json.loads(line) for line in dns.file(SINK_LOG).content_string.splitlines()]


def postfix_log(host):
    return host.check_output("journalctl -t postfix/smtp --no-pager --since -10min")


def wait_for(check, seconds=90):
    for _ in range(seconds):
        if check():
            return True
        time.sleep(1)
    return False


def submit(client, ctx, recipient):
    subject = "dane" + uuid.uuid4().hex[:10]
    result = client("submit", ctx["ip"], ctx["carol"], CAROL_APP, ctx["carol"], recipient, subject)
    assert result["ok"], result


def test_correct_tlsa_record_is_verified(host, dns, client, ctx, sink):
    recipient = "someone@dane-ok.test"
    submit(client, ctx, recipient)
    assert wait_for(lambda: [m for m in received(dns) if recipient in m["rcpt"]]), postfix_log(host)
    message = [m for m in received(dns) if recipient in m["rcpt"]][0]
    assert message["tls"]
    assert "Verified TLS connection established to mx.dane-ok.test" in postfix_log(host)


def test_wrong_tlsa_record_defers_the_mail(host, dns, client, ctx, sink):
    recipient = "someone@dane-bad.test"
    submit(client, ctx, recipient)

    def deferred():
        return [line for line in postfix_log(host).splitlines() if "to=<%s>" % recipient in line and "status=deferred" in line]

    try:
        assert wait_for(deferred), postfix_log(host)
        assert "not verified" in deferred()[0], deferred()
        assert not [m for m in received(dns) if recipient in m["rcpt"]]
    finally:
        # Do not leave it in the queue for the following tests.
        for line in host.check_output("postqueue -j").splitlines():
            entry = json.loads(line)
            if [r for r in entry["recipients"] if r["address"] == recipient]:
                host.run("postsuper -d %s", entry["queue_id"])


@pytest.mark.parametrize(
    "domain, dane",
    [
        ("dane-ok.test", True),
        # One MX without TLSA: Postfix would use unauthenticated TLS there, so the
        # domain's MTA-STS policy (if it has one) must apply.
        ("dane-mixed.test", False),
        # Only a TLSA record SMTP ignores.
        ("dane-unusable.test", False),
        # Not signed at all.
        ("ext.test", False),
    ],
)
def test_tls_policy_skips_mta_sts_only_with_dane_for_every_mx(host, domain, dane):
    host.run("postmap -q %s socketmap:inet:127.0.0.1:8462:postfix", domain)
    decisions = [
        line
        for line in host.check_output("journalctl -u sovereign-tls-policy --no-pager --since -2min -o cat").splitlines()
        # Lines look like "INFO <domain>: <decision>".
        if line.split(" ", 1)[-1].startswith(domain + ":")
    ]
    assert decisions, "no decision logged for " + domain
    assert ("MTA-STS not consulted" in decisions[-1]) == dane, decisions[-1]

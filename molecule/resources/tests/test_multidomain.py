"""Several mail domains on one server.

alice exists on both domains on purpose: nothing may mix them up.
"""

import base64
import json
import pathlib
import time
import uuid
import xml.dom.minidom

import pytest

from conftest import mail_client, run_playbook

testinfra_hosts = ["mail"]

TESTS = pathlib.Path(__file__).parent
ALICE = "sovtest-alice-pass"
ALICE2 = "sovtest-alice2-pass"
BOB = "sovtest-bob-pass"


@pytest.fixture(scope="module")
def ctx(sovtest_vars):
    first = sovtest_vars["sovtest_domain"]
    second = sovtest_vars["sovtest_second_domain"]
    return {
        "ip": sovtest_vars["sovtest_ips"]["mail"],
        "first": first,
        "second": second,
        "external": sovtest_vars["sovtest_external_domain"],
        "alice": "alice@" + first,
        "alice2": "alice@" + second,
        "bob": "bob@" + first,
        "web": "mail." + first,
        "dav": "dav." + first,
    }


@pytest.fixture(scope="module")
def dns(peer):
    return peer("dns")


@pytest.fixture(scope="module")
def client(dns):
    return mail_client(dns)


@pytest.fixture(scope="module")
def sink(dns, client):
    log = "/tmp/sink-multidomain.jsonl"
    dns.run("pkill -f 'mailclient.py sink' || true; rm -f %s", log)
    dns.check_output("nohup python3 /tmp/mailclient.py sink 25 %s >/dev/null 2>&1 &", log)
    time.sleep(1)

    def messages():
        if not dns.file(log).exists:
            return []
        return [json.loads(line) for line in dns.file(log).content_string.splitlines()]

    yield messages
    dns.run("pkill -f 'mailclient.py sink' || true")


def unique(prefix):
    return prefix + uuid.uuid4().hex[:10]


def wait_for(check, seconds=60):
    for _ in range(seconds):
        result = check()
        if result:
            return result
        time.sleep(1)
    return None


def delivered(client, ctx, user, password, subject):
    return wait_for(lambda: client("imap-count", ctx["ip"], user, password, subject)["count"] == 1)


def https(host, name, path, *options):
    return host.check_output("curl -fsS --resolve %s:443:127.0.0.1 " + " ".join(options) + " https://%s%s", name, name, path)


# --- Delivery ---------------------------------------------------------------------


def test_same_localpart_reaches_the_right_mailbox(client, ctx):
    subject = unique("second")
    assert client("smtp", ctx["ip"], "sender@origin.example", ctx["alice2"], subject)["ok"]
    assert delivered(client, ctx, ctx["alice2"], ALICE2, subject)
    assert client("imap-count", ctx["ip"], ctx["alice"], ALICE, subject)["count"] == 0

    subject = unique("first")
    assert client("smtp", ctx["ip"], "sender@origin.example", ctx["alice"], subject)["ok"]
    assert delivered(client, ctx, ctx["alice"], ALICE, subject)
    assert client("imap-count", ctx["ip"], ctx["alice2"], ALICE2, subject)["count"] == 0


def test_mailboxes_are_stored_per_domain(host, ctx):
    assert host.file("/var/vmail/%s/alice/Maildir" % ctx["second"]).is_directory
    assert host.file("/var/vmail/%s/alice/Maildir" % ctx["first"]).is_directory


def test_passwords_are_per_domain(client, ctx):
    assert client("imap-login", ctx["ip"], "993", ctx["alice2"], ALICE2)["ok"]
    assert not client("imap-login", ctx["ip"], "993", ctx["alice2"], ALICE)["ok"]
    assert not client("imap-login", ctx["ip"], "993", ctx["alice"], ALICE2)["ok"]


def test_mail_between_the_domains(client, ctx):
    subject = unique("between")
    sent = client("submit", ctx["ip"], ctx["alice2"], ALICE2, ctx["alice2"], ctx["bob"], subject)
    assert sent["ok"], sent
    assert delivered(client, ctx, ctx["bob"], BOB, subject)


def test_unknown_user_on_second_domain_rejected(client, ctx):
    assert not client("smtp", ctx["ip"], "sender@origin.example", "nobody@" + ctx["second"], unique("nobody"))["ok"]


def test_alias_across_domains(client, ctx):
    subject = unique("alias")
    assert client("smtp", ctx["ip"], "sender@origin.example", "info@" + ctx["second"], subject)["ok"]
    assert delivered(client, ctx, ctx["alice"], ALICE, subject)


# --- Sender addresses ---------------------------------------------------------------


def test_cannot_send_as_the_same_localpart_on_the_other_domain(client, ctx):
    result = client("submit", ctx["ip"], ctx["alice2"], ALICE2, ctx["alice"], ctx["bob"], unique("forged"))
    assert not result["ok"], result
    result = client("submit", ctx["ip"], ctx["alice"], ALICE, ctx["alice2"], ctx["bob"], unique("forged"))
    assert not result["ok"], result


def test_can_send_as_an_alias_on_the_other_domain(client, ctx):
    sender = "info@" + ctx["second"]
    subject = unique("asalias")
    result = client("submit", ctx["ip"], ctx["alice"], ALICE, sender, ctx["bob"], subject)
    assert result["ok"], result
    assert delivered(client, ctx, ctx["bob"], BOB, subject)


# --- DKIM and SRS --------------------------------------------------------------------


def test_each_domain_has_its_own_dkim_key(host, ctx):
    first = host.file("/var/lib/rspamd/dkim/%s.sovereign.key" % ctx["first"]).content_string
    second = host.file("/var/lib/rspamd/dkim/%s.sovereign.key" % ctx["second"]).content_string
    assert first and second and first != second


def test_outbound_mail_is_signed_with_the_senders_domain(host, client, ctx, sink):
    recipient = unique("dkim") + "@" + ctx["external"]
    sent = client("submit", ctx["ip"], ctx["alice2"], ALICE2, ctx["alice2"], recipient, unique("dkim"))
    assert sent["ok"], sent
    message = wait_for(lambda: [m for m in sink() if recipient in m["rcpt"]])
    assert message, "nothing arrived"
    data = message[0]["data"]
    raw = base64.b64decode(data).decode(errors="replace")
    signature = raw.split("DKIM-Signature:", 1)[1].split("\n\n", 1)[0]
    assert "d=" + ctx["second"] in signature, signature

    txt = host.check_output("cat /var/lib/rspamd/dkim/%s.sovereign.txt" % ctx["second"])
    record = "".join(txt.split('"')[1::2])
    assert client("dkim-verify", data, record)["ok"]


def test_forwarded_mail_uses_the_first_domain_for_srs(client, ctx, sink):
    subject = unique("srs")
    assert client("smtp", ctx["ip"], "sender@origin.example", "fwd2@" + ctx["second"], subject)["ok"]
    recipient = "someone2@" + ctx["external"]
    message = wait_for(lambda: [m for m in sink() if recipient in m["rcpt"]])
    assert message, "nothing arrived"
    sender = message[0]["from"]
    assert sender.startswith("SRS0=") and sender.endswith("@" + ctx["first"]), sender


# --- Web endpoints -------------------------------------------------------------------


@pytest.mark.parametrize("prefix", ["mta-sts", "autoconfig", "autodiscover"])
def test_certificate_covers_the_second_domain(host, ctx, prefix):
    # curl verifies the certificate, so a missing name fails here.
    code = host.check_output(
        "curl -s -o /dev/null -w '%%{http_code}' --resolve %s:443:127.0.0.1 https://%s/", prefix + "." + ctx["second"], prefix + "." + ctx["second"]
    )
    assert code == "404"


def test_mta_sts_policy_for_the_second_domain(host, ctx):
    policy = https(host, "mta-sts." + ctx["second"], "/.well-known/mta-sts.txt").splitlines()
    assert "mode: enforce" in policy
    assert "mx: " + ctx["web"] in policy


def test_autoconfig_for_the_second_domain(host, ctx):
    doc = xml.dom.minidom.parseString(https(host, "autoconfig." + ctx["second"], "/mail/config-v1.1.xml"))
    assert {n.firstChild.data for n in doc.getElementsByTagName("hostname")} == {ctx["web"]}
    assert ctx["second"] in {n.firstChild.data for n in doc.getElementsByTagName("domain")}


def test_autodiscover_for_the_second_domain(host, ctx):
    body = https(host, "autodiscover." + ctx["second"], "/autodiscover/autodiscover.xml", "-X POST", "--data '<Autodiscover/>'")
    doc = xml.dom.minidom.parseString(body)
    assert {n.firstChild.data for n in doc.getElementsByTagName("Server")} == {ctx["web"]}


# --- Webmail and calendars ------------------------------------------------------------


def test_webmail_login_on_the_second_domain(client, ctx):
    assert client("web-login", ctx["ip"], ctx["web"], ctx["alice2"], ALICE2)["ok"]
    assert not client("web-login", ctx["ip"], ctx["web"], ctx["alice2"], ALICE)["ok"]


def test_calendars_are_separate_per_domain(client, ctx):
    def propfind(path, user, password):
        return client("dav", ctx["ip"], ctx["dav"], "PROPFIND", path, user, password)["status"]

    assert propfind("/%s/" % ctx["alice2"], ctx["alice2"], ALICE2) == 207
    assert propfind("/%s/" % ctx["alice"], ctx["alice2"], ALICE2) == 403
    assert propfind("/%s/" % ctx["alice2"], ctx["alice"], ALICE) == 403


# --- Configuration --------------------------------------------------------------------


@pytest.mark.parametrize("role, missing", [("mta_sts", "mta-sts."), ("autoconfig", "autoconfig."), ("autoconfig", "autodiscover.")])
def test_missing_certificate_name_stops_the_run(host, ansible_var, ctx, role, missing):
    names = [name for name in ansible_var("certbot_domains") if name != missing + ctx["second"]]
    output = run_playbook(host, TESTS / "assert_role.yml", {"sovtest_role": role, "certbot_domains": names}, expect_failure=True)
    assert missing + ctx["second"] in output, output


def test_removing_a_domain(host, client, ctx):
    keep = {
        "maildb_domains": ["{{ sovtest_domain }}"],
        "maildb_mailboxes": "{{ mail_mailboxes | rejectattr('address', 'search', sovtest_second_domain) | list }}",
        "maildb_aliases": "{{ mail_aliases | rejectattr('source', 'search', sovtest_second_domain) | list }}",
    }
    subject = unique("removal")
    assert client("smtp", ctx["ip"], "sender@origin.example", ctx["alice2"], subject)["ok"]
    assert delivered(client, ctx, ctx["alice2"], ALICE2, subject)
    try:
        run_playbook(host, TESTS / "maildb_run.yml", keep)
        assert not client("imap-login", ctx["ip"], "993", ctx["alice2"], ALICE2)["ok"]
        assert not client("smtp", ctx["ip"], "sender@origin.example", ctx["alice2"], unique("gone"))["ok"]
        # The other domain is untouched, and the mail stays on disk.
        assert client("imap-login", ctx["ip"], "993", ctx["alice"], ALICE)["ok"]
        assert host.file("/var/vmail/%s/alice/Maildir" % ctx["second"]).is_directory
    finally:
        run_playbook(host, TESTS / "maildb_run.yml", {})
    # Back in the inventory: the mailbox and its mail return.
    assert client("imap-count", ctx["ip"], ctx["alice2"], ALICE2, subject)["count"] == 1

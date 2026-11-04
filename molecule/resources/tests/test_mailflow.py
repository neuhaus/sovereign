"""Mail transport (postfix and dovecot roles), Phase 2.3.

Clients run on the dns instance, i.e. from another address: Dovecot treats
connections from its own address as secure and would allow plaintext logins.
"""

import base64
import json
import pathlib
import time
import uuid

import pytest

testinfra_hosts = ["mail"]

ALICE = "sovtest-alice-pass"
ALICE_APP = "AlicPhn1-sovtest-app-phone"
BOB = "sovtest-bob-pass"


@pytest.fixture(scope="module")
def ctx(sovtest_vars):
    d = sovtest_vars["sovtest_domain"]
    return {
        "mail_ip": sovtest_vars["sovtest_ips"]["mail"],
        "alice": "alice@" + d,
        "bob": "bob@" + d,
        "domain": d,
        "external": sovtest_vars["sovtest_external_domain"],
        "cert": "/etc/letsencrypt/live/%s/cert.pem" % sovtest_vars["certbot_domains"][0],
    }


@pytest.fixture(scope="module")
def client(peer):
    """Run mailclient.py commands on the dns instance; returns parsed JSON."""
    dns = peer("dns")
    code = base64.b64encode((pathlib.Path(__file__).parent / "mailclient.py").read_bytes()).decode()
    dns.check_output("echo %s | base64 -d > /tmp/mailclient.py", code)

    def run(*args):
        return json.loads(dns.check_output("python3 /tmp/mailclient.py " + " ".join(["%s"] * len(args)), *args))

    run.host = dns
    return run


def unique(prefix):
    return prefix + uuid.uuid4().hex[:10]


def wait_for(fn, timeout=30):
    end = time.time() + timeout
    while time.time() < end:
        result = fn()
        if result:
            return result
        time.sleep(1)
    return fn()


def delivered(client, ctx, user, password, subject):
    return wait_for(lambda: client("imap-count", ctx["mail_ip"], user, password, subject)["count"] == 1)


# Services and configuration


@pytest.mark.parametrize("service", ["postfix", "dovecot", "postsrsd"])
def test_services_running(host, service):
    assert host.service(service).is_running
    assert host.service(service).is_enabled


def test_configuration_checks_pass(host):
    host.check_output("postfix check")
    host.check_output("doveconf -n")


def test_postsrsd_from_backports_on_trixie(host, sovtest_vars):
    version = host.check_output("dpkg-query -W -f '${Version}' postsrsd")
    assert version.startswith("2."), version
    if host.file("/etc/debian_version").content_string.startswith("13"):
        assert "bpo13" in version


@pytest.mark.parametrize("port", [993, 4190])
def test_dovecot_uses_the_acme_certificate(host, ctx, port):
    # Verified against the system store, which trusts the Pebble root on mail.
    starttls = "-starttls sieve" if port == 4190 else ""
    served = host.check_output(
        "openssl s_client -connect 127.0.0.1:%s %s -servername mail.%s -verify_return_error </dev/null 2>/dev/null"
        " | openssl x509 -noout -fingerprint -sha256" % (port, starttls, ctx["domain"])
    )
    assert served == host.check_output("openssl x509 -in %s -noout -fingerprint -sha256", ctx["cert"])


@pytest.mark.parametrize("port", [25, 587])
def test_postfix_uses_the_acme_certificate(host, ctx, port):
    served = host.check_output(
        "openssl s_client -connect 127.0.0.1:%s -starttls smtp -servername mail.%s -verify_return_error </dev/null 2>/dev/null"
        " | openssl x509 -noout -fingerprint -sha256" % (port, ctx["domain"])
    )
    assert served == host.check_output("openssl x509 -in %s -noout -fingerprint -sha256", ctx["cert"])


# Submission (587)


def test_submission_requires_starttls(client, ctx):
    result = client("submission-plain", ctx["mail_ip"])
    assert result["starttls"]
    assert not result["auth_before_tls"]
    assert result["mail_code"] == 530


@pytest.mark.parametrize("password", [ALICE, ALICE_APP], ids=["main-password", "app-password"])
def test_submission_delivers(client, ctx, password):
    subject = unique("subm")
    assert client("submit", ctx["mail_ip"], ctx["alice"], password, ctx["alice"], ctx["bob"], subject)["ok"]
    assert delivered(client, ctx, ctx["bob"], BOB, subject)


def test_submission_rejects_wrong_password(client, ctx):
    result = client("submit", ctx["mail_ip"], ctx["alice"], "wrong-password", ctx["alice"], ctx["bob"], unique("x"))
    assert not result["ok"] and result["stage"] == "auth"


def test_submission_rejects_foreign_sender(client, ctx):
    result = client("submit", ctx["mail_ip"], ctx["alice"], ALICE, ctx["bob"], ctx["alice"], unique("spoof"))
    assert not result["ok"] and "553" in result["error"], result


def test_submission_allows_alias_of_the_login(client, ctx):
    result = client("submit", ctx["mail_ip"], ctx["alice"], ALICE, "team@" + ctx["domain"], ctx["bob"], unique("team"))
    assert result["ok"], result


# Incoming SMTP (25)


def test_inbound_plus_address_delivered_to_user(client, ctx):
    subject = unique("plus")
    result = client("smtp", ctx["mail_ip"], "someone@origin.example", "alice+tag@" + ctx["domain"], subject)
    assert result["ok"] and result["starttls"] and not result["auth"], result
    assert delivered(client, ctx, ctx["alice"], ALICE, subject)


def test_no_open_relay(client, ctx):
    result = client("smtp", ctx["mail_ip"], "someone@origin.example", "victim@elsewhere.example", unique("relay"))
    assert not result["ok"] and "Relay access denied" in result["error"], result


def test_forwarded_mail_has_srs_sender(client, ctx):
    sink = client.host
    sink.run("rm -f /tmp/sink.jsonl; pkill -f 'mailclient.py sink' || true")
    sink.check_output("nohup python3 /tmp/mailclient.py sink 25 /tmp/sink.jsonl >/dev/null 2>&1 &")
    try:
        time.sleep(1)
        result = client("smtp", ctx["mail_ip"], "sender@origin.example", "fwd@" + ctx["domain"], unique("fwd"))
        assert result["ok"], result
        assert wait_for(lambda: sink.file("/tmp/sink.jsonl").exists, timeout=60)
        envelope = json.loads(sink.file("/tmp/sink.jsonl").content_string.splitlines()[-1])
        assert envelope["rcpt"] == ["someone@" + ctx["external"]]
        sender = envelope["from"]
        assert sender.startswith("SRS0=") and "origin.example" in sender, sender
        assert sender.endswith("@" + ctx["domain"]), sender
    finally:
        sink.run("pkill -f 'mailclient.py sink' || true")


# IMAP (143, 993) and ManageSieve (4190)


@pytest.mark.parametrize("port", ["993", "143"])
@pytest.mark.parametrize("password", [ALICE, ALICE_APP], ids=["main-password", "app-password"])
def test_imap_login(client, ctx, port, password):
    assert client("imap-login", ctx["mail_ip"], port, ctx["alice"], password)["ok"]


def test_imap_rejects_wrong_password(client, ctx):
    assert not client("imap-login", ctx["mail_ip"], "993", ctx["alice"], "wrong-password")["ok"]


def test_imap_143_refuses_login_before_starttls(client, ctx):
    result = client("imap-plain", ctx["mail_ip"], ctx["alice"], ALICE)
    assert "LOGINDISABLED" in result["capabilities"]
    assert not result["login_without_tls"]


def test_managesieve_offers_starttls(client, ctx):
    assert client("sieve", ctx["mail_ip"])["starttls"]


# TLS versions on all mail ports


@pytest.mark.parametrize(
    "port,mode", [(25, "smtp"), (587, "smtp"), (143, "imap"), (993, "implicit")]
)
@pytest.mark.parametrize("version,accepted", [("TLSv1", False), ("TLSv1_1", False), ("TLSv1_2", True), ("TLSv1_3", True)])
def test_tls_versions(client, ctx, port, mode, version, accepted):
    result = client("tls", ctx["mail_ip"], str(port), version, mode)
    assert result["ok"] == accepted, result


# Storage


def test_mail_at_rest_is_encrypted(host, client, ctx):
    subject = unique("crypt")
    client("smtp", ctx["mail_ip"], "someone@origin.example", ctx["alice"], subject)
    assert delivered(client, ctx, ctx["alice"], ALICE, subject)
    maildir = "/var/vmail/%s/alice/Maildir" % ctx["domain"]
    # Only the message files: Dovecot's index cache and the FTS index keep
    # header fields and terms in plaintext by design (disk encryption covers them).
    assert host.run("grep -rl %s %s/cur %s/new", subject, maildir, maildir).stdout == ""
    newest = host.check_output("ls -t %s/cur/* %s/new/* 2>/dev/null | head -1", maildir, maildir)
    assert host.check_output("head -c 7 %s", newest) == "CRYPTED"


def test_full_text_search_finds_new_mail(host, client, ctx):
    word = unique("ftsword")
    client("smtp", ctx["mail_ip"], "someone@origin.example", ctx["alice"], word)
    assert delivered(client, ctx, ctx["alice"], ALICE, word)
    found = host.check_output("doveadm search -u %s mailbox INBOX body %s", ctx["alice"], word)
    assert found.strip(), "doveadm search returned nothing"


def test_vmail_permissions(host):
    assert host.file("/var/vmail").user == "vmail"
    assert host.file("/var/vmail").mode == 0o700
    key = host.file("/etc/dovecot/mail-crypt/ecprivkey.pem")
    assert (key.user, key.group, key.mode) == ("root", "vmail", 0o640)


# Monitoring and intrusion prevention


def test_dovecot_metrics(host):
    metrics = host.check_output("curl -fsS http://127.0.0.1:9900/metrics")
    assert "dovecot_auth_success_total" in metrics


@pytest.mark.parametrize("jail", ["postfix", "dovecot"])
def test_fail2ban_mail_jails(host, jail):
    assert "Journal matches:" in host.check_output("fail2ban-client status %s", jail)

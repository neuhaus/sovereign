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
def ctx(sovtest_vars, ansible_var):
    d = sovtest_vars["sovtest_domain"]
    return {
        "mail_ip": sovtest_vars["sovtest_ips"]["mail"],
        "alice": "alice@" + d,
        "bob": "bob@" + d,
        "domain": d,
        "external": sovtest_vars["sovtest_external_domain"],
        "cert": "/etc/letsencrypt/live/%s/cert.pem" % ansible_var("certbot_domains")[0],
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


@pytest.fixture
def sink(client):
    """SMTP sink on the dns instance, the MX of the external test domain."""
    dns = client.host
    dns.run("pkill -f 'mailclient.py sink' || true; rm -f /tmp/sink.jsonl")
    dns.check_output("nohup python3 /tmp/mailclient.py sink 25 /tmp/sink.jsonl >/dev/null 2>&1 &")
    time.sleep(1)

    def last_message(timeout=60):
        assert wait_for(lambda: dns.file("/tmp/sink.jsonl").exists, timeout=timeout), "nothing arrived"
        return json.loads(dns.file("/tmp/sink.jsonl").content_string.splitlines()[-1])

    yield last_message
    dns.run("pkill -f 'mailclient.py sink' || true")


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


def test_forwarded_mail_has_srs_sender(client, ctx, sink):
    result = client("smtp", ctx["mail_ip"], "sender@origin.example", "fwd@" + ctx["domain"], unique("fwd"))
    assert result["ok"], result
    envelope = sink()
    assert envelope["rcpt"] == ["someone@" + ctx["external"]]
    sender = envelope["from"]
    assert sender.startswith("SRS0=") and "origin.example" in sender, sender
    assert sender.endswith("@" + ctx["domain"]), sender


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


# Spam filter (rspamd role), Phase 2.4


@pytest.mark.parametrize("service", ["rspamd", "redis-server"])
def test_rspamd_services_running(host, service):
    assert host.service(service).is_running
    assert host.service(service).is_enabled


def test_rspamd_configtest(host):
    host.check_output("rspamadm configtest")


def test_rspamd_controller_password_is_not_debians_default(host):
    dump = host.check_output("rspamadm configdump worker")
    assert 'password = "q1"' not in dump
    assert 'password = "$2$' in dump


def test_rspamd_controller_and_redis_local_only(host):
    listening = host.check_output("ss --listening --numeric --tcp")
    for port in (":11334", ":11332", ":6379"):
        sockets = [line.split()[3] for line in listening.splitlines()[1:] if line.split()[3].endswith(port)]
        assert sockets, port
        assert all(s.startswith(("127.", "[::1]")) for s in sockets), sockets


def test_dkim_key_permissions(host, ctx):
    key = host.file("/var/lib/rspamd/dkim/%s.sovereign.key" % ctx["domain"])
    assert (key.user, key.group, key.mode) == ("root", "_rspamd", 0o640)
    assert "v=DKIM1" in host.file("/var/lib/rspamd/dkim/%s.sovereign.txt" % ctx["domain"]).content_string


def test_inbound_mail_is_scanned(client, ctx):
    subject = unique("scan")
    client("smtp", ctx["mail_ip"], "someone@origin.example", ctx["alice"], subject)
    assert delivered(client, ctx, ctx["alice"], ALICE, subject)
    names = {name for name, _ in client("imap-headers", ctx["mail_ip"], ctx["alice"], ALICE, subject)["headers"]}
    assert {"Authentication-Results", "X-Spamd-Result"} <= names, names


@pytest.mark.parametrize("kind", ["exe", "zip-exe"])
def test_dangerous_attachments_rejected(client, ctx, kind):
    result = client("smtp", ctx["mail_ip"], "someone@origin.example", ctx["alice"], unique("att"), kind)
    assert not result["ok"] and "554" in result["error"], result


def test_outbound_mail_is_dkim_signed(host, client, ctx, sink):
    subject = unique("dkim")
    sent = client("submit", ctx["mail_ip"], ctx["alice"], ALICE, ctx["alice"], "someone@" + ctx["external"], subject)
    assert sent["ok"], sent
    message = sink()
    raw = base64.b64decode(message["data"]).decode(errors="replace")
    assert "\nDKIM-Signature:" in "\n" + raw
    assert "\nARC-Seal:" in "\n" + raw
    # No internal scan details on outgoing mail.
    assert "\nX-Spamd-Result:" not in "\n" + raw
    txt = host.check_output("cat /var/lib/rspamd/dkim/%s.sovereign.txt" % ctx["domain"])
    record = "".join(part for part in txt.split('"')[1::2])
    assert client("dkim-verify", message["data"], record)["ok"]


def test_outbound_rate_limit_defers(client, ctx):
    # Molecule sets a burst of 10 messages per user; bob sends nothing else.
    results = [
        client("submit", ctx["mail_ip"], ctx["bob"], BOB, ctx["bob"], ctx["alice"], unique("rl"))
        for _ in range(13)
    ]
    deferred = [r for r in results if not r["ok"]]
    assert deferred, results
    assert all("451" in r["error"] and "Ratelimit" in r["error"] for r in deferred), deferred


def test_moving_to_junk_trains_spam(host, client, ctx):
    subject = unique("junk")
    client("smtp", ctx["mail_ip"], "promo@origin.example", ctx["alice"], subject, "long")
    assert delivered(client, ctx, ctx["alice"], ALICE, subject)
    assert client("imap-move", ctx["mail_ip"], ctx["alice"], ALICE, subject, "Junk")["result"] == "OK"
    # Rspamd logs every learned message with its Message-ID.
    assert wait_for(
        lambda: host.run(
            "grep -q 'learned message as spam: %s@sovtest.example' /var/log/rspamd/rspamd.log", subject
        ).rc == 0
    )

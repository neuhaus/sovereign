"""Full disaster recovery onto an empty instance, Phase 4."""

import pathlib
import tempfile
import uuid

import pytest

from conftest import mail_client, run_playbook

testinfra_hosts = ["mail"]

TESTS = pathlib.Path(__file__).parent
SITE = TESTS.parents[2] / "site.yml"
DB = "/var/lib/sovereign/maildb/mail.sqlite"
BOB = "sovtest-bob-pass"


def key_fingerprint(instance, path):
    return instance.check_output("sha256sum %s", path).split()[0]


@pytest.fixture(scope="module")
def recovered(host, peer, sovtest_vars):
    """Back up the server with a marked message, then recover onto the instance."""
    domain = sovtest_vars["sovtest_domain"]
    bob = "bob@" + domain
    subject = "recovery" + uuid.uuid4().hex[:10]
    body = "recovery-marker-" + uuid.uuid4().hex
    message = "From: a@example.org\nTo: %s\nSubject: %s\n\n%s\n" % (bob, subject, body)
    host.check_output("printf %s | doveadm save -u %s -m INBOX", message, bob)
    assert host.run("systemctl start sovereign-backup.service").rc == 0

    with tempfile.TemporaryDirectory() as workdir:
        # Makes the instance a mail server for the runs of the real playbook.
        extra_inventory = pathlib.Path(workdir) / "recovery.ini"
        extra_inventory.write_text("[mailservers]\nrecovery\n")
        run_playbook(host, TESTS / "disaster_recovery.yml", {"sovtest_recovery_dir": workdir}, extra_inventory=extra_inventory)
        site_args = {"extra_inventory": extra_inventory, "limit": "recovery"}
        run_playbook(host, SITE, {}, **site_args)
        run_playbook(host, TESTS / "disaster_recovery_finish.yml", {}, **site_args)
        # A second run of the playbook must not undo or change anything.
        changed_again = run_playbook(host, SITE, {}, **site_args)

    return {
        "host": peer("recovery"),
        "ip": sovtest_vars["sovtest_ips"]["recovery"],
        "bob": bob,
        "domain": domain,
        "subject": subject,
        "body": body,
        "changed_again": changed_again,
    }


def test_no_failed_units(recovered):
    assert recovered["host"].run("systemctl --failed --no-legend --plain").stdout.strip() == ""


def test_second_run_changes_nothing(recovered):
    assert recovered["changed_again"] == 0


@pytest.mark.parametrize(
    "path",
    ["/etc/dovecot/mail-crypt/ecprivkey.pem", "/etc/postsrsd.secret"],
)
def test_keys_are_the_old_ones(host, recovered, path):
    assert key_fingerprint(recovered["host"], path) == key_fingerprint(host, path)


def test_dkim_key_is_the_old_one(host, recovered):
    listing = "ls /var/lib/rspamd/dkim/*.key | head -1"
    path = host.check_output(listing)
    assert key_fingerprint(recovered["host"], path) == key_fingerprint(host, path)


def test_certificate_key_is_the_old_one(host, recovered):
    # The DANE TLSA records depend on it.
    path = "/etc/letsencrypt/live/mail.%s/privkey.pem" % recovered["domain"]
    assert key_fingerprint(recovered["host"], path) == key_fingerprint(host, path)


def test_passwords_are_the_restored_ones(host, recovered):
    # From the backup, not from the inventory: users may have changed them.
    query = "SELECT localpart || password FROM mailboxes ORDER BY 1"
    assert recovered["host"].check_output("sqlite3 %s %s", DB, query) == host.check_output("sqlite3 %s %s", DB, query)


def test_mail_is_readable_through_dovecot(recovered):
    instance = recovered["host"]
    text = instance.check_output("doveadm fetch -u %s text mailbox INBOX header subject %s", recovered["bob"], recovered["subject"])
    assert recovered["body"] in text


def test_mail_stays_encrypted_on_disk(recovered):
    mailbox = "/var/vmail/%s/bob/Maildir" % recovered["domain"]
    assert recovered["host"].run("grep -rl %s %s/cur %s/new", recovered["body"], mailbox, mailbox).rc != 0


def test_imap_login_from_another_host(peer, recovered):
    client = mail_client(peer("dns"))
    assert client("imap-count", recovered["ip"], recovered["bob"], BOB, recovered["subject"])["count"] == 1


def test_webmail_works_with_the_restored_database(peer, recovered):
    client = mail_client(peer("dns"))
    assert client("web-login", recovered["ip"], "mail." + recovered["domain"], recovered["bob"], BOB)["ok"]


def test_shared_calendar_is_back(recovered):
    props = "/var/lib/radicale/collections/collection-root/shared/family/.Radicale.props"
    assert recovered["host"].file(props).user == "radicale"

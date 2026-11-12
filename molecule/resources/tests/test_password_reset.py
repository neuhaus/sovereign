"""Mailbox lifecycle and password reset through the inventory, Phase 3.

Runs the real maildb and dovecot roles with an extra mailbox, dave, who is gone
again afterwards.
"""

import json
import pathlib
import time

import pytest

from conftest import mail_client, run_playbook

testinfra_hosts = ["mail"]

DB = "/var/lib/sovereign/maildb/mail.sqlite"
TESTS = pathlib.Path(__file__).parent


@pytest.fixture(scope="module")
def ctx(sovtest_vars):
    d = sovtest_vars["sovtest_domain"]
    return {"ip": sovtest_vars["sovtest_ips"]["mail"], "web": "mail." + d, "dave": "dave@" + d}


@pytest.fixture(scope="module")
def client(peer):
    return mail_client(peer("dns"))


@pytest.fixture(scope="module")
def apply_roles(host):
    """Run the roles with dave added (no hash: without him); returns the changed count."""

    def run(dave_hash=None, app_passwords=None, extra_aliases=None, enabled=True, quota_mb=0):
        variables = {
            "maildb_mailboxes": "{{ mail_mailboxes }}",
            "sovtest_extra_aliases": extra_aliases or [],
            "maildb_aliases": "{{ mail_aliases + sovtest_extra_aliases }}",
        }
        if dave_hash:
            dave = {
                "address": "dave@{{ sovtest_domain }}",
                "password": dave_hash,
                "app_passwords": app_passwords or [],
                "enabled": enabled,
                "quota_mb": quota_mb,
            }
            variables["sovtest_dave"] = [dave]
            variables["maildb_mailboxes"] = "{{ mail_mailboxes + sovtest_dave }}"
        return run_playbook(host, TESTS / "maildb_run.yml", variables)

    return run


def new_hash(host, password):
    return host.check_output("doveadm pw -s ARGON2ID -p %s", password)


def imap_ok(client, ctx, password):
    return client("imap-login", ctx["ip"], "993", ctx["dave"], password)["ok"]


def session_ends(host, peer, ctx, password, change):
    """Hold an IMAP session as dave, run change(), report whether it was ended."""
    dns = peer("dns")
    dns.run("rm -f /tmp/imap-hold.json")
    dns.check_output(
        "nohup python3 /tmp/mailclient.py imap-hold %s %s %s 120 > /tmp/imap-hold.json 2>&1 &", ctx["ip"], ctx["dave"], password
    )
    assert wait_for(lambda: ctx["dave"] in host.run("doveadm who").stdout)
    change()
    assert wait_for(lambda: dns.run("test -s /tmp/imap-hold.json").rc == 0, seconds=150)
    return json.loads(dns.file("/tmp/imap-hold.json").content_string)["disconnected"]


def wait_for(check, seconds=30):
    for _ in range(seconds):
        if check():
            return True
        time.sleep(1)
    return False


def test_mailbox_lifecycle_and_reset(host, peer, client, ctx, apply_roles):
    initial, by_user, first_reset, second_reset = (
        "sovtest-dave-initial",
        "sovtest-dave-by-user",
        "sovtest-dave-first-reset",
        "sovtest-dave-second-reset",
    )
    hash_initial, hash_first, hash_second = (new_hash(host, p) for p in (initial, first_reset, second_reset))
    try:
        # A new mailbox gets its initial password.
        apply_roles(hash_initial)
        assert imap_ok(client, ctx, initial)

        # The user changes it; another run with the same inventory changes nothing.
        changed = client("web-password", ctx["ip"], ctx["web"], ctx["dave"], initial, by_user)
        assert changed["ok"], changed
        assert apply_roles(hash_initial) == 0
        assert imap_ok(client, ctx, by_user)
        assert not imap_ok(client, ctx, initial)

        # A new hash resets it, also without any open session to end; once.
        assert apply_roles(hash_first) > 0
        assert imap_ok(client, ctx, first_reset)
        assert not imap_ok(client, ctx, by_user)
        assert apply_roles(hash_first) == 0
        assert host.check_output("sqlite3 %s 'PRAGMA journal_mode'", DB) == "delete"

        # The user's next change survives too.
        changed = client("web-password", ctx["ip"], ctx["web"], ctx["dave"], first_reset, by_user)
        assert changed["ok"], changed
        assert apply_roles(hash_first) == 0
        assert imap_ok(client, ctx, by_user)

        # A reset ends open sessions.
        assert session_ends(host, peer, ctx, by_user, lambda: apply_roles(hash_second))
        assert imap_ok(client, ctx, second_reset)

        # Disabling the mailbox ends them too, and blocks logins.
        assert session_ends(host, peer, ctx, second_reset, lambda: apply_roles(hash_second, enabled=False))
        assert not imap_ok(client, ctx, second_reset)
        apply_roles(hash_second)
        assert imap_ok(client, ctx, second_reset)

        # So does removing it.
        assert session_ends(host, peer, ctx, second_reset, apply_roles)
    finally:
        apply_roles()
    # A removed mailbox can no longer log in.
    assert not imap_ok(client, ctx, second_reset)
    assert host.check_output("sqlite3 %s %s", DB, "SELECT count(*) FROM mailboxes WHERE localpart = 'dave'") == "0"
    assert apply_roles() == 0


def test_migration_from_schema_1_keeps_passwords(host, ctx, apply_roles):
    # Downgrade to schema version 1, as a database deployed before this column.
    live = "SELECT localpart || password FROM mailboxes ORDER BY 1"
    before = host.check_output("sqlite3 %s %s", DB, live)
    host.check_output(
        "sqlite3 -bail %s %s", DB, "ALTER TABLE mailboxes DROP COLUMN inventory_password; PRAGMA user_version = 1;"
    )
    apply_roles()
    assert host.check_output("sqlite3 %s 'PRAGMA user_version'", DB) == "2"
    # Dovecot was restarted: its old connection would fail the first lookup.
    assert host.run("doveadm user %s", ctx["dave"].replace("dave@", "alice@")).rc == 0
    assert host.check_output("sqlite3 %s %s", DB, live) == before
    assert host.check_output("sqlite3 %s %s", DB, "SELECT count(*) FROM mailboxes WHERE inventory_password = ''") == "0"
    assert apply_roles() == 0


def alias_targets(host, source):
    result = host.run("postmap -q %s proxy:sqlite:/etc/postfix/sqlite/virtual-aliases.cf", source)
    return result.stdout.strip()


def test_app_passwords_follow_the_inventory(host, peer, client, ctx, apply_roles):
    main = "sovtest-dave-main"
    main_hash = new_hash(host, main)
    first, second = "DavePhn1-sovtest-first", "DavePhn1-sovtest-second"
    try:
        # Added.
        apply_roles(main_hash, [{"name": "phone", "id": "DavePhn1", "password": new_hash(host, first)}])
        assert imap_ok(client, ctx, first)

        # Changed: only the new one works, the main password is untouched.
        apply_roles(main_hash, [{"name": "phone", "id": "DavePhn1", "password": new_hash(host, second)}])
        assert imap_ok(client, ctx, second)
        assert not imap_ok(client, ctx, first)
        assert imap_ok(client, ctx, main)

        # Removed. Sessions can't be matched to the password they used, so all of
        # the mailbox's sessions end, also one opened with the main password.
        assert session_ends(host, peer, ctx, main, lambda: apply_roles(main_hash))
        assert not imap_ok(client, ctx, second)
        assert imap_ok(client, ctx, main)
    finally:
        apply_roles()


def test_aliases_follow_the_inventory(host, sovtest_vars, apply_roles):
    domain = sovtest_vars["sovtest_domain"]
    source = "sales@" + domain
    try:
        # Added.
        apply_roles(extra_aliases=[{"source": source, "destinations": ["alice@" + domain]}])
        assert alias_targets(host, source) == "alice@" + domain

        # Changed.
        apply_roles(extra_aliases=[{"source": source, "destinations": ["bob@" + domain]}])
        assert alias_targets(host, source) == "bob@" + domain
    finally:
        # Removed.
        apply_roles()
    assert alias_targets(host, source) == ""


def test_manual_changes_are_reverted(host, sovtest_vars, apply_roles):
    domain = sovtest_vars["sovtest_domain"]
    manual = (
        "INSERT INTO aliases (source, destination) VALUES ('manual@%s', 'alice@%s');"
        "DELETE FROM aliases WHERE source = 'postmaster@%s';"
        "UPDATE mailboxes SET enabled = 0 WHERE localpart = 'bob';"
        "DELETE FROM app_passwords WHERE id = 'AlicPhn1';"
    ) % (domain, domain, domain)
    host.check_output("sqlite3 -bail %s %s", DB, manual)
    assert apply_roles() > 0
    assert alias_targets(host, "manual@" + domain) == ""
    assert alias_targets(host, "postmaster@" + domain) == "alice@" + domain
    assert host.check_output("sqlite3 %s %s", DB, "SELECT enabled FROM mailboxes WHERE localpart = 'bob'") == "1"
    assert host.check_output("sqlite3 %s %s", DB, "SELECT count(*) FROM app_passwords WHERE id = 'AlicPhn1'") == "1"
    assert apply_roles() == 0


def storage_limit(host, user):
    rows = [line.split("\t") for line in host.check_output("doveadm -f tab quota get -u %s", user).splitlines()[1:]]
    storage = [row for row in rows if row[1] == "STORAGE"]
    assert storage, rows
    return storage[0][3]


def test_quota_is_enforced(host, ctx, apply_roles):
    dave = ctx["dave"]
    try:
        apply_roles(new_hash(host, "sovtest-dave-quota"), quota_mb=1)
        # Columns: quota name, type, value, limit (KiB for STORAGE), percent.
        assert storage_limit(host, dave) == "1024"
        small = "From: a@example.org\nTo: %s\nSubject: small\n\nfits\n" % dave
        assert host.run("printf %s | doveadm save -u %s -m INBOX", small, dave).rc == 0
        # About 2 MB: over the 1 MB limit.
        big = host.run(
            "{ printf 'From: a@example.org\\nTo: %s\\nSubject: big\\n\\n'; head -c 1500000 /dev/urandom | base64; }"
            " | doveadm save -u %s -m INBOX", dave, dave
        )
        assert big.rc != 0
        assert "quota" in (big.stdout + big.stderr).lower()
        # Without a limit again, the same message fits.
        apply_roles(new_hash(host, "sovtest-dave-quota"))
        assert storage_limit(host, dave) in ("-", "")
        assert host.run(
            "{ printf 'From: a@example.org\\nTo: %s\\nSubject: big\\n\\n'; head -c 1500000 /dev/urandom | base64; }"
            " | doveadm save -u %s -m INBOX", dave, dave
        ).rc == 0
    finally:
        apply_roles()
        host.run("rm -rf /var/vmail/%s/dave", dave.split("@")[1])

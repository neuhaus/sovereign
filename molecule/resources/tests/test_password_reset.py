"""Mailbox lifecycle and password reset through the inventory, Phase 3.

Runs the real maildb and dovecot roles with an extra mailbox, dave, who is gone
again afterwards.
"""

import json
import os
import pathlib
import subprocess
import tempfile
import time

import pytest

from conftest import mail_client

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
    """Run the roles with dave's hash added (None: without dave); returns the changed count."""

    def run(dave_hash=None):
        extra = {"maildb_mailboxes": "{{ mail_mailboxes }}"}
        if dave_hash:
            extra = {
                "sovtest_dave": [{"address": "dave@{{ sovtest_domain }}", "password": dave_hash}],
                "maildb_mailboxes": "{{ mail_mailboxes + sovtest_dave }}",
            }
        with tempfile.NamedTemporaryFile("w", suffix=".json") as variables:
            json.dump(extra, variables)
            variables.flush()
            result = subprocess.run(
                ["ansible-playbook", "-i", host.backend.ansible_inventory, "-e", "@" + variables.name, str(TESTS / "maildb_run.yml")],
                env={**os.environ, "ANSIBLE_ROLES_PATH": str(TESTS.parents[2] / "roles")},
                capture_output=True,
                text=True,
                check=False,
            )
        assert result.returncode == 0, result.stdout[-3000:] + result.stderr[-2000:]
        recap = [line for line in result.stdout.splitlines() if line.startswith("mail ")]
        assert recap, result.stdout[-2000:]
        return int(recap[-1].split("changed=")[1].split()[0])

    return run


def new_hash(host, password):
    return host.check_output("doveadm pw -s ARGON2ID -p %s", password)


def imap_ok(client, ctx, password):
    return client("imap-login", ctx["ip"], "993", ctx["dave"], password)["ok"]


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
        dns = peer("dns")
        dns.check_output(
            "nohup python3 /tmp/mailclient.py imap-hold %s %s %s 120 > /tmp/imap-hold.json 2>&1 &", ctx["ip"], ctx["dave"], by_user
        )
        assert wait_for(lambda: ctx["dave"] in host.run("doveadm who").stdout)
        apply_roles(hash_second)
        assert wait_for(lambda: dns.run("test -s /tmp/imap-hold.json").rc == 0)
        assert json.loads(dns.file("/tmp/imap-hold.json").content_string)["disconnected"]
        assert imap_ok(client, ctx, second_reset)
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

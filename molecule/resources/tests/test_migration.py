"""Mail copy from an old server, as in docs/MIGRATION.md.

The mail server plays both sides: the "old server" is the mailbox oldbox, read
over IMAPS through the server's public name, and the new mailbox is newbox. Both
exist only during this test.
"""

import pathlib
import uuid

import pytest

from conftest import run_playbook

testinfra_hosts = ["mail"]

TESTS = pathlib.Path(__file__).parent
CONF = "/root/migration.conf"
OLD_PASSWORD = "sovtest-oldbox-pass"


@pytest.fixture(scope="module")
def boxes(host, sovtest_vars):
    domain = sovtest_vars["sovtest_domain"]
    old, new = "oldbox@" + domain, "newbox@" + domain
    hashes = [host.check_output("doveadm pw -s ARGON2ID -p %s", p) for p in (OLD_PASSWORD, "sovtest-newbox-pass")]
    extra = [{"address": a, "password": h, "app_passwords": []} for a, h in zip((old, new), hashes)]
    base = {"maildb_aliases": "{{ mail_aliases }}"}
    run_playbook(
        host,
        TESTS / "maildb_run.yml",
        {**base, "sovtest_migration": extra, "maildb_mailboxes": "{{ mail_mailboxes + sovtest_migration }}"},
    )
    # The connection settings, written as the guide says.
    host.check_output("install -m 0600 /dev/null %s", CONF)
    # Dovecot 2.4: dovecot_config_version must be the file's first setting.
    versions = host.check_output("grep -m2 '^dovecot_[a-z]*_version' /etc/dovecot/dovecot.conf")
    settings = (
        f"{versions}\n!include /etc/dovecot/dovecot.conf\n\n"
        f"imapc_host = mail.{domain}\nimapc_port = 993\nimapc_ssl = imaps\n"
        f"imapc_user = {old}\nimapc_password = {OLD_PASSWORD}\n"
    )
    host.check_output("printf %%s %s > %s", settings, CONF)
    try:
        yield old, new
    finally:
        host.run("rm -f %s", CONF)
        for box in (old, new):
            host.run("doveadm kick %s", box)
        run_playbook(host, TESTS / "maildb_run.yml", {**base, "maildb_mailboxes": "{{ mail_mailboxes }}"})
        for box in (old, new):
            host.run("rm -rf /var/vmail/%s/%s", domain, box.split("@")[0])


def save(host, user, mailbox, subject, body):
    message = f"From: a@example.org\nTo: {user}\nSubject: {subject}\nMessage-ID: <{uuid.uuid4().hex}@test>\n\n{body}\n"
    host.check_output("printf %%s %s | doveadm save -u %s -m %s", message, user, mailbox)


def fetch(host, user, mailbox, subject, field):
    return host.check_output("doveadm fetch -u %s %s mailbox %s header subject %s", user, field, mailbox, subject)


def migrate(host, new, command):
    # command holds several words ("sync -1 -R"): not quoted as one argument.
    result = host.run(f"doveadm -c %s {command} -u %s imapc:", CONF, new)
    assert result.rc == 0, result.stdout + result.stderr
    # With -s, dsync prints the new sync state as the last line.
    return result.stdout.strip().splitlines()[-1] if "-s" in command.split() else None


def test_copy_then_final_sync(host, boxes):
    old, new = boxes
    tag = uuid.uuid4().hex[:8]
    first, archived, later, arrived = (f"{name}-{tag}" for name in ("first", "archived", "later", "arrived"))

    # The old mailbox: mail in INBOX with flags, and a subscribed folder.
    save(host, old, "INBOX", first, "body of the first message")
    host.check_output("doveadm flags add -u %s '\\Seen \\Flagged' mailbox INBOX header subject %s", old, first)
    host.check_output("doveadm mailbox create -s -u %s Projects", old)
    save(host, old, "Projects", archived, "body in a folder")

    state = migrate(host, new, "backup -R -s ''")
    assert state
    assert "body of the first message" in fetch(host, new, "INBOX", first, "text")
    flags = fetch(host, new, "INBOX", first, "flags")
    assert "\\Seen" in flags and "\\Flagged" in flags
    assert "body in a folder" in fetch(host, new, "Projects", archived, "text")
    assert "Projects" in host.check_output("doveadm mailbox list -s -u %s", new).split()

    # After the switch: the old server still gets one message, the new server
    # already gets one of its own. Both get the same UID, since backup copied
    # the numbering; the final sync must keep both (without the state, dsync
    # silently skips the old server's message).
    save(host, old, "INBOX", later, "late on the old server")
    save(host, new, "INBOX", arrived, "already on the new server")
    migrate(host, new, f"sync -1 -R -s {state}")
    assert "late on the old server" in fetch(host, new, "INBOX", later, "text")
    assert "already on the new server" in fetch(host, new, "INBOX", arrived, "text")
    # One-way: the old mailbox is not changed.
    assert fetch(host, old, "INBOX", arrived, "text") == ""

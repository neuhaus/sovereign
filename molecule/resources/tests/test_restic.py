"""Backups (restic role) into a repository on the mail instance, Phase 2.7."""

import uuid

import pytest

testinfra_hosts = ["mail"]

ENV = "set -a; . /etc/restic/env; set +a; "
MAILDB = "/var/lib/sovereign/maildb/mail.sqlite"


def restic(host, command):
    return host.check_output("bash -c %s", ENV + "restic " + command)


def fetch(host, user, subject, field="text"):
    return host.run("doveadm fetch -u %s %s mailbox INBOX header subject %s", user, field, subject).stdout


@pytest.fixture(scope="module")
def carol(sovtest_vars):
    return "carol@" + sovtest_vars["sovtest_domain"]


@pytest.fixture(scope="module")
def backup(host):
    """Run the backup job as the timer would; returns the files in the snapshot."""
    result = host.run("systemctl start sovereign-backup.service")
    assert result.rc == 0, host.check_output("journalctl -n 40 -u sovereign-backup.service --no-pager")
    return restic(host, "ls latest").splitlines()


def test_settings_only_for_root(host):
    for path in ("/etc/restic/password", "/etc/restic/env"):
        settings = host.file(path)
        assert (settings.user, settings.group, settings.mode) == ("root", "root", 0o600)
    staging = host.file("/var/backups/sovereign")
    assert (staging.user, staging.mode) == ("root", 0o700)


@pytest.mark.parametrize("timer", ["sovereign-backup.timer", "sovereign-backup-prune.timer"])
def test_timers_enabled(host, timer):
    assert host.service(timer).is_enabled
    assert host.service(timer).is_running


@pytest.mark.parametrize(
    "path",
    [
        "/var/backups/sovereign/mail.sqlite",
        "/var/backups/sovereign/roundcube.sqlite",
        "/etc/dovecot/mail-crypt/ecprivkey.pem",
        "/var/lib/radicale/collections/collection-root/shared/family/.Radicale.props",
        "/etc/postsrsd.secret",
    ],
)
def test_snapshot_contains(backup, path):
    assert path in backup


def test_snapshot_contains_keys_and_mail(backup, sovtest_vars):
    domain = sovtest_vars["sovtest_domain"]
    assert [p for p in backup if p.startswith("/var/lib/rspamd/dkim/%s." % domain) and p.endswith(".key")]
    assert [p for p in backup if p.startswith("/etc/letsencrypt/archive/") and "privkey" in p]
    assert [p for p in backup if p.startswith("/var/vmail/%s/alice/Maildir/" % domain)]


def test_snapshot_without_search_index(backup):
    assert not [p for p in backup if "fts-flatcurve" in p]


def test_repository_is_encrypted(host, backup):
    # Neither config nor data reveal content without the password.
    assert host.run("grep -rl ecprivkey /var/backups/restic-test").rc != 0
    assert host.run("bash -c 'RESTIC_REPOSITORY=/var/backups/restic-test RESTIC_PASSWORD=wrong restic cat config'").rc != 0


def test_success_metric_exported(host, backup):
    metrics = host.check_output("curl -fsS http://127.0.0.1:9100/metrics")
    assert "sovereign_backup_last_success_timestamp_seconds " in metrics


def test_restored_mail_database_is_intact(host, backup):
    host.run("rm -rf /tmp/restic-restore")
    restic(host, "restore latest --target /tmp/restic-restore --include /var/backups/sovereign/mail.sqlite")
    restored = "/tmp/restic-restore/var/backups/sovereign/mail.sqlite"
    try:
        assert host.check_output("sqlite3 %s 'PRAGMA integrity_check'", restored) == "ok"
        count = "SELECT count(*) FROM mailboxes"
        assert host.check_output("sqlite3 %s %s", restored, count) == host.check_output("sqlite3 %s %s", MAILDB, count)
    finally:
        host.run("rm -rf /tmp/restic-restore")


def test_restore_mailbox_and_read_it_through_dovecot(host, carol):
    subject = "backup" + uuid.uuid4().hex[:10]
    body = "restore-marker-" + uuid.uuid4().hex
    message = "From: a@example.org\nTo: %s\nSubject: %s\n\n%s\n" % (carol, subject, body)
    host.check_output("printf %s | doveadm save -u %s -m INBOX", message, carol)
    assert body in fetch(host, carol, subject)
    localpart, domain = carol.split("@")
    mailbox = "/var/vmail/%s/%s" % (domain, localpart)
    # mail_crypt: the message file on disk is not readable.
    assert host.run("grep -rl %s %s/Maildir/cur %s/Maildir/new", body, mailbox, mailbox).rc != 0

    assert host.run("systemctl start sovereign-backup.service").rc == 0

    # Lose the mailbox.
    host.run("doveadm kick %s", carol)
    host.check_output("rm -rf %s", mailbox)
    assert body not in fetch(host, carol, subject)
    host.run("doveadm kick %s", carol)
    host.check_output("rm -rf %s", mailbox)

    # Restored in place, Dovecot decrypts it with the same key.
    restic(host, "restore latest --target / --include %s" % mailbox)
    assert host.file(mailbox).user == "vmail"
    assert body in fetch(host, carol, subject)


def test_prune_keeps_recent_snapshots(host):
    result = host.run("systemctl start sovereign-backup-prune.service")
    assert result.rc == 0, host.check_output("journalctl -n 40 -u sovereign-backup-prune.service --no-pager")
    assert "sovereign" in restic(host, "snapshots --latest 1")
    assert host.check_output("bash -c %s", ENV + "restic check >/dev/null && echo ok") == "ok"

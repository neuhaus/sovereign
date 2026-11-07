"""Backups a compromised server cannot delete (restic role), Phase 2.7.

An append-only rest-server runs on dns. The mail instance has all its credentials
here, which is what an attacker with root on it would have too.
"""

import pathlib

import pytest

from conftest import run_playbook

testinfra_hosts = ["mail"]

TESTS = pathlib.Path(__file__).parent
ENV = "set -a; . /etc/restic/env; set +a; "


def restic(host, command):
    return host.run("bash -c %s", ENV + "restic " + command)


@pytest.fixture(scope="module")
def repository(sovtest_vars):
    return "rest:http://%s:8000/appendonly/" % sovtest_vars["sovtest_ips"]["dns"]


@pytest.fixture(scope="module")
def append_only(host, repository):
    """Point the server at the append-only repository, without pruning; back up once."""
    settings = {"restic_repository": repository, "restic_prune_enabled": False}
    run_playbook(host, TESTS / "restic_run.yml", settings)
    try:
        result = host.run("systemctl start sovereign-backup.service")
        assert result.rc == 0, host.check_output("journalctl -n 40 -u sovereign-backup.service --no-pager")
        yield
    finally:
        run_playbook(host, TESTS / "restic_run.yml", {})


def snapshots(host):
    result = restic(host, "snapshots --json")
    assert result.rc == 0, result.stderr
    return result.stdout


def test_backup_reaches_the_repository(host, append_only):
    assert '"tags":["sovereign"]' in snapshots(host).replace(" ", "")


def test_prune_timer_is_removed(host, append_only):
    assert not host.file("/etc/systemd/system/sovereign-backup-prune.timer").exists
    assert host.service("sovereign-backup.timer").is_enabled


def test_second_backup_works(host, append_only):
    # Needs creating and removing locks, which append-only mode must allow.
    assert host.run("systemctl start sovereign-backup.service").rc == 0


def test_root_on_the_mail_server_cannot_delete_backups(host, append_only, repository):
    before = snapshots(host)
    assert restic(host, "forget --prune --keep-last 1").rc != 0
    assert snapshots(host) == before

    # Directly at the server's API as well, without restic.
    base = repository[len("rest:"):]
    listing = host.check_output("curl -fsS -H 'Accept: application/vnd.x.restic.rest.v2' %ssnapshots/", base)
    assert '"name"' in listing
    name = listing.split('"name":"')[1].split('"')[0]
    status = host.check_output("curl -s -o /dev/null -w '%%{http_code}' -X DELETE %ssnapshots/%s", base, name)
    assert status == "403"
    assert snapshots(host) == before

    # And it is still readable and intact.
    assert restic(host, "check").rc == 0

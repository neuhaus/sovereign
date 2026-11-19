"""Integrity check (integrity role): package files, unowned files in /usr, AIDE."""

import re
import time
import uuid

import pytest

testinfra_hosts = ["mail"]

CHECK = "/usr/local/sbin/sovereign-integrity-check"


def findings(host):
    out = host.check_output("%s; cat /var/lib/prometheus/node-exporter/sovereign_integrity.prom", CHECK)
    return {m.group(1): int(m.group(2)) for m in re.finditer(r'check="(\w+)"\} (\d+)', out)}


def mails(host, sovtest_vars, word):
    alice = "alice@" + sovtest_vars["sovtest_domain"]
    return host.run("doveadm search -u %s mailbox INBOX body %s", alice, word).stdout.splitlines()


def test_debians_daily_aide_job_is_off(host):
    # It mails every day, also when nothing changed; ours mails new findings.
    assert not host.service("dailyaidecheck.timer").is_enabled
    assert host.service("sovereign-integrity-check.timer").is_enabled


def test_aide_scope_leaves_package_files_out(host):
    # A full scan covers about 57,000 entries on the test VM; package files
    # are left to dpkg, data that changes all the time is left out.
    out = host.run("aide --check --config /etc/aide/aide.conf").stdout
    total = int(re.search(r"Total number of entries:\s+(\d+)", out).group(1))
    assert total < 15000, total
    assert "/usr/bin/" not in out and "/var/vmail" not in out


def test_planted_files_are_found_and_mailed_once(host, sovtest_vars):
    # A new name each run: a reused VM still has the mails of earlier runs.
    tag = uuid.uuid4().hex[:8]
    planted = ["/usr/local/sbin/sovtest-planted-%s" % tag, "/usr/lib/sovtest-planted-%s.so" % tag]
    before = findings(host)
    try:
        host.check_output("for f in %s %s; do echo planted > $f; done", *planted)
        after = findings(host)
        assert after["aide"] > before["aide"], (before, after)
        assert after["unowned_in_usr"] == before["unowned_in_usr"] + 1, (before, after)
        for _ in range(30):
            if mails(host, sovtest_vars, "sovtest-planted-%s.so" % tag):
                break
            time.sleep(2)
        assert len(mails(host, sovtest_vars, "sovtest-planted-%s.so" % tag)) == 1
        findings(host)  # the same findings again: no second mail
        time.sleep(5)
        assert len(mails(host, sovtest_vars, "sovtest-planted-%s.so" % tag)) == 1
    finally:
        host.run("rm -f %s %s", *planted)
    assert findings(host)["unowned_in_usr"] == before["unowned_in_usr"]


def test_changed_package_file_is_found(host):
    # Any file with an md5sum in its package will do; the content goes back.
    path = "/usr/share/doc/aide/copyright"
    before = findings(host)["package_files"]
    host.check_output("cp -p %s /root/sovtest-copyright", path)
    try:
        host.check_output("echo tampered >> %s", path)
        assert findings(host)["package_files"] == before + 1
        assert path in host.check_output(CHECK + " >/dev/null; dpkg --verify aide-common aide")
    finally:
        host.run("cp -p /root/sovtest-copyright %s && rm /root/sovtest-copyright", path)
    assert findings(host)["package_files"] == before


def test_no_unexpected_files_in_usr(host):
    # After a converge, every file in /usr belongs to a package or is on the
    # role's list of expected ones: otherwise the daily mail would be noise.
    out = host.check_output("%s", CHECK)
    assert re.search(r"unowned in /usr: 0\b", out), out

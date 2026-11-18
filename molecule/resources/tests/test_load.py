"""Memory under concurrent load (Phase 5.5, step 4).

IMAP logins, webmail logins (PHP), submissions (Rspamd), full-text indexing
and a backup at the same time, with MemAvailable sampled four times a second
for its minimum and systemd's MemoryPeak per service. Only in a VM: in a
container /proc/meminfo does not describe the instance's own memory.

The figures go to /var/tmp/sovtest-load-report.txt on the mail instance.
"""

import time

import pytest

from conftest import mail_client

testinfra_hosts = ["mail"]

ALICE = "sovtest-alice-pass"
BOB = "sovtest-bob-pass"
MESSAGES = 300
REPORT = "/var/tmp/sovtest-load-report.txt"
SAMPLES = "/var/tmp/sovtest-mem.log"
SERVICES = ["dovecot", "rspamd", "redis-server", "postfix", "nginx", "unbound", "radicale", "sovereign-backup"]


def wait_inactive(host, unit, seconds):
    deadline = time.time() + seconds
    while time.time() < deadline:
        if host.run("systemctl is-active --quiet %s", unit).rc != 0:
            return True
        time.sleep(2)
    return False


@pytest.fixture(scope="module")
def load(host, peer, sovtest_vars):
    if host.run("systemd-detect-virt --container --quiet").rc == 0:
        pytest.skip("memory figures are only meaningful in a VM")
    domain = sovtest_vars["sovtest_domain"]
    ip = sovtest_vars["sovtest_ips"]["mail"]
    alice, bob = "alice@" + domain, "bob@" + domain

    # Mail to index: words that differ per message, so the index has work.
    host.check_output(
        "for i in $(seq %s); do printf 'From: load@%s\\nSubject: load test %%s\\n\\n%%s\\n' $i"
        " \"$(shuf -n 200 /usr/share/dict/words 2>/dev/null || seq $i $((i + 400)))\""
        " | doveadm save -u %s -m INBOX; done",
        str(MESSAGES),
        domain,
        alice,
    )
    php_fpm = host.check_output("systemctl list-units --type=service --no-legend --plain 'php*-fpm.service' | cut -d' ' -f1").strip()
    services = SERVICES + ([php_fpm.removesuffix(".service")] if php_fpm else [])

    start = host.check_output("date '+%Y-%m-%d %H:%M:%S'")
    host.run("rm -f %s", SAMPLES)
    host.check_output(
        "systemd-run --unit=sovtest-memsample sh -c "
        "'while :; do awk \"/MemAvailable/ {print \\$2}\" /proc/meminfo; sleep 0.25; done > %s'",
        SAMPLES,
    )
    host.check_output("systemctl start --no-block sovereign-backup.service")
    host.check_output(
        "systemd-run --unit=sovtest-index sh -c 'doveadm fts rescan -u %s && doveadm index -u %s \"*\"'", alice, alice
    )

    # The clients, all at once, from the dns instance.
    dns = peer("dns")
    mail_client(dns)  # copies mailclient.py there
    started = time.time()
    dns.check_output(
        "cd /tmp && ("
        " for w in $(seq 20); do (for i in $(seq 10); do python3 mailclient.py imap-login %s 993 %s %s >/dev/null; done) & done;"
        " for w in $(seq 8); do (for i in $(seq 5); do python3 mailclient.py web-login %s mail.%s %s %s >/dev/null; done) & done;"
        " for w in $(seq 5); do (for i in $(seq 2); do python3 mailclient.py submit %s %s %s %s %s load-$w-$i >/dev/null; done) & done;"
        " wait)",
        ip, alice, ALICE,
        ip, domain, bob, BOB,
        ip, bob, BOB, bob, alice,
    )
    clients_seconds = time.time() - started

    backup_done = wait_inactive(host, "sovereign-backup.service", 900)
    index_done = wait_inactive(host, "sovtest-index.service", 900)
    host.run("systemctl stop sovtest-memsample.service")

    samples = [int(v) for v in host.file(SAMPLES).content_string.split()]
    total = int(host.check_output("awk '/MemTotal/ {print $2}' /proc/meminfo"))
    swap_used = host.check_output("free -k | awk '/Swap/ {print $3}'")
    peaks = {}
    for service in services:
        value = host.run("systemctl show -p MemoryPeak --value %s.service", service).stdout.strip()
        peaks[service] = int(value) // 1024 if value.isdigit() else None
    oom = host.run("journalctl -k --since %s --no-pager -o cat | grep -iE 'out of memory|oom-kill'", start).stdout
    result = {
        "total_kb": total,
        "min_available_kb": min(samples),
        "samples": len(samples),
        "swap_used_kb": swap_used,
        "peaks_kb": peaks,
        "oom": oom,
        "clients_seconds": round(clients_seconds),
        "backup_done": backup_done,
        "backup_ok": host.run("systemctl show -p Result --value sovereign-backup.service").stdout.strip() == "success",
        "index_ok": index_done and host.run("systemctl show -p Result --value sovtest-index.service").stdout.strip() == "success",
    }
    lines = [
        "Memory under load (%d messages indexed, 200 IMAP logins, 40 webmail logins, 10 submissions, a backup)" % MESSAGES,
        "MemTotal:              %6d MiB" % (total // 1024),
        "Lowest MemAvailable:   %6d MiB (%.0f%%), %d samples" % (min(samples) // 1024, 100 * min(samples) / total, len(samples)),
        "Swap used afterwards:  %6s KiB" % swap_used,
        "Clients took %d s; backup %s; indexing %s" % (
            clients_seconds, "ok" if result["backup_ok"] else "FAILED", "ok" if result["index_ok"] else "FAILED"),
        "MemoryPeak per service (MiB, since the service started):",
    ] + ["  %-24s %s" % (name, "-" if kb is None else kb // 1024) for name, kb in peaks.items()] + [
        "OOM messages: " + (oom.strip() or "none"),
    ]
    report = "\n".join(lines)
    host.run("printf '%%s\\n' %s > %s", report, REPORT)
    result["report"] = report
    host.run("systemctl reset-failed sovtest-memsample.service sovtest-index.service")
    return result


def test_no_oom_kill(load):
    assert not load["oom"].strip(), load["report"]


def test_memory_left_under_load(load):
    assert load["min_available_kb"] >= 0.10 * load["total_kb"], load["report"]


def test_backup_and_indexing_finished(load):
    assert load["backup_ok"] and load["index_ok"], load["report"]

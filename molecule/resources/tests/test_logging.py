"""Log retention (logging role) and where the services log.

Everything goes to the journal (30 days, 1 GB) except Sovereign's nginx
sites, which log to /var/log/nginx/sovereign (30 days, compressed from the
second day on).
"""

testinfra_hosts = ["mail"]

NGINX_LOGS = "/var/log/nginx/sovereign"

# Files under /var/log that no logrotate rule covers, on purpose.
NOT_ROTATED = {
    "/var/log/README": "systemd's pointer to journalctl",
    "/var/log/bootstrap.log": "written once when the image was built",
        "/var/log/lastlog": "fixed-size login index, not a log",
    "/var/log/aide/aideinit.log": "written once, when AIDE's database is created",
    "/var/log/aide/aideinit.errors": "written once, when AIDE's database is created",
}


def test_logrotate_installed_and_scheduled(host):
    assert host.package("logrotate").is_installed
    timer = host.service("logrotate.timer")
    assert timer.is_enabled and timer.is_running


def test_journal_limits(host):
    config = host.check_output("systemd-analyze cat-config systemd/journald.conf")
    assert "MaxRetentionSec=30day" in config
    assert "SystemMaxUse=1G" in config
    assert host.file("/var/log/journal").is_directory


def test_rspamd_logs_to_the_journal(host):
    assert 'type = "console"' in host.check_output("rspamadm configdump logging")
    host.check_output("systemctl restart rspamd")
    assert host.check_output("journalctl -u rspamd --since -1min --no-pager -o cat")


def test_fail2ban_logs_to_the_journal(host):
    assert "SYSTEMD-JOURNAL" in host.check_output("fail2ban-client get logtarget")


def test_nginx_logs_to_its_directory(host):
    marker = "/sovtest-logging-%s" % host.check_output("date +%s%N")
    host.run("curl -s -o /dev/null http://127.0.0.1%s", marker)
    assert marker in host.file(NGINX_LOGS + "/access.log").content_string


def test_nginx_rotation_compresses_from_the_second_day(host):
    host.check_output("rm -f %s/*.log.*", NGINX_LOGS)
    for _ in range(2):
        host.run("curl -s -o /dev/null http://127.0.0.1/sovtest-rotation")
        host.check_output("logrotate -f /etc/logrotate.d/sovereign-nginx")
    assert host.file(NGINX_LOGS + "/access.log.1").exists
    assert host.file(NGINX_LOGS + "/access.log.2.gz").exists, host.check_output("ls -la %s", NGINX_LOGS)
    # nginx reopened its files: new requests land in the new access.log.
    host.run("curl -s -o /dev/null http://127.0.0.1/sovtest-after-rotation")
    assert "sovtest-after-rotation" in host.file(NGINX_LOGS + "/access.log").content_string


def test_every_log_file_is_rotated(host):
    debug = host.run("logrotate -d /etc/logrotate.conf").stderr
    considered = {line.split("considering log ", 1)[1].strip() for line in debug.splitlines() if "considering log " in line}
    files = host.check_output(
        "find /var/log -path /var/log/journal -prune -o -type f"
        " ! -name '*.gz' ! -name '*.xz' ! -regex '.*\\.[0-9]+$' -print"
    ).split()
    missing = sorted(set(files) - considered - set(NOT_ROTATED))
    assert missing == [], "not covered by any logrotate rule: %s" % missing


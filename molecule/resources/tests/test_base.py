"""Base system roles on the mail instance (Phase 2.1)."""

import time

import pytest

from conftest import mail_client

testinfra_hosts = ["mail"]


# nftables


def test_no_service_killed_by_its_system_call_filter(host):
    # A sandbox's SystemCallFilter kills a service that makes a call outside
    # it (SIGSYS); systemd restarts it, which can hide the problem. The kernel
    # logs each kill as an audit record of type 1326.
    kills = host.run("journalctl -k -b --no-pager -o cat | grep 'type=1326'").stdout.strip()
    assert not kills, kills


def test_nftables_active(host):
    service = host.service("nftables")
    assert service.is_enabled
    assert service.is_running
    assert host.run("nft list table inet sovereign").rc == 0


# fail2ban


def test_fail2ban_running(host):
    service = host.service("fail2ban")
    assert service.is_running
    assert service.is_enabled


def test_fail2ban_sshd_jail_reads_journal(host):
    status = host.check_output("fail2ban-client status sshd")
    # Only the systemd backend reports journal matches; file backends list files.
    assert "Journal matches:" in status
    assert "sshd-session" in status


def test_fail2ban_sshd_filter_counts_penalty_drops(host):
    line = (
        "Nov  4 10:00:03 mail sshd[1]: drop connection #0 from [192.0.2.9]:44884 "
        "on [192.0.2.1]:22 penalty: attempted authentication by invalid user"
    )
    result = host.check_output(
        "fail2ban-regex %s /etc/fail2ban/filter.d/sshd.conf", line
    )
    assert "1 matched" in result


def test_fail2ban_bans_ssh_attacker_via_nftables(host, sovtest_vars, peer):
    mail_ip = sovtest_vars["sovtest_ips"]["mail"]
    attacker_ip = sovtest_vars["sovtest_ips"]["pebble"]
    attacker = peer("pebble")
    def banned():
        return attacker_ip in host.check_output("fail2ban-client get sshd banip").split()

    try:
        # Keep trying like an attacker would. OpenSSH >= 10.1 throttles the
        # source itself after a few attempts and only logs "drop connection
        # ... penalty"; the role's sshd.local filter counts those as well.
        for _ in range(12):
            attacker.run(
                "ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no "
                "-o UserKnownHostsFile=/dev/null sovereign-nosuchuser@%s true",
                mail_ip,
            )
            time.sleep(1)
            if banned():
                break
        for _ in range(15):
            if banned():
                break
            time.sleep(1)
        assert banned(), host.check_output("fail2ban-client status sshd")

        # The ban is enforced in fail2ban's own nftables table ...
        assert attacker_ip in host.check_output("nft list ruleset")
        # ... which survives a reload of the Sovereign ruleset.
        host.check_output("systemctl reload nftables")
        assert attacker_ip in host.check_output("nft list ruleset")
    finally:
        host.run("fail2ban-client set sshd unbanip %s", attacker_ip)


def ban_seconds(host, jail, ip):
    """Duration of the current ban of ip in jail, None if not banned."""
    for line in host.check_output("fail2ban-client get %s banip --with-time", jail).splitlines():
        if line.split() and line.split()[0] == ip:
            return int(line.split("+", 1)[1].split("=", 1)[0])
    return None


def wait_for_ban(host, jail, ip, seconds=30):
    for _ in range(seconds):
        duration = ban_seconds(host, jail, ip)
        if duration:
            return duration
        time.sleep(1)
    return None


# Mail clients use stored passwords: one wrong password is enough for a ban.
@pytest.mark.parametrize(
    "jail, attempt",
    [
        ("dovecot", lambda c, ip, d: c("imap-login", ip, "993", "alice@" + d, "wrong-password")),
        ("postfix-sasl", lambda c, ip, d: c("smtp-auth", ip, "alice@" + d, "wrong-password", "587")),
    ],
)
def test_single_failed_login_bans(host, peer, sovtest_vars, jail, attempt):
    attacker_ip = sovtest_vars["sovtest_ips"]["pebble"]
    attacker = mail_client(peer("pebble"))
    try:
        attempt(attacker, sovtest_vars["sovtest_ips"]["mail"], sovtest_vars["sovtest_domain"])
        assert wait_for_ban(host, jail, attacker_ip), host.check_output("fail2ban-client status %s", jail)
    finally:
        host.run("fail2ban-client set %s unbanip %s", jail, attacker_ip)


def test_repeated_bans_get_longer(host, peer, sovtest_vars):
    attacker_ip = sovtest_vars["sovtest_ips"]["pebble"]
    attacker = mail_client(peer("pebble"))
    mail, domain = sovtest_vars["sovtest_ips"]["mail"], sovtest_vars["sovtest_domain"]
    durations = []
    try:
        # "unbanip" would also delete the ban from fail2ban's history, which
        # the increment is computed from: let the first ban expire by itself
        # (Molecule bans for 30 s, or longer if earlier tests left history).
        attacker("imap-login", mail, "993", "alice@" + domain, "wrong-password")
        durations.append(wait_for_ban(host, "dovecot", attacker_ip))
        deadline = time.time() + (durations[0] or 0) + 30
        while ban_seconds(host, "dovecot", attacker_ip) is not None and time.time() < deadline:
            time.sleep(2)
        attacker("imap-login", mail, "993", "alice@" + domain, "wrong-password")
        durations.append(wait_for_ban(host, "dovecot", attacker_ip))
    finally:
        host.run("fail2ban-client set dovecot unbanip %s", attacker_ip)
    assert None not in durations and durations[1] == 2 * durations[0], durations
    assert durations[1] <= 86400


# unattended-upgrades


def test_apt_timers_enabled(host):
    for timer in ("apt-daily.timer", "apt-daily-upgrade.timer"):
        service = host.service(timer)
        assert service.is_enabled
        assert service.is_running


def test_unattended_upgrades_enabled(host):
    config = host.check_output("apt-config dump APT::Periodic")
    assert 'APT::Periodic::Update-Package-Lists "1";' in config
    assert 'APT::Periodic::Unattended-Upgrade "1";' in config


def test_changed_conffiles_dont_hold_back_upgrades(host):
    # Otherwise unattended upgrades skip a package whose conffile differs.
    config = host.check_output("apt-config dump DPkg::Options")
    assert 'DPkg::Options:: "--force-confold";' in config, config


def test_failed_upgrades_are_mailed(host):
    config = host.check_output("apt-config dump Unattended-Upgrade")
    assert 'Unattended-Upgrade::Mail "root";' in config
    assert 'Unattended-Upgrade::MailReport "only-on-error";' in config


def test_unattended_upgrades_dry_run(host):
    result = host.run("unattended-upgrade --dry-run")
    assert result.rc == 0, result.stderr



def test_needrestart_restarts_automatically(host):
    assert host.package("needrestart").is_installed
    # Batch mode, list only: reports what it would restart without doing it,
    # which in the middle of the tests could pull services away.
    result = host.run("needrestart -b -r l")
    assert result.rc == 0, result.stderr
    assert "$nrconf{restart} = 'a';" in host.file("/etc/needrestart/conf.d/sovereign.conf").content_string


# Security support status (debian-security-support)

SUPPORT_METRICS = "/var/lib/prometheus/node-exporter/sovereign_security_support.prom"


def support_metrics(host, env=""):
    host.check_output("%s /usr/local/sbin/sovereign-support-status" % env)
    lines = host.file(SUPPORT_METRICS).content_string.splitlines()
    return dict(line.rsplit(" ", 1) for line in lines if not line.startswith("#"))


def test_isc_dhcp_client_removed(host):
    # The incus image installs it; nothing here uses it (systemd-networkd).
    assert not host.package("isc-dhcp-client").is_installed


@pytest.mark.parametrize(
    "setup,teardown,reason",
    [
        ("cp /bin/sleep /tmp/dhclient && (/tmp/dhclient 60 >/dev/null 2>&1 &)", "pkill -x dhclient; rm -f /tmp/dhclient", "dhclient is running"),
        (
            "mkdir -p /etc/network/interfaces.d && echo 'iface eth9 inet dhcp' > /etc/network/interfaces.d/sovtest",
            "rm -f /etc/network/interfaces.d/sovtest",
            "ifupdown uses DHCP",
        ),
    ],
)
def test_dhcp_client_check_sees_use(host, setup, teardown, reason):
    assert host.run("/usr/local/sbin/sovereign-dhcp-client-in-use").rc == 1
    host.check_output(setup)
    try:
        result = host.run("/usr/local/sbin/sovereign-dhcp-client-in-use")
        assert result.rc == 0 and reason in result.stdout, result.stdout
    finally:
        host.run(teardown)


def test_support_status_timer_scheduled(host):
    timer = host.service("sovereign-support-status.timer")
    assert timer.is_enabled
    assert timer.is_running


def test_no_packages_without_full_security_support(host):
    host.check_output("systemctl start sovereign-support-status.service")
    metrics = support_metrics(host)
    for kind in ("ended", "earlyend", "limited"):
        assert metrics['sovereign_security_support_affected_packages{type="%s"}' % kind] == "0", metrics
    assert time.time() - int(metrics["sovereign_security_support_last_run_timestamp_seconds"]) < 120


def test_support_status_reports_affected_packages(host):
    # Debian's list replaced by one that limits postfix: detection and parsing,
    # without installing anything.
    host.check_output("printf 'postfix limited sovtest\\n' > /tmp/sovtest-support-list")
    try:
        metrics = support_metrics(host, "SOVEREIGN_SUPPORT_LIST=/tmp/sovtest-support-list")
        affected = int(metrics['sovereign_security_support_affected_packages{type="limited"}'])
        # postfix and its installed binary packages (postfix-sqlite, postfix-lmdb).
        assert affected >= 3, metrics
        metrics = support_metrics(host, "SOVEREIGN_SUPPORT_LIST=/tmp/sovtest-support-list SOVEREIGN_SUPPORT_EXCEPT=postfix")
        assert int(metrics['sovereign_security_support_affected_packages{type="limited"}']) == affected - 1
    finally:
        host.run("rm -f /tmp/sovtest-support-list")
        support_metrics(host)


# systemd timers


def test_molecule_timer_scheduled(host):
    timer = host.service("sovereign-molecule-check.timer")
    assert timer.is_enabled
    assert timer.is_running


def test_molecule_timer_job_runs(host):
    host.check_output("systemctl start sovereign-molecule-check.service")
    assert host.file("/run/sovereign-molecule-check").exists


# node exporter


def test_node_exporter_serves_metrics(host):
    assert host.service("prometheus-node-exporter").is_running
    metrics = host.check_output("curl --silent --fail http://127.0.0.1:9100/metrics")
    assert "node_exporter_build_info" in metrics


# Everything that listens on a non-loopback address, by port: the firewall's
# open ports, the exporters (firewalled to monitoring_sources) and the DHCP
# client. A new listener fails here even though the firewall would drop its
# traffic, so the firewall stays a second layer, not the only one. Keep in
# sync with nftables_open_tcp_ports and the port table in README.md.
# A socket shows up under every process holding it: Postfix's master or an
# smtpd child, Dovecot's master or its login and stats processes.
POSTFIX = {"master", "smtpd"}
DOVECOT = {"dovecot", "imap-login", "stats"}
EXTERNAL_TCP = {
    22: {"sshd"}, 25: POSTFIX, 80: {"nginx"}, 143: DOVECOT, 443: {"nginx"}, 465: POSTFIX,
    587: POSTFIX, 993: DOVECOT, 9100: {"prometheus-node"}, 9900: DOVECOT,
}
EXTERNAL_UDP_ALLOWED = {68: {"systemd-network"}, 546: {"systemd-network"}}


def test_external_listeners_are_exactly_the_documented_ones(host):
    loopback = ("127.", "[::1]", "[::ffff:127.")
    tcp, udp = {}, {}
    for line in host.check_output("ss --listening --numeric --tcp --udp --processes").splitlines()[1:]:
        fields = line.split()
        address = fields[4]
        if address.startswith(loopback):
            continue
        port = int(address.rsplit(":", 1)[1])
        process = fields[6].split('"')[1] if len(fields) > 6 and '"' in fields[6] else "?"
        (tcp if fields[0] == "tcp" else udp).setdefault(port, set()).add(process)
    assert set(tcp) == set(EXTERNAL_TCP), tcp
    assert all(names <= EXTERNAL_TCP[port] for port, names in tcp.items()), tcp
    assert all(port in EXTERNAL_UDP_ALLOWED and names <= EXTERNAL_UDP_ALLOWED[port] for port, names in udp.items()), udp

"""Base system roles on the mail instance (Phase 2.1)."""

import time

testinfra_hosts = ["mail"]


# nftables


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


def test_fail2ban_bans_ssh_attacker_via_nftables(host, sovtest_vars, peer):
    mail_ip = sovtest_vars["sovtest_ips"]["mail"]
    attacker_ip = sovtest_vars["sovtest_ips"]["pebble"]
    attacker = peer("pebble")
    try:
        for _ in range(sovtest_vars.get("fail2ban_maxretry", 5) + 1):
            attacker.run(
                "ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no "
                "-o UserKnownHostsFile=/dev/null sovereign-nosuchuser@%s true",
                mail_ip,
            )

        banned = ""
        for _ in range(30):
            banned = host.check_output("fail2ban-client get sshd banip")
            if attacker_ip in banned.split():
                break
            time.sleep(1)
        assert attacker_ip in banned.split(), host.check_output("fail2ban-client status sshd")

        # The ban is enforced in fail2ban's own nftables table ...
        assert attacker_ip in host.check_output("nft list ruleset")
        # ... which survives a reload of the Sovereign ruleset.
        host.check_output("systemctl reload nftables")
        assert attacker_ip in host.check_output("nft list ruleset")
    finally:
        host.run("fail2ban-client set sshd unbanip %s", attacker_ip)


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


def test_unattended_upgrades_dry_run(host):
    result = host.run("unattended-upgrade --dry-run")
    assert result.rc == 0, result.stderr


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

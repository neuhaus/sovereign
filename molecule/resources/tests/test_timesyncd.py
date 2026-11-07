"""Time synchronisation (timesyncd role)."""

testinfra_hosts = ["mail"]


def test_configured_servers_are_used(host, ansible_var):
    servers = ansible_var("ntp_servers")
    assert servers
    config = host.check_output("systemd-analyze cat-config systemd/timesyncd.conf")
    assert "NTP=" + " ".join(servers) in config


def test_service_enabled(host):
    assert host.service("systemd-timesyncd").is_enabled


def test_service_runs_outside_containers(host):
    # In a container the host keeps the time, and the unit's condition stops it.
    in_container = host.run("systemd-detect-virt --container --quiet").rc == 0
    if not in_container:
        assert host.service("systemd-timesyncd").is_running

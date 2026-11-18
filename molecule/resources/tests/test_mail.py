"""Phase 0 smoke tests for the system under test."""

import json
import pathlib
import time

import pytest

from conftest import mail_client, run_playbook

testinfra_hosts = ["mail"]


@pytest.fixture(scope="module")
def sovtest(host):
    """Molecule inventory variables (sovtest_*) for the mail instance."""
    return host.ansible.get_variables()


def test_no_failed_units(host):
    state = host.run("systemctl is-system-running --wait").stdout.strip()
    failed = host.run("systemctl --failed --no-legend --plain").stdout
    assert state == "running", f"system state is {state!r}, failed units:\n{failed}"


def test_debian_track(host, sovtest):
    version = host.file("/etc/debian_version").content_string.strip()
    if sovtest["sovtest_target"] == "trixie":
        assert version.startswith("13"), version
    else:
        assert version.endswith("/sid"), version


def test_mock_dns_resolves_mail_host(host, sovtest):
    ips = sovtest["sovtest_ips"]
    answer = host.check_output(
        "kdig +short @%s mail.%s A", ips["dns"], sovtest["sovtest_domain"]
    )
    assert answer.strip() == ips["mail"]


def test_mock_dns_serves_mx(host, sovtest):
    ips = sovtest["sovtest_ips"]
    domain = sovtest["sovtest_domain"]
    answer = host.check_output("kdig +short @%s %s MX", ips["dns"], domain)
    assert answer.strip() == f"10 mail.{domain}."


def test_pebble_directory_reachable_over_trusted_tls(host, sovtest):
    # curl verifies against the system store, so this also checks that
    # prepare.yml installed the Pebble API CA.
    pebble = sovtest["sovtest_ips"]["pebble"]
    directory = json.loads(host.check_output("curl -fsS https://%s:14000/dir", pebble))
    assert "newAccount" in directory
    assert "newOrder" in directory


def test_pebble_issuance_root_trusted(host):
    root = host.file("/usr/local/share/ca-certificates/sovereign-test-pebble-root.crt")
    assert root.exists
    assert "BEGIN CERTIFICATE" in root.content_string


# Sandboxing of the services that handle untrusted input (rspamd, PHP-FPM).
# That they still work is covered by the mail flow, spam and webmail tests.
@pytest.mark.parametrize("unit", ["rspamd.service", "php*-fpm.service", "postfix@-.service", "nginx.service", "dovecot.service"])
def test_service_sandboxed(host, unit):
    name = host.check_output("systemctl list-units --type=service --all --no-legend --plain %s | cut -d' ' -f1", unit).split()[0]
    props = dict(
        line.split("=", 1)
        for line in host.check_output(
            "systemctl show -p ProtectSystem,NoNewPrivileges,PrivateTmp,ProtectHome,RestrictSUIDSGID,ActiveState %s", name
        ).splitlines()
    )
    assert props == {
        "ProtectSystem": "strict",
        "NoNewPrivileges": "yes",
        "PrivateTmp": "yes",
        "ProtectHome": "yes",
        "RestrictSUIDSGID": "yes",
        "ActiveState": "active",
    }, props


def test_php_fpm_capabilities(host):
    # Only what the master needs to switch to the pool users and hand the
    # socket to nginx; no CAP_DAC_OVERRIDE (/run/php is handed to root).
    name = host.check_output("systemctl list-units --type=service --all --no-legend --plain 'php*-fpm.service' | cut -d' ' -f1").split()[0]
    caps = host.check_output("systemctl show -p CapabilityBoundingSet --value %s", name).split()
    assert sorted(caps) == ["cap_chown", "cap_kill", "cap_setgid", "cap_setuid"], caps


def service_name(host, pattern):
    return host.check_output("systemctl list-units --type=service --all --no-legend --plain '%s' | cut -d' ' -f1" % pattern).split()[0]


# What neither Roundcube nor Rspamd may see. Listed here, not taken from the
# role variables, so that a gap in the sandbox can't hide in both places.
SECRETS = [
    "/var/vmail", "/var/lib/sovereign", "/var/lib/radicale", "/var/backups/sovereign", "/var/lib/redis",
    "/etc/restic", "/etc/letsencrypt", "/etc/ssl/private", "/etc/dovecot", "/etc/postsrsd.secret", "/etc/nginx",
]
OTHER_SERVICE = {
    "rspamd.service": ["/var/lib/php/sessions", "/var/lib/roundcube-sovereign", "/etc/roundcube"],
    "php*-fpm.service": ["/var/lib/rspamd", "/etc/rspamd"],
    "postfix@-.service": ["/var/lib/rspamd", "/var/lib/php/sessions", "/etc/roundcube", "/var/lib/sovereign/mobileconfig"],
    "nginx.service": ["/var/lib/rspamd", "/var/lib/php/sessions", "/var/lib/roundcube-sovereign", "/var/lib/dbconfig-common", "/etc/roundcube"],
    "dovecot.service": ["/var/lib/rspamd", "/var/lib/php/sessions", "/var/lib/roundcube-sovereign", "/etc/roundcube", "/etc/rspamd"],
}
# What a service legitimately reads: Postfix the mail database and its TLS keys.
NEEDED = {"postfix@-.service": ["/var/lib/sovereign", "/etc/letsencrypt"], "nginx.service": ["/etc/nginx", "/etc/letsencrypt"],
    "dovecot.service": ["/var/vmail", "/var/lib/sovereign", "/etc/letsencrypt", "/etc/dovecot"],
}


@pytest.mark.parametrize("unit", ["rspamd.service", "php*-fpm.service", "postfix@-.service", "nginx.service", "dovecot.service"])
def test_service_cannot_see_secrets(host, unit):
    # Inside the service's mount namespace each path is either gone (the
    # empty /var) or an empty node with mode 0, so even its root master sees
    # nothing there.
    pid = host.check_output("systemctl show -p MainPID --value %s", service_name(host, unit))
    checked = []
    for path in [p for p in SECRETS if p not in NEEDED.get(unit, [])] + OTHER_SERVICE[unit]:
        if not host.file(path).exists:
            continue
        inside = host.run(
            "nsenter -t %s -m -- sh -c '[ -e \"$1\" ] || exit 0; stat -c %%a \"$1\"; if [ -d \"$1\" ]; then ls -A \"$1\"; else cat \"$1\"; fi' _ %s",
            pid, path,
        )
        assert inside.rc == 0 and inside.stdout.splitlines() in ([], ["0"]), (path, inside.stdout[:200], inside.stderr)
        checked.append(path)
    # The ones that matter most must exist here, or the test proves nothing.
    assert {"/var/vmail", "/var/lib/radicale", "/etc/restic"} <= set(checked), checked


def test_postfix_capabilities(host):
    # Debian's set without CAP_CHOWN (no procmail, no /var/mail delivery).
    caps = host.check_output("systemctl show -p CapabilityBoundingSet --value postfix@-.service").split()
    assert sorted(caps) == sorted(
        ["cap_net_bind_service", "cap_sys_chroot", "cap_setgid", "cap_setuid", "cap_dac_override", "cap_dac_read_search"]
    ), caps


def test_mail_to_root_reaches_the_postmaster(host, sovtest_vars):
    # root -> postmaster@<first domain> -> alice in Molecule.
    subject = "sovtest-root-%d" % int(time.time())
    host.check_output("printf 'Subject: %s\\n\\nroot mail\\n' | /usr/sbin/sendmail root", subject)
    alice = "alice@" + sovtest_vars["sovtest_domain"]
    for _ in range(30):
        if host.run("doveadm search -u %s mailbox INBOX header subject %s", alice, subject).stdout.strip():
            break
        time.sleep(2)
    else:
        raise AssertionError(host.check_output("journalctl -u postfix@- --since -2min --no-pager -o cat | tail -15"))


def test_auth_workers_are_limited(host, peer, sovtest_vars):
    # 30 wrong passwords at once from dns (which fail2ban ignores): never more
    # than dovecot_auth_worker_limit (4) password checks, 64 MiB each.
    assert "process_limit = 4" in host.check_output("doveconf -n service/auth-worker")
    dns = peer("dns")
    mail_client(dns)
    ip, user = sovtest_vars["sovtest_ips"]["mail"], "alice@" + sovtest_vars["sovtest_domain"]
    host.check_output(
        "systemd-run --unit=sovtest-authcount sh -c 'for i in $(seq 120); do ps -C auth --no-headers | wc -l; sleep 0.25; done > /var/tmp/sovtest-authcount'"
    )
    dns.run("cd /tmp && for i in $(seq 30); do python3 mailclient.py imap-login %s 993 %s wrong-%s >/dev/null & done; wait", ip, user, "x")
    host.run("while systemctl is-active --quiet sovtest-authcount; do sleep 1; done")
    counts = [int(n) for n in host.file("/var/tmp/sovtest-authcount").content_string.split()]
    # "auth" is the auth master plus its workers.
    assert counts and max(counts) - 1 <= 4, counts


def test_nginx_capabilities(host):
    caps = host.check_output("systemctl show -p CapabilityBoundingSet --value nginx.service").split()
    assert sorted(caps) == sorted(
        ["cap_net_bind_service", "cap_setuid", "cap_setgid", "cap_chown", "cap_dac_override", "cap_kill"]
    ), caps


def test_nginx_sees_the_webmail_after_a_fresh_install(host):
    # The sandbox mounts /var/lib/roundcube only if it existed when nginx
    # started; the Roundcube role restarts nginx after installing it.
    pid = host.check_output("systemctl show -p MainPID --value nginx.service")
    assert host.run("nsenter -t %s -m -- test -f /var/lib/roundcube/public_html/index.php", pid).rc == 0


def test_dovecot_capabilities(host):
    caps = host.check_output("systemctl show -p CapabilityBoundingSet --value dovecot.service").split()
    assert sorted(caps) == sorted(
        ["cap_net_bind_service", "cap_setuid", "cap_setgid", "cap_sys_chroot", "cap_chown", "cap_dac_override", "cap_kill"]
    ), caps


def test_dovecot_login_processes_stay_chrooted(host):
    # They handle everything sent before a login: dovenull, in an empty chroot.
    host.run("(sleep 8 | openssl s_client -quiet -connect 127.0.0.1:993 >/dev/null 2>&1 &)")
    for _ in range(10):
        pids = host.run("pgrep -x imap-login").stdout.split()
        if pids:
            break
        time.sleep(0.5)
    assert pids, "no imap-login process"
    for pid in pids:
        assert host.check_output("ps -o user= -p %s", pid) == "dovenull"
        assert host.check_output("readlink /proc/%s/root", pid).endswith("/run/dovecot/login")


def metrics_listen(config):
    block = config.split("service stats {", 1)[1].split("\n}", 1)[0]
    return [line.split("=", 1)[1].strip() for line in block.splitlines() if line.strip().startswith("listen =")]


def test_dovecot_metrics_on_all_addresses_with_monitoring(host):
    # Molecule has a monitoring host (dns); the firewall limits it to that one.
    assert host.check_output("doveconf -h service/stats/inet_listener/http/listen") == "* ::"


@pytest.mark.parametrize(
    "variables, expected",
    [({"monitoring_sources": []}, "127.0.0.1"), ({"dovecot_metrics_listen": "10.20.30.40"}, "10.20.30.40")],
)
def test_dovecot_metrics_listen_address(host, variables, expected):
    # Without monitoring nobody outside needs the port: loopback only.
    run_playbook(host, pathlib.Path(__file__).parent / "render_dovecot_conf.yml", variables)
    try:
        assert metrics_listen(host.check_output("cat /var/tmp/sovtest-dovecot.conf")) == [expected]
    finally:
        host.run("rm -f /var/tmp/sovtest-dovecot.conf")

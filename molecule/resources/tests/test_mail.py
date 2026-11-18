"""Phase 0 smoke tests for the system under test."""

import json

import pytest

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
@pytest.mark.parametrize("unit", ["rspamd.service", "php*-fpm.service"])
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
OTHER_SERVICE = {"rspamd.service": ["/var/lib/php/sessions", "/var/lib/roundcube-sovereign", "/etc/roundcube"], "php*-fpm.service": ["/var/lib/rspamd", "/etc/rspamd"]}


@pytest.mark.parametrize("unit", ["rspamd.service", "php*-fpm.service"])
def test_service_cannot_see_secrets(host, unit):
    # Inside the service's mount namespace each path is either gone (the
    # empty /var) or an empty node with mode 0, so even its root master sees
    # nothing there.
    pid = host.check_output("systemctl show -p MainPID --value %s", service_name(host, unit))
    checked = []
    for path in SECRETS + OTHER_SERVICE[unit]:
        if not host.file(path).exists:
            continue
        inside = host.run(
            "nsenter -t %s -m -- sh -c '[ -e \"$1\" ] || exit 0; stat -c %%a \"$1\"; if [ -d \"$1\" ]; then ls -A \"$1\"; else cat \"$1\"; fi' _ %s",
            pid, path,
        )
        assert inside.rc == 0 and inside.stdout.splitlines() in ([], ["0"]), (path, inside.stdout[:200], inside.stderr)
        checked.append(path)
    # The ones that matter most must exist here, or the test proves nothing.
    assert {"/var/vmail", "/var/lib/sovereign", "/etc/letsencrypt"} <= set(checked), checked

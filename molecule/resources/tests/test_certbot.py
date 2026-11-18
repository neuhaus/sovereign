"""Certificate via ACME (certbot role) and the HTTP endpoint (nginx role)."""

import pytest

from conftest import apple_profile

testinfra_hosts = ["mail"]


@pytest.fixture(scope="module")
def domains(ansible_var):
    return ansible_var("certbot_domains")


@pytest.fixture(scope="module")
def live(domains):
    return "/etc/letsencrypt/live/" + domains[0]


def spki_sha256(host, live):
    """SHA-256 of the public key: what a DANE TLSA 3 1 1 record pins."""
    # pipefail: a missing certificate must fail here instead of hashing nothing.
    digest = host.check_output(
        "bash -o pipefail -c \"openssl x509 -in %s/cert.pem -noout -pubkey"
        " | openssl pkey -pubin -outform der | sha256sum | cut -d' ' -f1\"" % live
    )
    assert len(digest) == 64, digest
    return digest


def test_certificate_issued_by_pebble_for_all_names(host, live, domains):
    issuer = host.check_output("openssl x509 -in %s/cert.pem -noout -issuer", live)
    assert "Pebble" in issuer
    san = host.check_output("openssl x509 -in %s/cert.pem -noout -ext subjectAltName", live)
    names = sorted(part.strip()[4:] for part in san.splitlines()[-1].split(",") if part.strip().startswith("DNS:"))
    assert names == sorted(domains)


def test_certificate_chain_verifies(host, live):
    # The Pebble issuance root is trusted on mail (prepare.yml only).
    host.check_output("openssl verify -untrusted %s/chain.pem %s/cert.pem", live, live)


def test_renewal_keeps_key(host, domains):
    conf = host.file("/etc/letsencrypt/renewal/%s.conf" % domains[0])
    assert conf.exists
    assert "reuse_key = True" in conf.content_string


def test_renewal_timer_enabled(host):
    timer = host.service("certbot.timer")
    assert timer.is_enabled
    assert timer.is_running


def test_acme_challenge_served_on_port_80(host, peer, sovtest_vars):
    host.check_output(
        "mkdir -p /var/www/acme/.well-known/acme-challenge"
        " && printf token > /var/www/acme/.well-known/acme-challenge/sovtest"
    )
    try:
        body = peer("dns").check_output(
            "curl -fsS http://%s/.well-known/acme-challenge/sovtest", sovtest_vars["sovtest_ips"]["mail"]
        )
        assert body == "token"
    finally:
        host.run("rm -f /var/www/acme/.well-known/acme-challenge/sovtest")


def test_http_redirects_to_https(host, peer, sovtest_vars):
    result = peer("dns").check_output(
        "curl -s -o /dev/null -w '%%{http_code} %%{redirect_url}' -H 'Host: mail.%s' http://%s/x?y=1",
        sovtest_vars["sovtest_domain"],
        sovtest_vars["sovtest_ips"]["mail"],
    )
    assert result == "301 https://mail.%s/x?y=1" % sovtest_vars["sovtest_domain"]


def test_forced_renewal_keeps_key_and_runs_deploy_hook(host, live, domains):
    key_before = spki_sha256(host, live)
    serial_before = host.check_output("openssl x509 -in %s/cert.pem -noout -serial", live)
    host.run("rm -f /run/sovereign/certbot-deployed")

    result = host.run("certbot renew --force-renewal --no-random-sleep-on-renew")
    assert result.rc == 0, result.stderr

    assert spki_sha256(host, live) == key_before
    assert host.check_output("openssl x509 -in %s/cert.pem -noout -serial", live) != serial_before
    assert host.file("/run/sovereign/certbot-deployed").exists
    assert host.service("nginx").is_running

    # The Apple profiles are signed again with the renewed certificate.
    _, _, signer = apple_profile(host, "autoconfig." + domains[0].split(".", 1)[1])
    assert signer == host.check_output("openssl x509 -in %s/cert.pem -noout -fingerprint -sha256", live)


def test_deploy_hook_reports_a_failed_reload(host):
    # A systemctl that fails every reload, ahead of the real one in PATH.
    host.check_output(
        "mkdir -p /tmp/fakebin && printf '%%s\\n' '#!/bin/sh' "
        "'[ \"$1\" = reload ] && exit 1' 'exec /usr/bin/systemctl \"$@\"' > %s && chmod 0755 %s",
        "/tmp/fakebin/systemctl",
        "/tmp/fakebin/systemctl",
    )
    try:
        host.run("rm -f /run/sovereign/certbot-deployed")
        result = host.run("PATH=/tmp/fakebin:$PATH /etc/letsencrypt/renewal-hooks/deploy/sovereign-reload")
        assert result.rc != 0
        assert "reloading" in result.stderr
        assert not host.file("/run/sovereign/certbot-deployed").exists
    finally:
        host.run("rm -rf /tmp/fakebin")
    assert host.run("/etc/letsencrypt/renewal-hooks/deploy/sovereign-reload").rc == 0
    assert host.file("/run/sovereign/certbot-deployed").exists

"""Certificate via ACME (certbot role) and the HTTP endpoint (nginx role)."""

import pytest

testinfra_hosts = ["mail"]


@pytest.fixture(scope="module")
def live(sovtest_vars):
    return "/etc/letsencrypt/live/" + sovtest_vars["certbot_domains"][0]


def spki_sha256(host, live):
    """SHA-256 of the public key: what a DANE TLSA 3 1 1 record pins."""
    return host.check_output(
        "openssl x509 -in %s/cert.pem -noout -pubkey"
        " | openssl pkey -pubin -outform der | sha256sum | cut -d' ' -f1",
        live,
    )


def test_certificate_issued_by_pebble_for_all_names(host, live, sovtest_vars):
    issuer = host.check_output("openssl x509 -in %s/cert.pem -noout -issuer", live)
    assert "Pebble" in issuer
    san = host.check_output("openssl x509 -in %s/cert.pem -noout -ext subjectAltName", live)
    names = sorted(part.strip()[4:] for part in san.splitlines()[-1].split(",") if part.strip().startswith("DNS:"))
    assert names == sorted(sovtest_vars["certbot_domains"])


def test_certificate_chain_verifies(host, live):
    # The Pebble issuance root is trusted on mail (prepare.yml only).
    host.check_output("openssl verify -untrusted %s/chain.pem %s/cert.pem", live, live)


def test_renewal_keeps_key(host, sovtest_vars):
    conf = host.file("/etc/letsencrypt/renewal/%s.conf" % sovtest_vars["certbot_domains"][0])
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


def test_forced_renewal_keeps_key_and_runs_deploy_hook(host, live):
    key_before = spki_sha256(host, live)
    serial_before = host.check_output("openssl x509 -in %s/cert.pem -noout -serial", live)
    host.run("rm -f /run/sovereign/certbot-deployed")

    result = host.run("certbot renew --force-renewal --no-random-sleep-on-renew")
    assert result.rc == 0, result.stderr

    assert spki_sha256(host, live) == key_before
    assert host.check_output("openssl x509 -in %s/cert.pem -noout -serial", live) != serial_before
    assert host.file("/run/sovereign/certbot-deployed").exists
    assert host.service("nginx").is_running

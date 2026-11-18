"""Web endpoints and MTA-STS (nginx, mta_sts and autoconfig roles), Phase 2.5.

HTTPS requests run on the mail instance, which trusts the Pebble root, so
the certificate is verified; --resolve sends them to the local nginx.
"""

import uuid
import xml.dom.minidom

import pytest

from conftest import apple_profile

testinfra_hosts = ["mail"]


@pytest.fixture(scope="module")
def domain(sovtest_vars):
    return sovtest_vars["sovtest_domain"]


def https(host, name, path, *options):
    # Options are part of the format string: write a literal % as %%.
    return host.check_output(
        "curl -fsS --resolve %s:443:127.0.0.1 " + " ".join(options) + " https://%s%s", name, name, path
    )


def socketmap(host, port, key):
    return host.run("postmap -q %s socketmap:inet:127.0.0.1:%s:postfix", key, str(port))


def test_mta_sts_policy_served(host, domain):
    policy = https(host, "mta-sts." + domain, "/.well-known/mta-sts.txt").splitlines()
    assert policy[0] == "version: STSv1"
    assert "mode: enforce" in policy
    assert "mx: mail." + domain in policy
    assert any(line.startswith("max_age: ") for line in policy)


def test_mta_sts_policy_is_text_plain(host, domain):
    content_type = https(host, "mta-sts." + domain, "/.well-known/mta-sts.txt", "-o /dev/null", "-w '%%{content_type}'")
    assert content_type == "text/plain"


def test_mta_sts_id_recorded(host):
    policy_id = host.file("/var/lib/sovereign/mta-sts-id").content_string.strip()
    assert policy_id.isalnum() and 1 <= len(policy_id) <= 32


@pytest.mark.parametrize("path", ["/mail/config-v1.1.xml", "/.well-known/autoconfig/mail/config-v1.1.xml"])
def test_autoconfig_served(host, domain, path):
    body = https(host, "autoconfig." + domain, path)
    doc = xml.dom.minidom.parseString(body)
    hosts = {n.firstChild.data for n in doc.getElementsByTagName("hostname")}
    ports = {n.firstChild.data for n in doc.getElementsByTagName("port")}
    assert hosts == {"mail." + domain}
    assert ports == {"993", "143", "465", "587"}


@pytest.mark.parametrize("path", ["/autodiscover/autodiscover.xml", "/Autodiscover/Autodiscover.xml"])
def test_autodiscover_answers_post(host, domain, path):
    body = https(
        host, "autodiscover." + domain, path, "-X POST", "-H 'Content-Type: text/xml'", "--data '<Autodiscover/>'"
    )
    doc = xml.dom.minidom.parseString(body)
    assert {n.firstChild.data for n in doc.getElementsByTagName("Server")} == {"mail." + domain}


def test_apple_profile_signed_with_the_server_certificate(host, domain):
    content_type, _, signer = apple_profile(host, "autoconfig." + domain)
    assert content_type == "application/x-apple-aspen-config"
    current = host.check_output("openssl x509 -in /etc/letsencrypt/live/mail.%s/cert.pem -noout -fingerprint -sha256", domain)
    assert signer == current


def test_apple_profile_settings(host, domain):
    _, profile, _ = apple_profile(host, "autoconfig." + domain)
    assert profile["PayloadType"] == "Configuration"
    assert profile["PayloadIdentifier"] == ".".join(reversed(domain.split("."))) + ".sovereign.mail"
    [account] = profile["PayloadContent"]
    assert account["PayloadType"] == "com.apple.mail.managed"
    assert account["EmailAccountType"] == "EmailTypeIMAP"
    assert (account["IncomingMailServerHostName"], account["IncomingMailServerPortNumber"]) == ("mail." + domain, 993)
    assert (account["OutgoingMailServerHostName"], account["OutgoingMailServerPortNumber"]) == ("mail." + domain, 465)
    assert account["IncomingMailServerUseSSL"] and account["OutgoingMailServerUseSSL"]
    # One file for every user: the device asks for address, user and password.
    for key in ("EmailAddress", "IncomingMailServerUsername", "OutgoingMailServerUsername", "IncomingPassword", "OutgoingPassword"):
        assert key not in account
    # The UUIDs identify the profile on the device: two different ones, both valid.
    uuids = {profile["PayloadUUID"], account["PayloadUUID"]}
    assert len(uuids) == 2 and all(uuid.UUID(u) for u in uuids)


def test_apple_profile_only_on_autoconfig_hosts(host, domain):
    code = host.check_output(
        "curl -s -o /dev/null -w '%%{http_code}' --resolve autodiscover.%s:443:127.0.0.1 https://autodiscover.%s/mail.mobileconfig",
        domain,
        domain,
    )
    assert code == "404"


def test_apple_profile_not_signed_again_without_changes(host):
    assert host.check_output("/usr/local/sbin/sovereign-sign-mobileconfig") == ""


STATIC_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"


def headers(host, name, path, *options):
    raw = https(host, name, path, "-o /dev/null", "-D -", *options)
    result = {}
    for line in raw.splitlines()[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            result.setdefault(key.strip().lower(), []).append(value.strip())
    return result


@pytest.mark.parametrize(
    "prefix, path",
    [("mta-sts", "/.well-known/mta-sts.txt"), ("autoconfig", "/mail/config-v1.1.xml"), ("autoconfig", "/mail.mobileconfig")],
)
def test_static_sites_send_strict_headers(host, domain, prefix, path):
    sent = headers(host, prefix + "." + domain, path)
    assert sent.get("content-security-policy") == [STATIC_CSP], sent
    assert sent.get("x-content-type-options") == ["nosniff"], sent
    assert sent.get("referrer-policy") == ["no-referrer"], sent
    assert sent.get("strict-transport-security") == ["max-age=63072000"], sent


def all_hosts(ansible_var):
    return ansible_var("certbot_domains")


def test_security_txt_on_every_host(host, ansible_var):
    hosts = all_hosts(ansible_var)
    domain = ansible_var("mail_domains")[0]
    for name in hosts:
        # No basic auth: also the webmail serves it without a login.
        text = https(host, name, "/.well-known/security.txt")
        fields = [line.split(":", 1) for line in text.splitlines() if line and not line.startswith("#")]
        keys = [k for k, _ in fields]
        assert ("Contact", " mailto:postmaster@" + domain) in [(k, v) for k, v in fields], text
        assert keys.count("Expires") == 1 and set("https://%s/.well-known/security.txt" % h for h in hosts) == {
            v.strip() for k, v in fields if k == "Canonical"
        }, text


def test_security_txt_expires_within_a_year(host, ansible_var):
    text = https(host, ansible_var("certbot_domains")[0], "/.well-known/security.txt")
    expires = next(line.split(":", 1)[1].strip() for line in text.splitlines() if line.startswith("Expires:"))
    left = int(host.check_output("echo $(( $(date -d %s +%%s) - $(date +%%s) ))", expires))
    # RFC 9116: less than a year; one year from the start of this month.
    assert 300 * 86400 < left <= 366 * 86400, expires


def test_robots_txt_disallows_everything(host, ansible_var):
    for name in all_hosts(ansible_var):
        assert https(host, name, "/robots.txt").splitlines() == ["User-agent: *", "Disallow: /"], name


def test_no_indexing_header(host, domain):
    assert headers(host, "mta-sts." + domain, "/.well-known/mta-sts.txt").get("x-robots-tag") == ["noindex, nofollow"]


def test_unknown_paths_return_404(host, domain):
    code = host.check_output(
        "curl -s -o /dev/null -w '%%{http_code}' --resolve mta-sts.%s:443:127.0.0.1 https://mta-sts.%s/other",
        domain,
        domain,
    )
    assert code == "404"


@pytest.mark.parametrize("service", ["postfix-mta-sts-resolver", "sovereign-tls-policy"])
def test_mta_sts_services_running(host, service):
    assert host.service(service).is_running
    assert host.service(service).is_enabled


def test_resolver_returns_our_policy(host, domain):
    result = socketmap(host, 8461, domain)
    assert result.rc == 0, result.stderr
    assert "secure match=mail." + domain in result.stdout


def test_policy_service_passes_mta_sts_through(host, domain):
    # The test domain is not DNSSEC-signed, so MTA-STS applies.
    result = socketmap(host, 8462, domain)
    assert result.rc == 0, result.stderr
    assert "secure match=mail." + domain in result.stdout


def test_policy_service_prefers_dane(host):
    # signed.test: authenticated MX with a TLSA record -> no policy entry, so
    # Postfix keeps its DANE verification.
    result = socketmap(host, 8462, "signed.test")
    assert result.rc == 1 and result.stdout == "", (result.stdout, result.stderr)


def test_policy_service_defers_on_dnssec_failure(host):
    result = socketmap(host, 8462, "broken.test")
    assert "temporary error: DNS lookup failed" in result.stderr


def test_policy_service_no_policy_for_plain_domain(host, sovtest_vars):
    result = socketmap(host, 8462, sovtest_vars["sovtest_external_domain"])
    assert result.rc == 1 and result.stdout == "", (result.stdout, result.stderr)


def test_postfix_uses_the_policy_service(host):
    assert host.check_output("postconf -h smtp_tls_policy_maps") == "socketmap:inet:127.0.0.1:8462:postfix"

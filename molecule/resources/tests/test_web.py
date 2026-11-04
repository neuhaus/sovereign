"""Web endpoints and MTA-STS (nginx, mta_sts and autoconfig roles), Phase 2.5.

HTTPS requests run on the mail instance, which trusts the Pebble root, so
the certificate is verified; --resolve sends them to the local nginx.
"""

import xml.dom.minidom

import pytest

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
    assert ports == {"993", "143", "587"}


@pytest.mark.parametrize("path", ["/autodiscover/autodiscover.xml", "/Autodiscover/Autodiscover.xml"])
def test_autodiscover_answers_post(host, domain, path):
    body = https(
        host, "autodiscover." + domain, path, "-X POST", "-H 'Content-Type: text/xml'", "--data '<Autodiscover/>'"
    )
    doc = xml.dom.minidom.parseString(body)
    assert {n.firstChild.data for n in doc.getElementsByTagName("Server")} == {"mail." + domain}


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

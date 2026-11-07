"""Webmail and groupware (roundcube and radicale roles), Phase 2.6.

Clients run on the dns instance, which fail2ban ignores; pebble plays the
attacker in the ban tests.
"""

import time
import uuid

import pytest

from conftest import mail_client

testinfra_hosts = ["mail"]

DB = "/var/lib/sovereign/maildb/mail.sqlite"
ALICE = "sovtest-alice-pass"
ALICE_APP = "AlicPhn1-sovtest-app-phone"
BOB = "sovtest-bob-pass"
CAROL = "sovtest-carol-pass"
CAROL_APP = "CarolPh1-sovtest-app-phone"
WEBMAIL_AUTH = "webmail:sovtest-webmail-pass"


@pytest.fixture(scope="module")
def ctx(sovtest_vars):
    d = sovtest_vars["sovtest_domain"]
    return {
        "ip": sovtest_vars["sovtest_ips"]["mail"],
        "domain": d,
        "web": "mail." + d,
        "dav": "dav." + d,
        "alice": "alice@" + d,
        "bob": "bob@" + d,
        "carol": "carol@" + d,
    }


@pytest.fixture(scope="module")
def client(peer):
    return mail_client(peer("dns"))


@pytest.fixture(scope="module")
def attacker(peer):
    return mail_client(peer("pebble"))


def wait_for(check, seconds=30):
    for _ in range(seconds):
        if check():
            return True
        time.sleep(1)
    return False


# --- Roundcube ---------------------------------------------------------------


def test_login_page_with_elastic_and_all_assets(client, ctx):
    result = client("web-assets", ctx["ip"], ctx["web"])
    assert result["status"] == 200 and result["elastic"], result
    assert result["assets"] > 0 and not result["failed"], result


def test_certificate_verified_on_webmail(host, ctx):
    code = host.check_output("curl -fsS -o /dev/null -w '%%{http_code}' -u %s --resolve %s:443:127.0.0.1 https://%s/", WEBMAIL_AUTH, ctx["web"], ctx["web"])
    assert code == "200"


@pytest.mark.parametrize("path", ["/", "/index.php", "/?_task=login", "/skins/elastic/styles/styles.min.css", "/no-such-file"])
def test_nothing_reachable_without_basic_auth(client, ctx, path):
    result = client("web-basic", ctx["ip"], ctx["web"], path)
    assert result["status"] == 401 and not result["roundcube"], result
    result = client("web-basic", ctx["ip"], ctx["web"], path, "webmail", "wrong-password")
    assert result["status"] == 401 and not result["roundcube"], result


def test_basic_auth_password_not_passed_to_php(host):
    # A compromised Roundcube must not be able to collect these credentials.
    assert 'fastcgi_param HTTP_AUTHORIZATION "";' in host.check_output("nginx -T 2>/dev/null")


def test_basic_auth_file_permissions(host):
    htpasswd = host.file("/etc/nginx/roundcube.htpasswd")
    assert (htpasswd.user, htpasswd.group, htpasswd.mode) == ("root", "www-data", 0o640)
    assert htpasswd.content_string.startswith("webmail:$6$")


@pytest.mark.parametrize(
    "path",
    ["/config/config.inc.php", "/plugins/password/config.inc.php", "/plugins/password/drivers/sovereign.php", "/.htaccess", "/program/lib/Roundcube/rcube.php", "/SQL/sqlite.initial.sql", "/logs/errors.log", "/installer/"],
)
def test_internal_files_not_served(host, ctx, path):
    code = host.check_output("curl -s -o /dev/null -w '%%{http_code}' -u %s --resolve %s:443:127.0.0.1 https://%s%s", WEBMAIL_AUTH, ctx["web"], ctx["web"], path)
    assert code in ("403", "404"), path


def test_only_nginx_serves_http(host):
    # No Apache pulled in by the PHP packages.
    installed = host.check_output("dpkg-query -W -f '${db:Status-Abbrev}${Package}\\n'")
    assert not [line for line in installed.splitlines() if line.startswith("ii") and "apache2" in line]


def test_php_runs_as_its_own_user(host, client, ctx):
    assert host.socket("unix:///run/php/roundcube.sock").is_listening
    # Workers only exist after a request; www-data (nginx) must not run PHP.
    client("web-assets", ctx["ip"], ctx["web"])
    processes = host.check_output("ps -eo user:20,args")
    workers = [line.split()[0] for line in processes.splitlines() if "php-fpm: pool roundcube" in line]
    assert workers and set(workers) == {"roundcube"}, processes


def test_maintenance_job_runs(host):
    assert host.service("roundcube-maintenance.timer").is_enabled
    host.run("systemctl start roundcube-maintenance.service")
    result = host.run("systemctl show -p Result --value roundcube-maintenance.service")
    assert result.stdout.strip() == "success", host.check_output("journalctl -n 30 -u roundcube-maintenance.service --no-pager")


def test_login_with_main_password(client, ctx):
    assert client("web-login", ctx["ip"], ctx["web"], ctx["alice"], ALICE)["ok"]


def test_login_with_wrong_password_refused(client, ctx):
    assert not client("web-login", ctx["ip"], ctx["web"], ctx["alice"], "wrong-password")["ok"]


def test_app_password_refused_in_webmail(client, ctx):
    # Otherwise an app password would be enough to change the main password.
    assert not client("web-login", ctx["ip"], ctx["web"], ctx["alice"], ALICE_APP)["ok"]
    # It still works for IMAP from elsewhere.
    assert client("imap-login", ctx["ip"], "993", ctx["alice"], ALICE_APP)["ok"]


def test_send_through_webmail(client, ctx):
    subject = "webmail" + uuid.uuid4().hex[:10]
    result = client("web-send", ctx["ip"], ctx["web"], ctx["alice"], ALICE, ctx["bob"], subject)
    assert result["ok"], result
    assert wait_for(lambda: client("imap-count", ctx["ip"], ctx["bob"], BOB, subject)["count"] == 1)
    headers = dict(client("imap-headers", ctx["ip"], ctx["bob"], BOB, subject)["headers"])
    assert "DKIM-Signature" in headers
    assert headers["User-Agent"] == "Roundcube Webmail"


def test_filter_settings_reach_managesieve(client, ctx):
    result = client("web-sieve", ctx["ip"], ctx["web"], ctx["alice"], ALICE)
    assert result["ok"], result


def test_managesieve_starttls_and_authentication(client, ctx):
    result = client("sieve-login", ctx["ip"], ctx["alice"], ALICE)
    assert result["starttls"].startswith("OK") and result["ok"], result
    assert not client("sieve-login", ctx["ip"], ctx["alice"], "wrong-password")["ok"]


# --- Password self-service ----------------------------------------------------


def test_password_change(host, client, ctx):
    new = "sovtest-carol-" + uuid.uuid4().hex[:12]
    stored = "SELECT password FROM mailboxes WHERE localpart = 'carol'"
    before = host.check_output("sqlite3 %s %s", DB, stored)

    too_short = client("web-password", ctx["ip"], ctx["web"], ctx["carol"], CAROL, "short")
    assert not too_short["ok"], too_short
    assert host.check_output("sqlite3 %s %s", DB, stored) == before

    result = client("web-password", ctx["ip"], ctx["web"], ctx["carol"], CAROL, new)
    assert result["ok"], result

    # Stored as Argon2id, and only carol's row changed.
    after = host.check_output("sqlite3 %s %s", DB, stored)
    assert after != before and after.startswith("{ARGON2ID}$argon2id$")
    assert host.check_output("sqlite3 %s %s", DB, "SELECT count(*) FROM mailboxes WHERE password = '%s'" % after) == "1"

    # The database stays readable for Postfix and Dovecot, which need the
    # rollback journal (Roundcube's own database layer would switch to WAL).
    assert host.check_output("sqlite3 %s 'PRAGMA journal_mode'", DB) == "delete"
    assert host.run("postmap -q %s proxy:sqlite:/etc/postfix/sqlite/virtual-mailboxes.cf", ctx["carol"]).rc == 0

    # Both protocols use the new password, the old one is gone, and the app
    # password keeps working.
    assert client("imap-login", ctx["ip"], "993", ctx["carol"], new)["ok"]
    assert not client("imap-login", ctx["ip"], "993", ctx["carol"], CAROL)["ok"]
    assert client("imap-login", ctx["ip"], "993", ctx["carol"], CAROL_APP)["ok"]
    assert client("web-login", ctx["ip"], ctx["web"], ctx["carol"], new)["ok"]

    # The next Ansible synchronisation keeps the changed password but restores
    # everything else. sync.sql is what the maildb role runs.
    host.check_output("sqlite3 %s %s", DB, "DELETE FROM aliases WHERE source LIKE 'team@%'")
    host.check_output("sqlite3 -bail %s '.read /var/lib/sovereign/sync.sql'", DB)
    assert host.check_output("sqlite3 %s %s", DB, stored) == after
    assert host.check_output("sqlite3 %s %s", DB, "SELECT count(*) FROM aliases WHERE source LIKE 'team@%'") == "2"
    assert client("imap-login", ctx["ip"], "993", ctx["carol"], new)["ok"]


def test_maildb_does_not_see_changed_password_as_a_difference(host):
    # The role compares the inventory with the hash it last applied, not the
    # live one (test_password_change above changed carol's).
    live = host.check_output("sqlite3 %s %s", DB, "SELECT password FROM mailboxes WHERE localpart = 'carol'")
    export = host.check_output("sqlite3 -batch -noheader %s '.read /var/lib/sovereign/export.sql'", DB)
    assert "mailbox|carol@" in export and live not in export


# --- Radicale -----------------------------------------------------------------


def dav(client, ctx, method, path, user="", password="", body=""):
    return client("dav", ctx["ip"], ctx["dav"], method, path, user, password, body)


def test_radicale_only_on_loopback(host):
    assert host.service("radicale").is_running
    assert host.socket("tcp://127.0.0.1:5232").is_listening
    assert not host.socket("tcp://0.0.0.0:5232").is_listening


def test_auth_socket_only_for_its_group(host):
    socket_file = host.file("/run/dovecot/auth-external")
    assert socket_file.is_socket
    assert (socket_file.group, socket_file.mode) == ("dovecot-auth", 0o660)
    assert "dovecot-auth" in host.user("radicale").groups
    # Roundcube's PHP user and nginx must not be able to try passwords through it.
    for user in ("roundcube", "www-data"):
        assert host.run("runuser -u %s -- test -w /run/dovecot/auth-external", user).rc != 0
    assert host.run("runuser -u radicale -- test -w /run/dovecot/auth-external").rc == 0


def test_certificate_verified_on_dav(host, ctx):
    code = host.check_output("curl -s -o /dev/null -w '%%{http_code}' --resolve %s:443:127.0.0.1 https://%s/", ctx["dav"], ctx["dav"])
    assert code != "000"


@pytest.mark.parametrize("path", ["/.well-known/caldav", "/.well-known/carddav"])
def test_service_discovery_redirects(client, ctx, path):
    result = dav(client, ctx, "GET", path)
    assert result["status"] in (301, 302, 303, 307, 308), result


def test_propfind_requires_authentication(client, ctx):
    assert dav(client, ctx, "PROPFIND", "/" + ctx["alice"] + "/")["status"] == 401


def test_propfind_with_main_password(client, ctx):
    assert dav(client, ctx, "PROPFIND", "/" + ctx["alice"] + "/", ctx["alice"], ALICE)["status"] == 207


def test_propfind_with_app_password(client, ctx):
    assert dav(client, ctx, "PROPFIND", "/" + ctx["alice"] + "/", ctx["alice"], ALICE_APP)["status"] == 207


def test_propfind_with_wrong_password(client, ctx):
    assert dav(client, ctx, "PROPFIND", "/" + ctx["alice"] + "/", ctx["alice"], "wrong-password")["status"] == 401


def test_wrong_password_does_not_delay_other_users(client, ctx):
    # Dovecot's auth penalty would otherwise apply to all CalDAV users together
    # (Radicale sends no client address) and lock them out.
    for _ in range(3):
        assert dav(client, ctx, "PROPFIND", "/" + ctx["alice"] + "/", ctx["alice"], "wrong-password")["status"] == 401
    started = time.monotonic()
    assert dav(client, ctx, "PROPFIND", "/" + ctx["bob"] + "/", ctx["bob"], BOB)["status"] == 207
    assert time.monotonic() - started < 3


def test_parallel_logins(client, ctx):
    # Radicale handles requests in threads; each needs its own Dovecot connection id.
    results = client("dav-parallel", ctx["ip"], ctx["dav"], "/" + ctx["alice"] + "/", ctx["alice"], ALICE, "12")
    assert results["statuses"] == [207] * 12, results


def test_users_cannot_read_each_other(client, ctx):
    assert dav(client, ctx, "PROPFIND", "/" + ctx["alice"] + "/", ctx["bob"], BOB)["status"] == 403


def test_calendar_roundtrip(client, ctx):
    calendar = "/%s/cal-%s/" % (ctx["alice"], uuid.uuid4().hex[:8])
    assert dav(client, ctx, "MKCOL", calendar, ctx["alice"], ALICE, MKCOL_CALENDAR)["status"] == 201
    assert dav(client, ctx, "PUT", calendar + "event.ics", ctx["alice"], ALICE, EVENT)["status"] == 201
    result = dav(client, ctx, "GET", calendar + "event.ics", ctx["alice"], ALICE)
    assert result["status"] == 200 and "SUMMARY:Sovereign test" in result["body"]


MKCOL_CALENDAR = (
    '<?xml version="1.0"?><mkcol xmlns="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav"><set><prop>'
    "<resourcetype><collection/><C:calendar/></resourcetype></prop></set></mkcol>"
)
EVENT = (
    "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Sovereign//Test//EN\r\nBEGIN:VEVENT\r\nUID:sovereign-test\r\n"
    "DTSTAMP:20260101T000000Z\r\nDTSTART:20260101T100000Z\r\nDTEND:20260101T110000Z\r\nSUMMARY:Sovereign test\r\n"
    "END:VEVENT\r\nEND:VCALENDAR\r\n"
)


def test_shared_calendar_for_members_only(client, ctx):
    shared = "/shared/family/"
    member_a = dav(client, ctx, "PROPFIND", shared, ctx["alice"], ALICE)
    assert member_a["status"] == 207 and "Family" in member_a["body"] and "calendar" in member_a["body"], member_a
    assert dav(client, ctx, "PROPFIND", shared, ctx["bob"], BOB)["status"] == 207
    assert dav(client, ctx, "PROPFIND", shared, ctx["carol"], "wrong")["status"] == 401
    # carol is no member (password from before the change test is irrelevant:
    # an app password authenticates her either way).
    assert dav(client, ctx, "PROPFIND", shared, ctx["carol"], CAROL_APP)["status"] == 403
    assert dav(client, ctx, "PUT", shared + "x.ics", ctx["carol"], CAROL_APP, EVENT)["status"] == 403

    # Written by one member, readable by the other.
    assert dav(client, ctx, "PUT", shared + "shared-event.ics", ctx["alice"], ALICE, EVENT)["status"] in (201, 204)
    result = dav(client, ctx, "GET", shared + "shared-event.ics", ctx["bob"], BOB)
    assert result["status"] == 200 and "SUMMARY:Sovereign test" in result["body"]


# --- fail2ban -----------------------------------------------------------------


@pytest.mark.parametrize("jail", ["nginx-http-auth", "roundcube-auth", "radicale"])
def test_web_login_jails_active(host, jail):
    assert "Journal matches" in host.check_output("fail2ban-client status %s", jail)


@pytest.mark.parametrize(
    "jail, attempt",
    [
        ("nginx-http-auth", lambda a, c, i: a("web-basic", c["ip"], c["web"], "/", "nobody%d" % i, "wrong-password")),
        ("roundcube-auth", lambda a, c, i: a("web-login", c["ip"], c["web"], "nobody%d@%s" % (i, c["domain"]), "wrong-password")),
        ("radicale", lambda a, c, i: a("dav", c["ip"], c["dav"], "PROPFIND", "/", "nobody%d@%s" % (i, c["domain"]), "wrong-password")),
    ],
)
def test_failed_web_logins_get_banned(host, attacker, sovtest_vars, ctx, jail, attempt):
    attacker_ip = sovtest_vars["sovtest_ips"]["pebble"]

    def banned():
        return attacker_ip in host.check_output("fail2ban-client get %s banip", jail).split()

    try:
        for i in range(5):
            attempt(attacker, ctx, i)
        assert wait_for(banned), host.check_output("fail2ban-client status %s", jail)
    finally:
        host.run("fail2ban-client set %s unbanip %s", jail, attacker_ip)

"""Mail database (maildb role) on the mail instance."""

testinfra_hosts = ["mail"]

DB = "/var/lib/sovereign/maildb/mail.sqlite"


def query(host, sql):
    return host.check_output("sqlite3 -batch -noheader %s %s", DB, sql).splitlines()


def test_database_permissions(host):
    db = host.file(DB)
    assert db.user == "roundcube"
    assert db.group == "maildb"
    assert db.mode == 0o640
    # SQLite creates its journal next to the database, so the writer owns this
    # directory. Nobody but root may write where root's scripts are.
    directory = host.file("/var/lib/sovereign/maildb")
    assert (directory.user, directory.group, directory.mode) == ("roundcube", "maildb", 0o750)
    scripts = host.file("/var/lib/sovereign")
    assert (scripts.user, scripts.group, scripts.mode) == ("root", "maildb", 0o750)
    # The synchronisation script contains password hashes.
    script = host.file("/var/lib/sovereign/sync.sql")
    assert (script.user, script.group, script.mode) == ("root", "root", 0o600)


def test_database_mirrors_inventory(host, sovtest_vars):
    domain = sovtest_vars["sovtest_domain"]
    assert query(host, "SELECT name FROM domains") == [domain]
    assert query(host, "SELECT localpart || '@' || domain FROM mailboxes ORDER BY 1") == [
        "alice@" + domain,
        "bob@" + domain,
        "carol@" + domain,
    ]
    assert query(host, "SELECT id || ':' || name FROM app_passwords ORDER BY 1") == ["AlicPhn1:phone", "CarolPh1:phone"]
    assert query(host, "SELECT source || '>' || destination FROM aliases ORDER BY 1") == [
        "fwd@%s>someone@%s" % (domain, sovtest_vars["sovtest_external_domain"]),
        "postmaster@%s>alice@%s" % (domain, domain),
        "team@%s>alice@%s" % (domain, domain),
        "team@%s>bob@%s" % (domain, domain),
    ]


def test_schema_version(host):
    assert query(host, "PRAGMA user_version") == ["2"]


def test_nginx_cannot_write_the_database(host):
    assert host.run("runuser -u www-data -- test -r %s", DB).rc != 0
    assert host.run("runuser -u www-data -- test -w %s", DB).rc != 0
    assert host.run("runuser -u roundcube -- test -w %s", DB).rc == 0
    assert host.run("runuser -u roundcube -- test -w /var/lib/sovereign").rc != 0
    assert host.run("runuser -u dovecot -- test -w %s", DB).rc != 0
    assert host.run("runuser -u dovecot -- test -r %s", DB).rc == 0

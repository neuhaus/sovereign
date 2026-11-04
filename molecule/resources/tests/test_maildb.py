"""Mail database (maildb role) on the mail instance."""

testinfra_hosts = ["mail"]

DB = "/var/lib/sovereign/mail.sqlite"


def query(host, sql):
    return host.check_output("sqlite3 -batch -noheader %s %s", DB, sql).splitlines()


def test_database_permissions(host):
    db = host.file(DB)
    assert db.user == "root"
    assert db.group == "maildb"
    assert db.mode == 0o640
    # The synchronisation script contains password hashes.
    script = host.file("/var/lib/sovereign/sync.sql")
    assert (script.user, script.group, script.mode) == ("root", "root", 0o600)


def test_database_mirrors_inventory(host, sovtest_vars):
    domain = sovtest_vars["sovtest_domain"]
    assert query(host, "SELECT name FROM domains") == [domain]
    assert query(host, "SELECT localpart || '@' || domain FROM mailboxes ORDER BY 1") == [
        "alice@" + domain,
        "bob@" + domain,
    ]
    assert query(host, "SELECT id || ':' || name FROM app_passwords") == ["AlicPhn1:phone"]
    assert query(host, "SELECT source || '>' || destination FROM aliases ORDER BY 1") == [
        "postmaster@%s>alice@%s" % (domain, domain),
        "team@%s>alice@%s" % (domain, domain),
        "team@%s>bob@%s" % (domain, domain),
    ]


def test_schema_version(host):
    assert query(host, "PRAGMA user_version") == ["1"]

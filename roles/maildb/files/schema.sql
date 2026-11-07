-- Sovereign mail database (SQLite), schema version 2.
-- Managed by Ansible (maildb role). Applied when the database is created and
-- whenever this file changes; must stay idempotent.
PRAGMA foreign_keys = ON;
-- Rollback journal, not WAL: the readers (Postfix, Dovecot) cannot write the
-- -shm file that WAL needs. Also converts a database already switched to WAL.
PRAGMA journal_mode = DELETE;

CREATE TABLE IF NOT EXISTS domains (
    name TEXT PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS mailboxes (
    localpart TEXT NOT NULL,
    domain    TEXT NOT NULL REFERENCES domains(name) ON DELETE CASCADE,
    password  TEXT NOT NULL,
    -- Hash last taken from the inventory. Users change "password" in Roundcube;
    -- a new hash in the inventory resets it once. Empty: not known yet.
    inventory_password TEXT NOT NULL DEFAULT '',
    quota_mb  INTEGER NOT NULL DEFAULT 0,
    enabled   INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (localpart, domain)
);

-- An app password starts with its id (first 8 characters); Dovecot selects
-- the row by that prefix, so each login matches at most one row.
CREATE TABLE IF NOT EXISTS app_passwords (
    localpart TEXT NOT NULL,
    domain    TEXT NOT NULL,
    id        TEXT NOT NULL CHECK (length(id) = 8),
    name      TEXT NOT NULL,
    password  TEXT NOT NULL,
    PRIMARY KEY (localpart, domain, id),
    UNIQUE (localpart, domain, name),
    FOREIGN KEY (localpart, domain) REFERENCES mailboxes(localpart, domain) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS aliases (
    source      TEXT NOT NULL,
    destination TEXT NOT NULL,
    PRIMARY KEY (source, destination)
);

PRAGMA user_version = 2;

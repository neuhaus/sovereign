-- Sovereign mail database (SQLite), schema version 1.
-- Managed by Ansible (maildb role). Applied on every run; must stay idempotent.
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS domains (
    name TEXT PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS mailboxes (
    localpart TEXT NOT NULL,
    domain    TEXT NOT NULL REFERENCES domains(name) ON DELETE CASCADE,
    password  TEXT NOT NULL,
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

PRAGMA user_version = 1;

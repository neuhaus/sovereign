# Roles

How each role works and why, in the order `site.yml` runs them. This covers decisions and tradeoffs; settings are explained in each role's `defaults/main.yml`.

A few rules apply throughout: Debian packages only, every handler checks the configuration before it restarts a service, and each role is named after the software it configures, or after the mechanism if it is not one package.

## preflight

Stops early on anything unsupported: an old ansible-core, or a system other than Debian 13 or Testing. It sets the `sovereign_debian_track` fact, which is the only place the release is determined. Testing is recognised by `/sid` in `/etc/debian_version`, which it shares with unstable, because Testing has no stable version number to test for.

## openssh

Key logins only, through a drop-in that sorts first, because the first value of a setting wins in `sshd_config` and this way it also beats files such as cloud-init's.

The risk with this role is locking the admin out of a remote server, so it first checks that the connecting user has a key, and stops if not. The check can only show that a key file has content, not that the key is the right one, so the README also asks you to test your key first.

Root logins with a key stay as Debian sets them. The goal here is that no password can be guessed; whether root logs in directly is a separate matter.

## timesyncd

`systemd-timesyncd` rather than chrony or ntpd: a server that only needs correct time for certificates and DKIM has no use for serving time, and this is the lightest option. The role installs it, because a minimal Debian image (checked with the Debian 13 VM image from the incus image server) has no time client at all. `ntp_servers` selects the servers; without it, Debian's default pool applies. In a container the unit does not run, since the host keeps the time.

## unbound

A local DNSSEC-validating resolver, because Postfix needs validated answers for DANE, and because public resolvers often rate-limit or filter DNS blocklist queries.

`/etc/resolv.conf` carries `options trust-ad`, because otherwise glibc removes the AD flag that tells Postfix an answer was validated, and DANE silently stops working. The resolver must be running before the system points at it, or the rest of the playbook loses name resolution.

Unbound always recurses by itself; there is no forwarder setting. A network that blocks outgoing DNS would need one (tests on such a network add it by hand).

## nftables

Only Sovereign's own table is replaced on reload, not the whole ruleset, because `flush ruleset` would also remove fail2ban's table and with it all bans. Exporter ports open only for `monitoring_sources`; with an empty list no rule is rendered at all.

## fail2ban

Reads from journald, because Debian 13 has no syslog files to tail. Bans go into nftables. The sshd filter also counts OpenSSH's own penalty drops: since OpenSSH 10.1, sshd throttles a source itself and logs something else than a failed login.

Web logins reach Dovecot from loopback, where the dovecot jail cannot ban anyone. So basic auth, Roundcube and Radicale have jails of their own, which read the real client address from those services' logs. The Radicale filter trusts `X-Forwarded-For` because nginx always overwrites that header. fail2ban's journal backend prefixes each line with `host unit[pid]:`, which filters must allow for.

## nginx

Only the shared parts: port 80 for ACME challenges and redirects, and a TLS snippet with the same policy as Postfix and Dovecot. Roles that need a site add it themselves and notify this role's handler.

A catch for sites with basic auth: `return` runs before the access phase, so `return 404` answers without asking for credentials. Such sites use `try_files` instead.

## certbot

`--reuse-key` keeps the private key across renewals, because the DANE TLSA record (`3 1 1`) pins it. Rotating the key is therefore a deliberate step. A changed list of names reissues the certificate with the same key.

The deploy hook reloads the services that use the certificate. It fails if a reload fails, so certbot reports it, and only then writes `/run/sovereign/certbot-deployed`: a new certificate on disk and services actually using it are different things.

One certificate covers all names and all domains. That is simple and needs no per-domain configuration in Postfix and Dovecot, but its public name list shows which domains share a server. It uses HTTP-01 through nginx, so the names must resolve before the first run.

## maildb

SQLite, with no database server: one file to back up, and no credentials to manage. It mirrors the inventory exactly and reverts manual changes, with one exception: passwords.

Users change their password in Roundcube, so the role cannot simply compare hashes. It stores the hash last taken from the inventory (`inventory_password`) and compares that. A changed hash there means an admin reset, which applies once, so no flag has to be removed afterwards. The rejected alternative was a `reset_password: true` flag, which overwrites the user's password on every run until someone removes it.

**Revoking access ends open sessions.** A database change alone only stops new logins, so the role compares the database with the inventory before syncing and the dovecot role kicks every mailbox whose password is reset, that is removed or disabled, or that loses or changes an app password. Sessions can't be matched to the app password they used, so that last case ends all of the mailbox's sessions.

**The rollback journal is required, not WAL.** In WAL mode every reader must be able to write the `-shm` file, and Postfix and Dovecot only read. Dovecot's defaults (read-write, WAL) would switch the file to WAL, so it is explicitly opened read-only.

**The database has its own directory,** owned by the password service's user (`maildb-passwd`), because SQLite creates its journal next to the database. It must not be `/var/lib/sovereign`: root runs `sync.sql` from there, and write access to that directory would be a way to root.

**Password changes go through a small service,** `sovereign-passwd`, not through Roundcube. Roundcube's password plugin sends the user name, the current and the new password over a local socket only Roundcube's PHP user can open. The service, started by systemd per connection as `maildb-passwd` with no network and a read-only system, checks the current main password against the stored hash and updates only that row, and only if it is still the hash it checked. So a compromised Roundcube can change only passwords it already knows, instead of every account, forwarding and alias. App passwords don't count as the current password. It uses plain SQLite with the rollback journal; Roundcube's database layer would have switched the file to WAL.

Schema changes need a Dovecot restart: Dovecot 2.4.1 fails the first query after one on its open connection.

## mta_sts

Inbound, it serves the policy for each domain. The `_mta-sts` id is derived from the policy's content, so it changes exactly when the policy does.

Outbound, `postfix-mta-sts-resolver` alone is not enough, because it answers any domain with a policy with `secure`, which overrides Postfix's DANE verification, against RFC 8461. So a small socketmap (`sovereign-tls-policy`) sits in front. An authenticated MX set where every host has an authenticated TLSA record Postfix can use: no entry, so Postfix verifies DANE. Otherwise, including mixed MX sets: the resolver's answer. In a mixed set Postfix's DANE level would fall back to unauthenticated TLS for the hosts without TLSA, so the domain's MTA-STS policy, where it has one, is the stronger protection; the DANE hosts are then checked against the policy's names instead. More than 10 MX hosts count as mixed. DNS failures or a resolver that is down: a temporary error, so mail is deferred instead of being sent with weaker protection.

## autoconfig

Static files for Thunderbird's autoconfig and Outlook's autodiscover. Outlook POSTs its request, and nginx refuses POST to static files, so `error_page 405 =200` answers it with the static XML. Generating replies per user would need a script for no real gain.

Apple devices get a configuration profile per domain at `https://autoconfig.<domain>/mail.mobileconfig`. They never fetch it on their own; users open it in Safari. It contains no address, user name or password, so iOS and macOS ask for them on installation and one file serves every user. Its identifiers and UUIDs come from the domain: installing it again replaces the account instead of adding a second one. It is signed with the server certificate, so the device shows it as verified. `sovereign-sign-mobileconfig` signs it from Ansible and, as a certbot deploy hook, after every renewal. A signed file stays as long as it holds the current profile and the current certificate, because signatures differ on every run. nginx maps each autoconfig host name to its file explicitly, so the `Host` header never becomes part of a path. The profile's location sets no headers of its own: an `add_header` there would drop HSTS.

## rspamd

The Debian packages as they are (3.12 and 4.1), since no backport exists and one configuration works for both. Used as a milter, and mail is deferred while it is down rather than passed unfiltered.

There is no ClamAV, because it needs 1 to 1.5 GB of RAM on a server with about 2. An attachment policy rejects executables and scripts, also inside archives and with double extensions, which stops most mail-borne malware at no memory cost. A ClamAV on another host can be configured.

One DKIM key per domain, generated once and never replaced. The web interface is reachable from localhost only, and Debian's default controller password is replaced.

## postfix

Debian's `master.cf` is kept, with the submission service added through `postconf`, because the chroot default differs between Debian 13 and Testing and keeping theirs works for both. Lookup tables use lmdb, since Postfix 3.11 deprecates hash and btree. Mail lookups go through proxymap.

postsrsd 2 comes from `trixie-backports` on Debian 13, whose own 1.x has a different interface. Through the socketmap it rewrites the envelope sender of all foreign mail, also when delivered locally, so `Return-Path` shows the SRS address. That is harmless; its milter mode may be more precise.

## dovecot

Dovecot 2.4's configuration is largely incompatible with 2.3, so the whole configuration is one file written against the 2.4 documentation, and Debian's `conf.d` is not used. Dovecot 2.4 tools use the configuration of the running Dovecot unless given `-c`, which matters during a run.

**App passwords** start with an 8-character id that selects the row, because 2.4 fails a passdb lookup returning several rows. They are refused from loopback, which in practice means from Roundcube: its session password counts as the current password when changing the main password, and an app password must not be enough for that.

**mail_crypt** with one global key pair encrypts message files only. The index cache and the search index hold headers and terms in plaintext, which disk encryption has to cover. A per-user key would protect more only with a design where the server does not always have the key, which conflicts with delivery and search.

**A generic authentication socket** (`auth-external`, group `dovecot-auth`) lets local services check logins by joining the group. Dovecot does not need to know about them, and no role order depends on it.

## radicale

Behind nginx, on its own host name, because it stores data users upload, and that should not share an origin with the webmail.

It has its own small authentication plugin. Both Radicale's built-in `dovecot` type and `python3-radicale-dovecot-auth` send no client address, so Dovecot keeps one auth penalty for all of them: one wrong password from anyone delays every user's login by up to 15 seconds, past their timeout, so a stranger could lock out everybody. They also use the process ID as `CPID`, which must be unique per connection although Radicale uses threads, and the built-in type reads Dovecot 2.4's handshake with a timing-dependent read. The plugin sends `no-penalty`; brute force is handled by Radicale's delay and the fail2ban jail.

Shared collections are created by Ansible and access follows the inventory. Removing one revokes access but keeps the data, since it is user data.

## roundcube

**Roundcube is not trusted.** Mandatory basic auth covers the whole site, so nothing reaches its PHP code without it, and those credentials are not passed to PHP. Nginx runs only the front controller and serves only static files of listed types. Only SHA-512 crypt hashes are accepted for basic auth, because nginx checks them in its event loop on every request, including each static file, and a slow hash would stall it.

PHP runs as its own user, not nginx's `www-data`, and only that user may use the password service. Roundcube has no access to the mail database: password changes go through `sovereign-passwd` (see maildb), which checks the current password. Before that, Roundcube wrote the database directly, so a code execution bug in it could have changed every account; an external review in November 2026 led to the change.

**Its own password driver,** a few lines that pass the request to the password service. Roundcube's own database, by contrast, is left to Debian's dbconfig-common, which also upgrades its schema. Debian's cron job does nothing under systemd, hence the timer.

A wrong password in the webmail can delay other users' webmail logins, because they all reach Dovecot from loopback. This is accepted, since only holders of the basic auth credentials get that far.

## restic

Required by default, so that no server runs without backups by accident. SQLite databases are copied with `.backup` first, because the live files may change while restic reads them. The certificate's key is included because DANE depends on it. The search index is left out: Dovecot rebuilds it, and it holds terms in plaintext.

The repository is only created when restic reports there is none (exit code 10), never on a network or password error. Only exit code 0 counts as success. Exit code 3 means some files could not be read and the snapshot is incomplete; on a live Maildir the usual cause is a message renamed by a flag change, so the backup runs once more, and fails if that doesn't complete either. Metrics record the last attempt and its exit code separately from the last success, and a weekly `restic check` has its own. An earlier version counted exit code 3 as success, which could hide permission or read errors indefinitely.

By default root on the server can delete the backups, since pruning needs that right. `restic_prune_enabled: false` with an append-only target prevents it, but needs a second machine, so it is not the default.

A disaster recovery restores first and then runs the playbook. In the other order, the playbook generates new keys.

## unattended_upgrades

Security updates, on Debian 13 also for packages from backports, as postsrsd is one. Automatic reboots are opt-in, because a server with an encrypted disk then waits for a remote unlock.

**Security support status.** `sovereign-support-status` runs weekly and once at setup. It asks `check-support-status` (debian-security-support) which installed packages Debian's security team no longer fully supports, lists them in the journal and exports the counts per type (ended, early end, limited). It removes nothing. `check-support-status` always exits 0, so the script reads its output. `debsecan` is not used: it lists every open CVE, far too many to act on. What the check can't see: Go programs (restic, prometheus-node-exporter) are only rebuilt in point releases, because Debian's list names the `golang-*` libraries rather than the programs built from them, and postsrsd from `trixie-backports` is outside the security team's support altogether.

**isc-dhcp-client** lost its security support in 2023. Debian 13 installs `dhcpcd-base` instead, but servers upgraded from Debian 12 still carry it, and so do the incus test images. The role removes it only when nothing uses it: no `dhclient` running, no DHCP in `/etc/network/interfaces` without `dhcpcd-base` to take over, and nothing else removed with it. Removing the client that holds the lease would cut a remote server off at the next renewal. "Manually installed" and "systemd-networkd present" say nothing here: debootstrap marks the whole base system as manual, and networkd is part of the systemd package.

## systemd_timers

Replaces cron. Jobs come from the inventory (`systemd_timers_jobs`) and from other roles (restic's), and timers no longer listed are removed, which cron files would not do.

## node_exporter

Without the package's recommends, which add hardware collector timers that fail on many hosts. Dovecot's own OpenMetrics endpoint covers mail metrics instead of mtail, because there are no syslog files to tail, and the Debian Postfix exporter differs widely between the releases. The textfile directory carries the time of the last successful backup.

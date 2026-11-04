# Modernization status

Working notes for the Debian 13 / Testing rebuild of Sovereign (branch
`trixie-wip`). Updated with every step; the commit messages have the details.
The plan itself, with the decisions worked in, is [PLAN.md](PLAN.md).

Last update: Phase 2.5 complete (MTA-STS, autoconfig/autodiscover, outbound
MTA-STS with DANE precedence), verified locally; CI confirmation for 2.4 and
2.5 pending. Next: 2.6 (Roundcube, Radicale).

## Phases

| Phase | State | Notes |
|---|---|---|
| 0 Foundation | done | Molecule + incus, scenarios `trixie` and `testing`, GitHub Actions |
| 1 Bloat removal | done | non-mail roles, EncFS, Tarsnap, ufw, Vagrant, legacy tests removed |
| 2.1 Base system | done | nftables, fail2ban (journald), unattended-upgrades, systemd timers, node exporter |
| 2.2 Unbound | done | DNSSEC-validating resolver, `trust-ad` in resolv.conf |
| 2.5 core (moved ahead) | done | nginx (ACME on port 80), certbot with `--reuse-key` |
| 2.3 Mail transport | done (CI green on trixie) | SQLite mail DB, Postfix, Dovecot 2.4, postsrsd |
| 2.4 Rspamd | done (CI pending) | milter, DKIM/ARC, rate limit, attachment policy, IMAPSieve learning |
| 2.5 rest | done (CI pending) | MTA-STS policy, autoconfig/autodiscover, outbound MTA-STS with DANE precedence (`sovereign-tls-policy`) |
| 2.6 Webmail/groupware | next | Roundcube, Radicale |
| 2.7 Backups | open | Restic |
| 3 GitOps admin | partly done | `maildb` already mirrors the inventory exactly (incl. removals) |
| 4 Extended tests | open | DANE, disaster recovery, scheduled testing run |
| 5 Documentation | open | README rewrite, DNS/ports cheat sheets, migration guide |

## Roles in `site.yml` (in order)

preflight, unbound, nftables, fail2ban, nginx, certbot, maildb, mta_sts,
autoconfig, rspamd, postfix, dovecot, unattended_upgrades, systemd_timers,
node_exporter.
The legacy roles `common`, `mailserver` and `webmail` are no longer run and
will be deleted once replaced.

## Decisions (beyond the plan)

| Topic | Decision | Why |
|---|---|---|
| Mail database | SQLite (not PostgreSQL) | no extra daemon, no DB credentials, one file to back up |
| App passwords | 8-character id prefix + secret, e.g. `PhOnE001-...` | Dovecot 2.4 fails a passdb lookup that returns several rows |
| Password hashes | Argon2id only (`doveadm pw -s ARGON2ID`) | |
| Antivirus | no ClamAV; Rspamd attachment policy (executables/scripts rejected, also in archives and with double extensions); optional remote ClamAV | ClamAV needs ~1-1.5 GB RAM, too much for a 2 GB server |
| Rspamd | Debian packages as they are (3.12 on 13, 4.1 on Testing) | no backport exists; same config works for both |
| postsrsd | 2.x from `trixie-backports` on Debian 13 | Debian 13 ships 1.x with a different interface; Testing has 2.x |
| Mail exporters | Dovecot's own OpenMetrics endpoint (port 9900) instead of mtail | no syslog files on Debian 13; Postfix exporter differs widely between releases |
| Rspamd web UI | localhost only (SSH tunnel), Debian's default password `q1` replaced by a random hash | |
| Outbound MTA-STS | small socketmap shim: DANE (TLSA via DNSSEC) first, else postfix-mta-sts-resolver | the resolver alone lets MTA-STS override DANE (against RFC 8461) |
| User admin | Ansible mirrors `group_vars`; password self-service still open | see "Open" |
| Target hardware | 2 GB RAM | FTS indexer limited to one process |

## Findings worth knowing

- mail_crypt encrypts message files only; Dovecot's index cache and the FTS
  index contain header fields/terms in plaintext. Disk encryption (LUKS)
  covers those.
- Dovecot treats connections from its own address as secure (plaintext login
  allowed), so login tests must run from another host.
- Dovecot's SQLite defaults (read-write, WAL) break Postfix's read-only
  access; Dovecot opens the DB read-only, the schema forces journal mode
  DELETE.
- Dovecot 2.4 tools (sievec, doveadm) take the configuration of the running
  Dovecot unless `-c` is given.
- With the full configuration, Dovecot 2.4.5 tools refuse to act as the vmail
  system user if its UID is below `first_valid_uid` (default 500); the role sets
  first/last_valid_uid to exactly that UID. System UIDs differ between hosts
  (999 in the chroots, 101 in CI).
- Debian Testing changed Postfix's chroot default (13: chroot, Testing: none);
  the role keeps Debian's master.cf and only adds the submission service.
- OpenSSH >= 10.1 throttles failed logins itself ("drop connection ...
  penalty"); the fail2ban role counts those lines too.
- postsrsd via socketmap rewrites the envelope sender of all foreign mail,
  also when delivered locally (Return-Path shows the SRS address). Harmless,
  but postsrsd 2's milter mode may be more precise: to check.
- Outbound MTA-STS: `sovereign-tls-policy` (roles/mta_sts) answers Postfix's
  TLS policy lookups. Authenticated MX + TLSA: no entry (Postfix verifies
  DANE); otherwise postfix-mta-sts-resolver's answer; DNS failure or resolver
  down: TEMP (mail deferred, not sent with weaker protection).
- nginx refuses POST to static files (405); autodiscover uses
  `error_page 405 =200` to answer Outlook's POST with the static XML.
- The MTA-STS policy id (`_mta-sts` TXT record) is derived from the policy
  content and written to /var/lib/sovereign/mta-sts-id.
- Molecule expands `$VAR` in its configuration: dollar signs in hashes are
  doubled in `.config/molecule/config.yml`; `molecule list` in CI catches it.

## Open

- CI confirmation for Phase 2.4 (`sievec -c` fix) and 2.5.
- Password self-service (users changing their own passwords / app
  passwords) vs. Ansible as the only writer: decide before Phase 3 is closed.
- postsrsd milter mode (see findings).
- Unbound: systemd-resolved is masked when present; check on real servers.
- Role design documents: CONTRIBUTING.md asks for one per role; the new roles
  have none yet (decide in Phase 5).

## Testing

- CI: `.github/workflows/ci.yml` (lint, `molecule list`, Molecule matrix).
- Locally (no incus needed) every role is also checked in Debian 13 and
  Testing debootstrap chroots with the role templates: configuration checks
  (`doveconf`, `postfix check`, `rspamadm configtest`, `nft --check`, ...)
  and end-to-end runs of the mail stack in network namespaces. These scripts
  are not part of the repository yet.

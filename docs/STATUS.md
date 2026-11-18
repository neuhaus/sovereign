# Modernization status

Working notes for the Debian 13 / Testing rebuild of Sovereign (branch
`trixie-wip`). Updated with every step; the commit messages have the details.
The plan itself, with the decisions worked in, is [PLAN.md](PLAN.md).

Last update: Phases 0-5 complete, including password reset, multiple mail domains
and append-only backups, plus the `openssh` role (key logins only), the
`timesyncd` role (`ntp_servers`) and `docs/ROLES.md`. Since then, Phase 5.5
(operational readiness, from the review in [KRITIK.md](KRITIK.md)) steps 1-3.

Results of Phase 5.5 (2026-11-12), Debian 13 only so far:

| Run | Debian 13 | Testing |
|---|---|---|
| Local, containers, at `fb3d033` | 276 passed, 2 failed | converge fails: no `restic` package |
| Local, `mail` as a 2 GiB VM, at `fb3d033` | 276 passed, 2 failed | converge fails: no `restic` package |
| Local, VM, follow-up fixes: converge, idempotence, 32 affected tests | passed | not run |

The two failures (password service on Debian 13's argon2-cffi, migration guide)
are fixed in the follow-up commits, as are three findings from reviewing the
Phase 5.5 code (wrong passwords answered late, pending revocations survive an
interrupted run, backup attempt recorded on every exit). The migration test also
found that the final `sync -1 -R` without sync state silently skips mail that
arrived on both sides after the switch; the guide now keeps the state. A full run
on both releases is still due; Testing waits for restic (below).

Results at `e97fe72`, before Phase 5.5:

| Run | Debian 13 | Testing |
|---|---|---|
| CI (containers) | passed | passed |
| Local, containers | 263 passed | 263 passed |
| Local, `mail` as a 2 GiB VM | 263 passed | **262 passed, 1 failed** |

Converge and idempotence passed in all of these. The VM failure on Testing has a
fix, still to be tested on Testing (see below).
Not yet run on a real server. Next: a full test run on Debian 13 (Testing once
restic is back), then steps 4 and 5 of Phase 5.5, then Phase 6 (split setup).
Step 4 now also covers the security support status (`check-support-status`,
upstream issue #550).

## Phases

| Phase | State | Notes |
|---|---|---|
| 0 Foundation | done | Molecule + incus, scenarios `trixie` and `testing`, GitHub Actions |
| 1 Bloat removal | done | non-mail roles, EncFS, Tarsnap, ufw, Vagrant, legacy tests removed |
| 2.1 Base system | done | nftables, fail2ban (journald), unattended-upgrades, systemd timers, node exporter |
| 2.2 Unbound | done | DNSSEC-validating resolver, `trust-ad` in resolv.conf |
| 2.5 core (moved ahead) | done | nginx (ACME on port 80), certbot with `--reuse-key` |
| 2.3 Mail transport | done | SQLite mail DB, Postfix, Dovecot 2.4, postsrsd |
| 2.4 Rspamd | done | milter, DKIM/ARC, rate limit, attachment policy, IMAPSieve learning |
| 2.5 rest | done | MTA-STS policy, autoconfig/autodiscover, outbound MTA-STS with DANE precedence (`sovereign-tls-policy`) |
| 2.6 Webmail/groupware | done | Roundcube behind mandatory basic auth, Radicale, password self-service |
| 2.7 Backups | done | Restic: daily backup, weekly prune, restore tested through Dovecot, success metric, optional append-only target |
| 3 GitOps admin | done | `maildb` mirrors the inventory, keeps passwords changed by users, a new hash resets; several mail domains |
| 4 Extended tests | done | DANE, disaster recovery onto an empty instance, weekly run against Testing |
| 5 Documentation | done | README, `docs/ADMINISTRATION.md`, `docs/INSTALL.md`, `docs/BACKUP.md`, `docs/MIGRATION.md`, `docs/ROLES.md` |
| 5.5 Operational readiness | in progress | steps 1-3 done, tested on Debian 13: migration guide fixed (`imapc:` location, `sync -1 -R`) and `test_migration.py`; backups fail on incomplete snapshots, export last attempt/exit code, weekly `restic check`; one revocation path ending Dovecot sessions; quotas enforced (`quota_mb`); certbot hook fails on failed reloads; SSH key and `sshd -T` checks; DANE over MTA-STS only if every MX has usable TLSA; password service `sovereign-passwd` instead of Roundcube writing the DB; CI pinned (`constraints.txt`, `.github/collections-ci.yml`). Open: step 4 (pilot on Debian 13), step 5 (optional roles) |
| 6 Split setup | open | VPS gateway + home server over WireGuard; first check what the OpenVZ VPS allows (DNAT) |

## Roles in `site.yml` (in order)

preflight, logging, openssh, timesyncd, unbound, nftables, fail2ban, nginx, certbot, maildb, mta_sts,
autoconfig, rspamd, postfix, dovecot, radicale, roundcube, restic,
unattended_upgrades, systemd_timers, node_exporter.

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
| User admin | Ansible mirrors `group_vars`; users change their own main password in Roundcube; a new hash in the inventory resets it once and kicks open sessions; app passwords admin-only | no flag to clean up afterwards |
| Webmail exposure | mandatory HTTP basic auth in front of Roundcube; the credentials are not passed to PHP | Roundcube is not trusted, users in general are |
| Password changes | Roundcube asks `sovereign-passwd` (socket-activated, `/run/sovereign-passwd.sock`, group `sovereign-passwd`), which checks the current password and writes only that account's hash | a compromised Roundcube can no longer rewrite every account; Roundcube has no database access (Phase 5.5) |
| Quotas | Dovecot quota plugin, `quota_storage_size` from `quota_mb` in the userdb, `imap_quota` | the option existed but was not enforced |
| Supported releases | Debian 13 is the target; Testing is an early warning, fixed but not release-blocking | Phase 5.5 |
| Basic auth hashes | SHA-512 crypt only | nginx verifies in its event loop on every request; slow hashes would stall it |
| App passwords in webmail | refused from loopback by Dovecot | Roundcube accepts the session password as "current password"; an app password must not be enough to change the main password |
| Radicale auth | own plugin `sovereign_radicale_auth` | see findings; neither the built-in type nor `python3-radicale-dovecot-auth` is usable |
| Dovecot auth socket | `/run/dovecot/auth-external`, group `dovecot-auth`, mode 0660 | services join the group; Dovecot need not know them, and no role order depends on it |
| Backups required | the restic role fails without repository and password | no server without backups by accident; to be revisited with the optional roles |
| Mail database location | `/var/lib/sovereign/maildb/`, owned by the password service's user `maildb-passwd` (previously `roundcube`, removed from the database group on upgrade) | the rollback journal needs a writable directory, and root runs scripts from `/var/lib/sovereign` |
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

- Dovecot 2.4 requires `dovecot_config_version` as the first setting of every
  file it reads, also one that only adds to `!include /etc/dovecot/dovecot.conf`.
- `doveadm backup` copies the source's UIDVALIDITY and UID numbering. Without
  sync state, a later `sync -1 -R` sees the same UID on both sides with
  different messages and keeps the local one; the remote message is silently
  skipped, exit code 0. With the state from the first run (`-s`) both are kept.
- argon2-cffi 21.1 (Debian 13) has `exceptions.InvalidHash`, renamed
  `InvalidHashError` in 23.1.

- Roundcube's database layer sets `journal_mode = WAL` on every SQLite
  connection. Pointed at the mail database, it would break Postfix and Dovecot,
  so the old password driver used plain PDO. Since Phase 5.5 the driver only
  talks to `sovereign-passwd` and never opens the database.
- Dovecot's auth penalty is keyed by client address. Radicale's logins carry
  none, so they share one penalty: a single wrong password delayed every user's
  next login by up to 15 seconds, past the 5 second timeout of Radicale's
  built-in client. The plugin sends `no-penalty` and a per-thread CPID, and
  speaks Dovecot 2.4's handshake (the server waits for the client's VERSION).
- nginx `return` runs before the access phase, so it answers without basic
  auth; the webmail's catch-all uses `try_files` instead.
- fail2ban's journal backend prefixes lines with `host unit[pid]:`; own filters
  need `%(__prefix_line)s`.
- Debian 13 ships `/var/lib/radicale/collections` owned by root (Testing: by
  radicale); the role sets the owner.
- Debian's Roundcube cron job does nothing under systemd; the role has a timer.
- Dovecot 2.4.1 (Debian 13, not 2.4.5) fails the first query after a schema
  change on its open SQLite connection ("SQL logic error"); schema migrations
  must restart it. Ordinary writes are not affected.
- Settings live in `inventory/group_vars/`, not `group_vars/` next to `site.yml`:
  playbook-adjacent variables take precedence over Molecule's inventory and
  would silently change what the tests run with.
- Several mail domains share one certificate, so its name list shows which
  domains share a server. Unlinkable domains would need separate certificates or
  servers; not planned.
- `restic restore` exits with an error when the target has security labels the
  snapshot lacks (SELinux), although all data arrived; a recovery uses
  `--exclude-xattr 'security.*'`.
- Molecule finds `.config/molecule/config.yml` via the VCS root: without `.git`
  it silently ignores it and reports "Missing playbook".

## Open

- **restic is not in Debian Testing** (November 2026): 0.19.1-1 is blocked from
  migrating ("unsatisfiable Built-Using on golang-github-cespare-xxhash"), so
  the Testing scenario fails at converge and none of its tests run. A Debian
  packaging matter, not ours; Testing is an early warning only. Decided
  (2026-11-12): wait for it to return to Testing instead of installing it from
  unstable; CI's Testing job fails until then.

- Roundcube connects from loopback, so all webmail logins share one Dovecot auth
  penalty: a wrong password can delay other users' webmail logins by up to 15
  seconds. Accepted for now, since only holders of the basic auth credentials
  get that far.
- To document in Phase 5: password reset via a new hash (the user should change
  the temporary password; a reverted hash resets again; app passwords stay valid
  until removed), `roundcube_basic_auth_users` (required), the `dav.<domain>` record.
- **Failing on Testing as a VM:** `test_no_failed_units` finds the system degraded,
  because `systemd-resolved-varlink.socket` failed: "Unit systemd-resolved.service
  is masked". systemd 262 in Testing adds this socket and
  `systemd-resolved-monitor.socket`; the `unbound` role masked only the service.
  Debian 13 (systemd 257) has no varlink socket. Fix written, not yet tested: the
  role now masks all `systemd-resolved*` sockets and clears earlier failures.
  CI doesn't catch this, as it runs containers only. A VM run
  of the older code, before `openssh` and `timesyncd`, passed earlier the same day;
  why is not known.
- Nothing has run on a real server yet, only in containers and VMs. To check there: LUKS
  remote unlock, the migration guide, certificates from Let's Encrypt.
- Shared mail folders: not scheduled, see "Later" in [PLAN.md](PLAN.md).
- Make roundcube, radicale and restic optional (`*_enabled`, decided, deferred).
  A `when:` on the role is not enough: its public defaults still reach other
  roles (restic's timers, the Roundcube database in the backup), and disabling
  must also remove what is already there, above all Roundcube's nginx site and
  PHP-FPM, which can write the mail database. Fresh installs with a role disabled
  need the disabled path to work when nothing was ever installed.
- postsrsd milter mode (see findings).
- Unbound: systemd-resolved is masked when present; check on real servers.

## Testing

- CI: `.github/workflows/ci.yml` (lint, `molecule list`, Molecule matrix), and
  weekly against Testing once on the default branch.
- VM check by hand, not in CI: with `mail` created with `incus init --vm`, 2 GiB of
  RAM, all tests pass on both releases, with about 1.1-1.2 GB available afterwards
  (a snapshot after the tests, not a peak, and without real mail volume).
- Where direct DNS to the internet is blocked, Unbound cannot recurse: after
  `molecule prepare`, add a `.` forward zone in the instance's
  `/etc/unbound/unbound.conf.d/` (test only, not part of the roles).
- Locally (no incus needed) every role is also checked in Debian 13 and
  Testing debootstrap chroots with the role templates: configuration checks
  (`doveconf`, `postfix check`, `rspamadm configtest`, `nft --check`, ...)
  and end-to-end runs of the mail stack in network namespaces. These scripts
  are not part of the repository yet.

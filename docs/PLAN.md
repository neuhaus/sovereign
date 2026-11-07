# Sovereign Modernization Plan: Debian 13 & Testing

> Living document. Decisions made during implementation are worked into the
> phases below and collected in the [Decisions](#decisions) table. Progress
> and open points: [STATUS.md](STATUS.md).

## Objective

Transform the legacy [Sovereign](https://github.com/sovereign/sovereign) mail/cloud stack into a highly secure, bare-metal, low-maintenance email server targeting Debian 13 (Trixie) and Debian Testing (Forky). The new architecture relies on official Debian packages (including `trixie-backports` where a release gap would otherwise force two configurations), modern Ansible collections, native systemd integration, and a self-contained CI pipeline on GitHub Actions that needs nothing beyond the stock Ubuntu runner plus incus.

Target hardware: a small server with about 2 GB RAM. Defaults are chosen to fit (no ClamAV, one FTS indexer process, capped Redis memory).

## Guiding Principles

- **Test harness first, tests grow with the code.** No new role is "done" until its tests are green in CI.
- **No tests for the legacy stack.** Almost all of it is deleted; effort goes into testing the new architecture only.
- **New code is written in the target style from day one** (FQCNs, lint-clean, validated handlers), so there is no separate migration pass later.
- **Debian 13 ships Dovecot 2.4**, whose configuration format is largely incompatible with 2.3. All Dovecot work is written against the 2.4 documentation, not the old Sovereign templates.
- **Both releases from one configuration.** Where Debian 13 and Testing differ (Postfix chroot default, postsrsd major version, Rspamd 3.x/4.x), the roles either work for both or pick the variant per release; CI tests both.
- **Verify locally before CI** where possible: role templates are checked with the real Debian tools in Debian 13 and Testing chroots.

---

## Phase 0: Foundation (Ansible Baseline & Test Harness)

Build the scaffolding every later phase depends on.

### 0.1 Ansible Baseline

- Require **Ansible Core >= 2.15**.
- Enforce **ansible-lint** (production profile) and **yamllint** in CI from the first commit.
- **FQCNs** for all new or touched code (e.g. `ansible.builtin.apt`, `ansible.builtin.template`).
- **Fact-based targeting:** derive apt sources and version-specific logic from the `sovereign_debian_track` fact (`trixie` or `testing`, set by the `preflight` role) and fail early on any other release.
- **Handler convention:** every handler that restarts a service validates the configuration first (e.g. `postfix check`, `doveconf -n -c /etc/dovecot/dovecot.conf`, `nginx -t`, `nft -c -f /etc/nftables.conf`, `unbound-checkconf`, `rspamadm configtest`).

### 0.2 Test Harness (Molecule + incus)

- **Molecule** with the default (delegated) driver: `create.yml` / `destroy.yml` launch **incus system containers**, connection via the `community.general.incus` connection plugin. Full systemd, no nested virtualization required (Vagrant is dropped).
- Two scenarios: `trixie` and `testing`.
- **Test network:** one incus bridge with three instances:
  - `mail` – the system under test.
  - `pebble` – local ACME server (Pebble) for certificate issuance without rate limits.
  - `dns` – authoritative mock DNS (Knot) for the test domain (MX, SPF, DMARC, MTA-STS, TLS-RPT records), DNSSEC-signed test zones, and a foreign test domain whose MX is an SMTP sink. Test clients run here, so the system under test sees connections from another address.
- The test domain is resolved by the mail server's Unbound via a stub zone pointing at `dns`. The Pebble root CA is trusted on `mail` **only in `prepare.yml`**, never in production roles.
- **CI provider: GitHub Actions** on the standard Ubuntu runners. The workflow installs incus, initializes it non-interactively, and runs the Molecule scenarios as a matrix (`trixie`, `testing`).
- **Pipeline gates:** lint (yamllint, ansible-lint, `molecule list`) → converge → idempotence → verify (pytest/testinfra). On failure the job prints failed units, their journals and fail2ban bans.

**Done when:** an empty playbook converges on both scenarios in CI, and Pebble and the mock DNS are reachable from `mail`. *(done)*

---

## Phase 1: Bloat Removal & Attack Surface Reduction

Strip the repository of all non-mail components to reduce maintenance overhead.

- **Delete legacy cloud roles:** owncloud / nextcloud, selfoss, wallabag, cgit, blog.
- **Delete legacy chat/VPN roles:** prosody, znc, openvpn.
- **Delete deprecated system roles:** encfs, tarsnap, iptables, ufw, cron, monit/collectd/logwatch. *(Replacements for firewall, task scheduling and monitoring are written from scratch in Phase 2.1.)*
- **Delete legacy mail components:** dspam, amavis, opendkim, opendmarc, postgrey, spamassassin.
- **Delete legacy tooling:** Vagrant files and fixtures, legacy tests, filter plugins.
- Remove all related variables, templates, handlers and documentation references.

**Done when:** lint, converge and idempotence are still green. *(done)*

---

## Phase 2: Core Architecture Modernization (Role by Role)

Replace legacy components with modern, BSI TR-03108 compliant alternatives using native Debian 13 packages. Each step ships together with its tests. TLS everywhere: TLS 1.2/1.3, ECDHE with AES-GCM, curves P-256/P-384 (BSI TR-02102-2).

Implementation order: 2.1, 2.2, the certificate part of 2.5, 2.3, 2.4, rest of 2.5, 2.6, 2.7 (Postfix and Dovecot need the certificate from the start). Current state per phase: [STATUS.md](STATUS.md).

### 2.1 Security & Base System

- **Firewall:** nftables role. `/etc/nftables.conf` allows TCP 22, 25, 80, 143, 443, 587, 993 and 4190, dropping everything else. Only Sovereign's own table is replaced on reload, so fail2ban's table and bans survive.
- **Task scheduling:** systemd-timers role replacing all cron functionality (timers no longer defined are removed).
- **Intrusion prevention:** Fail2ban with the systemd backend (journald), nftables ban actions; jails for sshd, Postfix (aggressive mode) and Dovecot. The sshd filter also counts OpenSSH's own penalty drops (OpenSSH >= 10.1).
- **Updates:** unattended-upgrades for automated security patches (on Debian 13 also for packages installed from backports); automatic reboot is opt-in because of the LUKS remote unlock.
- **Monitoring:** Prometheus Node Exporter (without the hardware collector timers) and **Dovecot's built-in OpenMetrics endpoint** (auth successes/failures, deliveries) instead of mtail: Debian 13 has no syslog files to tail, and the Debian Postfix exporter differs widely between the releases.
  - Exporter ports (9100, 9900) are opened **only for the monitoring host(s)** via a source-restricted nftables rule. The allowed source addresses (IPv4 and IPv6) come from `monitoring_sources`; if the list is empty, no rule is rendered and the ports stay closed.

**Tests:** allowed ports reachable from a second instance, all other ports closed; exporter ports reachable from an instance listed in `monitoring_sources` and closed for any other source; Fail2ban jails active with systemd backend and an SSH attacker actually banned via nftables (surviving an nftables reload); unattended-upgrades timer enabled; exporters respond locally. *(done)*

### 2.2 DNS Resolver

- **Unbound** as a local DNSSEC-validating resolver on 127.0.0.1. systemd-resolved is masked when present; `/etc/resolv.conf` points at Unbound with `options trust-ad` (otherwise glibc drops the AD flag that Postfix needs for DANE).

**Tests:** resolution of the test domain via the stub zone; DNSSEC validation sets the AD flag on a signed zone (mock zone and a real internet zone) and returns SERVFAIL for a deliberately broken one. *(done)*

### 2.3 Mail Transport (Postfix & Dovecot 2.4)

- **Mail database: SQLite** (one file, no database server; Ansible and, for password changes, Roundcube are the only writers). Postfix reads it through proxymap, Dovecot read-only; rollback journal (WAL would require write access for every reader).
- Dovecot authentication with **Argon2id** password hashes. **App-Specific Passwords** start with an 8-character id (`PhOnE001-...`): Dovecot 2.4 fails a passdb lookup that returns several rows, so the app password row is selected by that prefix and its hash verified as usual.
- Enforce **TLS 1.2/1.3**, **DANE** (outbound) and strong ECDHE ciphers in Postfix and Dovecot.
- **At-rest encryption:** Dovecot mail_crypt with a globally generated EC keypair encrypting all Maildir message files. *(Dovecot's index cache and the FTS index keep header fields and terms in plaintext; their protection relies on LUKS.)*
- **Full-text search:** fts-flatcurve (Xapian; Debian package `dovecot-flatcurve`), autoindexing on delivery, Junk and Trash excluded, one indexer process with a memory limit.
- **SRS:** postsrsd 2 (socketmap), on Debian 13 from `trixie-backports` (Debian 13 ships 1.x with a different interface).
- **Plus-addressing:** sub-addressing with `+` as delimiter in Postfix and Dovecot.
- Dovecot listens on 143 (IMAP + STARTTLS) and 993 (IMAPS). Cleartext authentication without TLS is refused (`auth_allow_cleartext = no`). Submission (587) requires STARTTLS and SASL; the sender address must belong to the login or an alias pointing to it.
- Debian's `master.cf` is kept (its chroot default differs between Debian 13 and Testing); the submission service is added with `postconf`. Lookup tables use lmdb (Postfix 3.11 deprecates hash/btree).
- All Dovecot settings (SQL auth, mail_crypt, FTS, IMAPSieve, sub-addressing) are verified against the **Dovecot 2.4 documentation** and the real `doveconf` of both releases.

**Tests:**
- Submit mail via SMTP on 587 with STARTTLS and authentication (main and app password); foreign sender address rejected.
- Retrieve via IMAPS (993) and IMAP+STARTTLS (143).
- Login on 143 **before** STARTTLS is refused (tested from another host).
- TLS 1.0/1.1 handshakes are rejected on all mail ports, 1.2/1.3 accepted.
- Login with main password and with an App-Specific Password (both Argon2id).
- Mail to `user+tag@domain` is delivered to `user`; no open relay.
- Message files in the Maildir are not readable as plaintext (mail_crypt active).
- FTS search returns a freshly delivered message.
- A forwarded mail carries an SRS-rewritten envelope sender (checked at an SMTP sink).
- The ACME certificate is served on 25, 587, 993 and 4190.

### 2.4 Anti-Spam (Rspamd)

- **Rspamd** (Debian packages as they are: 3.12 on Debian 13, 4.1 on Testing; no backport exists, one configuration works for both) handles spam filtering, DKIM, ARC, SPF and DMARC, as Postfix milter (mail is deferred while Rspamd is down).
- **DKIM/ARC signing** with one 2048-bit key per mail domain; the TXT record to publish is stored next to the key.
- **Outbound rate limiting:** ratelimit module restricts outgoing mail volume per authenticated user.
- **Attachment policy instead of ClamAV** (ClamAV needs about 1-1.5 GB RAM): executables and scripts are rejected, also inside archives and with double extensions. ClamAV on another host can be configured optionally.
- Dovecot **IMAPSieve** pipes mails moved to/from "Junk" into Rspamd for global Bayes learning (Redis, memory-capped).
- The Rspamd web UI is reachable from localhost only (SSH tunnel); Debian's default controller password is replaced.

**Tests:** inbound mail carries Rspamd headers; dangerous attachments are rejected; outbound mail carries a valid DKIM signature (verified against the generated TXT record) and an ARC seal, and no scan headers; exceeding the rate limit causes deferral; moving a mail to Junk trains it as spam.

### 2.5 Web Endpoints, Certificates & MTA-STS

- **certbot** (Debian package) for certificate issuance *(implemented before 2.3)*:
  - HTTP-01 challenge via the Nginx webroot on port 80.
  - `--reuse-key` so the private key stays stable across renewals and the DANE TLSA record (`3 1 1`) remains valid; key rotation becomes a deliberate, documented step. A changed list of names reissues the certificate with the same key.
  - Deploy hook reloads Nginx, Postfix and Dovecot after renewal.
  - Renewal runs via the systemd timer shipped by the Debian package.
  - In Molecule, certbot points at Pebble via `--server`.
- **Nginx** serving:
  - the MTA-STS policy file,
  - static `mailconfig.xml` (`.well-known/autoconfig`) and `autodiscover.xml` (`/autodiscover`) templates.
- **Outbound MTA-STS:** postfix-mta-sts-resolver behind a small socketmap that gives **DANE precedence** (RFC 8461 section 2): if the destination's MX and TLSA records are DNSSEC-authenticated, Postfix's DANE verification applies; otherwise the MTA-STS policy is used. DNS failures and an unreachable resolver defer the mail. (The resolver alone lets MTA-STS override DANE.)

**Tests:** certificate issued by Pebble and used by Nginx, Postfix and Dovecot; a forced renewal keeps the same public key and triggers the reload hook; MTA-STS policy, Autoconfig and Autodiscover (also via POST) served with correct content; the resolver returns the policy for the test domain; DANE takes precedence for a domain with authenticated TLSA records, and a DNSSEC-bogus domain is deferred.

### 2.6 Webmail & Groupware

- **Roundcube** with the Elastic theme and the ManageSieve and password plugins; its own SQLite database (preferences, contacts, sessions), managed by Debian's dbconfig-common. Debian's cron job does nothing under systemd, so a timer runs its maintenance.
  - **Mandatory HTTP basic auth** in front of the whole site (nginx, `roundcube_basic_auth_users`): Roundcube is not trusted, so nothing reaches its PHP code without it. Users in general are trusted. Roundcube never sees these credentials. Failed attempts go to the `nginx-http-auth` jail.
  - PHP runs as its own user, not as nginx's `www-data`, because that user can write the mail database.
  - App-Specific Passwords are refused from loopback, i.e. in the webmail: Roundcube accepts the session password as the current password when changing the main password, and an app password must not be enough for that.
- **Radicale** for CalDAV/CardDAV on its own host name (`dav.<domain>`), authenticating against Dovecot over a local socket with a small plugin of its own (`sovereign_radicale_auth`): both Radicale's built-in type and `python3-radicale-dovecot-auth` share one Dovecot auth penalty among all users, so a single wrong password could lock everybody out. Main and App-Specific Passwords work. Shared calendars and address books (`radicale_shared_collections`) are created by Ansible, and the rights file follows the variables exactly; removing an entry revokes access and keeps the data.
- Web logins reach Dovecot from loopback, out of reach of its jail: Roundcube and Radicale have fail2ban jails of their own.

**Tests:** nothing reachable without basic auth; Roundcube login page and its assets served via HTTPS, internal files not; app password refused in the webmail; sending through the webmail; filter settings reach ManageSieve; ManageSieve (4190) accepts STARTTLS and authentication; authenticated CalDAV/CardDAV PROPFIND succeeds, unauthenticated fails; a shared calendar defined in group_vars is accessible to the intended users only; repeated failed logins are banned in all three jails; a wrong password does not delay other users' CalDAV logins; parallel CalDAV logins work.

### 2.7 Backups (Restic)

- **Restic** for encrypted offsite backups; `restic_repository` and `restic_password` are required, so no server runs without backups by accident.
- **systemd timers/services** (through the `systemd_timers` role) for daily backups and weekly retention pruning.
- Backed up: `/var/vmail`, consistent copies of the mail and Roundcube databases, the mail_crypt keys, DKIM keys, Radicale data, `/etc/letsencrypt` (DANE depends on the key) and the postsrsd secret. Not backed up: the FTS index, which Dovecot rebuilds, and Rspamd's Bayes data.
- The time of the last successful backup is a node exporter metric (`sovereign_backup_last_success_timestamp_seconds`), for alerting on backups that stop.

**Tests:** backup to a local test repository succeeds and contains the keys and databases; restoring a mailbox and reading it back through Dovecot (including mail_crypt decryption) succeeds; the restored mail database is intact; pruning works; the metric is exported.

---

## Phase 3: Declarative Mail Administration (GitOps)

- The `maildb` role (written in Phase 2.3) acts strictly on `group_vars/mailservers.yml`: `mail_domains`, `mail_mailboxes` (with `app_passwords`) and `mail_aliases`.
- Domains, mailboxes, App-Specific Passwords and aliases **precisely mirror** the code state, including removal of entries no longer defined; manual changes in the database are reverted on the next run.
- **Password self-service:** users change their own main password in Roundcube (password plugin). Ansible sets the initial password hash when it creates a mailbox and does not touch it afterwards; everything else (domains, mailboxes, aliases, App-Specific Passwords) stays exactly mirrored. Roundcube therefore gets write access to the mail database (only it and Ansible write); App-Specific Passwords remain admin-managed via `group_vars`.
- **Password reset:** a new hash for a mailbox in the inventory replaces the password once, also one the user changed, and disconnects the user's open sessions. The database remembers the hash last applied (`inventory_password`), which is what the role compares; there is no flag to remove afterwards.
- The database has its own directory, owned by Roundcube's PHP user, for the rollback journal; root's scripts stay in a directory only root can write. A small password driver opens the database with plain PDO, because Roundcube's database layer switches SQLite databases to WAL on connect.

**Tests:** adding, changing and removing users, aliases and App-Specific Passwords in the variables is reflected in the database; a password changed by the user survives the next Ansible run; a new hash in the inventory resets it and ends open sessions; a second run reports no changes; a removed user can no longer log in.

---

## Phase 4: Extended Test Scenarios

Scenarios that are expensive to set up and therefore come after the core stack is stable.

- **DANE:** DNSSEC-signed mock zone with TLSA records, custom trust anchor in Unbound; verify Postfix outbound DANE verification succeeds for a correct TLSA record and fails for a wrong one.
- **Full disaster recovery:** provision a fresh instance, restore `/var/vmail`, the database and the mail_crypt keys from Restic, and verify mail is readable.
- **Scheduled testing run:** weekly GitHub Actions run (`schedule` trigger) against Debian Testing to catch upstream breakage early. Note: GitHub disables scheduled workflows in public repositories after 60 days without repository activity.

---

## Phase 5: Documentation & Onboarding Overhaul

Rewrite the README and Wiki to reflect the modernized, bare-metal deployment strategy.

- **Pre-Ansible OS setup (LUKS vs. EncFS):**
  - Document the deprecation of EncFS.
  - Guide for provisioning Debian 13 with native **LUKS full-disk encryption**, including remote unlocking via dropbear-initramfs (also needed after automatic reboots).
- **GitOps administration guide:**
  - Managing users, domains, aliases and App-Specific Passwords via `group_vars/mailservers.yml`.
  - Generating Argon2id password hashes locally and securely (`doveadm pw -s ARGON2ID`), and generating app passwords in the id-prefix format.
  - Defining shared calendars and address books via the Radicale rights configuration.
- **DNS records cheat sheet** (tabular checklist):
  - **A/AAAA:** mail server IPv4/IPv6.
  - **MX:** pointing to the mail server.
  - **TXT (SPF):** Sender Policy Framework.
  - **TXT (DKIM):** generated by Rspamd (`/var/lib/rspamd/dkim/<domain>.<selector>.txt`).
  - **TXT (DMARC):** strict enforcement policy.
  - **TXT (MTA-STS & TLS-RPT):** strict transport security and reporting.
  - **TLSA (DANE):** checksum for the Let's Encrypt certificate (incl. key rollover guidance).
  - **PTR (reverse DNS):** setup instructions for the hosting provider panel.
  - **CNAME (Autodiscover):** autodiscover and autoconfig pointing to the mail server.
- **Network ports cheat sheet:**
  - TCP 22: SSH management
  - TCP 25: SMTP (server-to-server)
  - TCP 80: HTTP (ACME challenge, redirect to HTTPS)
  - TCP 143: IMAP (mail retrieval with STARTTLS)
  - TCP 443: HTTPS (webmail, MTA-STS policy, Autoconfig, Autodiscover)
  - TCP 587: message submission (STARTTLS)
  - TCP 993: IMAPS (implicit TLS mail retrieval)
  - TCP 4190: ManageSieve (filter configuration)
  - TCP 9100, 9900: metrics, monitoring hosts only
- **Operations notes:** Rspamd web UI via SSH tunnel; what mail_crypt does and does not encrypt; memory settings for small servers.
- **Backup & restore operations (Restic):**
  - **Setup:** generating and storing the repository password; initializing the remote backend.
  - **Encryption keys:** explicit warning to back up the Dovecot mail_crypt EC private key (`ecprivkey.pem`) alongside the Restic password.
  - **Restoration:** step-by-step disaster recovery for `/var/vmail`, the database and decryption with Dovecot's tools (mirrors the Phase 4 recovery test).
- **Manual migration guide (legacy Sovereign → new server):** there is no automated upgrade path; the new server is a fresh install and accounts are moved manually.
  - **Accounts:** define domains, users and aliases in `group_vars/mailservers.yml`. Old password hashes are not converted; every user gets a new Argon2id password (and new App-Specific Passwords where needed).
  - **Mailbox data:** copy mail with `doveadm backup` / `doveadm sync` using the `imapc` backend against the old server (per user, via master user or the user's credentials). Mail must go through Dovecot so that mail_crypt encrypts it on write; copying Maildir files directly would leave them unencrypted.
  - **Verification:** compare message and folder counts per mailbox (`doveadm mailbox status`) between old and new server.
  - **Sieve filters:** export the old scripts and install them via ManageSieve; check for syntax differences.
  - **Calendars and contacts:** export as `.ics` / `.vcf` from the old ownCloud/Nextcloud and import into Radicale.
  - **Cutover:** lower DNS TTLs in advance, run a final delta sync, then switch MX, autodiscover and related records and update the DKIM and TLSA records.
- **Developer guide:** running the Molecule scenarios locally with incus, and how the GitHub Actions workflow is structured.
- **Role design documents:** decide whether each new role gets a design description (as CONTRIBUTING.md asks) or the rule is dropped in favour of the in-file comments and commit messages.

---

## Decisions

| Topic | Decision |
|---|---|
| ACME client | certbot (Debian package), `--reuse-key` for stable DANE records |
| Exporter access | Source-restricted nftables rule driven by `monitoring_sources` |
| Migration | No automated path; manual migration guide in Phase 5 |
| CI provider | GitHub Actions, Ubuntu runners with incus |
| Mail database | SQLite instead of PostgreSQL; writers Ansible and Roundcube (passwords), readers read-only, rollback journal |
| Roundcube database | own SQLite file |
| App-Specific Passwords | 8-character id prefix + secret, selected by prefix (Dovecot 2.4: one row per passdb lookup) |
| Password hashes | Argon2id only |
| Target hardware | about 2 GB RAM; Argon2id with Dovecot's defaults (64 MiB), one FTS indexer |
| Antivirus | no local ClamAV; Rspamd attachment policy, optional remote ClamAV |
| Rspamd version | Debian packages as they are (3.12 / 4.1), one configuration |
| postsrsd | 2.x, from `trixie-backports` on Debian 13 |
| Mail metrics | Dovecot OpenMetrics endpoint instead of mtail |
| Outbound MTA-STS | postfix-mta-sts-resolver behind a DANE-precedence socketmap |
| Rspamd web UI | localhost only (SSH tunnel), random controller password |
| Admin web UI | none; administration via `group_vars` (GitOps) |
| Postfix master.cf | Debian's own, submission added via `postconf` |
| Implementation order | certificate part of 2.5 before 2.3 |
| Password self-service | users change their main password in Roundcube; Ansible sets only the initial hash; App-Specific Passwords stay admin-managed |
| Backups required | the restic role fails without repository and password |
| Password reset | a changed hash in the inventory applies once, via the stored `inventory_password`; open sessions are kicked |
| Webmail exposure | Roundcube is not trusted: mandatory HTTP basic auth in front of it; users in general are trusted, so Roundcube keeps direct write access to the mail database |
| Basic auth hashes | SHA-512 crypt only: nginx verifies on every request in its event loop, slow hashes would stall it |
| Radicale authentication | own small plugin instead of the built-in `dovecot` type or `python3-radicale-dovecot-auth`: `no-penalty`, one connection id per thread, correct Dovecot 2.4 handshake |

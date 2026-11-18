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

Replace legacy components with modern alternatives using native Debian 13 packages, with the TLS configuration based on BSI TR-03108 (not a certified or fully mapped compliance). Each step ships together with its tests. TLS everywhere: TLS 1.2/1.3, ECDHE with AES-GCM, curves P-256/P-384 (BSI TR-02102-2).

Implementation order: 2.1, 2.2, the certificate part of 2.5, 2.3, 2.4, rest of 2.5, 2.6, 2.7 (Postfix and Dovecot need the certificate from the start). Current state per phase: [STATUS.md](STATUS.md).

### 2.1 Security & Base System

- **Time:** systemd-timesyncd, servers from `ntp_servers`, otherwise Debian's default pool.
- **SSH:** key logins only (`openssh` role). The role stops if the connecting user has no key, so that it cannot lock anyone out.
- **Firewall:** nftables role. `/etc/nftables.conf` allows TCP 22, 25, 80, 143, 443, 465, 587, 993 and 4190, dropping everything else. Only Sovereign's own table is replaced on reload, so fail2ban's table and bans survive.
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

- **Mail database: SQLite** (one file, no database server; Ansible and, for password changes, a small password service are the only writers). Postfix reads it through proxymap, Dovecot read-only; rollback journal (WAL would require write access for every reader).
- Dovecot authentication with **Argon2id** password hashes. **App-Specific Passwords** start with an 8-character id (`PhOnE001-...`): Dovecot 2.4 fails a passdb lookup that returns several rows, so the app password row is selected by that prefix and its hash verified as usual.
- Enforce **TLS 1.2/1.3**, **DANE** (outbound) and strong ECDHE ciphers in Postfix and Dovecot.
- **At-rest encryption:** Dovecot mail_crypt with a globally generated EC keypair encrypting all Maildir message files. *(Dovecot's index cache and the FTS index keep header fields and terms in plaintext; their protection relies on LUKS.)*
- **Full-text search:** fts-flatcurve (Xapian; Debian package `dovecot-flatcurve`), autoindexing on delivery, Junk and Trash excluded, one indexer process with a memory limit.
- **SRS:** postsrsd 2 (socketmap), on Debian 13 from `trixie-backports` (Debian 13 ships 1.x with a different interface).
- **Plus-addressing:** sub-addressing with `+` as delimiter in Postfix and Dovecot.
- Dovecot listens on 143 (IMAP + STARTTLS) and 993 (IMAPS). Cleartext authentication without TLS is refused (`auth_allow_cleartext = no`). Submission on 465 (implicit TLS, preferred by the client configuration, RFC 8314) and on 587 (STARTTLS required) with SASL; the sender address must belong to the login or an alias pointing to it.
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

- **Roundcube** with the Elastic theme and the ManageSieve and password plugins; its own SQLite database (preferences, contacts, sessions), managed by Debian's dbconfig-common. Its maintenance runs from the package's own timers.
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
- **Append-only targets:** with `restic_prune_enabled: false` the server needs no delete rights on the repository and has no prune timer, so a compromised server cannot delete its backups. Pruning then runs from a trusted machine. Off by default, because it needs a second machine.
- The time of the last successful backup is a node exporter metric (`sovereign_backup_last_success_timestamp_seconds`), for alerting on backups that stop.

**Tests:** backup to a local test repository succeeds and contains the keys and databases; restoring a mailbox and reading it back through Dovecot (including mail_crypt decryption) succeeds; the restored mail database is intact; pruning works; the metric is exported; with an append-only server, backups work and root on the mail server cannot delete them, through restic or the API.

---

## Phase 3: Declarative Mail Administration (GitOps)

- The `maildb` role (written in Phase 2.3) acts strictly on `inventory/group_vars/mailservers.yml`: `mail_domains`, `mail_mailboxes` (with `app_passwords`) and `mail_aliases`.
- **Multiple mail domains** are a core feature: `alice@` on two domains are separate mailboxes, and missing certificate names stop the run. Tests cover delivery, passwords and sender rules per domain, DKIM with the right key, SRS, all web endpoints, Radicale, and removing a domain.
- Domains, mailboxes, App-Specific Passwords and aliases **precisely mirror** the code state, including removal of entries no longer defined; manual changes in the database are reverted on the next run.
- **Password self-service:** users change their own main password in Roundcube (password plugin). Ansible sets the initial password hash when it creates a mailbox and does not touch it afterwards; everything else (domains, mailboxes, aliases, App-Specific Passwords) stays exactly mirrored. Roundcube therefore gets write access to the mail database (only it and Ansible write); App-Specific Passwords remain admin-managed via `group_vars`.
- **Password reset:** a new hash for a mailbox in the inventory replaces the password once, also one the user changed, and disconnects the user's open sessions. The database remembers the hash last applied (`inventory_password`), which is what the role compares; there is no flag to remove afterwards.
- The database has its own directory, owned by the password service's user, for the rollback journal; root's scripts stay in a directory only root can write. Roundcube's password driver asks that service over a local socket (Phase 5.5); earlier, it wrote the database itself.

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
  - Managing users, domains, aliases and App-Specific Passwords via `inventory/group_vars/mailservers.yml`.
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
  - TCP 465: message submission (implicit TLS)
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
  - **Accounts:** define domains, users and aliases in `inventory/group_vars/mailservers.yml`. Old password hashes are not converted; every user gets a new Argon2id password (and new App-Specific Passwords where needed).
  - **Mailbox data:** copy mail with `doveadm backup` / `doveadm sync` using the `imapc` backend against the old server (per user, via master user or the user's credentials). Mail must go through Dovecot so that mail_crypt encrypts it on write; copying Maildir files directly would leave them unencrypted.
  - **Verification:** compare message and folder counts per mailbox (`doveadm mailbox status`) between old and new server.
  - **Sieve filters:** export the old scripts and install them via ManageSieve; check for syntax differences.
  - **Calendars and contacts:** export as `.ics` / `.vcf` from the old ownCloud/Nextcloud and import into Radicale.
  - **Cutover:** lower DNS TTLs in advance, run a final delta sync, then switch MX, autodiscover and related records and update the DKIM and TLSA records.
- **Developer guide:** running the Molecule scenarios locally with incus, and how the GitHub Actions workflow is structured.
- **Role design documents:** one chapter per role in `docs/ROLES.md`.

---

## Phase 5.5: Operational Readiness

Comes from an external review (November 2026). Converge, idempotence and mail flow are not enough. Migration, failures, revoking access and restoring must hold up too, before the first real deployment and before Phase 6 adds a tunnel, NAT and a second site. **Debian 13 is the supported target.** Testing stays in CI as an early warning: its failures are fixed, but they don't block a release.

Steps in order:

1. **Data safety**
   - **Migration guide:** select imapc only through the `imapc:` location, never with a global `mail_driver`, which would switch the local mailbox too. Use `backup -R` only for the first copy and `sync -1 -R` afterwards: once the new server has received mail, `backup` would delete it. Credentials go in a temporary, root-only configuration file, not on the command line.
   - **Migration test:** a Molecule test with an "old" IMAP server. First copy, then new mail on both sides, then the final sync. Check content, flags, folders and subscriptions, and that nothing that arrived on the new side is lost.
   - **Backups:** only exit code 0 counts as success. Also export the last attempt and its result, so an incomplete backup raises an alarm instead of looking fine. Add a regular `restic check`, and document the recovery point (daily backup: up to about a day of changes lost).
   - **Revoking access:** one path for removing or disabling a mailbox, resetting a password and removing an app password. Each ends the mailbox's open Dovecot sessions; sessions can't be matched to the app password they used, so a removed app password ends all of them. Roundcube sessions follow, since Roundcube logs in to IMAP for each request. Test with an open IMAP connection.
2. **Promises the configuration makes**
   - **Quotas:** enforce `quota_mb` with Dovecot's quota plugin (count and size, a warning to the user, a clear refusal at the limit) and test it, or remove the option.
   - **Certificates:** the certbot deploy hook fails when a reload fails, and the deploy timestamp records only successful reloads. Issuing a certificate and the services using it are separate facts, with separate checks.
   - **SSH:** besides `authorized_keys` not being empty, `ssh-keygen -l` must accept at least one key in it, and the effective configuration (`sshd -T`) is checked after the change. A real login with the admin's key stays a test (it needs the private key), and the install guide asks for one from a second terminal before the session is closed.
3. **Security boundaries**
   - **DANE vs. MTA-STS:** decide per MX, not per domain. MTA-STS is skipped only if every MX that Postfix may use has usable TLSA records; with mixed MX sets the MTA-STS policy applies. Test mixed MX sets, an MX outage, unusable TLSA records, DNS errors and an expired policy. Document what happens in each case.
   - **Roundcube's write access:** a small local service changes passwords instead. It checks the current password itself and can only change the password of the account it was asked for, so Roundcube needs no write access to the mail database. Until then the documentation states the risk plainly: a compromised Roundcube can take over every account. Basic auth stays as an extra hurdle.
   - **Read restrictions for the exposed services.** The systemd sandboxes (Rspamd, PHP-FPM) restrict where a service may *write*, not what it may *read*: a code execution bug in Roundcube could still read everything the `roundcube` user can. Two layers, cheapest first:
     1. **systemd namespaces** for PHP-FPM and Rspamd. `/var`, `/srv`, `/opt`, `/mnt` and `/media` are an allowlist: an empty file system with only the service's own directories mounted in, so mail, the mail database, calendars, backups and any data added later are invisible. `/etc` stays a blocklist (`InaccessiblePaths=`) for keys and other services' secrets: libraries read files there that nobody lists, and those secrets are root-only anyway. Works in the containers too, so every run tests it, including negative tests.
     2. **AppArmor only where systemd can't separate**, because several programs with different needs share one service: the **Dovecot login processes** first (`imap-login`, `managesieve-login`). They parse everything an attacker sends before authentication and need neither mail nor the mail database, but run in the same unit as `imap` and `auth`, which do. Then possibly **nginx**, one profile for master and workers (nginx forks its workers and has no `change_hat` support), which protects everything except the keys. Our own profiles, installed by the roles: the `apparmor-profiles` package is experimental, its Dovecot profiles are written for 2.3, and it has no nginx profile. Each profile starts in complain mode; a test at the end of the VM run fails on any AppArmor message for our profiles, then the profile switches to enforce. A timer exports the number of denials as a metric, with an alert rule, since an update applied by unattended-upgrades can add a helper or move a path. Tests only in the VM scenario: the containers have no AppArmor (misty runs Fedora with SELinux), so there the role skips the profiles if `aa-enabled` says no.
     - **Not done:** AppArmor for PHP-FPM (covered by step 1) and Postfix (most daemons already run chrooted in `/var/spool/postfix`). **No SELinux:** Debian's policy puts nginx and PHP-FPM in the same domain (`httpd_t`), so the separation that matters would need our own policy module anyway; it also means switching every server away from Debian's default LSM, a full relabel, and a policy few Debian users exercise.
4. **Pilot on Debian 13:** reboot, unattended upgrades, alarms, a restore. Measure memory peaks under concurrent load (IMAP logins, PHP, full-text indexing, backup) rather than looking at free memory after a test run. Ship example alert rules for the mail queue, disk space, inodes, certificate expiry and backup failures. A repeatable VM check for boot, resolver, time sync and restarts.
   - **Security support status** (upstream issue #550): install `debian-security-support`; a Molecule check that `check-support-status` reports nothing for our packages; a weekly timer exporting its result as a node exporter metric, with an alert rule. `debsecan` is not used: it lists every open CVE, too noisy to act on. `docs/ADMINISTRATION.md` names what the check can't see: restic and prometheus-node-exporter are Go programs, rebuilt only in point releases, and postsrsd comes from `trixie-backports`, which the security team does not cover. Afterwards, comment on #550 upstream and close it.
5. **Optional roles** (`roundcube`, `radicale`, `restic`), including removal of what is already installed. "No restic" must be an explicit statement that backups happen elsewhere, so that a server without backups still can't happen by accident.
6. Then Phase 6.

**Tooling:** CI uses a fixed combination of Python, Ansible and collections, so that test runs stay comparable. The documentation says "TLS configuration based on BSI TR-03108", not "compliant", until every requirement is met and tested; the mapping and the open points are in [BSI-TR-03108.md](BSI-TR-03108.md).

---

## Phase 6: Split Setup (Public Gateway + Home Server)

Optional deployment: a very small VPS holds the public IPv4 address and forwards all traffic through a WireGuard tunnel to the real server behind a residential router. A directly reachable server keeps working as before, without any of this.

```
Internet ──> VPS (public IPv4) ──WireGuard──> home server (all mail, keys, data)
```

- **The home server opens the tunnel**, so it needs no port forwarding on the router, and a changing home address or carrier-grade NAT does not matter.
- **The VPS holds no mail and no keys;** TLS ends at home. It is still treated as important: it can read SMTP that senders deliver without TLS, and whoever controls it could obtain a certificate for our names through HTTP-01.
- **Client addresses must survive.** SPF, DNS blocklists, rate limits and fail2ban depend on the real address. If connections appeared to come from the VPS, fail2ban would ban the gateway and cut off everyone.
- **All outbound traffic leaves through the tunnel** (default route on the home server, with a specific route to the VPS via the router), so that replies return the way they came and mail is sent from the VPS address. Residential addresses are widely blocklisted, and port 25 is often blocked.
- **MSS clamping** on the tunnel; without it, large mails stall in ways that are hard to diagnose.
- The mail roles need no changes for the recommended variant: `mynetworks` is loopback only, and the firewall matches ports, not interfaces.
- New roles: a gateway role for the VPS (it cannot use the `nftables` role, whose forward chain drops everything) and a tunnel role for the home server, in an inventory group of their own. The gateway play does not run `preflight`, since the VPS may not run Debian 13.

### 6.1 Gateway capabilities (first step)

The gateway should be as small as possible: it only needs WireGuard, forwarding and NAT, ideally on the cheapest machine available. Its minimum RAM is to be measured, not assumed; the role installs nothing else and runs no other services, and Ansible's Python only runs during a deployment.

The VPS available for testing ("vrede") is one example, not the requirement: **OpenVZ, with `wireguard-go`** (known to work there) instead of the kernel module. OpenVZ shares the host's kernel, so the deciding features depend on the provider and must be checked on the real machine before anything is built.

Known so far about this example: Debian 13, kernel reported as 4.19.0, `/dev/net/tun` present, no port filtering according to its owner, 1 GiB of RAM (`physpages` limit 262144 pages), at most 2000 iptables rules. The loaded modules include `iptable_nat`, `iptable_mangle`, `nf_nat_ipv4` and `nft_compat`, and also `nf_tables`, but not `nft_nat` or `nft_masq`. So the gateway should use iptables (`iptables-legacy` if needed), not native nftables NAT. 46 rules already exist there, so the role must only touch chains of its own and never flush. Still to check:

- Is IP forwarding possible (`net.ipv4.ip_forward`)?
- Does DNAT work, with nftables or with legacy iptables? (`MASQUERADE` is known to be unreliable on OpenVZ `venet` interfaces; use `SNAT --to-source`.)
- Is MSS clamping available (`TCPMSS`)?
- Debian version, kernel, memory limits (`/proc/user_beancounters`), Python for Ansible.
- Actual memory use of the tunnel under load, and of the whole system, to state a real minimum.
- Is outbound port 25 open, can the PTR record be set, and is the address on a blocklist?

### 6.2 Forwarding variant (depends on 6.1)

- **Preferred: DNAT** without SNAT on inbound. Client addresses are preserved by routing alone.
- **Fallback if DNAT is not available: a userspace proxy on the VPS with the PROXY protocol** to carry client addresses (Postfix `smtpd_upstream_proxy_protocol`, Dovecot `haproxy_trusted_networks`, nginx `proxy_protocol`). This changes the mail roles. The PROXY listeners must accept connections from the tunnel only, because otherwise anyone could forge a client address. Outbound SMTP also needs a separate solution. To be designed only if needed.

**Tests:** an extra Molecule instance plays the VPS, using `wireguard-go` as on the real one. The tests behind it run from a host outside the tunnel:

- A connection through the gateway reaches the server with the client's real address in the logs of Postfix and Dovecot.
- A client that fails repeatedly is banned, and other clients are not affected.
- Mail sent by the server arrives from the gateway's address.
- A mail larger than the tunnel MTU gets through in both directions.
- The certificate is issued through the tunnel.
- No port other than the forwarded ones is reachable on the gateway.
- The tunnel comes back after a restart of either side.

**Done when:** the steps above are green, and the setup has run on the real VPS.

---

## Later (not scheduled)

### Shared mail folders

Folders that several users can read and write. Today only calendars and address books can be shared (`radicale_shared_collections`); Dovecot has no ACL plugin or shared namespace configured.

**Proposed, not yet decided:** a public namespace with folders defined in the inventory, like shared calendars. Access follows the inventory and needs no ACL support in mail clients. The alternative is users sharing their own folders through IMAP ACLs, which adds a shared namespace and a dictionary of who shares what, and moves access control away from the inventory.

```yaml
mail_shared_folders:
  - name: family
    members: [alice@example.org, bob@example.org]
```

To settle when this is built:

- Read/unread flags are shared by default. Keep them per user with Dovecot's per-user index setting, and check what that means for a restore.
- Mail reaches a folder only by being moved there or through a Sieve rule. Decide whether an address should deliver straight into a folder.
- Removing a member or a folder revokes access and keeps the data, as with shared calendars.
- Confirm the Dovecot 2.4 configuration syntax, and how full-text search behaves on these folders.

**Tests:** a member can read, write and delete; a non-member can neither see nor open the folder, also after being removed from the list; flags behave as decided; the folder is in the restic backup and comes back in the disaster recovery test.

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
| SSH logins | keys only; the role refuses to run if the connecting user has no key. Root logins with a key stay as Debian sets them |
| Role design documents | one chapter per role in `docs/ROLES.md` instead of one file per role |
| Multiple domains | one server, one mail host, one certificate; per domain: mailboxes, aliases, DKIM key, `mta-sts`, `autoconfig` and `autodiscover` sites |
| Split setup | optional; WireGuard from home to a small VPS, DNAT preserving client addresses, PROXY protocol only as a fallback (Phase 6) |
| Supported releases | Debian 13 is the target; Testing is an early warning in CI, fixed but not release-blocking (Phase 5.5) |
| Order after Phase 5 | operational readiness (Phase 5.5) before the split setup |
| Backup deletion | a compromised server can delete backups by default; `restic_prune_enabled: false` with an append-only target prevents it |
| Backups required | the restic role fails without repository and password |
| Password reset | a changed hash in the inventory applies once, via the stored `inventory_password`; open sessions are kicked |
| Webmail exposure | Roundcube is not trusted: mandatory HTTP basic auth in front of it; users in general are trusted, password changes go through a narrow service that checks the current password, so Roundcube has no access to the mail database (Phase 5.5) |
| Basic auth hashes | SHA-512 crypt only: nginx verifies on every request in its event loop, slow hashes would stall it |
| Radicale authentication | own small plugin instead of the built-in `dovecot` type or `python3-radicale-dovecot-auth`: `no-penalty`, one connection id per thread, correct Dovecot 2.4 handshake |

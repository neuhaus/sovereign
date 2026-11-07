Sovereign
=========

Sovereign is a set of [Ansible](https://www.ansible.com/) playbooks that turn a small Debian server into a secure, low-maintenance mail server of your own, with webmail, calendars and contacts: SSH in every few weeks, and otherwise forget about it.

> **Status:** rebuilt for Debian 13 "Trixie" and Debian Testing on the `trixie-wip` branch. All of it is tested in containers on both releases, but it has not run on a real server yet. Try it on one you can afford to lose. Progress: [docs/STATUS.md](docs/STATUS.md).

What you get
------------

- **IMAP** with Dovecot 2.4: full-text search, mail encrypted at rest (mail_crypt), Sieve filters.
- **SMTP** with Postfix: TLS 1.2/1.3 only, outbound DANE and MTA-STS, plus addressing, SRS for forwarded mail.
- **Spam filtering** with Rspamd: DKIM, ARC, SPF, DMARC, Bayes learning when mail moves into or out of Junk, rejection of dangerous attachments, outbound rate limits.
- **Webmail** with Roundcube, behind HTTP basic auth, where users also change their password and filters.
- **Calendars and contacts** with Radicale, including shared ones.
- **Encrypted offsite backups** with Restic, and a tested restore.
- **Hardening and upkeep:** SSH with keys only, nftables firewall, fail2ban, a DNSSEC-validating resolver, automatic security updates, Prometheus metrics.
- **Several mail domains** on one server, each with its own mailboxes and DKIM key.
- **Administration as code:** domains, mailboxes and aliases on the server follow one YAML file exactly.

It fits on a server with about 2 GB of RAM. It deliberately has no admin web interface, database server or local virus scanner.

Installation
------------

**You need** a server running Debian 13 or Testing, preferably with an encrypted disk ([docs/INSTALL.md](docs/INSTALL.md)), a domain, a provider that lets you set the reverse DNS and does not block port 25, a place for backups, and a computer with Ansible.

**1. Prepare the server.** Create a user for Ansible with your SSH key:

    apt install sudo python3
    adduser --disabled-password deploy
    echo 'deploy ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/deploy
    install -d -o deploy -g deploy -m 700 /home/deploy/.ssh
    # put your public key into /home/deploy/.ssh/authorized_keys, owned by deploy

Make sure this key works: the playbook turns off SSH password logins for the whole server, and it stops if the user it connects as has no key.

**2. Configure.** On your computer:

    git clone -b trixie-wip https://github.com/neuhaus/sovereign.git
    cd sovereign
    pip install -r requirements.txt

Set your server's address in `inventory/hosts` and your settings in `inventory/group_vars/mailservers.yml`. The comments there explain each one. Password hashes come from `doveadm pw -s ARGON2ID` (Dovecot on any machine, or on the server after the first run) and `openssl passwd -6`. Keep the restic password in [Ansible Vault](https://docs.ansible.com/ansible/latest/vault_guide/index.html) and **a copy of it somewhere other than this server** ([docs/BACKUP.md](docs/BACKUP.md)).

**3. Publish the first DNS records** (the A/AAAA and CNAME rows below), and wait until they resolve: the certificate is requested over HTTP for all those names.

**4. Run it:**

    ansible-playbook -i inventory site.yml --ask-vault-pass

**5. Publish the remaining DNS records**, using the values the first run generated.

DNS records
-----------

For the mail domain `example.org` and mail host `mail.example.org`:

| Name | Type | Value | When |
|---|---|---|---|
| `mail.example.org` | A / AAAA | the server's addresses | before the first run |
| `mta-sts`, `autoconfig`, `autodiscover`, `dav` `.example.org` | CNAME | `mail.example.org` | before the first run |
| `example.org` | MX | `10 mail.example.org` | before the first run |
| the server's addresses | PTR | `mail.example.org`, in your provider's panel | before sending mail |
| `example.org` | TXT | `v=spf1 mx -all` | before sending mail |
| `_dmarc.example.org` | TXT | `v=DMARC1; p=reject; rua=mailto:postmaster@example.org` | before sending mail |
| `sovereign._domainkey.example.org` | TXT | contents of `/var/lib/rspamd/dkim/example.org.sovereign.txt` | after the first run |
| `_mta-sts.example.org` | TXT | `v=STSv1; id=<id>`, id from `/var/lib/sovereign/mta-sts-id` | after the first run |
| `_smtp._tls.example.org` | TXT | `v=TLSRPTv1; rua=mailto:postmaster@example.org` | any time |
| `_25._tcp.mail.example.org` | TLSA | `3 1 1 <hash>`, see below; needs a DNSSEC-signed zone | after the first run |

One server can host several mail domains. Each additional one needs its own MX, SPF, DMARC, DKIM, `_mta-sts`, `mta-sts`, `autoconfig` and `autodiscover` records, and those names in `certbot_domains`. See [Multiple domains](docs/ADMINISTRATION.md#multiple-domains), also for what the domains share.

The TLSA hash covers the certificate's public key, which stays the same across renewals:

    openssl x509 -in /etc/letsencrypt/live/mail.example.org/cert.pem -noout -pubkey \
      | openssl pkey -pubin -outform DER | sha256sum

Rotating that key: [docs/ADMINISTRATION.md](docs/ADMINISTRATION.md#rotating-the-certificate-key).

Network ports
-------------

| Port | Service |
|---|---|
| TCP 22 | SSH |
| TCP 25 | SMTP between servers |
| TCP 80 | ACME challenges, redirect to HTTPS |
| TCP 143 | IMAP with STARTTLS |
| TCP 443 | Webmail, CalDAV/CardDAV, MTA-STS policy, client autoconfiguration |
| TCP 587 | Mail submission with STARTTLS |
| TCP 993 | IMAP over TLS |
| TCP 4190 | ManageSieve (filters) |
| TCP 9100, 9900 | Metrics, only from `monitoring_sources` |

Everything else is dropped.

Using it
--------

Mail clients mostly configure themselves through autoconfiguration. The login is always the full mail address.

- **Webmail:** `https://mail.example.org`, first the basic auth credentials, then the mailbox login. Users change their password under Settings.
- **Calendars and contacts:** `https://dav.example.org`, with the mail address and password. Shared collections are at `https://dav.example.org/shared/<name>/`.
- **Phones and other devices:** use an app password; it can be revoked on its own, and it does not work in the webmail.

More documentation
------------------

- [docs/INSTALL.md](docs/INSTALL.md): disk encryption and remote unlock
- [docs/ADMINISTRATION.md](docs/ADMINISTRATION.md): users, passwords, aliases, shared calendars, operations
- [docs/BACKUP.md](docs/BACKUP.md): backups and disaster recovery
- [docs/MIGRATION.md](docs/MIGRATION.md): moving from a legacy Sovereign server
- [docs/ROLES.md](docs/ROLES.md): how each role works and why
- [CONTRIBUTING.md](CONTRIBUTING.md): development and tests

Questions and feedback on Matrix: [#sovereign:ping.de](https://matrix.to/#/%23sovereign:ping.de).

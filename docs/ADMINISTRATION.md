# Administration

Domains, mailboxes, aliases and app passwords on the server follow `inventory/group_vars/mailservers.yml` exactly. Change the file, then run:

    ansible-playbook -i inventory site.yml --ask-vault-pass

Entries no longer listed are removed, and manual changes in the mail database are reverted. Only the main passwords users set themselves are kept. A second run reports no changes.

## Mailboxes

    mail_mailboxes:
      - address: alice@example.org
        password: "{ARGON2ID}$argon2id$..."
        quota_mb: 0        # optional, 0 = unlimited
        enabled: true      # optional; disabled mailboxes cannot log in or receive mail

Generate hashes on your own computer where possible, so that passwords stay out of shell history on the server:

    doveadm pw -s ARGON2ID

Removing a mailbox ends its login and its mail delivery. **Its mail stays on disk** in `/var/vmail/<domain>/<user>`, and in the backups until retention removes it; delete the directory if the mail should go.

## Passwords

Users change their main password in the webmail, under Settings. Ansible does not touch that password afterwards.

**To reset a password,** put a new hash for the mailbox into the inventory and run the playbook. It replaces the password once, also one the user chose, and disconnects the user's open sessions. Then:

- Give the user the temporary password and ask them to change it. Nothing enforces this.
- If the account may be compromised, also remove its app passwords: they stay valid otherwise. Check its aliases and Sieve filters for forwarding too.

Reverting to an earlier hash counts as a new hash, so it resets the password again. That includes a `git revert` of a commit containing a reset.

## App passwords

For phones and other devices. They work for IMAP, SMTP and CalDAV/CardDAV, and not in the webmail, because they must not be enough to change the main password. An app password starts with an 8-character id (letters and digits), which selects it at login:

    # A long random secret after the id; this whole string is the password:
    PASSWORD="PhOnE001-$(openssl rand -hex 16)"; echo "$PASSWORD"
    doveadm pw -s ARGON2ID -p "$PASSWORD"

and in the inventory:

    app_passwords:
      - name: phone
        id: PhOnE001
        password: "{ARGON2ID}$argon2id$..."

To revoke one, remove its entry.

## Aliases

    mail_aliases:
      - source: postmaster@example.org
        destinations: [alice@example.org]
      - source: team@example.org
        destinations: [alice@example.org, bob@example.org]

Users may send from an alias that points to them. Forwarding to other domains works; the sender is rewritten (SRS) so that SPF still passes.

## Multiple domains

One server can host any number of mail domains. `alice@example.org` and `alice@example.net` are separate mailboxes with separate passwords, mail and calendars. An alias may point across domains, and a user may send from an alias on another domain that points to them.

**To add a domain:**

1. Add its records for the new domain, except DKIM (see the DNS table in the README): MX, SPF, DMARC, and CNAMEs for `mta-sts`, `autoconfig` and `autodiscover`. MX and CNAMEs point to the existing mail host. The new domain needs no A record for the mail host, no PTR and no TLSA record of its own.
2. Wait until the names resolve, because they are added to the certificate over HTTP.
3. In the inventory, add the domain to `mail_domains` and these three names to `certbot_domains`. The playbook stops and names any it finds missing. Keep the mail host first.

        mail_domains:
          - example.org
          - example.net
        certbot_domains:
          - mail.example.org
          - mta-sts.example.org
          - autoconfig.example.org
          - autodiscover.example.org
          - dav.example.org
          - mta-sts.example.net
          - autoconfig.example.net
          - autodiscover.example.net

4. Run the playbook; it reissues the certificate with the same key, so TLSA records stay valid.
5. Publish the new domain's DKIM record (`/var/lib/rspamd/dkim/example.net.sovereign.txt`) and its `_mta-sts` record, with the id from `/var/lib/sovereign/mta-sts-id`. **That id applies to all domains and changes when the policy changes,** for example when `mta_sts_mode` or `mta_sts_max_age` changes. Update it for every domain then.

**What each domain has of its own:** mailboxes, aliases, a DKIM key, and the `mta-sts`, `autoconfig` and `autodiscover` sites.

**What all domains share,** which the people using them can see:

- The **mail host:** clients of every domain connect to `mail.example.org`, the MX of every domain points to it, and it appears in the headers of all mail. There is no per-domain branding, and the webmail, the `dav` host and the autoconfiguration display name all use the first domain.
- The **certificate.** It lists all names, and certificates are public (Certificate Transparency), so anyone can see which domains share a server. If domains must not be linkable to each other, use separate servers.
- **SRS.** Forwarded mail from every domain is rewritten to an address on the first domain. So the first domain must keep valid SPF and accept mail. Set `postfix_srs_domain` to change it.
- The sending **IP address:** the reputation of one domain affects all of them.

**To remove a domain,** remove it with its mailboxes and aliases from `mail_domains`, `mail_mailboxes`, `mail_aliases` and `certbot_domains`, then run the playbook. Logins and delivery end at once. Some things stay on purpose, so that a mistake does not lose data; delete them yourself once you are sure:

- Mail, in `/var/vmail/<domain>/`. If the mailboxes are added again, they get their mail back, with the password now in the inventory.
- The DKIM key, in `/var/lib/rspamd/dkim/`. It would be reused if the domain came back.
- Calendars, in `/var/lib/radicale/collections/collection-root/<address>/`.
- Backups, until the retention policy removes them.

## Webmail access

Basic auth sits in front of everything in Roundcube, because Roundcube's code is the part of this server trusted least. You can share one set of credentials among people you trust or give each person their own:

    roundcube_basic_auth_users:
      - name: family
        password: "$6$..."   # openssl passwd -6

Only SHA-512 crypt hashes are accepted: nginx checks the hash on every request, and slow hashes would stall it. So use a long random password. Repeated failures ban the address for an hour.

## Shared calendars and address books

    radicale_shared_collections:
      - name: family
        type: calendar       # or addressbook
        display_name: Family
        users: [alice@example.org, bob@example.org]

Members set them up at `https://dav.example.org/shared/family/`. Access follows the list exactly. Removing an entry revokes all access but keeps the data on disk, in `/var/lib/radicale/collections/collection-root/shared/`.

## Rotating the certificate key

The certificate's key stays the same across renewals so that the TLSA record stays valid; rotating it is a deliberate step. Not covered by the tests:

1. Lower the TTL of the TLSA record ahead of time, and wait for the old TTL to pass.
2. On the server: `certbot renew --force-renewal --new-key --cert-name mail.example.org`
3. Compute the new hash (see the README) and publish it immediately.

Until the new record has spread, servers using DANE defer mail to you and retry later; they do not bounce it.

## Operations

- **Rspamd web interface:** only on the server itself. `ssh -L 11334:127.0.0.1:11334 deploy@mail.example.org`, then open <http://127.0.0.1:11334>.
- **Metrics:** node exporter on 9100, Dovecot on 9900, only from `monitoring_sources`. Worth alerting on: `sovereign_backup_last_success_timestamp_seconds`, which stops advancing when backups fail.
- **Failed logins:** `fail2ban-client banned` lists bans. There are jails for SSH, Postfix, Dovecot, webmail basic auth, Roundcube and Radicale. Unban with `fail2ban-client set <jail> unbanip <address>`.
- **Automatic reboots** after kernel updates are off, because an encrypted server needs a remote unlock. Enable them with `unattended_upgrades_automatic_reboot: true`.
- **What mail_crypt protects:** message files only. Dovecot's index cache and the search index hold header fields and search terms in plaintext. For those, rely on disk encryption.
- **Memory:** defaults suit about 2 GB of RAM (one search indexer, Redis capped at 256 MB, PHP workers only on demand). There is no local virus scanner, since ClamAV needs 1 to 1.5 GB; `rspamd_clamav_servers` can point to one on another host.

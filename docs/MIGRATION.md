# Moving from a legacy Sovereign server

There is no upgrade path: the new server is a fresh installation, and accounts move over by hand. The mail copy below is covered by a test, the rest of this guide is not. Try it with one mailbox first, and keep the old server until you have compared the results.

## Accounts

Define domains, mailboxes and aliases in `inventory/group_vars/mailservers.yml`. Old password hashes are not carried over. Every user gets a new Argon2id password, and new app passwords where needed.

## Mail

Copy mail through Dovecot, over IMAP from the old server, so that mail_crypt encrypts it as it arrives. **Do not copy Maildir files directly,** since they would stay unencrypted.

Per user, on the new server (this needs the user's password on the old server, or a master user there). Put the connection settings in a file only root can read, so the password doesn't end up in your shell history or in the process list:

    install -m 0600 /dev/null /root/migration.conf
    editor /root/migration.conf

```
dovecot_config_version = 2.4.1
dovecot_storage_version = 2.4.1
!include /etc/dovecot/dovecot.conf

imapc_host = old.example.org
imapc_port = 993
imapc_ssl = imaps
imapc_user = alice@example.org
imapc_password = the-password-on-the-old-server
```

Dovecot 2.4 requires `dovecot_config_version` as the first setting of every configuration file it reads, so the file starts with the same two version lines as `/etc/dovecot/dovecot.conf`; copy them from there (`head /etc/dovecot/dovecot.conf`).

`imapc:` at the end of the commands below selects the old server as the other side. Don't add `-o mail_driver=imapc` (as older guides do): it applies to the local mailbox too, which would then also point at the old server.

**First copy,** before the user works on the new server:

    install -m 0700 -d /root/migration-state
    doveadm -c /root/migration.conf backup -R -s '' -u alice@example.org imapc: \
        > /root/migration-state/alice@example.org

`backup` makes the new mailbox an exact copy of the old one and **deletes anything that is only on the new side.** Use it for the first copy only. `-s ''` prints the sync state, which the file keeps for the next run.

**Every later run,** including the final one after the switch, when new mail may already have arrived on the new server:

    state=$(cat /root/migration-state/alice@example.org)
    doveadm -c /root/migration.conf sync -1 -R -s "$state" -u alice@example.org imapc: \
        > /root/migration-state/alice@example.org.new &&
        mv /root/migration-state/alice@example.org.new /root/migration-state/alice@example.org

`sync -1 -R` copies changes from the old server and keeps what is new on the new server. **Don't leave out the state.** `backup` copies the old mailbox's UID numbering, so after the switch a message arriving on each side gets the same UID. Without the state, dsync can't tell that both are new: it keeps the new server's message and silently skips the old server's, and still reports success. With the state it renumbers the new server's message and copies both. (Tested; see below.)

For the next user, change `imapc_user` and `imapc_password`. With a master user on the old server, set `imapc_user = %{user}`, `imapc_master_user` and `imapc_password` (the master password) once for everyone. Remove the file at the end:

    rm -r /root/migration.conf /root/migration-state

If the old server's certificate is not valid (self-signed, expired), add `ssl_client_require_valid_cert = no` to the file; only do that on a network path you trust.

A test runs these commands (`molecule/resources/tests/test_migration.py`): first copy, then new mail on both sides, then the final sync. It checks content, flags, folders and subscriptions, and that mail that arrived on the new side is kept, also when both sides received a message after the first copy.

## Verifying

Compare the message count per folder on both servers:

    doveadm mailbox status -u alice@example.org messages '*'

## Filters

Export Sieve scripts from the old server and install them through the webmail or a ManageSieve client. Check them for syntax differences; the new server reports errors on upload.

## Calendars and contacts

Export them from the old ownCloud or Nextcloud as `.ics` and `.vcf`, and import them into Radicale with a CalDAV/CardDAV client.

## Cutover

1. Lower the DNS TTLs a day or more ahead.
2. Run `sync -1 -R` for everyone, while the old server no longer accepts mail or just after.
3. Switch the MX, A/AAAA, autodiscover and autoconfig records to the new server, and set the PTR record.
4. Publish the new DKIM and TLSA records (see the README).
5. Run `sync -1 -R` once more after the old TTLs have passed (never `backup`: it would delete mail that has arrived on the new server), then raise the TTLs again.

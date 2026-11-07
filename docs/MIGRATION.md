# Moving from a legacy Sovereign server

There is no upgrade path: the new server is a fresh installation, and accounts move over by hand. **Unlike the rest of Sovereign, this guide has not been tested.** Try it with one mailbox first, and keep the old server until you have compared the results.

## Accounts

Define domains, mailboxes and aliases in `inventory/group_vars/mailservers.yml`. Old password hashes are not carried over. Every user gets a new Argon2id password, and new app passwords where needed.

## Mail

Copy mail through Dovecot, over IMAP from the old server, so that mail_crypt encrypts it as it arrives. **Do not copy Maildir files directly,** since they would stay unencrypted.

Per user, on the new server (this needs the user's password on the old server, or a master user there):

    doveadm -o mail_driver=imapc -o imapc_host=old.example.org -o imapc_port=993 -o imapc_ssl=imaps \
      -o imapc_user=alice@example.org -o imapc_password='...' \
      backup -R -u alice@example.org imapc:

The password ends up in your shell history; use a temporary one on the old server, or clear the history afterwards. `backup` makes the new mailbox match the old one, **deleting what is only on the new side**, so run it before users start working on the new server. Repeat it later for a final sync.

## Verifying

Compare the message count per folder on both servers:

    doveadm mailbox status -u alice@example.org messages '*'

## Filters

Export Sieve scripts from the old server and install them through the webmail or a ManageSieve client. Check them for syntax differences; the new server reports errors on upload.

## Calendars and contacts

Export them from the old ownCloud or Nextcloud as `.ics` and `.vcf`, and import them into Radicale with a CalDAV/CardDAV client.

## Cutover

1. Lower the DNS TTLs a day or more ahead.
2. Run the final sync, while the old server no longer accepts mail or just after.
3. Switch the MX, A/AAAA, autodiscover and autoconfig records to the new server, and set the PTR record.
4. Publish the new DKIM and TLSA records (see the README).
5. Sync once more after the old TTLs have passed, then raise the TTLs again.

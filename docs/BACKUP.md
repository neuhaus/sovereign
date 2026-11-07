# Backups and disaster recovery

Restic backs up the server once a day and applies the retention policy once a week (7 daily, 4 weekly, 6 monthly snapshots, see `roles/restic/defaults/main.yml`). Backups are required: the playbook fails without a repository and password.

**Backed up:** `/var/vmail`, copies of the mail and Roundcube databases, the mail_crypt keys, DKIM keys, Radicale data, `/etc/letsencrypt` and the postsrsd secret.

**Not backed up:** the search index, which Dovecot rebuilds, and Rspamd's Bayes data, which is relearned.

## Keep these outside the server

> **Without the restic password the backups cannot be read. Without the mail_crypt private key the mail in them cannot be read.**

The key (`/etc/dovecot/mail-crypt/ecprivkey.pem`) is in the backups, so the restic password is what you cannot lose. Still keep a copy of both with your other important secrets, in a password manager for example, and not only on this server. Also keep `inventory/` safe, since a recovery needs it.

## Setup

    restic_repository: s3:https://s3.example.net/bucket/mail
    restic_password: "{{ vault_restic_password }}"
    restic_environment:
      AWS_ACCESS_KEY_ID: "{{ vault_backup_key_id }}"
      AWS_SECRET_ACCESS_KEY: "{{ vault_backup_key }}"

Generate the password with `openssl rand -base64 32`. The repository is created on the first run if there is none. Any [backend restic supports](https://restic.readthedocs.io/en/stable/030_preparing_a_new_repo.html) works, as long as it is on another machine.

## Protecting backups from a compromised server

With the default setup, **an attacker with root on the mail server can delete the backups,** because `/etc/restic/` holds full access to the repository and the weekly prune needs it. Ransomware-style attacks go after exactly this. To prevent it, give the server a repository it can only add to:

    restic_repository: rest:https://user:password@backup.example.net/mail/
    restic_prune_enabled: false

Use one of these on the other side:

- **[rest-server](https://github.com/restic/rest-server) with `--append-only`** on a machine you control. Debian's package is `restic-rest-server`. Use its `--private-repos` and TLS options when it is reachable over a network.
- **Object storage with object lock or versioning,** so that deleted data stays recoverable for a set time. Check your provider's terms and how long it keeps deleted versions.

Then prune from **a separate trusted machine**, with credentials the mail server does not have, for example a cron job on your backup host:

    restic -r /srv/restic/mail forget --prune --tag sovereign --keep-daily 7 --keep-weekly 4 --keep-monthly 6

The limits of this protection:

- The attacker can still **read** the backups, because the server has the password. It protects against deletion, not disclosure.
- The attacker can still add bad snapshots, so deciding what to prune needs care after an incident: retention keeps recent snapshots, which could be the damaged ones. Stop pruning first, and look at `restic snapshots` to find the last good one.
- The repository grows until something prunes it.

## Checking on backups

    systemctl list-timers 'sovereign-backup*'
    journalctl -u sovereign-backup.service
    systemctl start sovereign-backup.service      # one backup now

Other restic commands need the settings:

    set -a; . /etc/restic/env; set +a
    restic snapshots
    restic check

Alert on the metric `sovereign_backup_last_success_timestamp_seconds`, because nothing else tells you when backups stop.

## Restoring a mailbox

    set -a; . /etc/restic/env; set +a
    doveadm kick alice@example.org
    restic restore latest --target / --include /var/vmail/example.org/alice

This overwrites the mailbox with its state in the snapshot. To look at it first, restore to another `--target` instead. Dovecot decrypts the restored mail with the same key.

## Disaster recovery

The full recovery onto a new server. The automated tests run these steps on both Debian releases (`molecule/resources/tests/disaster_recovery*.yml`).

Order matters: **restore first, then run the playbook.** Otherwise it generates new keys, and the existing mail, DKIM records and TLSA records would no longer fit them.

1. Install Debian and prepare the server as in the README. Point the DNS records at the new address, so that it has the old server's names.

2. On the new server, install restic and restore the latest snapshot:

        apt install restic sqlite3
        export RESTIC_REPOSITORY='...' RESTIC_PASSWORD='...'   # and backend credentials
        restic restore latest --target / --exclude-xattr 'security.*'

   Security labels belong to the old server, and without this option restic can report errors for them although all data was restored.

3. Put the mail database in place. It holds the passwords users chose:

        install -d /var/lib/sovereign/maildb
        cp /var/backups/sovereign/mail.sqlite /var/lib/sovereign/maildb/mail.sqlite

4. From your computer, run the playbook as usual, with the same inventory.

5. Back on the server, hand the restored data to the local users (restic restored the old numeric owners), and put the Roundcube database in place:

        chown -R vmail:vmail /var/vmail
        chown -R radicale:radicale /var/lib/radicale/collections
        install -o www-data -g www-data -m 0660 /var/backups/sovereign/roundcube.sqlite \
          /var/lib/dbconfig-common/sqlite3/roundcube/roundcube

6. Check: `systemctl --failed`, log in by IMAP and read some mail, and log in to the webmail. The search index rebuilds as people search.

The DKIM and TLSA records stay valid, because the keys are the old ones. If the address changed, update the A/AAAA and PTR records.

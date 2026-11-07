# Disk encryption and remote unlock

Sovereign used to encrypt data with EncFS, which is gone: it is no longer maintained, and it left metadata exposed. Encrypt the whole disk with LUKS instead, when installing Debian. This protects what `mail_crypt` does not cover, such as search indexes and the mail database.

**These steps are not covered by the automated tests.** Try a reboot while you still have console access, ideally before you depend on the server.

## Installing

Use the Debian 13 installer, through your provider's console or rescue system. At partitioning choose "Guided - use entire disk and set up encrypted LVM", and choose a long passphrase. Keep a copy of it somewhere other than the server.

## Unlocking over SSH after a reboot

An encrypted server waits at boot for the passphrase. A small SSH server in the initramfs lets you enter it remotely.

    apt install dropbear-initramfs

Allow only your key, and only the unlock command, in `/etc/dropbear/initramfs/authorized_keys`:

    no-port-forwarding,no-agent-forwarding,no-x11-forwarding,command="/usr/bin/cryptroot-unlock" ssh-ed25519 AAAA... you@example

Set a separate port, so that SSH clients do not confuse this host key with the normal one, in `/etc/dropbear/initramfs/dropbear.conf`:

    DROPBEAR_OPTIONS="-p 2222 -s -j -k"

If the server has a static address rather than DHCP, set it in `/etc/initramfs-tools/initramfs.conf` (`IP=<address>::<gateway>:<netmask>:<hostname>`). Then rebuild, and test:

    update-initramfs -u
    reboot

From your computer:

    ssh -p 2222 root@mail.example.org

and enter the passphrase. After that, the server continues to boot.

Port 2222 is only open during that boot phase. Sovereign's firewall starts afterwards and does not allow it.

## Afterwards

Automatic reboots stay off by default, because each one waits for this unlock. If you want them anyway, see `unattended_upgrades_automatic_reboot` in [ADMINISTRATION.md](ADMINISTRATION.md#operations).

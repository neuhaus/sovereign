# Managed by Ansible (Sovereign dovecot role).
# IMAPSieve: a message copied or moved out of Junk is learned as ham, unless
# it goes to Trash (deleting spam is not a "not spam" verdict).
require ["vnd.dovecot.pipe", "copy", "imapsieve", "environment", "variables"];

if environment :matches "imap.mailbox" "*" {
  set "mailbox" "${1}";
}
if string "${mailbox}" "Trash" {
  stop;
}
pipe :copy "sovereign-learn-ham";

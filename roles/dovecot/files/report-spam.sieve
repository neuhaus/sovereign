# Managed by Ansible (Sovereign dovecot role).
# IMAPSieve: a message copied or moved into Junk is learned as spam.
require ["vnd.dovecot.pipe", "copy", "imapsieve", "environment", "variables"];

pipe :copy "sovereign-learn-spam";

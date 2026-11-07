-- Canonical, sorted export of the mail database content. The maildb role
-- compares it with templates/export.txt.j2 to detect any difference. For
-- mailboxes that is the hash last taken from the inventory, not the live one:
-- users may change their password.
SELECT 'domain|' || name FROM domains
UNION ALL
SELECT 'mailbox|' || localpart || '@' || domain || '|' || inventory_password || '|' || quota_mb || '|' || enabled FROM mailboxes
UNION ALL
SELECT 'app|' || localpart || '@' || domain || '|' || id || '|' || name || '|' || password FROM app_passwords
UNION ALL
SELECT 'alias|' || source || '|' || destination FROM aliases
ORDER BY 1;

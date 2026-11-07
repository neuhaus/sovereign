-- Canonical, sorted export of the mail database content. The maildb role
-- compares it with templates/export.txt.j2 to detect any difference. Password
-- hashes of mailboxes are left out: they belong to the users after creation.
SELECT 'domain|' || name FROM domains
UNION ALL
SELECT 'mailbox|' || localpart || '@' || domain || '|' || quota_mb || '|' || enabled FROM mailboxes
UNION ALL
SELECT 'app|' || localpart || '@' || domain || '|' || id || '|' || name || '|' || password FROM app_passwords
UNION ALL
SELECT 'alias|' || source || '|' || destination FROM aliases
ORDER BY 1;

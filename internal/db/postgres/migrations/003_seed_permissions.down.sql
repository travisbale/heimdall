-- Remove all seeded permissions
--
-- Matching on the namespace rather than an explicit name list means this cannot drift out
-- of sync with the up migration the way the previous hand-maintained list did: it omitted
-- every oidc:* permission, so a down migration left four rows behind. Everything under
-- "heimdall:" belongs to this service, and later migrations that add scopes run their own
-- down step before this one.
DELETE FROM permissions WHERE name LIKE 'heimdall:%';

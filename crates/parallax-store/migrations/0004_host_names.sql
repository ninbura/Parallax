-- Hosts may be DNS names (step 7a): a grant's host is an address or a
-- name, so its column is `host` like the service's. What names resolve to
-- isn't stored: only the latest lookup counts.

ALTER TABLE template_grants RENAME COLUMN ip TO host;

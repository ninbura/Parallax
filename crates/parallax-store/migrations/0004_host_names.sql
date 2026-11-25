-- Hosts may be DNS names (step 7a): a grant's host is an address or a
-- name, so its column is `host` like the service's. The daemon keeps what
-- each name last resolved to in daemon_state (`name:<hostname>`).

ALTER TABLE template_grants RENAME COLUMN ip TO host;

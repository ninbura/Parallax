-- How the home's public IP is found (`[server.public_ip]`). Existing rows
-- get the defaults: look it up, no encrypted DNS fallback.

ALTER TABLE server ADD COLUMN public_ip_address TEXT;
-- Provider names in order, comma-separated ('' when none).
ALTER TABLE server ADD COLUMN public_ip_encrypted_dns TEXT NOT NULL DEFAULT '';

-- What the daemon learned while running and keeps across restarts (the
-- home's public IP). Not configuration: never exported, and a restore
-- leaves this machine's values in place.
CREATE TABLE daemon_state (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

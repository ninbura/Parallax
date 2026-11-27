-- Per-peer activity logging (`[server.logs]`, `log` on grants and peers).
-- Existing rows get the defaults: nothing logged, records in logs.db next
-- to the database, kept 30 days or 1 GiB.

ALTER TABLE server ADD COLUMN logs_level TEXT NOT NULL DEFAULT 'off';
ALTER TABLE server ADD COLUMN logs_path TEXT NOT NULL DEFAULT '/var/lib/parallax/logs.db';
ALTER TABLE server ADD COLUMN logs_keep TEXT NOT NULL DEFAULT '30d';
ALTER TABLE server ADD COLUMN logs_max_size TEXT NOT NULL DEFAULT '1GiB';

-- NULL: the grant (or peer) sets no level of its own.
ALTER TABLE grants ADD COLUMN log TEXT;
ALTER TABLE peers ADD COLUMN log TEXT;

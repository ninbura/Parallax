-- DNS query logging (`server.logs.dns`, `log_dns` on grants and peers),
-- separate from the log level. Existing rows: off, and no setting of
-- their own.

ALTER TABLE server ADD COLUMN logs_dns INTEGER NOT NULL DEFAULT 0;

-- NULL: the grant (or peer) says nothing either way.
ALTER TABLE grants ADD COLUMN log_dns INTEGER;
ALTER TABLE peers ADD COLUMN log_dns INTEGER;

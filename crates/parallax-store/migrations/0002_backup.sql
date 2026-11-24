-- Backup settings (`[server.backup]`). Existing rows get the defaults.

ALTER TABLE server ADD COLUMN backup_directory TEXT NOT NULL DEFAULT '/var/lib/parallax/backups';
ALTER TABLE server ADD COLUMN backup_automatic BOOLEAN NOT NULL DEFAULT 1;
ALTER TABLE server ADD COLUMN backup_interval TEXT NOT NULL DEFAULT '1d';
ALTER TABLE server ADD COLUMN backup_keep INTEGER NOT NULL DEFAULT 14;
ALTER TABLE server ADD COLUMN backup_encrypt BOOLEAN NOT NULL DEFAULT 1;
ALTER TABLE server ADD COLUMN backup_passphrase_file TEXT NOT NULL DEFAULT '/etc/parallax/backup.passphrase';

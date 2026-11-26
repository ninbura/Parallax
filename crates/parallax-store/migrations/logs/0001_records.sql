-- The activity database (logs.db, docs/logging.md): what the collector
-- recorded. Names are kept as they were, not as references, so the history
-- survives renames and removals in the configuration.

CREATE TABLE records (
    id INTEGER PRIMARY KEY,
    -- Unix milliseconds.
    time INTEGER NOT NULL,
    -- opened, closed, denied, denied_gateway
    kind TEXT NOT NULL,
    peer TEXT NOT NULL,
    -- The peer's grants then, comma-separated.
    grants TEXT NOT NULL,
    source TEXT NOT NULL,
    -- As the peer addressed it; the real one when the gateway translated it.
    destination TEXT NOT NULL,
    real_destination TEXT,
    network TEXT,
    protocol TEXT NOT NULL,
    port INTEGER,
    -- Connection tracking's id: joins a flow's opened and closed records.
    flow INTEGER,
    bytes_out INTEGER,
    bytes_in INTEGER
);

CREATE INDEX records_time ON records (time);
CREATE INDEX records_peer_time ON records (peer, time);

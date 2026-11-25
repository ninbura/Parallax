-- Port lists (step 7a.3): a service has any number of ports, written like
-- ufw (`445/tcp`, `137-138/udp`, `25565` for TCP and UDP), and a host grant
-- may list its ports (none: every port). A `host_port` grant becomes a host
-- grant with its one port.

CREATE TABLE service_ports (
    service_id INTEGER NOT NULL REFERENCES services (id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    ports TEXT NOT NULL,
    PRIMARY KEY (service_id, position)
);
INSERT INTO service_ports (service_id, position, ports)
    SELECT id, 0, port || '/' || proto FROM services;
ALTER TABLE services DROP COLUMN proto;
ALTER TABLE services DROP COLUMN port;

-- A grant's ports, by the grant's position in its template.
CREATE TABLE template_grant_ports (
    template_id INTEGER NOT NULL REFERENCES templates (id) ON DELETE CASCADE,
    grant_position INTEGER NOT NULL,
    position INTEGER NOT NULL,
    ports TEXT NOT NULL,
    PRIMARY KEY (template_id, grant_position, position)
);
INSERT INTO template_grant_ports (template_id, grant_position, position, ports)
    SELECT template_id, position, 0, port || '/' || proto
    FROM template_grants WHERE kind = 'host_port';

-- The grants table without proto and port, and without the host_port kind.
CREATE TABLE template_grants_new (
    template_id INTEGER NOT NULL REFERENCES templates (id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    kind TEXT NOT NULL,
    network_id INTEGER REFERENCES networks (id),
    service_id INTEGER REFERENCES services (id),
    host TEXT,
    PRIMARY KEY (template_id, position),
    CHECK (
        (kind IN ('all_networks', 'internet')
            AND network_id IS NULL AND service_id IS NULL AND host IS NULL)
        OR (kind = 'network'
            AND network_id IS NOT NULL AND service_id IS NULL AND host IS NULL)
        OR (kind = 'service'
            AND network_id IS NULL AND service_id IS NOT NULL AND host IS NULL)
        OR (kind = 'host'
            AND network_id IS NULL AND service_id IS NULL AND host IS NOT NULL)
    )
);
INSERT INTO template_grants_new (template_id, position, kind, network_id, service_id, host)
    SELECT template_id, position,
        CASE kind WHEN 'host_port' THEN 'host' ELSE kind END,
        network_id, service_id, host
    FROM template_grants;
DROP TABLE template_grants;
ALTER TABLE template_grants_new RENAME TO template_grants;

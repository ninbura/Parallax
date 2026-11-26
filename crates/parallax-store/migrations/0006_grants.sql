-- Named grants replace templates (step 7b, ADR 0010). Each template becomes
-- a grant of the same name with its rules (plus a public_dns rule when it
-- had dns.public), and each peer gets its template's grant and copies its
-- client settings. Addresses stay as they are; pools and the Headscale
-- identity are dropped. A peer's grants are a list, so it may have many.

CREATE TABLE grants (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    position INTEGER NOT NULL,
    -- Applies to every peer without being attached.
    everyone BOOLEAN NOT NULL
);
-- Same ids as the templates, so the rows below carry over unchanged.
INSERT INTO grants (id, name, position, everyone)
    SELECT id, name, position, 0 FROM templates;

CREATE TABLE grant_rules (
    grant_id INTEGER NOT NULL REFERENCES grants (id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    kind TEXT NOT NULL,
    network_id INTEGER REFERENCES networks (id),
    service_id INTEGER REFERENCES services (id),
    host TEXT,
    PRIMARY KEY (grant_id, position),
    CHECK (
        (kind IN ('all_networks', 'internet', 'public_dns')
            AND network_id IS NULL AND service_id IS NULL AND host IS NULL)
        OR (kind = 'network'
            AND network_id IS NOT NULL AND service_id IS NULL AND host IS NULL)
        OR (kind = 'service'
            AND network_id IS NULL AND service_id IS NOT NULL AND host IS NULL)
        OR (kind = 'host'
            AND network_id IS NULL AND service_id IS NULL AND host IS NOT NULL)
    )
);
INSERT INTO grant_rules (grant_id, position, kind, network_id, service_id, host)
    SELECT template_id, position, kind, network_id, service_id, host FROM template_grants;
-- dns.public: a rule after the template's own.
INSERT INTO grant_rules (grant_id, position, kind)
    SELECT t.id, COALESCE(MAX(g.position) + 1, 0), 'public_dns'
    FROM templates t LEFT JOIN template_grants g ON g.template_id = t.id
    WHERE t.dns_public
    GROUP BY t.id;

-- A host rule's ports, by the rule's position in its grant.
CREATE TABLE grant_rule_ports (
    grant_id INTEGER NOT NULL REFERENCES grants (id) ON DELETE CASCADE,
    rule_position INTEGER NOT NULL,
    position INTEGER NOT NULL,
    ports TEXT NOT NULL,
    PRIMARY KEY (grant_id, rule_position, position)
);
INSERT INTO grant_rule_ports (grant_id, rule_position, position, ports)
    SELECT template_id, grant_position, position, ports FROM template_grant_ports;

-- Client settings for new WireGuard peers, and the tailnet-wide DNS mode
-- (Headscale's split DNS applies to every node). The DNS mode is the
-- templates' when they all agree.
ALTER TABLE server ADD COLUMN wireguard_peer_dns TEXT NOT NULL DEFAULT 'split';
ALTER TABLE server ADD COLUMN wireguard_peer_allowed_ips TEXT NOT NULL DEFAULT 'mapped_subnets';
ALTER TABLE server ADD COLUMN wireguard_peer_mtu INTEGER;
ALTER TABLE server ADD COLUMN wireguard_peer_persistent_keepalive INTEGER;
ALTER TABLE server ADD COLUMN headscale_dns TEXT NOT NULL DEFAULT 'split';
CREATE TABLE migrate_headscale_dns (mode TEXT NOT NULL);
INSERT INTO migrate_headscale_dns (mode)
    SELECT MAX(dns_tailscale) FROM templates HAVING COUNT(DISTINCT dns_tailscale) = 1;
UPDATE server SET headscale_dns = (SELECT mode FROM migrate_headscale_dns)
    WHERE EXISTS (SELECT 1 FROM migrate_headscale_dns);
DROP TABLE migrate_headscale_dns;

-- Which template each peer had, while the peers table is rebuilt.
CREATE TABLE migrate_peer_templates (
    peer_id INTEGER NOT NULL,
    template_id INTEGER NOT NULL
);
INSERT INTO migrate_peer_templates (peer_id, template_id)
    SELECT id, template_id FROM peers;

-- Peers without template_id, with their WireGuard client settings (set
-- exactly when the WireGuard identity is).
CREATE TABLE peers_new (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    position INTEGER NOT NULL,
    transport TEXT NOT NULL,
    enabled BOOLEAN NOT NULL,
    expires TEXT,
    wireguard_public_key TEXT,
    wireguard_address TEXT,
    wireguard_private_key TEXT,
    wireguard_preshared_key TEXT,
    wireguard_dns TEXT,
    wireguard_allowed_ips TEXT,
    wireguard_mtu INTEGER,
    wireguard_persistent_keepalive INTEGER,
    -- false: every network is visible. true: only the rows in
    -- peer_visible_networks, which may be none.
    wireguard_visible_networks_limited BOOLEAN,
    tailscale BOOLEAN NOT NULL,
    tailscale_node_id INTEGER,
    tailscale_address TEXT,
    CHECK (wireguard_public_key IS NOT NULL OR (wireguard_address IS NULL
        AND wireguard_private_key IS NULL AND wireguard_preshared_key IS NULL
        AND wireguard_dns IS NULL AND wireguard_allowed_ips IS NULL
        AND wireguard_mtu IS NULL AND wireguard_persistent_keepalive IS NULL
        AND wireguard_visible_networks_limited IS NULL)),
    CHECK (wireguard_public_key IS NULL OR (wireguard_dns IS NOT NULL
        AND wireguard_allowed_ips IS NOT NULL
        AND wireguard_visible_networks_limited IS NOT NULL)),
    CHECK (tailscale OR (tailscale_node_id IS NULL AND tailscale_address IS NULL))
);
INSERT INTO peers_new (id, name, position, transport, enabled, expires,
        wireguard_public_key, wireguard_address, wireguard_private_key,
        wireguard_preshared_key, wireguard_dns, wireguard_allowed_ips, wireguard_mtu,
        wireguard_persistent_keepalive, wireguard_visible_networks_limited,
        tailscale, tailscale_node_id, tailscale_address)
    SELECT p.id, p.name, p.position, p.transport, p.enabled, p.expires,
        p.wireguard_public_key, p.wireguard_address, p.wireguard_private_key,
        p.wireguard_preshared_key,
        CASE WHEN p.wireguard_public_key IS NULL THEN NULL ELSE t.dns_wireguard END,
        CASE WHEN p.wireguard_public_key IS NULL THEN NULL ELSE t.client_allowed_ips END,
        CASE WHEN p.wireguard_public_key IS NULL THEN NULL ELSE t.client_mtu END,
        CASE WHEN p.wireguard_public_key IS NULL THEN NULL
            ELSE t.client_persistent_keepalive END,
        CASE WHEN p.wireguard_public_key IS NULL THEN NULL
            ELSE t.visible_networks_limited END,
        p.tailscale, p.tailscale_node_id, p.tailscale_address
    FROM peers p JOIN templates t ON t.id = p.template_id;
DROP TABLE peers;
ALTER TABLE peers_new RENAME TO peers;

CREATE TABLE peer_grants (
    peer_id INTEGER NOT NULL REFERENCES peers (id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    grant_id INTEGER NOT NULL REFERENCES grants (id),
    PRIMARY KEY (peer_id, position)
);
INSERT INTO peer_grants (peer_id, position, grant_id)
    SELECT peer_id, 0, template_id FROM migrate_peer_templates;

CREATE TABLE peer_visible_networks (
    peer_id INTEGER NOT NULL REFERENCES peers (id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    network_id INTEGER NOT NULL REFERENCES networks (id),
    PRIMARY KEY (peer_id, position)
);
INSERT INTO peer_visible_networks (peer_id, position, network_id)
    SELECT m.peer_id, v.position, v.network_id
    FROM migrate_peer_templates m
    JOIN template_visible_networks v ON v.template_id = m.template_id
    JOIN peers p ON p.id = m.peer_id
    WHERE p.wireguard_public_key IS NOT NULL;

DROP TABLE migrate_peer_templates;
DROP TABLE template_visible_networks;
DROP TABLE template_grant_ports;
DROP TABLE template_grants;
DROP TABLE templates;

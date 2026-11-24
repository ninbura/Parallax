-- The configuration: one table per part of the model.
--
-- Every row has a hidden integer id beside its unique name. Other tables
-- (grants, peers, and later the GUI's own tables) point at the id, so a
-- rename keeps them. Ids never leave the database: the model and TOML only
-- know names. Lists keep their order in `position`.
--
-- Plain SQL, kept portable to Postgres: addresses, prefixes, keys and
-- enum values are TEXT in their TOML spelling.

CREATE TABLE server (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    wireguard_interface TEXT NOT NULL,
    wireguard_listen_port INTEGER NOT NULL,
    wireguard_supernet TEXT NOT NULL,
    wireguard_endpoint TEXT NOT NULL,
    wireguard_public_key TEXT NOT NULL,
    wireguard_private_key_file TEXT NOT NULL,
    headscale_interface TEXT NOT NULL,
    headscale_server_url TEXT NOT NULL,
    headscale_api_key_file TEXT NOT NULL,
    headscale_derp TEXT NOT NULL,
    headscale_subnet_router_node TEXT NOT NULL,
    dns_listen TEXT,
    dns_port INTEGER NOT NULL,
    dns_public_resolver TEXT NOT NULL,
    firewall_backend TEXT NOT NULL,
    firewall_docker_coexistence BOOLEAN NOT NULL,
    proxy_listen TEXT,
    proxy_port INTEGER NOT NULL,
    proxy_certificates TEXT NOT NULL,
    proxy_upstream_ca TEXT NOT NULL,
    wan_interface TEXT
);

CREATE TABLE networks (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    position INTEGER NOT NULL,
    interface TEXT NOT NULL,
    gateway_address TEXT,
    subnet TEXT NOT NULL,
    mapped_to TEXT,
    masquerade BOOLEAN NOT NULL
);

CREATE TABLE network_upstream_dns (
    network_id INTEGER NOT NULL REFERENCES networks (id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    address TEXT NOT NULL,
    PRIMARY KEY (network_id, position)
);

CREATE TABLE network_domains (
    network_id INTEGER NOT NULL REFERENCES networks (id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    domain TEXT NOT NULL,
    PRIMARY KEY (network_id, position)
);

CREATE TABLE services (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    position INTEGER NOT NULL,
    host TEXT NOT NULL,
    proto TEXT NOT NULL,
    port INTEGER NOT NULL,
    nginx_vhost BOOLEAN NOT NULL
);

CREATE TABLE service_hostnames (
    service_id INTEGER NOT NULL REFERENCES services (id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    hostname TEXT NOT NULL,
    PRIMARY KEY (service_id, position)
);

CREATE TABLE templates (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    position INTEGER NOT NULL,
    wireguard_pool TEXT NOT NULL,
    headscale_user TEXT,
    headscale_tag TEXT,
    -- false: every network is visible (`visible_networks` absent). true: only
    -- the rows in template_visible_networks, which may be none.
    visible_networks_limited BOOLEAN NOT NULL,
    dns_wireguard TEXT NOT NULL,
    dns_tailscale TEXT NOT NULL,
    dns_public BOOLEAN NOT NULL,
    client_allowed_ips TEXT NOT NULL,
    client_mtu INTEGER,
    client_persistent_keepalive INTEGER
);

CREATE TABLE template_visible_networks (
    template_id INTEGER NOT NULL REFERENCES templates (id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    network_id INTEGER NOT NULL REFERENCES networks (id),
    PRIMARY KEY (template_id, position)
);

CREATE TABLE template_grants (
    template_id INTEGER NOT NULL REFERENCES templates (id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    kind TEXT NOT NULL,
    network_id INTEGER REFERENCES networks (id),
    service_id INTEGER REFERENCES services (id),
    ip TEXT,
    proto TEXT,
    port INTEGER,
    PRIMARY KEY (template_id, position),
    CHECK (
        (kind IN ('all_networks', 'internet')
            AND network_id IS NULL AND service_id IS NULL
            AND ip IS NULL AND proto IS NULL AND port IS NULL)
        OR (kind = 'network'
            AND network_id IS NOT NULL AND service_id IS NULL
            AND ip IS NULL AND proto IS NULL AND port IS NULL)
        OR (kind = 'service'
            AND network_id IS NULL AND service_id IS NOT NULL
            AND ip IS NULL AND proto IS NULL AND port IS NULL)
        OR (kind = 'host'
            AND network_id IS NULL AND service_id IS NULL
            AND ip IS NOT NULL AND proto IS NULL AND port IS NULL)
        OR (kind = 'host_port'
            AND network_id IS NULL AND service_id IS NULL
            AND ip IS NOT NULL AND proto IS NOT NULL AND port IS NOT NULL)
    )
);

CREATE TABLE peers (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    position INTEGER NOT NULL,
    template_id INTEGER NOT NULL REFERENCES templates (id),
    transport TEXT NOT NULL,
    enabled BOOLEAN NOT NULL,
    expires TEXT,
    -- The WireGuard identity: absent when the public key is NULL.
    wireguard_public_key TEXT,
    wireguard_address TEXT,
    wireguard_private_key TEXT,
    wireguard_preshared_key TEXT,
    -- The Tailscale identity may be present with every field empty.
    tailscale BOOLEAN NOT NULL,
    tailscale_node_id INTEGER,
    tailscale_address TEXT,
    CHECK (wireguard_public_key IS NOT NULL OR (wireguard_address IS NULL
        AND wireguard_private_key IS NULL AND wireguard_preshared_key IS NULL)),
    CHECK (tailscale OR (tailscale_node_id IS NULL AND tailscale_address IS NULL))
);

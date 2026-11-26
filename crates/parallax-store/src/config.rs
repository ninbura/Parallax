//! Reading and writing the configuration tables.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Display;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use parallax_core::model::*;
use parallax_core::Config;
use serde::de::DeserializeOwned;
use serde::Serialize;
use turso::{Row, Value};

use crate::{Error, Result, Store};

impl Store {
    /// The whole configuration. Fails with [`Error::Empty`] before the first import.
    pub async fn load(&mut self) -> Result<Config> {
        // One read transaction: a consistent snapshot.
        self.conn.execute("BEGIN", ()).await?;
        let result = self.load_inner().await;
        let _ = self.conn.execute("COMMIT", ()).await;
        result.map_err(|e| self.busy(e))
    }

    pub(crate) async fn load_inner(&self) -> Result<Config> {
        let Some(server) = self.load_server().await? else {
            return Err(Error::Empty(self.path.clone()));
        };
        Ok(Config {
            server,
            networks: self.load_networks().await?,
            services: self.load_services().await?,
            grants: self.load_grants().await?,
            peers: self.load_peers().await?,
        })
    }

    /// Replace the stored configuration with `config`, in one transaction.
    ///
    /// Rows are matched by name: a kept name keeps its id, a new name gets a
    /// row, a missing name loses its row. Validate `config` first; the store
    /// only refuses what it can't represent (a grant naming an unknown
    /// network, a duplicate name).
    ///
    /// Takes `&mut self`: one transaction at a time on this connection.
    pub async fn save(&mut self, config: &Config) -> Result<()> {
        self.begin().await.map_err(|e| self.busy(e))?;
        let result = self.save_inner(config).await;
        self.finish(result).await.map_err(|e| self.busy(e))?;
        self.tighten()
    }

    /// Read, change and write the configuration in one write transaction, so
    /// no other write lands in between (two `peer add`s can't both take
    /// the same free address). Nothing is saved if `change` fails.
    pub async fn update<T, E>(
        &mut self,
        change: impl FnOnce(&mut Config) -> std::result::Result<T, E>,
    ) -> std::result::Result<T, E>
    where
        E: From<Error>,
    {
        self.begin().await.map_err(|e| self.busy(e))?;
        let mut config = match self.load_inner().await {
            Ok(config) => config,
            Err(e) => {
                self.rollback().await;
                return Err(self.busy(e).into());
            }
        };
        let out = match change(&mut config) {
            Ok(out) => out,
            Err(e) => {
                self.rollback().await;
                return Err(e);
            }
        };
        let saved = self.save_inner(&config).await;
        self.finish(saved).await.map_err(|e| self.busy(e))?;
        self.tighten()?;
        Ok(out)
    }

    /// Save `config` only if the database holds no configuration yet, checked
    /// inside the same transaction. Returns whether it saved.
    pub async fn save_if_empty(&mut self, config: &Config) -> Result<bool> {
        self.begin().await.map_err(|e| self.busy(e))?;
        let result = async {
            if self.load_server().await?.is_some() {
                return Ok(false);
            }
            self.save_inner(config).await?;
            Ok(true)
        }
        .await;
        let saved = self.finish(result).await.map_err(|e| self.busy(e))?;
        self.tighten()?;
        Ok(saved)
    }

    async fn save_inner(&self, config: &Config) -> Result<()> {
        // Refuse duplicate names before writing anything: a second row with a
        // kept name would overwrite the first.
        unique("network", config.networks.iter().map(|n| &n.name))?;
        unique("service", config.services.iter().map(|s| &s.name))?;
        unique("grant", config.grants.iter().map(|g| &g.name))?;
        unique("peer", config.peers.iter().map(|p| &p.name))?;

        // Rule, attachment and visibility rows have no identity of their
        // own; rewrite them all, which also frees grants, networks and
        // services about to be removed.
        for table in [
            "grant_rule_ports",
            "grant_rules",
            "peer_grants",
            "peer_visible_networks",
        ] {
            self.exec(&format!("DELETE FROM {table}"), Vec::new())
                .await?;
        }

        self.save_server(&config.server).await?;
        let networks = self.save_networks(&config.networks).await?;
        let services = self.save_services(&config.services).await?;
        let grants = self
            .save_grants(&config.grants, &networks, &services)
            .await?;
        self.save_peers(&config.peers, &grants, &networks).await?;

        // Removals last, children first: by now nothing kept points at them.
        self.delete_missing("peers", config.peers.iter().map(|p| &p.name))
            .await?;
        self.delete_missing("grants", config.grants.iter().map(|g| &g.name))
            .await?;
        self.delete_missing("services", config.services.iter().map(|s| &s.name))
            .await?;
        self.delete_missing("networks", config.networks.iter().map(|n| &n.name))
            .await?;
        Ok(())
    }

    // --- server ---------------------------------------------------------

    async fn load_server(&self) -> Result<Option<ServerConfig>> {
        let rows = self
            .rows(
                "SELECT wireguard_interface, wireguard_listen_port, wireguard_supernet,
                    wireguard_endpoint, wireguard_public_key, wireguard_private_key_file,
                    headscale_interface, headscale_server_url, headscale_api_key_file,
                    headscale_derp, headscale_subnet_router_node,
                    dns_listen, dns_port, dns_public_resolver,
                    firewall_backend, firewall_docker_coexistence,
                    proxy_listen, proxy_port, proxy_certificates, proxy_upstream_ca,
                    wan_interface,
                    backup_directory, backup_automatic, backup_interval, backup_keep,
                    backup_encrypt, backup_passphrase_file,
                    public_ip_address, public_ip_encrypted_dns,
                    wireguard_peer_dns, wireguard_peer_allowed_ips, wireguard_peer_mtu,
                    wireguard_peer_persistent_keepalive, headscale_dns
                 FROM server WHERE id = 1",
                Vec::new(),
            )
            .await?;
        let Some(r) = rows.first() else {
            return Ok(None);
        };
        let at = "server";
        Ok(Some(ServerConfig {
            wireguard: WireGuardServer {
                interface: r.get(0)?,
                listen_port: port(at, r.get(1)?)?,
                supernet: parse(at, "wireguard supernet", &r.get::<String>(2)?)?,
                endpoint: r.get(3)?,
                public_key: parse(at, "wireguard public key", &r.get::<String>(4)?)?,
                private_key_file: PathBuf::from(r.get::<String>(5)?),
                peer_defaults: PeerDefaults {
                    dns: variant(at, "wireguard peer dns", &r.get::<String>(29)?)?,
                    allowed_ips: variant(at, "wireguard peer allowed_ips", &r.get::<String>(30)?)?,
                    mtu: small_opt(at, "wireguard peer mtu", r.get(31)?)?,
                    persistent_keepalive: small_opt(
                        at,
                        "wireguard peer persistent_keepalive",
                        r.get(32)?,
                    )?,
                },
            },
            headscale: HeadscaleServer {
                interface: r.get(6)?,
                server_url: r.get(7)?,
                api_key_file: PathBuf::from(r.get::<String>(8)?),
                derp: variant(at, "headscale derp", &r.get::<String>(9)?)?,
                subnet_router_node: r.get(10)?,
                dns: variant(at, "headscale dns", &r.get::<String>(33)?)?,
            },
            dns: DnsServer {
                listen: parse_opt(at, "dns listen", r.get(11)?)?,
                port: port(at, r.get(12)?)?,
                public_resolver: parse(at, "dns public resolver", &r.get::<String>(13)?)?,
            },
            firewall: FirewallServer {
                backend: variant(at, "firewall backend", &r.get::<String>(14)?)?,
                docker_coexistence: r.get(15)?,
            },
            proxy: ProxyServer {
                listen: parse_opt(at, "proxy listen", r.get(16)?)?,
                port: port(at, r.get(17)?)?,
                certificates: PathBuf::from(r.get::<String>(18)?),
                upstream_ca: PathBuf::from(r.get::<String>(19)?),
            },
            backup: BackupServer {
                directory: PathBuf::from(r.get::<String>(21)?),
                automatic: r.get(22)?,
                interval: parse(at, "backup interval", &r.get::<String>(23)?)?,
                keep: {
                    let keep: i64 = r.get(24)?;
                    u32::try_from(keep).map_err(|_| {
                        Error::Stored(format!("{at}: backup keep {keep} is out of range"))
                    })?
                },
                encrypt: r.get(25)?,
                passphrase_file: PathBuf::from(r.get::<String>(26)?),
            },
            public_ip: PublicIpServer {
                address: parse_opt(at, "public ip address", r.get(27)?)?,
                encrypted_dns: r
                    .get::<String>(28)?
                    .split(',')
                    .filter(|p| !p.is_empty())
                    .map(|p| parse(at, "public ip encrypted dns", p))
                    .collect::<Result<_>>()?,
            },
            wan_interface: r.get(20)?,
        }))
    }

    async fn save_server(&self, s: &ServerConfig) -> Result<()> {
        let w = &s.wireguard;
        let h = &s.headscale;
        let b = &s.backup;
        self.upsert(
            "server",
            "id",
            &[
                ("id", Value::from(1)),
                ("wireguard_interface", text(&w.interface)),
                ("wireguard_listen_port", w.listen_port.into()),
                ("wireguard_supernet", text(w.supernet)),
                ("wireguard_endpoint", text(&w.endpoint)),
                ("wireguard_public_key", w.public_key.to_base64().into()),
                (
                    "wireguard_private_key_file",
                    path("server.wireguard.private_key_file", &w.private_key_file)?,
                ),
                ("headscale_interface", text(&h.interface)),
                ("headscale_server_url", text(&h.server_url)),
                (
                    "headscale_api_key_file",
                    path("server.headscale.api_key_file", &h.api_key_file)?,
                ),
                ("headscale_derp", variant_text(&h.derp)?),
                ("headscale_subnet_router_node", text(&h.subnet_router_node)),
                ("headscale_dns", variant_text(&h.dns)?),
                ("wireguard_peer_dns", variant_text(&w.peer_defaults.dns)?),
                (
                    "wireguard_peer_allowed_ips",
                    variant_text(&w.peer_defaults.allowed_ips)?,
                ),
                ("wireguard_peer_mtu", w.peer_defaults.mtu.into()),
                (
                    "wireguard_peer_persistent_keepalive",
                    w.peer_defaults.persistent_keepalive.into(),
                ),
                ("dns_listen", s.dns.listen.map(|a| a.to_string()).into()),
                ("dns_port", s.dns.port.into()),
                ("dns_public_resolver", text(s.dns.public_resolver)),
                ("firewall_backend", variant_text(&s.firewall.backend)?),
                (
                    "firewall_docker_coexistence",
                    s.firewall.docker_coexistence.into(),
                ),
                ("proxy_listen", s.proxy.listen.map(|a| a.to_string()).into()),
                ("proxy_port", s.proxy.port.into()),
                (
                    "proxy_certificates",
                    path("server.proxy.certificates", &s.proxy.certificates)?,
                ),
                (
                    "proxy_upstream_ca",
                    path("server.proxy.upstream_ca", &s.proxy.upstream_ca)?,
                ),
                ("wan_interface", s.wan_interface.clone().into()),
                (
                    "backup_directory",
                    path("server.backup.directory", &b.directory)?,
                ),
                ("backup_automatic", b.automatic.into()),
                ("backup_interval", text(b.interval)),
                ("backup_keep", i64::from(b.keep).into()),
                ("backup_encrypt", b.encrypt.into()),
                (
                    "backup_passphrase_file",
                    path("server.backup.passphrase_file", &b.passphrase_file)?,
                ),
                (
                    "public_ip_address",
                    s.public_ip.address.map(|a| a.to_string()).into(),
                ),
                (
                    "public_ip_encrypted_dns",
                    s.public_ip
                        .encrypted_dns
                        .iter()
                        .map(|p| p.as_str())
                        .collect::<Vec<_>>()
                        .join(",")
                        .into(),
                ),
            ],
        )
        .await?;
        Ok(())
    }

    // --- networks -------------------------------------------------------

    async fn load_networks(&self) -> Result<Vec<Network>> {
        let mut out = Vec::new();
        let rows = self
            .rows(
                "SELECT id, name, interface, gateway_address, subnet, mapped_to, masquerade
                 FROM networks ORDER BY position",
                Vec::new(),
            )
            .await?;
        for r in rows {
            let id: i64 = r.get(0)?;
            let name: String = r.get(1)?;
            let at = format!("network '{name}'");
            let mut upstream_dns = Vec::new();
            for a in self
                .strings(
                    "SELECT address FROM network_upstream_dns WHERE network_id = ?1 ORDER BY position",
                    id,
                )
                .await?
            {
                upstream_dns.push(parse(&at, "upstream dns", &a)?);
            }
            out.push(Network {
                interface: r.get(2)?,
                gateway_address: parse_opt(&at, "gateway address", r.get(3)?)?,
                subnet: parse(&at, "subnet", &r.get::<String>(4)?)?,
                mapped_to: parse_opt(&at, "mapped_to", r.get(5)?)?,
                upstream_dns,
                domains: self
                    .strings(
                        "SELECT domain FROM network_domains WHERE network_id = ?1 ORDER BY position",
                        id,
                    )
                    .await?,
                masquerade: r.get(6)?,
                name,
            });
        }
        Ok(out)
    }

    async fn save_networks(&self, networks: &[Network]) -> Result<BTreeMap<String, i64>> {
        let mut ids = BTreeMap::new();
        for (position, n) in (0_i64..).zip(networks) {
            let id = self
                .upsert(
                    "networks",
                    "name",
                    &[
                        ("name", text(&n.name)),
                        ("position", position.into()),
                        ("interface", text(&n.interface)),
                        (
                            "gateway_address",
                            n.gateway_address.map(|a| a.to_string()).into(),
                        ),
                        ("subnet", text(n.subnet)),
                        ("mapped_to", n.mapped_to.map(|m| m.to_string()).into()),
                        ("masquerade", n.masquerade.into()),
                    ],
                )
                .await?;
            self.replace_list(
                "network_upstream_dns",
                "network_id",
                id,
                "address",
                &n.upstream_dns,
            )
            .await?;
            self.replace_list("network_domains", "network_id", id, "domain", &n.domains)
                .await?;
            ids.insert(n.name.clone(), id);
        }
        Ok(ids)
    }

    // --- services -------------------------------------------------------

    async fn load_services(&self) -> Result<Vec<Service>> {
        let mut out = Vec::new();
        let rows = self
            .rows(
                "SELECT id, name, host, nginx_vhost FROM services ORDER BY position",
                Vec::new(),
            )
            .await?;
        for r in rows {
            let id: i64 = r.get(0)?;
            let name: String = r.get(1)?;
            let at = format!("service '{name}'");
            let ports = self
                .strings(
                    "SELECT ports FROM service_ports WHERE service_id = ?1 ORDER BY position",
                    id,
                )
                .await?;
            out.push(Service {
                host: parse(&at, "host", &r.get::<String>(2)?)?,
                ports: ports
                    .iter()
                    .map(|p| parse(&at, "ports", p))
                    .collect::<Result<_>>()?,
                nginx_vhost: r.get(3)?,
                hostnames: self
                    .strings(
                        "SELECT hostname FROM service_hostnames WHERE service_id = ?1 ORDER BY position",
                        id,
                    )
                    .await?,
                name,
            });
        }
        Ok(out)
    }

    async fn save_services(&self, services: &[Service]) -> Result<BTreeMap<String, i64>> {
        let mut ids = BTreeMap::new();
        for (position, s) in (0_i64..).zip(services) {
            let id = self
                .upsert(
                    "services",
                    "name",
                    &[
                        ("name", text(&s.name)),
                        ("position", position.into()),
                        ("host", text(&s.host)),
                        ("nginx_vhost", s.nginx_vhost.into()),
                    ],
                )
                .await?;
            self.replace_list("service_ports", "service_id", id, "ports", &s.ports)
                .await?;
            self.replace_list(
                "service_hostnames",
                "service_id",
                id,
                "hostname",
                &s.hostnames,
            )
            .await?;
            ids.insert(s.name.clone(), id);
        }
        Ok(ids)
    }

    // --- grants ---------------------------------------------------------

    async fn load_grants(&self) -> Result<Vec<Grant>> {
        let mut out = Vec::new();
        let rows = self
            .rows(
                "SELECT id, name, everyone FROM grants ORDER BY position",
                Vec::new(),
            )
            .await?;
        for r in rows {
            let id: i64 = r.get(0)?;
            let name: String = r.get(1)?;
            let at = format!("grant '{name}'");
            out.push(Grant {
                rules: self.load_rules(id, &at).await?,
                everyone: r.get(2)?,
                name,
            });
        }
        Ok(out)
    }

    async fn load_rules(&self, grant_id: i64, at: &str) -> Result<Vec<Rule>> {
        let rows = self
            .rows(
                "SELECT g.kind, n.name, s.name, g.host, g.position
                 FROM grant_rules g
                 LEFT JOIN networks n ON n.id = g.network_id
                 LEFT JOIN services s ON s.id = g.service_id
                 WHERE g.grant_id = ?1 ORDER BY g.position",
                vec![grant_id.into()],
            )
            .await?;
        let mut rules = Vec::new();
        for r in rows {
            let kind: String = r.get(0)?;
            let missing = || Error::Stored(format!("{at}: {kind} rule is incomplete"));
            rules.push(match kind.as_str() {
                "all_networks" => Rule::AllNetworks,
                "internet" => Rule::Internet,
                "public_dns" => Rule::PublicDns,
                "network" => Rule::Network {
                    name: r.get::<Option<String>>(1)?.ok_or_else(missing)?,
                },
                "service" => Rule::Service {
                    name: r.get::<Option<String>>(2)?.ok_or_else(missing)?,
                },
                "host" => Rule::Host {
                    host: parse(
                        at,
                        "rule host",
                        &r.get::<Option<String>>(3)?.ok_or_else(missing)?,
                    )?,
                    ports: self
                        .rows(
                            "SELECT ports FROM grant_rule_ports
                             WHERE grant_id = ?1 AND rule_position = ?2 ORDER BY position",
                            vec![grant_id.into(), r.get::<i64>(4)?.into()],
                        )
                        .await?
                        .iter()
                        .map(|p| parse(at, "rule ports", &p.get::<String>(0)?))
                        .collect::<Result<_>>()?,
                },
                other => return Err(Error::Stored(format!("{at}: unknown rule kind '{other}'"))),
            });
        }
        Ok(rules)
    }

    async fn save_grants(
        &self,
        grants: &[Grant],
        networks: &BTreeMap<String, i64>,
        services: &BTreeMap<String, i64>,
    ) -> Result<BTreeMap<String, i64>> {
        let mut ids = BTreeMap::new();
        for (position, g) in (0_i64..).zip(grants) {
            let at = format!("grant '{}'", g.name);
            let id = self
                .upsert(
                    "grants",
                    "name",
                    &[
                        ("name", text(&g.name)),
                        ("position", position.into()),
                        ("everyone", g.everyone.into()),
                    ],
                )
                .await?;
            for (position, rule) in (0_i64..).zip(&g.rules) {
                let null = || Value::Null;
                let (kind, network, service, host) = match rule {
                    Rule::AllNetworks => ("all_networks", null(), null(), null()),
                    Rule::Internet => ("internet", null(), null(), null()),
                    Rule::PublicDns => ("public_dns", null(), null(), null()),
                    Rule::Network { name } => (
                        "network",
                        lookup(networks, &at, "rule refers to unknown network", name)?.into(),
                        null(),
                        null(),
                    ),
                    Rule::Service { name } => (
                        "service",
                        null(),
                        lookup(services, &at, "rule refers to unknown service", name)?.into(),
                        null(),
                    ),
                    Rule::Host { host, .. } => ("host", null(), null(), text(host)),
                };
                self.exec(
                    "INSERT INTO grant_rules
                        (grant_id, position, kind, network_id, service_id, host)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    vec![
                        id.into(),
                        position.into(),
                        kind.into(),
                        network,
                        service,
                        host,
                    ],
                )
                .await?;
                if let Rule::Host { ports, .. } = rule {
                    for (n, p) in (0_i64..).zip(ports) {
                        self.exec(
                            "INSERT INTO grant_rule_ports
                                (grant_id, rule_position, position, ports)
                             VALUES (?1, ?2, ?3, ?4)",
                            vec![id.into(), position.into(), n.into(), text(p)],
                        )
                        .await?;
                    }
                }
            }
            ids.insert(g.name.clone(), id);
        }
        Ok(ids)
    }

    // --- peers ----------------------------------------------------------

    async fn load_peers(&self) -> Result<Vec<Peer>> {
        let rows = self
            .rows(
                "SELECT id, name, transport, enabled, expires,
                    wireguard_public_key, wireguard_address, wireguard_private_key,
                    wireguard_preshared_key, tailscale, tailscale_node_id, tailscale_address,
                    wireguard_dns, wireguard_allowed_ips, wireguard_mtu,
                    wireguard_persistent_keepalive, wireguard_visible_networks_limited
                 FROM peers ORDER BY position",
                Vec::new(),
            )
            .await?;
        let mut out = Vec::new();
        for r in rows {
            let id: i64 = r.get(0)?;
            let name: String = r.get(1)?;
            let at = format!("peer '{name}'");
            let wireguard = match r.get::<Option<String>>(5)? {
                Some(public_key) => {
                    let missing = |what: &str| Error::Stored(format!("{at}: no wireguard {what}"));
                    let limited: bool = r
                        .get::<Option<bool>>(16)?
                        .ok_or_else(|| missing("visible networks"))?;
                    Some(WireGuardPeer {
                        public_key: parse(&at, "wireguard public key", &public_key)?,
                        address: parse_opt(&at, "wireguard address", r.get(6)?)?,
                        private_key: secret_opt(&at, "wireguard private key", r.get(7)?)?,
                        preshared_key: secret_opt(&at, "wireguard preshared key", r.get(8)?)?,
                        dns: variant(
                            &at,
                            "wireguard dns",
                            &r.get::<Option<String>>(12)?.ok_or_else(|| missing("dns"))?,
                        )?,
                        allowed_ips: variant(
                            &at,
                            "wireguard allowed_ips",
                            &r.get::<Option<String>>(13)?
                                .ok_or_else(|| missing("allowed_ips"))?,
                        )?,
                        mtu: small_opt(&at, "wireguard mtu", r.get(14)?)?,
                        persistent_keepalive: small_opt(
                            &at,
                            "wireguard persistent_keepalive",
                            r.get(15)?,
                        )?,
                        visible_networks: if limited {
                            Some(
                                self.strings(
                                    "SELECT n.name FROM peer_visible_networks v
                                     JOIN networks n ON n.id = v.network_id
                                     WHERE v.peer_id = ?1 ORDER BY v.position",
                                    id,
                                )
                                .await?,
                            )
                        } else {
                            None
                        },
                    })
                }
                None => None,
            };
            let tailscale = if r.get::<bool>(9)? {
                Some(TailscalePeer {
                    node_id: r
                        .get::<Option<i64>>(10)?
                        .map(|id| {
                            u64::try_from(id).map_err(|_| {
                                Error::Stored(format!("{at}: tailscale node id {id} is negative"))
                            })
                        })
                        .transpose()?,
                    address: parse_opt(&at, "tailscale address", r.get(11)?)?,
                })
            } else {
                None
            };
            out.push(Peer {
                grants: self
                    .strings(
                        "SELECT g.name FROM peer_grants pg
                         JOIN grants g ON g.id = pg.grant_id
                         WHERE pg.peer_id = ?1 ORDER BY pg.position",
                        id,
                    )
                    .await?,
                transport: variant(&at, "transport", &r.get::<String>(2)?)?,
                enabled: r.get(3)?,
                expires: parse_opt(&at, "expires", r.get(4)?)?,
                wireguard,
                tailscale,
                name,
            });
        }
        Ok(out)
    }

    async fn save_peers(
        &self,
        peers: &[Peer],
        grants: &BTreeMap<String, i64>,
        networks: &BTreeMap<String, i64>,
    ) -> Result<()> {
        for (position, p) in (0_i64..).zip(peers) {
            let at = format!("peer '{}'", p.name);
            let wg = p.wireguard.as_ref();
            let ts = p.tailscale.as_ref();
            let node_id = ts
                .and_then(|t| t.node_id)
                .map(|id| {
                    i64::try_from(id).map_err(|_| {
                        Error::Invalid(format!(
                            "{at}: tailscale node id {id} is too large to store"
                        ))
                    })
                })
                .transpose()?;
            let id = self
                .upsert(
                    "peers",
                    "name",
                    &[
                        ("name", text(&p.name)),
                        ("position", position.into()),
                        ("transport", variant_text(&p.transport)?),
                        ("enabled", p.enabled.into()),
                        ("expires", p.expires.map(|d| d.to_string()).into()),
                        (
                            "wireguard_public_key",
                            wg.map(|w| w.public_key.to_base64()).into(),
                        ),
                        (
                            "wireguard_address",
                            wg.and_then(|w| w.address).map(|a| a.to_string()).into(),
                        ),
                        (
                            "wireguard_private_key",
                            wg.and_then(|w| w.private_key.as_ref())
                                .map(|k| k.expose_base64())
                                .into(),
                        ),
                        (
                            "wireguard_preshared_key",
                            wg.and_then(|w| w.preshared_key.as_ref())
                                .map(|k| k.expose_base64())
                                .into(),
                        ),
                        (
                            "wireguard_dns",
                            wg.map(|w| variant_text(&w.dns)).transpose()?.into(),
                        ),
                        (
                            "wireguard_allowed_ips",
                            wg.map(|w| variant_text(&w.allowed_ips)).transpose()?.into(),
                        ),
                        ("wireguard_mtu", wg.and_then(|w| w.mtu).into()),
                        (
                            "wireguard_persistent_keepalive",
                            wg.and_then(|w| w.persistent_keepalive).into(),
                        ),
                        (
                            "wireguard_visible_networks_limited",
                            wg.map(|w| w.visible_networks.is_some()).into(),
                        ),
                        ("tailscale", ts.is_some().into()),
                        ("tailscale_node_id", node_id.into()),
                        (
                            "tailscale_address",
                            ts.and_then(|t| t.address).map(|a| a.to_string()).into(),
                        ),
                    ],
                )
                .await?;
            for (position, g) in (0_i64..).zip(&p.grants) {
                let grant = lookup(grants, &at, "refers to unknown grant", g)?;
                self.exec(
                    "INSERT INTO peer_grants (peer_id, position, grant_id) VALUES (?1, ?2, ?3)",
                    vec![id.into(), position.into(), grant.into()],
                )
                .await?;
            }
            let visible = wg.and_then(|w| w.visible_networks.as_ref());
            for (position, n) in (0_i64..).zip(visible.into_iter().flatten()) {
                let network = lookup(
                    networks,
                    &at,
                    "visible_networks mentions unknown network",
                    n,
                )?;
                self.exec(
                    "INSERT INTO peer_visible_networks (peer_id, position, network_id)
                     VALUES (?1, ?2, ?3)",
                    vec![id.into(), position.into(), network.into()],
                )
                .await?;
            }
        }
        Ok(())
    }

    // --- helpers --------------------------------------------------------

    pub(crate) async fn exec(&self, sql: &str, params: Vec<Value>) -> Result<u64> {
        Ok(self.conn.execute(sql, params).await?)
    }

    pub(crate) async fn rows(&self, sql: &str, params: Vec<Value>) -> Result<Vec<Row>> {
        let mut rows = self.conn.query(sql, params).await?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().await? {
            out.push(row);
        }
        Ok(out)
    }

    /// The first column of every row, for the child lists keyed by a parent id.
    async fn strings(&self, sql: &str, parent: i64) -> Result<Vec<String>> {
        self.rows(sql, vec![parent.into()])
            .await?
            .iter()
            .map(|r| Ok(r.get::<String>(0)?))
            .collect()
    }

    /// Insert a row or update the one with the same `key`, returning its id.
    async fn upsert(&self, table: &str, key: &str, columns: &[(&str, Value)]) -> Result<i64> {
        let names: Vec<&str> = columns.iter().map(|(c, _)| *c).collect();
        let placeholders: Vec<String> = (1..=names.len()).map(|i| format!("?{i}")).collect();
        let updates: Vec<String> = names
            .iter()
            .filter(|c| **c != key)
            .map(|c| format!("{c} = excluded.{c}"))
            .collect();
        let sql = format!(
            "INSERT INTO {table} ({}) VALUES ({}) ON CONFLICT ({key}) DO UPDATE SET {} RETURNING id",
            names.join(", "),
            placeholders.join(", "),
            updates.join(", ")
        );
        let params = columns.iter().map(|(_, v)| v.clone()).collect::<Vec<_>>();
        let rows = self.rows(&sql, params).await?;
        match rows.first() {
            Some(r) => Ok(r.get::<i64>(0)?),
            None => Err(Error::Stored(format!("{table}: upsert returned no id"))),
        }
    }

    /// Rewrite a parent's ordered list of values.
    async fn replace_list<T: Display>(
        &self,
        table: &str,
        parent_column: &str,
        parent: i64,
        column: &str,
        values: &[T],
    ) -> Result<()> {
        self.exec(
            &format!("DELETE FROM {table} WHERE {parent_column} = ?1"),
            vec![parent.into()],
        )
        .await?;
        let sql = format!(
            "INSERT INTO {table} ({parent_column}, position, {column}) VALUES (?1, ?2, ?3)"
        );
        for (position, v) in (0_i64..).zip(values) {
            self.exec(&sql, vec![parent.into(), position.into(), text(v)])
                .await?;
        }
        Ok(())
    }

    /// Delete the rows of `table` whose name isn't in `keep`.
    async fn delete_missing(&self, table: &str, keep: impl Iterator<Item = &String>) -> Result<()> {
        let keep: BTreeSet<&String> = keep.collect();
        let stored = self
            .rows(&format!("SELECT name FROM {table}"), Vec::new())
            .await?;
        let sql = format!("DELETE FROM {table} WHERE name = ?1");
        for r in stored {
            let name: String = r.get(0)?;
            if !keep.contains(&name) {
                self.exec(&sql, vec![name.into()]).await?;
            }
        }
        Ok(())
    }
}

fn text(v: impl Display) -> Value {
    Value::from(v.to_string())
}

fn path(what: &str, p: &Path) -> Result<Value> {
    p.to_str()
        .map(Value::from)
        .ok_or_else(|| Error::Invalid(format!("{what} ({}) is not valid UTF-8", p.display())))
}

/// An enum in its TOML spelling, so the database and TOML always agree.
fn variant_text<T: Serialize>(v: &T) -> Result<Value> {
    match toml::Value::try_from(v) {
        Ok(toml::Value::String(s)) => Ok(Value::from(s)),
        _ => Err(Error::Invalid(
            "an enum value has no plain-text form".to_string(),
        )),
    }
}

fn variant<T: DeserializeOwned>(at: &str, what: &str, s: &str) -> Result<T> {
    use serde::de::value::{Error as DeError, StrDeserializer};
    T::deserialize(StrDeserializer::<DeError>::new(s))
        .map_err(|e| Error::Stored(format!("{at}: {what} '{s}': {e}")))
}

fn parse<T>(at: &str, what: &str, s: &str) -> Result<T>
where
    T: FromStr,
    T::Err: Display,
{
    s.parse()
        .map_err(|e| Error::Stored(format!("{at}: {what} '{s}': {e}")))
}

fn parse_opt<T>(at: &str, what: &str, s: Option<String>) -> Result<Option<T>>
where
    T: FromStr,
    T::Err: Display,
{
    s.map(|s| parse(at, what, &s)).transpose()
}

/// Like [`parse_opt`], but the error never quotes the stored value.
fn secret_opt<T: FromStr>(at: &str, what: &str, s: Option<String>) -> Result<Option<T>> {
    s.map(|s| {
        s.parse()
            .map_err(|_| Error::Stored(format!("{at}: {what} is not a valid key")))
    })
    .transpose()
}

fn port(at: &str, v: i64) -> Result<u16> {
    u16::try_from(v).map_err(|_| Error::Stored(format!("{at}: port {v} is out of range")))
}

fn small_opt(at: &str, what: &str, v: Option<i64>) -> Result<Option<u16>> {
    v.map(|v| {
        u16::try_from(v).map_err(|_| Error::Stored(format!("{at}: {what} {v} is out of range")))
    })
    .transpose()
}

fn lookup(ids: &BTreeMap<String, i64>, at: &str, problem: &str, name: &str) -> Result<i64> {
    ids.get(name)
        .copied()
        .ok_or_else(|| Error::Invalid(format!("{at}: {problem} '{name}'")))
}

fn unique<'a>(kind: &str, names: impl Iterator<Item = &'a String>) -> Result<()> {
    let mut seen = BTreeSet::new();
    for name in names {
        if !seen.insert(name) {
            return Err(Error::Invalid(format!("{kind} '{name}' is defined twice")));
        }
    }
    Ok(())
}

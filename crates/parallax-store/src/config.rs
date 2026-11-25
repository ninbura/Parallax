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
            templates: self.load_templates().await?,
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
        unique("template", config.templates.iter().map(|t| &t.name))?;
        unique("peer", config.peers.iter().map(|p| &p.name))?;

        // Grant and visibility rows have no identity of their own; rewrite them
        // all, which also frees networks and services about to be removed.
        self.exec("DELETE FROM template_grants", Vec::new()).await?;
        self.exec("DELETE FROM template_visible_networks", Vec::new())
            .await?;

        self.save_server(&config.server).await?;
        let networks = self.save_networks(&config.networks).await?;
        let services = self.save_services(&config.services).await?;
        let templates = self
            .save_templates(&config.templates, &networks, &services)
            .await?;
        self.save_peers(&config.peers, &templates).await?;

        // Removals last, children first: by now nothing kept points at them.
        self.delete_missing("peers", config.peers.iter().map(|p| &p.name))
            .await?;
        self.delete_missing("templates", config.templates.iter().map(|t| &t.name))
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
                    backup_encrypt, backup_passphrase_file
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
            },
            headscale: HeadscaleServer {
                interface: r.get(6)?,
                server_url: r.get(7)?,
                api_key_file: PathBuf::from(r.get::<String>(8)?),
                derp: variant(at, "headscale derp", &r.get::<String>(9)?)?,
                subnet_router_node: r.get(10)?,
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
                "SELECT id, name, host, proto, port, nginx_vhost FROM services ORDER BY position",
                Vec::new(),
            )
            .await?;
        for r in rows {
            let id: i64 = r.get(0)?;
            let name: String = r.get(1)?;
            let at = format!("service '{name}'");
            out.push(Service {
                host: parse(&at, "host", &r.get::<String>(2)?)?,
                proto: variant(&at, "proto", &r.get::<String>(3)?)?,
                port: port(&at, r.get(4)?)?,
                nginx_vhost: r.get(5)?,
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
                        ("host", text(s.host)),
                        ("proto", variant_text(&s.proto)?),
                        ("port", s.port.into()),
                        ("nginx_vhost", s.nginx_vhost.into()),
                    ],
                )
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

    // --- templates ------------------------------------------------------

    async fn load_templates(&self) -> Result<Vec<Template>> {
        let mut out = Vec::new();
        let rows = self
            .rows(
                "SELECT id, name, wireguard_pool, headscale_user, headscale_tag,
                    visible_networks_limited, dns_wireguard, dns_tailscale, dns_public,
                    client_allowed_ips, client_mtu, client_persistent_keepalive
                 FROM templates ORDER BY position",
                Vec::new(),
            )
            .await?;
        for r in rows {
            let id: i64 = r.get(0)?;
            let name: String = r.get(1)?;
            let at = format!("template '{name}'");
            let limited: bool = r.get(5)?;
            let visible_networks = if limited {
                Some(
                    self.strings(
                        "SELECT n.name FROM template_visible_networks v
                         JOIN networks n ON n.id = v.network_id
                         WHERE v.template_id = ?1 ORDER BY v.position",
                        id,
                    )
                    .await?,
                )
            } else {
                None
            };
            out.push(Template {
                wireguard: WireGuardTemplate {
                    pool: parse(&at, "wireguard pool", &r.get::<String>(2)?)?,
                },
                headscale: HeadscaleIdentity {
                    user: r.get(3)?,
                    tag: r.get(4)?,
                },
                grants: self.load_grants(id, &at).await?,
                visible_networks,
                dns: DnsPolicy {
                    wireguard: variant(&at, "dns wireguard", &r.get::<String>(6)?)?,
                    tailscale: variant(&at, "dns tailscale", &r.get::<String>(7)?)?,
                    public: r.get(8)?,
                },
                client: ClientDefaults {
                    allowed_ips: variant(&at, "client allowed_ips", &r.get::<String>(9)?)?,
                    mtu: small_opt(&at, "client mtu", r.get(10)?)?,
                    persistent_keepalive: small_opt(
                        &at,
                        "client persistent_keepalive",
                        r.get(11)?,
                    )?,
                },
                name,
            });
        }
        Ok(out)
    }

    async fn load_grants(&self, template_id: i64, at: &str) -> Result<Vec<Grant>> {
        let rows = self
            .rows(
                "SELECT g.kind, n.name, s.name, g.ip, g.proto, g.port
                 FROM template_grants g
                 LEFT JOIN networks n ON n.id = g.network_id
                 LEFT JOIN services s ON s.id = g.service_id
                 WHERE g.template_id = ?1 ORDER BY g.position",
                vec![template_id.into()],
            )
            .await?;
        let mut grants = Vec::new();
        for r in rows {
            let kind: String = r.get(0)?;
            let missing = || Error::Stored(format!("{at}: {kind} grant is incomplete"));
            grants.push(match kind.as_str() {
                "all_networks" => Grant::AllNetworks,
                "internet" => Grant::Internet,
                "network" => Grant::Network {
                    name: r.get::<Option<String>>(1)?.ok_or_else(missing)?,
                },
                "service" => Grant::Service {
                    name: r.get::<Option<String>>(2)?.ok_or_else(missing)?,
                },
                "host" => Grant::Host {
                    ip: parse(
                        at,
                        "grant ip",
                        &r.get::<Option<String>>(3)?.ok_or_else(missing)?,
                    )?,
                },
                "host_port" => Grant::HostPort {
                    ip: parse(
                        at,
                        "grant ip",
                        &r.get::<Option<String>>(3)?.ok_or_else(missing)?,
                    )?,
                    proto: variant(
                        at,
                        "grant proto",
                        &r.get::<Option<String>>(4)?.ok_or_else(missing)?,
                    )?,
                    port: port(at, r.get::<Option<i64>>(5)?.ok_or_else(missing)?)?,
                },
                other => return Err(Error::Stored(format!("{at}: unknown grant kind '{other}'"))),
            });
        }
        Ok(grants)
    }

    async fn save_templates(
        &self,
        templates: &[Template],
        networks: &BTreeMap<String, i64>,
        services: &BTreeMap<String, i64>,
    ) -> Result<BTreeMap<String, i64>> {
        let mut ids = BTreeMap::new();
        for (position, t) in (0_i64..).zip(templates) {
            let at = format!("template '{}'", t.name);
            let id = self
                .upsert(
                    "templates",
                    "name",
                    &[
                        ("name", text(&t.name)),
                        ("position", position.into()),
                        ("wireguard_pool", text(t.wireguard.pool)),
                        ("headscale_user", t.headscale.user.clone().into()),
                        ("headscale_tag", t.headscale.tag.clone().into()),
                        (
                            "visible_networks_limited",
                            t.visible_networks.is_some().into(),
                        ),
                        ("dns_wireguard", variant_text(&t.dns.wireguard)?),
                        ("dns_tailscale", variant_text(&t.dns.tailscale)?),
                        ("dns_public", t.dns.public.into()),
                        ("client_allowed_ips", variant_text(&t.client.allowed_ips)?),
                        ("client_mtu", t.client.mtu.into()),
                        (
                            "client_persistent_keepalive",
                            t.client.persistent_keepalive.into(),
                        ),
                    ],
                )
                .await?;
            for (position, n) in (0_i64..).zip(t.visible_networks.iter().flatten()) {
                let network = lookup(
                    networks,
                    &at,
                    "visible_networks mentions unknown network",
                    n,
                )?;
                self.exec(
                    "INSERT INTO template_visible_networks (template_id, position, network_id)
                     VALUES (?1, ?2, ?3)",
                    vec![id.into(), position.into(), network.into()],
                )
                .await?;
            }
            for (position, g) in (0_i64..).zip(&t.grants) {
                let null = || Value::Null;
                let (kind, network, service, ip, proto, port) = match g {
                    Grant::AllNetworks => ("all_networks", null(), null(), null(), null(), null()),
                    Grant::Internet => ("internet", null(), null(), null(), null(), null()),
                    Grant::Network { name } => (
                        "network",
                        lookup(networks, &at, "grant refers to unknown network", name)?.into(),
                        null(),
                        null(),
                        null(),
                        null(),
                    ),
                    Grant::Service { name } => (
                        "service",
                        null(),
                        lookup(services, &at, "grant refers to unknown service", name)?.into(),
                        null(),
                        null(),
                        null(),
                    ),
                    Grant::Host { ip } => ("host", null(), null(), text(ip), null(), null()),
                    Grant::HostPort { ip, proto, port } => (
                        "host_port",
                        null(),
                        null(),
                        text(ip),
                        variant_text(proto)?,
                        (*port).into(),
                    ),
                };
                self.exec(
                    "INSERT INTO template_grants
                        (template_id, position, kind, network_id, service_id, ip, proto, port)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    vec![
                        id.into(),
                        position.into(),
                        kind.into(),
                        network,
                        service,
                        ip,
                        proto,
                        port,
                    ],
                )
                .await?;
            }
            ids.insert(t.name.clone(), id);
        }
        Ok(ids)
    }

    // --- peers ----------------------------------------------------------

    async fn load_peers(&self) -> Result<Vec<Peer>> {
        let rows = self
            .rows(
                "SELECT p.name, t.name, p.transport, p.enabled, p.expires,
                    p.wireguard_public_key, p.wireguard_address, p.wireguard_private_key,
                    p.wireguard_preshared_key, p.tailscale, p.tailscale_node_id, p.tailscale_address
                 FROM peers p JOIN templates t ON t.id = p.template_id
                 ORDER BY p.position",
                Vec::new(),
            )
            .await?;
        let mut out = Vec::new();
        for r in rows {
            let name: String = r.get(0)?;
            let at = format!("peer '{name}'");
            let wireguard = match r.get::<Option<String>>(5)? {
                Some(public_key) => Some(WireGuardPeer {
                    public_key: parse(&at, "wireguard public key", &public_key)?,
                    address: parse_opt(&at, "wireguard address", r.get(6)?)?,
                    private_key: secret_opt(&at, "wireguard private key", r.get(7)?)?,
                    preshared_key: secret_opt(&at, "wireguard preshared key", r.get(8)?)?,
                }),
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
                template: r.get(1)?,
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

    async fn save_peers(&self, peers: &[Peer], templates: &BTreeMap<String, i64>) -> Result<()> {
        for (position, p) in (0_i64..).zip(peers) {
            let at = format!("peer '{}'", p.name);
            let template = lookup(templates, &at, "refers to unknown template", &p.template)?;
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
            self.upsert(
                "peers",
                "name",
                &[
                    ("name", text(&p.name)),
                    ("position", position.into()),
                    ("template_id", template.into()),
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
                    ("tailscale", ts.is_some().into()),
                    ("tailscale_node_id", node_id.into()),
                    (
                        "tailscale_address",
                        ts.and_then(|t| t.address).map(|a| a.to_string()).into(),
                    ),
                ],
            )
            .await?;
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

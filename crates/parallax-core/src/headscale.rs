//! What Parallax reads from Headscale, the Tailscale control server: its
//! users and nodes, through the admin API (`/api/v1`) at
//! `server.headscale.server_url`, with the API key in
//! `server.headscale.api_key_file` (ADR 0014).
//!
//! A Tailscale peer names its Headscale node by id. Headscale decides the
//! node's address, so the address it reports is the one the firewall, DNS
//! and the proxy use for that peer: the daemon asks every
//! [`POLL_SECONDS`] and applies again when an address changes. Only the
//! latest answer counts; when Headscale can't be reached, the last one
//! stays in effect (the nodes keep the tunnels they have meanwhile).
//!
//! The requests go through [`HeadscaleApi`], so everything here is tested
//! against recorded replies.

use std::collections::BTreeMap;
use std::fmt;
use std::net::Ipv4Addr;

use serde::Deserialize;

use crate::doctor::{Check, Outcome};
use crate::io::{HeadscaleApi, HttpReply};
use crate::model::{Config, HeadscaleServer, TransportKind};
use crate::secret::Secret;
use crate::{Error, Result, TAILSCALE_CGNAT};

/// How often the daemon asks Headscale for its nodes. A new node gets its
/// access within this long of registering.
pub const POLL_SECONDS: u64 = 10;

/// A Headscale user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub id: u64,
    pub name: String,
}

/// A Headscale node: one device logged in to the tailnet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    pub id: u64,
    /// The name it registered with (its hostname).
    pub name: String,
    /// The user it belongs to.
    pub user: String,
    /// Its tailnet IPv4 address; `None` when Headscale gave it only IPv6.
    pub address: Option<Ipv4Addr>,
    pub online: bool,
    /// `nodekey:...`, as its client reports it.
    pub node_key: String,
    /// The routes it advertises, and those Headscale approved.
    pub available_routes: Vec<String>,
    pub approved_routes: Vec<String>,
}

/// Each node's IPv4 address, by node id: what generation needs.
pub type Tailnet = BTreeMap<u64, Ipv4Addr>;

/// Whether any peer is on Tailscale with a known node, so the gateway has
/// to ask Headscale for addresses.
pub fn needed(config: &Config) -> bool {
    config.peers.iter().any(|p| {
        p.transport == TransportKind::Tailscale
            && p.tailscale.as_ref().is_some_and(|t| t.node_id.is_some())
    })
}

/// Headscale's version (`/version`, which needs no key).
pub fn version(server: &HeadscaleServer, api: &dyn HeadscaleApi) -> Result<String> {
    #[derive(Deserialize)]
    struct Version {
        version: String,
    }
    let body = get(server, api, "/version")?;
    let v: Version = parse(server, "/version", &body)?;
    Ok(v.version)
}

/// Every user.
pub fn users(server: &HeadscaleServer, api: &dyn HeadscaleApi) -> Result<Vec<User>> {
    #[derive(Deserialize)]
    struct Users {
        users: Vec<WireUser>,
    }
    const PATH: &str = "/api/v1/user";
    let body = get(server, api, PATH)?;
    let users: Users = parse(server, PATH, &body)?;
    users
        .users
        .into_iter()
        .map(|u| u.into_user(server, PATH))
        .collect()
}

/// Every node.
pub fn nodes(server: &HeadscaleServer, api: &dyn HeadscaleApi) -> Result<Vec<Node>> {
    #[derive(Deserialize)]
    struct Nodes {
        nodes: Vec<WireNode>,
    }
    const PATH: &str = "/api/v1/node";
    let body = get(server, api, PATH)?;
    let nodes: Nodes = parse(server, PATH, &body)?;
    nodes
        .nodes
        .into_iter()
        .map(|n| {
            let id = id(server, PATH, &n.id)?;
            // Headscale's IPv4 prefix is configurable; the firewall only
            // takes Tailscale traffic from the Tailscale range.
            let address = n
                .ip_addresses
                .iter()
                .filter_map(|a| a.parse::<Ipv4Addr>().ok())
                .find(|a| TAILSCALE_CGNAT.contains(a));
            Ok(Node {
                id,
                name: n.given_name,
                user: n.user.map(|u| u.name).unwrap_or_default(),
                address,
                online: n.online,
                node_key: n.node_key,
                available_routes: n.available_routes,
                approved_routes: n.approved_routes,
            })
        })
        .collect()
}

/// The user called `name`, if there is one.
pub fn user(server: &HeadscaleServer, api: &dyn HeadscaleApi, name: &str) -> Result<Option<User>> {
    #[derive(Deserialize)]
    struct Users {
        users: Vec<WireUser>,
    }
    // Names Parallax asks for are its own constants: nothing to escape.
    let path = format!("/api/v1/user?name={name}");
    let body = get(server, api, &path)?;
    let users: Users = parse(server, &path, &body)?;
    users
        .users
        .into_iter()
        .find(|u| u.name == name)
        .map(|u| u.into_user(server, &path))
        .transpose()
}

/// Create the user `name`.
pub fn create_user(server: &HeadscaleServer, api: &dyn HeadscaleApi, name: &str) -> Result<User> {
    #[derive(Deserialize)]
    struct Created {
        user: WireUser,
    }
    const PATH: &str = "/api/v1/user";
    let body = post(server, api, PATH, &serde_json::json!({ "name": name }))?;
    let created: Created = parse(server, PATH, &body)?;
    created.user.into_user(server, PATH)
}

/// A single-use pre-auth key for `user`, void after `expires` (UTC
/// midnight). Headscale shows the key only in this reply.
pub fn create_pre_auth_key(
    server: &HeadscaleServer,
    api: &dyn HeadscaleApi,
    user: u64,
    expires: crate::date::Date,
) -> Result<Secret> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Created {
        pre_auth_key: Key,
    }
    #[derive(Deserialize)]
    struct Key {
        key: String,
    }
    const PATH: &str = "/api/v1/preauthkey";
    let request = serde_json::json!({
        "user": user.to_string(),
        "reusable": false,
        "ephemeral": false,
        "expiration": format!("{expires}T00:00:00Z"),
    });
    let body = post(server, api, PATH, &request)?;
    // Not `parse`: its error would quote serde's, which can quote the key.
    let created: Created = serde_json::from_str(&body).map_err(|_| {
        Error::Headscale(format!(
            "Headscale at {} answered POST {PATH} with a reply Parallax can't read",
            server.server_url
        ))
    })?;
    Ok(Secret::new(created.pre_auth_key.key))
}

/// Approve exactly `routes` for node `id`; any other approved route is
/// withdrawn.
pub fn approve_routes(
    server: &HeadscaleServer,
    api: &dyn HeadscaleApi,
    id: u64,
    routes: &[ipnet::Ipv4Net],
) -> Result<()> {
    let path = format!("/api/v1/node/{id}/approve_routes");
    let routes: Vec<String> = routes.iter().map(ToString::to_string).collect();
    post(server, api, &path, &serde_json::json!({ "routes": routes })).map(drop)
}

/// The address of every node that has an IPv4 one.
pub fn tailnet(nodes: &[Node]) -> Tailnet {
    nodes
        .iter()
        .filter_map(|n| Some((n.id, n.address?)))
        .collect()
}

/// What changed between two tailnets, one line per node, for the log.
pub fn changes(before: Option<&Tailnet>, after: &Tailnet) -> Vec<String> {
    let empty = Tailnet::new();
    let before = before.unwrap_or(&empty);
    let mut lines = Vec::new();
    for (id, address) in after {
        match before.get(id) {
            Some(old) if old == address => {}
            Some(old) => lines.push(format!("Headscale node {id} moved from {old} to {address}")),
            None => lines.push(format!("Headscale node {id} is {address}")),
        }
    }
    for id in before.keys().filter(|id| !after.contains_key(id)) {
        lines.push(format!("Headscale node {id} is gone"));
    }
    lines
}

/// Each Tailscale peer that names a node, with that node if Headscale has it.
fn peer_nodes<'a>(config: &'a Config, nodes: &'a [Node]) -> Vec<(&'a str, u64, Option<&'a Node>)> {
    config
        .peers
        .iter()
        .filter(|p| p.transport == TransportKind::Tailscale)
        .filter_map(|p| {
            let id = p.tailscale.as_ref()?.node_id?;
            Some((p.name.as_str(), id, nodes.iter().find(|n| n.id == id)))
        })
        .collect()
}

/// `parallax headscale status`: Headscale's version, users and nodes, and
/// which peer each node is.
pub fn status(config: &Config, api: &dyn HeadscaleApi) -> Result<Vec<String>> {
    let server = &config.server.headscale;
    let version = version(server, api)?;
    let users = users(server, api)?;
    let nodes = nodes(server, api)?;
    let mut lines = vec![format!("Headscale {version} at {}", server.server_url)];
    lines.extend(
        users
            .iter()
            .map(|u| format!("user {} (id {})", u.name, u.id)),
    );
    let peers = peer_nodes(config, &nodes);
    for n in &nodes {
        let address = n
            .address
            .map_or("no IPv4 address".into(), |a| a.to_string());
        let online = if n.online { "online" } else { "offline" };
        let peer = peers
            .iter()
            .filter(|(_, id, _)| *id == n.id)
            .map(|(name, _, _)| format!("peer {name}"))
            .collect::<Vec<_>>();
        let peer = if peer.is_empty() {
            "no peer".to_string()
        } else {
            peer.join(", ")
        };
        lines.push(format!(
            "node {} {}: user {}, {address}, {online}; {peer}",
            n.id, n.name, n.user
        ));
    }
    for (name, id, _) in peers.iter().filter(|(_, _, node)| node.is_none()) {
        lines.push(format!("peer {name}: node {id} isn't in Headscale"));
    }
    Ok(lines)
}

/// `parallax doctor`: whether Headscale answers with the nodes the
/// Tailscale peers name. Not asked while no peer names one.
pub fn check(config: &Config, api: &dyn HeadscaleApi) -> Check {
    let server = &config.server.headscale;
    let outcome = if !needed(config) {
        Outcome::Ok("not asked: no Tailscale peer names a Headscale node".into())
    } else {
        match version(server, api).and_then(|v| Ok((v, nodes(server, api)?))) {
            // A warning: the gateway runs without Headscale (WireGuard,
            // DNS, the proxy), and doctor gates its start.
            Err(e) => Outcome::Warn(format!(
                "{e}. The daemon keeps the addresses Headscale last gave; after a restart, Tailscale peers that name a node get no access until it answers"
            )),
            Ok((version, nodes)) => {
                let peers = peer_nodes(config, &nodes);
                let missing: Vec<String> = peers
                    .iter()
                    .filter(|(_, _, n)| n.is_none_or(|n| n.address.is_none()))
                    .map(|(name, id, _)| format!("{name} (node {id})"))
                    .collect();
                if missing.is_empty() {
                    Outcome::Ok(format!(
                        "{version} at {}: {} nodes, every Tailscale peer's node has an address",
                        server.server_url,
                        nodes.len()
                    ))
                } else {
                    Outcome::Warn(format!(
                        "{version} at {}: no address for {}; those peers get no access",
                        server.server_url,
                        missing.join(", ")
                    ))
                }
            }
        }
    };
    Check {
        name: "headscale".into(),
        outcome,
    }
}

/// Fields of Headscale's replies that Parallax reads. Unknown fields are
/// ignored, unlike in the configuration: Headscale adds fields between
/// releases, and that must not stop the gateway.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireNode {
    id: String,
    given_name: String,
    #[serde(default)]
    node_key: String,
    #[serde(default)]
    available_routes: Vec<String>,
    #[serde(default)]
    approved_routes: Vec<String>,
    #[serde(default)]
    ip_addresses: Vec<String>,
    /// A tagged node may have none.
    #[serde(default)]
    user: Option<WireUser>,
    #[serde(default)]
    online: bool,
}

#[derive(Deserialize)]
struct WireUser {
    id: String,
    name: String,
}

impl WireUser {
    fn into_user(self, server: &HeadscaleServer, path: &str) -> Result<User> {
        Ok(User {
            id: id(server, path, &self.id)?,
            name: self.name,
        })
    }
}

/// Ids come as decimal strings (protobuf's JSON mapping of a uint64).
fn id(server: &HeadscaleServer, path: &str, id: &str) -> Result<u64> {
    id.parse().map_err(|_| {
        Error::Headscale(format!(
            "Headscale at {} answered {path} with id '{id}', which isn't a number",
            server.server_url
        ))
    })
}

fn get(server: &HeadscaleServer, api: &dyn HeadscaleApi, path: &str) -> Result<String> {
    answer(server, "GET", path, api.get(path)?)
}

fn post(
    server: &HeadscaleServer,
    api: &dyn HeadscaleApi,
    path: &str,
    body: &serde_json::Value,
) -> Result<String> {
    answer(server, "POST", path, api.post(path, &body.to_string())?)
}

/// The body of a 200, or an error naming the request and Headscale's words.
fn answer(server: &HeadscaleServer, method: &str, path: &str, reply: HttpReply) -> Result<String> {
    if reply.status == 200 {
        return Ok(reply.body);
    }
    let hint = match reply.status {
        401 | 403 => format!(
            "; it refused the API key in {} (create one with `headscale apikeys create`)",
            server.api_key_file.display()
        ),
        _ => String::new(),
    };
    Err(Error::Headscale(format!(
        "Headscale at {} answered {method} {path} with {}{hint}",
        server.server_url,
        Problem(&reply)
    )))
}

fn parse<T: for<'de> Deserialize<'de>>(
    server: &HeadscaleServer,
    path: &str,
    body: &str,
) -> Result<T> {
    serde_json::from_str(body).map_err(|e| {
        Error::Headscale(format!(
            "Headscale at {} answered {path} with a reply Parallax can't read ({e}); is that a Headscale built from the commit docker/headscale pins?",
            server.server_url
        ))
    })
}

/// An error reply, as status and Headscale's own words. Headscale answers
/// with RFC 9457 problem details; their `value` fields can echo the
/// request, so only the title, the detail and the messages are shown.
struct Problem<'a>(&'a HttpReply);

impl fmt::Display for Problem<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        #[derive(Deserialize)]
        struct Details {
            #[serde(default)]
            title: String,
            #[serde(default)]
            detail: String,
            #[serde(default)]
            errors: Vec<Message>,
        }
        #[derive(Deserialize)]
        struct Message {
            #[serde(default)]
            message: String,
        }
        write!(f, "{}", self.0.status)?;
        let Ok(details) = serde_json::from_str::<Details>(&self.0.body) else {
            return Ok(());
        };
        let words: Vec<&str> = [details.title.as_str(), details.detail.as_str()]
            .into_iter()
            .chain(details.errors.iter().map(|e| e.message.as_str()))
            .filter(|w| !w.is_empty())
            .collect();
        if !words.is_empty() {
            write!(f, " ({})", words.join(": "))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::memory::FakeHeadscale;

    /// Recorded from Headscale at the commit docker/headscale pins: one
    /// node logged in with a pre-auth key (key redacted), its route
    /// advertised but not approved.
    const NODES: &str = r#"{"nodes":[{"id":"1","machineKey":"mkey:887ae3cc96d01b4ec1f8058fbef5a4a46969a36bbdf3f4d0cb380e75a6fc7764","nodeKey":"nodekey:a93ccc9b8648498b9e074dd63e438110f9dcdb4778f43c14e296a4793a4b4d3f","discoKey":"discokey:40b95a2428ff8d3edf8162801513765cf0f8a12d908d3251bc88fbbdabe02c10","ipAddresses":["100.64.0.1","fd7a:115c:a1e0::1"],"name":"sister-phone","user":{"id":"1","name":"sister","createdAt":"2026-11-26T17:07:09.44141579-07:00","displayName":"","email":"","providerId":"","provider":"","profilePicUrl":""},"lastSeen":"2026-11-26T17:08:18.167626885-07:00","expiry":null,"preAuthKey":{"user":{"id":"1","name":"sister","createdAt":"2026-11-26T17:07:09.44141579-07:00","displayName":"","email":"","providerId":"","provider":"","profilePicUrl":""},"id":"5","key":"hskey-auth-redacted","reusable":true,"ephemeral":false,"used":false,"expiration":"2026-11-27T12:00:00Z","createdAt":"2026-11-27T00:08:15.116586286Z","aclTags":[]},"createdAt":"2026-11-26T17:08:17.134420392-07:00","registerMethod":"REGISTER_METHOD_AUTH_KEY","givenName":"sister-phone","online":true,"ephemeral":false,"approvedRoutes":[],"availableRoutes":["198.18.0.0/24"],"subnetRoutes":[],"tags":[]}]}"#;
    const USERS: &str = r#"{"users":[{"id":"1","name":"sister","createdAt":"2026-11-26T17:07:09.44141579-07:00","displayName":"","email":"","providerId":"","provider":"","profilePicUrl":""}]}"#;
    const VERSION: &str = r#"{"version":"v0.29.1-0.20261125200334-d9bf885c4911","commit":"d9bf885c4911bfd079842ba70165b809e7c52c6d","buildTime":"2026-11-25T20:03:34Z","go":{"version":"go1.27.4","os":"linux","arch":"amd64"},"dirty":false}"#;
    const UNAUTHORIZED: &str = r#"{"title":"Unauthorized","status":401,"detail":"Unauthorized"}"#;

    fn server() -> HeadscaleServer {
        HeadscaleServer {
            server_url: "https://headscale.mydomain.com".into(),
            ..HeadscaleServer::default()
        }
    }

    #[test]
    fn reads_nodes_users_and_the_version() {
        let api = FakeHeadscale::new()
            .reply("/api/v1/node", 200, NODES)
            .reply("/api/v1/user", 200, USERS)
            .reply("/version", 200, VERSION);
        let nodes = nodes(&server(), &api).unwrap();
        assert_eq!(
            nodes,
            vec![Node {
                id: 1,
                name: "sister-phone".into(),
                user: "sister".into(),
                address: Some(Ipv4Addr::new(100, 64, 0, 1)),
                online: true,
                node_key:
                    "nodekey:a93ccc9b8648498b9e074dd63e438110f9dcdb4778f43c14e296a4793a4b4d3f"
                        .into(),
                available_routes: vec!["198.18.0.0/24".into()],
                approved_routes: vec![],
            }]
        );
        assert_eq!(
            users(&server(), &api).unwrap(),
            vec![User {
                id: 1,
                name: "sister".into()
            }]
        );
        assert_eq!(
            version(&server(), &api).unwrap(),
            "v0.29.1-0.20261125200334-d9bf885c4911"
        );
        assert_eq!(
            tailnet(&nodes),
            Tailnet::from([(1, Ipv4Addr::new(100, 64, 0, 1))])
        );
    }

    #[test]
    fn an_address_outside_the_tailscale_range_is_not_the_nodes() {
        let body = NODES.replace("100.64.0.1", "10.99.0.1");
        let api = FakeHeadscale::new().reply("/api/v1/node", 200, &body);
        let nodes = nodes(&server(), &api).unwrap();
        assert_eq!(nodes[0].address, None);
        assert!(tailnet(&nodes).is_empty());
    }

    #[test]
    fn a_node_without_a_user_is_still_read() {
        let body = NODES.replacen(r#""user":{"id":"1","name":"sister","createdAt":"2026-11-26T17:07:09.44141579-07:00","displayName":"","email":"","providerId":"","provider":"","profilePicUrl":""},"lastSeen""#, r#""user":null,"lastSeen""#, 1);
        assert!(body.contains(r#""user":null"#));
        let api = FakeHeadscale::new().reply("/api/v1/node", 200, &body);
        let nodes = nodes(&server(), &api).unwrap();
        assert_eq!((nodes[0].id, nodes[0].user.as_str()), (1, ""));
    }

    #[test]
    fn a_refused_key_names_the_key_file() {
        let api = FakeHeadscale::new().reply("/api/v1/node", 401, UNAUTHORIZED);
        let e = nodes(&server(), &api).unwrap_err().to_string();
        assert_eq!(
            e,
            "Headscale at https://headscale.mydomain.com answered GET /api/v1/node with 401 (Unauthorized: Unauthorized); it refused the API key in /etc/parallax/headscale-api.key (create one with `headscale apikeys create`)"
        );
    }

    #[test]
    fn an_error_never_shows_the_echoed_request() {
        let body = r#"{"title":"Bad Request","status":400,"detail":"validation failed","errors":[{"message":"expected string","location":"body.user","value":"secret-ish"}]}"#;
        let api = FakeHeadscale::new().reply("/api/v1/node", 400, body);
        let e = nodes(&server(), &api).unwrap_err().to_string();
        assert!(
            e.contains("400 (Bad Request: validation failed: expected string)"),
            "{e}"
        );
        assert!(!e.contains("secret-ish"), "{e}");
    }

    #[test]
    fn an_unreadable_reply_says_which_headscale_it_expects() {
        let api = FakeHeadscale::new().reply("/api/v1/node", 200, r#"{"nodes":[{"id":1}]}"#);
        let e = nodes(&server(), &api).unwrap_err().to_string();
        assert!(e.contains("a reply Parallax can't read"), "{e}");
        assert!(e.contains("docker/headscale"), "{e}");
    }

    #[test]
    fn changes_name_new_moved_and_gone_nodes() {
        let a = Ipv4Addr::new(100, 64, 0, 1);
        let b = Ipv4Addr::new(100, 64, 0, 2);
        let before = Tailnet::from([(1, a), (2, b)]);
        let after = Tailnet::from([(1, b), (3, a)]);
        assert_eq!(
            changes(Some(&before), &after),
            vec![
                "Headscale node 1 moved from 100.64.0.1 to 100.64.0.2",
                "Headscale node 3 is 100.64.0.1",
                "Headscale node 2 is gone",
            ]
        );
        assert!(changes(Some(&after), &after).is_empty());
    }

    /// The canonical scenario plus a Tailscale peer named after node `id`.
    fn with_node(id: u64) -> Config {
        let mut config = crate::testing::canonical_config();
        let mut peer = config.peers[0].clone();
        peer.name = "sister-tablet".into();
        peer.transport = TransportKind::Tailscale;
        peer.wireguard = None;
        peer.tailscale = Some(crate::model::TailscalePeer {
            node_id: Some(id),
            address: None,
        });
        config.peers.push(peer);
        config.server.headscale = server();
        config
    }

    fn answering() -> FakeHeadscale {
        FakeHeadscale::new()
            .reply("/api/v1/node", 200, NODES)
            .reply("/api/v1/user", 200, USERS)
            .reply("/version", 200, VERSION)
    }

    #[test]
    fn status_says_which_peer_each_node_is() {
        let lines = status(&with_node(1), &answering()).unwrap();
        assert_eq!(
            lines,
            vec![
                "Headscale v0.29.1-0.20261125200334-d9bf885c4911 at https://headscale.mydomain.com",
                "user sister (id 1)",
                "node 1 sister-phone: user sister, 100.64.0.1, online; peer sister-tablet",
            ]
        );
        let lines = status(&with_node(7), &answering()).unwrap();
        assert_eq!(
            lines[2],
            "node 1 sister-phone: user sister, 100.64.0.1, online; no peer"
        );
        assert_eq!(lines[3], "peer sister-tablet: node 7 isn't in Headscale");
    }

    #[test]
    fn doctor_asks_only_when_a_peer_names_a_node() {
        let api = FakeHeadscale::new();
        let quiet = check(&crate::testing::canonical_config(), &api);
        assert!(matches!(quiet.outcome, Outcome::Ok(_)), "{quiet:?}");
        assert!(api.asked.borrow().is_empty());

        assert!(matches!(
            check(&with_node(1), &answering()).outcome,
            Outcome::Ok(_)
        ));
        let Outcome::Warn(w) = check(&with_node(7), &answering()).outcome else {
            panic!("not a warning");
        };
        assert!(w.contains("sister-tablet (node 7)"), "{w}");
        // Never a failure: doctor gates the gateway's start.
        let Outcome::Warn(f) = check(&with_node(1), &FakeHeadscale::new()).outcome else {
            panic!("not a warning");
        };
        assert!(f.contains("connection refused"), "{f}");
    }

    #[test]
    fn needed_only_with_a_tailscale_peer_that_has_a_node() {
        let mut config = crate::testing::canonical_config();
        assert!(!needed(&config));
        let mut peer = config.peers[0].clone();
        peer.name = "sister-tablet".into();
        peer.transport = TransportKind::Tailscale;
        peer.wireguard = None;
        peer.tailscale = Some(crate::model::TailscalePeer::default());
        config.peers.push(peer);
        assert!(!needed(&config));
        if let Some(t) = config.peers.last_mut().and_then(|p| p.tailscale.as_mut()) {
            t.node_id = Some(1);
        }
        assert!(needed(&config));
    }
}

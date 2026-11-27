//! The subnet router: the `tailscaled` that carries Tailscale peers'
//! traffic into the mapped networks (ADR 0015).
//!
//! It advertises every network as its peers address it (mapped, if
//! mapped) and the DNS server's and the proxy's addresses. Its own
//! filtering and NAT stay off (`--netfilter-mode=off`, no SNAT): the
//! firewall Parallax generates is the gate, and each network's
//! `masquerade` decides NAT, as for WireGuard.
//!
//! One `tailscaled` per machine. Parallax sets one up only when it's logged
//! out, or logged in as Parallax's own node (user [`USER`] on the configured
//! Headscale): it logs it in with a single-use pre-auth key, keeps its
//! settings and routes as they should be, and approves the routes. A
//! client logged in as anyone else's node is the operator's: Parallax never
//! changes it, and says what the operator has to run instead.

use std::fmt;

use ipnet::{IpNet, Ipv4Net};
use serde::Deserialize;

use crate::date::Date;
use crate::doctor::{Check, Outcome};
use crate::headscale::{self, Node};
use crate::io::{HeadscaleApi, ProcessRunner};
use crate::model::{Config, TransportKind};
use crate::secret::Secret;
use crate::validate::Model;
use crate::{Error, Result};

/// The Headscale user Parallax's router node belongs to.
pub const USER: &str = "parallax";
/// How often the daemon looks at the router.
pub const POLL_SECONDS: u64 = 30;
/// How long `tailscale up` may take to log in.
const LOGIN_TIMEOUT: &str = "30s";

/// Whether any peer is on Tailscale, so the router has to be up.
pub fn needed(config: &Config) -> bool {
    config
        .peers
        .iter()
        .any(|p| p.transport == TransportKind::Tailscale)
}

/// What the router advertises: every network as peers address it, and
/// the DNS server's and the proxy's addresses. Sorted, nothing inside
/// another.
pub fn routes(model: &Model<'_>) -> Vec<Ipv4Net> {
    let mut all: Vec<Ipv4Net> = model
        .config()
        .networks
        .iter()
        .map(|n| n.client_subnet().trunc())
        .chain([
            Ipv4Net::from(model.shim_address()),
            Ipv4Net::from(model.proxy_address()),
        ])
        .collect();
    all.sort();
    all.dedup();
    let inside = |n: &Ipv4Net, all: &[Ipv4Net]| all.iter().any(|o| o != n && o.contains(n));
    all.iter().filter(|n| !inside(n, &all)).copied().collect()
}

/// How to reach the `tailscaled` the router is.
#[derive(Clone, Copy)]
pub struct Tailscaled<'a> {
    /// Its socket (`tailscale --socket`).
    pub socket: &'a str,
    /// The user this process runs as when that isn't root: `tailscale up`
    /// makes it the client's operator, so it can keep managing it.
    pub operator: Option<&'a str>,
    pub runner: &'a dyn ProcessRunner,
}

impl fmt::Debug for Tailscaled<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tailscaled")
            .field("socket", &self.socket)
            .field("operator", &self.operator)
            .finish_non_exhaustive()
    }
}

impl Tailscaled<'_> {
    fn run(&self, args: &[&str], stdin: Option<&str>) -> Result<String> {
        let socket = format!("--socket={}", self.socket);
        let mut all = vec![socket.as_str()];
        all.extend_from_slice(args);
        let out = self.runner.run("tailscale", &all, stdin)?;
        if out.ok() {
            return Ok(out.stdout);
        }
        let said = out.stderr.trim();
        let said = if said.is_empty() {
            out.stdout.trim()
        } else {
            said
        };
        Err(Error::Command {
            command: format!("tailscale --socket={} {}", self.socket, args.join(" ")),
            status: out.status,
            stderr: said.to_string(),
        })
    }
}

/// What the client says about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Client {
    /// `BackendState`: `NeedsLogin`, `Running`, `Stopped`, `Starting`, ...
    pub state: String,
    /// Its node key, if it has one.
    pub node_key: Option<String>,
}

/// The client's settings that matter here (`tailscale debug prefs`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Prefs {
    /// Logged out on purpose (`tailscale logout`), not just expired.
    #[serde(default)]
    pub logged_out: bool,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub advertise_routes: Option<Vec<String>>,
    /// 0 is off.
    #[serde(default)]
    pub netfilter_mode: u8,
    #[serde(rename = "NoSNAT", default)]
    pub no_snat: bool,
    /// `--accept-dns`.
    #[serde(rename = "CorpDNS", default)]
    pub corp_dns: bool,
    /// `--accept-routes`.
    #[serde(default)]
    pub route_all: bool,
}

/// `tailscale status --json`.
pub fn client(ts: &Tailscaled<'_>) -> Result<Client> {
    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct Status {
        backend_state: String,
        #[serde(rename = "Self")]
        me: Option<SelfNode>,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct SelfNode {
        #[serde(default)]
        public_key: String,
    }
    let out = ts.run(&["status", "--json"], None)?;
    let status: Status = serde_json::from_str(&out).map_err(|e| {
        Error::Tailscale(format!(
            "`tailscale --socket={} status --json` answered something Parallax can't read: {e}",
            ts.socket
        ))
    })?;
    // A client that never logged in has an all-zero key.
    let node_key = status.me.map(|s| s.public_key).filter(|k| {
        k.starts_with("nodekey:") && !k.trim_start_matches("nodekey:").bytes().all(|b| b == b'0')
    });
    Ok(Client {
        state: status.backend_state,
        node_key,
    })
}

/// `tailscale debug prefs`.
pub fn prefs(ts: &Tailscaled<'_>) -> Result<Prefs> {
    let out = ts.run(&["debug", "prefs"], None)?;
    serde_json::from_str(&out).map_err(|e| {
        Error::Tailscale(format!(
            "`tailscale --socket={} debug prefs` answered something Parallax can't read: {e}",
            ts.socket
        ))
    })
}

/// Whose the client is, and what's still to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Router {
    /// Parallax's own node, `id`, set up as it should be once `steps` ran.
    Ours { id: u64, steps: Vec<Step> },
    /// Logged out: Parallax logs it in.
    LoggedOut,
    /// The operator's own node, `id`: left alone. `todo` is what the
    /// operator still has to run; empty when it's all in place.
    Theirs { id: u64, todo: Vec<String> },
    /// Not a node of the configured Headscale; Parallax can't use it.
    Elsewhere(String),
    /// Starting, or waiting on something; looked at again next time.
    Waiting(String),
}

/// A change Parallax makes to its own router.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// `tailscale up` again with its settings (it was stopped).
    Up,
    /// `tailscale set` its settings and routes.
    Set(Vec<String>),
    /// Approve exactly these routes in Headscale.
    Approve(Vec<Ipv4Net>),
}

impl fmt::Display for Step {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Step::Up => write!(f, "start the router again (`tailscale up`)"),
            Step::Set(why) => write!(f, "set the router's {}", why.join(", ")),
            Step::Approve(routes) => write!(f, "approve the routes {}", list(routes)),
        }
    }
}

fn list(routes: &[Ipv4Net]) -> String {
    if routes.is_empty() {
        return "(none)".into();
    }
    routes
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// Routes of both families, sorted: what a node has, to compare with.
fn parse_routes(routes: &[String]) -> Vec<IpNet> {
    let mut v: Vec<IpNet> = routes.iter().filter_map(|r| r.parse().ok()).collect();
    v.sort();
    v.dedup();
    v
}

fn as_ip(routes: &[Ipv4Net]) -> Vec<IpNet> {
    routes.iter().copied().map(IpNet::V4).collect()
}

/// `have` plus whichever of `wanted` it doesn't cover, every family kept:
/// the full list a replacing command (`--advertise-routes`) needs.
fn with_missing(have: &[String], wanted: &[Ipv4Net]) -> Option<String> {
    let parsed = parse_routes(have);
    let missing: Vec<&Ipv4Net> = wanted
        .iter()
        // A default route is an exit node: devices accepting routes don't
        // use it for Parallax's networks.
        .filter(|w| {
            !parsed
                .iter()
                .any(|h| matches!(h, IpNet::V4(h) if h.prefix_len() > 0 && h.contains(*w)))
        })
        .collect();
    if missing.is_empty() {
        return None;
    }
    let mut all: Vec<String> = have.to_vec();
    all.extend(missing.iter().map(ToString::to_string));
    Some(all.join(","))
}

/// Decide whose the client is and what it needs. Pure: `prefs` is read
/// at most once, never for the operator's own node, and `nodes` is
/// Headscale's node list.
pub fn decide(
    model: &Model<'_>,
    client: &Client,
    prefs: impl FnOnce() -> Result<Prefs>,
    nodes: &[Node],
) -> Result<Router> {
    let server = &model.server().headscale;
    let wanted = routes(model);
    let node = client
        .node_key
        .as_deref()
        .and_then(|key| nodes.iter().find(|n| n.node_key == key));
    let needs_login = match client.state.as_str() {
        "NeedsLogin" => true,
        "Running" | "Stopped" => false,
        "NeedsMachineAuth" => {
            return Ok(Router::Waiting(
                "the router waits for its node to be approved in Headscale".into(),
            ))
        }
        // NoState: starting, or its state store failed. Not "logged out".
        other => {
            return Ok(Router::Waiting(format!(
                "the router's tailscaled is {other}"
            )))
        }
    };
    let Some(node) = node else {
        // Logged out means never logged in, or `tailscale logout`. An
        // expired node also needs a login, and it may be anyone's.
        if needs_login && (client.node_key.is_none() || prefs()?.logged_out) {
            return Ok(Router::LoggedOut);
        }
        return Ok(Router::Elsewhere(format!(
            "the router's tailscaled is logged in, but not as a node of Headscale at {}. Log it out (`tailscale logout`) to let Parallax log it in there",
            server.server_url
        )));
    };
    if node.user != USER {
        let mut todo = Vec::new();
        match client.state.as_str() {
            "Stopped" => todo.push("start it: `tailscale up`".to_string()),
            "NeedsLogin" => todo.push("log it in again: `tailscale up`".to_string()),
            _ => {}
        }
        if let Some(all) = with_missing(&node.available_routes, &wanted) {
            todo.push(format!(
                "advertise Parallax's routes: `tailscale set --advertise-routes={all}`"
            ));
        }
        if let Some(all) = with_missing(&node.approved_routes, &wanted) {
            todo.push(format!(
                "approve them: `headscale nodes approve-routes --identifier {} --routes {all}`",
                node.id
            ));
        }
        return Ok(Router::Theirs { id: node.id, todo });
    }
    // Its own node, logged out or expired: log it in again.
    if needs_login {
        return Ok(Router::LoggedOut);
    }
    let mut steps = Vec::new();
    if client.state == "Stopped" {
        steps.push(Step::Up);
    } else {
        let prefs = prefs()?;
        let mut why = Vec::new();
        let advertised = parse_routes(prefs.advertise_routes.as_deref().unwrap_or_default());
        if advertised != as_ip(&wanted) {
            why.push(format!("routes to {}", list(&wanted)));
        }
        if prefs.hostname != server.subnet_router_node {
            why.push(format!("hostname to {}", server.subnet_router_node));
        }
        if prefs.netfilter_mode != 0 {
            why.push("netfilter mode to off".into());
        }
        if !prefs.no_snat {
            why.push("subnet SNAT to off".into());
        }
        if prefs.corp_dns {
            why.push("accept-dns to off".into());
        }
        if prefs.route_all {
            why.push("accept-routes to off".into());
        }
        if !why.is_empty() {
            steps.push(Step::Set(why));
        }
    }
    if parse_routes(&node.approved_routes) != as_ip(&wanted) {
        steps.push(Step::Approve(wanted));
    }
    Ok(Router::Ours { id: node.id, steps })
}

/// The flags Parallax's router always has.
fn settings(model: &Model<'_>, routes: &str) -> Vec<String> {
    vec![
        format!("--hostname={}", model.server().headscale.subnet_router_node),
        format!("--advertise-routes={routes}"),
        "--netfilter-mode=off".into(),
        "--snat-subnet-routes=false".into(),
        "--accept-dns=false".into(),
        "--accept-routes=false".into(),
    ]
}

/// `tailscale up` for Parallax's router: every setting stated (`--reset`),
/// the operator kept, and the pre-auth key, if any, on stdin.
fn up(model: &Model<'_>, ts: &Tailscaled<'_>, key: Option<&Secret>) -> Result<()> {
    let routes = list_flag(&routes(model));
    let mut args: Vec<String> = vec![
        "up".into(),
        "--reset".into(),
        format!(
            "--login-server={}",
            model.server().headscale.server_url.trim_end_matches('/')
        ),
    ];
    if key.is_some() {
        args.push("--auth-key=file:/dev/stdin".into());
    }
    args.extend(settings(model, &routes));
    if let Some(operator) = ts.operator {
        args.push(format!("--operator={operator}"));
    }
    args.push(format!("--timeout={LOGIN_TIMEOUT}"));
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    ts.run(&args, key.map(Secret::expose))
        .map(drop)
        .map_err(|e| match (e, key) {
            // Whatever `tailscale` says, it never shows the key.
            (
                Error::Command {
                    command,
                    status,
                    stderr,
                },
                Some(key),
            ) => Error::Command {
                command,
                status,
                stderr: stderr.replace(key.expose(), "<pre-auth key>"),
            },
            (e, _) => e,
        })
}

/// The routes as `--advertise-routes` takes them (empty for none).
fn list_flag(routes: &[Ipv4Net]) -> String {
    routes
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// Look at the router and make it what it should be. Returns what was
/// done and what's left for the operator, one line each, and the state.
///
/// `login` false (no peer is on Tailscale): Parallax's own router still
/// follows the configuration's routes, but nothing is logged in.
pub fn sync(
    model: &Model<'_>,
    ts: &Tailscaled<'_>,
    api: &dyn HeadscaleApi,
    login: bool,
) -> Result<(Router, Vec<String>)> {
    let server = &model.server().headscale;
    let client = client(ts)?;
    let nodes = headscale::nodes(server, api)?;
    let router = decide(model, &client, || prefs(ts), &nodes)?;
    let mut done = Vec::new();
    match &router {
        Router::LoggedOut if !login => {}
        Router::LoggedOut => {
            let user = match headscale::user(server, api, USER)? {
                Some(user) => user,
                None => {
                    let user = headscale::create_user(server, api, USER)?;
                    done.push(format!("created the Headscale user {USER} for the router"));
                    user
                }
            };
            // Single use, and void within two days if the login fails.
            let expires = Date::from_unix_days(model.today().to_unix_days() + 2);
            let key = headscale::create_pre_auth_key(server, api, user.id, expires)?;
            up(model, ts, Some(&key))?;
            done.push(format!(
                "logged the router in to Headscale at {} as {}, advertising {}",
                server.server_url,
                server.subnet_router_node,
                list(&routes(model))
            ));
            // Its routes are approved on the next look, once it's a node.
        }
        Router::Ours { id, steps } => {
            for step in steps {
                match step {
                    Step::Up => up(model, ts, None)?,
                    Step::Set(_) => {
                        let mut args = vec!["set".to_string()];
                        args.extend(settings(model, &list_flag(&routes(model))));
                        let args: Vec<&str> = args.iter().map(String::as_str).collect();
                        ts.run(&args, None)?;
                    }
                    Step::Approve(routes) => headscale::approve_routes(server, api, *id, routes)?,
                }
                done.push(format!("router: {step}"));
            }
        }
        Router::Theirs { .. } | Router::Elsewhere(_) | Router::Waiting(_) => {}
    }
    Ok((router, done))
}

/// What the router's state means for an operator, one line.
pub fn describe(model: &Model<'_>, router: &Router) -> std::result::Result<String, String> {
    let server = &model.server().headscale;
    match router {
        Router::Ours { id, steps } if steps.is_empty() => Ok(format!(
            "Parallax's router is node {id} on Headscale at {}, routing {}",
            server.server_url,
            list(&routes(model))
        )),
        Router::Ours { id, steps } => Err(format!(
            "Parallax's router (node {id}) needs to {}; the daemon does it",
            steps
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", then ")
        )),
        Router::LoggedOut => Err(format!(
            "the router's tailscaled isn't logged in; the daemon logs it in to Headscale at {}",
            server.server_url
        )),
        Router::Theirs { id, todo } if todo.is_empty() => Ok(format!(
            "this machine's own Tailscale (node {id}) routes {}; Parallax leaves its settings alone",
            list(&routes(model))
        )),
        Router::Theirs { id, todo } => Err(format!(
            "this machine's own Tailscale (node {id}) is the router, and Parallax leaves its settings to you: {}",
            todo.join("; ")
        )),
        Router::Elsewhere(why) | Router::Waiting(why) => Err(why.clone()),
    }
}

/// `parallax doctor`: whether the router carries Tailscale peers' traffic.
/// Only warns, like the Headscale check: doctor gates the gateway's start,
/// and the daemon sets the router up after it.
pub fn check(model: &Model<'_>, ts: &Tailscaled<'_>, api: &dyn HeadscaleApi) -> Check {
    let outcome = if !needed(model.config()) {
        Outcome::Ok("not needed: no peer is on Tailscale".into())
    } else {
        let looked = client(ts).and_then(|client| {
            let nodes = headscale::nodes(&model.server().headscale, api)?;
            decide(model, &client, || prefs(ts), &nodes)
        });
        match looked {
            Err(e) => Outcome::Warn(format!(
                "{e}. Tailscale peers can't reach the networks until the router is up"
            )),
            Ok(router) => match describe(model, &router) {
                Ok(fine) => Outcome::Ok(fine),
                Err(problem) => Outcome::Warn(problem),
            },
        }
    };
    Check {
        name: "tailscale router".into(),
        outcome,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::memory::{FakeHeadscale, RecordingRunner};
    use crate::io::Output;
    use crate::model::{HeadscaleServer, TailscalePeer};
    use crate::testing::{canonical_config, today};

    const SOCKET: &str = "/run/tailscale/tailscaled.sock";
    const KEY: &str = "nodekey:43bc63d6525a832539b4dca5135d53927b6317c8e4d47ec34a2bf7695bd40a31";
    /// Recorded from `tailscale status --json` (v1.104.7), trimmed.
    const LOGGED_OUT: &str = r#"{"Version":"1.104.7","TUN":false,"BackendState":"NeedsLogin","AuthURL":"","TailscaleIPs":null,"Self":{"ID":"","NodeID":0,"PublicKey":"nodekey:0000000000000000000000000000000000000000000000000000000000000000","HostName":"gateway","OS":"linux","UserID":0},"Health":["Tailscale is stopped."]}"#;
    const ROUTES: &str = "198.18.1.0/24,10.8.0.1/32";

    fn running() -> String {
        LOGGED_OUT.replace("NeedsLogin", "Running").replace(
            "nodekey:0000000000000000000000000000000000000000000000000000000000000000",
            KEY,
        )
    }

    /// Recorded from `tailscale debug prefs` after Parallax's `up`, trimmed.
    fn prefs_json(routes: &str) -> String {
        let routes: Vec<&str> = routes.split(',').filter(|r| !r.is_empty()).collect();
        format!(
            r#"{{"ControlURL":"https://headscale.mydomain.com","RouteAll":false,"CorpDNS":false,"WantRunning":true,"LoggedOut":false,"Hostname":"parallax-gateway","AdvertiseRoutes":{},"NoSNAT":true,"NetfilterMode":0}}"#,
            serde_json::to_string(&routes).unwrap()
        )
    }

    fn ok(stdout: &str) -> Output {
        Output {
            status: 0,
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }

    /// The canonical scenario plus a Tailscale peer.
    fn config() -> Config {
        let mut config = canonical_config();
        let mut peer = config.peers[0].clone();
        peer.name = "sister-tablet".into();
        peer.transport = TransportKind::Tailscale;
        peer.wireguard = None;
        peer.tailscale = Some(TailscalePeer {
            node_id: Some(2),
            address: None,
        });
        config.peers.push(peer);
        config.server.headscale = HeadscaleServer {
            server_url: "https://headscale.mydomain.com".into(),
            ..HeadscaleServer::default()
        };
        config
    }

    fn node(user: &str, available: &str, approved: &str) -> Node {
        let split = |s: &str| {
            s.split(',')
                .filter(|r| !r.is_empty())
                .map(String::from)
                .collect()
        };
        Node {
            id: 1,
            name: "parallax-gateway".into(),
            user: user.into(),
            address: Some(std::net::Ipv4Addr::new(100, 64, 0, 1)),
            online: true,
            node_key: KEY.into(),
            available_routes: split(available),
            approved_routes: split(approved),
        }
    }

    fn client(state: &str) -> Client {
        Client {
            state: state.into(),
            node_key: Some(KEY.into()),
        }
    }

    fn prefs(routes: &str) -> Result<Prefs> {
        Ok(serde_json::from_str(&prefs_json(routes)).unwrap())
    }

    #[test]
    fn routes_are_the_networks_as_peers_see_them_and_the_dns_address() {
        let config = config();
        let model = Model::resolve(&config, today()).unwrap();
        assert_eq!(list(&routes(&model)), "10.8.0.1/32,198.18.1.0/24");
        // An address inside an advertised network isn't advertised again.
        let mut config = config.clone();
        config.server.dns.listen = Some("198.18.1.53".parse().unwrap());
        let model = Model::resolve(&config, today()).unwrap();
        assert_eq!(list(&routes(&model)), "10.8.0.1/32,198.18.1.0/24");
    }

    #[test]
    fn needed_only_with_a_tailscale_peer() {
        assert!(!needed(&canonical_config()));
        assert!(needed(&config()));
    }

    #[test]
    fn reads_the_client() {
        let runner = RecordingRunner::new();
        runner.respond("tailscale", ok(LOGGED_OUT));
        runner.respond("tailscale", ok(&running()));
        let ts = Tailscaled {
            socket: SOCKET,
            operator: None,
            runner: &runner,
        };
        // Never logged in: the all-zero key is no key.
        assert_eq!(
            super::client(&ts).unwrap(),
            Client {
                state: "NeedsLogin".into(),
                node_key: None
            }
        );
        assert_eq!(super::client(&ts).unwrap(), client("Running"));
        assert_eq!(
            runner.command_lines()[0],
            format!("tailscale --socket={SOCKET} status --json")
        );
    }

    #[test]
    fn its_own_router_set_up_right_needs_nothing() {
        let config = config();
        let model = Model::resolve(&config, today()).unwrap();
        let nodes = [node(USER, ROUTES, ROUTES)];
        let router = decide(&model, &client("Running"), || prefs(ROUTES), &nodes).unwrap();
        assert_eq!(
            router,
            Router::Ours {
                id: 1,
                steps: vec![]
            }
        );
        assert!(describe(&model, &router).is_ok());
    }

    #[test]
    fn its_own_router_gets_new_routes_and_their_approval() {
        let mut config = config();
        let mut lan2 = config.networks[0].clone();
        lan2.name = "lan2".into();
        lan2.interface = "eth2".into();
        lan2.subnet = "192.168.2.0/24".parse().unwrap();
        lan2.mapped_to = Some("198.18.2.0/24".parse().unwrap());
        lan2.domains = vec![];
        config.networks.push(lan2);
        let model = Model::resolve(&config, today()).unwrap();
        // Advertises and has approved only the first network, plus a stale route.
        let nodes = [node(
            USER,
            ROUTES,
            "198.18.1.0/24,10.8.0.1/32,198.18.9.0/24",
        )];
        let router = decide(&model, &client("Running"), || prefs(ROUTES), &nodes).unwrap();
        let wanted: Vec<Ipv4Net> = ["10.8.0.1/32", "198.18.1.0/24", "198.18.2.0/24"]
            .iter()
            .map(|r| r.parse().unwrap())
            .collect();
        assert_eq!(
            router,
            Router::Ours {
                id: 1,
                steps: vec![
                    Step::Set(vec![
                        "routes to 10.8.0.1/32,198.18.1.0/24,198.18.2.0/24".into()
                    ]),
                    Step::Approve(wanted),
                ]
            }
        );
    }

    #[test]
    fn its_own_router_gets_its_settings_back() {
        let config = config();
        let model = Model::resolve(&config, today()).unwrap();
        let nodes = [node(USER, ROUTES, ROUTES)];
        let changed = || {
            let mut p = prefs(ROUTES)?;
            p.netfilter_mode = 2;
            p.no_snat = false;
            p.corp_dns = true;
            Ok(p)
        };
        let router = decide(&model, &client("Running"), changed, &nodes).unwrap();
        let Router::Ours { steps, .. } = router else {
            panic!("{router:?}");
        };
        assert_eq!(
            steps,
            vec![Step::Set(vec![
                "netfilter mode to off".into(),
                "subnet SNAT to off".into(),
                "accept-dns to off".into()
            ])]
        );
        // Stopped: started again with all its settings.
        let router = decide(&model, &client("Stopped"), || prefs(ROUTES), &nodes).unwrap();
        assert_eq!(
            router,
            Router::Ours {
                id: 1,
                steps: vec![Step::Up]
            }
        );
    }

    #[test]
    fn the_operators_own_client_is_left_alone() {
        let config = config();
        let model = Model::resolve(&config, today()).unwrap();
        let never =
            || -> Result<Prefs> { panic!("the operator's prefs are none of Parallax's business") };
        let nodes = [node("operator", "192.168.50.0/24", "192.168.50.0/24")];
        let router = decide(&model, &client("Running"), never, &nodes).unwrap();
        assert_eq!(
            router,
            Router::Theirs {
                id: 1,
                todo: vec![
                    "advertise Parallax's routes: `tailscale set --advertise-routes=192.168.50.0/24,10.8.0.1/32,198.18.1.0/24`".into(),
                    "approve them: `headscale nodes approve-routes --identifier 1 --routes 192.168.50.0/24,10.8.0.1/32,198.18.1.0/24`".into(),
                ]
            }
        );
        let nodes = [node(
            "operator",
            "0.0.0.0/0,10.8.0.1/32,198.18.1.0/24",
            "0.0.0.0/0,10.8.0.1/32,198.18.1.0/24",
        )];
        let router = decide(&model, &client("Running"), never, &nodes).unwrap();
        assert_eq!(
            router,
            Router::Theirs {
                id: 1,
                todo: vec![]
            }
        );
    }

    #[test]
    fn a_client_on_another_control_server_is_not_used() {
        let config = config();
        let model = Model::resolve(&config, today()).unwrap();
        let router = decide(&model, &client("Running"), || prefs(ROUTES), &[]).unwrap();
        let Router::Elsewhere(why) = router else {
            panic!("{router:?}");
        };
        assert!(why.contains("tailscale logout"), "{why}");
        let router = decide(
            &model,
            &Client {
                state: "NeedsLogin".into(),
                node_key: None,
            },
            || prefs(ROUTES),
            &[],
        )
        .unwrap();
        assert_eq!(router, Router::LoggedOut);
        let router = decide(&model, &client("Starting"), || prefs(ROUTES), &[]).unwrap();
        assert!(matches!(router, Router::Waiting(_)), "{router:?}");
    }

    #[test]
    fn an_expired_node_is_logged_in_again_only_if_its_parallaxs() {
        let config = config();
        let model = Model::resolve(&config, today()).unwrap();
        let never = || -> Result<Prefs> { panic!("not needed") };
        // Parallax's own, expired: logged in again.
        let nodes = [node(USER, ROUTES, ROUTES)];
        let router = decide(&model, &client("NeedsLogin"), never, &nodes).unwrap();
        assert_eq!(router, Router::LoggedOut);
        // The operator's, expired: theirs to log in.
        let nodes = [node(
            "operator",
            "10.8.0.1/32,198.18.1.0/24",
            "10.8.0.1/32,198.18.1.0/24",
        )];
        let router = decide(&model, &client("NeedsLogin"), never, &nodes).unwrap();
        assert_eq!(
            router,
            Router::Theirs {
                id: 1,
                todo: vec!["log it in again: `tailscale up`".into()]
            }
        );
        // A node key this Headscale doesn't know: only a `tailscale logout`
        // makes it Parallax's to log in.
        let expired = || prefs(ROUTES);
        let router = decide(&model, &client("NeedsLogin"), expired, &[]).unwrap();
        assert!(matches!(router, Router::Elsewhere(_)), "{router:?}");
        let logged_out = || {
            let mut p = prefs(ROUTES)?;
            p.logged_out = true;
            Ok(p)
        };
        let router = decide(&model, &client("NeedsLogin"), logged_out, &[]).unwrap();
        assert_eq!(router, Router::LoggedOut);
        // Starting, or a broken state store, isn't logged out.
        let fresh = Client {
            state: "NoState".into(),
            node_key: None,
        };
        let router = decide(&model, &fresh, never, &[]).unwrap();
        assert!(matches!(router, Router::Waiting(_)), "{router:?}");
    }

    #[test]
    fn the_operators_other_routes_stay_in_the_commands() {
        let config = config();
        let model = Model::resolve(&config, today()).unwrap();
        let never = || -> Result<Prefs> { panic!("not needed") };
        // An exit node's default routes don't carry Parallax's networks;
        // the commands keep them, IPv6 included.
        let nodes = [node("operator", "0.0.0.0/0,::/0", "0.0.0.0/0,::/0")];
        let Router::Theirs { todo, .. } =
            decide(&model, &client("Running"), never, &nodes).unwrap()
        else {
            panic!("not theirs");
        };
        assert!(
            todo[0].contains("--advertise-routes=0.0.0.0/0,::/0,10.8.0.1/32,198.18.1.0/24"),
            "{todo:?}"
        );
        let nodes = [node("operator", "fd00::/64", "fd00::/64")];
        let Router::Theirs { todo, .. } =
            decide(&model, &client("Running"), never, &nodes).unwrap()
        else {
            panic!("not theirs");
        };
        assert!(
            todo[0].contains("--advertise-routes=fd00::/64,10.8.0.1/32,198.18.1.0/24"),
            "{todo:?}"
        );
        assert!(
            todo[1].contains("--routes fd00::/64,10.8.0.1/32,198.18.1.0/24"),
            "{todo:?}"
        );
    }

    #[test]
    fn a_failed_login_never_shows_the_key() {
        let config = config();
        let model = Model::resolve(&config, today()).unwrap();
        let runner = RecordingRunner::new();
        runner.respond("tailscale", ok(LOGGED_OUT));
        runner.respond(
            "tailscale",
            Output {
                status: 1,
                stdout: String::new(),
                stderr: "invalid key: hskey-auth-test-0123456789 not valid".into(),
            },
        );
        let api = FakeHeadscale::new()
            .reply("/api/v1/node", 200, r#"{"nodes":[]}"#)
            .reply(
                "/api/v1/user?name=parallax",
                200,
                r#"{"users":[{"id":"3","name":"parallax"}]}"#,
            )
            .reply("POST /api/v1/preauthkey", 200, KEY_CREATED);
        let ts = Tailscaled {
            socket: SOCKET,
            operator: None,
            runner: &runner,
        };
        let e = sync(&model, &ts, &api, true).unwrap_err().to_string();
        assert!(!e.contains("hskey-auth-test"), "{e}");
        assert!(e.contains("invalid key: <pre-auth key> not valid"), "{e}");
    }

    #[test]
    fn without_tailscale_peers_nothing_is_logged_in() {
        let config = config();
        let model = Model::resolve(&config, today()).unwrap();
        let runner = RecordingRunner::new();
        runner.respond("tailscale", ok(LOGGED_OUT));
        let api = FakeHeadscale::new().reply("/api/v1/node", 200, r#"{"nodes":[]}"#);
        let ts = Tailscaled {
            socket: SOCKET,
            operator: None,
            runner: &runner,
        };
        let (router, done) = sync(&model, &ts, &api, false).unwrap();
        assert_eq!(router, Router::LoggedOut);
        assert!(done.is_empty());
        assert!(api.posted.borrow().is_empty());
        assert_eq!(runner.calls.borrow().len(), 1);
    }

    const USERS_NONE: &str = r#"{"users":[]}"#;
    const USER_CREATED: &str = r#"{"user":{"id":"3","name":"parallax","createdAt":"2026-11-26T22:28:49.48404755-07:00","displayName":"","email":"","providerId":"","provider":"","profilePicUrl":""}}"#;
    /// Recorded from Headscale at the commit docker/headscale pins (key changed).
    const KEY_CREATED: &str = r#"{"preAuthKey":{"user":{"id":"3","name":"parallax","createdAt":"2026-11-26T22:28:49.48404755-07:00","displayName":"","email":"","providerId":"","provider":"","profilePicUrl":""},"id":"2","key":"hskey-auth-test-0123456789","reusable":false,"ephemeral":false,"used":false,"expiration":"2026-09-08T00:00:00Z","createdAt":"2026-11-27T05:28:49.841541864Z","aclTags":[]}}"#;

    #[test]
    fn logs_a_logged_out_client_in_as_its_own_node() {
        let config = config();
        let model = Model::resolve(&config, today()).unwrap();
        let runner = RecordingRunner::new();
        runner.respond("tailscale", ok(LOGGED_OUT));
        let api = FakeHeadscale::new()
            .reply("/api/v1/node", 200, r#"{"nodes":[]}"#)
            .reply("/api/v1/user?name=parallax", 200, USERS_NONE)
            .reply("POST /api/v1/user", 200, USER_CREATED)
            .reply("POST /api/v1/preauthkey", 200, KEY_CREATED);
        let ts = Tailscaled {
            socket: SOCKET,
            operator: Some("parallax"),
            runner: &runner,
        };
        let (router, done) = sync(&model, &ts, &api, true).unwrap();
        assert_eq!(router, Router::LoggedOut);
        assert_eq!(done.len(), 2, "{done:?}");
        assert_eq!(
            api.posted.borrow()[1],
            (
                "/api/v1/preauthkey".to_string(),
                r#"{"ephemeral":false,"expiration":"2026-09-08T00:00:00Z","reusable":false,"user":"3"}"#.to_string()
            )
        );
        let calls = runner.calls.borrow();
        let (_, args, stdin) = &calls[1];
        assert_eq!(
            args.join(" "),
            format!("--socket={SOCKET} up --reset --login-server=https://headscale.mydomain.com --auth-key=file:/dev/stdin --hostname=parallax-gateway --advertise-routes=10.8.0.1/32,198.18.1.0/24 --netfilter-mode=off --snat-subnet-routes=false --accept-dns=false --accept-routes=false --operator=parallax --timeout=30s")
        );
        // The key goes on stdin, never in the arguments.
        assert_eq!(stdin.as_deref(), Some("hskey-auth-test-0123456789"));
    }

    #[test]
    fn sets_and_approves_its_own_router() {
        let config = config();
        let model = Model::resolve(&config, today()).unwrap();
        let runner = RecordingRunner::new();
        runner.respond("tailscale", ok(&running()));
        runner.respond("tailscale", ok(&prefs_json("198.18.1.0/24")));
        let nodes = format!(
            r#"{{"nodes":[{{"id":"1","nodeKey":"{KEY}","ipAddresses":["100.64.0.1"],"givenName":"parallax-gateway","user":{{"id":"3","name":"parallax"}},"online":true,"availableRoutes":["198.18.1.0/24"],"approvedRoutes":[]}}]}}"#
        );
        let api = FakeHeadscale::new()
            .reply("/api/v1/node", 200, &nodes)
            .reply("POST /api/v1/node/1/approve_routes", 200, "{}");
        let ts = Tailscaled {
            socket: SOCKET,
            operator: None,
            runner: &runner,
        };
        let (_, done) = sync(&model, &ts, &api, true).unwrap();
        assert_eq!(
            done,
            vec![
                "router: set the router's routes to 10.8.0.1/32,198.18.1.0/24",
                "router: approve the routes 10.8.0.1/32,198.18.1.0/24"
            ]
        );
        assert_eq!(
            runner.command_lines()[2],
            format!("tailscale --socket={SOCKET} set --hostname=parallax-gateway --advertise-routes=10.8.0.1/32,198.18.1.0/24 --netfilter-mode=off --snat-subnet-routes=false --accept-dns=false --accept-routes=false")
        );
        assert_eq!(
            api.posted.borrow()[0].1,
            r#"{"routes":["10.8.0.1/32","198.18.1.0/24"]}"#
        );
    }

    #[test]
    fn doctor_only_warns() {
        let config = config();
        let model = Model::resolve(&config, today()).unwrap();
        let runner = RecordingRunner::new();
        runner.respond(
            "tailscale",
            Output {
                status: 1,
                stdout: String::new(),
                stderr: "failed to connect to local tailscaled; it doesn't appear to be running"
                    .into(),
            },
        );
        let ts = Tailscaled {
            socket: SOCKET,
            operator: None,
            runner: &runner,
        };
        let check = check(&model, &ts, &FakeHeadscale::new());
        let Outcome::Warn(w) = check.outcome else {
            panic!("{check:?}");
        };
        assert!(w.contains("doesn't appear to be running"), "{w}");
        let plain = canonical_config();
        let quiet = Model::resolve(&plain, today()).unwrap();
        let check = super::check(&quiet, &ts, &FakeHeadscale::new());
        assert!(matches!(check.outcome, Outcome::Ok(_)));
    }
}

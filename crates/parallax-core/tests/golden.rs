//! Golden-file tests: every generator's output for the canonical scenario is
//! frozen under `tests/golden/`. Run with `UPDATE_GOLDEN=1` to refresh after
//! an intentional change, then review the diff.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test helpers: failures should panic loudly"
)]

use std::path::{Path, PathBuf};

use parallax_core::generate::{self, ArtifactKind, Bundle};
use parallax_core::io::memory::{MemoryFs, RecordingRunner};
use parallax_core::io::System;
use parallax_core::model::{FirewallBackend, Host, Platform, PortSpec, Proto, Rule};
use parallax_core::testing::{canonical_config, keypair, today};
use parallax_core::transport::{self, Transport};
use parallax_core::{Config, Model};

fn golden_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden")
}

fn fs_with_server_key() -> MemoryFs {
    MemoryFs::new().with_file(
        "/etc/parallax/wg-server.key",
        keypair(200).private.expose_base64(),
    )
}

fn check_golden(name: &str, actual: &str) {
    let path = golden_dir().join(name);
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, actual).unwrap();
        return;
    }
    let expected = std::fs::read_to_string(&path).unwrap_or_else(|_| {
        panic!(
            "missing golden file {}; run with UPDATE_GOLDEN=1",
            path.display()
        )
    });
    if expected != actual {
        panic!(
            "golden mismatch for {}\n{}",
            path.display(),
            parallax_core::plan::unified_diff(&expected, actual)
        );
    }
}

/// Tier set names (`wg_<16 hex>`) as `wg_*`: they hash each tier's access,
/// so they differ between scenarios.
fn anon(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(i) = rest.find(['w', 't']) {
        let (head, tail) = rest.split_at(i);
        out.push_str(head);
        let is_set = (tail.starts_with("wg_") || tail.starts_with("ts_"))
            && tail.len() >= 19
            && tail.as_bytes()[3..19].iter().all(u8::is_ascii_hexdigit);
        if is_set {
            out.push_str(&tail[..3]);
            out.push('*');
            rest = &tail[19..];
        } else {
            out.push_str(&tail[..1]);
            rest = &tail[1..];
        }
    }
    out.push_str(rest);
    out
}

fn bundle_for(config: &Config) -> Bundle {
    let model = Model::resolve(config, today()).expect("valid");
    generate::generate_all(&model, &fs_with_server_key()).expect("generate")
}

#[test]
fn canonical_bundle_matches_golden() {
    let cfg = canonical_config();
    let bundle = bundle_for(&cfg);
    let paths: Vec<String> = bundle
        .artifacts
        .iter()
        .map(|a| {
            format!(
                "{}{}",
                a.path.display(),
                if a.secret { " (secret)" } else { "" }
            )
        })
        .collect();
    check_golden("canonical/MANIFEST", &(paths.join("\n") + "\n"));
    for a in &bundle.artifacts {
        check_golden(&format!("canonical/{}", a.path.display()), &a.contents);
    }
}

#[test]
fn exports_match_golden_for_every_platform() {
    let cfg = canonical_config();
    let model = Model::resolve(&cfg, today()).unwrap();
    let wg = transport::WireGuardTransport;
    for peer in ["laptop", "sister-phone", "router"] {
        let p = model.peer(peer).unwrap();
        for platform in Platform::ALL {
            let export = wg.export(&model, p, platform).unwrap();
            check_golden(&format!("exports/{peer}/{platform}.conf"), &export.contents);
            check_golden(
                &format!("exports/{peer}/{platform}.warnings"),
                &(export.warnings.join("\n") + "\n"),
            );
        }
    }
}

#[test]
fn iptables_backend_matches_golden() {
    let mut cfg = canonical_config();
    cfg.server.firewall.backend = FirewallBackend::IptablesNft;
    cfg.grants[0].rules.push(Rule::Internet);
    // A guest with internet and a proxied service: not_public and the DNAT.
    cfg.grants[1].rules.push(Rule::Internet);
    cfg.services[0].hostnames = vec!["immich.mydomain.com".into()];
    let bundle = bundle_for(&cfg);
    for a in bundle
        .of_kind(ArtifactKind::Firewall)
        .chain(bundle.of_kind(ArtifactKind::FirewallDockerUser))
    {
        check_golden(&format!("iptables/{}", a.path.display()), &a.contents);
    }
}

#[test]
fn internet_grant_and_masquerade_match_golden() {
    let mut cfg = canonical_config();
    cfg.grants[0].rules.push(Rule::Internet);
    cfg.grants[1].rules.push(Rule::Internet);
    cfg.networks[0].masquerade = true;
    let bundle = bundle_for(&cfg);
    let fw = bundle.of_kind(ArtifactKind::Firewall).next().unwrap();
    check_golden("variants/internet-masquerade.nft", &fw.contents);
    let rule = |tag: &str| {
        fw.contents
            .lines()
            .find(|l| l.contains(&format!("\"{tag}: internet")))
            .unwrap()
    };
    // The owner's all_networks tier still reaches private space beyond
    // the configured networks; a guest reaches only public addresses.
    assert!(rule("personal").contains("ip daddr != @lan_real"));
    assert!(rule("family").contains("ip daddr != @not_public"));
    // Merged, since nft rejects overlapping intervals: the configured
    // 192.168.1.0/24 sits inside 192.168.0.0/16.
    assert!(fw.contents.contains("192.168.0.0/16"));
    assert!(!fw.contents.contains("192.168.1.0/24,"));
}

#[test]
fn guest_internet_drops_the_home_public_ip() {
    let mut cfg = canonical_config();
    cfg.grants[0].rules.push(Rule::Internet);
    cfg.grants[1].rules.push(Rule::Internet);
    let home = std::net::Ipv4Addr::new(1, 2, 3, 4);
    let model = Model::resolve(&cfg, today())
        .unwrap()
        .with_public_ip(Some(home));
    let bundle = generate::generate_all(&model, &fs_with_server_key()).unwrap();
    let fw = bundle.of_kind(ArtifactKind::Firewall).next().unwrap();
    check_golden("variants/hairpin.nft", &fw.contents);
    // In the not_public set, which only public-only tiers use: the owner's
    // all_networks tier (lan_real) reaches the router anyway, and a grant
    // listed after `internet` that covers the address still works.
    let set: Vec<&str> = fw
        .contents
        .lines()
        .skip_while(|l| !l.contains("set not_public"))
        .take_while(|l| !l.trim().starts_with('}'))
        .collect();
    assert!(set.iter().any(|l| l.contains("1.2.3.4")), "{set:#?}");
    assert_eq!(fw.contents.matches("1.2.3.4").count(), 1, "{}", fw.contents);
    // Unknown: not in the set.
    let unknown = bundle_for(&cfg);
    let unknown = unknown.of_kind(ArtifactKind::Firewall).next().unwrap();
    assert!(!unknown.contents.contains("1.2.3.4"));
    assert!(!unknown.contents.contains("home's public IP"));
}

#[test]
fn proxied_service_gets_no_direct_accept() {
    let mut cfg = canonical_config();
    cfg.services[0].hostnames = vec!["immich.mydomain.com".into()];
    cfg.networks[0].gateway_address = Some("192.168.1.5".parse().unwrap());
    let bundle = bundle_for(&cfg);
    let fw = bundle.of_kind(ArtifactKind::Firewall).next().unwrap();
    // Set names follow each scenario's access (issue #35).
    let fw_text = anon(&fw.contents);
    check_golden("variants/proxied-service.nft", &fw.contents);
    let routes = bundle.of_kind(ArtifactKind::ProxyRoutes).next().unwrap();
    check_golden("variants/proxied-service-routes.toml", &routes.contents);
    assert!(
        !fw_text
            .lines()
            .any(|l| l.contains("service immich") && l.contains(" accept ")),
        "family must not reach immich directly, not even on the gateway host:\n{}",
        fw_text
    );
    assert!(fw
        .contents
        .contains("drop comment \"family: default deny\""));
    // Family's HTTPS to Immich's client address goes to the proxy, before
    // NETMAP would send it to the real host; only family may reach the proxy.
    let pre: Vec<&str> = fw
        .contents
        .lines()
        .skip_while(|l| !l.contains("chain prerouting"))
        .collect();
    assert!(pre[2].contains(
        "iifname \"wg0\" ip saddr @wg_* ip daddr 198.18.1.5 tcp dport 443 dnat ip to 10.8.0.1:8443"
    ), "{pre:#?}");
    assert!(pre.iter().any(|l| l.contains("netmap home")));
    assert!(!fw_text.contains("personal/wireguard: https proxy"));
    assert!(
        fw_text.contains("iifname \"wg0\" ip saddr @wg_* ip daddr 10.8.0.1 tcp dport 8443 accept")
    );
}

#[test]
fn no_proxy_redirect_where_a_grant_reaches_the_host_directly() {
    let mut cfg = canonical_config();
    cfg.services[0].hostnames = vec!["immich.mydomain.com".into()];
    cfg.grants[1].rules.push(Rule::Host {
        host: "192.168.1.5".parse().unwrap(),
        ports: vec![PortSpec::one(parallax_core::model::Proto::Tcp, 443)],
    });
    let bundle = bundle_for(&cfg);
    let fw = bundle.of_kind(ArtifactKind::Firewall).next().unwrap();
    assert!(!fw.contents.contains("dnat ip to"), "{}", fw.contents);
    assert!(!fw.contents.contains("https proxy"), "{}", fw.contents);
}

#[test]
fn tunnel_peers_are_checked_on_every_packet() {
    let bundle = bundle_for(&canonical_config());
    let fw = bundle.of_kind(ArtifactKind::Firewall).next().unwrap();
    // Set names follow each scenario's access (issue #35).
    let fw_text = anon(&fw.contents);
    // No blanket "established" accept: a removed grant cuts open flows.
    assert!(!fw_text.contains("established"), "{}", fw_text);
    for chain in ["chain input", "chain forward"] {
        let body: Vec<&str> = fw
            .contents
            .lines()
            .skip_while(|l| !l.contains(chain))
            .take_while(|l| !l.trim().starts_with('}'))
            .collect();
        assert!(
            body[2].contains("meta nfproto ipv6 iifname { \"wg0\", \"tailscale0\" } drop"),
            "{body:#?}"
        );
        assert!(body.iter().any(|l| l.contains("ct direction reply accept")));
        assert!(body.iter().any(|l| l.contains("ct state related accept")));
    }
    // A packet sees its own tier's rules only: one lookup by source
    // address picks the chain, however many peers and tiers there are.
    assert!(fw_text.contains(
        "iifname \"wg0\" ip saddr vmap { 10.8.1.1 : jump tier_0, 10.8.1.2 : jump tier_0, 10.8.2.1 : jump tier_1 }"
    ));
    assert!(fw
        .contents
        .contains("iifname \"tailscale0\" ip saddr @ts_* jump tier_1"));
    let family: Vec<&str> = fw
        .contents
        .lines()
        .skip_while(|l| !l.contains("chain tier_1 {"))
        .take_while(|l| !l.trim().starts_with('}'))
        .collect();
    assert_eq!(
        family.last().map(|l| l.trim()),
        Some("drop comment \"family: default deny\"")
    );
}

#[test]
fn gateway_address_turns_grants_into_input_accepts() {
    let mut cfg = canonical_config();
    cfg.networks[0].gateway_address = Some("192.168.1.5".parse().unwrap());
    let bundle = bundle_for(&cfg);
    let fw = bundle.of_kind(ArtifactKind::Firewall).next().unwrap();
    // Set names follow each scenario's access (issue #35).
    let fw_text = anon(&fw.contents);
    check_golden("variants/gateway-address.nft", &fw.contents);
    let input: Vec<&str> = fw
        .contents
        .lines()
        .skip_while(|l| !l.contains("chain input"))
        .take_while(|l| !l.contains("chain forward"))
        .collect();
    assert!(
        input
            .iter()
            .any(|l| l.contains("ip saddr @wg_* ip daddr 192.168.1.5 accept")),
        "{input:#?}"
    );
    assert!(
        input
            .iter()
            .any(|l| l.contains("ip saddr @wg_* ip daddr 192.168.1.5 tcp dport 443 accept")),
        "{input:#?}"
    );
    let drop_idx = input
        .iter()
        .position(|l| l.contains("may not reach anything else"))
        .unwrap();
    let accept_idx = input
        .iter()
        .position(|l| l.contains("family/wireguard: service immich"))
        .unwrap();
    assert!(accept_idx < drop_idx, "grant accepts must precede the drop");
    // A gateway address outside the subnet is rejected.
    cfg.networks[0].gateway_address = Some("192.168.9.5".parse().unwrap());
    let (errors, _) = parallax_core::validate::check(&cfg);
    assert!(
        errors
            .iter()
            .any(|e| e.contains("gateway_address 192.168.9.5 is not inside")),
        "{errors:?}"
    );
}

#[test]
fn guest_allowed_ips_are_granted_hosts_only_in_virtual_space() {
    let cfg = canonical_config();
    let model = Model::resolve(&cfg, today()).unwrap();
    let sister = model.peer("sister-phone").unwrap();
    let ips = generate::client::allowed_ips(&model, sister, Platform::Mobile);
    assert_eq!(
        ips,
        vec![
            "198.18.1.5/32".parse().unwrap(),
            "10.8.0.1/32".parse().unwrap()
        ]
    );
    let laptop = model.peer("laptop").unwrap();
    let ips = generate::client::allowed_ips(&model, laptop, Platform::Linux);
    assert_eq!(
        ips,
        vec![
            "198.18.1.0/24".parse().unwrap(),
            "10.8.0.1/32".parse().unwrap()
        ]
    );
}

#[test]
fn named_hosts_get_what_they_resolved_to() {
    // A service and a game server by name; the NAS's name resolves to two
    // addresses.
    let mut cfg = canonical_config();
    cfg.services[0].host = Host::Name("immich.mydomain.com".into());
    cfg.grants[1].rules.push(Rule::Host {
        host: Host::Name("game.mydomain.com".into()),
        ports: vec![PortSpec::one(Proto::Udp, 25565)],
    });
    cfg.grants[1].rules.push(Rule::Host {
        host: Host::Name("nas.mydomain.com".into()),
        ports: Vec::new(),
    });
    let addr = |s: &str| s.parse::<std::net::Ipv4Addr>().unwrap();
    let names = [
        ("immich.mydomain.com", vec![addr("192.168.1.5")]),
        ("game.mydomain.com", vec![addr("192.168.1.20")]),
        (
            "nas.mydomain.com",
            vec![addr("192.168.1.9"), addr("192.168.1.10")],
        ),
    ]
    .into_iter()
    .map(|(n, a)| (n.to_string(), a))
    .collect();
    let model = Model::resolve(&cfg, today()).unwrap().with_names(names);
    assert!(
        model.name_problems().is_empty(),
        "{:?}",
        model.name_problems()
    );
    let bundle = generate::generate_all(&model, &fs_with_server_key()).unwrap();
    let fw = bundle.of_kind(ArtifactKind::Firewall).next().unwrap();
    check_golden("variants/named-hosts.nft", &fw.contents);
    let dns = bundle.of_kind(ArtifactKind::DnsRoutes).next().unwrap();
    check_golden("variants/named-hosts-dns.toml", &dns.contents);
    let sister = model.peer("sister-phone").unwrap();
    let ips = generate::client::allowed_ips(&model, sister, Platform::Mobile);
    let ips: Vec<String> = ips.iter().map(ToString::to_string).collect();
    assert_eq!(
        ips,
        [
            "198.18.1.5/32",
            "198.18.1.20/32",
            "198.18.1.9/32",
            "198.18.1.10/32",
            "10.8.0.1/32"
        ]
    );
    // Not resolved yet: the grants give nothing, the service included.
    let unresolved = Model::resolve(&cfg, today()).unwrap();
    let bundle = generate::generate_all(&unresolved, &fs_with_server_key()).unwrap();
    let fw = bundle.of_kind(ArtifactKind::Firewall).next().unwrap();
    assert!(!fw.contents.contains("192.168.1.20"), "{}", fw.contents);
    assert!(!fw.contents.contains("service immich"), "{}", fw.contents);
    assert_eq!(unresolved.name_problems().len(), 3);
}

#[test]
fn names_on_the_home_public_ip_are_port_forwards() {
    // A guest with full tunnel and internet: a game server's port and an
    // HTTPS service by name, both behind port forwards on the public IP.
    let mut cfg = canonical_config();
    cfg.services[0].host = Host::Name("immich.mydomain.com".into());
    cfg.services[0].hostnames = vec!["immich.mydomain.com".into()];
    cfg.grants[1].rules.push(Rule::Host {
        host: Host::Name("game.mydomain.com".into()),
        ports: vec![PortSpec::one(Proto::Udp, 25565)],
    });
    cfg.grants[1].rules.push(Rule::Internet);
    cfg.peers[2].wireguard.as_mut().unwrap().allowed_ips =
        parallax_core::model::AllowedIpsStrategy::FullTunnel;
    let home = std::net::Ipv4Addr::new(1, 2, 3, 4);
    let names: parallax_core::names::Resolved = [
        ("immich.mydomain.com".to_string(), vec![home]),
        ("game.mydomain.com".to_string(), vec![home]),
    ]
    .into();
    let model = Model::resolve(&cfg, today())
        .unwrap()
        .with_public_ip(Some(home))
        .with_names(names.clone());
    assert!(
        model.name_problems().is_empty(),
        "{:?}",
        model.name_problems()
    );
    let bundle = generate::generate_all(&model, &fs_with_server_key()).unwrap();
    let fw = bundle.of_kind(ArtifactKind::Firewall).next().unwrap();
    // Set names follow each scenario's access (issue #35).
    let fw_text = anon(&fw.contents);
    check_golden("variants/home-public-names.nft", &fw.contents);
    let routes = bundle.of_kind(ArtifactKind::ProxyRoutes).next().unwrap();
    check_golden("variants/home-public-names-routes.toml", &routes.contents);
    // The game port: accepted out the WAN, masqueraded; still in not_public.
    assert!(fw_text.contains(
        "oifname \"eth0\" ip daddr 1.2.3.4 udp dport 25565 accept comment \"family: host game.mydomain.com (1.2.3.4) (a port forward on the home's public IP)\""
    ), "{}", fw_text);
    // HTTPS by name: redirected to the proxy, which connects to the public IP.
    assert!(fw_text.contains(
        "iifname \"wg0\" ip saddr @wg_* ip daddr 1.2.3.4 tcp dport 443 dnat ip to 10.8.0.1:8443"
    ), "{}", fw_text);
    assert!(
        routes.contents.contains("upstream = \"1.2.3.4:443\""),
        "{}",
        routes.contents
    );
    // Nothing else on the public IP: no all-ports accept.
    assert!(!fw_text.contains("ip daddr 1.2.3.4 accept"), "{}", fw_text);
    // The owner's tier (all_networks + internet) reaches the public IP
    // anyway: granting it the service adds no redirect to the proxy.
    let mut owner = cfg.clone();
    owner.grants[0].rules.push(Rule::Internet);
    owner.grants[0].rules.push(Rule::Service {
        name: "immich".into(),
    });
    let model = Model::resolve(&owner, today())
        .unwrap()
        .with_public_ip(Some(home))
        .with_names(names.clone());
    let bundle = generate::generate_all(&model, &fs_with_server_key()).unwrap();
    let fw = bundle.of_kind(ArtifactKind::Firewall).next().unwrap();
    let fw_text = anon(&fw.contents);
    assert!(
        !fw_text.contains("ip saddr @wg_* ip daddr 1.2.3.4 tcp dport 443 dnat"),
        "{}",
        fw_text
    );
    let routes = bundle.of_kind(ArtifactKind::ProxyRoutes).next().unwrap();
    assert!(
        !routes.contents.contains("10.8.1.1/32"),
        "{}",
        routes.contents
    );
    // Without `internet` the forward still goes out masqueraded.
    cfg.grants[1].rules.retain(|g| *g != Rule::Internet);
    let model = Model::resolve(&cfg, today())
        .unwrap()
        .with_public_ip(Some(home))
        .with_names(names);
    let bundle = generate::generate_all(&model, &fs_with_server_key()).unwrap();
    let fw = bundle.of_kind(ArtifactKind::Firewall).next().unwrap();
    let fw_text = anon(&fw.contents);
    assert!(
        fw_text.contains("ip daddr 1.2.3.4 udp dport 25565 accept"),
        "{}",
        fw_text
    );
    assert!(
        fw_text.contains("masquerade comment \"internet egress\""),
        "{}",
        fw_text
    );
}

#[test]
fn port_lists_are_one_rule_per_protocol() {
    // SMB as a service, granted to the guests: four ports, two protocols.
    let mut cfg = canonical_config();
    let mut smb = cfg.services[0].clone();
    smb.name = "nas-smb".into();
    smb.host = "192.168.1.9".parse().unwrap();
    smb.nginx_vhost = false;
    smb.ports = ["137-138/udp", "139/tcp", "445/tcp"]
        .iter()
        .map(|p| p.parse().unwrap())
        .collect();
    cfg.services.push(smb);
    cfg.grants[1].rules.push(Rule::Service {
        name: "nas-smb".into(),
    });
    // And a game server's port on TCP and UDP, inline.
    cfg.grants[1].rules.push(Rule::Host {
        host: "192.168.1.20".parse().unwrap(),
        ports: vec!["25565".parse().unwrap()],
    });
    let fw = bundle_for(&cfg);
    let fw = fw.of_kind(ArtifactKind::Firewall).next().unwrap();
    check_golden("variants/port-lists.nft", &fw.contents);
    for line in [
        "oifname \"eth0\" ip daddr 192.168.1.9 tcp dport { 139, 445 } accept comment \"family: service nas-smb\"",
        "oifname \"eth0\" ip daddr 192.168.1.9 udp dport 137-138 accept comment \"family: service nas-smb\"",
        "oifname \"eth0\" ip daddr 192.168.1.20 tcp dport 25565 accept comment \"family: host 192.168.1.20\"",
        "oifname \"eth0\" ip daddr 192.168.1.20 udp dport 25565 accept comment \"family: host 192.168.1.20\"",
    ] {
        assert!(fw.contents.contains(line), "missing {line}:\n{}", fw.contents);
    }
    cfg.server.firewall.backend = FirewallBackend::IptablesNft;
    let bundle = bundle_for(&cfg);
    let rules = bundle.of_kind(ArtifactKind::Firewall).next().unwrap();
    assert!(
        rules
            .contents
            .contains("-d 192.168.1.9/32 -p tcp -m multiport --dports 139,445 "),
        "{}",
        rules.contents
    );
    assert!(
        rules
            .contents
            .contains("-d 192.168.1.9/32 -p udp --dport 137:138 "),
        "{}",
        rules.contents
    );
}

#[test]
fn generation_is_deterministic() {
    let cfg = canonical_config();
    assert_eq!(bundle_for(&cfg), bundle_for(&cfg));
}

#[test]
fn disabled_and_expired_peers_leave_the_server_config() {
    let mut cfg = canonical_config();
    cfg.peers[0].enabled = false;
    cfg.peers[2].expires = Some("2026-01-01".parse().unwrap());
    let bundle = bundle_for(&cfg);
    let server = bundle
        .of_kind(ArtifactKind::WireGuardServer)
        .next()
        .unwrap();
    assert_eq!(server.contents.matches("[Peer]").count(), 1);
    assert!(server.contents.contains("# laptop"));
}

#[test]
fn server_key_mismatch_is_reported() {
    let cfg = canonical_config();
    let model = Model::resolve(&cfg, today()).unwrap();
    let fs = MemoryFs::new().with_file(
        "/etc/parallax/wg-server.key",
        keypair(201).private.expose_base64(),
    );
    let err = generate::generate_all(&model, &fs).unwrap_err().to_string();
    assert!(
        err.contains("does not match server.wireguard.public_key"),
        "{err}"
    );
    let err = generate::generate_all(&model, &MemoryFs::new())
        .unwrap_err()
        .to_string();
    assert!(err.contains("parallax keygen"), "{err}");
}

#[test]
fn apply_runs_expected_commands_and_is_idempotent() {
    let cfg = canonical_config();
    let model = Model::resolve(&cfg, today()).unwrap();
    let fs = fs_with_server_key();
    let bundle = generate::generate_all(&model, &fs).unwrap();
    let runner = RecordingRunner::new();
    // Interface does not exist on the first apply; DOCKER-USER exists with a stale parallax rule.
    runner.respond_to(
        "ip",
        &["link", "show", "dev", "wg0"],
        parallax_core::io::Output {
            status: 1,
            stdout: String::new(),
            stderr: "does not exist".into(),
        },
    );
    runner.respond_to(
        "nft",
        &["-a", "list", "chain", "ip", "filter", "DOCKER-USER"],
        parallax_core::io::Output {
            status: 0,
            stdout: "table ip filter {\n\tchain DOCKER-USER {\n\t\tiifname \"wg0\" accept comment \"parallax\" # handle 12\n\t\tcounter return # handle 3\n\t}\n}\n".into(),
            stderr: String::new(),
        },
    );
    let sys = System {
        fs: &fs,
        runner: &runner,
    };
    let out = Path::new("/var/lib/parallax");
    let report = parallax_core::apply::apply(&model, &bundle, out, sys).unwrap();
    let lines = runner.command_lines();
    check_golden("apply/commands.txt", &(lines.join("\n") + "\n"));
    // `wg` reads the config from the pipe, not a path (AppArmor on Ubuntu).
    let fed = runner
        .calls
        .borrow()
        .iter()
        .find(|(p, a, _)| p == "wg" && a.first().is_some_and(|a| a == "syncconf"))
        .and_then(|(_, _, stdin)| stdin.clone());
    assert_eq!(
        fed.as_deref(),
        parallax_core::io::FileSystem::read(&fs, &out.join("wireguard/wg0.conf"))
            .unwrap()
            .as_deref()
    );
    assert!(
        report
            .log
            .iter()
            .any(|l| l.contains("created interface wg0")),
        "{:?}",
        report.log
    );
    assert_eq!(fs.is_secret(&out.join("wireguard/wg0.conf")), Some(true));
    assert_eq!(
        fs.is_secret(&out.join("nftables/parallax.nft")),
        Some(false)
    );

    // Second apply: nothing on disk changes, and the plan is empty.
    let plan = parallax_core::plan::plan(&bundle, out, &fs).unwrap();
    assert!(!plan.has_changes(), "{}", plan.render());
    let before = fs.paths();
    parallax_core::apply::apply(&model, &bundle, out, sys).unwrap();
    assert_eq!(fs.paths(), before);
}

#[test]
fn apply_preflight_names_missing_tools() {
    let cfg = canonical_config();
    let model = Model::resolve(&cfg, today()).unwrap();
    let fs = fs_with_server_key();
    let bundle = generate::generate_all(&model, &fs).unwrap();
    let runner = RecordingRunner::new();
    runner.respond(
        "nft",
        parallax_core::io::Output {
            status: 127,
            stdout: String::new(),
            stderr: "not found".into(),
        },
    );
    let sys = System {
        fs: &fs,
        runner: &runner,
    };
    let err = parallax_core::apply::apply(&model, &bundle, Path::new("/out"), sys)
        .unwrap_err()
        .to_string();
    assert!(err.contains("`nft` is not available"), "{err}");
}

#[test]
fn iptables_apply_refills_chains_in_one_restore() {
    let mut cfg = canonical_config();
    cfg.server.firewall.backend = FirewallBackend::IptablesNft;
    cfg.grants[1].rules.push(Rule::Internet);
    let model = Model::resolve(&cfg, today()).unwrap();
    let fs = fs_with_server_key();
    let bundle = generate::generate_all(&model, &fs).unwrap();
    // A live tier set's name, as the ruleset gives it.
    let live = parallax_core::generate::firewall::build(&model)
        .unwrap()
        .sets
        .into_iter()
        .find(|s| s.name.starts_with("wg_"))
        .unwrap()
        .name;
    let runner = RecordingRunner::new();
    // A tier went away since the last apply: its chain is still there.
    runner.respond_to(
        "iptables",
        &["-t", "filter", "-S"],
        parallax_core::io::Output {
            status: 0,
            stdout: "-P INPUT ACCEPT\n-N PARALLAX_FORWARD\n-N PARALLAX_T0\n-N PARALLAX_T1\n-N PARALLAX_T2\n".into(),
            stderr: String::new(),
        },
    );
    // A set from before grants, one of a tier that went away, and a live one.
    runner.respond_to(
        "ipset",
        &["list", "-n"],
        parallax_core::io::Output {
            status: 0,
            stdout: format!("ts_family\nwg_0000000000000000\n{live}\nnot_public\n"),
            stderr: String::new(),
        },
    );
    let sys = System {
        fs: &fs,
        runner: &runner,
    };
    parallax_core::apply::apply(&model, &bundle, Path::new("/var/lib/parallax"), sys).unwrap();
    let lines = runner.command_lines();
    let pos = |needle: &str| lines.iter().position(|l| l.starts_with(needle));
    // Stale sets go after the restore; live ones stay.
    let gone = |set: &str| pos(&format!("ipset destroy {set}"));
    assert!(gone("ts_family").unwrap() > pos("iptables-restore").unwrap());
    assert!(gone("wg_0000000000000000").is_some());
    assert!(gone(&live).is_none() && gone("not_public").is_none());
    let restore = pos("iptables-restore --noflush").unwrap();
    // No flush of live chains before the restore: that left a window with
    // empty chains, and empty ones if the restore failed.
    assert!(
        !lines[..restore].iter().any(|l| l.contains(" -F ")),
        "{lines:#?}"
    );
    // Sets are filled aside and swapped in, never flushed while in use.
    assert!(pos("ipset swap parallax-swap not_public").unwrap() < restore);
    assert!(!lines.iter().any(|l| l == "ipset flush not_public"));
    // Only the stale tier chain goes.
    assert!(lines
        .iter()
        .any(|l| l == "iptables -t filter -X PARALLAX_T2"));
    assert!(!lines.iter().any(|l| l.contains("-X PARALLAX_T1")));
}

/// `config export` writes one canonical layout; freeze it, and check it
/// parses back to the same configuration.
#[test]
fn config_export_layout_matches_golden() {
    let canonical = canonical_config();
    let text = canonical.to_toml().unwrap();
    assert_eq!(Config::from_toml(&text).unwrap(), canonical);
    check_golden("config/canonical.toml", &text);

    // Several grants go one per line; a section's sub-table that doesn't fit
    // on one line becomes a header in every entry of that section.
    let mut busy = canonical_config();
    busy.server.wan_interface = Some("eth1".into());
    busy.grants[0].rules = vec![
        Rule::Network {
            name: "home".into(),
        },
        Rule::Host {
            host: std::net::Ipv4Addr::new(192, 168, 1, 10).into(),
            ports: vec![PortSpec::one(Proto::Udp, 53)],
        },
        Rule::Internet,
    ];
    busy.grants.push(parallax_core::model::Grant {
        name: "public".into(),
        everyone: true,
        rules: vec![Rule::PublicDns],
    });
    busy.peers[0].grants.push("family".into());
    let wg = busy.peers[0].wireguard.as_mut().unwrap();
    wg.visible_networks = Some(vec!["home".into()]);
    wg.mtu = Some(1380);
    let text = busy.to_toml().unwrap();
    assert_eq!(Config::from_toml(&text).unwrap(), busy);
    check_golden("config/busy.toml", &text);

    // A fresh install has no peers: the section is left out, not `peer = []`.
    let mut empty = canonical_config();
    empty.peers.clear();
    let text = empty.to_toml().unwrap();
    assert!(
        !text.contains("# Peers") && !text.contains("[[peer]]"),
        "{text}"
    );
    assert_eq!(Config::from_toml(&text).unwrap(), empty);
}

/// A file written before grants replaced templates imports as the same
/// access: each template a grant, each peer its template's grant and
/// client settings.
#[test]
fn template_configs_import_as_grants() {
    let old = std::fs::read_to_string(golden_dir().join("config/legacy-templates.toml")).unwrap();
    assert_eq!(Config::from_toml(&old).unwrap(), canonical_config());
    let both = old.replacen(
        "template = \"personal\"",
        "template = \"personal\"\ngrants = [\"family\"]",
        1,
    );
    let err = Config::from_toml(&both).unwrap_err().to_string();
    assert!(
        err.contains("peer 'router' has both template and grants"),
        "{err}"
    );
    // A template that isn't there doesn't bind to a grant of that name.
    let new = canonical_config().to_toml().unwrap().replacen(
        "grants = [\"personal\"]",
        "template = \"personal\"",
        1,
    );
    let err = Config::from_toml(&new).unwrap_err().to_string();
    assert!(
        err.contains("peer 'router' has template 'personal', which isn't defined"),
        "{err}"
    );
}

/// Grants decide access at the gateway, not in the device's config: a peer
/// whose grants change keeps its address, and its exported config only
/// differs in comments (and in `AllowedIPs` when that follows the grants,
/// `grants_only`).
#[test]
fn changing_grants_keeps_the_address_and_the_exported_config() {
    let lines = |cfg: &Config, peer: &str| {
        let model = Model::resolve(cfg, today()).unwrap();
        let peer = model.peer(peer).unwrap();
        let export = generate::client::render(&model, peer, Platform::Linux).unwrap();
        export
            .contents
            .lines()
            .filter(|l| !l.starts_with('#'))
            .map(str::to_string)
            .collect::<Vec<_>>()
    };
    let before = canonical_config();
    let mut after = before.clone();
    after.peers[1].grants = vec!["family".into()];
    after.grants.push(parallax_core::model::Grant {
        name: "photos".into(),
        everyone: true,
        rules: vec![Rule::Network {
            name: "home".into(),
        }],
    });
    assert_eq!(lines(&before, "laptop"), lines(&after, "laptop"));
    assert_eq!(after.peers[1].wireguard, before.peers[1].wireguard);
    // The firewall follows: the laptop is in another tier now.
    let model = Model::resolve(&after, today()).unwrap();
    let laptop = model.tier_of(model.peer("laptop").unwrap()).unwrap();
    assert_eq!(laptop.label(), "family+photos");
}

/// A peer with two grants reaches what both give and nothing more; a grant
/// for everyone reaches every peer.
#[test]
fn a_peer_reaches_the_union_of_its_grants() {
    let mut cfg = canonical_config();
    cfg.services.push(parallax_core::model::Service {
        name: "nas".into(),
        host: std::net::Ipv4Addr::new(192, 168, 1, 9).into(),
        ports: vec![PortSpec::one(Proto::Tcp, 445)],
        nginx_vhost: false,
        hostnames: Vec::new(),
    });
    cfg.grants.push(parallax_core::model::Grant {
        name: "files".into(),
        everyone: false,
        rules: vec![Rule::Service { name: "nas".into() }],
    });
    cfg.grants.push(parallax_core::model::Grant {
        name: "public".into(),
        everyone: true,
        rules: vec![Rule::PublicDns],
    });
    cfg.peers[2].grants.push("files".into());
    let bundle = bundle_for(&cfg);
    let fw = bundle.of_kind(ArtifactKind::Firewall).next().unwrap();
    // The rules of the tier chain ending in `label`'s default deny.
    let chain = |label: &str| -> Vec<String> {
        let deny = format!("drop comment \"{label}: default deny\"");
        fw.contents
            .split("chain tier_")
            .find(|c| c.contains(&deny))
            .unwrap()
            .lines()
            .skip(1)
            .map(str::trim)
            .take_while(|l| *l != "}")
            .map(str::to_string)
            .collect()
    };
    assert_eq!(
        chain("family+files+public"),
        [
            "oifname \"eth0\" ip daddr 192.168.1.5 tcp dport 443 accept comment \"family+files+public: service immich\"",
            "oifname \"eth0\" ip daddr 192.168.1.9 tcp dport 445 accept comment \"family+files+public: service nas\"",
            "drop comment \"family+files+public: default deny\"",
        ]
    );
    // Everyone has `public`: the owner's tier too, and every tier answers
    // public names.
    assert_eq!(chain("personal+public").len(), 2);
    let dns = bundle.of_kind(ArtifactKind::DnsRoutes).next().unwrap();
    let routes = generate::dns::DnsRoutes::from_toml(&dns.contents).unwrap();
    assert!(routes.tiers.iter().all(|t| t.public), "{routes:?}");
}

/// An address that changes hands in one save: the old key is off the
/// interface before the firewall gives the address its new owner's access.
#[test]
fn apply_takes_a_moved_address_off_its_old_key_first() {
    let cfg = canonical_config();
    let model = Model::resolve(&cfg, today()).unwrap();
    let fs = fs_with_server_key();
    let bundle = generate::generate_all(&model, &fs).unwrap();
    let wg = |n: usize| cfg.peers[n].wireguard.as_ref().unwrap();
    let old_key = parallax_core::testing::keypair(77).public.to_base64();
    let runner = RecordingRunner::new();
    let wide_key = parallax_core::testing::keypair(78).public.to_base64();
    // Live: the router with an extra address of nobody's (syncconf's job),
    // the laptop's address on another key, a key holding a whole range,
    // and the sister's phone as configured.
    runner.respond_to(
        "wg",
        &["show", "wg0", "allowed-ips"],
        parallax_core::io::Output {
            status: 0,
            stdout: format!(
                "{}\t10.8.1.1/32 10.8.9.9/32 fd00::2/128\n{old_key}\t10.8.1.2/32\n{wide_key}\t10.8.2.0/24\n{}\t10.8.2.1/32\n",
                wg(0).public_key.to_base64(),
                wg(2).public_key.to_base64()
            ),
            stderr: String::new(),
        },
    );
    let sys = System {
        fs: &fs,
        runner: &runner,
    };
    parallax_core::apply::apply(&model, &bundle, Path::new("/var/lib/parallax"), sys).unwrap();
    let lines = runner.command_lines();
    let pos = |needle: &str| lines.iter().position(|l| l.starts_with(needle)).unwrap();
    let removed: Vec<&String> = lines.iter().filter(|l| l.ends_with(" remove")).collect();
    assert_eq!(removed.len(), 2, "{lines:#?}");
    assert!(pos(&format!("wg set wg0 peer {old_key} remove")) < pos("nft -f"));
    assert!(pos(&format!("wg set wg0 peer {wide_key} remove")) < pos("nft -f"));
}

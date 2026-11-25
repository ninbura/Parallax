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
use parallax_core::model::{FirewallBackend, Grant, Platform};
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
    cfg.templates[0].grants.push(Grant::Internet);
    // A guest with internet and a proxied service: not_public and the DNAT.
    cfg.templates[1].grants.push(Grant::Internet);
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
    cfg.templates[0].grants.push(Grant::Internet);
    cfg.templates[1].grants.push(Grant::Internet);
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
    // The owner's all_networks template still reaches private space beyond
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
    cfg.templates[0].grants.push(Grant::Internet);
    cfg.templates[1].grants.push(Grant::Internet);
    let home = std::net::Ipv4Addr::new(1, 2, 3, 4);
    let model = Model::resolve(&cfg, today())
        .unwrap()
        .with_public_ip(Some(home));
    let bundle = generate::generate_all(&model, &fs_with_server_key()).unwrap();
    let fw = bundle.of_kind(ArtifactKind::Firewall).next().unwrap();
    check_golden("variants/hairpin.nft", &fw.contents);
    let family: Vec<&str> = fw
        .contents
        .lines()
        .skip_while(|l| !l.contains("chain tier_family"))
        .collect();
    let drop = family
        .iter()
        .position(|l| l.contains("ip daddr 1.2.3.4 drop"))
        .unwrap();
    let internet = family
        .iter()
        .position(|l| l.contains("family: internet"))
        .unwrap();
    assert!(drop < internet, "{family:#?}");
    // The owner's all_networks template reaches the router anyway.
    assert_eq!(fw.contents.matches("1.2.3.4").count(), 1, "{}", fw.contents);
    // Unknown: no rule, the rest unchanged.
    let unknown = bundle_for(&cfg);
    let unknown = unknown.of_kind(ArtifactKind::Firewall).next().unwrap();
    assert!(!unknown.contents.contains("hairpin"));
}

#[test]
fn proxied_service_gets_no_direct_accept() {
    let mut cfg = canonical_config();
    cfg.services[0].hostnames = vec!["immich.mydomain.com".into()];
    cfg.networks[0].gateway_address = Some("192.168.1.5".parse().unwrap());
    let bundle = bundle_for(&cfg);
    let fw = bundle.of_kind(ArtifactKind::Firewall).next().unwrap();
    check_golden("variants/proxied-service.nft", &fw.contents);
    let routes = bundle.of_kind(ArtifactKind::ProxyRoutes).next().unwrap();
    check_golden("variants/proxied-service-routes.toml", &routes.contents);
    assert!(
        !fw.contents
            .lines()
            .any(|l| l.contains("service immich") && l.contains(" accept ")),
        "family must not reach immich directly, not even on the gateway host:\n{}",
        fw.contents
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
        "iifname \"wg0\" ip saddr 10.8.2.0/24 ip daddr 198.18.1.5 tcp dport 443 dnat ip to 10.8.0.1:8443"
    ), "{pre:#?}");
    assert!(pre.iter().any(|l| l.contains("netmap home")));
    assert!(!fw.contents.contains("personal/wireguard: https proxy"));
    assert!(fw
        .contents
        .contains("iifname \"wg0\" ip saddr 10.8.2.0/24 ip daddr 10.8.0.1 tcp dport 8443 accept"));
}

#[test]
fn no_proxy_redirect_where_a_grant_reaches_the_host_directly() {
    let mut cfg = canonical_config();
    cfg.services[0].hostnames = vec!["immich.mydomain.com".into()];
    cfg.templates[1].grants.push(Grant::HostPort {
        ip: "192.168.1.5".parse().unwrap(),
        proto: parallax_core::model::Proto::Tcp,
        port: 443,
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
    // No blanket "established" accept: a removed grant cuts open flows.
    assert!(!fw.contents.contains("established"), "{}", fw.contents);
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
    // A packet sees its own template's rules only: one lookup by source
    // address picks the chain, however many templates come before it.
    assert!(fw.contents.contains(
        "iifname \"wg0\" ip saddr vmap { 10.8.1.0/24 : jump tier_personal, 10.8.2.0/24 : jump tier_family }"
    ));
    assert!(fw
        .contents
        .contains("iifname \"tailscale0\" ip saddr @ts_family jump tier_family"));
    let family: Vec<&str> = fw
        .contents
        .lines()
        .skip_while(|l| !l.contains("chain tier_family {"))
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
            .any(|l| l.contains("ip saddr 10.8.1.0/24 ip daddr 192.168.1.5 accept")),
        "{input:#?}"
    );
    assert!(
        input
            .iter()
            .any(|l| l.contains("ip saddr 10.8.2.0/24 ip daddr 192.168.1.5 tcp dport 443 accept")),
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
    let family = model.template("family").unwrap();
    let ips = generate::client::allowed_ips(&model, family, Platform::Mobile);
    assert_eq!(
        ips,
        vec![
            "198.18.1.5/32".parse().unwrap(),
            "10.8.0.1/32".parse().unwrap()
        ]
    );
    let personal = model.template("personal").unwrap();
    let ips = generate::client::allowed_ips(&model, personal, Platform::Linux);
    assert_eq!(
        ips,
        vec![
            "198.18.1.0/24".parse().unwrap(),
            "10.8.0.1/32".parse().unwrap()
        ]
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
    cfg.templates[1].grants.push(Grant::Internet);
    let model = Model::resolve(&cfg, today()).unwrap();
    let fs = fs_with_server_key();
    let bundle = generate::generate_all(&model, &fs).unwrap();
    let runner = RecordingRunner::new();
    // A template was removed since the last apply: its chain is still there.
    runner.respond_to(
        "iptables",
        &["-t", "filter", "-S"],
        parallax_core::io::Output {
            status: 0,
            stdout: "-P INPUT ACCEPT\n-N PARALLAX_FORWARD\n-N PARALLAX_T0\n-N PARALLAX_T1\n-N PARALLAX_T2\n".into(),
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
    // Only the stale template chain goes.
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
    let t = &mut busy.templates[0];
    t.grants = vec![
        Grant::Network {
            name: "home".into(),
        },
        Grant::HostPort {
            ip: std::net::Ipv4Addr::new(192, 168, 1, 10),
            proto: parallax_core::model::Proto::Udp,
            port: 53,
        },
        Grant::Internet,
    ];
    t.visible_networks = Some(vec!["home".into()]);
    t.headscale.tag = Some("tag:personal-devices-with-a-long-name".into());
    t.headscale.user = Some("someone-with-a-long-user-name-for-the-headscale-identity".into());
    let text = busy.to_toml().unwrap();
    assert_eq!(Config::from_toml(&text).unwrap(), busy);
    check_golden("config/busy.toml", &text);

    // A fresh install has no peers: the section is left out, not `peer = []`.
    let mut empty = canonical_config();
    empty.peers.clear();
    let text = empty.to_toml().unwrap();
    assert!(!text.contains("peer"), "{text}");
    assert_eq!(Config::from_toml(&text).unwrap(), empty);
}

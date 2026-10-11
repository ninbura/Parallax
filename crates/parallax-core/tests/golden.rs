//! Golden-file tests: every generator's output for the canonical scenario is
//! frozen under `tests/golden/`. Run with `UPDATE_GOLDEN=1` to refresh after
//! an intentional change, then review the diff.

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
    cfg.networks[0].masquerade = true;
    let bundle = bundle_for(&cfg);
    let fw = bundle.of_kind(ArtifactKind::Firewall).next().unwrap();
    check_golden("variants/internet-masquerade.nft", &fw.contents);
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

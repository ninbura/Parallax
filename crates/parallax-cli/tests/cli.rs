//! End-to-end tests of the harness against a scratch copy of the example.

use std::path::{Path, PathBuf};
use std::process::Command;

struct Scratch {
    dir: PathBuf,
}

impl Scratch {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("parallax-cli-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let example = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../example/parallax.toml");
        let text = std::fs::read_to_string(example).unwrap().replace(
            "/etc/parallax/wg-server.key",
            &dir.join("wg-server.key").to_string_lossy(),
        );
        std::fs::write(dir.join("parallax.toml"), text).unwrap();
        Scratch { dir }
    }
    fn config(&self) -> PathBuf {
        self.dir.join("parallax.toml")
    }
    fn run(&self, args: &[&str]) -> (bool, String, String) {
        let out = Command::new(env!("CARGO_BIN_EXE_parallax"))
            .arg("-c")
            .arg(self.config())
            .args(args)
            .output()
            .unwrap();
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn validate_accepts_the_example() {
    let s = Scratch::new("validate");
    let (ok, out, err) = s.run(&["validate"]);
    assert!(ok, "{err}");
    assert!(
        out.contains("valid (1 networks, 2 templates, 3 peers, 3 active)"),
        "{out}"
    );
}

#[test]
fn keygen_then_generate_and_plan() {
    let s = Scratch::new("keygen");
    let (ok, _, err) = s.run(&["generate", "-o", &s.dir.join("out").to_string_lossy()]);
    assert!(!ok);
    assert!(err.contains("parallax keygen"), "{err}");

    let (ok, out, err) = s.run(&["keygen", "--write-config"]);
    assert!(ok, "{err}");
    assert!(out.contains("public key:"), "{out}");
    let (ok, _, err) = s.run(&["keygen"]);
    assert!(!ok, "second keygen must refuse to overwrite: {err}");

    let out_dir = s.dir.join("out");
    let (ok, out, err) = s.run(&["plan", "-o", &out_dir.to_string_lossy()]);
    assert!(ok, "{err}");
    assert!(out.contains("+ create"), "{out}");
    let (ok, _, err) = s.run(&["generate", "-o", &out_dir.to_string_lossy()]);
    assert!(ok, "{err}");
    assert!(out_dir.join("nftables/parallax.nft").exists());
    assert!(out_dir.join("clients/sister-phone/mobile.conf").exists());
    assert!(
        !out_dir.join("clients/router").exists(),
        "router retains no private key"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(out_dir.join("wireguard/wg0.conf"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    let (ok, out, err) = s.run(&["plan", "-o", &out_dir.to_string_lossy()]);
    assert!(ok, "{err}");
    assert!(out.contains("No changes."), "{out}");
}

#[test]
fn peer_lifecycle_preserves_comments() {
    let s = Scratch::new("peer");
    s.run(&["keygen", "--write-config"]);
    let (ok, out, err) = s.run(&[
        "peer",
        "add",
        "tablet",
        "--template",
        "family",
        "--platform",
        "mobile",
        "--preshared-key",
    ]);
    assert!(ok, "{err}");
    assert!(out.contains("Address = 10.8.2.2/32"), "{out}");
    assert!(
        out.contains("AllowedIPs = 198.18.1.5/32, 10.8.0.1/32"),
        "{out}"
    );
    assert!(out.contains("PresharedKey = "), "{out}");
    assert!(
        !out.contains("<paste"),
        "one-time export must include the private key: {out}"
    );
    assert!(err.contains("shown once"), "{err}");

    let text = std::fs::read_to_string(s.config()).unwrap();
    assert!(
        text.contains("# Parallax configuration: the canonical scenario."),
        "comments must survive"
    );
    assert!(text.contains("name = \"tablet\""));
    assert_eq!(
        text.matches("private_key = \"").count(),
        2,
        "tablet's private key must not be stored:\n{text}"
    );

    let (ok, out, err) = s.run(&["export", "tablet", "--platform", "mobile"]);
    assert!(ok, "{err}");
    assert!(out.contains("<paste the private key"), "{out}");
    assert!(err.contains("does not retain its private key"), "{err}");

    let (ok, out, _) = s.run(&["peer", "show", "tablet"]);
    assert!(ok);
    assert!(
        out.contains("reaches service immich as 198.18.1.5/32"),
        "{out}"
    );

    let (ok, _, err) = s.run(&["peer", "add", "tablet", "--template", "family"]);
    assert!(!ok);
    assert!(err.contains("already exists"), "{err}");

    let (ok, _, err) = s.run(&["peer", "remove", "tablet"]);
    assert!(ok, "{err}");
    let (ok, _, err) = s.run(&["peer", "remove", "tablet"]);
    assert!(!ok, "{err}");
    let (ok, out, _) = s.run(&["validate"]);
    assert!(ok);
    assert!(out.contains("3 peers"), "{out}");
}

#[test]
fn allocate_fills_missing_addresses() {
    let s = Scratch::new("alloc");
    let mut text = std::fs::read_to_string(s.config()).unwrap();
    text.push_str("\n[[peer]]\nname = \"nas\"\ntemplate = \"personal\"\ntransport = \"wireguard\"\nwireguard = { public_key = \"DSuieBHAaq5V19ySBwUTiLBh9Pnduq1K9gcWaxXqMVc=\" }\n");
    std::fs::write(s.config(), text).unwrap();
    let (ok, _, err) = s.run(&["validate"]);
    assert!(!ok);
    assert!(err.contains("peer 'nas': has no address yet"), "{err}");
    let (ok, out, err) = s.run(&["peer", "allocate"]);
    assert!(ok, "{err}");
    assert!(out.contains("nas: 10.8.1.3"), "{out}");
    let (ok, _, err) = s.run(&["validate"]);
    assert!(ok, "{err}");
}

#[test]
fn validation_errors_are_specific() {
    let s = Scratch::new("invalid");
    let text = std::fs::read_to_string(s.config())
        .unwrap()
        .replace(
            "mapped_to = \"198.18.1.0/24\"",
            "mapped_to = \"198.18.1.0/25\"",
        )
        .replace(
            "{ kind = \"service\", name = \"immich\" }",
            "{ kind = \"service\", name = \"plex\" }",
        );
    std::fs::write(s.config(), text).unwrap();
    let (ok, _, err) = s.run(&["validate"]);
    assert!(!ok);
    assert!(err.contains("same prefix length"), "{err}");
    assert!(err.contains("unknown service 'plex'"), "{err}");
}

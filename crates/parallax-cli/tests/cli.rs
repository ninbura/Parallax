//! End-to-end tests of the harness against a scratch database holding the example.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test helpers: failures should panic loudly"
)]

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
    /// The TOML file tests edit before importing it.
    fn config(&self) -> PathBuf {
        self.dir.join("parallax.toml")
    }
    fn db(&self) -> PathBuf {
        self.dir.join("parallax.db")
    }
    /// Import the TOML file into the database, which must succeed.
    fn import(&self) {
        let (ok, _, err) = self.run(&["config", "import", &self.config().to_string_lossy()]);
        assert!(ok, "{err}");
    }
    fn run(&self, args: &[&str]) -> (bool, String, String) {
        self.run_with_env(args, &[])
    }
    fn run_with_env(&self, args: &[&str], env: &[(&str, &str)]) -> (bool, String, String) {
        let out = Command::new(env!("CARGO_BIN_EXE_parallax"))
            .arg("--db")
            .arg(self.db())
            .args(args)
            .envs(env.iter().copied())
            .env_remove("VISUAL")
            .stdin(std::process::Stdio::null())
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
    s.import();
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
    s.import();
    let (ok, _, err) = s.run(&["generate", "-o", &s.dir.join("out").to_string_lossy()]);
    assert!(!ok);
    assert!(err.contains("parallax keygen"), "{err}");

    let (ok, out, err) = s.run(&["keygen", "--write-config"]);
    assert!(ok, "{err}");
    assert!(out.contains("public key:"), "{out}");
    let (ok, _, err) = s.run(&["keygen"]);
    assert!(!ok, "second keygen must refuse to overwrite: {err}");
    let (ok, out, err) = s.run(&["keygen", "--if-missing", "--write-config"]);
    assert!(ok && out.is_empty(), "{out}{err}");

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
fn peer_lifecycle_stores_no_private_key() {
    let s = Scratch::new("peer");
    s.import();
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

    let (ok, text, err) = s.run(&["config", "export"]);
    assert!(ok, "{err}");
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
    let (ok, _, err) = s.run(&["config", "import", &s.config().to_string_lossy()]);
    assert!(ok, "{err}");
    assert!(err.contains("allocated 10.8.1.3 to peer 'nas'"), "{err}");
    let (ok, out, err) = s.run(&["peer", "show", "nas"]);
    assert!(ok, "{err}");
    assert!(out.contains("address=10.8.1.3"), "{out}");
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
    let (ok, _, err) = s.run(&["config", "import", &s.config().to_string_lossy()]);
    assert!(!ok);
    assert!(err.contains("same prefix length"), "{err}");
    assert!(err.contains("unknown service 'plex'"), "{err}");
    let (ok, _, err) = s.run(&["validate"]);
    assert!(!ok, "a refused import must not create the database");
    assert!(err.contains("no database at"), "{err}");
}

#[test]
fn peer_show_marks_proxied_services() {
    let s = Scratch::new("proxied");
    let text = std::fs::read_to_string(s.config()).unwrap().replace(
        "nginx_vhost = true\n",
        "nginx_vhost = true\nhostnames = [\"immich.mydomain.com\"]\n",
    );
    std::fs::write(s.config(), text).unwrap();
    s.import();
    let (ok, out, err) = s.run(&["peer", "show", "sister-phone"]);
    assert!(ok, "{err}");
    assert!(
        out.contains("reaches service immich as 198.18.1.5/32 through the HTTPS proxy"),
        "{out}"
    );
}

#[test]
fn plan_needs_a_certificate_for_every_proxied_hostname() {
    let s = Scratch::new("certs");
    let certs = s.dir.join("certs");
    std::fs::create_dir_all(&certs).unwrap();
    let text = std::fs::read_to_string(s.config())
        .unwrap()
        .replace(
            "nginx_vhost = true\n",
            "nginx_vhost = true\nhostnames = [\"immich.mydomain.com\"]\n",
        )
        .replace(
            "certificates = \"/etc/parallax/certs\"",
            &format!("certificates = {:?}", certs),
        );
    std::fs::write(s.config(), text).unwrap();
    s.import();
    let (ok, _, err) = s.run(&["keygen", "--write-config"]);
    assert!(ok, "{err}");
    let out = s.dir.join("out").to_string_lossy().into_owned();

    let (ok, _, err) = s.run(&["plan", "-o", &out]);
    assert!(!ok);
    assert!(err.contains("covers immich.mydomain.com"), "{err}");

    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["*.mydomain.com".to_string()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let live = certs.join("live/mydomain.com");
    std::fs::create_dir_all(&live).unwrap();
    std::fs::write(live.join("fullchain.pem"), cert.pem()).unwrap();
    std::fs::write(live.join("privkey.pem"), key.serialize_pem()).unwrap();
    let (ok, out, err) = s.run(&["plan", "-o", &out]);
    assert!(ok, "{err}");
    assert!(out.contains("proxy/routes.toml"), "{out}");
}

#[test]
fn export_reproduces_the_imported_configuration() {
    let s = Scratch::new("export");
    s.import();
    let (ok, first, err) = s.run(&["config", "export"]);
    assert!(ok, "{err}");
    let file = s.dir.join("exported.toml");
    let (ok, _, err) = s.run(&["config", "export", "-o", &file.to_string_lossy()]);
    assert!(ok, "{err}");
    assert_eq!(std::fs::read_to_string(&file).unwrap(), first);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&file).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    // Importing the export changes nothing.
    let (ok, _, err) = s.run(&["config", "import", &file.to_string_lossy()]);
    assert!(ok, "{err}");
    let (_, second, _) = s.run(&["config", "export"]);
    assert_eq!(first, second);
}

#[test]
fn config_edit_saves_what_the_editor_changed() {
    let s = Scratch::new("edit");
    s.import();
    s.run(&["keygen", "--write-config"]);
    let out = s.dir.join("out").to_string_lossy().into_owned();

    let (ok, stdout, err) = s.run_with_env(&["config", "edit", "-o", &out], &[("EDITOR", "true")]);
    assert!(ok, "{err}");
    assert!(stdout.contains("no changes"), "{stdout}");

    // Without a terminal, only --yes saves.
    let sed = [("EDITOR", "sed -i s/eth0/eth9/")];
    let (ok, _, err) = s.run_with_env(&["config", "edit", "-o", &out], &sed);
    assert!(!ok);
    assert!(err.contains("--yes"), "{err}");
    let (_, text, _) = s.run(&["config", "export"]);
    assert!(text.contains("\"eth0\""), "nothing may be saved: {text}");

    let (ok, stdout, err) = s.run_with_env(&["config", "edit", "-o", &out, "--yes"], &sed);
    assert!(ok, "{err}");
    assert!(stdout.contains("+interface = \"eth9\""), "{stdout}");
    assert!(
        stdout.contains("+ create"),
        "the generated files are previewed: {stdout}"
    );
    let (_, text, _) = s.run(&["config", "export"]);
    assert!(text.contains("\"eth9\""), "{text}");

    // An edit that breaks the configuration is refused.
    let bad = [("EDITOR", "sed -i s/10.8.1.0/10.9.1.0/")];
    let (ok, _, err) = s.run_with_env(&["config", "edit", "-o", &out, "--yes"], &bad);
    assert!(!ok);
    assert!(err.contains("invalid"), "{err}");
    let (_, after, _) = s.run(&["config", "export"]);
    assert_eq!(after, text);
}

#[test]
fn config_diffs_never_show_keys() {
    let s = Scratch::new("redact");
    s.import();
    let out = s.dir.join("out").to_string_lossy().into_owned();
    let (ok, stdout, err) = s.run_with_env(
        &["config", "edit", "-o", &out, "--yes"],
        &[("EDITOR", "sed -i /^private_key/d")],
    );
    assert!(ok, "{err}");
    assert!(stdout.contains("-private_key = (redacted)"), "{stdout}");
    assert!(!stdout.contains("private_key = \""), "{stdout}");
}

#[test]
fn concurrent_peer_adds_all_land_with_distinct_addresses() {
    let s = Scratch::new("concurrent");
    s.import();
    let children: Vec<_> = (0..8)
        .map(|i| {
            Command::new(env!("CARGO_BIN_EXE_parallax"))
                .arg("--db")
                .arg(s.db())
                .args(["peer", "add", &format!("dev{i}"), "--template", "family"])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap()
        })
        .collect();
    for child in children {
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let (ok, out, err) = s.run(&["peer", "show"]);
    assert!(ok, "{err}");
    let mut addresses: Vec<&str> = out
        .lines()
        .filter(|l| l.starts_with("dev"))
        .filter_map(|l| l.split("address=").nth(1))
        .filter_map(|a| a.split_whitespace().next())
        .collect();
    assert_eq!(addresses.len(), 8, "{out}");
    addresses.sort_unstable();
    addresses.dedup();
    assert_eq!(addresses.len(), 8, "two peers got one address: {out}");
}

#[test]
fn import_if_empty_never_overwrites() {
    let s = Scratch::new("ifempty");
    let file = s.config().to_string_lossy().into_owned();
    let (ok, out, err) = s.run(&["config", "import", "--if-empty", &file]);
    assert!(ok, "{err}");
    assert!(out.starts_with("imported"), "{out}");
    s.run(&["peer", "remove", "router"]);

    // A broken file is not even read once the database holds a configuration.
    std::fs::write(s.config(), "not toml [").unwrap();
    let (ok, out, err) = s.run(&["config", "import", "--if-empty", &file]);
    assert!(ok, "{err}");
    assert!(out.is_empty(), "{out}");
    assert!(err.contains("already holds a configuration"), "{err}");
    let (_, out, _) = s.run(&["validate"]);
    assert!(out.contains("2 peers"), "{out}");
}

#[test]
fn keygen_finishes_recording_a_key_it_already_wrote() {
    let s = Scratch::new("keyresume");
    s.import();
    // As if an earlier run wrote the key and stopped before recording it.
    let (ok, out, err) = s.run(&["keygen"]);
    assert!(ok, "{err}");
    let public = out
        .lines()
        .find_map(|l| l.strip_prefix("public key: "))
        .unwrap()
        .to_string();
    let (ok, out, err) = s.run(&["keygen", "--if-missing", "--write-config"]);
    assert!(ok, "{err}");
    assert!(out.contains("recorded the public key"), "{out}");
    let (_, text, _) = s.run(&["config", "export"]);
    assert!(
        text.contains(&format!("public_key = \"{public}\"")),
        "{text}"
    );
    let (ok, out, _) = s.run(&["keygen", "--if-missing", "--write-config"]);
    assert!(ok && out.is_empty(), "{out}");
}

#[cfg(unix)]
#[test]
fn every_database_file_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let s = Scratch::new("modes");
    s.import();
    s.run(&["peer", "add", "tablet", "--template", "family"]);
    let mut seen = 0;
    for entry in std::fs::read_dir(&s.dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if name.starts_with("parallax.db") {
            seen += 1;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "{name}");
        }
    }
    assert!(seen >= 2, "expected the database and its log");
}

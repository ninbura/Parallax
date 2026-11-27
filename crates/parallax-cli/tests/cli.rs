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
        let mut text = std::fs::read_to_string(example).unwrap();
        for (from, to) in [
            ("/etc/parallax/wg-server.key", "wg-server.key"),
            ("/var/lib/parallax/backups", "backups"),
            ("/etc/parallax/backup.passphrase", "backup.passphrase"),
        ] {
            text = text.replace(from, &dir.join(to).to_string_lossy());
        }
        std::fs::write(dir.join("parallax.toml"), text).unwrap();
        Scratch { dir }
    }
    /// The backups written so far, oldest first.
    fn backups(&self) -> Vec<PathBuf> {
        let mut found: Vec<PathBuf> = std::fs::read_dir(self.dir.join("backups"))
            .map(|d| {
                d.map(|e| e.unwrap().path())
                    .filter(|p| p.extension().is_some_and(|e| e == "tar"))
                    .collect()
            })
            .unwrap_or_default();
        found.sort();
        found
    }
    /// Import, create the server key and set a generated backup passphrase.
    fn gateway(&self) {
        self.import();
        let (ok, _, err) = self.run(&["keygen", "--write-config"]);
        assert!(ok, "{err}");
        let (ok, out, err) = self.run(&["backup", "passphrase", "--generate"]);
        assert!(ok, "{err}");
        assert_eq!(out.trim().len(), 29, "{out}");
        assert!(err.contains("password manager"), "{err}");
    }
    /// The TOML file tests edit before importing it.
    fn config(&self) -> PathBuf {
        self.dir.join("parallax.toml")
    }
    fn db(&self) -> PathBuf {
        self.dir.join("parallax.db")
    }
    /// Where a daemon would listen; nothing does unless a test says so.
    fn socket(&self) -> PathBuf {
        self.dir.join("parallax.sock")
    }
    /// Import the TOML file into the database, which must succeed.
    fn import(&self) {
        let (ok, _, err) = self.run(&["config", "import", &self.config().to_string_lossy()]);
        assert!(ok, "{err}");
    }
    fn run(&self, args: &[&str]) -> (bool, String, String) {
        self.run_with_env(args, &[])
    }
    /// The command `run` runs, for tests that set up its streams themselves.
    fn command(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_parallax"));
        cmd.arg("--db")
            .arg(self.db())
            .arg("--socket")
            .arg(self.socket())
            .args(args)
            .env_remove("VISUAL")
            .stdin(std::process::Stdio::null());
        cmd
    }
    fn run_with_env(&self, args: &[&str], env: &[(&str, &str)]) -> (bool, String, String) {
        let out = self
            .command(args)
            .envs(env.iter().copied())
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
        out.contains("valid (1 networks, 2 grants, 3 peers, 3 active)"),
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
        "--grant",
        "family",
        "--allowed-ips",
        "grants_only",
        "--platform",
        "mobile",
        "--preshared-key",
    ]);
    assert!(ok, "{err}");
    // The lowest free address of the supernet.
    assert!(out.contains("Address = 10.8.0.2/32"), "{out}");
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
        out.contains("reaches service immich (443/tcp) as 198.18.1.5/32"),
        "{out}"
    );

    let (ok, _, err) = s.run(&["peer", "add", "tablet", "--grant", "family"]);
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
    text.push_str("\n[[peer]]\nname = \"nas\"\ngrants = [\"personal\"]\ntransport = \"wireguard\"\nwireguard = { public_key = \"DSuieBHAaq5V19ySBwUTiLBh9Pnduq1K9gcWaxXqMVc=\" }\n");
    std::fs::write(s.config(), text).unwrap();
    let (ok, _, err) = s.run(&["config", "import", &s.config().to_string_lossy()]);
    assert!(ok, "{err}");
    // The lowest free address of the supernet: access isn't in addresses.
    assert!(err.contains("allocated 10.8.0.2 to peer 'nas'"), "{err}");
    let (ok, out, err) = s.run(&["peer", "show", "nas"]);
    assert!(ok, "{err}");
    assert!(out.contains("address=10.8.0.2"), "{out}");
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
        out.contains("reaches service immich (443/tcp) as 198.18.1.5/32 through the HTTPS proxy"),
        "{out}"
    );
}

#[test]
fn log_levels_are_set_for_everyone_a_grant_or_a_peer() {
    let s = Scratch::new("log-level");
    s.import();
    let ok = |args: &[&str]| {
        let (ok, out, err) = s.run(args);
        assert!(ok, "{args:?}: {err}");
        out
    };
    let refused = |args: &[&str]| {
        let (ok, _, err) = s.run(args);
        assert!(!ok, "{args:?} should fail");
        err
    };
    let out = ok(&["log", "level", "blocked", "--grant", "family"]);
    assert!(
        out.contains("grant 'family' logs blocked for its peers now"),
        "{out}"
    );
    let out = ok(&["log", "level", "detailed", "--peer", "sister-phone"]);
    assert!(
        out.contains("peer 'sister-phone' logs detailed now"),
        "{out}"
    );
    assert!(
        !out.contains("in effect"),
        "its own level is what's in effect: {out}"
    );
    // Back to its grant's level.
    let out = ok(&["log", "level", "inherit", "--peer", "sister-phone"]);
    assert!(out.contains("in effect: blocked"), "{out}");
    let out = ok(&["log", "level", "connections"]);
    assert!(
        out.contains("everyone logs connections by default now"),
        "{out}"
    );
    let text = ok(&["config", "export"]);
    assert!(text.contains("level = \"connections\""), "{text}");
    assert!(text.contains("log = \"blocked\""), "{text}");

    let err = refused(&["log", "level", "inherit"]);
    assert!(err.contains("nothing to inherit"), "{err}");
    let err = refused(&["log", "level", "detailed", "--peer", "nobody"]);
    assert!(err.contains("peer 'nobody' not found"), "{err}");
    let err = refused(&["log", "level", "verbose"]);
    assert!(err.contains("verbose"), "{err}");
}

#[test]
fn grants_are_managed_from_either_side() {
    let s = Scratch::new("grants");
    s.import();
    let ok = |args: &[&str]| {
        let (ok, out, err) = s.run(args);
        assert!(ok, "{args:?}: {err}");
        out
    };
    let refused = |args: &[&str]| {
        let (ok, _, err) = s.run(args);
        assert!(!ok, "{args:?} should fail");
        err
    };
    let address = || ok(&["peer", "show", "laptop"]).contains("address=10.8.1.2 ");

    ok(&["grant", "create", "photos", "service:immich"]);
    let out = ok(&["grant", "attach", "photos", "--to", "laptop,sister-phone"]);
    assert!(out.contains("attached 'photos' to 'laptop'"), "{out}");
    assert!(out.contains("attached 'photos' to 'sister-phone'"), "{out}");
    let out = ok(&["grant", "show", "photos"]);
    assert!(
        out.starts_with(
            "photos  everyone=false  peers=laptop,sister-phone\n    rule service:immich\n"
        ),
        "{out}"
    );
    assert!(address());

    // A rule that isn't there, or a peer that doesn't exist, changes nothing.
    let err = refused(&[
        "grant",
        "rule",
        "remove",
        "photos",
        "service:immich",
        "host:192.168.1.9:445/tcp",
    ]);
    assert!(
        err.contains("has no rule host:192.168.1.9:445/tcp; nothing removed"),
        "{err}"
    );
    let err = refused(&["grant", "attach", "photos", "--to", "router,mom"]);
    assert!(err.contains("peer 'mom' not found"), "{err}");
    assert!(!ok(&["grant", "show", "photos"]).contains("router"));
    let err = refused(&["grant", "rule", "add", "photos", "services:immich"]);
    assert!(err.contains("'services' is not one of"), "{err}");

    // From the peer's side.
    let out = ok(&["peer", "grants", "laptop", "remove", "personal"]);
    assert!(out.contains("'laptop' now has 'photos'"), "{out}");
    let err = refused(&["peer", "grants", "laptop", "add", "familly"]);
    assert!(err.contains("grant 'familly' not found"), "{err}");
    ok(&["peer", "grants", "laptop", "set", "personal,family"]);
    assert!(ok(&["peer", "show", "laptop"]).contains("grants=personal,family "));

    // For everyone: says what it opens, and can't be detached from one peer.
    ok(&["grant", "create", "public", "public_dns"]);
    ok(&["grant", "everyone", "public", "on"]);
    let (_, _, err) = s.run(&["grant", "rule", "add", "public", "network:home"]);
    assert!(
        err.contains("applies to everyone and opens network 'home'"),
        "{err}"
    );
    assert!(
        ok(&["grant", "show", "public"]).contains("peers=everyone (router,laptop,sister-phone)")
    );
    let err = refused(&["grant", "detach", "public", "--from", "router"]);
    assert!(err.contains("because it applies to everyone"), "{err}");

    // Removing a grant someone has takes --force; renaming follows it.
    ok(&["grant", "rename", "photos", "pics"]);
    assert!(ok(&["peer", "show", "sister-phone"]).contains("grants=family,pics,public "));
    let err = refused(&["grant", "remove", "pics"]);
    assert!(
        err.contains("held by 'sister-phone'; removing it takes it from them"),
        "{err}"
    );
    let out = ok(&["grant", "remove", "pics", "--force"]);
    assert!(out.contains("taken from 'sister-phone'"), "{out}");
    assert!(address());
    let (ok_, _, err) = s.run(&["validate"]);
    assert!(ok_, "{err}");
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
    let bad = [("EDITOR", "sed -i s/10.8.1.1/10.9.1.1/")];
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

/// Without a daemon each command holds the database while it runs; another
/// process gets an error naming the socket that should have answered.
#[test]
fn a_held_database_names_the_daemon_socket() {
    let s = Scratch::new("held");
    s.import();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    let store = runtime
        .block_on(parallax_store::Store::open(&s.db()))
        .unwrap();
    let (ok, _, err) = s.run(&["peer", "show"]);
    assert!(!ok);
    assert!(err.contains("locked by another process"), "{err}");
    assert!(
        err.contains(&s.socket().display().to_string()),
        "the socket is named: {err}"
    );
    drop(store);
    let (ok, _, err) = s.run(&["peer", "show"]);
    assert!(ok, "{err}");
}

#[test]
fn status_says_when_no_daemon_runs() {
    let s = Scratch::new("status");
    let (ok, _, err) = s.run(&["status"]);
    assert!(!ok);
    assert!(err.contains("no daemon is running"), "{err}");
}

/// A stand-in daemon: answers `load` with the example and `save` with an
/// apply log, recording each request.
fn fake_daemon(
    socket: &Path,
    config: serde_json::Value,
    connections: usize,
) -> std::thread::JoinHandle<Vec<serde_json::Value>> {
    use std::io::{BufRead, BufReader, Write};
    let listener = std::os::unix::net::UnixListener::bind(socket).unwrap();
    std::thread::spawn(move || {
        let mut seen = Vec::new();
        for _ in 0..connections {
            let (stream, _) = listener.accept().unwrap();
            let mut line = String::new();
            BufReader::new(&stream).read_line(&mut line).unwrap();
            let request: serde_json::Value = serde_json::from_str(&line).unwrap();
            let reply = match request["request"].as_str().unwrap() {
                "load" => serde_json::json!({
                    "protocol": 5, "reply": "configuration", "public_ip": null, "names": {},
                    "configuration": config, "revision": 3,
                }),
                "save" => serde_json::json!({
                    "protocol": 5, "reply": "applied", "revision": 4,
                    "log": ["applied by the fake daemon"], "error": null,
                }),
                other => panic!("unexpected request {other}"),
            };
            (&stream)
                .write_all(format!("{reply}\n").as_bytes())
                .unwrap();
            seen.push(request);
        }
        seen
    })
}

/// With a daemon answering, commands go through it and never open the
/// database (there is none here).
#[test]
fn commands_go_through_a_running_daemon() {
    let s = Scratch::new("daemon");
    let text = std::fs::read_to_string(s.config()).unwrap();
    let config: parallax_core::Config = parallax_core::Config::from_toml(&text).unwrap();
    let json = serde_json::to_value(&config).unwrap();
    let daemon = fake_daemon(&s.socket(), json, 3);

    let (ok, out, err) = s.run(&["validate"]);
    assert!(ok, "{err}");
    assert!(out.contains("valid"), "{out}");
    let (ok, out, err) = s.run(&["peer", "remove", "router"]);
    assert!(ok, "{err}");
    assert!(out.contains("removed peer 'router'"), "{out}");
    assert!(err.contains("applied by the fake daemon"), "{err}");
    assert!(!err.contains("parallax apply"), "no apply hint: {err}");
    assert!(!s.db().exists(), "the database was never opened");

    let seen = daemon.join().unwrap();
    let kinds: Vec<&str> = seen
        .iter()
        .map(|r| r["request"].as_str().unwrap())
        .collect();
    assert_eq!(kinds, ["load", "load", "save"]);
    assert_eq!(seen[2]["revision"], 3, "saved against the loaded revision");
    let peers = seen[2]["configuration"]["peer"].as_array().unwrap();
    assert!(peers.iter().all(|p| p["name"] != "router"), "{peers:?}");
    assert!(seen.iter().all(|r| r["protocol"] == 5));
}

/// A stale socket file (its daemon is gone) means no daemon.
#[test]
fn a_stale_socket_falls_back_to_the_database() {
    let s = Scratch::new("stale");
    s.import();
    drop(std::os::unix::net::UnixListener::bind(s.socket()).unwrap());
    assert!(s.socket().exists());
    let (ok, out, err) = s.run(&["validate"]);
    assert!(ok, "{err}");
    assert!(out.contains("valid"), "{out}");
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
    s.run(&["peer", "add", "tablet", "--grant", "family"]);
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

#[test]
fn a_backup_restores_what_changed_since() {
    let s = Scratch::new("backup");
    s.gateway();
    let (ok, out, err) = s.run(&["backup", "create"]);
    assert!(ok, "{err}");
    assert!(out.contains("(encrypted)"), "{out}");
    let file = s.backups().pop().unwrap();
    let (ok, out, _) = s.run(&["backup", "list"]);
    assert!(
        ok && out.contains("encrypted") && out.contains("schema 7"),
        "{out}"
    );

    let key = std::fs::read_to_string(s.dir.join("wg-server.key")).unwrap();
    s.run(&["peer", "remove", "laptop"]);
    std::fs::write(
        s.dir.join("wg-server.key"),
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n",
    )
    .unwrap();

    // Without a terminal, only --yes can say yes.
    let (ok, _, err) = s.run(&["backup", "restore", &file.to_string_lossy()]);
    assert!(!ok && err.contains("needs a terminal"), "{err}");

    let out_dir = s.dir.join("out");
    let (ok, out, err) = s.run(&[
        "backup",
        "restore",
        &file.to_string_lossy(),
        "--yes",
        "-o",
        &out_dir.to_string_lossy(),
    ]);
    assert!(ok, "{err}");
    assert!(out.contains("+name = \"laptop\""), "{out}");
    assert!(out.contains("is replaced with the backup's"), "{out}");
    assert!(out.contains("generated files after"), "{out}");
    assert!(out.contains("saved the current state first"), "{out}");
    assert!(out.contains("run `parallax apply`"), "{out}");
    assert!(!out.contains(key.trim()), "the key must never be printed");
    let (_, out, _) = s.run(&["validate"]);
    assert!(out.contains("3 peers"), "{out}");
    assert_eq!(
        std::fs::read_to_string(s.dir.join("wg-server.key")).unwrap(),
        key
    );
    // The original and the state saved before restoring.
    assert_eq!(s.backups().len(), 2);
}

#[test]
fn a_backup_restores_onto_a_fresh_install() {
    let s = Scratch::new("backup-fresh");
    s.gateway();
    s.run(&["backup", "create"]);
    let file = s.backups().pop().unwrap();
    let passphrase = s.dir.join("backup.passphrase");
    let typed = s.dir.join("typed");
    std::fs::rename(&passphrase, &typed).unwrap();
    std::fs::remove_file(s.dir.join("wg-server.key")).unwrap();

    let fresh = s.dir.join("fresh/parallax.db");
    let restore = |pass: &Path| {
        Command::new(env!("CARGO_BIN_EXE_parallax"))
            .arg("--db")
            .arg(&fresh)
            .args(["backup", "restore", "--yes", "-o"])
            .arg(s.dir.join("out"))
            .arg("--passphrase-file")
            .arg(pass)
            .arg(&file)
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap()
    };
    std::fs::write(s.dir.join("wrong"), "not it\n").unwrap();
    let out = restore(&s.dir.join("wrong"));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success() && err.contains("passphrase is wrong"),
        "{err}"
    );

    let out = restore(&typed);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(text.contains("holds no configuration yet"), "{text}");
    assert!(text.contains("saved the backup passphrase"), "{text}");
    assert_eq!(
        std::fs::read_to_string(&passphrase).unwrap(),
        std::fs::read_to_string(&typed).unwrap()
    );
    assert!(s.dir.join("wg-server.key").exists());
}

#[test]
fn automatic_backups_skip_when_not_due_or_unchanged() {
    let s = Scratch::new("backup-due");
    s.gateway();
    let (ok, out, err) = s.run(&["backup", "create", "--if-due"]);
    assert!(ok && out.contains("wrote"), "{out}{err}");
    // Not due: the newest is younger than the interval.
    let (ok, out, err) = s.run(&["backup", "create", "--if-due"]);
    assert!(ok && out.is_empty(), "{out}{err}");

    // Due, but nothing changed: nothing written, and the next look is a
    // whole interval later.
    let file = s.backups().pop().unwrap();
    let old = file.with_file_name("parallax-backup-20200101T000000Z.tar");
    std::fs::rename(&file, &old).unwrap();
    let (ok, out, err) = s.run(&["backup", "create", "--if-due"]);
    assert!(ok && out.is_empty(), "{out}{err}");
    assert_eq!(s.backups(), std::slice::from_ref(&old));
    let last_check = s.dir.join("backups/.last-check");
    assert!(last_check.exists());

    // A change within the interval waits for the next look.
    s.run(&["peer", "remove", "laptop"]);
    let (ok, out, err) = s.run(&["backup", "create", "--if-due"]);
    assert!(ok && out.is_empty(), "{out}{err}");

    // A day later (2020 here) it's due again, and the change is backed up.
    std::fs::write(&last_check, "1577836800\n").unwrap();
    let (ok, out, err) = s.run(&["backup", "create", "--if-due"]);
    assert!(ok && out.contains("wrote"), "{out}{err}");
    assert_eq!(s.backups().len(), 2);
}

#[test]
fn backups_rotate_and_need_a_passphrase_when_encrypted() {
    let s = Scratch::new("backup-rotate");
    s.import();
    s.run(&["keygen", "--write-config"]);
    let (ok, _, err) = s.run(&["backup", "create"]);
    assert!(!ok && err.contains("`parallax backup passphrase`"), "{err}");

    let edited = std::fs::read_to_string(s.config())
        .unwrap()
        .replace("keep = 14", "keep = 2")
        .replace("encrypt = true", "encrypt = false");
    std::fs::write(s.config(), edited).unwrap();
    s.import();
    for _ in 0..3 {
        let (ok, out, err) = s.run(&["backup", "create"]);
        assert!(ok && out.contains("(not encrypted)"), "{out}{err}");
    }
    let (_, out, _) = s.run(&["backup", "create"]);
    assert!(
        out.contains("deleted") && out.contains("(keeping 2)"),
        "{out}"
    );
    assert_eq!(s.backups().len(), 2);

    let (ok, _, err) = s.run(&["backup", "passphrase", "--generate"]);
    assert!(ok && err.contains("don't use it yet"), "{err}");

    std::fs::write(s.dir.join("wg-server.key"), "not a key\n").unwrap();
    let (ok, _, err) = s.run(&["backup", "create"]);
    assert!(
        !ok && err.contains("doesn't hold a WireGuard private key"),
        "{err}"
    );
    let (ok, _, err) = s.run(&["backup", "passphrase", "--generate"]);
    assert!(!ok && err.contains("--replace"), "{err}");
}

#[test]
fn a_restore_without_an_undo_backup_changes_nothing() {
    let s = Scratch::new("backup-undo");
    s.gateway();
    s.run(&["backup", "create"]);
    let file = s.backups().pop().unwrap();
    s.run(&["peer", "remove", "laptop"]);
    // Backups can't be written any more: the directory is now a file.
    let blocker = s.dir.join("blocker");
    std::fs::write(&blocker, "").unwrap();
    let text = std::fs::read_to_string(s.config()).unwrap().replace(
        &s.dir.join("backups").to_string_lossy().into_owned(),
        &blocker.to_string_lossy(),
    );
    std::fs::write(s.config(), text).unwrap();
    s.import();
    let (_, before, _) = s.run(&["config", "export"]);

    let (ok, _, err) = s.run(&["backup", "restore", "--yes", &file.to_string_lossy()]);
    assert!(
        !ok && err.contains("couldn't save the current state first"),
        "{err}"
    );
    let (_, after, _) = s.run(&["config", "export"]);
    assert_eq!(before, after);
}

#[test]
fn a_backup_dated_in_the_future_does_not_stay_newest() {
    let s = Scratch::new("backup-future");
    s.gateway();
    s.run(&["backup", "create"]);
    let file = s.backups().pop().unwrap();
    // Written while the clock was ahead.
    std::fs::rename(
        &file,
        file.with_file_name("parallax-backup-20991231T000000Z.tar"),
    )
    .unwrap();
    s.run(&["peer", "remove", "laptop"]);
    let (ok, out, err) = s.run(&["backup", "create", "--if-due"]);
    assert!(ok && out.contains("wrote"), "{out}{err}");
    // The one just written counts as newest now: not due again.
    let (ok, out, err) = s.run(&["backup", "create", "--if-due"]);
    assert!(ok && out.is_empty(), "{out}{err}");
    assert_eq!(s.backups().len(), 2);
}

/// A reader that goes away (`parallax peer show | head -1`, a pager that quits)
/// stops the command quietly with SIGPIPE's status, not a panic. The pipe's
/// read end is closed before the command starts, so every write fails.
#[cfg(unix)]
#[test]
fn a_closed_stdout_stops_the_command_without_a_panic() {
    use std::os::unix::process::ExitStatusExt;
    let s = Scratch::new("closed-stdout");
    s.import();
    for args in [&["config", "export"][..], &["peer", "show"], &["validate"]] {
        let (reader, writer) = std::io::pipe().unwrap();
        drop(reader);
        let out = s.command(args).stdout(writer).output().unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(
            (out.status.code(), out.status.signal()),
            (Some(141), None),
            "{args:?}: {err}"
        );
        assert!(err.is_empty(), "{args:?}: {err}");
    }
}

/// stderr only carries messages about the work: with it closed, `peer add`
/// still saves the peer and prints its one-time config.
#[test]
fn a_closed_stderr_changes_nothing() {
    let s = Scratch::new("closed-stderr");
    s.import();
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    let out = s
        .command(&["peer", "add", "tablet", "--grant", "family"])
        .stderr(writer)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{:?}", out.status);
    assert!(
        text.contains("[Interface]") && text.contains("PrivateKey"),
        "{text}"
    );
    let (ok, shown, err) = s.run(&["peer", "show", "tablet"]);
    assert!(ok && shown.contains("tablet"), "{shown}{err}");
}

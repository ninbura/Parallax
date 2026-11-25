//! Lookups the gateway makes for itself (the home's public IP), as opposed
//! to answering tunnel peers: plain DNS to one resolver, or DNS over HTTPS
//! to a provider reached by IP address, so no lookup has to come first.

use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use hickory_server::net::runtime::TokioRuntimeProvider;
use hickory_server::proto::rr::RData;
use hickory_server::resolver::config::{NameServerConfig, ResolveHosts, ResolverConfig};
use hickory_server::resolver::TokioResolver;
use parallax_core::io::{Nameserver, Resolver};
use rustls::RootCertStore;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::CertificateDer;

/// How long one nameserver (or provider, over all its addresses) gets.
pub const TIMEOUT: Duration = Duration::from_secs(3);

/// Blocking lookups.
#[derive(Debug, Clone)]
pub struct Lookup {
    /// The CA bundle encrypted DNS providers' certificates are checked against.
    ca: PathBuf,
}

impl Lookup {
    pub fn new(ca: &Path) -> Self {
        Lookup {
            ca: ca.to_path_buf(),
        }
    }

    async fn ask(&self, name: &str, via: Nameserver) -> Result<Vec<Ipv4Addr>, String> {
        let servers = match via {
            Nameserver::Plain(ip) => vec![NameServerConfig::udp_and_tcp(IpAddr::V4(ip))],
            Nameserver::Encrypted(provider) => provider
                .addresses()
                .iter()
                .map(|ip| {
                    NameServerConfig::https(IpAddr::V4(*ip), Arc::from(provider.tls_name()), None)
                })
                .collect(),
        };
        let config = ResolverConfig::from_parts(None, Vec::new(), servers);
        let mut builder =
            TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());
        if let Nameserver::Encrypted(_) = via {
            builder = builder.with_tls_config(self.tls()?);
        }
        let opts = builder.options_mut();
        opts.timeout = TIMEOUT;
        opts.attempts = 1;
        opts.cache_size = 0;
        opts.use_hosts_file = ResolveHosts::Never;
        let resolver = builder.build().map_err(|e| e.to_string())?;
        // Fully qualified: no search list, no guessing.
        let fqdn = if name.ends_with('.') {
            name.to_string()
        } else {
            format!("{name}.")
        };
        match tokio::time::timeout(TIMEOUT, resolver.ipv4_lookup(fqdn)).await {
            Err(_) => Err(format!("no answer within {} seconds", TIMEOUT.as_secs())),
            Ok(Err(e)) if e.is_no_records_found() => Ok(Vec::new()),
            Ok(Err(e)) => Err(e.to_string()),
            Ok(Ok(lookup)) => Ok(lookup
                .answers()
                .iter()
                .filter_map(|r| match &r.data {
                    RData::A(a) => Some(a.0),
                    _ => None,
                })
                .collect()),
        }
    }

    fn tls(&self) -> Result<rustls::ClientConfig, String> {
        let context = || format!("reading the CA bundle {}", self.ca.display());
        let mut roots = RootCertStore::empty();
        let certs =
            CertificateDer::pem_file_iter(&self.ca).map_err(|e| format!("{}: {e}", context()))?;
        for cert in certs {
            let cert = cert.map_err(|e| format!("{}: {e}", context()))?;
            // Bundles carry the odd certificate webpki can't use; skip those.
            let _ = roots.add(cert);
        }
        if roots.is_empty() {
            return Err(format!("{}: no usable CA certificate in it", context()));
        }
        rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map(|b| b.with_root_certificates(roots).with_no_client_auth())
        .map_err(|e| e.to_string())
    }
}

impl Resolver for Lookup {
    /// Blocks. Runs on a thread and runtime of its own, so it works from
    /// anywhere, inside an async runtime too (where it blocks that thread).
    fn lookup_ipv4(&self, name: &str, via: Nameserver) -> parallax_core::Result<Vec<Ipv4Addr>> {
        let run = || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| format!("starting a runtime: {e}"))?
                .block_on(self.ask(name, via))
        };
        std::thread::scope(|scope| {
            scope
                .spawn(run)
                .join()
                .unwrap_or_else(|_| Err("the lookup thread panicked".into()))
        })
        .map_err(parallax_core::Error::Lookup)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests")]

    use super::*;
    use parallax_core::model::EncryptedDns;

    #[test]
    fn a_missing_ca_bundle_is_named() {
        let lookup = Lookup::new(Path::new("/nonexistent/ca.pem"));
        let err = lookup
            .lookup_ipv4("example.com", Nameserver::Encrypted(EncryptedDns::Quad9))
            .unwrap_err()
            .to_string();
        assert!(err.contains("/nonexistent/ca.pem"), "{err}");
    }

    #[test]
    fn a_silent_resolver_times_out() {
        // Documentation space: nothing answers there.
        let lookup = Lookup::new(Path::new("/nonexistent/ca.pem"));
        let started = std::time::Instant::now();
        let err = lookup
            .lookup_ipv4(
                "example.com",
                Nameserver::Plain(Ipv4Addr::new(192, 0, 2, 1)),
            )
            .unwrap_err();
        assert!(
            started.elapsed() < TIMEOUT + Duration::from_secs(2),
            "{err}"
        );
    }

    /// Asks the real providers. `cargo test -p parallax-dns -- --ignored`.
    #[test]
    #[ignore = "needs the internet"]
    fn providers_answer_over_https() {
        let lookup = Lookup::new(Path::new("/etc/ssl/certs/ca-certificates.crt"));
        for provider in EncryptedDns::ALL {
            let found = lookup
                .lookup_ipv4("one.one.one.one", Nameserver::Encrypted(provider))
                .unwrap();
            assert!(
                found.contains(&Ipv4Addr::new(1, 1, 1, 1)),
                "{provider}: {found:?}"
            );
        }
    }
}

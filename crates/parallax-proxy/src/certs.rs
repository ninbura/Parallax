//! Certificates from the operator's folder.
//!
//! Parallax never issues certificates. The operator keeps one folder of PEM
//! files current (certbot or anything else that writes PEM). Every directory
//! under it holding `fullchain.pem` and `privkey.pem` is one certificate, so
//! certbot's `live/<name>` layout works as is. For each hostname the proxy
//! uses a certificate that names it exactly, else one whose wildcard covers
//! it; ties go to the first in path order. A certificate whose key is
//! missing or doesn't match is skipped. `plan` and `apply` make the same
//! choice ([`crate::preflight`]), so what they accept is what the proxy serves.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::crypto::CryptoProvider;
use rustls::{RootCertStore, ServerConfig};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};

use crate::{Error, Result};

pub const CHAIN_FILE: &str = "fullchain.pem";
pub const KEY_FILE: &str = "privkey.pem";

/// How deep to look under the folder. certbot's `live/<name>` is two levels
/// down from `/etc/letsencrypt`; the limit also stops symlink loops.
const MAX_DEPTH: usize = 4;

/// One certificate chain found in the folder. The private key stays on disk
/// until the proxy loads it to serve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    pub dir: PathBuf,
    pub chain: Vec<CertificateDer<'static>>,
}

/// How a certificate covers a hostname. Exact sorts first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Coverage {
    Exact,
    Wildcard,
}

impl Certificate {
    /// Does this certificate cover `hostname`, and how?
    pub fn coverage(&self, hostname: &str) -> Option<Coverage> {
        let leaf = self.chain.first()?;
        let cert = webpki::EndEntityCert::try_from(leaf).ok()?;
        let name = ServerName::try_from(hostname).ok()?;
        cert.verify_is_valid_for_subject_name(&name).ok()?;
        // Only ranks a name the check above already accepted.
        if cert
            .valid_dns_names()
            .any(|n| n.eq_ignore_ascii_case(hostname))
        {
            Some(Coverage::Exact)
        } else {
            Some(Coverage::Wildcard)
        }
    }

    /// Read this certificate's private key.
    pub fn private_key(&self) -> Result<PrivateKeyDer<'static>> {
        let path = self.dir.join(KEY_FILE);
        PrivateKeyDer::from_pem_file(&path)
            .map_err(|e| Error::invalid(format!("reading {}", path.display()), e))
    }

    /// A TLS server config serving this certificate. Fails when the key is
    /// unreadable or doesn't belong to the certificate.
    pub fn server_config(&self) -> Result<Arc<ServerConfig>> {
        let context = || format!("certificate in {}", self.dir.display());
        let mut config = ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .map_err(|e| Error::invalid(context(), e))?
            .with_no_client_auth()
            .with_single_cert(self.chain.clone(), self.private_key()?)
            .map_err(|e| Error::invalid(context(), e))?;
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(Arc::new(config))
    }
}

pub(crate) fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Every certificate under `dir`, in path order, plus a message for each
/// directory that has the files but can't be read. Fails only if `dir`
/// itself is missing or unreadable.
pub fn scan(dir: &Path) -> Result<(Vec<Certificate>, Vec<String>)> {
    let mut dirs = Vec::new();
    find(dir, 0, &mut dirs)?;
    let mut certs = Vec::new();
    let mut problems = Vec::new();
    for d in dirs {
        match load_chain(&d.join(CHAIN_FILE)) {
            Ok(chain) => certs.push(Certificate { dir: d, chain }),
            Err(e) => problems.push(e.to_string()),
        }
    }
    Ok((certs, problems))
}

fn find(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) -> Result<()> {
    let entries = std::fs::read_dir(dir)
        .map_err(|e| Error::io(format!("reading certificate folder {}", dir.display()), e))?;
    let mut subdirs: Vec<PathBuf> = entries
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_dir())
        .collect();
    subdirs.sort();
    if dir.join(CHAIN_FILE).is_file() && dir.join(KEY_FILE).is_file() {
        out.push(dir.to_path_buf());
    }
    if depth < MAX_DEPTH {
        for sub in subdirs {
            // A subdirectory that vanished or can't be read mid-scan isn't fatal.
            let _ = find(&sub, depth + 1, out);
        }
    }
    Ok(())
}

fn load_chain(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let context = || format!("reading {}", path.display());
    let chain = CertificateDer::pem_file_iter(path)
        .map_err(|e| Error::invalid(context(), e))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| Error::invalid(context(), e))?;
    if chain.is_empty() {
        return Err(Error::invalid(context(), "no certificate in the file"));
    }
    Ok(chain)
}

/// The certificate to serve `hostname` with, and its TLS config: the best
/// ranked one whose key loads and matches. The error says why there's none.
pub fn select<'a>(
    certs: &'a [Certificate],
    hostname: &str,
) -> std::result::Result<(&'a Certificate, Arc<ServerConfig>), String> {
    let mut ranked: Vec<(Coverage, &Certificate)> = certs
        .iter()
        .filter_map(|c| c.coverage(hostname).map(|how| (how, c)))
        .collect();
    // Stable: equally good certificates stay in path order.
    ranked.sort_by_key(|(how, _)| *how);
    let mut problems = Vec::new();
    for (_, cert) in ranked {
        match cert.server_config() {
            Ok(config) => return Ok((cert, config)),
            Err(e) => problems.push(e.to_string()),
        }
    }
    if problems.is_empty() {
        Err(format!("no certificate covers {hostname}"))
    } else {
        Err(format!(
            "no usable certificate covers {hostname} ({})",
            problems.join("; ")
        ))
    }
}

/// The CA bundle upstream certificates are verified against.
pub fn upstream_roots(ca: &Path) -> Result<RootCertStore> {
    let context = || format!("reading the upstream CA bundle {}", ca.display());
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_file_iter(ca).map_err(|e| Error::invalid(context(), e))? {
        let cert = cert.map_err(|e| Error::invalid(context(), e))?;
        // Bundles carry the odd certificate webpki can't use; skip those.
        let _ = roots.add(cert);
    }
    if roots.is_empty() {
        return Err(Error::invalid(context(), "no usable CA certificate in it"));
    }
    Ok(roots)
}

/// A cheap fingerprint of every certificate and key file under `dir`, to
/// notice renewals without rebuilding TLS state every time. Never shown.
pub fn fingerprint(dir: &Path) -> u64 {
    let mut dirs = Vec::new();
    let _ = find(dir, 0, &mut dirs);
    let mut h = DefaultHasher::new();
    for d in dirs {
        d.hash(&mut h);
        for file in [CHAIN_FILE, KEY_FILE] {
            std::fs::read(d.join(file)).ok().hash(&mut h);
        }
    }
    h.finish()
}

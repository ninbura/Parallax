//! Parallax's HTTPS proxy.
//!
//! One address and port often serves many sites, so the firewall alone can't
//! limit a template to one of them. Tiers that reach an HTTPS service only
//! through `service` grants are redirected here instead. The proxy
//! terminates TLS with the operator's certificate for the hostname, checks
//! that the caller's tunnel address may use it and that every request names
//! it, and forwards to the configured upstream over verified TLS.
//!
//! It reads only the routes file `apply` generates
//! ([`parallax_core::generate::proxy`]); SIGHUP re-reads it, and the
//! certificate folder is re-checked every minute so renewals need no restart.

mod error;
mod server;

pub mod certs;
pub mod http;

pub use error::{Error, Result};
pub use server::{serve, Proxy};

use parallax_core::generate::proxy::ProxyRoutes;

/// What `plan` and `apply` check before the proxy is handed new routes, so a
/// change the proxy would refuse fails there instead: the upstream CA bundle
/// loads, and every hostname has a usable certificate (one that covers it,
/// with a matching key). Returns warnings about unreadable certificates.
pub fn preflight(routes: &ProxyRoutes) -> Result<Vec<String>> {
    if routes.sites.is_empty() {
        return Ok(Vec::new());
    }
    certs::upstream_roots(&routes.upstream_ca)?;
    let (found, warnings) = certs::scan(&routes.certificates)?;
    let missing: Vec<String> = routes
        .sites
        .iter()
        .filter_map(|s| certs::select(&found, &s.hostname).err())
        .collect();
    if missing.is_empty() {
        Ok(warnings)
    } else {
        Err(Error::invalid(
            format!(
                "certificates in {} (server.proxy.certificates)",
                routes.certificates.display()
            ),
            format!(
                "{}; put one in a directory under it (fullchain.pem and privkey.pem, as certbot writes them)",
                missing.join("; ")
            ),
        ))
    }
}

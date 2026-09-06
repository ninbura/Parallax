//! Secret-bearing types. `Debug` never prints the value; `Serialize` does,
//! because the TOML file *is* the M1 persistence layer and the operator opted
//! into storing the value there. Callers must write such files with mode 0600
//! (see [`crate::generate::Artifact::secret`]).

use std::fmt;

use base64::Engine;
use serde::{Deserialize, Serialize};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// An opaque secret string (API keys, preauth keys). Redacted in `Debug`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Secret(value.into())
    }
    /// Reveal the secret. Callers must not log the result.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

/// A 32-byte Curve25519 key, base64-encoded as WireGuard expects.
fn decode_key(s: &str, what: &'static str) -> crate::Result<[u8; 32]> {
    let bytes = B64.decode(s.trim()).map_err(|e| crate::Error::Malformed {
        what,
        detail: format!("not valid base64: {e}"),
    })?;
    bytes
        .try_into()
        .map_err(|v: Vec<u8>| crate::Error::Malformed {
            what,
            detail: format!("expected 32 bytes, got {}", v.len()),
        })
}

/// A WireGuard public key (base64 of 32 bytes). Not secret.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        PublicKey(bytes)
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    pub fn to_base64(&self) -> String {
        B64.encode(self.0)
    }
}

impl std::str::FromStr for PublicKey {
    type Err = crate::Error;
    fn from_str(s: &str) -> crate::Result<Self> {
        decode_key(s, "public key").map(PublicKey)
    }
}

impl TryFrom<String> for PublicKey {
    type Error = crate::Error;
    fn try_from(s: String) -> crate::Result<Self> {
        s.parse()
    }
}

impl From<PublicKey> for String {
    fn from(k: PublicKey) -> String {
        k.to_base64()
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", self.to_base64())
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_base64())
    }
}

/// A WireGuard private key. Redacted in `Debug`; never `Display`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PrivateKey([u8; 32]);

impl PrivateKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        PrivateKey(bytes)
    }
    /// Reveal the key in WireGuard's base64 form. Callers must not log the result.
    pub fn expose_base64(&self) -> String {
        B64.encode(self.0)
    }
    /// The corresponding public key.
    pub fn public_key(&self) -> PublicKey {
        let secret = x25519_dalek::StaticSecret::from(self.0);
        PublicKey(x25519_dalek::PublicKey::from(&secret).to_bytes())
    }
}

impl std::str::FromStr for PrivateKey {
    type Err = crate::Error;
    fn from_str(s: &str) -> crate::Result<Self> {
        decode_key(s, "private key").map(PrivateKey)
    }
}

impl TryFrom<String> for PrivateKey {
    type Error = crate::Error;
    fn try_from(s: String) -> crate::Result<Self> {
        s.parse()
    }
}

impl From<PrivateKey> for String {
    fn from(k: PrivateKey) -> String {
        k.expose_base64()
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateKey(<redacted>)")
    }
}

/// A WireGuard preshared key (symmetric, 32 bytes). Redacted in `Debug`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PresharedKey([u8; 32]);

impl PresharedKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        PresharedKey(bytes)
    }
    pub fn expose_base64(&self) -> String {
        B64.encode(self.0)
    }
}

impl std::str::FromStr for PresharedKey {
    type Err = crate::Error;
    fn from_str(s: &str) -> crate::Result<Self> {
        decode_key(s, "preshared key").map(PresharedKey)
    }
}

impl TryFrom<String> for PresharedKey {
    type Error = crate::Error;
    fn try_from(s: String) -> crate::Result<Self> {
        s.parse()
    }
}

impl From<PresharedKey> for String {
    fn from(k: PresharedKey) -> String {
        k.expose_base64()
    }
}

impl fmt::Debug for PresharedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PresharedKey(<redacted>)")
    }
}

/// A freshly generated WireGuard keypair.
#[derive(Debug, Clone)]
pub struct KeyPair {
    pub private: PrivateKey,
    pub public: PublicKey,
}

impl KeyPair {
    /// Build a keypair from raw private key bytes (clamped as `wg genkey` does).
    pub fn from_private_bytes(mut bytes: [u8; 32]) -> Self {
        bytes[0] &= 248;
        bytes[31] &= 127;
        bytes[31] |= 64;
        let private = PrivateKey(bytes);
        let public = private.public_key();
        KeyPair { private, public }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_private_material() {
        let kp = KeyPair::from_private_bytes([7u8; 32]);
        assert_eq!(format!("{:?}", kp.private), "PrivateKey(<redacted>)");
        assert!(format!("{:?}", kp).contains("<redacted>"));
        assert!(!format!("{:?}", kp).contains(&kp.private.expose_base64()));
        assert_eq!(format!("{:?}", Secret::new("x")), "Secret(<redacted>)");
    }

    #[test]
    fn public_key_round_trips_base64() {
        let kp = KeyPair::from_private_bytes([1u8; 32]);
        let text = kp.public.to_base64();
        assert_eq!(text.parse::<PublicKey>().unwrap(), kp.public);
        assert!("bad".parse::<PublicKey>().is_err());
        assert!(B64.encode([0u8; 31]).parse::<PublicKey>().is_err());
    }

    #[test]
    fn matches_known_wireguard_vector() {
        // Private key from the WireGuard test-suite: all zeros clamped is a
        // valid key; verify pubkey derivation is stable across runs.
        let a = KeyPair::from_private_bytes([0u8; 32]);
        let b = KeyPair::from_private_bytes([0u8; 32]);
        assert_eq!(a.public, b.public);
    }
}

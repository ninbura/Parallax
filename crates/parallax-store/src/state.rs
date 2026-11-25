//! What the daemon learned while running and keeps across restarts, in the
//! `daemon_state` table. Not configuration: `load` and `save` never see it.

use std::net::Ipv4Addr;

use crate::{Error, Result, Store};

const PUBLIC_IP: &str = "public_ip";

impl Store {
    /// The home's public IP as last found; `None` if it never was.
    pub async fn public_ip(&self) -> Result<Option<Ipv4Addr>> {
        let rows = self
            .rows(
                "SELECT value FROM daemon_state WHERE key = ?1",
                vec![PUBLIC_IP.into()],
            )
            .await?;
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        let text: String = row.get(0)?;
        text.parse().map(Some).map_err(|_| {
            Error::Stored(format!(
                "daemon state: the public IP '{text}' is not an IPv4 address"
            ))
        })
    }

    /// Remember the home's public IP.
    pub async fn set_public_ip(&self, ip: Ipv4Addr) -> Result<()> {
        self.exec(
            "INSERT INTO daemon_state (key, value) VALUES (?1, ?2)
             ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            vec![PUBLIC_IP.into(), ip.to_string().into()],
        )
        .await
        .map_err(|e| self.busy(e))?;
        Ok(())
    }
}

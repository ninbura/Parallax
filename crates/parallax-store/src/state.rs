//! What the daemon learned while running and keeps across restarts, in the
//! `daemon_state` table: the home's public IP, and what each host named by
//! DNS name last resolved to. Not configuration: `load` and `save` never
//! see it.

use std::net::Ipv4Addr;

use parallax_core::names::Resolved;

use crate::{Error, Result, Store};

const PUBLIC_IP: &str = "public_ip";
/// Each name's row is this plus the name; the value is its addresses,
/// comma-separated.
const NAME: &str = "name:";

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

    /// What each host named by DNS name last resolved to.
    pub async fn names(&self) -> Result<Resolved> {
        let rows = self
            .rows(
                "SELECT key, value FROM daemon_state WHERE key LIKE 'name:%' ORDER BY key",
                Vec::new(),
            )
            .await?;
        let mut out = Resolved::new();
        for row in rows {
            let key: String = row.get(0)?;
            let value: String = row.get(1)?;
            let Some(name) = key.strip_prefix(NAME) else {
                continue;
            };
            let addresses = value
                .split(',')
                .map(|a| {
                    a.parse().map_err(|_| {
                        Error::Stored(format!(
                            "daemon state: {name} resolved to '{a}', which is not an IPv4 address"
                        ))
                    })
                })
                .collect::<Result<Vec<Ipv4Addr>>>()?;
            out.insert(name.to_string(), addresses);
        }
        Ok(out)
    }

    /// Remember what the names resolved to, replacing what was there: names
    /// missing from `names` are forgotten.
    pub async fn set_names(&self, names: &Resolved) -> Result<()> {
        self.begin().await.map_err(|e| self.busy(e))?;
        let written = async {
            self.exec(
                "DELETE FROM daemon_state WHERE key LIKE 'name:%'",
                Vec::new(),
            )
            .await?;
            // A name without addresses is one never found: nothing to keep.
            for (name, addresses) in names.iter().filter(|(_, a)| !a.is_empty()) {
                let value = addresses
                    .iter()
                    .map(Ipv4Addr::to_string)
                    .collect::<Vec<_>>()
                    .join(",");
                self.exec(
                    "INSERT INTO daemon_state (key, value) VALUES (?1, ?2)",
                    vec![format!("{NAME}{name}").into(), value.into()],
                )
                .await?;
            }
            Ok(())
        }
        .await;
        self.finish(written).await.map_err(|e| self.busy(e))
    }
}

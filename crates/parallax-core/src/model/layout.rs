//! The one TOML layout `config export` and `config edit` write, so every
//! exported file reads the same way and diffs stay small:
//!
//! - Sections in model order (server, networks, services, grants, peers),
//!   each under a `# Heading`, with a blank line between blocks.
//! - Each `[[network]]`, `[[grant]]`, ... entry is one block without blank
//!   lines. Its plain keys come first, then its sub-tables: on one line
//!   (`dns = { ... }`) when that line fits in [`WIDTH`] for every entry of the
//!   section, otherwise as a `[peer.wireguard]` header in every entry, so all
//!   entries of a section look alike. A list of tables (`rules`) is one line for a
//!   single item, one item per line otherwise, so adding a rule is a
//!   one-line change.
//! - The server's sub-tables are always `[server.x]` blocks: they're
//!   settings, read and edited one at a time.
//!
//! It walks the generic TOML value, so a new model field needs nothing here.

use std::fmt::Write;

use toml::{Table, Value};

/// Longest one-line sub-table inside an entry.
const WIDTH: usize = 100;

/// Render the serialized configuration. `root` must keep field order
/// (`toml`'s `preserve_order`).
pub(super) fn render(root: &Table) -> String {
    let mut out = String::new();
    // Plain top-level keys first, as TOML requires (the model has none).
    write_keys(&mut out, root, false);
    for (key, value) in root {
        match value {
            Value::Table(table) => {
                heading(&mut out, key);
                write_table(&mut out, key, table, true);
            }
            Value::Array(items) if is_tables(items) => {
                heading(&mut out, key);
                let entries: Vec<&Table> = items.iter().filter_map(Value::as_table).collect();
                let long = long_tables(&entries);
                for entry in entries {
                    blank_line(&mut out);
                    let _ = writeln!(out, "[[{}]]", bare(key));
                    write_entry(&mut out, key, entry, &long);
                }
            }
            _ => {}
        }
    }
    out
}

/// A settings table and its sub-tables, each as a header block.
fn write_table(out: &mut String, path: &str, table: &Table, spaced: bool) {
    let has_keys = table.values().any(|v| !v.is_table());
    // `[server]` holding only sub-tables needs no header of its own; an empty
    // table keeps one so it parses back as present.
    if has_keys || table.is_empty() {
        if spaced {
            blank_line(out);
        }
        let _ = writeln!(out, "[{path}]");
        write_keys(out, table, true);
    }
    for (key, value) in table {
        if let Value::Table(child) = value {
            write_table(out, &format!("{path}.{}", bare(key)), child, spaced);
        }
    }
}

/// Sub-table keys that some entry can't write on one line: those become
/// headers in every entry.
fn long_tables<'a>(entries: &[&'a Table]) -> Vec<&'a str> {
    let mut long = Vec::new();
    for entry in entries {
        for (key, value) in entry.iter() {
            if let Value::Table(child) = value {
                let fits =
                    inline(key, value).len() <= WIDTH && !child.values().any(Value::is_table);
                if !fits && !long.contains(&key.as_str()) {
                    long.push(key.as_str());
                }
            }
        }
    }
    long
}

/// One list entry: keys, sub-tables inline unless `long`, then the rest as
/// headers.
fn write_entry(out: &mut String, path: &str, entry: &Table, long: &[&str]) {
    write_keys(out, entry, true);
    for (key, value) in entry {
        if value.is_table() && !long.contains(&key.as_str()) {
            let _ = writeln!(out, "{}", inline(key, value));
        }
    }
    for (key, value) in entry {
        if let Value::Table(child) = value {
            if long.contains(&key.as_str()) {
                write_table(out, &format!("{path}.{}", bare(key)), child, false);
            }
        }
    }
}

fn inline(key: &str, value: &Value) -> String {
    format!("{} = {value}", bare(key))
}

/// `key = value` for everything that isn't a sub-table. Lists of tables are
/// written inline when `inline_lists`, otherwise skipped (they're sections).
fn write_keys(out: &mut String, table: &Table, inline_lists: bool) {
    for (key, value) in table {
        match value {
            Value::Table(_) => {}
            // An empty section (no peers yet) is left out, not `peer = []`.
            Value::Array(items) if items.is_empty() && !inline_lists => {}
            Value::Array(items) if is_tables(items) => {
                if !inline_lists {
                    continue;
                }
                if items.len() == 1 {
                    let _ = writeln!(out, "{}", inline(key, value));
                } else {
                    let _ = writeln!(out, "{} = [", bare(key));
                    for item in items {
                        let _ = writeln!(out, "    {item},");
                    }
                    out.push_str("]\n");
                }
            }
            _ => {
                let _ = writeln!(out, "{}", inline(key, value));
            }
        }
    }
}

fn heading(out: &mut String, key: &str) {
    let title = match key {
        "server" => "Server",
        "network" => "Networks",
        "service" => "Services",
        "grant" => "Grants",
        "peer" => "Peers",
        _ => return,
    };
    blank_line(out);
    let _ = writeln!(out, "# {title}");
}

/// Separate blocks by exactly one blank line, never at the top of the file.
fn blank_line(out: &mut String) {
    if !out.is_empty() && !out.ends_with("\n\n") {
        out.push('\n');
    }
}

/// A non-empty list holding only tables: a TOML array of tables.
fn is_tables(items: &[Value]) -> bool {
    !items.is_empty() && items.iter().all(Value::is_table)
}

/// The key as TOML writes it: bare when it can be, quoted otherwise.
fn bare(key: &str) -> String {
    let is_bare = !key.is_empty()
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if is_bare {
        key.to_owned()
    } else {
        Value::String(key.to_owned()).to_string()
    }
}

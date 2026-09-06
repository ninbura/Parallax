//! `plan`: generate everything and diff it against what is on disk.

use std::path::{Path, PathBuf};

use crate::generate::{Artifact, Bundle};
use crate::io::FileSystem;
use crate::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    Unchanged,
    Created,
    /// A unified diff of old → new.
    Modified(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedArtifact {
    pub path: PathBuf,
    pub change: Change,
    pub secret: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub out_dir: PathBuf,
    pub items: Vec<PlannedArtifact>,
    pub warnings: Vec<String>,
}

impl Plan {
    pub fn has_changes(&self) -> bool {
        self.items.iter().any(|i| i.change != Change::Unchanged)
    }

    /// Human-readable summary with diffs. Secret files show only that they changed.
    pub fn render(&self) -> String {
        let mut s = String::new();
        for w in &self.warnings {
            s.push_str(&format!("warning: {w}\n"));
        }
        for item in &self.items {
            let path = self.out_dir.join(&item.path);
            match &item.change {
                Change::Unchanged => s.push_str(&format!("  unchanged {}\n", path.display())),
                Change::Created => s.push_str(&format!("+ create    {}\n", path.display())),
                Change::Modified(diff) => {
                    s.push_str(&format!("~ modify    {}\n", path.display()));
                    if item.secret {
                        s.push_str("    (contents redacted: file holds secrets)\n");
                    } else {
                        for line in diff.lines() {
                            s.push_str("    ");
                            s.push_str(line);
                            s.push('\n');
                        }
                    }
                }
            }
        }
        if !self.has_changes() {
            s.push_str("No changes.\n");
        }
        s
    }
}

pub fn unified_diff(old: &str, new: &str) -> String {
    similar::TextDiff::from_lines(old, new)
        .unified_diff()
        .context_radius(3)
        .header("current", "generated")
        .to_string()
}

fn classify(fs: &dyn FileSystem, out_dir: &Path, a: &Artifact) -> Result<Change> {
    match fs.read(&out_dir.join(&a.path))? {
        None => Ok(Change::Created),
        Some(existing) if existing == a.contents => Ok(Change::Unchanged),
        Some(existing) => Ok(Change::Modified(unified_diff(&existing, &a.contents))),
    }
}

/// Compare a generated bundle with the files under `out_dir`.
pub fn plan(bundle: &Bundle, out_dir: &Path, fs: &dyn FileSystem) -> Result<Plan> {
    let mut items = Vec::new();
    for a in &bundle.artifacts {
        items.push(PlannedArtifact {
            path: a.path.clone(),
            change: classify(fs, out_dir, a)?,
            secret: a.secret,
        });
    }
    Ok(Plan {
        out_dir: out_dir.to_path_buf(),
        items,
        warnings: bundle.warnings.clone(),
    })
}

/// Write every artifact under `out_dir` (secret ones with mode 0600).
pub fn write_bundle(bundle: &Bundle, out_dir: &Path, fs: &dyn FileSystem) -> Result<()> {
    for a in &bundle.artifacts {
        fs.write(&out_dir.join(&a.path), &a.contents, a.secret)?;
    }
    Ok(())
}

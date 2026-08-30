//! Plaintext JSON store of site entries. Contains no secrets — the Ledger
//! is the only secret material. Losing this file just loses the *policy*
//! (length, charset, counter) — passwords can be regenerated once known.

use anyhow::{Context, Result, bail};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use crate::derive::Charset;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Entry {
    pub site: String,
    #[serde(default)]
    pub username: String,
    #[serde(default = "default_length")]
    pub length: usize,
    #[serde(default = "default_charset")]
    pub charset: Charset,
    /// Bump to rotate the password for a site without changing site/username.
    #[serde(default)]
    pub counter: u32,
    #[serde(default)]
    pub notes: String,
}

fn default_length() -> usize {
    20
}
fn default_charset() -> Charset {
    Charset::Symbols
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Store {
    #[serde(default)]
    pub entries: Vec<Entry>,
}

impl Store {
    pub fn path() -> Result<PathBuf> {
        let dirs = ProjectDirs::from("", "", "pwmgr")
            .ok_or_else(|| anyhow::anyhow!("cannot resolve config dir"))?;
        Ok(dirs.config_dir().join("entries.json"))
    }

    pub fn load() -> Result<Self> {
        let p = Self::path()?;
        if !p.exists() {
            return Ok(Store::default());
        }
        let txt = fs::read_to_string(&p)
            .with_context(|| format!("read {}", p.display()))?;
        let s: Store = serde_json::from_str(&txt)
            .with_context(|| format!("parse {}", p.display()))?;
        Ok(s)
    }

    pub fn save(&self) -> Result<PathBuf> {
        let p = Self::path()?;
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create {}", parent.display()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                // Owner-only, so other local users can't enumerate saved sites.
                let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
            }
        }
        let txt = serde_json::to_string_pretty(self)?;
        atomic_write(&p, txt.as_bytes())?;
        Ok(p)
    }

    // Callers pass sites already canonicalized via `canonicalize_site`, so
    // comparison is exact. That keeps the string used for Ledger derivation
    // (which is case-sensitive) in lockstep with the string used for lookup.
    pub fn find(&self, site: &str) -> Option<&Entry> {
        self.entries.iter().find(|e| e.site == site)
    }

    pub fn find_mut(&mut self, site: &str) -> Option<&mut Entry> {
        self.entries.iter_mut().find(|e| e.site == site)
    }

    pub fn upsert(&mut self, entry: Entry) -> bool {
        if let Some(slot) = self.find_mut(&entry.site) {
            *slot = entry;
            false
        } else {
            self.entries.push(entry);
            self.entries.sort_by(|a, b| a.site.cmp(&b.site));
            true
        }
    }

    pub fn remove(&mut self, site: &str) -> bool {
        let before = self.entries.len();
        self.entries.retain(|e| e.site != site);
        self.entries.len() != before
    }
}

fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = path.with_extension("json.tmp");
    // Create the tmp file with 0600 on unix so its contents are never briefly
    // world-readable between rename and any later chmod. Windows falls through
    // to the default ACL.
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .with_context(|| format!("create {}", tmp.display()))?;
        f.write_all(data)
            .with_context(|| format!("write {}", tmp.display()))?;
        f.sync_all().ok();
    }
    #[cfg(not(unix))]
    {
        fs::write(&tmp, data).with_context(|| format!("write {}", tmp.display()))?;
    }
    fs::rename(&tmp, path).with_context(|| format!("rename to {}", path.display()))?;
    Ok(())
}

/// Canonicalize a site name: lowercase, printable non-whitespace ASCII,
/// no ':' (our field separator in the signed message). Returns the string
/// that will be *both* stored and hashed — keeping those in lockstep is
/// what prevents the "add Github.com then get github.com yields a different
/// password" footgun.
pub fn canonicalize_site(site: &str) -> Result<String> {
    if site.is_empty() {
        bail!("site must not be empty");
    }
    if site.len() > 200 {
        bail!("site too long (max 200 bytes)");
    }
    for &b in site.as_bytes() {
        // 0x21..=0x7e: printable ASCII excluding space and control chars.
        if !(0x21..=0x7e).contains(&b) || b == b':' {
            bail!(
                "site must be printable ASCII with no whitespace, control chars, or ':'"
            );
        }
    }
    Ok(site.to_ascii_lowercase())
}

/// Validate a username. Spaces are allowed (some services use them), but
/// control chars, non-ASCII, and ':' are not. Case is preserved because
/// service usernames are often case-sensitive.
pub fn validate_username(user: &str) -> Result<()> {
    if user.len() > 200 {
        bail!("username too long (max 200 bytes)");
    }
    for &b in user.as_bytes() {
        // 0x20..=0x7e: printable ASCII including space.
        if !(0x20..=0x7e).contains(&b) || b == b':' {
            bail!("username must be printable ASCII with no control chars or ':'");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn site_lowercased() {
        assert_eq!(canonicalize_site("GitHub.com").unwrap(), "github.com");
    }

    #[test]
    fn site_rejects_whitespace_and_colon() {
        assert!(canonicalize_site("foo bar").is_err());
        assert!(canonicalize_site("foo\t").is_err());
        assert!(canonicalize_site("foo:bar").is_err());
        assert!(canonicalize_site("").is_err());
        assert!(canonicalize_site("café.com").is_err()); // non-ASCII
    }

    #[test]
    fn username_allows_spaces_but_not_colon() {
        assert!(validate_username("first last").is_ok());
        assert!(validate_username("me@example.com").is_ok());
        assert!(validate_username("").is_ok());
        assert!(validate_username("with:colon").is_err());
        assert!(validate_username("café").is_err());
        assert!(validate_username("nl\n").is_err());
    }
}

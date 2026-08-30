//! pwmgr — deterministic password manager backed by a Ledger hardware wallet.
//!
//! Passwords are derived on-demand from an Ed25519 signature produced by the
//! Solana app at a dedicated derivation path (m/44'/501'/255'). Nothing
//! sensitive is ever stored on disk — losing the entries file just means
//! losing the per-site policy (length, charset).

mod derive;
mod ledger;
mod store;

use anyhow::{Context, Result, bail};
use arboard::Clipboard;
use clap::{Parser, Subcommand};
use dialoguer::{Confirm, Input, Select, theme::ColorfulTheme};

use crate::{
    derive::{Charset, build_message, derive_password},
    ledger::LedgerSolana,
    store::{Entry, Store, canonicalize_site, validate_username},
};

/// Fixed hardened derivation path: m/44'/501'/0x1627ddd1'.
/// The account index is the first 4 bytes of `sha256("pwmgr")` (big-endian),
/// masked with 0x7fffffff and then OR'd with the BIP32 hardened flag. This
/// visibly encodes the app identity in the path so it's obviously reserved.
/// Do NOT import this key into a wallet used for real Solana transactions.
const PWMGR_TAG: u32 = 0x1627_ddd1; // sha256("pwmgr")[0..4] as u32 BE
const PATH: [u32; 3] = [0x8000_002c, 0x8000_01f5, 0x8000_0000 | PWMGR_TAG];

#[derive(Parser)]
#[command(name = "pwmgr", version, about)]
struct Cli {
    /// Omit to launch interactive mode.
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Add or update a site entry (no password is generated; run `get` for that).
    Add {
        site: String,
        #[arg(long, default_value = "")]
        username: String,
        #[arg(long, default_value_t = 20)]
        length: usize,
        #[arg(long, value_enum, default_value = "symbols")]
        charset: CharsetArg,
        #[arg(long, default_value_t = 0)]
        counter: u32,
        #[arg(long, default_value = "")]
        notes: String,
    },
    /// Print (or copy) the derived password for a saved site.
    /// If --site-only is given, derive without a stored entry.
    Get {
        site: String,
        /// Copy to clipboard instead of printing to stdout.
        #[arg(long)]
        copy: bool,
        /// Print even if --copy was passed.
        #[arg(long)]
        show: bool,
        /// Use these parameters and ignore any stored entry.
        #[arg(long)]
        ad_hoc: bool,
        #[arg(long, default_value = "")]
        username: String,
        #[arg(long, default_value_t = 20)]
        length: usize,
        #[arg(long, value_enum, default_value = "symbols")]
        charset: CharsetArg,
        #[arg(long, default_value_t = 0)]
        counter: u32,
    },
    /// List saved sites and their policy.
    List,
    /// Remove a saved entry.
    Rm { site: String },
    /// Print the Ledger pubkey used for derivation (for sanity checks).
    Pubkey,
    /// Print the path where entries.json lives.
    Where,
}

#[derive(Copy, Clone, clap::ValueEnum)]
enum CharsetArg {
    Symbols,
    Alphanumeric,
    Digits,
    Hex,
}
impl From<CharsetArg> for Charset {
    fn from(c: CharsetArg) -> Self {
        match c {
            CharsetArg::Symbols => Charset::Symbols,
            CharsetArg::Alphanumeric => Charset::Alphanumeric,
            CharsetArg::Digits => Charset::Digits,
            CharsetArg::Hex => Charset::Hex,
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        None => interactive(),
        Some(Cmd::Add {
            site,
            username,
            length,
            charset,
            counter,
            notes,
        }) => cmd_add(site, username, length, charset.into(), counter, notes),
        Some(Cmd::Get {
            site,
            copy,
            show,
            ad_hoc,
            username,
            length,
            charset,
            counter,
        }) => cmd_get(
            site,
            copy,
            show,
            ad_hoc,
            username,
            length,
            charset.into(),
            counter,
        ),
        Some(Cmd::List) => cmd_list(),
        Some(Cmd::Rm { site }) => cmd_rm(site),
        Some(Cmd::Pubkey) => cmd_pubkey(),
        Some(Cmd::Where) => cmd_where(),
    }
}

// ---------------------------------------------------------------------------
// Interactive mode
// ---------------------------------------------------------------------------

fn interactive() -> Result<()> {
    let theme = ColorfulTheme::default();
    let items = [
        "Get password",
        "List entries",
        "Add / update entry",
        "Remove entry",
        "Show Ledger pubkey",
        "Show config path",
        "Quit",
    ];
    loop {
        let choice = Select::with_theme(&theme)
            .with_prompt("pwmgr")
            .items(&items)
            .default(0)
            .interact_opt()
            .context("menu prompt")?;
        let result = match choice {
            Some(0) => interactive_get(&theme),
            Some(1) => cmd_list(),
            Some(2) => interactive_add(&theme),
            Some(3) => interactive_rm(&theme),
            Some(4) => cmd_pubkey(),
            Some(5) => cmd_where(),
            Some(6) | None => return Ok(()),
            _ => unreachable!(),
        };
        // Report but don't exit — errors in one action shouldn't kill the session.
        if let Err(e) = result {
            eprintln!("error: {:#}", e);
        }
        eprintln!();
    }
}

fn interactive_get(theme: &ColorfulTheme) -> Result<()> {
    let store = Store::load()?;
    if store.entries.is_empty() {
        println!("(no entries yet — pick 'Add / update entry' first)");
        return Ok(());
    }
    let labels: Vec<String> = store
        .entries
        .iter()
        .map(|e| {
            if e.username.is_empty() {
                e.site.clone()
            } else {
                format!("{}  ({})", e.site, e.username)
            }
        })
        .collect();
    let idx = match Select::with_theme(theme)
        .with_prompt("which site?")
        .items(&labels)
        .default(0)
        .interact_opt()
        .context("site prompt")?
    {
        Some(i) => i,
        None => return Ok(()),
    };
    let entry = store.entries[idx].clone();
    derive_and_copy(&entry, theme)
}

fn derive_and_copy(entry: &Entry, theme: &ColorfulTheme) -> Result<()> {
    let message = build_message(&entry.site, &entry.username, entry.counter);
    eprintln!("Approve on Ledger: {}", message);
    let ledger = LedgerSolana::open().context("open Ledger")?;
    let sig = ledger.sign_offchain(&PATH, message.as_bytes())?;
    let password = derive_password(&*sig, &message, entry.length, entry.charset)?;

    let mut cb = Clipboard::new().context("open clipboard")?;
    cb.set_text(password.as_str()).context("write clipboard")?;
    eprintln!("copied to clipboard ({} chars)", password.len());

    let reveal = Confirm::with_theme(theme)
        .with_prompt("show password?")
        .default(false)
        .interact_opt()
        .context("reveal prompt")?
        .unwrap_or(false);
    if reveal {
        println!("{}", *password);
    }
    Ok(())
}

fn interactive_add(theme: &ColorfulTheme) -> Result<()> {
    let site_raw: String = Input::with_theme(theme)
        .with_prompt("site (e.g. github.com)")
        .validate_with(|s: &String| -> Result<(), String> {
            canonicalize_site(s).map(|_| ()).map_err(|e| e.to_string())
        })
        .interact_text()
        .context("site prompt")?;
    let site = canonicalize_site(&site_raw)?;

    let existing = Store::load()?.find(&site).cloned();
    if let Some(ref e) = existing {
        eprintln!(
            "(entry exists — press Enter to keep defaults: user={:?} len={} charset={:?} counter={})",
            e.username, e.length, e.charset, e.counter
        );
    }

    let username: String = Input::with_theme(theme)
        .with_prompt("username")
        .default(existing.as_ref().map(|e| e.username.clone()).unwrap_or_default())
        .allow_empty(true)
        .validate_with(|s: &String| -> Result<(), String> {
            validate_username(s).map_err(|e| e.to_string())
        })
        .interact_text()
        .context("username prompt")?;

    let length: usize = Input::with_theme(theme)
        .with_prompt("length")
        .default(existing.as_ref().map(|e| e.length).unwrap_or(20))
        .validate_with(|n: &usize| -> Result<(), &'static str> {
            if *n > 0 && *n <= 256 {
                Ok(())
            } else {
                Err("length must be 1..=256")
            }
        })
        .interact_text()
        .context("length prompt")?;

    let charsets = ["symbols", "alphanumeric", "digits", "hex"];
    let default_charset_idx = existing
        .as_ref()
        .map(|e| match e.charset {
            Charset::Symbols => 0,
            Charset::Alphanumeric => 1,
            Charset::Digits => 2,
            Charset::Hex => 3,
        })
        .unwrap_or(0);
    let charset = match Select::with_theme(theme)
        .with_prompt("charset")
        .items(&charsets)
        .default(default_charset_idx)
        .interact()
        .context("charset prompt")?
    {
        0 => Charset::Symbols,
        1 => Charset::Alphanumeric,
        2 => Charset::Digits,
        3 => Charset::Hex,
        _ => unreachable!(),
    };

    let counter: u32 = Input::with_theme(theme)
        .with_prompt("counter (bump to rotate)")
        .default(existing.as_ref().map(|e| e.counter).unwrap_or(0))
        .interact_text()
        .context("counter prompt")?;

    let notes: String = Input::with_theme(theme)
        .with_prompt("notes")
        .default(existing.as_ref().map(|e| e.notes.clone()).unwrap_or_default())
        .allow_empty(true)
        .interact_text()
        .context("notes prompt")?;

    let mut store = Store::load()?;
    let inserted = store.upsert(Entry {
        site: site.clone(),
        username,
        length,
        charset,
        counter,
        notes,
    });
    let p = store.save()?;
    println!(
        "{} {} in {}",
        if inserted { "added" } else { "updated" },
        site,
        p.display()
    );
    Ok(())
}

fn interactive_rm(theme: &ColorfulTheme) -> Result<()> {
    let mut store = Store::load()?;
    if store.entries.is_empty() {
        println!("(no entries)");
        return Ok(());
    }
    let labels: Vec<String> = store.entries.iter().map(|e| e.site.clone()).collect();
    let idx = match Select::with_theme(theme)
        .with_prompt("remove which?")
        .items(&labels)
        .default(0)
        .interact_opt()
        .context("select prompt")?
    {
        Some(i) => i,
        None => return Ok(()),
    };
    let site = labels[idx].clone();
    let ok = Confirm::with_theme(theme)
        .with_prompt(format!("really remove {}?", site))
        .default(false)
        .interact_opt()
        .context("confirm prompt")?
        .unwrap_or(false);
    if !ok {
        println!("(kept)");
        return Ok(());
    }
    store.remove(&site);
    store.save()?;
    println!("removed {}", site);
    Ok(())
}

fn cmd_add(
    site: String,
    username: String,
    length: usize,
    charset: Charset,
    counter: u32,
    notes: String,
) -> Result<()> {
    let site = canonicalize_site(&site)?;
    validate_username(&username)?;
    if length == 0 || length > 256 {
        bail!("length must be 1..=256");
    }
    let mut store = Store::load()?;
    let entry = Entry {
        site: site.clone(),
        username,
        length,
        charset,
        counter,
        notes,
    };
    let inserted = store.upsert(entry);
    let path = store.save()?;
    println!(
        "{} {} in {}",
        if inserted { "added" } else { "updated" },
        site,
        path.display()
    );
    Ok(())
}

fn cmd_get(
    site: String,
    copy: bool,
    show: bool,
    ad_hoc: bool,
    username: String,
    length: usize,
    charset: Charset,
    counter: u32,
) -> Result<()> {
    let site = canonicalize_site(&site)?;
    let entry = if ad_hoc {
        validate_username(&username)?;
        Entry {
            site: site.clone(),
            username,
            length,
            charset,
            counter,
            notes: String::new(),
        }
    } else {
        let store = Store::load()?;
        store
            .find(&site)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("no entry for '{}'. Use `add` first or pass --ad-hoc", site))?
    };

    let message = build_message(&entry.site, &entry.username, entry.counter);
    eprintln!("Approve on Ledger: {}", message);
    let ledger = LedgerSolana::open().context("open Ledger")?;
    let sig = ledger.sign_offchain(&PATH, message.as_bytes())?;
    let password = derive_password(&*sig, &message, entry.length, entry.charset)?;

    if copy {
        let mut cb = Clipboard::new().context("open clipboard")?;
        cb.set_text(password.as_str()).context("write clipboard")?;
        if show {
            println!("{}", *password);
        }
        eprintln!("(copied to clipboard, {} chars)", password.len());
    } else {
        println!("{}", *password);
    }
    Ok(())
}

fn cmd_list() -> Result<()> {
    let store = Store::load()?;
    if store.entries.is_empty() {
        println!("(no entries; use `pwmgr add <site>` to add one)");
        return Ok(());
    }
    println!("{:<32} {:<24} {:>4} {:<12} {:>4}", "SITE", "USER", "LEN", "CHARSET", "CTR");
    for e in &store.entries {
        println!(
            "{:<32} {:<24} {:>4} {:<12} {:>4}",
            truncate(&e.site, 32),
            truncate(&e.username, 24),
            e.length,
            format!("{:?}", e.charset).to_lowercase(),
            e.counter,
        );
    }
    Ok(())
}

fn cmd_rm(site: String) -> Result<()> {
    let site = canonicalize_site(&site)?;
    let mut store = Store::load()?;
    if !store.remove(&site) {
        bail!("no entry for '{}'", site);
    }
    let path = store.save()?;
    println!("removed {} from {}", site, path.display());
    Ok(())
}

fn cmd_pubkey() -> Result<()> {
    let ledger = LedgerSolana::open().context("open Ledger")?;
    let pk = ledger.get_pubkey(&PATH)?;
    println!("{}", bs58_encode(&pk));
    Ok(())
}

fn cmd_where() -> Result<()> {
    println!("{}", Store::path()?.display());
    Ok(())
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(n.saturating_sub(1)).collect();
        t.push('…');
        t
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn pwmgr_tag_matches_sha256() {
        let h = Sha256::digest(b"pwmgr");
        let expected = u32::from_be_bytes([h[0], h[1], h[2], h[3]]) & 0x7fff_ffff;
        assert_eq!(PWMGR_TAG, expected, "PWMGR_TAG drifted from sha256(\"pwmgr\")");
        assert_eq!(PATH[2] & 0x8000_0000, 0x8000_0000, "path component must be hardened");
        assert_eq!(PATH[2] & 0x7fff_ffff, PWMGR_TAG);
    }
}

/// Minimal Base58 encoder (Bitcoin alphabet) — used only to print the pubkey.
fn bs58_encode(input: &[u8]) -> String {
    const ALPH: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut leading_zeros = 0;
    for &b in input {
        if b == 0 {
            leading_zeros += 1;
        } else {
            break;
        }
    }
    let mut num = input.to_vec();
    let mut out = Vec::new();
    let mut start = leading_zeros;
    while start < num.len() {
        let mut carry = 0u32;
        for byte in num.iter_mut().skip(start) {
            let v = (carry << 8) | (*byte as u32);
            *byte = (v / 58) as u8;
            carry = v % 58;
        }
        out.push(ALPH[carry as usize]);
        while start < num.len() && num[start] == 0 {
            start += 1;
        }
    }
    for _ in 0..leading_zeros {
        out.push(ALPH[0]);
    }
    out.reverse();
    String::from_utf8(out).unwrap()
}

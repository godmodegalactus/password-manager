//! pwmgr — deterministic password manager backed by a Ledger hardware wallet.
//!
//! Passwords are derived on-demand from a secp256k1 ECDSA signature produced
//! by the Ethereum app's EIP-191 `personal_sign` at a dedicated derivation
//! path (m/44'/60'/0x1627ddd1'/0/0). Nothing sensitive is ever stored on
//! disk — losing the entries file just means losing the per-site policy
//! (length, charset).

mod derive;
mod ledger;
mod store;

use anyhow::{Context, Result, bail};
use arboard::Clipboard;
use clap::{Parser, Subcommand};
use dialoguer::{Confirm, Input, Select, theme::ColorfulTheme};
use zeroize::Zeroizing;

use crate::{
    derive::{Charset, build_message, derive_password},
    ledger::LedgerEth,
    store::{Entry, Store, canonicalize_site, validate_username},
};

/// Standard BIP44 Ethereum path shape (m/44'/60'/account'/change/address_idx)
/// with a pwmgr-reserved account index. The account is `sha256("pwmgr")[0..4]`
/// masked with 0x7fffffff and OR'd with the BIP32 hardened flag, so the app
/// identity is visible in the path and the account is obviously not one you'd
/// ever type by hand. Do NOT import this key into a wallet you use for real
/// Ethereum transactions — an attacker who tricked you into personal-signing
/// a `pwmgr:v1:...` message with that key could recover the site's password.
const PWMGR_TAG: u32 = 0x1627_ddd1; // sha256("pwmgr")[0..4] as u32 BE
const PATH: [u32; 5] = [
    0x8000_002c,             // 44'
    0x8000_003c,             // 60' (Ethereum)
    0x8000_0000 | PWMGR_TAG, // pwmgr-reserved account
    0,                       // change
    0,                       // address index
];

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
    /// Remove a saved entry. If the site has more than one account, pass --username.
    Rm {
        site: String,
        #[arg(long, default_value = "")]
        username: String,
    },
    /// Print the Ledger address used for derivation (for sanity checks).
    Address,
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
        Some(Cmd::Rm { site, username }) => cmd_rm(site, username),
        Some(Cmd::Address) => cmd_address(),
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
        "Show Ledger address",
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
            Some(4) => cmd_address(),
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

/// Ask the Ledger to sign `entry`'s message and stretch the signature into a
/// password. Prints the "Approve on Ledger:" hint before opening the device
/// so the user knows what to look at.
fn sign_and_derive(entry: &Entry) -> Result<Zeroizing<String>> {
    let message = build_message(&entry.site, &entry.username, entry.counter);
    eprintln!("Approve on Ledger: {}", message);
    let ledger = LedgerEth::open().context("open Ledger")?;
    let sig = ledger.sign_personal(&PATH, message.as_bytes())?;
    derive_password(&*sig, &message, entry.length, entry.charset)
}

fn derive_and_copy(entry: &Entry, theme: &ColorfulTheme) -> Result<()> {
    let password = sign_and_derive(entry)?;

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

    // Show any existing accounts for this site so the user knows whether
    // they're editing one or adding a new one. Existing-entry defaults are
    // resolved after the username is entered, since (site, username) is
    // the identity of an entry.
    let store_before = Store::load()?;
    let siblings = store_before.find_by_site(&site);
    if !siblings.is_empty() {
        eprintln!("(existing accounts for {}:)", site);
        for e in &siblings {
            eprintln!("  - {:?}", e.username);
        }
    }

    let username: String = Input::with_theme(theme)
        .with_prompt("username")
        .allow_empty(true)
        .validate_with(|s: &String| -> Result<(), String> {
            validate_username(s).map_err(|e| e.to_string())
        })
        .interact_text()
        .context("username prompt")?;

    let existing = store_before.find(&site, &username).cloned();
    if let Some(ref e) = existing {
        eprintln!(
            "(entry exists — press Enter to keep defaults: len={} charset={:?} counter={})",
            e.length, e.charset, e.counter
        );
    }

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

    let entry = Entry {
        site: site.clone(),
        username,
        length,
        charset,
        counter,
        notes,
    };
    let mut store = Store::load()?;
    let inserted = store.upsert(entry.clone());
    let p = store.save()?;
    println!(
        "{} {} ({}) in {}",
        if inserted { "added" } else { "updated" },
        site,
        display_username(&entry.username),
        p.display()
    );
    // Derive the password now so the user doesn't have to run `get` right
    // after `add` — the whole point of registering an entry is to use it.
    derive_and_copy(&entry, theme)
}

fn display_username(user: &str) -> &str {
    if user.is_empty() { "(no user)" } else { user }
}

fn interactive_rm(theme: &ColorfulTheme) -> Result<()> {
    let mut store = Store::load()?;
    if store.entries.is_empty() {
        println!("(no entries)");
        return Ok(());
    }
    let labels: Vec<String> = store
        .entries
        .iter()
        .map(|e| format!("{}  ({})", e.site, display_username(&e.username)))
        .collect();
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
    let target = store.entries[idx].clone();
    let ok = Confirm::with_theme(theme)
        .with_prompt(format!(
            "really remove {} ({})?",
            target.site,
            display_username(&target.username)
        ))
        .default(false)
        .interact_opt()
        .context("confirm prompt")?
        .unwrap_or(false);
    if !ok {
        println!("(kept)");
        return Ok(());
    }
    store.remove(&target.site, &target.username);
    store.save()?;
    println!("removed {} ({})", target.site, display_username(&target.username));
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
    let inserted = store.upsert(entry.clone());
    let path = store.save()?;
    eprintln!(
        "{} {} ({}) in {}",
        if inserted { "added" } else { "updated" },
        site,
        display_username(&entry.username),
        path.display()
    );
    // Derive right after saving so scripts can pipe the password without a
    // second `pwmgr get` round-trip. Password goes to stdout, everything
    // else to stderr.
    let password = sign_and_derive(&entry)?;
    println!("{}", *password);
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
        validate_username(&username)?;
        let store = Store::load()?;
        resolve_entry(&store, &site, &username)?
    };

    let password = sign_and_derive(&entry)?;

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

fn cmd_rm(site: String, username: String) -> Result<()> {
    let site = canonicalize_site(&site)?;
    validate_username(&username)?;
    let mut store = Store::load()?;
    let target = resolve_entry(&store, &site, &username)?;
    store.remove(&target.site, &target.username);
    let path = store.save()?;
    println!(
        "removed {} ({}) from {}",
        target.site,
        display_username(&target.username),
        path.display()
    );
    Ok(())
}

/// Resolve which stored entry the user meant.
///
/// - Exact `(site, username)` match wins.
/// - Otherwise, if the user didn't supply a username *and* the site has
///   exactly one saved account, use it.
/// - If the site has multiple accounts and none matched, bail with the
///   list so the caller can retry with `--username`.
fn resolve_entry(store: &Store, site: &str, username: &str) -> Result<Entry> {
    if let Some(e) = store.find(site, username) {
        return Ok(e.clone());
    }
    let siblings = store.find_by_site(site);
    if username.is_empty() && siblings.len() == 1 {
        return Ok(siblings[0].clone());
    }
    if siblings.is_empty() {
        bail!("no entry for '{}'. Use `add` first or pass --ad-hoc", site);
    }
    let users = siblings
        .iter()
        .map(|e| format!("{:?}", e.username))
        .collect::<Vec<_>>()
        .join(", ");
    bail!(
        "site '{}' has multiple accounts ({}). Pass --username to pick one.",
        site,
        users
    );
}

fn cmd_address() -> Result<()> {
    let ledger = LedgerEth::open().context("open Ledger")?;
    let addr = ledger.get_address(&PATH)?;
    println!("{}", addr);
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
    fn path_matches_bip44_ethereum_with_pwmgr_account() {
        let h = Sha256::digest(b"pwmgr");
        let expected = u32::from_be_bytes([h[0], h[1], h[2], h[3]]) & 0x7fff_ffff;
        assert_eq!(PWMGR_TAG, expected, "PWMGR_TAG drifted from sha256(\"pwmgr\")");
        assert_eq!(PATH[0], 0x8000_002c, "purpose must be BIP44 (44')");
        assert_eq!(PATH[1], 0x8000_003c, "coin must be Ethereum (60')");
        assert_eq!(PATH[2] & 0x8000_0000, 0x8000_0000, "account must be hardened");
        assert_eq!(PATH[2] & 0x7fff_ffff, PWMGR_TAG);
        assert_eq!(PATH[3], 0, "change must be 0");
        assert_eq!(PATH[4], 0, "address_index must be 0");
    }
}

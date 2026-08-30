//! Turn a 64-byte Ed25519 signature into a password of the requested
//! length and character set, using HKDF-SHA256 as a stretcher.

use anyhow::{Result, bail};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

/// Message signed on the Ledger. Must be printable ASCII.
/// v1 format: `pwmgr:v1:<site>:<username>:<counter>`.
pub fn build_message(site: &str, username: &str, counter: u32) -> String {
    format!("pwmgr:v1:{}:{}:{}", site, username, counter)
}

/// Charset alphabets. Selected via CLI flag or per-entry policy.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Charset {
    /// letters + digits + common symbols
    Symbols,
    /// letters + digits, no symbols
    Alphanumeric,
    /// digits only (e.g. PINs)
    Digits,
    /// lowercase hex
    Hex,
}

impl Charset {
    fn alphabet(self) -> &'static [u8] {
        match self {
            Charset::Symbols => {
                b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{};:,.<>/?"
            }
            Charset::Alphanumeric => {
                b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
            }
            Charset::Digits => b"0123456789",
            Charset::Hex => b"0123456789abcdef",
        }
    }
}

/// Deterministically derive a password of `length` characters over `charset`
/// from the given signature bytes. Uses HKDF-SHA256 with a domain-separating
/// info string, then rejection-samples bytes to avoid modulo bias.
///
/// Takes a 65-byte input because that's what the Ethereum app's personal_sign
/// returns ([v, r, s]); HKDF doesn't care about the length, but pinning the
/// type keeps callers honest.
pub fn derive_password(
    signature: &[u8; 65],
    message: &str,
    length: usize,
    charset: Charset,
) -> Result<Zeroizing<String>> {
    if length == 0 || length > 256 {
        bail!("length must be between 1 and 256");
    }
    let alphabet = charset.alphabet();
    let n = alphabet.len() as u16;
    // Largest multiple of n that fits in a u8 (256). Bytes >= threshold get
    // discarded to keep the distribution uniform.
    let threshold: u16 = 256 - (256 % n);

    // HKDF: extract with no salt, expand with an info string that binds
    // message + charset + length so different callers can't collide.
    let hk = Hkdf::<Sha256>::new(None, signature);
    let info = format!("pwmgr:v1:derive:{}:{}:{:?}", message, length, charset);

    let mut out = Zeroizing::new(String::with_capacity(length));
    // Expand in generous chunks; loop again if too many rejections.
    let mut counter: u32 = 0;
    while out.len() < length {
        let need = (length - out.len()).saturating_mul(2).max(32);
        let mut buf = Zeroizing::new(vec![0u8; need]);
        // HKDF-Expand supports up to 255*HashLen bytes per call; loop with a
        // salted info if we ever need more (won't happen for realistic sizes).
        let expand_info = format!("{}:chunk={}", info, counter);
        hk.expand(expand_info.as_bytes(), &mut buf)
            .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;
        for &b in buf.iter() {
            if (b as u16) < threshold {
                out.push(alphabet[(b as usize) % (n as usize)] as char);
                if out.len() == length {
                    break;
                }
            }
        }
        counter = counter.checked_add(1).ok_or_else(|| anyhow::anyhow!("HKDF chunk overflow"))?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_inputs_same_password() {
        let sig = [7u8; 65];
        let a = derive_password(&sig, "pwmgr:v1:github.com:me:0", 20, Charset::Symbols).unwrap();
        let b = derive_password(&sig, "pwmgr:v1:github.com:me:0", 20, Charset::Symbols).unwrap();
        assert_eq!(*a, *b);
        assert_eq!(a.len(), 20);
    }

    #[test]
    fn different_message_different_password() {
        let sig = [7u8; 65];
        let a = derive_password(&sig, "pwmgr:v1:github.com:me:0", 20, Charset::Symbols).unwrap();
        let b = derive_password(&sig, "pwmgr:v1:gitlab.com:me:0", 20, Charset::Symbols).unwrap();
        assert_ne!(*a, *b);
    }

    #[test]
    fn digits_charset_only_digits() {
        let sig = [42u8; 65];
        let p = derive_password(&sig, "site", 12, Charset::Digits).unwrap();
        assert!(p.chars().all(|c| c.is_ascii_digit()));
    }
}

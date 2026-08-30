//! Minimal Ledger-over-HID client for the Ethereum app.
//!
//! Implements just enough of the APDU + transport protocol to:
//!   - fetch the secp256k1 address at a derivation path
//!   - sign an EIP-191 "personal message" at a derivation path
//!
//! ECDSA over secp256k1 with RFC 6979 nonces is deterministic — the same
//! (key, message) pair always yields the same signature, which is all the
//! HKDF password derivation needs. The Ethereum app displays personal
//! messages verbatim (no envelope; no blind-signing required for ASCII).
//!
//! Reference: LedgerHQ/app-ethereum, doc/ethapp.adoc.

use anyhow::{Context, Result, anyhow, bail};
use hidapi::{HidApi, HidDevice};
use zeroize::Zeroizing;

const LEDGER_VID: u16 = 0x2c97;

const CHANNEL_ID: u16 = 0x0101;
const APDU_TAG: u8 = 0x05;
const APDU_CLA: u8 = 0xe0;

const INS_GET_PUBLIC_KEY: u8 = 0x02;
const INS_SIGN_PERSONAL_MESSAGE: u8 = 0x08;

const P1_NON_CONFIRM: u8 = 0x00;
const P1_FIRST_CHUNK: u8 = 0x00;
const P1_MORE_CHUNK: u8 = 0x80;

const HID_PACKET_SIZE: usize = 64;
const MAX_APDU_CHUNK: usize = 255;

pub struct LedgerEth {
    dev: HidDevice,
}

impl LedgerEth {
    /// Open the first Ledger device found on USB HID.
    pub fn open() -> Result<Self> {
        let api = HidApi::new().context("failed to init hidapi")?;
        let info = api
            .device_list()
            .find(|d| d.vendor_id() == LEDGER_VID && d.usage_page() == 0xffa0)
            .or_else(|| api.device_list().find(|d| d.vendor_id() == LEDGER_VID))
            .ok_or_else(|| anyhow!("no Ledger device found on USB"))?;
        let dev = info
            .open_device(&api)
            .context("failed to open Ledger HID device")?;
        Ok(Self { dev })
    }

    /// Fetch the checksummed hex Ethereum address at the given hardened path
    /// (e.g. "0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B"). Non-confirming —
    /// no prompt appears on the device. The uppercase-hex payload the app
    /// returns is EIP-55 checksummed; we prefix "0x" and hand it back as-is.
    pub fn get_address(&self, path: &[u32]) -> Result<String> {
        let data = serialize_path(path);
        let resp = self.exchange(INS_GET_PUBLIC_KEY, P1_NON_CONFIRM, 0, &data)?;
        // Layout: [pubkey_len (1)][pubkey (=65)][address_len (1)][address (=40 ASCII hex)]
        if resp.len() < 1 {
            bail!("empty GET_PUBLIC_KEY response");
        }
        let pk_len = resp[0] as usize;
        let addr_len_off = 1 + pk_len;
        if resp.len() < addr_len_off + 1 {
            bail!("short GET_PUBLIC_KEY response");
        }
        let addr_len = resp[addr_len_off] as usize;
        let addr_off = addr_len_off + 1;
        if resp.len() < addr_off + addr_len {
            bail!("truncated address in GET_PUBLIC_KEY response");
        }
        let ascii = &resp[addr_off..addr_off + addr_len];
        let hex = std::str::from_utf8(ascii)
            .context("address is not ASCII hex")?;
        Ok(format!("0x{}", hex))
    }

    /// Sign an EIP-191 personal message with the secp256k1 key at `path`.
    /// The app internally hashes `keccak256("\x19Ethereum Signed Message:\n"
    /// || len(msg) || msg)` and signs that. Returns the 65-byte [v, r, s]
    /// signature, wrapped so drop zeros the memory.
    pub fn sign_personal(&self, path: &[u32], message: &[u8]) -> Result<Zeroizing<[u8; 65]>> {
        // We restrict callers to printable ASCII so the app can show the
        // message verbatim (rather than falling back to hex) and so the
        // signed material has no ambiguity.
        if !message.iter().all(|&b| (0x20..=0x7e).contains(&b)) {
            bail!("password derivation message must be printable ASCII");
        }
        if message.len() > u32::MAX as usize {
            bail!("message too long");
        }

        // First-chunk header: [path_len][path...][msg_len BE u32]. Message
        // bytes then fill the rest of the first APDU; anything left flows
        // into P1_MORE_CHUNK continuations of up to 255 raw message bytes.
        let path_bytes = serialize_path(path);
        let mut header = Vec::with_capacity(path_bytes.len() + 4);
        header.extend_from_slice(&path_bytes);
        header.extend_from_slice(&(message.len() as u32).to_be_bytes());
        if header.len() > MAX_APDU_CHUNK {
            bail!("derivation path too long for first APDU");
        }

        let first_room = MAX_APDU_CHUNK - header.len();
        let first_take = std::cmp::min(first_room, message.len());
        let mut first_chunk = Vec::with_capacity(header.len() + first_take);
        first_chunk.extend_from_slice(&header);
        first_chunk.extend_from_slice(&message[..first_take]);

        let mut resp = self.exchange(
            INS_SIGN_PERSONAL_MESSAGE,
            P1_FIRST_CHUNK,
            0,
            &first_chunk,
        )?;

        let mut sent = first_take;
        while sent < message.len() {
            let take = std::cmp::min(MAX_APDU_CHUNK, message.len() - sent);
            resp = self.exchange(
                INS_SIGN_PERSONAL_MESSAGE,
                P1_MORE_CHUNK,
                0,
                &message[sent..sent + take],
            )?;
            sent += take;
        }

        if resp.len() != 65 {
            bail!("unexpected signature length: {}", resp.len());
        }
        let mut sig = Zeroizing::new([0u8; 65]);
        sig.copy_from_slice(&resp);
        Ok(sig)
    }

    // -- transport ---------------------------------------------------------

    /// Send an APDU and read the response, stripping the trailing status word.
    /// Response is wrapped in `Zeroizing` defensively — sign responses carry
    /// the signature and must not linger in memory.
    fn exchange(&self, ins: u8, p1: u8, p2: u8, data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        self.write_apdu(ins, p1, p2, data)?;
        self.read_apdu()
    }

    fn write_apdu(&self, ins: u8, p1: u8, p2: u8, data: &[u8]) -> Result<()> {
        // Full APDU: [CLA, INS, P1, P2, LC, DATA...]. Ledger transport wraps this
        // in [APDU_TOTAL_LEN_BE_u16] plus 64-byte HID frames with [channel, tag, seq].
        // LC is one byte, so payload must fit in 255 bytes; bail loudly instead of
        // silently truncating if a future caller violates that.
        if data.len() > 255 {
            bail!("APDU payload too large ({} bytes, max 255)", data.len());
        }
        let mut apdu = Vec::with_capacity(5 + data.len());
        apdu.push(APDU_CLA);
        apdu.push(ins);
        apdu.push(p1);
        apdu.push(p2);
        apdu.push(data.len() as u8);
        apdu.extend_from_slice(data);

        // Prepend 2-byte BE length prefix to the APDU for the transport layer.
        let apdu_len = apdu.len() as u16;
        let mut framed = Vec::with_capacity(2 + apdu.len());
        framed.extend_from_slice(&apdu_len.to_be_bytes());
        framed.extend_from_slice(&apdu);

        // Split into HID frames.
        let mut seq: u16 = 0;
        let mut offset = 0;
        while offset < framed.len() {
            let mut frame = [0u8; HID_PACKET_SIZE];
            frame[0..2].copy_from_slice(&CHANNEL_ID.to_be_bytes());
            frame[2] = APDU_TAG;
            frame[3..5].copy_from_slice(&seq.to_be_bytes());
            let body = &mut frame[5..];
            let take = std::cmp::min(body.len(), framed.len() - offset);
            body[..take].copy_from_slice(&framed[offset..offset + take]);
            self.dev
                .write(&frame)
                .context("HID write failed")?;
            offset += take;
            seq = seq.checked_add(1).ok_or_else(|| anyhow!("HID seq overflow"))?;
        }
        Ok(())
    }

    fn read_apdu(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut expected_len: usize = 0;
        let mut buf: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
        let mut seq: u16 = 0;

        loop {
            let mut frame = [0u8; HID_PACKET_SIZE];
            let n = self.dev.read(&mut frame).context("HID read failed")?;
            if n < 5 {
                bail!("short HID frame");
            }
            if frame[0..2] != CHANNEL_ID.to_be_bytes()
                || frame[2] != APDU_TAG
                || frame[3..5] != seq.to_be_bytes()
            {
                bail!("unexpected HID frame header");
            }
            let mut off = 5;
            if seq == 0 {
                if n < 7 {
                    bail!("short first HID frame");
                }
                expected_len = u16::from_be_bytes([frame[5], frame[6]]) as usize;
                off = 7;
            }
            let remaining = expected_len - buf.len();
            let take = std::cmp::min(remaining, n - off);
            buf.extend_from_slice(&frame[off..off + take]);
            if buf.len() >= expected_len {
                break;
            }
            seq = seq.checked_add(1).ok_or_else(|| anyhow!("HID seq overflow"))?;
        }

        if buf.len() < 2 {
            bail!("APDU response missing status word");
        }
        let n = buf.len();
        let sw_hi = buf[n - 2];
        let sw_lo = buf[n - 1];
        let sw = ((sw_hi as u16) << 8) | (sw_lo as u16);
        buf.truncate(n - 2);
        match sw {
            0x9000 => Ok(buf),
            0x6985 => bail!("user rejected the request on the device"),
            0x6d00 => bail!("instruction not supported — is the Ethereum app open?"),
            0x6e00 => bail!("app not open on device"),
            other => bail!("Ledger error: SW=0x{:04x}", other),
        }
    }
}

/// Encode a BIP32 derivation path as: [num_indices][index_1 BE u32]...
fn serialize_path(path: &[u32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 4 * path.len());
    out.push(path.len() as u8);
    for i in path {
        out.extend_from_slice(&i.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_serialization() {
        // m/44'/60'/0'/0/0
        let path = [0x8000_002c, 0x8000_003c, 0x8000_0000, 0, 0];
        let got = serialize_path(&path);
        assert_eq!(
            got,
            vec![
                5,
                0x80, 0, 0, 0x2c,
                0x80, 0, 0, 0x3c,
                0x80, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
            ]
        );
    }

    /// Regression pin: fixed 65-byte "signature" bytes and a fixed message
    /// must always derive the same password. If this fails, either the HKDF
    /// info string or the alphabet changed — both silently rotate every
    /// user's passwords, so do NOT update the golden value without a
    /// migration plan.
    #[test]
    fn golden_password_pins_derivation() {
        use crate::derive::{Charset, build_message, derive_password};

        // Pretend the Ledger returned this signature for the message below.
        // The bytes don't need to be a valid ECDSA signature — HKDF only
        // treats them as input key material.
        let mut sig = [0u8; 65];
        for (i, b) in sig.iter_mut().enumerate() {
            *b = i as u8;
        }
        let message = build_message("example.com", "alice", 0);
        let password = derive_password(&sig, &message, 20, Charset::Symbols).unwrap();
        assert_eq!(&*password as &str, ":VB5qou]$AuzJfGRv,/;");
    }
}

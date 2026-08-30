//! Minimal Ledger-over-HID client for the Solana app.
//!
//! Implements just enough of the APDU + transport protocol to:
//!   - fetch the ed25519 pubkey at a derivation path
//!   - sign an off-chain message at a derivation path
//!
//! Reference: agave/remote-wallet/src/ledger.rs (Solana's own client).

use anyhow::{Context, Result, anyhow, bail};
use hidapi::{HidApi, HidDevice};
use zeroize::Zeroizing;

const LEDGER_VID: u16 = 0x2c97;

const CHANNEL_ID: u16 = 0x0101;
const APDU_TAG: u8 = 0x05;
const APDU_CLA: u8 = 0xe0;

const INS_GET_PUBKEY: u8 = 0x05;
const INS_SIGN_OFFCHAIN_MESSAGE: u8 = 0x07;

const P1_NON_CONFIRM: u8 = 0x00;
const P1_CONFIRM: u8 = 0x01;
const P2_EXTEND: u8 = 0x01;
const P2_MORE: u8 = 0x02;

const HID_PACKET_SIZE: usize = 64;
const MAX_APDU_CHUNK: usize = 255;

const OFFCHAIN_SIGNING_DOMAIN: &[u8; 16] = b"\xffsolana offchain";
const OFFCHAIN_HEADER_VERSION: u8 = 0;
const OFFCHAIN_APPLICATION_DOMAIN_LEN: usize = 32;
const OFFCHAIN_FORMAT_ASCII: u8 = 0;

pub struct LedgerSolana {
    dev: HidDevice,
}

impl LedgerSolana {
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

    /// Fetch the ed25519 pubkey (32 bytes) at the given hardened path.
    pub fn get_pubkey(&self, path: &[u32]) -> Result<[u8; 32]> {
        let data = serialize_path(path);
        let resp = self.exchange(INS_GET_PUBKEY, P1_NON_CONFIRM, 0, &data)?;
        if resp.len() != 32 {
            bail!("unexpected pubkey length: {}", resp.len());
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&resp);
        Ok(out)
    }

    /// Sign an off-chain message with the ed25519 key at the given path.
    /// Returns the 64-byte signature, wrapped so drop zeros the memory.
    pub fn sign_offchain(&self, path: &[u32], message: &[u8]) -> Result<Zeroizing<[u8; 64]>> {
        // The Solana app parses the envelope's `signers` list and rejects with
        // InvalidMessageHeader unless the pubkey derived at `path` appears in
        // it — so fetch our own pubkey (non-confirming) and include it.
        let signer = self.get_pubkey(path)?;
        let envelope = build_offchain_envelope(message, &signer)?;
        let mut payload = serialize_path(path);
        payload.extend_from_slice(&envelope);

        let mut p2: u8 = 0;
        let mut slice = payload.as_slice();
        while slice.len() > MAX_APDU_CHUNK {
            let (chunk, rest) = slice.split_at(MAX_APDU_CHUNK);
            self.exchange(INS_SIGN_OFFCHAIN_MESSAGE, P1_CONFIRM, p2 | P2_MORE, chunk)?;
            slice = rest;
            p2 |= P2_EXTEND;
        }
        let resp = self.exchange(INS_SIGN_OFFCHAIN_MESSAGE, P1_CONFIRM, p2, slice)?;

        if resp.len() != 64 {
            bail!("unexpected signature length: {}", resp.len());
        }
        let mut sig = Zeroizing::new([0u8; 64]);
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
            0x6d00 => bail!("instruction not supported — is the Solana app open?"),
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

/// Wrap `message` in the Solana v0 off-chain message envelope, as parsed by
/// the app-solana Ledger firmware:
///   [signing_domain 16B]
///   [version=0 1B]
///   [application_domain 32B]   (zeroed — no per-app binding)
///   [format=0 1B]              (RestrictedAscii)
///   [signer_count=1 1B]
///   [signer 32B]               (must match the pubkey the device derives)
///   [len LE u16]
///   [message]
fn build_offchain_envelope(message: &[u8], signer: &[u8; 32]) -> Result<Vec<u8>> {
    if !message.iter().all(|&b| (0x20..=0x7e).contains(&b)) {
        bail!("password derivation message must be printable ASCII");
    }
    if message.len() > u16::MAX as usize {
        bail!("off-chain message too long");
    }
    let mut env = Vec::with_capacity(
        OFFCHAIN_SIGNING_DOMAIN.len()
            + 1
            + OFFCHAIN_APPLICATION_DOMAIN_LEN
            + 1
            + 1
            + signer.len()
            + 2
            + message.len(),
    );
    env.extend_from_slice(OFFCHAIN_SIGNING_DOMAIN);
    env.push(OFFCHAIN_HEADER_VERSION);
    env.extend_from_slice(&[0u8; OFFCHAIN_APPLICATION_DOMAIN_LEN]);
    env.push(OFFCHAIN_FORMAT_ASCII);
    env.push(1);
    env.extend_from_slice(signer);
    env.extend_from_slice(&(message.len() as u16).to_le_bytes());
    env.extend_from_slice(message);
    Ok(env)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_matches_reference() {
        // Hand-computed reference for the v0 header layout the app-solana
        // firmware parses (see libsol/include/sol/offchain_message_signing.h).
        let signer = [0xAAu8; 32];
        let got = build_offchain_envelope(b"Test Message", &signer).unwrap();
        let mut want: Vec<u8> = Vec::new();
        want.extend_from_slice(b"\xffsolana offchain"); // signing_domain (16)
        want.push(0); // version
        want.extend_from_slice(&[0u8; 32]); // application_domain
        want.push(0); // format (RestrictedAscii)
        want.push(1); // signer_count
        want.extend_from_slice(&signer); // signers[0]
        want.extend_from_slice(&12u16.to_le_bytes()); // message length
        want.extend_from_slice(b"Test Message");
        assert_eq!(got, want);
        assert_eq!(got.len(), 16 + 1 + 32 + 1 + 1 + 32 + 2 + 12);
    }

    /// Golden regression test: pins the exact password derived from a fixed
    /// Ed25519 keypair signing a fixed pwmgr message through the real V0
    /// envelope. If this test fails, either the envelope layout or the
    /// derivation changed — both silently rotate every user's passwords, so
    /// do NOT update the golden value without a migration plan.
    #[test]
    fn golden_password_end_to_end() {
        use crate::derive::{Charset, build_message, derive_password};
        use ed25519_dalek::{Signer, SigningKey};

        let sk = SigningKey::from_bytes(&[0x11u8; 32]);
        let pk = sk.verifying_key().to_bytes();

        let message = build_message("example.com", "alice", 0);
        let envelope = build_offchain_envelope(message.as_bytes(), &pk).unwrap();
        let sig_bytes: [u8; 64] = sk.sign(&envelope).to_bytes();

        let password = derive_password(&sig_bytes, &message, 20, Charset::Symbols).unwrap();
        assert_eq!(&*password as &str, "[m08_>43ViG&<3[0xBl3");
    }

    #[test]
    fn path_serialization() {
        // m/44'/501'/255'
        let path = [0x8000_002c, 0x8000_01f5, 0x8000_00ff];
        let got = serialize_path(&path);
        assert_eq!(
            got,
            vec![3, 0x80, 0, 0, 0x2c, 0x80, 0, 1, 0xf5, 0x80, 0, 0, 0xff]
        );
    }
}

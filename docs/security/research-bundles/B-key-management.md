# Research Prompt B — Transport-to-First-Field SCP03/PBS Lifecycle

## Research question

Design and attack a production provisioning + first-field lifecycle:

1. The factory installs and locks only per-device SE transport and
   attestation state, then ships at RDP0 so the owner can verify the MCU
   before first power. It does not install the final pairing secret, perform
   the BHK first write, create the wallet seed, or set RDP2.
2. On first field boot, the secure-application `rdp2-self-lock` candidate
   self-locks RDP2, performs the BHK first write, and journal-rotates the
   transport credentials to BHK-rooted SE050 keys and a fresh-TRNG-salted
   DHUK OPTIGA PBS before the seed wizard. The code exists but is not an
   approved production ceremony.
3. Page 126 stores only the DHUK-wrapped BHK; page 127 owns the append-only
   first-boot journal and persisted salt. Require authenticated per-device
   handoff and authenticate-before-rotate, then prove old/new/KVN recovery,
   power-cut safety, and the exact E140 lifecycle ordering without inventing
   an HUK-wrapped SCP03/PBS secret blob.
4. Establish verifiable per-device attestation binding the physical SE050
   and OPTIGA UIDs to the STM32 UID so swap attacks fail at boot.

Constraints: authenticate-before-rotate, old/new/KVN recovery, the exact E140
ratchet-versus-final-PBS ordering, and silicon receipts are OPEN and
owner-gated. Do not infer authority for an irreversible ceremony from this
research prompt.

Deliverables: protocol/state diagram, durable-state sketch, power-cut matrix,
and the minimum STM32U585 SAES API usage pattern. Clearly separate measured
facts, current code, proposed ceremony steps, and still-open silicon gates.


---

## Project context (condensed; current sources are linked in each bundle)

**What this is.** PQSigner OS: a post-quantum ERC-4337 smart-wallet
firmware for STM32U585 (Cortex-M33 + ARM TrustZone) on the
B-U585I-IOT02A Discovery board. Only external interface is USB-C. No
Bluetooth, no UART, no debug access in production (RDP Level 2
planned).

**Secure elements.** **Dual**-SE architecture, not single:
- **NXP SE050** (I2C1, addr `0x48`, EAL6+): stores `half_E` of XOR-
  split BIP-39 entropy. Hardware PIN gate via UserID (10 attempts).
- **Infineon OPTIGA Trust M V3** (I2C1, addr `0x30`, EAL6+): stores
  `half_O`. Shielded Connection (AES-128-CCM-8) for bus encryption.

Both chips are mandatory. Neither alone reveals any bit of the seed —
only `half_O XOR half_E = entropy`.

**Why signing must run on the Cortex-M33, not the SE.** Bootstrap and
slot signatures both use the project's **SPHINCS+C10** hash-based
post-quantum scheme; there is no classical or ML-DSA signer. No
commercial secure element currently computes it. The SEs are gated
storage, not signing accelerators. The seed
therefore transits STM32 secure-world SRAM during the active signing
window (~120 s idle timeout, then zeroize). TrustZone SAU+GTZC isolates
this from the non-secure world.

**TrustZone partition.** Secure world (flash bank 1, SRAM1) owns all
crypto, PIN, persistent secrets, transaction decoding, and the trusted
NV3007 LCD UI. Non-secure world owns USB transport. Crossings go through
the fixed NSC gateway with pointer validation and TOCTOU-safe copy-in.

**Power supervision state.** BOR, PVD, ECC (except SRAM1 which is
always-on), IWDG all at factory defaults. Stage 1 of a 5-stage brownout
roadmap added reset-cause classification + verified flash writes; the
rest is planned. `make stm32-harden-opts` is a one-time option-byte
setup target (sets BOR3 + SRAM2_RST=0) but has not been run yet. See
`docs/security/brownout-hardening.md` for the full plan.

**VBAT.** Production hardware uses a **0.47 F supercap** (not a
battery) on VBAT via Schottky from Vdd. Bounded retention (~12-24 h
after unplug). The dev board has an unpopulated CR1220 holder whose
pads can be reused for a tack-soldered supercap during validation.
Indefinite-retention tamper monitoring during long cold storage is
explicitly out of scope — the 24-word BIP-39 backup is the long-term
security anchor.

**Accepted trade-offs (research that contradicts these is not useful):**
1. Seed transits STM32 SRAM during signing. Unavoidable until SE can
   do SLH-DSA.
2. SE050's value is hardware PIN gate + XOR storage, not "seed never
   leaves silicon." Don't suggest "do all signing on SE050" — it
   can't.
3. USB-C is the only external interface.
4. Out of scope: EAL6+ invasive decapping attacks.

**Dark Skippy and similar nonce-exfil attacks do NOT apply.** Hash-
based SLH-DSA has no nonce. Don't chase this.

**Current SCP03 lifecycle.** The SE050 SCP03 channel is active (every TX
has CLA=0x84). Factory defaults are not an acceptable production state:
the factory transport credentials are derived from the per-device OTP master
burned for that handoff. After RDP2 self-lock and the BHK first write, the
implemented first-field candidate rotates SE050 SCP03/admin credentials to
the final BHK axis and rotates the OPTIGA E140 PBS to the final DHUK derivation
bound to a fresh TRNG salt persisted in the page-127 journal. Page 126 holds
only the DHUK-wrapped BHK. This candidate is not a production-approved
ceremony: authenticated per-unit handoff and authenticate-before-rotate,
durable old/new/KVN recovery, the exact E140 lifecycle-versus-final-rotation
order, and silicon receipts remain OPEN.

---

## Style guidance

- Cite specific RM0456 / AN5342 / ES0499 / UM11225 / Infineon doc
  sections where possible. Prefer "per AN5342" over inventing
  revision numbers you aren't sure of.
- Say "I don't know" on things not answerable from public sources,
  rather than guessing.
- Give concrete, implementable code / register values — hand-wave
  recommendations without specifics are not useful.
- Respect the architecture above. Suggestions that require signing
  on the SE are category errors for this project.

---


## Relevant code and design


### `secure/src/se050/scp03.rs`

```rust
//! SCP03 (Secure Channel Protocol 03) for SE050.
//!
//! Establishes an authenticated, encrypted channel with the SE050 using
//! GlobalPlatform SCP03. After session establishment every command is
//! MAC'd (C-MAC) and encrypted (C-DEC), AND every response is MAC'd
//! (R-MAC) and encrypted (R-ENC). This is GP SCP03 security level
//! 0x33 — the "all four" mode.
//!
//! **Why 0x33, not 0x03 (the pre-S-5 value).** S-5 (`docs/security-review-
//! 2026-05.md` §C-7) — at level 0x03 the SE050 returns responses in
//! cleartext on the I²C bus, leaking `half_E` every unlock. NXP's own
//! reference (`fsl_sss_se05x_scp03.c`) ships at 0x33; SE050 conforms
//! to GP SCP03 per AN12413 §4.5.3.2, which defers to GP Amendment D
//! Table 7-6 (every P1 in {0x00, 0x01, 0x03, 0x11, 0x13, 0x33} is
//! valid).

// Pure-logic primitives live in `crate::scp03_logic` so the NIST
// AES-128 / CMAC vectors + the GP `PUT KEY` layout tests run under
// `cargo test -p sphincs-tz-secure` (this module is `feature = "se050"`
// + `not(test)`-gated in `main.rs`, so its own `#[cfg(test)]` blocks
// would never compile). Re-export the surface so existing call sites
// (and `Se050::rotate_scp03_keys`) keep working unchanged.
pub use crate::scp03_logic::{
    aes128_cbc_decrypt, aes128_cbc_encrypt, aes128_ecb_encrypt, build_put_key_apdu, cmac_aes128,
    keys_are_factory_default, verify_put_key_response, TransportAuthProof,
    AUTH_CTX_ADMIN_TRANSPORT, AUTH_CTX_PBS_TRANSPORT, AUTH_CTX_SCP03_TRANSPORT, KEY_VERSION,
    PLATFORM_DEK, PLATFORM_ENC, PLATFORM_MAC, PUT_KEY_APDU_LEN,
};
use crate::scp03_logic::{
    build_derivation_data, kdf, DD_CARD_CRYPTOGRAM, DD_HOST_CRYPTOGRAM, DD_S_ENC, DD_S_MAC,
    DD_S_RMAC,
};

use super::apdu::Se050Error;
use zeroize::Zeroizing;

// The factory-key fallback only makes sense when the build *prefers*
// derived keys (otherwise the preferred set already IS the factory keys
// and there is nothing to fall back from). Catch the nonsensical combo
// at compile time rather than shipping a no-op flag. (Defense-in-depth:
// dead today because Cargo.toml declares the feature edge
// `se050-scp03-allow-factory-fallback = ["se050-derived-scp03"]`; this
// fires only if that edge is ever removed.)
#[cfg(all(
    feature = "se050-scp03-allow-factory-fallback",
    not(feature = "se050-derived-scp03")
))]
compile_error!(
    "se050-scp03-allow-factory-fallback requires se050-derived-scp03 \
     (without derived keys the preferred set already is the factory keys)"
);

// Constants `PLATFORM_ENC/MAC/DEK`, `KEY_VERSION`, the SCP03 KDF
// derivation-data constants, and the pure crypto helpers all live in
// `crate::scp03_logic` now (see the `use` block at the top of this
// file) — kept un-gated so the host test build can run the NIST KATs
// + the GP `PUT KEY` layout assertions.

/// Resolve the SCP03 static keys this build should *prefer* — `(S-ENC,
/// S-MAC, DEK)`.
///
/// - Without `se050-derived-scp03` (the default): the published factory
///   constants from `scp03_logic::PLATFORM_*`.
/// - With `se050-derived-scp03`: the per-device keys from
///   `hw::secret_keys::se050_scp03_{enc,mac,dek}_key()` (BHK-rooted in a
///   `bhk`-on build; DHUK / OTP per build otherwise). A device whose chip
///   has been `PUT KEY`-rotated holds exactly these; one that hasn't still
///   holds the factory keys — `establish()` probes the preferred set first
///   and falls back to `PLATFORM_*` on a card-cryptogram mismatch, so one
///   firmware copes with both. `KEY_VERSION` stays `0x0B` either way (the
///   rotation replaces keyset `0x0B` in place, it does not add a new KVN).
///
/// Lives here (not in `scp03_logic`) because the derived-key path imports
/// `hw::secret_keys`, and the `hw` module is `not(test)`-gated — keeping
/// this stub in the gated `se050` module keeps `scp03_logic` host-clean.
///
/// Returns each key wrapped in [`Zeroizing`] (finding F12) so the per-device
/// static keys — and the DEK that `establish` binds but never uses — auto-wipe
/// on every caller return path. The derived-key path derives in place (no
/// un-wiped `Copy` temp); the factory-constant path wraps the public AN12436
/// constants (harmless, and keeps a single return type across both cfgs).
pub fn load_platform_keys(
) -> Result<(Zeroizing<[u8; 16]>, Zeroizing<[u8; 16]>, Zeroizing<[u8; 16]>), Se050Error> {
    #[cfg(not(feature = "se050-derived-scp03"))]
    {
        Ok((
            Zeroizing::new(PLATFORM_ENC),
            Zeroizing::new(PLATFORM_MAC),
            Zeroizing::new(PLATFORM_DEK),
        ))
    }
    #[cfg(feature = "se050-derived-scp03")]
    {
        use crate::hw::secret_keys;
        let enc = secret_keys::se050_scp03_enc_key().map_err(|_| Se050Error::Scp03)?;
        let mac = secret_keys::se050_scp03_mac_key().map_err(|_| Se050Error::Scp03)?;
        let dek = secret_keys::se050_scp03_dek_key().map_err(|_| Se050Error::Scp03)?;
        Ok((enc, mac, dek))
    }
}

// ---------------------------------------------------------------------------
// Session state
// ---------------------------------------------------------------------------

/// SCP03 session — holds derived session keys and MAC chaining value.
pub struct Scp03Session {
    pub s_enc: [u8; 16],
    pub s_mac: [u8; 16],
    pub s_rmac: [u8; 16],
    /// MAC Chaining Value — updated after every wrapped command.
    pub mcv: [u8; 16],
    /// Command counter for IV derivation (big-endian, incremented per command).
    pub counter: [u8; 16],
    /// Whether the session is established.
    pub active: bool,
}

impl Scp03Session {
    pub const fn new() -> Self {
        Self {
            s_enc: [0; 16],
            s_mac: [0; 16],
            s_rmac: [0; 16],
            mcv: [0; 16],
            counter: [0; 16],
            active: false,
        }
    }

    fn inc_counter(&mut self) {
        for i in (0..16).rev() {
            self.counter[i] = self.counter[i].wrapping_add(1);
            if self.counter[i] != 0 {
                break;
            }
        }
    }

    /// Zeroize the live SCP03 session keys and force re-establishment.
    ///
    /// Reached from `Se050`'s `zeroize_caches`, which the lock / idle-wipe /
    /// panic path drives via `nsc::zeroize_sensitive_state`. The `Se050`
    /// driver is a `static mut` singleton, so it is never `Drop`ped in
    /// production — without this, the AES-128 session keys
    /// (`s_enc`/`s_mac`/`s_rmac`) that wrap `half_E` on the SE050 I2C bus
    /// would persist in secure SRAM through the entire locked state, where
    /// they could combine with a captured bus transcript to recover the
    /// half. Re-establishment is the caller's job: `Se050::zeroize_caches`
    /// pairs this with `ready = false` so the next SE access re-runs the
    /// full `init()` handshake. There is deliberately NO lazy establish
    /// inside `send_apdu` — it fails CLOSED (`Se050Error::Scp03`) on an
    /// inactive session instead of downgrading to cleartext. (audit
    /// secret-lifecycle 20260611, MEDIUM-1; idle-relock fix 2026-07-02)
    pub fn zeroize_session(&mut self) {
        use zeroize::Zeroize;
        self.s_enc.zeroize();
        self.s_mac.zeroize();
        self.s_rmac.zeroize();
        self.mcv.zeroize();
        self.counter.zeroize();
        crate::fi::zeroize_barrier();
        self.active = false;
    }
}

// AES-128 ECB/CBC + CMAC primitives and the SP 800-108 derivation-data
// builder + `kdf` block-emitter all live in `crate::scp03_logic` now
// (imported at the top of this file).

// ---------------------------------------------------------------------------
// Session establishment
// ---------------------------------------------------------------------------

/// Establish an SCP03 session with the SE050.
///
/// Probe-on-boot: tries the keys this build *prefers* (the derived
/// per-device keys when `se050-derived-scp03` is on; the published
/// factory constants otherwise — see `load_platform_keys`). If that
/// fails the card-cryptogram check (the signal that the chip holds a
/// different key set), it retries once with the factory constants —
/// but ONLY in a build that sets `se050-scp03-allow-factory-fallback`
/// (the provisioning/rotation tool, §29, which must open a factory-key
/// session to send GP PUT KEY). A runtime-signing SHIP build omits that
/// flag and therefore **fails closed** on a derived-key mismatch rather
/// than silently downgrading to the attacker-known published keys.
/// `KEY_VERSION` is `0x0B` either way.
pub unsafe fn establish(
    session: &mut Scp03Session,
    t1: &mut super::t1oi2c::T1State,
) -> Result<(), Se050Error> {
    let (enc, mac, _dek) = load_platform_keys()?;

    match establish_with_keys(session, t1, &enc, &mac) {
        Ok(()) => Ok(()),
        Err(e) => {
            // The published-factory-key fallback is GATED to the
            // provisioning/rotation tool (`se050-scp03-allow-factory-
            // fallback`). In a runtime-signing build this whole arm is
            // compiled out, so a derived-key mismatch returns `Err(e)`
            // and the SE050 stays locked — fail CLOSED, never fall back
            // to the AN12436 keys an attacker also holds. When the flag
            // IS set, retry once on a key-related failure (card-cryptogram
            // mismatch `Scp03` or a status word like `0x6A88`); never
            // retry a pure transport glitch.
            #[cfg(all(
                feature = "se050-derived-scp03",
                feature = "se050-scp03-allow-factory-fallback"
            ))]
            if matches!(e, Se050Error::Scp03 | Se050Error::Status(_)) {
                #[cfg(feature = "debug-log")]
                secure_log!("[SCP03] derived-key establish failed ({:?}); falling back to factory keys", e);
                return establish_with_keys(session, t1, &PLATFORM_ENC, &PLATFORM_MAC);
            }
            Err(e)
        }
    }
}

/// work-todo #36: establish an SCP03 session under an EXPLICIT static keyset,
/// with NO fallback. The first-boot rotation uses this to probe the FINAL
/// keyset (resume) and to open the TRANSPORT session before `PUT KEY` — it
/// must NOT silently fall back to the AN12436 published keys (that would be
/// the fail-OPEN the runtime `establish` deliberately compiles out), so this
/// is a thin, fallback-free wrapper over `establish_with_keys`.
///
/// # Safety
/// Drives the SE050 SCP03 handshake; single-threaded secure world.
#[cfg(feature = "rdp2-self-lock")]
pub unsafe fn establish_with(
    session: &mut Scp03Session,
    t1: &mut super::t1oi2c::T1State,
    static_enc: &[u8; 16],
    static_mac: &[u8; 16],
) -> Result<(), Se050Error> {
    // SAFETY: forwarded contract.
    unsafe { establish_with_keys(session, t1, static_enc, static_mac) }
}

/// One INITIALIZE-UPDATE + EXTERNAL-AUTHENTICATE handshake using the
/// given static `(S-ENC, S-MAC)` keys. Returns `Se050Error::Scp03` on a
/// card-cryptogram mismatch (the "wrong keys" signal the caller uses to
/// decide whether to retry with a different set).
unsafe fn establish_with_keys(
    session: &mut Scp03Session,
    t1: &mut super::t1oi2c::T1State,
    static_enc: &[u8; 16],
    static_mac: &[u8; 16],
) -> Result<(), Se050Error> {
    // Generate 8-byte host challenge from hardware TRNG
    let mut host_challenge = [0u8; 8];
    crate::rng::fill(&mut host_challenge).map_err(|_| Se050Error::Scp03)?;

    // --- INITIALIZE UPDATE ---
    let mut init_update = [0u8; 13];
    init_update[0] = 0x80; // CLA
    init_update[1] = 0x50; // INS_INITIALIZE_UPDATE
    init_update[2] = KEY_VERSION;
    init_update[3] = 0x00;
    init_update[4] = 0x08; // Lc
    init_update[5..13].copy_from_slice(&host_challenge);

    let mut resp = [0u8; 64];
    let n = t1.transceive(&init_update, &mut resp).map_err(|_| Se050Error::Transport)?;

    if n < 31 {
        return Err(Se050Error::Scp03);
    }

    let sw = ((resp[n - 2] as u16) << 8) | (resp[n - 1] as u16);
    if sw != 0x9000 {
        return Err(Se050Error::Status(sw));
    }

    // Parse: KeyDivData(10) + KeyInfo(3) + CardChallenge(8) + CardCryptogram(8)
    let mut card_challenge = [0u8; 8];
    card_challenge.copy_from_slice(&resp[13..21]);
    let mut card_cryptogram = [0u8; 8];
    card_cryptogram.copy_from_slice(&resp[21..29]);

    // --- Derive session keys ---
    let dd_enc = build_derivation_data(DD_S_ENC, 0x0080, &host_challenge, &card_challenge);
    let dd_mac = build_derivation_data(DD_S_MAC, 0x0080, &host_challenge, &card_challenge);
    let dd_rmac = build_derivation_data(DD_S_RMAC, 0x0080, &host_challenge, &card_challenge);

    session.s_enc = kdf(static_enc, &dd_enc);
    session.s_mac = kdf(static_mac, &dd_mac);
    session.s_rmac = kdf(static_mac, &dd_rmac);

    // --- Verify card cryptogram (CT + FI hardened) ---
    // This is the SE050 authenticating ITSELF to the MCU during SCP03
    // establishment — the twin of the R-MAC verify in `unwrap_response`
    // below, and it must be hardened identically. A plain
    // `if a[..8] != b { Err }` is BOTH variable-time (a byte-wise forgery
    // oracle for a bus-SCA / counterfeit-SE adversary — the exact desolder /
    // I2C-tamper threat the SCP03 tunnel exists to close) AND single-fault-
    // skippable (one `[skip]` glitch lets an UNauthenticated SE complete
    // SCP03, so the MCU then trusts an attacker-controlled channel). The
    // `make scp03-fi` sweep found this `[skip]` class on the sibling R-MAC.
    // Mirror that gate exactly: recompute the cryptogram INSIDE the double-
    // evaluated closure (a fault that corrupts one computation makes the two
    // disagree → fail closed), constant-time compare via `ct_eq_8`, verdict
    // is the Hamming-distant `OK_SENTINEL` (a branch skip can't synthesise
    // it), `black_box` stops LLVM CSE-collapsing the re-check, `wait_random`
    // defeats clock-aligned bursts timed to the fixed-shape control flow.
    let dd_card = build_derivation_data(DD_CARD_CRYPTOGRAM, 0x0040, &host_challenge, &card_challenge);
    crate::fi::wait_random();
    let card_ok = crate::fi::check_true_into_sentinel(|| {
        let mac = kdf(&session.s_mac, &dd_card);
        core::hint::black_box(ct_eq_8(&mac[..8], &card_cryptogram[..]))
    });
    if card_ok != crate::fi::OK_SENTINEL {
        #[cfg(feature = "debug-log")]
        secure_log!("[SCP03] Card cryptogram MISMATCH");
        return Err(Se050Error::Scp03);
    }

    // --- Compute host cryptogram ---
    let dd_host = build_derivation_data(DD_HOST_CRYPTOGRAM, 0x0040, &host_challenge, &card_challenge);
    let host_crypto_full = kdf(&session.s_mac, &dd_host);
    let host_cryptogram = &host_crypto_full[..8];

    // --- EXTERNAL AUTHENTICATE ---
    // P1=0x33: C-DECRYPTION | R-ENCRYPTION | C-MAC | R-MAC.  S-5 fix —
    // GP Amendment D Table 7-6 (page 35); NXP plug-and-trust
    // `fsl_sss_se05x_scp03.c:186-198` (`SECLVL_CDEC_RENC_CMAC_RMAC`).
    let header = [0x84u8, 0x82, 0x33, 0x00, 0x10];
    session.mcv = [0; 16];
    let mac_full = cmac_aes128(&session.s_mac, &[&session.mcv, &header, host_cryptogram]);
    session.mcv = mac_full;

    let mut ext_auth = [0u8; 21];
    ext_auth[0] = 0x84;
    ext_auth[1] = 0x82;
    ext_auth[2] = 0x33;
    ext_auth[3] = 0x00;
    ext_auth[4] = 0x10; // Lc = 16 (8 host crypto + 8 MAC)
    ext_auth[5..13].copy_from_slice(host_cryptogram);
    ext_auth[13..21].copy_from_slice(&mac_full[..8]);

    let mut ext_resp = [0u8; 32];
    let ext_n = t1.transceive(&ext_auth, &mut ext_resp).map_err(|_| Se050Error::Transport)?;

    if ext_n < 2 {
        return Err(Se050Error::Scp03);
    }
    let ext_sw = ((ext_resp[ext_n - 2] as u16) << 8) | (ext_resp[ext_n - 1] as u16);
    if ext_sw != 0x9000 {
        #[cfg(feature = "debug-log")]
        secure_log!("[SCP03] EXT AUTH SW=0x{:04x}", ext_sw);
        return Err(Se050Error::Status(ext_sw));
    }

    session.counter = [0; 16];
    session.counter[15] = 0x01;
    session.active = true;

    #[cfg(feature = "debug-log")]
    secure_log!("[SCP03] Session established");

    Ok(())
}

// ---------------------------------------------------------------------------
// APDU MAC + encryption wrapping
// ---------------------------------------------------------------------------

/// Compute the command ICV (Initial Chaining Value) for AES-CBC encryption.
///
/// GP Amendment D §6.2.6: `ICV = AES-ECB-Enc(S-ENC, padded_counter)` where
/// the counter is left-padded with zeroes to one block. (`session.counter`
/// already lives in that left-padded representation — 15 high zero bytes
/// then the counter value in the low byte(s).)
fn command_icv(session: &Scp03Session) -> [u8; 16] {
    aes128_ecb_encrypt(&session.s_enc, &session.counter)
}

/// Compute the response ICV for AES-CBC decryption of an R-ENC response.
///
/// GP Amendment D §6.2.7 (page 30): the response uses the SAME padded
/// counter block as the matching command, with one byte changed —
/// "Before encryption, the most significant byte of this block shall be
/// set to '80'." That separates response ICVs from command ICVs even
/// though both share `S-ENC` and `counter`.
///
/// Mirrors `nxpSCP03_Get_ResponseICV` in NXP plug-and-trust
/// (`hostlib/hostLib/libCommon/nxScp/nxScp03_Com.c:296-330`).
fn response_icv(session: &Scp03Session) -> [u8; 16] {
    let mut block = session.counter;
    block[0] = 0x80;
    aes128_ecb_encrypt(&session.s_enc, &block)
}

/// Wrap an APDU with SCP03 C-MAC and C-DEC (command encryption).
///
/// Always applies both C-MAC and C-DEC. The counter is left at the
/// command's value — `unwrap_response()` increments it on success so the
/// wrap/unwrap pair uses the same counter (GP Amd D §6.2.6 + §6.2.7), and
/// a transport-level loss of the response keeps host/card counters in
/// sync (the card also only advances after successfully sending the
/// response).
pub fn wrap_apdu(
    session: &mut Scp03Session,
    apdu: &[u8],
    out: &mut [u8],
) -> usize {
    if !session.active || apdu.len() < 4 {
        out[..apdu.len()].copy_from_slice(apdu);
        return apdu.len();
    }

    // Parse incoming APDU to locate header and data
    let extended = apdu.len() >= 7 && apdu[4] == 0x00;
    let (hdr_len, data_len) = if extended {
        let lc = ((apdu[5] as usize) << 8) | (apdu[6] as usize);
        (7, lc)
    } else if apdu.len() > 5 {
        (5, apdu.len() - 5)
    } else {
        (apdu.len(), 0)
    };
    let has_data = data_len > 0;

    // --- C-DEC: encrypt command data ---
    let enc_len = if has_data {
        // LCR-F4: holds plaintext command data (PIN / provisioned-object bytes)
        // before + after in-place encryption — wipe on scope exit.
        let mut enc_buf = Zeroizing::new([0u8; 1024]);
        enc_buf[..data_len].copy_from_slice(&apdu[hdr_len..hdr_len + data_len]);
        // ISO 7816-4 padding: 0x80 then zeros to next 16-byte boundary
        let mut padded_len = data_len;
        enc_buf[padded_len] = 0x80;
        padded_len += 1;
        while padded_len % 16 != 0 {
            enc_buf[padded_len] = 0x00;
            padded_len += 1;
        }
        let icv = command_icv(session);
        aes128_cbc_encrypt(&session.s_enc, &icv, &mut enc_buf[..padded_len]);
        // Place encrypted data at offset 7 (extended Lc position)
        out[7..7 + padded_len].copy_from_slice(&enc_buf[..padded_len]);
        padded_len
    } else {
        0
    };

    // New Lc = encrypted data + 8-byte MAC
    let new_lc = enc_len + 8;
    let use_extended = extended || new_lc >= 256;
    let out_hdr_len = if use_extended { 7 } else { 5 };

    // Shift data to correct position if header length changed
    if has_data && !use_extended {
        for i in 0..enc_len {
            out[5 + i] = out[7 + i];
        }
    }

    // Write header
    out[0] = apdu[0] | 0x04; // Set CLA security bit
    out[1] = apdu[1];
    out[2] = apdu[2];
    out[3] = apdu[3];

    if use_extended {
        out[4] = 0x00;
        out[5] = (new_lc >> 8) as u8;
        out[6] = (new_lc & 0xFF) as u8;
    } else {
        out[4] = new_lc as u8;
    }

    // Compute C-MAC
    let mac_header = &out[0..out_hdr_len];
    let mac_data = if has_data {
        &out[out_hdr_len..out_hdr_len + enc_len]
    } else {
        &[] as &[u8]
    };
    let mac_full = cmac_aes128(&session.s_mac, &[&session.mcv, mac_header, mac_data]);

    // Append 8-byte MAC
    let mac_offset = out_hdr_len + enc_len;
    out[mac_offset..mac_offset + 8].copy_from_slice(&mac_full[..8]);
    session.mcv = mac_full;

    mac_offset + 8
}

// ---------------------------------------------------------------------------
// SCP03 response unwrap — R-MAC verify + R-ENC decrypt
// ---------------------------------------------------------------------------

/// Errors specific to `unwrap_response`. Surfaced via `Se050Error::Scp03`
/// upstream — the variant exists for diagnostic logging.
#[derive(Debug)]
pub enum UnwrapError {
    /// Response was shorter than 2 bytes (not even a SW).
    Truncated,
    /// SCP03 session is not active — caller should bypass unwrap.
    Inactive,
    /// Response length is in the "no man's land" between 2 (bare SW) and
    /// 10 (minimum protected response = R-MAC + SW), with no valid
    /// interpretation under GP Amendment D §6.2.5.
    MalformedLength,
    /// R-MAC verification failed in constant time.
    RMacMismatch,
    /// The decrypted padded plaintext does not re-encrypt to the
    /// authenticated ciphertext (decryption fault / corruption), or a
    /// receipt-bound copy out of the verified staging buffer failed.
    RelationMismatch,
    /// Encrypted body length was not a multiple of 16 (ISO 7816-4 padded
    /// AES-CBC must be).
    BadCiphertextLen,
    /// ISO 7816-4 depad found no `0x80` sentinel.
    BadPadding,
    /// Output buffer too small for the plaintext.
    Overflow,
}

impl From<UnwrapError> for super::apdu::Se050Error {
    fn from(_: UnwrapError) -> Self {
        super::apdu::Se050Error::Scp03
    }
}

/// Constant-time equality on two 8-byte slices.
///
/// Uses `subtle::ConstantTimeEq` rather than a hand-rolled XOR-OR loop —
/// the loop is correct in principle but rustc + future LLVM versions
/// can introduce vectorised early-exit code that breaks the CT
/// property.  `subtle` wraps the comparison in `core::hint::black_box`
/// and volatile reads to defeat reordering.  Matches CLAUDE.md's
/// "`subtle` for constant-time compares" convention used throughout
/// the rest of the secure world.
fn ct_eq_8(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    debug_assert_eq!(a.len(), 8);
    debug_assert_eq!(b.len(), 8);
    a.ct_eq(b).into()
}

/// Unwrap an SCP03-protected response APDU (R-MAC verify, optionally
/// R-ENC decrypt) and place `plaintext_body || SW1 SW2` into `out`.
///
/// Returns the number of bytes written to `out` (≥ 2). The last two
/// are always the status word (`SW1 SW2`) — for downstream handlers that
/// already expect the raw form `body || SW`.
///
/// Handles the three GP Amd D §6.2.5 cases:
/// 1. **Bare error (length 2):** SW1 SW2 only, no R-MAC. Per §6.2.5
///    first sentence — "no R-MAC shall be generated and no protection
///    shall be applied to a response that includes an error status
///    word". All SW ∉ {`9000`, `62xx`, `63xx`} → bare. Verified by
///    matching `len == 2`; we *don't* re-classify by SW value because
///    a SW=9000 response with R-ENC will be ≥ 10 bytes (R-MAC + SW
///    minimum) and a SW=9000 with no data is also ≥ 10 bytes (still
///    has R-MAC).
/// 2. **No-body protected (length 10):** R-MAC(8) || SW(2). Empty
///    response data field — R-MAC still computed over `MCV || SW`
///    (§6.2.5 last paragraph + §6.2.7 "no encryption shall be applied
///    to a response where there is no response data field: in this
///    case the message shall be protected as defined in section
///    6.2.5").
/// 3. **Full protected (length ≥ 26):** ciphertext_body || R-MAC(8)
///    || SW(2). Ciphertext is a multiple of 16. R-MAC over `MCV ||
///    ciphertext_body || SW`. Decrypt with `response_icv()`, depad
///    via ISO 7816-4 (scan from end for `0x80`).
///
/// Mirrors `nxpSCP03_Decrypt_ResponseAPDU` in NXP plug-and-trust
/// (`hostlib/hostLib/libCommon/nxScp/nxScp03_Com.c:124-248`). The
/// encryption counter advances on EVERY response — protected or bare
/// error SW — because the card consumed the command's counter value the
/// moment its SM layer processed the command (GP Amd D §6.2.6: per
/// command sent, not per protected response). Only a verify/decrypt
/// failure of a *protected* response (R-MAC mismatch — a forgery, not a
/// card response) leaves the counter untouched.
///
/// **F8 (corrected):** that R-MAC-mismatch path returns `Err(RMacMismatch)`
/// but does NOT itself clear `session.active` (an earlier comment claimed it
/// "kills the session" — it does not). The channel still fails CLOSED: no
/// plaintext is ever released on the mismatch (the fail-initialized R-MAC
/// authentication receipt — published only after two independent full
/// recomputations inside `verify_rmac_into` and re-checked by two
/// independent volatile reads — never reaches the copy, counter advance, or
/// `Ok` on a mismatch), and the seed half is only ever read,
/// never sent, and always travels as R-ENC ciphertext on the bus. A desynced
/// session is an availability concern, not a confidentiality/integrity one:
/// the counter desync makes every SUBSEQUENT command error too, so the unlock
/// fails closed, and the SE error paths re-`reinit()` (full SELECT + fresh
/// `establish`) before the session is reused. Do NOT "fix" this by setting
/// `session.active = false` here. Historically that flipped `send_apdu` into
/// a pre-handshake cleartext branch — a fail-OPEN plaintext downgrade on I2C,
/// the exact invariant-#3 break this guards against. Since the idle-relock
/// fix (2026-07-02) `send_apdu` refuses outright on an inactive session, so
/// the downgrade is structurally gone — but clearing the flag here is still
/// wrong: it would swap the observable per-command SW errors the `reinit()`
/// recovery paths key off for a blanket local refusal, hiding the desync
/// without adding safety.
pub fn unwrap_response(
    session: &mut Scp03Session,
    wrapped: &[u8],
    out: &mut [u8],
) -> Result<usize, UnwrapError> {
    if !session.active {
        return Err(UnwrapError::Inactive);
    }
    let n = wrapped.len();
    if n < 2 {
        return Err(UnwrapError::Truncated);
    }

    // Case 1 — bare error response: just SW1 SW2.  No R-MAC, no R-ENC.
    // GP Amd D §6.2.5 first paragraph.
    if n == 2 {
        if out.len() < 2 {
            return Err(UnwrapError::Overflow);
        }
        out[0] = wrapped[0];
        out[1] = wrapped[1];
        // Counter MUST advance here. The card's SM layer consumed this
        // command's counter value when it C-DEC/C-MAC-processed the
        // command; an applet-level error that returns a bare SW (object
        // missing, wrong state) has still burned it — GP Amd D §6.2.6
        // counts per command sent, not per protected response. Holding
        // the host counter back desyncs the C-ENC ICV one command later:
        // observed on silicon 2026-06-12 (wiped chip → reconcile's
        // ReadObjectAttributes → bare 0x6985 → next command 0x6982
        // (card-side SM failure, session terminated) → every later APDU
        // 0x6985 → first-boot wizard rng_strong bricked). Transport
        // failures (no response at all) never reach unwrap_response, so
        // this arm only fires when the card actually processed a command.
        session.inc_counter();
        return Ok(2);
    }

    if n < 10 {
        return Err(UnwrapError::MalformedLength);
    }

    // Case 2 + Case 3 share the R-MAC verify path.  Layout:
    //   wrapped[..n-10]    = ciphertext body (may be empty in case 2)
    //   wrapped[n-10..n-2] = 8-byte R-MAC
    //   wrapped[n-2..n]    = SW1 SW2
    let body_end = n - 10;
    let body = &wrapped[..body_end];
    let rmac_recv = &wrapped[body_end..body_end + 8];
    let sw = &wrapped[n - 2..];

    // GP Amd D §6.2.5 + Figure 6-3:
    //   R-MAC = CMAC(S-RMAC, MCV || ciphered_body || SW)[..8]
    // The MCV is the full 16-byte command CMAC produced by `wrap_apdu`
    // (`session.mcv`); it is NOT updated by `unwrap_response`.
    //
    // FI-hardening (F-28 rework, 2026-08-03 — `tools/sca/README.md` §F-28).
    // This R-MAC verify is the ONLY thing between a forged
    // (attacker-supplied, wrong-R-MAC) response and the host releasing
    // attacker-influenced plaintext (a substituted SE050 entropy
    // contribution / `half_E`). The authoritative gate is a fail-initialized
    // authentication receipt: `verify_rmac_into` publishes `OK_SENTINEL`
    // only after two independent full R-MAC recomputations (constant-time
    // compare, `black_box`ed so LTO cannot fold the duplicate checks), and
    // two independent volatile success checks — separated by `wait_random`
    // — must pass below before ANY protected-response copy, counter
    // advance, or `Ok` return, covering BOTH the empty-body (case 2) and
    // full encrypted (case 3) paths. A skipped verifier call, a skipped
    // store, or one faulted recomputation leaves `FAIL_SENTINEL`
    // authoritative.
    //
    // There is deliberately NO complementing infective mask here. The
    // previous gate folded a mismatch into the released bytes as XOR-0xFF —
    // a public bijection: a forging attacker who can form R-ENC ciphertext
    // submits the *complement* of the desired payload and receives exactly
    // those bytes (with attacker-chosen SW, advanced counter, and an `Ok`
    // return) once a single fault skips an early rejection (the wave-17
    // GPT-5.6 blocker). A mask that returns `Ok` cannot be the release
    // authority; the receipt is.
    crate::fi::wait_random();
    let mut rmac_auth_receipt: u32 = crate::fi::FAIL_SENTINEL;
    // SAFETY: unique stack receipt, fail-initialized so a skipped verifier
    // call cannot synthesize success from stale stack state.
    unsafe {
        core::ptr::write_volatile(&mut rmac_auth_receipt, crate::fi::FAIL_SENTINEL);
    }
    crate::scp03_logic::verify_rmac_into(
        &session.s_rmac,
        &session.mcv,
        body,
        sw,
        rmac_recv,
        &mut rmac_auth_receipt,
    );
    // First volatile success check.
    if unsafe { core::ptr::read_volatile(&rmac_auth_receipt) } != crate::fi::OK_SENTINEL {
        #[cfg(feature = "debug-log")]
        secure_log!("[SCP03] R-MAC MISMATCH");
        return Err(UnwrapError::RMacMismatch);
    }
    crate::fi::wait_random();
    // Second independent volatile success check — a single fault cannot
    // defeat both.
    if unsafe { core::ptr::read_volatile(&rmac_auth_receipt) } != crate::fi::OK_SENTINEL {
        #[cfg(feature = "debug-log")]
        secure_log!("[SCP03] R-MAC MISMATCH");
        return Err(UnwrapError::RMacMismatch);
    }

    // Case 2 — empty body: just write the SW.
    if body_end == 0 {
        if out.len() < 2 {
            return Err(UnwrapError::Overflow);
        }
        out[0] = sw[0];
        out[1] = sw[1];
        session.inc_counter();
        return Ok(2);
    }

    // Case 3 — decrypt body, depad, append SW.
    if body_end % 16 != 0 {
        return Err(UnwrapError::BadCiphertextLen);
    }

    // LCR-F4: holds the DECRYPTED SE050 response body (provisioned-object reads,
    // PIN-gated data) — wipe on scope exit, success or error.
    let mut plain = Zeroizing::new([0u8; 1024]);
    if body_end > plain.len() {
        return Err(UnwrapError::Overflow);
    }
    plain[..body_end].copy_from_slice(body);

    let icv = response_icv(session);
    aes128_cbc_decrypt(&session.s_enc, &icv, &mut plain[..body_end]);

    // Decrypt-fidelity receipt (wave-18 GPT-5.6 blocker). The R-MAC gate
    // above authenticates the CIPHERTEXT; it cannot see a fault that
    // corrupts the decryption — a single skip of the per-block writeback
    // inside `aes128_cbc_decrypt` leaves bus-visible ciphertext in `plain`
    // (coordinator-reproduced: `Ok` + intact TLV header + SW + advanced
    // counter, block bytes equal to the on-wire ciphertext). Bind the
    // decrypted padded buffer back to the authenticated ciphertext:
    // `verify_renc_relation_into` re-encrypts `plain` twice independently
    // (CBC re-encryption is the identity on a faithful decrypt), each pass
    // under an independently recomputed response ICV — sharing the caller's
    // `icv` would let one faulted ICV computation make the decrypt and the
    // check consistently wrong. `OK_SENTINEL` is published only when both
    // passes match `body`. Two independent volatile checks, separated by
    // `wait_random`, must pass before any depad, copy, counter advance, or
    // `Ok`.
    let mut renc_receipt: u32 = crate::fi::FAIL_SENTINEL;
    // SAFETY: unique stack receipt, fail-initialized so a skipped verifier
    // call cannot synthesize success from stale stack state.
    unsafe {
        core::ptr::write_volatile(&mut renc_receipt, crate::fi::FAIL_SENTINEL);
    }
    crate::scp03_logic::verify_renc_relation_into(
        &session.s_enc,
        &session.counter,
        &plain[..body_end],
        body,
        &mut renc_receipt,
    );
    // First volatile success check.
    if unsafe { core::ptr::read_volatile(&renc_receipt) } != crate::fi::OK_SENTINEL {
        #[cfg(feature = "debug-log")]
        secure_log!("[SCP03] R-ENC RELATION MISMATCH");
        return Err(UnwrapError::RelationMismatch);
    }
    crate::fi::wait_random();
    // Second independent volatile success check — a single fault cannot
    // defeat both.
    if unsafe { core::ptr::read_volatile(&renc_receipt) } != crate::fi::OK_SENTINEL {
        #[cfg(feature = "debug-log")]
        secure_log!("[SCP03] R-ENC RELATION MISMATCH");
        return Err(UnwrapError::RelationMismatch);
    }

    // ISO 7816-4 depad: scan back from end of last block for the `0x80`
    // sentinel.  GP Amd D §6.2.7 + GP Card Spec §B.2.3.
    let mut pad_pos = body_end;
    while pad_pos > 0 {
        pad_pos -= 1;
        if plain[pad_pos] == 0x80 {
            break;
        }
        if plain[pad_pos] != 0x00 {
            return Err(UnwrapError::BadPadding);
        }
        if pad_pos + 16 <= body_end {
            // Spec mandates padding lies in the last block only — scanning
            // past one full block back means there was no `0x80` and
            // every trailing byte was `0x00`.  Reject.
            return Err(UnwrapError::BadPadding);
        }
    }
    if plain[pad_pos] != 0x80 {
        return Err(UnwrapError::BadPadding);
    }
    let plaintext_len = pad_pos;

    if out.len() < plaintext_len + 2 {
        return Err(UnwrapError::Overflow);
    }

    // The R-MAC receipt authenticated the ciphertext and the R-ENC relation
    // receipt bound the plaintext to it, so the authenticated plaintext is
    // copied out verbatim. The copy itself is receipt-bound
    // (`rng_exact::copy_exact`: pointer publication, volatile byte copy with
    // progress, and two independent read-back relations; it wipes the
    // destination on any failure) so a skipped or shortened copy cannot
    // release stale bytes behind an `Ok`. There is no complementing
    // infective mask anywhere on this path: it returned `Ok` on a mismatch
    // and its XOR-0xFF garble was invertible by the attacker.
    if crate::rng_exact::copy_exact(&plain[..plaintext_len], &mut out[..plaintext_len]).is_err() {
        #[cfg(feature = "debug-log")]
        secure_log!("[SCP03] RELEASE COPY RECEIPT MISMATCH");
        return Err(UnwrapError::RelationMismatch);
    }
    out[plaintext_len] = sw[0];
    out[plaintext_len + 1] = sw[1];

    session.inc_counter();

    Ok(plaintext_len + 2)
}

// `aes128_cbc_decrypt` lives in `crate::scp03_logic` (re-exported via
// the `pub use` block at the top of this file) so the round-trip KATs
// in `scp03_logic::tests` exercise both directions on the host.

// `build_put_key_apdu` lives in `crate::scp03_logic` now (re-exported via
// `pub use` at the top of this file). Tests for the APDU layout + KCV +
// AES/CMAC primitives also live there — and unlike the `#[cfg(test)]`
// block that used to be here, they actually run under
// `cargo test -p sphincs-tz-secure` because `scp03_logic` is un-gated.

```


### `secure/src/optiga/shield.rs`

```rust
//! Shielded Connection for OPTIGA Trust M (AES-128-CCM-8).
//!
//! Provides an E2E encrypted I2C channel between the STM32U585 secure world
//! and the OPTIGA Trust M chip. Satisfies Invariant #3 (encrypted tunnel).
//!
//! **Protocol:**
//! - Root of trust: Platform Binding Secret (PBS) at OID 0xE140
//! - Key derivation: TLS 1.2 PRF with HMAC-SHA256
//! - Encryption: AES-128-CCM with 8-byte MAC tag
//! - 4-step handshake establishes per-session keys
//!
//! **Crypto dependencies:** Uses `aes` (block cipher), `hmac`, `sha2` —
//! all already in the project's Cargo.toml. AES-128-CCM is implemented
//! manually (CTR mode + CBC-MAC) to avoid adding a `ccm` crate dependency.

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use zeroize::Zeroize;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// AES-128-CCM MAC tag length (8 bytes, "CCM-8").
const CCM_TAG_LEN: usize = 8;
/// AES block size.
const AES_BLOCK: usize = 16;
/// CCM nonce length (we use 8 bytes: 4 base + 4 sequence).
const CCM_NONCE_LEN: usize = 8;

/// Shielded connection header: SCTR(1) + SeqNum(4) = 5 bytes.
const SC_HEADER_LEN: usize = 5;
/// Total overhead per message: header + MAC tag.
const SC_OVERHEAD: usize = SC_HEADER_LEN + CCM_TAG_LEN;

/// SCTR byte values.
const SCTR_HANDSHAKE_HELLO: u8 = 0x00;
const SCTR_HANDSHAKE_FINISHED: u8 = 0x08;
const SCTR_RECORD_FULL: u8 = 0x23; // Record type + full protection

/// Infineon's presentation-layer reference accepts a received slave sequence
/// only when it advances by 1..=DL_TRANS_REPEAT. `DL_TRANS_REPEAT` is 3 in
/// `ifx_i2c_config.h`; a wider jump is not a valid recovery transition.
const PRL_MAX_FORWARD_DELTA: u32 = 3;
/// Renegotiate before a record sequence reaches the reference driver's nonce
/// exhaustion threshold.
const PRL_SEQUENCE_THRESHOLD: u32 = 0xFFFF_FFF0;

/// Protocol version for pre-shared-secret mode.
const PROTOCOL_VERSION: u8 = 0x01;

/// TLS PRF label for Platform Binding key derivation.
const PRF_LABEL: &[u8] = b"Platform Binding";

/// Session key material length: 2×16 (keys) + 2×4 (nonces) = 40 bytes.
const SESSION_KEY_LEN: usize = 40;

/// Master random length.
const RANDOM_LEN: usize = 32;

/// Read a sequence value/complement pair through volatile accesses and bind it
/// to an inclusive upper limit. Volatile reads are deliberate: without them,
/// LTO can common-subexpression-eliminate the second FI check across
/// `wait_random`, leaving one skippable machine-code relation.
#[inline(always)]
fn sequence_pair_at_most_volatile(
    sequence: *const u32,
    sequence_inv: *const u32,
    upper_limit: u32,
) -> bool {
    let value = unsafe { core::ptr::read_volatile(sequence) };
    let value_inv = unsafe { core::ptr::read_volatile(sequence_inv) };
    (value ^ value_inv) == u32::MAX && value <= upper_limit
}

/// Read and validate a response-sequence window through volatile accesses so
/// both source-level checks remain independent in the optimized artifact.
#[inline(always)]
fn response_sequence_window_volatile(
    last_sequence: *const u32,
    last_sequence_inv: *const u32,
    received_sequence: *const u32,
) -> bool {
    let last = unsafe { core::ptr::read_volatile(last_sequence) };
    let last_inv = unsafe { core::ptr::read_volatile(last_sequence_inv) };
    let received = unsafe { core::ptr::read_volatile(received_sequence) };
    (last ^ last_inv) == u32::MAX
        && received > last
        && received.wrapping_sub(last) <= PRL_MAX_FORWARD_DELTA
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum ShieldError {
    NotActive,
    /// The handshake did not complete for **transport** reasons: a PRL
    /// transceive failed, or a frame was short/malformed/oversized. The
    /// exchange never reached the point of proving anything.
    ///
    /// **This tells you NOTHING about the PBS** (work-todo D1 follow-up). It
    /// must not be read as "the pairing secret is wrong", because the caller
    /// that asks that question — `rotate_pbs_to_salted`'s resume probe —
    /// answers "not rotated yet" by **rewriting E140**, the operation that
    /// bricked the bench chip (`docs/secure-elements/optiga-brick-postmortem.md`).
    HandshakeTransport,
    /// The exchange completed and the OPTIGA's `SlaveFinished` did **not**
    /// authenticate under the session keys we derived from the loaded PBS —
    /// CCM MAC failure, or a `random_S` / `master_seq` echo mismatch after a
    /// successful decrypt.
    ///
    /// This is an **authoritative** verdict: the chip answered, and the answer
    /// proves our PBS is not the one it holds. Directly analogous to
    /// `Se050Error::Scp03` (cryptogram mismatch) as opposed to
    /// `Se050Error::Transport`, which is the split this mirrors.
    HandshakeRejected,
    DecryptFailed,
    BufferOverflow,
    NoPbs,
}

// ---------------------------------------------------------------------------
// ShieldedConnection state
// ---------------------------------------------------------------------------

/// Shielded Connection session state.
///
/// Manages the AES-128-CCM keys and sequence counters for encrypted
/// communication with the OPTIGA Trust M chip.
pub struct ShieldedConnection {
    /// Host→OPTIGA encryption key (16 bytes).
    enc_key: [u8; 16],
    /// OPTIGA→Host decryption key (16 bytes).
    dec_key: [u8; 16],
    /// Base nonce for encryption direction (4 bytes).
    enc_nonce_base: [u8; 4],
    /// Base nonce for decryption direction (4 bytes).
    dec_nonce_base: [u8; 4],
    /// Encryption message sequence counter.
    enc_seq: u32,
    /// Complement binding for the next host→OPTIGA sequence number.
    enc_seq_inv: u32,
    /// Last authenticated OPTIGA→host sequence number.
    dec_seq: u32,
    /// Complement binding for `dec_seq`; any torn or faulted publication is
    /// rejected before a record can be authenticated.
    dec_seq_inv: u32,
    /// Whether the shielded connection is active.
    pub active: bool,
    /// Platform Binding Secret. 64 bytes per OPTIGA Trust M SRM §
    /// "Platform Binding Secret" ("It shall be 64 bytes …") — derived
    /// on demand from the configured device root via
    /// `hw::secret_keys::optiga_pairing_secret` (DHUK in the current
    /// bring-up transport path; OTP only in explicit dev/legacy builds).
    /// This buffer does not implement the still-open fresh-TRNG
    /// production-final pairing protocol.
    pbs: [u8; 64],
    /// Whether PBS has been loaded.
    pub pbs_loaded: bool,
}

/// Validate one OPTIGA→host response counter against the authenticated
/// value/complement state and Infineon's bounded retransmission window.
///
/// The full relation is evaluated twice around an FI delay. The caller owns
/// and double-checks the fail-initialized receipt, so neither an omitted call
/// nor one skipped rejection can authorize a replay or an unbounded jump.
#[inline(never)]
#[export_name = "pqsigner_optiga_sequence_verify_into"]
pub(crate) fn verify_response_sequence_into(
    last_sequence: u32,
    last_sequence_inv: u32,
    received_sequence: u32,
    receipt: &mut u32,
) {
    let last_sequence_snapshot = last_sequence;
    let last_sequence_inv_snapshot = last_sequence_inv;
    let received_sequence_snapshot = received_sequence;
    unsafe {
        core::ptr::write_volatile(receipt, crate::fi::FAIL_SENTINEL);
    }
    if !response_sequence_window_volatile(
        core::ptr::addr_of!(last_sequence_snapshot),
        core::ptr::addr_of!(last_sequence_inv_snapshot),
        core::ptr::addr_of!(received_sequence_snapshot),
    ) {
        return;
    }
    crate::fi::wait_random();
    if !response_sequence_window_volatile(
        core::ptr::addr_of!(last_sequence_snapshot),
        core::ptr::addr_of!(last_sequence_inv_snapshot),
        core::ptr::addr_of!(received_sequence_snapshot),
    ) {
        return;
    }
    unsafe {
        core::ptr::write_volatile(receipt, crate::fi::OK_SENTINEL);
    }
}

/// Publish an authenticated response counter as a duplicated value/complement
/// state transition. READY is represented by the caller-owned success receipt;
/// a torn or omitted publication leaves that receipt failed.
#[inline(never)]
#[export_name = "pqsigner_optiga_sequence_commit_into"]
pub(crate) fn commit_sequence_state_into(
    sequence: u32,
    destination: &mut u32,
    destination_inv: &mut u32,
    receipt: &mut u32,
) {
    unsafe {
        core::ptr::write_volatile(receipt, crate::fi::FAIL_SENTINEL);
    }
    unsafe {
        core::ptr::write_volatile(destination, sequence);
        core::ptr::write_volatile(destination, sequence);
        core::ptr::write_volatile(destination_inv, !sequence);
        core::ptr::write_volatile(destination_inv, !sequence);
    }
    if unsafe { core::ptr::read_volatile(destination) } != sequence
        || unsafe { core::ptr::read_volatile(destination_inv) } != !sequence
    {
        return;
    }
    crate::fi::wait_random();
    if unsafe { core::ptr::read_volatile(destination) } != sequence
        || unsafe { core::ptr::read_volatile(destination_inv) } != !sequence
    {
        return;
    }
    unsafe {
        core::ptr::write_volatile(receipt, crate::fi::OK_SENTINEL);
    }
}

/// Atomically reserve one host→OPTIGA CCM sequence number by publishing its
/// successor before any ciphertext is released. A transport failure may leave
/// a harmless gap, but a skipped increment can never reuse a nonce.
#[inline(never)]
#[export_name = "pqsigner_optiga_sequence_reserve_tx_into"]
pub(crate) fn reserve_transmit_sequence_into(
    current_sequence: u32,
    current_sequence_inv: u32,
    destination: &mut u32,
    destination_inv: &mut u32,
    receipt: &mut u32,
) {
    let current_sequence_snapshot = current_sequence;
    let current_sequence_inv_snapshot = current_sequence_inv;
    unsafe {
        core::ptr::write_volatile(receipt, crate::fi::FAIL_SENTINEL);
    }
    if !sequence_pair_at_most_volatile(
        core::ptr::addr_of!(current_sequence_snapshot),
        core::ptr::addr_of!(current_sequence_inv_snapshot),
        PRL_SEQUENCE_THRESHOLD,
    ) {
        return;
    }
    let next_sequence = current_sequence + 1;
    unsafe {
        core::ptr::write_volatile(destination, next_sequence);
        core::ptr::write_volatile(destination, next_sequence);
        core::ptr::write_volatile(destination_inv, !next_sequence);
        core::ptr::write_volatile(destination_inv, !next_sequence);
    }
    if !sequence_pair_at_most_volatile(
        core::ptr::addr_of!(current_sequence_snapshot),
        core::ptr::addr_of!(current_sequence_inv_snapshot),
        PRL_SEQUENCE_THRESHOLD,
    )
        || unsafe { core::ptr::read_volatile(destination) } != next_sequence
        || unsafe { core::ptr::read_volatile(destination_inv) } != !next_sequence
    {
        return;
    }
    crate::fi::wait_random();
    if !sequence_pair_at_most_volatile(
        core::ptr::addr_of!(current_sequence_snapshot),
        core::ptr::addr_of!(current_sequence_inv_snapshot),
        PRL_SEQUENCE_THRESHOLD,
    )
        || unsafe { core::ptr::read_volatile(destination) } != next_sequence
        || unsafe { core::ptr::read_volatile(destination_inv) } != !next_sequence
    {
        return;
    }
    unsafe {
        core::ptr::write_volatile(receipt, crate::fi::OK_SENTINEL);
    }
}

impl ShieldedConnection {
    pub const fn new() -> Self {
        Self {
            enc_key: [0; 16],
            dec_key: [0; 16],
            enc_nonce_base: [0; 4],
            dec_nonce_base: [0; 4],
            enc_seq: 0,
            enc_seq_inv: !0,
            dec_seq: 0,
            dec_seq_inv: !0,
            active: false,
            pbs: [0; 64],
            pbs_loaded: false,
        }
    }

    /// Load the Platform Binding Secret from caller-provided buffer.
    pub fn load_pbs(&mut self, pbs: &[u8; 64]) {
        self.pbs.copy_from_slice(pbs);
        self.pbs_loaded = true;
    }

    /// Zeroize the live Shielded-Connection session keys and force a fresh
    /// handshake on next use.
    ///
    /// Reached from `OptigaTrustM`'s `zeroize_caches` on the lock / idle-wipe
    /// / panic path (`nsc::zeroize_sensitive_state`). The `OptigaTrustM`
    /// driver is a `static mut` singleton, so the `Drop` impl below never
    /// runs in production — without this the AES-128-CCM session keys that
    /// wrap `half_O` on the OPTIGA I2C bus would persist in secure SRAM
    /// through the entire locked state, where they could combine with a
    /// captured bus transcript to recover the half. Clearing `active` makes
    /// `ensure_shield` re-handshake on the next OPTIGA APDU (the same
    /// recovery the HIGH-9 renegotiation threshold relies on). The PBS is
    /// intentionally retained: it is the long-lived pairing root (loaded
    /// once at boot, re-derivable from the OTP/DHUK master) needed to
    /// re-derive the session keys on the next handshake.
    /// (audit secret-lifecycle 20260611, MEDIUM-1)
    pub fn zeroize_session(&mut self) {
        self.enc_key.zeroize();
        self.dec_key.zeroize();
        self.enc_nonce_base.zeroize();
        self.dec_nonce_base.zeroize();
        crate::fi::zeroize_barrier();
        self.enc_seq = 0;
        self.enc_seq_inv = !0;
        self.dec_seq = 0;
        self.dec_seq_inv = !0;
        self.active = false;
    }

    /// Construct a deterministic authenticated-record state for the host-only
    /// protocol tests. This is absent from firmware builds.
    #[cfg(test)]
    pub(crate) fn activate_for_test(
        &mut self,
        key: [u8; 16],
        nonce_base: [u8; 4],
        next_master_sequence: u32,
        last_slave_sequence: u32,
    ) {
        self.enc_key = key;
        self.dec_key = key;
        self.enc_nonce_base = nonce_base;
        self.dec_nonce_base = nonce_base;
        self.enc_seq = next_master_sequence;
        self.enc_seq_inv = !next_master_sequence;
        self.dec_seq = last_slave_sequence;
        self.dec_seq_inv = !last_slave_sequence;
        self.active = true;
    }

    /// Expose only the bound counter state needed by host protocol tests.
    #[cfg(test)]
    pub(crate) fn sequence_state_for_test(&self) -> (u32, u32, u32, u32) {
        (
            self.enc_seq,
            self.enc_seq_inv,
            self.dec_seq,
            self.dec_seq_inv,
        )
    }

    /// Derive session keys from the PBS and the chip-provided `random_S`.
    ///
    /// Uses TLS 1.2 PRF (HMAC-SHA256) to expand:
    ///   `PRF(pbs, "Platform Binding", random_S)` → 40 bytes
    ///
    /// Note: Infineon's PRL only uses `random_S` (single 32-byte buffer
    /// `p_ctx->prl.random`); there is no `random_M` in the handshake —
    /// see `ifx_i2c_presentation_layer.c:285-319,497-500`.
    ///
    /// Output layout (matches `PRL_MASTER_*_OFFSET` in the reference):
    ///   [0..16]  = Master Encryption Key (host→chip)
    ///   [16..32] = Master Decryption Key (chip→host)
    ///   [32..36] = Encryption nonce base
    ///   [36..40] = Decryption nonce base
    fn derive_session_keys(&mut self, random_s: &[u8; 32]) {
        let mut key_material = [0u8; SESSION_KEY_LEN];
        tls_prf_sha256(&self.pbs, PRF_LABEL, random_s, &mut key_material);

        self.enc_key.copy_from_slice(&key_material[0..16]);
        self.dec_key.copy_from_slice(&key_material[16..32]);
        self.enc_nonce_base.copy_from_slice(&key_material[32..36]);
        self.dec_nonce_base.copy_from_slice(&key_material[36..40]);
        self.enc_seq = 0;
        self.enc_seq_inv = !0;
        self.dec_seq = 0;
        self.dec_seq_inv = !0;

        key_material.zeroize();
    }

    /// Build the 8-byte CCM nonce from base + sequence counter.
    fn build_nonce(base: &[u8; 4], seq: u32) -> [u8; CCM_NONCE_LEN] {
        let mut nonce = [0u8; CCM_NONCE_LEN];
        nonce[..4].copy_from_slice(base);
        nonce[4] = (seq >> 24) as u8;
        nonce[5] = (seq >> 16) as u8;
        nonce[6] = (seq >> 8) as u8;
        nonce[7] = seq as u8;
        nonce
    }

    /// Build AAD (Associated Authenticated Data) for CCM.
    ///
    /// AAD format: `SCTR(1) | SeqNum(4 BE) | ProtocolVersion(1) | PlaintextLen(2 BE)`
    fn build_aad(sctr: u8, seq: u32, plaintext_len: u16) -> [u8; 8] {
        [
            sctr,
            (seq >> 24) as u8,
            (seq >> 16) as u8,
            (seq >> 8) as u8,
            seq as u8,
            PROTOCOL_VERSION,
            (plaintext_len >> 8) as u8,
            plaintext_len as u8,
        ]
    }

    // -----------------------------------------------------------------------
    // Encrypt / Decrypt
    // -----------------------------------------------------------------------

    /// Encrypt an APDU command for the shielded connection.
    ///
    /// Output format: `SCTR(1) | SeqNum(4 BE) | Ciphertext | MAC(8)`
    ///
    /// Returns the total output length.
    pub fn wrap_command(
        &mut self,
        plaintext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, ShieldError> {
        if !self.active {
            return Err(ShieldError::NotActive);
        }

        // Infineon's reference permits the next master sequence through
        // 0xFFFFFFF0 and renegotiates once the next sequence would exceed that
        // threshold. Beyond it the AEAD nonce approaches wrap/reuse. Force the
        // connection closed so the caller triggers a fresh handshake.
        if self.enc_seq > PRL_SEQUENCE_THRESHOLD {
            self.active = false;
            return Err(ShieldError::NotActive);
        }

        // The reference renegotiates before another transaction when the last
        // authenticated slave counter has reached the threshold. Check the
        // value/complement relation twice so a torn receive-state update cannot
        // be bypassed by one omitted condition.
        if !sequence_pair_at_most_volatile(
            core::ptr::addr_of!(self.dec_seq),
            core::ptr::addr_of!(self.dec_seq_inv),
            PRL_SEQUENCE_THRESHOLD - 1,
        ) {
            self.active = false;
            return Err(ShieldError::NotActive);
        }
        crate::fi::wait_random();
        if !sequence_pair_at_most_volatile(
            core::ptr::addr_of!(self.dec_seq),
            core::ptr::addr_of!(self.dec_seq_inv),
            PRL_SEQUENCE_THRESHOLD - 1,
        ) {
            self.active = false;
            return Err(ShieldError::NotActive);
        }

        let out_len = SC_HEADER_LEN + plaintext.len() + CCM_TAG_LEN;
        if out_len > out.len() {
            return Err(ShieldError::BufferOverflow);
        }

        // Guard the internal scratch too: the caller's `out` check above does
        // not prove that plaintext + tag fits this fixed staging buffer.
        if plaintext.len() + CCM_TAG_LEN > 600 {
            return Err(ShieldError::BufferOverflow);
        }

        // Reserve the successor before materializing or releasing ciphertext.
        // If transmission later fails, a sequence gap is safe and is accepted
        // by Infineon's bounded retry window; reusing a CCM nonce is not.
        let sequence = self.enc_seq;
        let mut sequence_reservation_receipt = crate::fi::FAIL_SENTINEL;
        reserve_transmit_sequence_into(
            sequence,
            self.enc_seq_inv,
            &mut self.enc_seq,
            &mut self.enc_seq_inv,
            &mut sequence_reservation_receipt,
        );
        if unsafe { core::ptr::read_volatile(&sequence_reservation_receipt) }
            != crate::fi::OK_SENTINEL
        {
            self.active = false;
            out[..out_len].zeroize();
            crate::fi::zeroize_barrier();
            return Err(ShieldError::NotActive);
        }
        crate::fi::wait_random();
        if unsafe { core::ptr::read_volatile(&sequence_reservation_receipt) }
            != crate::fi::OK_SENTINEL
        {
            self.active = false;
            out[..out_len].zeroize();
            crate::fi::zeroize_barrier();
            return Err(ShieldError::NotActive);
        }

        // Header: SCTR + SeqNum
        out[0] = SCTR_RECORD_FULL;
        out[1] = (sequence >> 24) as u8;
        out[2] = (sequence >> 16) as u8;
        out[3] = (sequence >> 8) as u8;
        out[4] = sequence as u8;

        // Build nonce and AAD
        let nonce = Self::build_nonce(&self.enc_nonce_base, sequence);
        let aad = Self::build_aad(SCTR_RECORD_FULL, sequence, plaintext.len() as u16);

        // AES-128-CCM encrypt
        let mut ciphertext_and_tag = [0u8; 600];
        let ct_len = aes128_ccm_encrypt(
            &self.enc_key,
            &nonce,
            &aad,
            plaintext,
            &mut ciphertext_and_tag,
        );

        out[SC_HEADER_LEN..SC_HEADER_LEN + ct_len].copy_from_slice(&ciphertext_and_tag[..ct_len]);
        Ok(out_len)
    }

    /// Decrypt a response from the shielded connection.
    ///
    /// Input format: `SCTR(1) | SeqNum(4 BE) | Ciphertext | MAC(8)`
    ///
    /// Returns the plaintext length.
    pub fn unwrap_response(
        &mut self,
        input: &[u8],
        out: &mut [u8],
        auth_receipt: &mut u32,
    ) -> Result<usize, ShieldError> {
        unsafe {
            core::ptr::write_volatile(auth_receipt, crate::fi::FAIL_SENTINEL);
        }
        out.fill(0);
        crate::fi::zeroize_barrier();
        if !self.active {
            return Err(ShieldError::NotActive);
        }
        if input.len() < SC_OVERHEAD {
            return Err(ShieldError::DecryptFailed);
        }

        let sctr = input[0];
        if sctr != SCTR_RECORD_FULL {
            // HIGH-M16: the record type byte is part of the AAD, and
            // we also want to refuse alert / handshake frames coming
            // back at this stage — only full-protection record frames
            // are valid responses to a wrapped command.
            return Err(ShieldError::DecryptFailed);
        }
        let seq = ((input[1] as u32) << 24)
            | ((input[2] as u32) << 16)
            | ((input[3] as u32) << 8)
            | input[4] as u32;

        // Bind the received counter to the last authenticated handshake or
        // record state. Infineon's reference permits only a 1..=3 advance to
        // account for bounded transport retransmission. A caller-owned receipt
        // plus two checks makes an omitted verifier or one skipped rejection
        // fail closed before CCM can expose plaintext.
        let mut sequence_receipt = crate::fi::FAIL_SENTINEL;
        verify_response_sequence_into(
            self.dec_seq,
            self.dec_seq_inv,
            seq,
            &mut sequence_receipt,
        );
        if unsafe { core::ptr::read_volatile(&sequence_receipt) } != crate::fi::OK_SENTINEL {
            return Err(ShieldError::DecryptFailed);
        }
        crate::fi::wait_random();
        if unsafe { core::ptr::read_volatile(&sequence_receipt) } != crate::fi::OK_SENTINEL {
            return Err(ShieldError::DecryptFailed);
        }

        let ct_and_tag = &input[SC_HEADER_LEN..];
        let plaintext_len = ct_and_tag.len() - CCM_TAG_LEN;

        if plaintext_len > out.len() {
            return Err(ShieldError::BufferOverflow);
        }

        let nonce = Self::build_nonce(&self.dec_nonce_base, seq);
        let aad = Self::build_aad(SCTR_RECORD_FULL, seq, plaintext_len as u16);

        // A caller-owned fail receipt makes an omitted decrypt/authentication
        // call observable. Check it twice so one skipped rejection branch cannot
        // release plaintext that was written before CCM authentication.
        let mut ccm_receipt = crate::fi::FAIL_SENTINEL;
        aes128_ccm_decrypt_into(
            &self.dec_key,
            &nonce,
            &aad,
            ct_and_tag,
            out,
            &mut ccm_receipt,
        );
        if unsafe { core::ptr::read_volatile(&ccm_receipt) } != crate::fi::OK_SENTINEL {
            out[..plaintext_len].zeroize();
            crate::fi::zeroize_barrier();
            return Err(ShieldError::DecryptFailed);
        }
        crate::fi::wait_random();
        if unsafe { core::ptr::read_volatile(&ccm_receipt) } != crate::fi::OK_SENTINEL {
            out[..plaintext_len].zeroize();
            crate::fi::zeroize_barrier();
            return Err(ShieldError::DecryptFailed);
        }

        // Publish the authenticated counter through a duplicated value/
        // complement state update. If the helper call or one store is omitted,
        // the fail receipt or the complement check prevents this record from
        // being released and prevents stale state from authorizing a replay.
        let mut sequence_commit_receipt = crate::fi::FAIL_SENTINEL;
        commit_sequence_state_into(
            seq,
            &mut self.dec_seq,
            &mut self.dec_seq_inv,
            &mut sequence_commit_receipt,
        );
        if unsafe { core::ptr::read_volatile(&sequence_commit_receipt) }
            != crate::fi::OK_SENTINEL
        {
            out[..plaintext_len].zeroize();
            crate::fi::zeroize_barrier();
            return Err(ShieldError::DecryptFailed);
        }
        crate::fi::wait_random();
        if unsafe { core::ptr::read_volatile(&sequence_commit_receipt) }
            != crate::fi::OK_SENTINEL
        {
            out[..plaintext_len].zeroize();
            crate::fi::zeroize_barrier();
            return Err(ShieldError::DecryptFailed);
        }
        unsafe {
            core::ptr::write_volatile(auth_receipt, crate::fi::OK_SENTINEL);
        }
        Ok(plaintext_len)
    }

    // -----------------------------------------------------------------------
    // Handshake
    // -----------------------------------------------------------------------

    /// Perform the 4-step Shielded Connection handshake.
    ///
    /// Requires a mutable reference to the IFX I2C state for sending/receiving
    /// handshake messages directly (bypassing the shielded encryption layer).
    ///
    /// This must be called AFTER `open_application()` and BEFORE any protected
    /// APDU commands.
    pub unsafe fn establish(
        &mut self,
        ifx: &mut super::ifx_i2c::IfxState,
    ) -> Result<(), ShieldError> {
        if !self.pbs_loaded {
            return Err(ShieldError::NoPbs);
        }

        secure_log!("[OPTIGA/shield] establish: start");

        // Step 1: Send MasterHello via the presentation-layer path
        // (PRESENCE_BIT set in PCTR). Format: SCTR(0x00) | ProtoVer(0x01).
        // Note: Infineon PRL does NOT send a master random — the handshake
        // uses only `random_S` from SlaveHello. See `ifx_i2c_presentation_
        // layer.c:451-472`.
        let hello = [SCTR_HANDSHAKE_HELLO, PROTOCOL_VERSION];
        let mut resp = [0u8; 64];
        secure_log!("[OPTIGA/shield] sending MasterHello");
        let n = match ifx.transceive_prl(&hello, &mut resp) {
            Ok(n) => n,
            Err(e) => {
                secure_log!("[OPTIGA/shield] MasterHello transceive FAILED: {:?}", e);
                // Transport: the chip may not even have seen MasterHello.
                return Err(ShieldError::HandshakeTransport);
            }
        };

        // Step 2: Parse SlaveHello — 38 bytes total per Infineon
        // `ifx_i2c_presentation_layer.c::PRL_SLAVE_HELLO_LENGTH = 0x26`:
        //   byte 0      : SCTR (0x00)
        //   byte 1      : ProtocolVersion (0x01)
        //   bytes 2..34 : Random_S (32 bytes)
        //   bytes 34..38: SeqNum_S (4 bytes, big-endian)
        const SLAVE_HELLO_RANDOM_OFFSET: usize = 2;
        const SLAVE_HELLO_SEQ_OFFSET: usize = 34;
        const SLAVE_HELLO_LEN: usize = 38;

        secure_log!("[OPTIGA/shield] MasterHello response n={}", n);
        if n != SLAVE_HELLO_LEN
            || resp[0] != SCTR_HANDSHAKE_HELLO
            || resp[1] != PROTOCOL_VERSION
        {
            secure_log!(
                "[OPTIGA/shield] SlaveHello malformed (n={} expected={}), bytes=[{:02x}{:02x}{:02x}{:02x}...]",
                n, SLAVE_HELLO_LEN, resp[0], resp[1], resp[2], resp[3]
            );
            // Wrong size/type/version is a framing fault, not a PBS verdict.
            return Err(ShieldError::HandshakeTransport);
        }
        let mut random_s = [0u8; RANDOM_LEN];
        random_s.copy_from_slice(
            &resp[SLAVE_HELLO_RANDOM_OFFSET..SLAVE_HELLO_RANDOM_OFFSET + RANDOM_LEN]
        );
        let slave_seq = u32::from_be_bytes([
            resp[SLAVE_HELLO_SEQ_OFFSET],
            resp[SLAVE_HELLO_SEQ_OFFSET + 1],
            resp[SLAVE_HELLO_SEQ_OFFSET + 2],
            resp[SLAVE_HELLO_SEQ_OFFSET + 3],
        ]);
        secure_log!("[OPTIGA/shield] slave_seq={:#010x}", slave_seq);

        // Step 3: Derive session keys from PBS + random_S.
        self.derive_session_keys(&random_s);

        // Step 4: Send MasterFinished.
        // Plaintext = random_S (32) || slave_seq_num (4 BE) = 36 bytes
        //   — see `ifx_i2c_presentation_layer.c:512-521`.
        // All three of {CCM nonce counter, AAD seq, header seq} are the
        // slave_sequence_number (not zero). See `ifx_i2c_presentation_
        // layer.c:523-542`.
        let mut finished_plain = [0u8; 36];
        finished_plain[..32].copy_from_slice(&random_s);
        finished_plain[32..36].copy_from_slice(&slave_seq.to_be_bytes());

        let nonce = Self::build_nonce(&self.enc_nonce_base, slave_seq);
        let aad = Self::build_aad(SCTR_HANDSHAKE_FINISHED, slave_seq, 36);

        let mut finished_enc = [0u8; 64];
        let ct_len = aes128_ccm_encrypt(
            &self.enc_key,
            &nonce,
            &aad,
            &finished_plain,
            &mut finished_enc,
        );
        // ct_len = 36 plaintext + 8 MAC = 44

        // Frame: SCTR(0x08) | SeqNum=slave_seq(4 BE) | ciphertext+tag(44)
        // = 5 + 44 = 49 bytes (PRL_FINISHED_DATA_LENGTH + 1).
        let mut finished_msg = [0u8; 128];
        finished_msg[0] = SCTR_HANDSHAKE_FINISHED;
        finished_msg[1..5].copy_from_slice(&slave_seq.to_be_bytes());
        finished_msg[5..5 + ct_len].copy_from_slice(&finished_enc[..ct_len]);
        let msg_len = 5 + ct_len;

        let mut resp2 = [0u8; 128];
        secure_log!("[OPTIGA/shield] sending MasterFinished ({}B)", msg_len);
        let n2 = ifx.transceive_prl(&finished_msg[..msg_len], &mut resp2)
            .map_err(|_| ShieldError::HandshakeTransport)?;
        secure_log!(
            "[OPTIGA/shield] MasterFinished response n={}, SCTR={:02x}",
            n2, resp2[0]
        );

        // Step 5: Verify SlaveFinished.
        // Format: SCTR(0x08) | master_seq(4 BE) | ct(36) | MAC(8) = 49 B.
        // See `ifx_i2c_presentation_layer.c:559-607`.
        const SLAVE_FINISHED_LEN: usize = SC_HEADER_LEN + 36 + CCM_TAG_LEN;
        if n2 != SLAVE_FINISHED_LEN {
            // Wrong-sized frame — framing fault, no PBS evidence.
            return Err(ShieldError::HandshakeTransport);
        }
        if resp2[0] != SCTR_HANDSHAKE_FINISHED {
            secure_log!("[OPTIGA/shield] SlaveFinished SCTR unexpected: {:02x}", resp2[0]);
            return Err(ShieldError::HandshakeTransport);
        }
        let master_seq = u32::from_be_bytes([resp2[1], resp2[2], resp2[3], resp2[4]]);
        secure_log!("[OPTIGA/shield] master_seq={:#010x}", master_seq);

        let dec_nonce = Self::build_nonce(&self.dec_nonce_base, master_seq);
        let slave_ct = &resp2[SC_HEADER_LEN..n2];
        let slave_pt_len = slave_ct.len() - CCM_TAG_LEN;

        // Upper-bound the plaintext against the fixed 64-byte `slave_plain`
        // sink BEFORE decrypting. `n2` is bounded only by `resp2.len()`
        // (128) inside `transceive_prl`, so a frame with `n2 > 77` yields
        // `slave_pt_len > 64`; `aes128_ccm_decrypt` would then write past
        // `slave_plain` and panic (bounds-check), aborting the unlock. The
        // I2C bus is the explicitly-untrusted channel this shielded
        // connection exists to protect (invariant #3), and a merely
        // malfunctioning OPTIGA is plausible-malformed input — so this
        // must fail closed, mirroring the `plaintext_len > out.len()` guard
        // `unwrap_response` already carries on the steady-state path. (A
        // conformant SlaveFinished is exactly 36 B of plaintext.)
        let mut slave_plain = [0u8; 64];
        if slave_pt_len > slave_plain.len() {
            secure_log!(
                "[OPTIGA/shield] SlaveFinished plaintext too long ({}B > {}B)",
                slave_pt_len,
                slave_plain.len()
            );
            // Oversized frame — malformed transport, no PBS evidence.
            return Err(ShieldError::HandshakeTransport);
        }
        let dec_aad = Self::build_aad(SCTR_HANDSHAKE_FINISHED, master_seq, slave_pt_len as u16);

        let mut ccm_receipt = crate::fi::FAIL_SENTINEL;
        aes128_ccm_decrypt_into(
            &self.dec_key,
            &dec_nonce,
            &dec_aad,
            slave_ct,
            &mut slave_plain,
            &mut ccm_receipt,
        );
        if unsafe { core::ptr::read_volatile(&ccm_receipt) } != crate::fi::OK_SENTINEL {
            slave_plain.zeroize();
            crate::fi::zeroize_barrier();
            secure_log!("[OPTIGA/shield] SlaveFinished decrypt FAILED");
            // CCM MAC failure under keys derived from the loaded PBS: the chip
            // holds a different PBS. THIS is the authoritative "wrong PBS".
            return Err(ShieldError::HandshakeRejected);
        }
        crate::fi::wait_random();
        if unsafe { core::ptr::read_volatile(&ccm_receipt) } != crate::fi::OK_SENTINEL {
            slave_plain.zeroize();
            crate::fi::zeroize_barrier();
            secure_log!("[OPTIGA/shield] SlaveFinished decrypt receipt changed");
            return Err(ShieldError::HandshakeRejected);
        }

        // Plaintext of SlaveFinished must be `random_S (32) || master_seq (4 BE)`.
        if slave_pt_len != 36 {
            // Authenticated (MAC passed) but the wrong shape — the chip is
            // speaking our session keys, so this is a chip/protocol fault, not
            // a transport one.
            return Err(ShieldError::HandshakeRejected);
        }
        let mut diff: u8 = 0;
        for i in 0..RANDOM_LEN {
            diff |= slave_plain[i] ^ random_s[i];
        }
        if diff != 0 {
            secure_log!("[OPTIGA/shield] SlaveFinished random_S mismatch");
            return Err(ShieldError::HandshakeRejected);
        }
        let echoed_master_seq = u32::from_be_bytes([
            slave_plain[32], slave_plain[33], slave_plain[34], slave_plain[35],
        ]);
        if echoed_master_seq != master_seq {
            secure_log!("[OPTIGA/shield] SlaveFinished master_seq mismatch");
            return Err(ShieldError::HandshakeRejected);
        }

        // Session established. Subsequent protected records use the
        // master_sequence_number counter (bumped before each send), and
        // the slave's responses must advance from the authenticated
        // `slave_seq` baseline by the reference driver's bounded 1..=3 window.
        // Publish that baseline before `active=true`, with a caller-owned
        // receipt so omitting the publication cannot open a replay window.
        let mut sequence_commit_receipt = crate::fi::FAIL_SENTINEL;
        commit_sequence_state_into(
            slave_seq,
            &mut self.dec_seq,
            &mut self.dec_seq_inv,
            &mut sequence_commit_receipt,
        );
        if unsafe { core::ptr::read_volatile(&sequence_commit_receipt) }
            != crate::fi::OK_SENTINEL
        {
            finished_plain.zeroize();
            slave_plain.zeroize();
            crate::fi::zeroize_barrier();
            return Err(ShieldError::HandshakeRejected);
        }
        crate::fi::wait_random();
        if unsafe { core::ptr::read_volatile(&sequence_commit_receipt) }
            != crate::fi::OK_SENTINEL
        {
            finished_plain.zeroize();
            slave_plain.zeroize();
            crate::fi::zeroize_barrier();
            return Err(ShieldError::HandshakeRejected);
        }

        // `wrap_command` consumes the already-incremented master direction.
        // Publish it through the same value/complement receipt before making
        // the session active; an omitted baseline store must not permit nonce
        // zero or a stale nonce to be used.
        let next_master_sequence = match master_seq.checked_add(1) {
            Some(sequence) if sequence <= PRL_SEQUENCE_THRESHOLD => sequence,
            _ => {
                finished_plain.zeroize();
                slave_plain.zeroize();
                crate::fi::zeroize_barrier();
                return Err(ShieldError::HandshakeTransport);
            }
        };
        unsafe {
            core::ptr::write_volatile(
                &mut sequence_commit_receipt,
                crate::fi::FAIL_SENTINEL,
            );
        }
        commit_sequence_state_into(
            next_master_sequence,
            &mut self.enc_seq,
            &mut self.enc_seq_inv,
            &mut sequence_commit_receipt,
        );
        if unsafe { core::ptr::read_volatile(&sequence_commit_receipt) }
            != crate::fi::OK_SENTINEL
        {
            finished_plain.zeroize();
            slave_plain.zeroize();
            crate::fi::zeroize_barrier();
            return Err(ShieldError::HandshakeRejected);
        }
        crate::fi::wait_random();
        if unsafe { core::ptr::read_volatile(&sequence_commit_receipt) }
            != crate::fi::OK_SENTINEL
        {
            finished_plain.zeroize();
            slave_plain.zeroize();
            crate::fi::zeroize_barrier();
            return Err(ShieldError::HandshakeRejected);
        }
        self.active = true;

        finished_plain.zeroize();
        slave_plain.zeroize();

        secure_log!("[OPTIGA/shield] establish: DONE");
        Ok(())
    }
}

impl Drop for ShieldedConnection {
    fn drop(&mut self) {
        self.enc_key.zeroize();
        self.dec_key.zeroize();
        self.enc_nonce_base.zeroize();
        self.dec_nonce_base.zeroize();
        self.pbs.zeroize();
    }
}

// ---------------------------------------------------------------------------
// TLS 1.2 PRF (HMAC-SHA256)
// ---------------------------------------------------------------------------

/// TLS 1.2 PRF using HMAC-SHA256 (RFC 5246 §5).
///
/// `P_SHA256(secret, seed) = HMAC(secret, A(1) || seed) || HMAC(secret, A(2) || seed) || ...`
/// where `A(0) = seed`, `A(i) = HMAC(secret, A(i-1))`.
///
/// The full PRF seed is: `label || seed`.
fn tls_prf_sha256(secret: &[u8], label: &[u8], seed: &[u8], output: &mut [u8]) {
    use hmac::Mac;
    type HmacSha256 = hmac::Hmac<sha2::Sha256>;

    // Combine label + seed
    let mut combined = [0u8; 128];
    let combined_len = label.len() + seed.len();
    combined[..label.len()].copy_from_slice(label);
    combined[label.len()..combined_len].copy_from_slice(seed);
    let combined = &combined[..combined_len];

    // A(1) = HMAC(secret, seed)
    let mut a = hmac_sha256(secret, combined);

    let mut offset = 0;
    while offset < output.len() {
        // HMAC(secret, A(i) || seed)
        let mut mac = <HmacSha256 as Mac>::new_from_slice(secret).unwrap();
        mac.update(&a);
        mac.update(combined);
        let result = mac.finalize().into_bytes();

        let copy_len = (output.len() - offset).min(32);
        output[offset..offset + copy_len].copy_from_slice(&result[..copy_len]);
        offset += copy_len;

        // A(i+1) = HMAC(secret, A(i))
        if offset < output.len() {
            a = hmac_sha256(secret, &a);
        }
    }
}

/// Simple HMAC-SHA256.
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    use hmac::Mac;
    type HmacSha256 = hmac::Hmac<sha2::Sha256>;

    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).unwrap();
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

// ---------------------------------------------------------------------------
// AES-128-CCM-8 (manual implementation using AES block cipher)
// ---------------------------------------------------------------------------
//
// CCM (Counter with CBC-MAC) combines:
// 1. CBC-MAC for authentication (produces tag)
// 2. CTR mode for encryption (encrypts payload + tag)
//
// We use CCM-8: 8-byte MAC tag (t=8), 8-byte nonce (n=8, so q=7).

/// AES-128-CCM encrypt. Returns total output length (ciphertext + 8-byte tag).
fn aes128_ccm_encrypt(
    key: &[u8; 16],
    nonce: &[u8; CCM_NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
    out: &mut [u8],
) -> usize {
    let cipher = Aes128::new(key.into());
    let tag = ccm_cbc_mac(&cipher, nonce, aad, plaintext);

    // CTR mode: encrypt plaintext + tag
    // A_0 = Flags(1) || Nonce(8) || Counter(7, starting at 0)
    // We encrypt the tag with A_0, then plaintext with A_1, A_2, ...
    let mut a_block = [0u8; AES_BLOCK];
    // Flags: (t-2)/2 = 3 in bits 5-3, q-1 = 6 in bits 2-0
    // Actually for CCM with n=8, q=7 (15-8), flags for A_i = q-1 = 6
    a_block[0] = 6; // q - 1 = 7 - 1 = 6
    a_block[1..1 + CCM_NONCE_LEN].copy_from_slice(nonce);

    // Encrypt tag with A_0 (counter = 0)
    set_counter(&mut a_block, 0);
    let mut s0 = a_block;
    let s0_block = aes::Block::from_mut_slice(&mut s0);
    cipher.encrypt_block(s0_block);
    let mut encrypted_tag = [0u8; CCM_TAG_LEN];
    for i in 0..CCM_TAG_LEN {
        encrypted_tag[i] = tag[i] ^ s0[i];
    }

    // Encrypt plaintext with A_1, A_2, ...
    let mut counter: u64 = 1;
    let mut pt_offset = 0;
    while pt_offset < plaintext.len() {
        set_counter(&mut a_block, counter);
        let mut keystream = a_block;
        let ks_block = aes::Block::from_mut_slice(&mut keystream);
        cipher.encrypt_block(ks_block);

        let chunk = (plaintext.len() - pt_offset).min(AES_BLOCK);
        for i in 0..chunk {
            out[pt_offset + i] = plaintext[pt_offset + i] ^ keystream[i];
        }
        pt_offset += chunk;
        counter += 1;
    }

    // Append encrypted tag
    out[plaintext.len()..plaintext.len() + CCM_TAG_LEN]
        .copy_from_slice(&encrypted_tag);

    plaintext.len() + CCM_TAG_LEN
}

/// Recompute and compare the received CCM tag without trusting state from the
/// plaintext-decryption loop. The caller invokes this out-of-line operation
/// twice, so one omitted call or one fault-shortened verification cannot
/// authenticate a record.
#[inline(never)]
#[export_name = "pqsigner_optiga_ccm_tag_matches"]
fn ccm_tag_matches(
    key: &[u8; 16],
    nonce: &[u8; CCM_NONCE_LEN],
    aad: &[u8],
    ct_and_tag: &[u8],
    plaintext: &[u8],
) -> bool {
    use subtle::ConstantTimeEq;

    if ct_and_tag.len() < CCM_TAG_LEN
        || plaintext.len() != ct_and_tag.len() - CCM_TAG_LEN
    {
        return false;
    }

    let ct_len = ct_and_tag.len() - CCM_TAG_LEN;
    let received_enc_tag = &ct_and_tag[ct_len..];
    let cipher = Aes128::new(key.into());

    // Decrypt the received tag with A_0 independently of the plaintext pass.
    let mut a_block = [0u8; AES_BLOCK];
    a_block[0] = 6; // q - 1
    a_block[1..1 + CCM_NONCE_LEN].copy_from_slice(nonce);
    set_counter(&mut a_block, 0);
    let mut s0 = a_block;
    let s0_block = aes::Block::from_mut_slice(&mut s0);
    cipher.encrypt_block(s0_block);
    let mut received_tag = [0u8; CCM_TAG_LEN];
    for i in 0..CCM_TAG_LEN {
        received_tag[i] = received_enc_tag[i] ^ s0[i];
    }

    let expected_tag = ccm_cbc_mac(&cipher, nonce, aad, plaintext);
    received_tag
        .as_slice()
        .ct_eq(expected_tag.as_slice())
        .into()
}

/// Publish CCM authentication only after two independent full tag
/// recomputations. The caller fail-initializes and double-checks `receipt`.
#[inline(never)]
#[export_name = "pqsigner_optiga_ccm_verify_into"]
fn verify_ccm_tag_into(
    key: &[u8; 16],
    nonce: &[u8; CCM_NONCE_LEN],
    aad: &[u8],
    ct_and_tag: &[u8],
    plaintext: &[u8],
    receipt: &mut u32,
) {
    unsafe {
        core::ptr::write_volatile(receipt, crate::fi::FAIL_SENTINEL);
    }
    if !ccm_tag_matches(key, nonce, aad, ct_and_tag, plaintext) {
        return;
    }
    crate::fi::wait_random();
    if !ccm_tag_matches(key, nonce, aad, ct_and_tag, plaintext) {
        return;
    }
    unsafe {
        core::ptr::write_volatile(receipt, crate::fi::OK_SENTINEL);
    }
}

/// AES-128-CCM decrypt with caller-owned, fail-initialized authentication
/// receipt. Plaintext may be materialized internally before its tag is known,
/// but no caller accepts it until the receipt has passed two independent gates.
/// Authentication failure wipes the materialized prefix before returning.
#[inline(never)]
#[export_name = "pqsigner_optiga_ccm_decrypt_into"]
pub(crate) fn aes128_ccm_decrypt_into(
    key: &[u8; 16],
    nonce: &[u8; CCM_NONCE_LEN],
    aad: &[u8],
    ct_and_tag: &[u8],
    out: &mut [u8],
    auth_receipt: &mut u32,
) {
    unsafe {
        core::ptr::write_volatile(auth_receipt, crate::fi::FAIL_SENTINEL);
    }
    if ct_and_tag.len() < CCM_TAG_LEN {
        return;
    }

    let ct_len = ct_and_tag.len() - CCM_TAG_LEN;
    if ct_len > out.len() {
        return;
    }
    let ciphertext = &ct_and_tag[..ct_len];
    let cipher = Aes128::new(key.into());

    // CTR decrypt plaintext with A_1, A_2, ... . Authentication is performed
    // afterward by two independent full CCM tag recomputations.
    let mut a_block = [0u8; AES_BLOCK];
    a_block[0] = 6; // q - 1
    a_block[1..1 + CCM_NONCE_LEN].copy_from_slice(nonce);
    let mut counter: u64 = 1;
    let mut ct_offset = 0;
    while ct_offset < ct_len {
        set_counter(&mut a_block, counter);
        let mut keystream = a_block;
        let ks_block = aes::Block::from_mut_slice(&mut keystream);
        cipher.encrypt_block(ks_block);

        let chunk = (ct_len - ct_offset).min(AES_BLOCK);
        for i in 0..chunk {
            out[ct_offset + i] = ciphertext[ct_offset + i] ^ keystream[i];
        }
        ct_offset += chunk;
        counter += 1;
    }

    verify_ccm_tag_into(
        key,
        nonce,
        aad,
        ct_and_tag,
        &out[..ct_len],
        auth_receipt,
    );
    if unsafe { core::ptr::read_volatile(auth_receipt) } != crate::fi::OK_SENTINEL {
        // If a fault skips the valid-path branch into this cleanup, poison the
        // receipt before changing bytes that were covered by the successful
        // tag. The caller's two receipt gates then reject the wiped plaintext.
        unsafe {
            core::ptr::write_volatile(auth_receipt, crate::fi::FAIL_SENTINEL);
            core::ptr::write_volatile(auth_receipt, crate::fi::FAIL_SENTINEL);
        }
        out[..ct_len].zeroize();
        crate::fi::zeroize_barrier();
    }
}

#[cfg(test)]
pub(crate) fn ccm_encrypt_for_test(
    key: &[u8; 16],
    nonce: &[u8; CCM_NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
    out: &mut [u8],
) -> usize {
    aes128_ccm_encrypt(key, nonce, aad, plaintext, out)
}

/// Compute CCM CBC-MAC (authentication tag).
///
/// B_0 = Flags || Nonce || Q (message length)
/// If AAD present: B_1 = AAD_length(2) || AAD || padding
/// Then: B_i = plaintext blocks (padded to AES block size)
///
/// Returns the 8-byte truncated tag.
fn ccm_cbc_mac(
    cipher: &Aes128,
    nonce: &[u8; CCM_NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> [u8; CCM_TAG_LEN] {
    // B_0: Flags || Nonce || Q
    // Flags: bit 6 = Adata (1 if AAD present), bits 5-3 = (t-2)/2 = 3, bits 2-0 = q-1 = 6
    let has_aad: u8 = if aad.is_empty() { 0 } else { 1 << 6 };
    let flags = has_aad | (((CCM_TAG_LEN as u8 - 2) / 2) << 3) | 6;

    let mut b = [0u8; AES_BLOCK];
    b[0] = flags;
    b[1..1 + CCM_NONCE_LEN].copy_from_slice(nonce);

    // Q: message length in q=7 bytes (big-endian)
    let q_start = 1 + CCM_NONCE_LEN; // byte 9
    let msg_len = plaintext.len() as u64;
    for i in 0..7 {
        b[q_start + 6 - i] = ((msg_len >> (i * 8)) & 0xFF) as u8;
    }

    // CBC-MAC: T = E(K, B_0) XOR B_1, then E(K, T) XOR B_2, etc.
    let mut t = b;
    let t_block = aes::Block::from_mut_slice(&mut t);
    cipher.encrypt_block(t_block);

    // AAD processing
    if !aad.is_empty() {
        let mut aad_buf = [0u8; AES_BLOCK];
        // AAD length encoding (2 bytes for lengths < 0xFF00)
        let aad_len = aad.len() as u16;
        aad_buf[0] = (aad_len >> 8) as u8;
        aad_buf[1] = aad_len as u8;

        // Fill rest of first block with AAD data
        let first_chunk = aad.len().min(AES_BLOCK - 2);
        aad_buf[2..2 + first_chunk].copy_from_slice(&aad[..first_chunk]);

        // XOR and encrypt
        for i in 0..AES_BLOCK {
            t[i] ^= aad_buf[i];
        }
        let t_block = aes::Block::from_mut_slice(&mut t);
        cipher.encrypt_block(t_block);

        // Remaining AAD blocks
        let mut aad_offset = first_chunk;
        while aad_offset < aad.len() {
            let mut block = [0u8; AES_BLOCK];
            let chunk = (aad.len() - aad_offset).min(AES_BLOCK);
            block[..chunk].copy_from_slice(&aad[aad_offset..aad_offset + chunk]);

            for i in 0..AES_BLOCK {
                t[i] ^= block[i];
            }
            let t_block = aes::Block::from_mut_slice(&mut t);
            cipher.encrypt_block(t_block);
            aad_offset += chunk;
        }
    }

    // Plaintext processing
    let mut pt_offset = 0;
    while pt_offset < plaintext.len() {
        let mut block = [0u8; AES_BLOCK];
        let chunk = (plaintext.len() - pt_offset).min(AES_BLOCK);
        block[..chunk].copy_from_slice(&plaintext[pt_offset..pt_offset + chunk]);

        for i in 0..AES_BLOCK {
            t[i] ^= block[i];
        }
        let t_block = aes::Block::from_mut_slice(&mut t);
        cipher.encrypt_block(t_block);
        pt_offset += chunk;
    }

    // Truncate to CCM_TAG_LEN
    let mut tag = [0u8; CCM_TAG_LEN];
    tag.copy_from_slice(&t[..CCM_TAG_LEN]);
    tag
}

/// Set the counter value in an A_i block (last 7 bytes, big-endian).
fn set_counter(a: &mut [u8; AES_BLOCK], counter: u64) {
    let start = 1 + CCM_NONCE_LEN; // byte 9
    for i in 0..7 {
        a[start + 6 - i] = ((counter >> (i * 8)) & 0xFF) as u8;
    }
}

```


### `secure/src/hw/flash.rs`

```rust
//! Minimal secure flash driver for STM32U585.
//!
//! Provides read/write/erase for the last two pages of bank 1:
//! - Page 127 (0x0C0F_E000): first-boot provisioning journal (KEY_PAGE)
//! - Page 126 (0x0C0F_C000): DHUK-wrapped SE050 BHK when `bhk` is enabled
//!
//! OPTIGA PBS bytes are derived rather than stored verbatim, but the
//! `rdp2-self-lock` final PBS depends on the persisted salt in page 127.
//! Firmware-update verification has no persistent failure counter.
//!
//! The linker script (`memory-stm32u585.x`) must shrink FLASH LENGTH
//! by 16 KB to prevent firmware code from being placed in these pages.
//!
//! ## Unsafe surface
//!
//! All MMIO register access is funnelled through `hw::mmio::{Reg32, RoReg32}`,
//! which encapsulates `read_volatile` / `write_volatile` once per address.
//! The remaining `unsafe fn` markers sit on the public flash-*mutating*
//! APIs (erase / program / bump) for commit-visibility — callers must
//! reason about *which* flash bytes they are about to change. Read-only
//! helpers (`pin_attempts_read`, `offchain_count_read`,
//! `last_userop_count_read`, `offchain_count_is_registered`,
//! `is_wipe_armed`) are safe `fn` because they cannot
//! commit anything; raw pointer derefs of flash memory inside them stay
//! in tight `unsafe { ... }` blocks with `// SAFETY:` comments.

use core::ptr::{read_volatile, write_volatile};

use crate::flash_policy::{self, GenericNsPage, GenericSecurePage, GenericSecureQwAddr};
use crate::hw::mmio::{Reg32, RoReg32};

// ---------------------------------------------------------------------------
// Flash controller registers (secure alias)
// ---------------------------------------------------------------------------

const FLASH: u32 = 0x5002_2000;

// Non-secure-controller registers MUST be reached via the NS alias of the
// FLASH peripheral block (0x4002_2000), even when called from the secure
// world. The secure alias of the SAME register set silently corrupts NSCR
// writes — every NSCR-initiated program/erase returns PGSERR on STM32U585.
// ST's HAL `FLASH_PageErase`/`FLASH_Program_QuadWord` confirm this: when
// `IS_FLASH_SECURE_OPERATION()` is false (i.e. the caller is operating on
// NS-classified pages) HAL uses `&(FLASH_NS->NSCR)` — the NS alias of the
// same register block. Driving NSCR via the secure alias was the cause of
// the bank-2 erase failure during the fwup-transport-e2e bring-up.
const FLASH_NS: u32 = 0x4002_2000;

/// `FLASH_OPTR` offset (RM0456 §7.11) — RDP[7:0] in the low byte. And
/// `FLASH_SECBOOTADD0R` offset (secure boot-address option register), confirmed
/// as `FLASH_S+0x4C` by the vendor SVD (`STM32CubeProgrammer/SVD/STM32U585.svd`,
/// `FLASH_SECBOOTADD0R` addressOffset `0x4c`) and RM0456 §7.9.16.
#[allow(dead_code)]
const FLASH_OPTR_OFF: u32 = 0x40;
#[allow(dead_code)]
const FLASH_SECBOOTADD0R_OFF: u32 = 0x4C;

/// STM32U585 legacy bench FSBL base (secure bank-1 page 0).
///
/// The target shipping design keeps this entry, but production extent/WRP and
/// option-byte authority remain open until their reviewed ceremony and silicon
/// receipts close.
#[allow(dead_code)]
pub const FSBL_BASE_ADDR: u32 = pqsigner_geometry::BANK1_BASE;

// The pure RDP/SECBOOTADD0 decode + its host unit tests live in the
// host-compiled `sphincs_tz_shared::lockdown` (this whole `hw` module is
// `#[cfg(not(test))]`, so an in-module test never runs). Re-export the level
// enum so `hw::flash::RdpLevel` keeps working for callers.
pub use sphincs_tz_shared::lockdown::RdpLevel;

/// Read the live RDP level from `FLASH_OPTR` (secure alias, read-only).
///
/// NOTE (BOOT_LOCK/HDP1 follow-up): we check the RDP level and the boot
/// *address* (`secboot_selects_fsbl`) — the reliable, code-confirmed signals.
/// `BOOT_LOCK` is bit 0 (RM0456 §7.9.16, pinned as
/// `lockdown::SECBOOTADD0_BOOT_LOCK`); the apparent `0x0C00_007C` vs
/// `0x0018_0000` contradiction was register-word vs CubeProgrammer field-value,
/// not a disagreement about the bit (#214). `HDP1` polarity IS still
/// doc-ambiguous, so asserting that remains a bench-confirmation follow-up.
#[cfg(feature = "stm32u585")]
#[allow(dead_code)]
#[must_use]
pub fn rdp_level() -> RdpLevel {
    // SAFETY: `FLASH_OPTR` is a real, 4-byte-aligned MMIO register in the
    // secure FLASH-controller block (unlike NSCR, OPTR is readable via the
    // secure alias). The secure world is single-threaded; this is a pure read.
    let optr = unsafe { crate::hw::mmio::RoReg32::new(FLASH + FLASH_OPTR_OFF) }.read();
    sphincs_tz_shared::lockdown::rdp_level_from_byte((optr & 0xFF) as u8)
}

/// Read the live `SECBOOTADD0R` (secure alias, read-only).
#[cfg(feature = "stm32u585")]
#[allow(dead_code)]
#[must_use]
pub fn secboot_add0_reg() -> u32 {
    // SAFETY: a real, 4-byte-aligned secure option register (same class as
    // `FLASH_OPTR`); single-threaded secure world; pure read.
    unsafe { crate::hw::mmio::RoReg32::new(FLASH + FLASH_SECBOOTADD0R_OFF) }.read()
}

/// Selects which bank the flash controller targets. Only meaningful for
/// dual-bank operations; bank 1 is S-flash, bank 2 is NS-flash in our
/// layout. NSCR.BKER bit.
const BKER: u32 = 1 << 11;

// Unlock key sequence (same as all STM32 families)
const KEY1: u32 = 0x4567_0123;
const KEY2: u32 = 0xCDEF_89AB;

// SECCR bit positions
const PG: u32 = 1 << 0; // Programming
const PER: u32 = 1 << 1; // Page Erase
const PNB_SHIFT: u32 = 3; // Page Number starts at bit 3
const STRT: u32 = 1 << 16; // Start
const LOCK: u32 = 1 << 31; // Lock

// SECSR bit positions
const BSY: u32 = 1 << 16; // Busy
const ERR_MASK: u32 = 0xFA; // PROGERR | WRPERR | PGAERR | SIZERR | PGSERR

// ---------------------------------------------------------------------------
// Instruction cache (ICACHE) — must be invalidated after every flash
// erase or program, or subsequent reads return stale cached bytes.
// ---------------------------------------------------------------------------
//
// STM32U5 has a transparent instruction/data cache in front of flash
// (ICACHE at 0x4003_0400 NS / 0x5003_0400 S, enabled at boot by
// default). Cache lines are NOT automatically invalidated when the
// flash contents underneath change — software must issue a `CACHEINV`
// after every flash mutation that touches a region the CPU may have
// cached.
//
// Symptom when missing: `write_quadword_verified` writes fresh bytes,
// the flash controller reports Ok (no SR error), but the immediately-
// following readback returns the OLD pre-write bytes — because the
// CPU is reading from the cache. `write_quadword_verified` then fails
// the compare and returns Err, with the actual flash having the correct
// content. The bug is trivially reproducible when a region is read
// before the flash mutation (so it's cached), then erased/programmed,
// then read again.
//
// Fix: after every successful erase or program (before returning Ok),
// call `icache_invalidate()`. The call is a handful of cycles and
// completely eliminates the "silent readback mismatch" failure mode.

// ICACHE registers live at 0x4003_0400 (NS alias) / 0x5003_0400 (S alias).
// We're secure-world code; use the S alias for symmetry with the FLASH
// register block above. The wrong base (0x4003_0000 — off by 0x400) lands
// in a reserved region on AHB1 and provokes unpredictable behaviour
// (previously: u64_div_rem HardFault shortly after the first write).
const ICACHE_BASE: u32 = 0x5003_0400;
const ICACHE_CR_CACHEINV: u32 = 1 << 1;
const ICACHE_SR_BUSYF: u32 = 1 << 0;

/// All MMIO registers this driver owns, bundled so the one-time
/// `unsafe { ... }` for `Reg32::new` happens once at module scope.
struct FlashRegs {
    seckeyr: Reg32,
    secsr: Reg32,
    seccr: Reg32,
    nskeyr: Reg32,
    nssr: Reg32,
    nscr: Reg32,
    icache_cr: Reg32,
    icache_sr: RoReg32,
}

// SAFETY: each address below is a real, 4-byte-aligned MMIO register
// exclusively owned by this driver (the FLASH and ICACHE controllers).
// The secure world is single-threaded and non-preemptive — nothing else
// races us. After this one-time construction every register touch is via
// safe `.read()` / `.write()` / `.modify()`.
const REG: FlashRegs = unsafe {
    FlashRegs {
        seckeyr: Reg32::new(FLASH + 0x0C),
        secsr: Reg32::new(FLASH + 0x24),
        seccr: Reg32::new(FLASH + 0x2C),
        // NS-controller registers via the NS alias — see the comment on
        // FLASH_NS above. The secure alias for NSCR fails with PGSERR.
        nskeyr: Reg32::new(FLASH_NS + 0x08),
        nssr: Reg32::new(FLASH_NS + 0x20),
        nscr: Reg32::new(FLASH_NS + 0x28),
        icache_cr: Reg32::new(ICACHE_BASE),
        icache_sr: RoReg32::new(ICACHE_BASE + 0x04),
    }
};

/// Invalidate the entire ICACHE so subsequent flash reads see fresh
/// post-erase / post-program bytes rather than stale cached lines.
/// Must be called inside the same interrupt-free block as the flash
/// mutation that triggered it — interleaving isn't a correctness bug
/// (invalidation is idempotent) but keeps the cache-coherency window
/// tight.
fn icache_invalidate() {
    REG.icache_cr.set_bits(ICACHE_CR_CACHEINV);
    while REG.icache_sr.read() & ICACHE_SR_BUSYF != 0 {
        cortex_m::asm::nop();
    }
    cortex_m::asm::dsb();
    cortex_m::asm::isb();
}

// ---------------------------------------------------------------------------
// First-boot provisioning journal — last 8 KB of secure flash bank 1 (page 127)
// ---------------------------------------------------------------------------

/// Base address of the reserved first-boot journal page (page 127).
pub const KEY_PAGE_ADDR: u32 = flash_policy::FIRST_BOOT_JOURNAL_ADDR;

// NOTE: flash page 126 (the former OPTIGA PBS seal page at
// 0x0C0F_C000) was freed by work-todo #24 — the Platform Binding
// Secret is now resolved via `hw::secret_keys::current_pbs`; after first-boot
// completion that derivation also depends on the salt in page 127. Page 126
// is exclusively owned by the wrapped SE050 BHK store when `bhk` is enabled. Firmware
// update verification intentionally has no persistent failure counter:
// malformed companion input must never erase, reset, or write wallet state.

// ---------------------------------------------------------------------------
// Low-level helpers
// ---------------------------------------------------------------------------

/// Wait until the secure flash controller is not busy.
fn wait_bsy() {
    while REG.secsr.read() & BSY != 0 {
        cortex_m::asm::nop();
    }
}

/// Clear any pending error flags in SECSR (write-1-to-clear).
fn clear_errors() {
    let sr = REG.secsr.read();
    if sr & ERR_MASK != 0 {
        REG.secsr.write(sr & ERR_MASK);
    }
}

/// Unlock the secure flash controller for programming/erase.
fn unlock() {
    // If already unlocked, the key writes are ignored.
    REG.seckeyr.write(KEY1);
    REG.seckeyr.write(KEY2);
}

/// Lock the secure flash controller.
fn lock() {
    REG.seccr.set_bits(LOCK);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// The raw bank-1 program primitive is private to this child module.  Its only
// outward capabilities are (a) a generic writer that requires the pure
// policy's validated, journal-disjoint address type and (b) an index-bounded
// journal writer.  A same-file helper cannot alias the raw primitive because
// Rust privacy prevents the parent module from naming child-private items.
mod bank1_programming {
    use super::{
        clear_errors, icache_invalidate, lock, read_volatile, unlock, wait_bsy, write_volatile,
        GenericSecureQwAddr, ERR_MASK, PG, REG,
    };

    /// Program one raw bank-1 quad-word. The destination contract is supplied
    /// exclusively by one of the two capability-bearing wrappers below.
    unsafe fn write_raw(addr: u32, data: &[u8; 16]) -> Result<(), ()> {
        cortex_m::interrupt::free(|_| {
            wait_bsy();
            clear_errors();
            unlock();

            REG.seccr.write(PG);
            let dst = addr as *mut u32;
            for i in 0..4 {
                let word = u32::from_le_bytes([
                    data[i * 4],
                    data[i * 4 + 1],
                    data[i * 4 + 2],
                    data[i * 4 + 3],
                ]);
                // SAFETY: the caller supplied either a validated generic
                // address or an index-bounded journal address. Volatile writes
                // preserve the controller's required four-word sequence.
                unsafe { write_volatile(dst.add(i), word) };
            }

            wait_bsy();
            REG.seccr.write(0);
            let sr = REG.secsr.read();
            lock();
            cortex_m::asm::dsb();
            cortex_m::asm::isb();
            icache_invalidate();

            if sr & ERR_MASK != 0 {
                clear_errors();
                Err(())
            } else {
                Ok(())
            }
        })
    }

    /// Program and read back a raw address already authorized by this module.
    unsafe fn write_verified_raw(addr: u32, data: &[u8; 16]) -> Result<(), ()> {
        // SAFETY: forwarded contract from the capability-bearing caller.
        unsafe { write_raw(addr, data)? };

        let src = addr as *const u8;
        for (i, expected) in data.iter().enumerate() {
            // SAFETY: the capability proves `addr..addr+16` is a valid flash
            // quad-word. This is a read-only verification pass.
            if unsafe { read_volatile(src.add(i)) } != *expected {
                return Err(());
            }
        }
        Ok(())
    }

    pub(super) unsafe fn write_generic_verified(
        addr: GenericSecureQwAddr,
        data: &[u8; 16],
    ) -> Result<(), ()> {
        // SAFETY: `GenericSecureQwAddr` proves the full raw-writer contract
        // except erased state, which remains the caller's responsibility.
        unsafe { write_verified_raw(addr.get(), data) }
    }

    #[cfg(feature = "rdp2-self-lock")]
    pub(super) unsafe fn write_journal_verified(
        qw_index: usize,
        data: &[u8; 16],
    ) -> Result<(), ()> {
        if qw_index >= 512 {
            return Err(());
        }
        let addr = super::KEY_PAGE_ADDR + (qw_index as u32) * 16;
        // SAFETY: the checked index confines the address to page 127 and the
        // caller guarantees append-at-erased-frontier semantics.
        unsafe { write_verified_raw(addr, data) }
    }
}

/// Program one quad-word **and read it back to confirm the bytes landed**.
///
/// Detects class-A torn writes (brown-out mid-program leaving some bits
/// committed and others not). The first-boot journal page is deliberately
/// rejected: its only writer is [`write_journal_qw`], which holds the private
/// raw capability above. This makes a renamed or cross-module generic caller
/// unable to overwrite the persisted final-PBS salt.
///
/// # Safety
/// The destination must be erased. The address is validated here as an
/// aligned quad-word wholly inside bank-1 pages 0..=126; page 127 is never a
/// valid target.
pub unsafe fn write_quadword_verified(addr: u32, data: &[u8; 16]) -> Result<(), ()> {
    let addr = GenericSecureQwAddr::new(addr).ok_or(())?;
    // SAFETY: the validated capability excludes page 127, misalignment,
    // out-of-bank ranges, and checked-add overflow. The caller still owns the
    // erased-destination precondition.
    unsafe { bank1_programming::write_generic_verified(addr, data) }
}

// ===========================================================================
// work-todo #36 — first-boot RDP-2 self-lock + page-127 provisioning journal.
//
// Compiled ONLY for the shipping self-lock feature (`rdp2-self-lock`); every
// current dev / QEMU / bench build omits this block entirely, so their flash
// behaviour is byte-identical to before. The one genuinely new *mutating*
// routine is `program_rdp_level2_and_launch` — the irreversible RDP burn —
// which is why it lives behind the same feature the `nsc/mod.rs` ship fence
// forces on only for `mode-production`.
//
// Register offsets and the OPTSTRT/OBL_LAUNCH/OPTLOCK bit positions come from
// the vendor SVD (`STM32CubeProgrammer/SVD/STM32U585.svd`) and RM0456; they are
// mirrored as host-tested constants in `sphincs_tz_shared::lockdown`
// (`FLASH_NSCR_OFF`, `FLASH_OPTSTRT`, …). The former `tools/ob-configurator`
// is NOT the authority for them — it swapped the SECSR/SECCR offsets and has
// been deleted (#37). `secsr=0x24 / seccr=0x2C` as bound in `REG` above is
// SVD-correct. WRP1AR / SECWM offsets + the OEM-lock status register are
// BENCH-CONFIRM (RM0456) items — see the #36 deferred runbook.
//
// ┌─────────────────────────────────────────────────────────────────────────┐
// │ KNOWN DEFECT #268 — the three option-byte accesses below use `seccr`.   │
// │ Per the SVD, `OPTSTRT` (17), `OBL_LAUNCH` (27) and `OPTLOCK` (30) exist │
// │ ONLY in `FLASH_NSCR` (0x28); `FLASH_SECCR` (0x2C) implements none of    │
// │ them. So the commit is inert, the OPTLOCK check can never fire, and     │
// │ `program_rdp_level2_and_launch` returns Ok(()) after failing to burn.   │
// │ NOT fixed here by deliberate decision: this is the irreversible RDP-2   │
// │ path and wants an owner decision plus a sacrificial-silicon plan, not a │
// │ drive-by edit. `REG.nscr` is already bound and correct for the fix.     │
// │ Never executed — `rdp2-self-lock` is production-quarantined.            │
// │ Guarded by `negative_optbyte_commit_defect_268_is_marked_or_fixed`.     │
// └─────────────────────────────────────────────────────────────────────────┘
// ===========================================================================

/// Option-byte key register offset (RM0456; `FLASH_S+0x10`).
#[cfg(feature = "rdp2-self-lock")]
const OPTKEYR_OFF: u32 = 0x10;
/// Option-byte unlock keys (RM0456 §7.9.2 `FLASH_OPTKEYR`).
#[cfg(feature = "rdp2-self-lock")]
const OPT_KEY1: u32 = 0x0819_2A3B;
#[cfg(feature = "rdp2-self-lock")]
const OPT_KEY2: u32 = 0x4C5D_6E7F;
/// `SECCR.OPTSTRT` (bit 17) — commit staged option bytes to flash.
#[cfg(feature = "rdp2-self-lock")]
const OPTSTRT: u32 = 1 << 17;
/// `SECCR.OBL_LAUNCH` (bit 27) — reload option bytes (triggers a reset).
#[cfg(feature = "rdp2-self-lock")]
const OBL_LAUNCH: u32 = 1 << 27;
/// `SECCR.OPTLOCK` (bit 30) — cleared by the `OPTKEYR` key sequence.
#[cfg(feature = "rdp2-self-lock")]
const OPTLOCK: u32 = 1 << 30;
/// `FLASH_OPTR.RDP` byte value for Level 2 (permanent debug lockdown).
#[cfg(feature = "rdp2-self-lock")]
const RDP_LEVEL2: u32 = 0xCC;
/// BENCH-CONFIRM (RM0456) register offsets for the ship-profile verifier.
#[cfg(feature = "rdp2-self-lock")]
const SECWM1R1_OFF: u32 = 0x50;
#[cfg(feature = "rdp2-self-lock")]
const WRP1AR_OFF: u32 = 0x58;
/// RM0456 §7.9.23 — bank-2 WRP area A. Bank-1 twin is `WRP1AR_OFF` (§7.9.19).
const WRP2AR_OFF: u32 = 0x68;
#[cfg(feature = "rdp2-self-lock")]
const SECWM2R1_OFF: u32 = 0x60;

/// Raw `FLASH_OPTR` (TZEN / BOR_LEV / RDP fields for the ship-profile check).
#[cfg(feature = "rdp2-self-lock")]
#[must_use]
pub fn optr_raw() -> u32 {
    // SAFETY: real, 4-byte-aligned secure option register; pure read.
    unsafe { RoReg32::new(FLASH + FLASH_OPTR_OFF) }.read()
}

/// Raw `SECWM1R1` (bank-1 secure watermark).
#[cfg(feature = "rdp2-self-lock")]
#[must_use]
pub fn secwm1r1_raw() -> u32 {
    // SAFETY: as `optr_raw`.
    unsafe { RoReg32::new(FLASH + SECWM1R1_OFF) }.read()
}

/// Raw `SECWM2R1` (bank-2 secure watermark).
#[cfg(feature = "rdp2-self-lock")]
#[must_use]
pub fn secwm2r1_raw() -> u32 {
    // SAFETY: as `optr_raw`.
    unsafe { RoReg32::new(FLASH + SECWM2R1_OFF) }.read()
}

/// Raw `WRP1AR` (FSBL write-protect span). BENCH-CONFIRM offset.
#[cfg(feature = "rdp2-self-lock")]
#[must_use]
pub fn wrp1ar_raw() -> u32 {
    // SAFETY: as `optr_raw`.
    unsafe { RoReg32::new(FLASH + WRP1AR_OFF) }.read()
}

/// Raw `WRP2AR` (bank-2 FSBL-mirror write-protect span). **Address offset
/// `0x68`**, RM0456 §7.9.23 "FLASH WPR2 area A address register" — the bank-2
/// twin of `WRP1AR` at `0x58` (§7.9.19).
///
/// Added 2026-09-24: `verify_ship_profile` checked only bank 1, so the FSBL
/// copy the frozen geometry puts in bank 2 was never verified write-protected
/// before RDP-2 froze the option bytes for good.
#[cfg(feature = "rdp2-self-lock")]
#[must_use]
pub fn wrp2ar_raw() -> u32 {
    // SAFETY: as `optr_raw`.
    unsafe { RoReg32::new(FLASH + WRP2AR_OFF) }.read()
}

/// Raw OEM-lock status. BENCH-CONFIRM register (FLASH_NSSR vs FLASH_OPTSR) —
/// the bit *masks* live in `sphincs_tz_shared::lockdown` (`OEM1LOCK`/`OEM2LOCK`).
#[cfg(feature = "rdp2-self-lock")]
#[must_use]
pub fn oem_lock_status_raw() -> u32 {
    // SAFETY: real, 4-byte-aligned FLASH status register; pure read.
    unsafe { RoReg32::new(FLASH_NS + 0x20) }.read()
}

/// Is a bank-1 secure page fully erased (all `0xFF`)? Phase A blank-checks the
/// per-device pages 123..=127 before the RDP burn: a pre-planted page-127
/// journal salt would otherwise yield a predictable final PBS (#36 hardening).
#[cfg(feature = "rdp2-self-lock")]
#[must_use]
pub fn is_secure_page_blank(page: u32) -> bool {
    assert!(page <= 127, "bank-1 page out of range");
    let base = FSBL_BASE_ADDR + page * 0x2000; // 8 KB pages, secure alias
    let src = base as *const u32;
    for i in 0..(0x2000 / 4) {
        // SAFETY: `base..base+8KB` is a fixed in-flash page; read-only.
        if unsafe { read_volatile(src.add(i)) } != 0xFFFF_FFFF {
            return false;
        }
    }
    true
}

/// Append one 16-byte record to the page-127 provisioning journal at
/// `qw_index` (0..512). Read-back-verified; ICACHE is invalidated by
/// the same raw bank-1 writer used by `write_quadword_verified`.
///
/// # Safety
/// Programs persistent flash in page 127 (KEY_PAGE — owned outright by the
/// first-boot journal). Caller ensures the QW is
/// currently erased (the codec only ever appends at the scanned `next_free`).
#[cfg(feature = "rdp2-self-lock")]
pub unsafe fn write_journal_qw(qw_index: usize, rec: &[u8; 16]) -> Result<(), ()> {
    // SAFETY: the child-module capability checks the index and confines the
    // write to page 127; the caller guarantees append-at-erased-frontier.
    unsafe { bank1_programming::write_journal_verified(qw_index, rec) }
}

/// **Irreversible.** Stage `FLASH_OPTR.RDP = 0xCC` (Level 2), commit the
/// option bytes, and reload them (`OBL_LAUNCH` → system reset).
///
/// On success this **never returns** (the MCU resets). It only *returns* on a
/// pre-launch error — as `Err(())` — so Phase A can show a numbered fault and
/// halt UNLOCKED without having locked a bad unit. A power loss between the
/// `OPTSTRT` commit and `OBL_LAUNCH` is safe: the option bytes are already in
/// flash, so the next natural reset boots at RDP-2 (#36 (b) — the one
/// unavoidable residual window; keep it short, BOR on).
///
/// # Safety
/// Permanently sets RDP Level 2. Caller MUST have verified the ship option-
/// byte profile + blank per-device pages first (Phase A) — RDP-2 is
/// unrecoverable.
#[cfg(feature = "rdp2-self-lock")]
pub unsafe fn program_rdp_level2_and_launch() -> Result<(), ()> {
    let commit = cortex_m::interrupt::free(|_| -> Result<(), ()> {
        // SAFETY: option-byte registers in the secure FLASH block; single-
        // threaded secure world; each `unsafe` funnels through `Reg32` once.
        let optkeyr = unsafe { Reg32::new(FLASH + OPTKEYR_OFF) };
        let optr = unsafe { Reg32::new(FLASH + FLASH_OPTR_OFF) };

        wait_bsy();
        clear_errors();
        unlock();
        if REG.seccr.read() & LOCK != 0 {
            return Err(()); // flash controller still locked (not in secure mode?)
        }

        // Unlock the option-byte area.
        optkeyr.write(OPT_KEY1);
        optkeyr.write(OPT_KEY2);
        cortex_m::asm::dsb();
        if REG.seccr.read() & OPTLOCK != 0 {
            return Err(()); // option bytes still locked
        }

        // Stage RDP=0xCC, preserving TZEN / BOR / WRP / SECWM / … .
        let staged = (optr.read() & !0xFF) | RDP_LEVEL2;
        optr.write(staged);

        // Commit the staged option bytes to flash.
        REG.seccr.write(OPTSTRT);
        wait_bsy();
        let sr = REG.secsr.read();
        // NOTE (BENCH-CONFIRM): `ERR_MASK` catches the general program/erase
        // errors; option-write errors (`OPTWERR`) live in a separate bit that
        // is a runbook pin. A missed OPTWERR is non-fatal — the burn simply
        // didn't take, so the next boot re-attempts idempotently.
        if sr & ERR_MASK != 0 {
            clear_errors();
            return Err(());
        }
        Ok(())
    });

    commit?;

    // Success: reload option bytes → system reset. Diverges.
    // SAFETY: option bytes are staged + committed; OBL_LAUNCH resets the MCU.
    unsafe { obl_launch() }
}

/// Trigger `OBL_LAUNCH` (option-byte reload → system reset). Never returns.
#[cfg(feature = "rdp2-self-lock")]
unsafe fn obl_launch() -> ! {
    cortex_m::interrupt::free(|_| {
        REG.seccr.write(OBL_LAUNCH);
    });
    // OBL_LAUNCH triggers a system reset; if for any reason it doesn't, park
    // rather than continue into an inconsistent boot.
    loop {
        cortex_m::asm::wfe();
    }
}

// ---------------------------------------------------------------------------
// SE050 admin-wipe state — page 125
// ---------------------------------------------------------------------------
//
// Holds the per-device admin PIN (16 bytes from STM32 TRNG, used to
// authenticate against ADMIN_WIPE_OBJ on SE050 during PIN-lockout wipe)
// and a crash-safety flag for interrupted wipes. Independent of OPTIGA
// PBS so SE050-standalone builds work without additional dependencies.
//
// Layout of page 125 (0x0C0F_A000, 8 KB):
//   QW 0 (offset  0..15): admin PIN (16 bytes)
//   QW 1 (offset 16..31): wipe flag — byte 0: 0x00 armed / 0xFF blank
//                                     bytes 1..15: padding (0xFF)
//   bytes 32..8192:       unused, 0xFF after erase
//
// Lifecycle:
//   - First boot: page erased (all 0xFF) → generate random admin PIN
//                 via rng::fill(), write QW 0. Wipe flag stays blank.
//   - Wipe start: program QW 1 to [0x00, 0xFF × 15]. This is a 1→0
//                 bit-clear on a blank QW, which NOR flash allows
//                 without page erase — the admin PIN at QW 0 is preserved
//                 so the wipe routine can still authenticate.
//   - Wipe finish: erase_admin_page(). Clears PIN + flag both back to
//                  0xFF, leaving the SE050 side of the device
//                  "unprovisioned" from this page's perspective.

/// Base address of the SE050 admin-state page (page 125).
pub const ADMIN_PAGE_ADDR: u32 =
    pqsigner_geometry::page_addr(pqsigner_geometry::Bank::One, ADMIN_PAGE_NUM as u8);
const ADMIN_PAGE_NUM: u32 = 125;

// Page-125 layout: QW0 (offset 0) is unused on v6 chips (the former
// admin-PIN slot; dead since the OTP-derived scheme); QW1 (offset 16)
// holds the wipe-in-progress flag.
const WIPE_FLAG_OFFSET: u32 = 16;
const WIPE_FLAG_ARMED: u8 = 0x00;

/// Erase page 125. Clears both the admin PIN and the wipe flag.
///
/// # Safety
/// Erases persistent flash at `ADMIN_PAGE_ADDR`.
pub unsafe fn erase_admin_page() -> Result<(), ()> {
    cortex_m::interrupt::free(|_| {
        wait_bsy();
        clear_errors();
        unlock();

        let cr = PER | (ADMIN_PAGE_NUM << PNB_SHIFT);
        REG.seccr.write(cr);
        REG.seccr.write(cr | STRT);

        wait_bsy();

        REG.seccr.write(0);
        let sr = REG.secsr.read();
        lock();
        cortex_m::asm::dsb();
        cortex_m::asm::isb();
        icache_invalidate();

        if sr & ERR_MASK != 0 {
            clear_errors();
            Err(())
        } else {
            Ok(())
        }
    })
}

// NOTE: `write_admin_pin` / `read_admin_pin` / `is_admin_pin_blank`
// and `ADMIN_PIN_OFFSET` were all removed (2026-05-11). The SE050
// admin PIN is never persisted to flash — it's re-derived on demand
// via `hw::secret_keys::se050_admin_pin()` (BHK in the production
// target, DHUK fallback, OTP only in explicit dev/legacy builds; see
// `Se050::store_objects` /
// `Se050::factory_reset_admin`). The e2e pre-clean cascades that used
// to read a pre-v6 flash PIN now call `Se050::factory_reset_admin()`
// (the v6 path) directly. Page 125 still holds the wipe-in-progress
// flag at `WIPE_FLAG_OFFSET`, which is unrelated.

/// Arm the wipe-in-progress marker. Call immediately before initiating
/// a factory reset so boot-time resume can pick up an interrupted wipe.
///
/// Does NOT erase page 125 — uses a 1→0 bit-clear on a single QW, which
/// NOR flash supports without pre-erase. The admin PIN at QW 0 is
/// preserved so the wipe routine can still authenticate against
/// ADMIN_WIPE_OBJ during resume.
///
/// # Safety
/// Programs a flash quad-word at `ADMIN_PAGE_ADDR + WIPE_FLAG_OFFSET`.
pub unsafe fn arm_wipe_flag() -> Result<(), ()> {
    let mut qw = [0xFFu8; 16];
    qw[0] = WIPE_FLAG_ARMED;
    // SAFETY: forwarded contract; target QW is the dedicated wipe-flag slot.
    unsafe { write_quadword_verified(ADMIN_PAGE_ADDR + WIPE_FLAG_OFFSET, &qw) }
}

/// Read the wipe-in-progress flag. Returns true iff armed.
pub fn is_wipe_armed() -> bool {
    let src = (ADMIN_PAGE_ADDR + WIPE_FLAG_OFFSET) as *const u8;
    // SAFETY: fixed in-flash address inside page 125; memory-mapped read.
    unsafe { read_volatile(src) == WIPE_FLAG_ARMED }
}

// §32 P5 — duress action mode (page 125, QW2 @ offset 32).
//   blank (0xFF) = DECOY  (default — `is_duress_wipe_mode()` is false)
//   programmed (0x00) = WIPE on a duress-PIN unlock
// Blank-as-decoy is the safe default: a power loss after `erase_admin_page`
// but before the wizard sets the mode falls back to decoy (loses no funds),
// matching the wipe-flag convention. Same QW lifecycle — `erase_admin_page`
// (wipe finish) clears it back to decoy, and the next wizard re-collects.
//
// F26/LIFE-1 (cut point B): the READ is fail-closed — anything OTHER than
// the pristine-blank byte (0xFF) means wipe. Only a deliberately-blank QW
// (never armed, or cleanly cleared by `erase_admin_page`) selects decoy;
// the armed 0x00 AND every unknown/torn/glitch pattern select the
// destruction path, so an ambiguous read can never silently downgrade the
// user's chosen protection to the decoy.
const DURESS_WIPE_MODE_OFFSET: u32 = 32;
const DURESS_WIPE_MODE_SET: u8 = 0x00;

/// Mark the device as WIPE-on-duress. 1→0 bit-clear on a blank QW (no page
/// erase). MUST be called BEFORE provisioning the wallet: a crash between
/// provisioning and this write would leave a duress PIN configured but
/// mode = decoy (default), which silently downgrades the user's chosen
/// protection — flush the mode first, then provision.
///
/// # Safety
/// Programs a flash quad-word at `ADMIN_PAGE_ADDR + DURESS_WIPE_MODE_OFFSET`.
#[cfg(feature = "duress-pin")]
pub unsafe fn arm_duress_wipe_mode() -> Result<(), ()> {
    let mut qw = [0xFFu8; 16];
    qw[0] = DURESS_WIPE_MODE_SET;
    // SAFETY: forwarded contract; dedicated duress-mode QW slot in page 125.
    unsafe { write_quadword_verified(ADMIN_PAGE_ADDR + DURESS_WIPE_MODE_OFFSET, &qw) }
}

/// Returns true iff the device is configured to WIPE on a duress-PIN
/// unlock (vs the default: open the decoy wallet). Read by
/// `nsc::gated_unlock` in the duress-match branch.
///
/// FAIL-CLOSED (F26/LIFE-1): true unless the byte reads the
/// pristine-blank `0xFF`. The armed value (`DURESS_WIPE_MODE_SET`)
/// and any unknown/torn pattern both read as wipe — only a
/// deliberately-blank QW opens the decoy.
#[cfg(feature = "duress-pin")]
pub fn is_duress_wipe_mode() -> bool {
    let src = (ADMIN_PAGE_ADDR + DURESS_WIPE_MODE_OFFSET) as *const u8;
    // SAFETY: fixed in-flash address inside page 125; memory-mapped read.
    unsafe { read_volatile(src) != 0xFF }
}

// ---------------------------------------------------------------------------
// MCU-side PIN attempt counter — page 124
// ---------------------------------------------------------------------------
//
// Persistent user-facing PIN-attempt counter. Trezor-parity design (see
// `storage/storage.c:1171-1311` in trezor-firmware): page 124 is precharged
// BEFORE every SE verify and reset only after a successful PIN match. It is
// therefore the firmware gate for the ten-attempt policy.
//
// Under `optiga-hw-counter`, OPTIGA E120 is a separate silicon-enforced LUC
// and the directional boot rollback witness. A benign cut can leave page 124
// one attempt ahead, so reconciliation accepts `mcu >= e120`; only
// `e120 > mcu` proves page-124 rollback. F1E1 is frozen as the
// provisioning/reset sentinel in this profile and is not an attempt counter.
// SE050 UserID independently enforces its max-ten retry policy, but its attempt
// attribute is not boot-readable under the production policy. Do not describe
// reconciliation as "the MCU counter always wins" or as a symmetric
// three-counter readback.
//
// Layout of page 124 (0x0C0F_8000, 8 KB):
//   QW 0..(MAX_ATTEMPTS-1): one programmed QW per attempt (any non-
//                           blank pattern marks consumed).
//   Remaining QWs: unused, 0xFF after erase (reserved headroom).
//
// Programmed sentinel: `[0x00; 16]`. Blank sentinel: `[0xFF; 16]`.
//
// Encoding rationale:
//   - STM32U5 flash does NOT allow re-programming an already-
//     programmed word (ECC locks the value). A counter implemented
//     as "rewrite a single byte with the new count" would need a
//     page erase every bump — catastrophic flash wear.
//   - One-QW-per-attempt needs only a fresh blank QW per bump, no
//     rewrite. Page erase only on successful unlock.
//
// Lifecycle:
//   - First boot / successful unlock: page blank (all 0xFF).
//     `pin_attempts_read()` returns 0.
//   - Wrong PIN attempt N: `pin_attempts_bump()` programs QW N-1
//     with `[0x00; 16]`. Post-bump read returns N.
//   - Reach `MAX_ATTEMPTS`: wallet locks out. `trigger_lockout_wipe`
//     wipes SEs + erases page 124 via `pin_attempts_reset()`.
//
// Page choice: 124 over 126. Page 126 (the former OPTIGA PBS seal
// page, now owned by the wrapped BHK store) turned out to be in a "freed-but-
// write-hostile" state on the current bench chip — erase returns
// OK (no SR error) but subsequent programs of QW0 fail with
// PROGERR|PGSERR. Page 124 is truly never-touched and accepts
// writes without drama. If future chips exhibit the same issue
// at page 124, we have page 123 still in reserve.

const PIN_ATTEMPTS_PAGE_ADDR: u32 =
    pqsigner_geometry::page_addr(pqsigner_geometry::Bank::One, PIN_ATTEMPTS_PAGE_NUM as u8);
const PIN_ATTEMPTS_PAGE_NUM: u32 = 124;

/// Maximum counter capacity supported by the current layout. Bigger
/// than `sphincs_tz_shared::MAX_ATTEMPTS` so future relaxation of the
/// PIN policy doesn't need a flash layout change.
const PIN_ATTEMPTS_CAPACITY: u32 = 32;
const PIN_ATTEMPTS_QW_SIZE: u32 = 16;

/// Read the current PIN-attempt count (0..=`PIN_ATTEMPTS_CAPACITY`).
/// Reads the per-QW sentinel bytes and counts how many have been
/// programmed (any non-0xFF byte in QW N). A partially-programmed
/// QW (brown-out mid-write) counts as programmed — conservative:
/// the user gets at most one fewer attempt than the silicon actually
/// recorded, never one more.
///
/// **F-15.r5 hardening (forward + reverse double scan).** Mirrors
/// the F-12 fix to `offchain_count_read`: walk the page forward
/// (early-exit on the first blank QW) and again from the end
/// backward (early-exit on the first programmed QW), and require
/// both passes to agree. A single fault that lands on one
/// direction's early-exit cannot symmetrically affect the other —
/// the two scans have asymmetric control flow by construction. On
/// mismatch we fail-closed by returning `PIN_ATTEMPTS_CAPACITY`,
/// which is strictly greater than `MAX_ATTEMPTS = 10`, so every
/// downstream gate (`gated_unlock`'s `pre_count < MAX_ATTEMPTS`,
/// `verify_pin_with_chip`'s `remaining_after != 0`, and
/// `pin_attempts_bump`'s `pre >= PIN_ATTEMPTS_CAPACITY`) treats this
/// as "lockout reached."
pub unsafe fn pin_attempts_read() -> u8 {
    let fwd = unsafe { pin_attempts_scan_forward() };
    crate::fi::wait_random();
    let rev = unsafe { pin_attempts_scan_reverse() };
    if fwd != rev {
        // Fail-closed sentinel. `PIN_ATTEMPTS_CAPACITY` = 32 >
        // `MAX_ATTEMPTS` = 10, so every gate treats this as locked.
        return PIN_ATTEMPTS_CAPACITY as u8;
    }
    fwd
}

#[inline(never)]
unsafe fn pin_attempts_scan_forward() -> u8 {
    let base = PIN_ATTEMPTS_PAGE_ADDR as *const u8;
    let mut count: u8 = 0;
    for qw_idx in 0..PIN_ATTEMPTS_CAPACITY {
        // SAFETY: `qw_idx * 16 < 512` stays inside the 8 KB page.
        let qw_base = unsafe { base.add((qw_idx * PIN_ATTEMPTS_QW_SIZE) as usize) };
        // Any non-0xFF byte inside this QW marks it "programmed".
        let mut programmed = false;
        for byte_idx in 0..PIN_ATTEMPTS_QW_SIZE {
            // SAFETY: `byte_idx < 16` keeps the offset inside the QW.
            if unsafe { read_volatile(qw_base.add(byte_idx as usize)) } != 0xFF {
                programmed = true;
                break;
            }
        }
        if programmed {
            count = count.saturating_add(1);
        } else {
            // Once we hit a blank QW, all subsequent QWs are also
            // blank (we program them in order). Early-exit.
            break;
        }
    }
    count
}

#[inline(never)]
unsafe fn pin_attempts_scan_reverse() -> u8 {
    // Asymmetric control flow vs `pin_attempts_scan_forward`: walk
    // from CAPACITY-1 backward, early-return on the first programmed
    // QW. Under the invariant "QWs are programmed in order from 0,
    // contiguously," the first-programmed-from-end QW is at index
    // `count - 1`, so we return `i + 1`. A fault that early-exits
    // the forward scan (e.g. flipping the `programmed` flag false
    // mid-scan) cannot identically affect the reverse pass, which
    // starts from the opposite boundary and walks in the opposite
    // direction with a different loop shape.
    let base = PIN_ATTEMPTS_PAGE_ADDR as *const u8;
    let mut i = PIN_ATTEMPTS_CAPACITY;
    while i > 0 {
        i -= 1;
        let qw_base = base.add((i as usize) * (PIN_ATTEMPTS_QW_SIZE as usize));
        let mut programmed = false;
        for byte_idx in 0..PIN_ATTEMPTS_QW_SIZE {
            if read_volatile(qw_base.add(byte_idx as usize)) != 0xFF {
                programmed = true;
                break;
            }
        }
        if programmed {
            // u8 holds 0..=PIN_ATTEMPTS_CAPACITY (32) — well below
            // the u8 ceiling, so saturating_add is defensive only.
            return (i as u8).saturating_add(1);
        }
    }
    0
}

/// Bump the attempt counter by one. Programs the next blank QW
/// (at index == pre-bump count) with `[0x00; 16]` and verifies
/// the post-bump count is exactly one higher. Returns the new count.
///
/// Fault-injection note: a glitch that skips the program entirely
/// would leave the count unchanged. The post-bump read-back rejects
/// that with `Err(())` — caller must halt / refuse the attempt on
/// failure. A glitch that writes a DIFFERENT QW would leave gaps
/// (blank QWs between programmed ones); `pin_attempts_read` counts
/// strictly in-order and stops at the first blank, so such a write
/// is detected as "count unchanged" and similarly rejected.
///
/// # Safety
/// Same contract as [`pin_attempts_read`].
///
/// `#[inline(never)]` (MEDIUM-2, audit pin-unlock 20260625): the caller
/// (`nsc::gated_unlock`) FAIL-INs on a missing bump, which only works if the
/// bump is a real `bl` at the call site — an inlined body would let a glitch
/// skip the program without leaving a skippable branch for the sentinel to
/// catch.
#[inline(never)]
pub unsafe fn pin_attempts_bump() -> Result<u8, ()> {
    let pre = pin_attempts_read();
    if (pre as u32) >= PIN_ATTEMPTS_CAPACITY {
        return Err(());
    }

    let target_addr =
        PIN_ATTEMPTS_PAGE_ADDR + (pre as u32) * PIN_ATTEMPTS_QW_SIZE;
    let sentinel = [0u8; 16];
    // SAFETY: target QW is inside page 124 and was confirmed blank above.
    unsafe { write_quadword_verified(target_addr, &sentinel)? };

    // FI hardening: volatile-delay between write and readback so a
    // clock-aligned glitch that skipped the write cannot also suppress
    // the readback of the old value on the same cycle.
    crate::fi::wait_random();

    let post = pin_attempts_read();
    if post != pre + 1 {
        return Err(());
    }
    // Re-read under a sentinel-gated check — a glitch that skips the
    // `if post != pre + 1` bypass has to also defeat `fi::check_true`.
    if crate::fi::check_true_into_sentinel(|| pin_attempts_read() == pre + 1)
        != crate::fi::OK_SENTINEL
    {
        return Err(());
    }
    Ok(post)
}

/// Erase page 124 — clears every attempt marker back to blank.
/// Called only after a successful PIN verify completes end-to-end
/// on both SEs. After this, `pin_attempts_read()` returns 0.
///
/// # Safety
/// Erases the PIN-attempt counter page. Must only be called after a
/// successful PIN verify on both SEs; an out-of-order call would
/// silently reset the lockout state.
pub unsafe fn pin_attempts_reset() -> Result<(), ()> {
    cortex_m::interrupt::free(|_| {
        wait_bsy();
        clear_errors();
        unlock();

        let cr = PER | (PIN_ATTEMPTS_PAGE_NUM << PNB_SHIFT);
        REG.seccr.write(cr);
        REG.seccr.write(cr | STRT);

        wait_bsy();

        REG.seccr.write(0);
        let sr = REG.secsr.read();
        lock();
        cortex_m::asm::dsb();
        cortex_m::asm::isb();
        icache_invalidate();

        if sr & ERR_MASK != 0 {
            clear_errors();
            Err(())
        } else {
            Ok(())
        }
    })
}

// ===========================================================================
// Firmware-update plumbing: bank-2 (non-secure) flash + slot geometry
// ===========================================================================
//
// The firmware-update subsystem writes new firmware images into the
// inactive A/B slot. The secure world owns the entire update flow — NS
// code never programs flash directly — so we provide bank-2 primitives
// on the secure side, accessed through the FLASH_NS{KEYR,SR,CR} register
// aliases. These registers are on the secure peripheral bus and are
// reachable from secure-world code; the "NS" prefix refers to which
// side's watermarks the controller honours (NSCR programs pages that
// SECCR refuses because of the SECWMn watermark).
//
// Slot layout (see docs/firmware/firmware-update.md for the full picture):
//
//   Bank 1 (secure):
//     FSBL             pages   0..3    0x0C00_0000  (legacy 32 KB bench layout)
//     Manifest A       page    4       0x0C00_8000  (8 KB)
//     Manifest B       page    5       0x0C00_A000  (8 KB)
//     Boot state       page    6       0x0C00_C000  (8 KB, redundant)
//     Slot A secure    pages   7..64   0x0C00_E000  (464 KB)
//     Slot B secure    pages  65..122  0x0C08_2000  (464 KB)
//     (reserved)       pages 123..127  legacy state + admin/wipe + wrapped BHK
//
//   Bank 2 (non-secure):
//     Slot A NS        pages   0..63   0x0810_0000  (512 KB)
//     Slot B NS        pages  64..127  0x0818_0000  (512 KB)

/// A/B slot identifier. The current V1 selector is legacy bench code; the
/// Draft 1.1 proposes a replacement typed selector interface, but is not
/// implementation-approved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Slot {
    A,
    B,
}

// --- Manifest page addresses --------------------------------------------------

pub const MANIFEST_A_ADDR: u32 = 0x0C00_8000;
pub const MANIFEST_A_PAGE: u32 = 4;
pub const MANIFEST_B_ADDR: u32 = 0x0C00_A000;
pub const MANIFEST_B_PAGE: u32 = 5;

pub fn manifest_addr(slot: Slot) -> u32 {
    match slot {
        Slot::A => MANIFEST_A_ADDR,
        Slot::B => MANIFEST_B_ADDR,
    }
}

pub fn manifest_page_num(slot: Slot) -> u32 {
    match slot {
        Slot::A => MANIFEST_A_PAGE,
        Slot::B => MANIFEST_B_PAGE,
    }
}

// --- Boot state page ----------------------------------------------------------

pub const BOOT_STATE_ADDR: u32 = 0x0C00_C000;
pub const BOOT_STATE_PAGE: u32 = 6;

// --- Slot image addresses -----------------------------------------------------

pub const SLOT_A_SECURE_ADDR: u32 = 0x0C00_E000;
pub const SLOT_A_SECURE_FIRST_PAGE: u32 = 7;
pub const SLOT_A_SECURE_LAST_PAGE: u32 = 64;

pub const SLOT_B_SECURE_ADDR: u32 = 0x0C08_2000;
pub const SLOT_B_SECURE_FIRST_PAGE: u32 = 65;
pub const SLOT_B_SECURE_LAST_PAGE: u32 = 122;

/// Slot capacities are a shared host/device release-policy constant.
pub use fw_manifest::{SLOT_NS_CAPACITY, SLOT_SECURE_CAPACITY};

pub const SLOT_A_NS_ADDR: u32 = 0x0810_0000;
pub const SLOT_A_NS_FIRST_PAGE: u32 = 0;
pub const SLOT_A_NS_LAST_PAGE: u32 = 63;

pub const SLOT_B_NS_ADDR: u32 = 0x0818_0000;
pub const SLOT_B_NS_FIRST_PAGE: u32 = 64;
pub const SLOT_B_NS_LAST_PAGE: u32 = 127;

pub fn slot_secure_addr(slot: Slot) -> u32 {
    match slot {
        Slot::A => SLOT_A_SECURE_ADDR,
        Slot::B => SLOT_B_SECURE_ADDR,
    }
}

pub fn slot_ns_addr(slot: Slot) -> u32 {
    match slot {
        Slot::A => SLOT_A_NS_ADDR,
        Slot::B => SLOT_B_NS_ADDR,
    }
}

pub fn slot_secure_pages(slot: Slot) -> (u32, u32) {
    match slot {
        Slot::A => (SLOT_A_SECURE_FIRST_PAGE, SLOT_A_SECURE_LAST_PAGE),
        Slot::B => (SLOT_B_SECURE_FIRST_PAGE, SLOT_B_SECURE_LAST_PAGE),
    }
}

pub fn slot_ns_pages(slot: Slot) -> (u32, u32) {
    match slot {
        Slot::A => (SLOT_A_NS_FIRST_PAGE, SLOT_A_NS_LAST_PAGE),
        Slot::B => (SLOT_B_NS_FIRST_PAGE, SLOT_B_NS_LAST_PAGE),
    }
}

// ---------------------------------------------------------------------------
// Bank-2 (NS flash) program + erase primitives
// ---------------------------------------------------------------------------

/// Unlock the NS flash controller. Symmetric to [`unlock`] but uses the
/// NSKEYR register, enabling programming of pages covered by the NS
/// watermark (bank 2 in our layout). A failed unlock latches OPTLOCK;
/// recovery requires a system reset.
fn unlock_ns() {
    REG.nskeyr.write(KEY1);
    REG.nskeyr.write(KEY2);
}

/// Lock the NS flash controller after a program/erase sequence.
fn lock_ns() {
    REG.nscr.set_bits(LOCK);
}

fn wait_bsy_ns() {
    while REG.nssr.read() & BSY != 0 {
        cortex_m::asm::nop();
    }
}

fn clear_errors_ns() {
    let sr = REG.nssr.read();
    if sr & ERR_MASK != 0 {
        REG.nssr.write(sr & ERR_MASK);
    }
}

/// Erase one page of bank 2. `page` is the in-bank index (0..=127);
/// physical address is `0x0810_0000 + page * 8192`.
///
/// Returns `Err(())` on any error flag in NSSR (including WRPERR if
/// the pages are write-protected, which would catch an accidental
/// attempt to erase a slot that the FSBL has marked locked — though
/// WRP in our design only covers the FSBL pages themselves, not the
/// slots).
///
/// # Safety
/// Erases a non-secure-bank page. Caller must ensure the page is part
/// of the inactive A/B slot.
pub unsafe fn erase_ns_page(page: u8) -> Result<(), ()> {
    // SAFETY: forwarded contract. Bank 2 is the only bank with non-secure
    // pages under the current geometry, so this stays the ordinary entry.
    unsafe { erase_ns_page_in(pqsigner_geometry::Bank::Two, page) }
}

/// Erase one non-secure page in an EXPLICIT bank.
///
/// `erase_ns_page` used to set `BKER` unconditionally, i.e. always bank 2 —
/// correct only while "non-secure page" and "bank-2 page" are the same claim.
/// A geometry that puts an NS slot in bank 1 breaks that equivalence, and the
/// failure is worse than the secure-side twin's: erasing the INACTIVE bank-1
/// NS slot would target the bank-2 page of the same number, i.e. the NS slot
/// the device is currently RUNNING FROM, in the middle of an update.
///
/// The bank now comes from a [`GenericNsPage`] proof, so the control-register
/// write and the caller's intent cannot disagree.
///
/// # Safety
/// Erases a non-secure page. Caller must ensure the page is part of the
/// INACTIVE A/B slot.
pub unsafe fn erase_ns_page_in(bank: pqsigner_geometry::Bank, page: u8) -> Result<(), ()> {
    let proof = GenericNsPage::new_in(bank, page as u32).ok_or(())?;
    let page = proof.get();
    let bker = match proof.bank() {
        pqsigner_geometry::Bank::One => 0,
        pqsigner_geometry::Bank::Two => BKER,
    };

    // NSCR is reached via the NS alias of the FLASH register block
    // (see `FLASH_NS` at top of file). The single-shot CR write matches
    // ST HAL's `FLASH_PageErase` MODIFY_REG pattern.
    cortex_m::interrupt::free(|_| {
        wait_bsy_ns();
        clear_errors_ns();
        unlock_ns();

        // BKER comes from the proof (see `erase_ns_page_in`), not from the
        // assumption that every NS page is in bank 2.
        let cr = PER | bker | (page << PNB_SHIFT) | STRT;
        REG.nscr.write(cr);

        wait_bsy_ns();

        REG.nscr.write(0);
        let sr = REG.nssr.read();
        lock_ns();
        cortex_m::asm::dsb();
        cortex_m::asm::isb();
        // Invalidate ICACHE after the bank-2 erase/program, matching the
        // bank-1 helpers (see the file header comment: "after every
        // successful erase or program, call icache_invalidate()"). Without
        // this, a same-power-cycle re-flash whose target lines were cached
        // by a prior read (e.g. COMMIT's verify_images hashing the slot)
        // makes the verified read-back observe STALE bytes and fail the
        // compare — a spurious FlashError that dogs the FW-update retry
        // until a power cycle, even though the flash is correct.
        icache_invalidate();

        if sr & ERR_MASK != 0 {
            clear_errors_ns();
            Err(())
        } else {
            Ok(())
        }
    })
}

/// First byte after flash bank 2 (NS alias `0x0810_0000`, 128 × 8 KiB).
const BANK2_END: u32 = pqsigner_geometry::BANK2_BASE
    + pqsigner_geometry::PAGES_PER_BANK as u32 * pqsigner_geometry::PAGE_SIZE;
/// First byte after flash bank 1 (secure alias `0x0C00_0000`).
const BANK1_END: u32 = pqsigner_geometry::BANK1_BASE
    + pqsigner_geometry::PAGES_PER_BANK as u32 * pqsigner_geometry::PAGE_SIZE;

/// Program one quad-word to bank 2 at `addr`. Unlike
/// `write_quadword`, this routes through NSCR so the NS watermark is
/// honoured. `addr` must be inside bank-2 (`0x0810_0000..0x0820_0000`)
/// and quad-word-aligned, and the 16 bytes at `addr` must already be
/// erased (all 0xFF).
///
/// Same semantics as `write_quadword`: returns `Err(())` only on a
/// flagged error. **Not** read-back verified — for persistence use
/// [`write_ns_quadword_verified`] which adds the brown-out guard.
///
/// # Safety
/// Same shape as [`write_quadword`] but targets bank 2.
unsafe fn write_ns_quadword(addr: u32, data: &[u8; 16]) -> Result<(), ()> {
    debug_assert!(addr >= pqsigner_geometry::BANK2_BASE && addr < BANK2_END);
    debug_assert_eq!(addr & 0xF, 0);

    cortex_m::interrupt::free(|_| {
        wait_bsy_ns();
        clear_errors_ns();
        unlock_ns();

        // Clear any latent op bits, then arm PG.
        REG.nscr.write(0);
        REG.nscr.write(PG);

        let dst = addr as *mut u32;
        for i in 0..4 {
            let word = u32::from_le_bytes([
                data[i * 4],
                data[i * 4 + 1],
                data[i * 4 + 2],
                data[i * 4 + 3],
            ]);
            // SAFETY: caller asserts `addr..addr+16` is a valid, erased,
            // quad-word-aligned bank-2 flash region. Volatile guarantees the
            // four word writes happen in order, as the flash controller
            // expects.
            unsafe { write_volatile(dst.add(i), word) };
        }

        wait_bsy_ns();

        REG.nscr.write(0);
        let sr = REG.nssr.read();
        lock_ns();
        cortex_m::asm::dsb();
        cortex_m::asm::isb();
        // Invalidate ICACHE after the bank-2 erase/program, matching the
        // bank-1 helpers (see the file header comment: "after every
        // successful erase or program, call icache_invalidate()"). Without
        // this, a same-power-cycle re-flash whose target lines were cached
        // by a prior read (e.g. COMMIT's verify_images hashing the slot)
        // makes the verified read-back observe STALE bytes and fail the
        // compare — a spurious FlashError that dogs the FW-update retry
        // until a power cycle, even though the flash is correct.
        icache_invalidate();

        if sr & ERR_MASK != 0 {
            clear_errors_ns();
            Err(())
        } else {
            Ok(())
        }
    })
}

/// Program one bank-2 quad-word and verify the bytes landed. Defends
/// against silent torn writes (brown-out mid-program leaving some bits
/// committed) — same invariant as [`write_quadword_verified`] on bank 1.
///
/// # Safety
/// Same contract as [`write_ns_quadword`].
pub unsafe fn write_ns_quadword_verified(addr: u32, data: &[u8; 16]) -> Result<(), ()> {
    // SAFETY: forwarded contract.
    unsafe { write_ns_quadword(addr, data)? };

    let src = addr as *const u8;
    for i in 0..16 {
        // SAFETY: `addr..addr+16` was just written; read-back stays in-region.
        if unsafe { read_volatile(src.add(i)) } != data[i] {
            return Err(());
        }
    }
    Ok(())
}

/// Erase a page that's part of a slot (dispatches to SECCR for secure
/// bank-1 pages and NSCR for NS bank-2 pages based on the absolute
/// page index). Used by `CMD_FW_BEGIN` to prepare the inactive slot
/// before streaming starts.
///
/// # Safety
/// Erases a secure-bank page. Caller must ensure the page is part of
/// the inactive A/B slot or is otherwise safe to clear.
pub unsafe fn erase_secure_page(page: u32) -> Result<(), ()> {
    // The proof constructor fails closed for page 127 and every out-of-range
    // value before the flash controller is unlocked or any MMIO write occurs.
    let proof = GenericSecurePage::new(page).ok_or(())?;
    let page = proof.get();
    // BKER selects the bank for a page erase. This used to be omitted
    // entirely, i.e. hard-wired to bank 1 — correct only while every secure
    // page lives in bank 1, and silently catastrophic under a geometry that
    // puts a secure slot in bank 2: a bank-2 page number would erase the
    // BANK-1 page of the same number (the manifests, slot A, or the
    // per-device pages). The bank now comes from the proof, so the two cannot
    // disagree.
    let bker = match proof.bank() {
        pqsigner_geometry::Bank::One => 0,
        pqsigner_geometry::Bank::Two => BKER,
    };
    cortex_m::interrupt::free(|_| {
        wait_bsy();
        clear_errors();
        unlock();

        let cr = PER | bker | (page << PNB_SHIFT);
        REG.seccr.write(cr);
        REG.seccr.write(cr | STRT);

        wait_bsy();

        REG.seccr.write(0);
        let sr = REG.secsr.read();
        lock();
        cortex_m::asm::dsb();
        cortex_m::asm::isb();
        // Invalidate ICACHE after the bank-1 slot-page erase, matching the
        // other secure erase/program helpers (file header comment). A
        // stale cached line here would make a subsequent verified re-flash
        // read back the pre-erase bytes and spuriously fail (see the
        // erase_ns_page / write_ns_quadword twins).
        icache_invalidate();

        if sr & ERR_MASK != 0 {
            clear_errors();
            Err(())
        } else {
            Ok(())
        }
    })
}

/// Erase the full set of pages owned by `slot` — both secure and
/// non-secure halves. Used at `CMD_FW_BEGIN` after the host declares
/// which inactive slot it's about to stream into. Order matters: we
/// erase the manifest last so a power-fail midway leaves the old
/// manifest still intact (and the now-partially-erased slot unusable,
/// which matches the previous state exactly — the old manifest
/// pointed at the *other* slot).
///
/// # Safety
/// Erases all pages of `slot`. Caller must ensure `slot` is the
/// inactive A/B slot.
pub unsafe fn erase_slot(slot: Slot) -> Result<(), ()> {
    let (first_s, last_s) = slot_secure_pages(slot);
    let (first_ns, last_ns) = slot_ns_pages(slot);

    for p in first_ns..=last_ns {
        // SAFETY: forwarded contract.
        unsafe { erase_ns_page(p as u8)? };
    }
    for p in first_s..=last_s {
        // SAFETY: forwarded contract.
        unsafe { erase_secure_page(p)? };
    }
    // Erase the target manifest last: this is what FSBL keys off to
    // decide whether the slot is active. While the manifest is erased
    // (all-0xFF), FSBL will reject it as BadMagic, so it cannot be
    // booted — and the other slot's manifest is still whole.
    // SAFETY: forwarded contract.
    unsafe { erase_secure_page(manifest_page_num(slot))? };

    Ok(())
}

/// Program a single quad-word anywhere inside a slot. Routes to the
/// correct controller (SECCR for bank 1, NSCR for bank 2) based on
/// the address. Returns `Err(())` on any flagged error or torn-write
/// detection.
///
/// # Safety
/// Commits 16 bytes to flash at `addr`. Caller must ensure the address
/// is inside the inactive A/B slot and currently erased.
pub unsafe fn write_slot_quadword_verified(addr: u32, data: &[u8; 16]) -> Result<(), ()> {
    if (pqsigner_geometry::BANK2_BASE..BANK2_END).contains(&addr) {
        // SAFETY: forwarded contract; bank-2 dispatch.
        unsafe { write_ns_quadword_verified(addr, data) }
    } else if (pqsigner_geometry::BANK1_BASE..BANK1_END).contains(&addr) {
        // SAFETY: forwarded contract; bank-1 dispatch.
        unsafe { write_quadword_verified(addr, data) }
    } else {
        Err(())
    }
}

// ===========================================================================
// Off-chain (EIP-1271) per-slot counter — page 123
// ===========================================================================
//
// One-page log-structured store for two per-slot u64 counters:
//   * `offchain_count[slot]`  — bumped on every CMD_SIGN_OFFCHAIN.
//   * `last_userop_count[slot]` — set when CMD_SIGN_USEROP commits
//     `local_offchain_count` into the signed inner tx.
//
// Each entry is one 16-byte quad-word:
//
//     [ 0..  8) slot_key  — sha256(account_index‖chain_id‖slot_index)[..8]
//     [ 8..  9) type      — 0x01 = offchain count, 0x02 = last_userop count
//     [ 9.. 16) count     — u64 BE big-endian, top byte is `type`
//
// Read = scan the page; for each non-blank QW with matching `slot_key`
// and `type`, take `max(current, count)`. Write = program the next
// blank QW. When the page fills, compaction reads the latest
// (slot_key, type) values into SRAM, erases the page, and replays them.
//
// "Slot is registered" is defined as "this firmware has at least one
// entry for this slot_key in flash". `register_slot` writes a
// last_userop_count = 0 entry the first time the firmware signs Type 1
// for the slot — that single QW is enough to flip the
// `is_registered` predicate to true for all subsequent calls. Without
// it, `cmd_sign_offchain` refuses, which is the recovery-correctness
// gate after a seed-restore.
//
// Page choice: 123 is the highest free secure page (124..127 are
// already allocated; 122 is the last secure-firmware page in the A/B
// slot layout). 8 KB / 16 = 512 QWs per cycle; we expect realistic
// usage < 50 active slots × 65,536 sigs ≈ 3.3 M total bumps over the
// device lifetime, ÷ 512 per cycle = ~6500 erase cycles — within the
// 10,000-cycle minimum endurance the STM32U585 datasheet specifies.

const OFFCHAIN_PAGE_ADDR: u32 =
    pqsigner_geometry::page_addr(pqsigner_geometry::Bank::One, OFFCHAIN_PAGE_NUM as u8);
const OFFCHAIN_PAGE_NUM: u32 = 123;
const OFFCHAIN_QW_SIZE: u32 = 16;
const OFFCHAIN_CAPACITY: u32 = 512; // 8 KB / 16

const OFFCHAIN_TYPE_COUNT: u8 = 0x01;
const OFFCHAIN_TYPE_USEROP: u8 = 0x02;
// MEDIUM-2 (audit counter-replay 20260611): durable per-slot count of
// Type-2 (slot-key) UserOp signatures this firmware has *produced* for
// the slot — including ones the companion never broadcast or that
// reverted on-chain. On-chain `slotUses[i]` only counts UserOps that
// *landed*, and EIP-1271 off-chain sigs are never counted on-chain at
// all, so the device cannot enforce the combined SPHINCS+ budget
// `slotUses + offchainSigCount <= MAX_SLOT_USES` from on-chain state
// alone. This local tally lets the firmware bound the *total* slot-key
// signatures it emits (off-chain + UserOp) to `MAX_SLOT_USES` per device
// incarnation, closing the ~2x combined-cap evasion a malicious companion
// could otherwise reach by withholding the publishing UserOps.
const OFFCHAIN_TYPE_USEROP_SIGS: u8 = 0x03;

/// Pack a journal entry into a 16-byte quad-word.
fn entry_qw(slot_key: &[u8; 8], entry_type: u8, count: u64) -> [u8; 16] {
    let mut qw = [0u8; 16];
    qw[..8].copy_from_slice(slot_key);
    qw[8] = entry_type;
    let count_be = count.to_be_bytes();
    qw[9..16].copy_from_slice(&count_be[1..8]); // 7-byte BE — supports up to 2^56
    qw
}

/// Parse a journal entry. Three outcomes:
///   * `None` — QW is truly blank (every byte is 0xFF). End of journal;
///     readers can stop scanning here.
///   * `Some((0, _, _))` — QW is non-blank but undecodable (stale bits
///     inherited from pre-all-C10 cutover firmware where the type byte
///     happens to be 0xFF but other bytes are not, OR an unknown type).
///     Readers MUST treat this as "skip and keep scanning" — there may
///     be valid entries past this hole.
///   * `Some((COUNT|USEROP, slot_key, count))` — valid entry.
///
/// The all-16-byte blank check has to mirror `find_next_blank_idx` exactly.
/// Without it, the writer's "skip stale QW, write to next truly-blank slot"
/// path produces entries the reader cannot find: every read short-circuits
/// at the first stale QW and `is_registered` returns false even though the
/// write succeeded into a later QW. Symptom on a real device that
/// upgraded across the cutover: `cmd_sign_offchain` refuses with
/// `OffchainSlotUnregistered` after one or more successful UserOps that
/// (silently) appended valid entries past a stale type-byte-0xFF QW.
///
fn parse_entry(qw_addr: u32) -> Option<(u8, [u8; 8], u64)> {
    let base = qw_addr as *const u8;
    // SAFETY: `base.add(8)` stays inside the QW.
    let type_byte = unsafe { read_volatile(base.add(8)) };
    if type_byte == 0xFF {
        // Type byte is 0xFF — could be a truly-blank QW (end of journal)
        // or a stale QW where only the type byte happens to read 0xFF.
        // Disambiguate via the same all-16-byte check `find_next_blank_idx`
        // uses; only an all-blank QW signals end-of-journal.
        let mut all_blank = true;
        for k in 0..(OFFCHAIN_QW_SIZE as usize) {
            // SAFETY: `k < 16` stays inside the QW.
            if unsafe { read_volatile(base.add(k)) } != 0xFF {
                all_blank = false;
                break;
            }
        }
        if all_blank {
            return None;
        }
        // Stale, undecodable, but the page may have valid entries past it.
        return Some((0, [0u8; 8], 0));
    }
    if type_byte != OFFCHAIN_TYPE_COUNT
        && type_byte != OFFCHAIN_TYPE_USEROP
        && type_byte != OFFCHAIN_TYPE_USEROP_SIGS
    {
        // Unknown type — treat as corrupt, skip but don't stop the scan.
        return Some((0, [0u8; 8], 0));
    }
    let mut slot_key = [0u8; 8];
    for i in 0..8 {
        // SAFETY: `i < 8` stays inside the QW.
        slot_key[i] = unsafe { read_volatile(base.add(i)) };
    }
    let mut count_bytes = [0u8; 8];
    for i in 0..7 {
        // SAFETY: `9 + i < 16` stays inside the QW.
        count_bytes[1 + i] = unsafe { read_volatile(base.add(9 + i)) };
    }
    let count = u64::from_be_bytes(count_bytes);
    Some((type_byte, slot_key, count))
}

/// Find the first blank QW in the page. Returns the QW *index*, or
/// `None` if the page is full and a compaction is required.
///
/// "Blank" means all 16 bytes of the QW are 0xFF. The cheap one-byte
/// check on the type field is wrong on devices that were upgraded
/// across the all-C10 cutover: pages 123–124 used to hold per-slot
/// persistent state, the firmware update doesn't erase them, and
/// stale bytes randomly leave QWs whose type byte is 0xFF but whose
/// other 15 bytes still hold old programmed bits. Writing to such a
/// QW with `write_quadword_verified` PROGERRs (NOR flash can only
/// flip 1→0; it cannot re-program a bit that is already 0) and the
/// caller surfaces it as "Sig commit FAIL".
///
fn find_next_blank_idx() -> Option<u32> {
    let base = OFFCHAIN_PAGE_ADDR as *const u8;
    for i in 0..OFFCHAIN_CAPACITY {
        // SAFETY: `i * 16 < 8192` stays inside the page.
        let qw_base = unsafe { base.add((i * OFFCHAIN_QW_SIZE) as usize) };
        let mut all_blank = true;
        for k in 0..(OFFCHAIN_QW_SIZE as usize) {
            // SAFETY: `k < 16` stays inside the QW.
            if unsafe { read_volatile(qw_base.add(k)) } != 0xFF {
                all_blank = false;
                break;
            }
        }
        if all_blank {
            return Some(i);
        }
    }
    None
}

/// Erase page 123 — wipes every off-chain counter back to "no record".
/// On the next access, every slot will look unregistered. Use only as
/// part of compaction (which immediately re-writes the latest values
/// before any other code touches the page) or in a deliberate
/// reset-to-factory flow.
///
/// # Safety
/// Erases persistent flash at `OFFCHAIN_PAGE_ADDR`.
unsafe fn erase_offchain_page() -> Result<(), ()> {
    cortex_m::interrupt::free(|_| {
        wait_bsy();
        clear_errors();
        unlock();

        let cr = PER | (OFFCHAIN_PAGE_NUM << PNB_SHIFT);
        REG.seccr.write(cr);
        REG.seccr.write(cr | STRT);

        wait_bsy();

        REG.seccr.write(0);
        let sr = REG.secsr.read();
        lock();
        cortex_m::asm::dsb();
        cortex_m::asm::isb();
        icache_invalidate();

        if sr & ERR_MASK != 0 {
            clear_errors();
            Err(())
        } else {
            Ok(())
        }
    })
}

/// Maximum number of distinct active slots the SRAM compaction buffer
/// supports. Realistic usage is far below this; well-behaved firmware
/// rotates slots before they exhaust their 65,536-sig cap.
const MAX_ACTIVE_SLOTS: usize = 256;

/// SRAM scratch table for compaction.
#[derive(Clone, Copy)]
struct SlotEntry {
    slot_key: [u8; 8],
    offchain_count: u64,
    last_userop_count: u64,
    userop_sigs: u64,
    has_offchain: bool,
    has_userop: bool,
    has_userop_sigs: bool,
}

/// Scan the page once and project the latest `(offchain, last_userop,
/// userop_sigs)` triple for every observed `slot_key`. Used by both
/// compaction and the (rarely-needed) "show me all active slots"
/// introspection path. The table is allocated on the caller's stack via
/// the in/out reference.
///
/// Returns the number of distinct slot_keys observed. **HIGH-1 (audit
/// counter-replay 20260611):** if more than `MAX_ACTIVE_SLOTS` distinct
/// slot_keys are present, `*overflow` is set to `true` and the surplus
/// slots are NOT projected. The old code silently dropped them, which
/// erased those slots' counters on the next compaction — a counter
/// rollback. `compact_page` now refuses (fail-closed) when `overflow`
/// is set rather than committing a lossy compaction.
fn scan_page_into_table(
    table: &mut [SlotEntry; MAX_ACTIVE_SLOTS],
    overflow: &mut bool,
) -> usize {
    let mut n: usize = 0;
    for i in 0..OFFCHAIN_CAPACITY {
        let addr = OFFCHAIN_PAGE_ADDR + i * OFFCHAIN_QW_SIZE;
        match parse_entry(addr) {
            None => break, // first blank — done
            Some((0, _, _)) => continue, // unknown type — skip
            Some((t, sk, count)) => {
                // Find existing entry for this slot_key, else allocate.
                let mut found: Option<usize> = None;
                for j in 0..n {
                    if table[j].slot_key == sk {
                        found = Some(j);
                        break;
                    }
                }
                let idx = match found {
                    Some(j) => j,
                    None => {
                        if n >= MAX_ACTIVE_SLOTS {
                            // HIGH-1 fail-closed: do NOT silently drop. Flag
                            // the overflow so the caller refuses the
                            // (lossy) compaction instead of rolling back
                            // the surplus slots' counters to zero. The page
                            // only holds 512 QWs, so 256 distinct live slots
                            // is already pathological.
                            *overflow = true;
                            continue;
                        }
                        let j = n;
                        n += 1;
                        table[j] = SlotEntry {
                            slot_key: sk,
                            offchain_count: 0,
                            last_userop_count: 0,
                            userop_sigs: 0,
                            has_offchain: false,
                            has_userop: false,
                            has_userop_sigs: false,
                        };
                        j
                    }
                };
                if t == OFFCHAIN_TYPE_COUNT {
                    if count > table[idx].offchain_count || !table[idx].has_offchain {
                        table[idx].offchain_count = count;
                    }
                    table[idx].has_offchain = true;
                } else if t == OFFCHAIN_TYPE_USEROP {
                    if count > table[idx].last_userop_count || !table[idx].has_userop {
                        table[idx].last_userop_count = count;
                    }
                    table[idx].has_userop = true;
                } else if t == OFFCHAIN_TYPE_USEROP_SIGS {
                    if count > table[idx].userop_sigs || !table[idx].has_userop_sigs {
                        table[idx].userop_sigs = count;
                    }
                    table[idx].has_userop_sigs = true;
                }
            }
        }
    }
    n
}

/// Compact the page: read the latest values per (slot_key, type) into
/// SRAM, erase, then replay. Power-loss-tolerant: a torn compaction
/// leaves the page (partially) erased, which loses counters for some
/// slots — those slots then look unregistered, which forces a Type 1
/// re-registration but does not break correctness.
///
/// # Safety
/// Erases and rewrites page 123.
unsafe fn compact_page() -> Result<(), ()> {
    let mut table = [SlotEntry {
        slot_key: [0u8; 8],
        offchain_count: 0,
        last_userop_count: 0,
        userop_sigs: 0,
        has_offchain: false,
        has_userop: false,
        has_userop_sigs: false,
    }; MAX_ACTIVE_SLOTS];
    let mut overflow = false;
    let n = scan_page_into_table(&mut table, &mut overflow);

    // HIGH-1 fail-closed: if the page holds more distinct slots than the
    // SRAM projection table can hold, a compaction would drop the surplus
    // and silently roll their counters back to zero. Refuse here —
    // BEFORE erasing — so the page (and every slot's budget) stays
    // intact. The caller surfaces this as a write failure and declines to
    // sign, which is strictly safer than a counter rollback.
    if overflow {
        return Err(());
    }

    // SAFETY: about to replay from SRAM.
    unsafe { erase_offchain_page()? };

    // Replay: write surviving entries at the start of the page. Each
    // present (slot, type) projection is written to the next blank QW;
    // blanks only advance as we write, so no regression is possible.
    //
    // F3 crash-atomicity: `compact_page` is erase-then-replay on a SINGLE
    // page with no two-phase staging, so a power-loss / reset BETWEEN the
    // erase and the end of replay can tear it. Because "registered" ==
    // "≥1 entry exists", the dangerous torn state is "slot registered but
    // its counter rolled back to 0" — the F-12 forward/reverse double-scan
    // cannot catch it (both scans agree on the durably-gone data). We make
    // the SECURITY-critical instance of that state UNREACHABLE by replaying
    // `USEROP_SIGS` FIRST for each slot:
    //
    //   * USEROP_SIGS is the unbounded, NO-on-chain-backstop few-time-key
    //     sig tally (off-chain / withheld slot-key sigs eroding the C10
    //     few-time margin). Writing it first means the instant a slot
    //     becomes registered after a torn compaction, its tally is already
    //     the true high-water mark. A tear BEFORE it leaves the slot
    //     unregistered → invariant #9 forces a Type-1 re-registration (safe).
    //   * COUNT (offchain) and USEROP (last on-chain userop count) are
    //     written after. A tear that rolls THESE back is bounded: COUNT is
    //     backstopped by the on-chain `_setOffchainSigCount` monotonicity +
    //     the firmware gap ≤ MAX_OFFCHAIN_GAP, and USEROP reflects landed
    //     userops the on-chain `slotUses` cap independently rejects.
    //
    // Residual (tracked): a torn COUNT/USEROP roll-back is still possible but
    // bounded as above. Full crash-atomicity (two-page ping-pong / commit
    // marker) is a larger flash-layout change; see docs/security/threat-model.md.
    for j in 0..n {
        let entry = table[j];
        if entry.has_userop_sigs {
            // F3 + MEDIUM-2: the durable few-time-sig tally is written FIRST so
            // a torn compaction can never leave a registered slot with this
            // (unbacked) counter rolled back to zero.
            let qw = entry_qw(&entry.slot_key, OFFCHAIN_TYPE_USEROP_SIGS, entry.userop_sigs);
            let blank = find_next_blank_idx().ok_or(())?;
            // SAFETY: target QW is inside page 123 and was just erased.
            unsafe {
                write_quadword_verified(OFFCHAIN_PAGE_ADDR + blank * OFFCHAIN_QW_SIZE, &qw)?
            };
        }
        if entry.has_userop {
            let qw = entry_qw(&entry.slot_key, OFFCHAIN_TYPE_USEROP, entry.last_userop_count);
            let blank = find_next_blank_idx().ok_or(())?;
            // SAFETY: target QW is inside page 123 and was just erased.
            unsafe {
                write_quadword_verified(OFFCHAIN_PAGE_ADDR + blank * OFFCHAIN_QW_SIZE, &qw)?
            };
        }
        if entry.has_offchain {
            let qw = entry_qw(&entry.slot_key, OFFCHAIN_TYPE_COUNT, entry.offchain_count);
            let blank = find_next_blank_idx().ok_or(())?;
            // SAFETY: target QW is inside page 123 and was just erased.
            unsafe {
                write_quadword_verified(OFFCHAIN_PAGE_ADDR + blank * OFFCHAIN_QW_SIZE, &qw)?
            };
        }
    }
    Ok(())
}

/// Count distinct live slot keys currently in the page, saturating at
/// `MAX_DISTINCT_SLOTS`. Lightweight companion to the `write_entry` Layer-2
/// cap (see [`crate::offchain_state::MAX_DISTINCT_SLOTS`]): it dedups seen keys
/// into a small fixed table (`MAX_DISTINCT_SLOTS` × 8 bytes ≈ 1 KB stack —
/// deliberately NOT the ~10 KB `[SlotEntry; MAX_ACTIVE_SLOTS]` compaction
/// table, given the documented secure-world stack pressure) and stops as soon
/// as it has seen `MAX_DISTINCT_SLOTS` distinct keys, since the only caller
/// compares `>= MAX_DISTINCT_SLOTS`. Stale / blank QWs are skipped exactly as
/// `scan_page_into_table` / `is_registered_forward` skip them.
fn distinct_slot_count_capped() -> usize {
    const CAP: usize = crate::offchain_state::MAX_DISTINCT_SLOTS;
    let mut seen = [[0u8; 8]; CAP];
    let mut n = 0usize;
    for i in 0..OFFCHAIN_CAPACITY {
        let addr = OFFCHAIN_PAGE_ADDR + i * OFFCHAIN_QW_SIZE;
        match parse_entry(addr) {
            None => break,               // first truly-blank QW — end of journal
            Some((0, _, _)) => continue, // stale / undecodable — skip, keep scanning
            Some((_, sk, _)) => {
                let mut found = false;
                for s in seen[..n].iter() {
                    if *s == sk {
                        found = true;
                        break;
                    }
                }
                if !found {
                    seen[n] = sk;
                    n += 1;
                    if n >= CAP {
                        // Already at the cap; the sole caller refuses a new
                        // slot at this point and more distinct keys can only
                        // keep n == CAP, so stop early (bounds-safe: the last
                        // write was seen[CAP-1]).
                        return n;
                    }
                }
            }
        }
    }
    n
}

/// Strict, read-only page-123 projection for the optional forced-blind
/// preflight. Unlike the legacy readers, this path accepts only one canonical
/// append prefix followed by erased QWs: an unknown record, a nonblank record
/// after the first blank, or more than the lifetime slot cap is fatal. It
/// computes the exact compacted live-QW count without erasing or repairing the
/// page and binds the receipt to every byte read.
///
/// # Safety
///
/// Reads the secure flash mapping at `OFFCHAIN_PAGE_ADDR`. The caller must
/// serialize the scan with page-123 mutators.
#[cfg(feature = "erc7730-forced-blind")]
#[inline(never)]
pub unsafe fn forced_capacity_snapshot(
    requested_slot: &[u8; 8],
) -> Result<crate::offchain_state::ForcedCapacitySnapshot, crate::offchain_state::ForcedCapacityError>
{
    use sha2::{Digest, Sha256};

    const CAP: usize = crate::offchain_state::MAX_DISTINCT_SLOTS;
    let mut keys = [[0u8; 8]; CAP];
    let mut type_masks = [0u8; CAP];
    let mut distinct_live = 0usize;
    let mut blank_qws = 0usize;
    let mut saw_blank = false;
    let mut slot_present = false;
    let mut state = Sha256::new();
    state.update(b"PQSigner/offchain-state/page123-capacity/v1");

    for index in 0..OFFCHAIN_CAPACITY {
        let base = (OFFCHAIN_PAGE_ADDR + index * OFFCHAIN_QW_SIZE) as *const u8;
        let mut raw = [0u8; OFFCHAIN_QW_SIZE as usize];
        for (offset, byte) in raw.iter_mut().enumerate() {
            // SAFETY: index < 512 and offset < 16 stay inside page 123.
            *byte = unsafe { read_volatile(base.add(offset)) };
        }
        state.update(raw);

        if raw.iter().all(|byte| *byte == 0xFF) {
            saw_blank = true;
            blank_qws += 1;
            continue;
        }
        if saw_blank {
            return Err(crate::offchain_state::ForcedCapacityError::InvalidProjection);
        }

        let type_mask = match raw[8] {
            OFFCHAIN_TYPE_COUNT => 0b001,
            OFFCHAIN_TYPE_USEROP => 0b010,
            OFFCHAIN_TYPE_USEROP_SIGS => 0b100,
            _ => {
                return Err(crate::offchain_state::ForcedCapacityError::InvalidProjection);
            }
        };
        let mut slot_key = [0u8; 8];
        slot_key.copy_from_slice(&raw[..8]);
        slot_present |= &slot_key == requested_slot;

        let mut existing = None;
        for (slot_index, key) in keys[..distinct_live].iter().enumerate() {
            if *key == slot_key {
                existing = Some(slot_index);
                break;
            }
        }
        let slot_index = match existing {
            Some(slot_index) => slot_index,
            None => {
                if distinct_live == CAP {
                    return Err(crate::offchain_state::ForcedCapacityError::InvalidProjection);
                }
                let slot_index = distinct_live;
                keys[slot_index] = slot_key;
                distinct_live += 1;
                slot_index
            }
        };
        type_masks[slot_index] |= type_mask;
    }

    let projected_live_qws = type_masks[..distinct_live]
        .iter()
        .map(|mask| mask.count_ones() as usize)
        .sum();
    let mut state_sha256 = [0u8; 32];
    state_sha256.copy_from_slice(&state.finalize());
    Ok(crate::offchain_state::ForcedCapacitySnapshot {
        state_sha256,
        distinct_live,
        projected_live_qws,
        blank_qws,
        slot_present,
    })
}

/// Append a journal entry, compacting first if the page is full and
/// self-healing the page if it inherited unwritable garbage from the
/// pre-all-C10 per-slot state.
///
/// Three retry tiers:
/// 1. Happy path: a truly-blank QW exists, write succeeds.
/// 2. Page full: run a normal compaction (preserves valid entries).
/// 3. Page is wedged in an unwritable shape — i.e. either compaction
///    can't free space *or* the targeted "blank" QW won't accept the
///    write because of stale 0-bits from the prior incarnation. Bulk-
///    erase the whole page and retry once. Stale data here cannot be
///    a valid current entry the wallet still cares about: pages
///    123–124 were freed by the cutover and any leftover bits were
///    written by long-since-removed firmware. Compaction would have
///    surfaced that as `Some((0, _, _))` "unknown type" entries which
///    are explicitly skipped, so the bulk erase loses nothing live.
///
/// # Safety
/// Programs page 123.
unsafe fn write_entry(qw: &[u8; 16]) -> Result<(), ()> {
    // Layer-2 structural cap (page-123 exhaustion → permanent-brick fix; see
    // docs/security/vulns/VULN-offchain-sync-page123-exhaustion-brick.md and
    // crate::offchain_state::MAX_DISTINCT_SLOTS). Refuse to create a NEW
    // distinct slot once the page already holds MAX_DISTINCT_SLOTS of them, so
    // the page can never reach the un-compactable state that bricks every sign
    // path. Updates to an already-present slot are always allowed — they can't
    // grow the distinct-slot set. This sits ABOVE compact_page (which replays
    // via write_quadword_verified and bypasses write_entry), so existing slots
    // always re-compact; only brand-new slots beyond the cap are refused. The
    // distinct scan runs ONLY on the new-slot branch, so steady-state
    // existing-slot writes pay only the cheap presence check — negligible
    // against the ~1 s C10 sign. This does NOT weaken HIGH-1/F3: nothing is
    // evicted or erased, the few-time `userop_sigs` tally is untouched.
    let mut sk = [0u8; 8];
    sk.copy_from_slice(&qw[0..8]);
    // SAFETY: page-123 journal read only (same contract as the other readers).
    let already_present = unsafe { offchain_count_is_registered(&sk) };
    let distinct = if already_present {
        0 // ignored by may_create_distinct_slot when present; skips the scan
    } else {
        distinct_slot_count_capped()
    };
    if !crate::offchain_state::may_create_distinct_slot(distinct, already_present) {
        return Err(());
    }

    if find_next_blank_idx().is_none() {
        // SAFETY: caller asserts page 123 is writable; compaction is
        // power-loss-tolerant per its doc comment.
        unsafe { compact_page()? };
    }

    // First write attempt — at the QW chosen by find_next_blank_idx.
    if let Some(blank) = find_next_blank_idx() {
        // SAFETY: target QW is inside page 123 and was just observed blank.
        if unsafe {
            write_quadword_verified(OFFCHAIN_PAGE_ADDR + blank * OFFCHAIN_QW_SIZE, qw)
        }
        .is_ok()
        {
            return Ok(());
        }
    }

    // HIGH-1 (audit counter-replay 20260611): the bulk-erase self-heal
    // must NEVER destroy live counters. A failed / fault-injected write on
    // a page full of live per-slot entries would otherwise erase every
    // slot's offchain / last_userop / userop_sigs counter to zero — a
    // single-fault rollback of the entire off-chain signing budget that
    // the F-12 read double-scan cannot detect (after the erase both the
    // forward and reverse scans agree on the empty page, so no mismatch
    // fires). Only bulk-erase when the page holds NO decodable COUNT /
    // USEROP / USEROP_SIGS entry — i.e. it is pure pre-all-C10 cutover
    // garbage, the only case this self-heal was ever designed for. If live
    // entries exist, fail closed: refuse the write (the caller surfaces
    // "Sig commit FAIL" and declines to sign), which is strictly safer
    // than rolling the budget back.
    if offchain_page_has_live_entries() {
        return Err(());
    }

    // Page is cutover-garbage only — safe to bulk-erase and retry once.
    // After the erase the whole page is 0xFF, so find_next_blank_idx
    // returns 0 and the write must succeed (or the flash itself is dead).
    // SAFETY: see write_entry's # Safety contract.
    unsafe { erase_offchain_page()? };
    let blank = find_next_blank_idx().ok_or(())?;
    // SAFETY: target QW is inside page 123 and was just erased.
    unsafe { write_quadword_verified(OFFCHAIN_PAGE_ADDR + blank * OFFCHAIN_QW_SIZE, qw) }
}

/// True iff page 123 holds at least one decodable COUNT / USEROP /
/// USEROP_SIGS entry — i.e. live per-slot counter state the wallet still
/// cares about. Gates the `write_entry` self-heal bulk erase (HIGH-1) so
/// a failed / glitched write can never roll back live counters. Pre-all-
/// C10 cutover garbage (non-decodable QWs) reads as "no live entries", so
/// the legitimate one-time self-heal of an inherited-garbage page is
/// preserved. Scans the whole page (no early-exit) so a live entry that
/// happens to sit past a blank QW is still detected — fail-closed.
fn offchain_page_has_live_entries() -> bool {
    for i in 0..OFFCHAIN_CAPACITY {
        let addr = OFFCHAIN_PAGE_ADDR + i * OFFCHAIN_QW_SIZE;
        if let Some((t, _, _)) = parse_entry(addr) {
            if t == OFFCHAIN_TYPE_COUNT
                || t == OFFCHAIN_TYPE_USEROP
                || t == OFFCHAIN_TYPE_USEROP_SIGS
            {
                return true;
            }
        }
    }
    false
}

/// Forward scan — the original log-structured implementation. Stops at the
/// first all-blank QW (= end of journal). Used as the first leg of the
/// F-12 fault-injection-hardened double-scan.
#[inline(never)]
unsafe fn scan_forward(slot_key: &[u8; 8], target_type: u8) -> u64 {
    let mut latest: u64 = 0;
    let mut found = false;
    for i in 0..OFFCHAIN_CAPACITY {
        let addr = OFFCHAIN_PAGE_ADDR + i * OFFCHAIN_QW_SIZE;
        match parse_entry(addr) {
            None => break,
            Some((t, sk, count)) if t == target_type && sk == *slot_key => {
                if count > latest || !found {
                    latest = count;
                    found = true;
                }
            }
            _ => {}
        }
    }
    latest
}

/// Reverse scan — iterates QWs from CAPACITY-1 down to 0, skipping ALL
/// blanks and undecodable entries (no early-break on None). Asymmetric
/// control flow vs `scan_forward`: a fault that early-exits the forward
/// loop doesn't symmetrically early-exit this one. F-12 fix: comparing
/// the two scans' results catches any FI-induced underreporting.
#[inline(never)]
unsafe fn scan_reverse(slot_key: &[u8; 8], target_type: u8) -> u64 {
    let mut latest: u64 = 0;
    let mut i = OFFCHAIN_CAPACITY;
    while i > 0 {
        i -= 1;
        let addr = OFFCHAIN_PAGE_ADDR + i * OFFCHAIN_QW_SIZE;
        if let Some((t, sk, count)) = parse_entry(addr) {
            if t == target_type && sk == *slot_key && count > latest {
                latest = count;
            }
        }
        // Note: no break-on-None — keep iterating across blank tail QWs.
    }
    latest
}

/// Read the latest off-chain sig count for `slot_key`. Returns 0 if no
/// entry exists (caller distinguishes "0 sigs" from "unregistered" via
/// `offchain_count_is_registered`).
///
/// **F-12 hardening (single-fault rollback resistance).** Scans the page
/// forward AND reverse with `wait_random()` between, and halts the CPU on
/// mismatch. A single fault that underreports one direction cannot affect
/// both — the reverse pass iterates the page asymmetrically (no early-break
/// on blank, walks from end), so a control-flow corruption at scan entry
/// affects forward only. Pre-fix, `make flashctr` empirically found **770
/// single-fault rollback cases** on this code (see tools/sca/README.md §F-12);
/// post-fix the hardened mirror is down to ~10 (control-flow at scan entry
/// that early-exits BOTH directions identically — the residual is bounded
/// by additional layers a future hardening pass could add).
pub unsafe fn offchain_count_read(slot_key: &[u8; 8]) -> u64 {
    // F-12 hardening: slot_key input-register redundancy. Load the key
    // twice via `read_volatile` with a randomised gap between, halt-on-
    // mismatch. A stuck-at-0 fault on the slot_key argument register
    // would otherwise survive into both forward and reverse scans
    // (`make flashctr` empirically saw 10 such residuals before this
    // belt-and-braces was added).
    let sk_a: [u8; 8] = *slot_key;
    crate::fi::wait_random();
    let sk_b: [u8; 8] = *slot_key;
    if sk_a != sk_b {
        return u64::MAX;
    }
    let r1 = scan_forward(&sk_a, OFFCHAIN_TYPE_COUNT);
    crate::fi::wait_random();
    let r2 = scan_reverse(&sk_b, OFFCHAIN_TYPE_COUNT);
    if r1 != r2 {
        // FI glitch detected. The caller can't recover — return the
        // safest value: u64::MAX. Downstream cap checks (`new_count >
        // MAX_SLOT_USES`) will trip and refuse to sign. This is fail-
        // closed: rather than risk a silent rollback we permanently
        // refuse signing until the next power cycle resets the cap-check
        // path on a fresh emulator instance.
        return u64::MAX;
    }
    r1
}

/// Read the most recent UserOp-snapshot count (the value embedded in
/// the inner tx of the last `CMD_SIGN_USEROP`). F-12-hardened: same
/// forward+reverse double scan as `offchain_count_read`.
pub unsafe fn last_userop_count_read(slot_key: &[u8; 8]) -> u64 {
    let sk_a: [u8; 8] = *slot_key;
    crate::fi::wait_random();
    let sk_b: [u8; 8] = *slot_key;
    if sk_a != sk_b {
        return u64::MAX;
    }
    let r1 = scan_forward(&sk_a, OFFCHAIN_TYPE_USEROP);
    crate::fi::wait_random();
    let r2 = scan_reverse(&sk_b, OFFCHAIN_TYPE_USEROP);
    if r1 != r2 {
        return u64::MAX;
    }
    r1
}

/// True iff this firmware has at least one entry for `slot_key`.
/// After a fresh-from-seed boot this is `false` for every slot, which
/// is the recovery refusal gate.
///
/// F-12-hardened: forward + reverse double scan, halt-on-mismatch. The
/// answer is a single bit so a fault on one direction's return could flip
/// it; reverse cross-check catches that.
///
/// # Safety
/// Same contract as the other `offchain_count_*` readers — reads from
/// the page-123 journal.
pub unsafe fn offchain_count_is_registered(slot_key: &[u8; 8]) -> bool {
    let sk_a: [u8; 8] = *slot_key;
    crate::fi::wait_random();
    let sk_b: [u8; 8] = *slot_key;
    if sk_a != sk_b {
        return false;
    }
    let r1 = unsafe { is_registered_forward(&sk_a) };
    crate::fi::wait_random();
    let r2 = unsafe { is_registered_reverse(&sk_b) };
    if r1 != r2 {
        // Fail-closed: report unregistered → refuses the off-chain sign
        // path until the next call.
        return false;
    }
    r1
}

#[inline(never)]
unsafe fn is_registered_forward(slot_key: &[u8; 8]) -> bool {
    for i in 0..OFFCHAIN_CAPACITY {
        let addr = OFFCHAIN_PAGE_ADDR + i * OFFCHAIN_QW_SIZE;
        match parse_entry(addr) {
            None => return false,
            Some((0, _, _)) => continue,
            Some((_, sk, _)) if sk == *slot_key => return true,
            _ => continue,
        }
    }
    false
}

#[inline(never)]
unsafe fn is_registered_reverse(slot_key: &[u8; 8]) -> bool {
    let mut i = OFFCHAIN_CAPACITY;
    while i > 0 {
        i -= 1;
        let addr = OFFCHAIN_PAGE_ADDR + i * OFFCHAIN_QW_SIZE;
        if let Some((t, sk, _)) = parse_entry(addr) {
            if t != 0 && sk == *slot_key {
                return true;
            }
        }
    }
    false
}

/// Write the "slot is registered" marker (a last_userop_count = 0
/// entry). No-op if already registered. Called by `cmd_sign_userop`
/// when it signs a Type 1 for a fresh slot.
///
/// # Safety
/// Programs page 123.
pub unsafe fn offchain_count_register_slot(slot_key: &[u8; 8]) -> Result<(), ()> {
    if offchain_count_is_registered(slot_key) {
        return Ok(());
    }
    let qw = entry_qw(slot_key, OFFCHAIN_TYPE_USEROP, 0);
    // SAFETY: forwarded contract.
    unsafe { write_entry(&qw)? };
    // FI hardening (F16/SCAFI-4): read-back + sentinel-gated re-check,
    // mirroring the `offchain_count_bump` / `userop_sigs_bump` twins —
    // a suppressed write or a value-faulted entry (wrong slot key) must
    // not report success. `write_quadword_verified` only proves the QW
    // landed AS GIVEN, not that `entry_qw` produced the intended value.
    if !offchain_count_is_registered(slot_key) {
        return Err(());
    }
    if crate::fi::check_true_into_sentinel(|| offchain_count_is_registered(slot_key))
        != crate::fi::OK_SENTINEL
    {
        return Err(());
    }
    Ok(())
}

/// Bump the off-chain sig counter to `new_count`. Reverts via `Err(())`
/// if `new_count <= current`; the caller (cmd_sign_offchain) computes
/// `new_count = current + 1` so this only fails on flash trouble.
///
/// **F-12 hardening — slot_key input-redundancy.** A fault at function
/// prologue can stuck-at the `slot_key` register before it's used by
/// `offchain_count_read` / `entry_qw`. The function would then operate
/// on the WRONG slot (read its max, write an entry for it), pass the
/// FI triple-check (which also reads the wrong slot), and return Ok —
/// while OUR slot's counter never advanced. Defense: dereference the
/// caller's slot_key into TWO local copies with `wait_random()` between,
/// compare; halt if they differ. Then use only the locally-verified copy.
///
/// # Safety
/// Programs page 123.
pub unsafe fn offchain_count_bump(slot_key: &[u8; 8], new_count: u64) -> Result<(), ()> {
    // F-12: input redundancy on slot_key. Catches stuck-at on the
    // slot_key pointer/register at function entry.
    let sk_a: [u8; 8] = *slot_key;
    crate::fi::wait_random();
    let sk_b: [u8; 8] = *slot_key;
    if sk_a != sk_b {
        return Err(());
    }
    let slot_key = &sk_a;

    let pre = offchain_count_read(slot_key);
    if new_count <= pre {
        return Err(());
    }
    let qw = entry_qw(slot_key, OFFCHAIN_TYPE_COUNT, new_count);
    // SAFETY: forwarded contract.
    unsafe { write_entry(&qw)? };
    // FI hardening: read-back the post-bump value, refuse if it didn't
    // land. Mirrors `pin_attempts_bump`.
    let post = offchain_count_read(slot_key);
    if post != new_count {
        return Err(());
    }
    if crate::fi::check_true_into_sentinel(|| offchain_count_read(slot_key) == new_count)
        != crate::fi::OK_SENTINEL
    {
        return Err(());
    }
    Ok(())
}

/// Promote the off-chain sig counter for `slot_key` to at least `target`.
/// Idempotent if the stored value already meets or exceeds `target`.
///
/// Used by the sign path to repair a stale local view: if a flash event
/// (compaction half-failure, partial torn write, etc.) lost a `COUNT`
/// entry but kept its `USEROP` snapshot, `offchain_count_read` can dip
/// below `last_userop_count_read`. Signing with the lower value would
/// always revert on-chain because `_setOffchainSigCount` enforces
/// monotonicity over `offchainSigCount[i]`. Re-asserting the high-water
/// mark here keeps the firmware's view consistent with what was last
/// committed to the chain so the next Type 2 sig commits a value the
/// chain will accept.
///
/// # Safety
/// Programs page 123.
pub unsafe fn offchain_count_promote_to(slot_key: &[u8; 8], target: u64) -> Result<(), ()> {
    // F-12: slot_key input-redundancy (see offchain_count_bump for rationale).
    let sk_a: [u8; 8] = *slot_key;
    crate::fi::wait_random();
    let sk_b: [u8; 8] = *slot_key;
    if sk_a != sk_b {
        return Err(());
    }
    let slot_key = &sk_a;

    // Value-inflation brick defence (see
    // `docs/security/vulns/VULN-offchain-sync-value-inflation-slot-brick.md` and
    // `crate::offchain_state::OFFCHAIN_COUNT_CEILING`): never promote the
    // monotonic off-chain counter to a value at or above `MAX_SLOT_USES`. A
    // companion-inflated `last_userop` reaches this promote via the sign-path
    // repair branch; clamping here is the structural chokepoint that keeps every
    // caller (sync + both sign paths) from durably tripping the combined-cap gate
    // forever. The clamp never clips a legitimate value — a truthful on-chain
    // `offchainSigCount` is always `< MAX_SLOT_USES`.
    let target = crate::offchain_state::clamp_offchain_count(target);

    let pre = offchain_count_read(slot_key);
    if target <= pre {
        return Ok(());
    }
    let qw = entry_qw(slot_key, OFFCHAIN_TYPE_COUNT, target);
    // SAFETY: forwarded contract.
    unsafe { write_entry(&qw)? };
    // FI hardening (F16/SCAFI-4): read-back + sentinel-gated re-check,
    // mirroring `offchain_count_bump` — a suppressed write or a
    // value-faulted entry (wrong slot key or count) must fail, not
    // silently leave the local view below the on-chain high-water mark.
    // `write_quadword_verified` only proves the QW landed AS GIVEN, not
    // that `entry_qw` produced the intended value.
    let post = offchain_count_read(slot_key);
    if post != target {
        return Err(());
    }
    if crate::fi::check_true_into_sentinel(|| offchain_count_read(slot_key) == target)
        != crate::fi::OK_SENTINEL
    {
        return Err(());
    }
    Ok(())
}

/// Update the last_userop_count snapshot for `slot_key`. Idempotent if
/// `count == current`. Tolerant of `count < current`: rather than
/// permanently failing the sign with an `Err` (which manifested as
/// "Sig commit FAIL" on the OLED and bricked the slot for future
/// signs), it returns `Ok` as a no-op. Real monotonicity is enforced
/// at two stronger gates: (a) the sign path promotes
/// `new_offchain_count` to `max(offchain_count_read,
/// last_userop_count_read)` so this function is never reached with
/// `count < pre` in correct execution, and (b) the on-chain
/// `_setOffchainSigCount` reverts on non-monotonic input — that revert
/// is the authoritative gate, not this firmware-side check.
///
/// # Safety
/// Programs page 123.
pub unsafe fn last_userop_count_set(slot_key: &[u8; 8], count: u64) -> Result<(), ()> {
    // F-12: slot_key input-redundancy.
    let sk_a: [u8; 8] = *slot_key;
    crate::fi::wait_random();
    let sk_b: [u8; 8] = *slot_key;
    if sk_a != sk_b {
        return Err(());
    }
    let slot_key = &sk_a;

    // Value-inflation brick defence (see
    // `docs/security/vulns/VULN-offchain-sync-value-inflation-slot-brick.md` and
    // `crate::offchain_state::OFFCHAIN_COUNT_CEILING`): the `count` here is the
    // untrusted companion's `CMD_OFFCHAIN_SYNC` target. Clamp it below
    // `MAX_SLOT_USES` so a hostile floor bump cannot be promoted into the
    // monotonic off-chain counter and permanently trip the combined-cap gate. A
    // legitimate on-chain `offchainSigCount` is always `< MAX_SLOT_USES`, so the
    // clamp is a no-op for every honest sync.
    let count = crate::offchain_state::clamp_offchain_count(count);

    let pre = last_userop_count_read(slot_key);
    if count < pre {
        // Defensive no-op. The flash already records a higher
        // high-water mark; the caller is either replaying a stale
        // value (harmless) or has a bug we cannot fix from here. Do
        // not regress the stored value — the on-chain state would
        // not accept a regression either.
        return Ok(());
    }
    if count == pre && offchain_count_is_registered(slot_key) {
        return Ok(());
    }
    let qw = entry_qw(slot_key, OFFCHAIN_TYPE_USEROP, count);
    // SAFETY: forwarded contract.
    unsafe { write_entry(&qw)? };
    // FI hardening (F16/SCAFI-4): read-back + sentinel-gated re-check,
    // mirroring the `offchain_count_bump` / `userop_sigs_bump` twins —
    // a suppressed write or a value-faulted entry (wrong slot key or
    // count) must not report success. `write_quadword_verified` only
    // proves the QW landed AS GIVEN, not that `entry_qw` produced the
    // intended value.
    let post = last_userop_count_read(slot_key);
    if post != count {
        return Err(());
    }
    if crate::fi::check_true_into_sentinel(|| last_userop_count_read(slot_key) == count)
        != crate::fi::OK_SENTINEL
    {
        return Err(());
    }
    Ok(())
}

/// Read the durable per-slot tally of Type-2 (slot-key) UserOp signatures
/// this firmware has produced for `slot_key` (MEDIUM-2). Returns 0 when
/// no entry exists. F-12-hardened: forward + reverse double scan with
/// `wait_random()` between, returning `u64::MAX` on disagreement so the
/// combined-cap check fails closed (refuses to sign).
///
/// # Safety
/// Reads from the page-123 journal.
pub unsafe fn userop_sigs_read(slot_key: &[u8; 8]) -> u64 {
    let sk_a: [u8; 8] = *slot_key;
    crate::fi::wait_random();
    let sk_b: [u8; 8] = *slot_key;
    if sk_a != sk_b {
        return u64::MAX;
    }
    let r1 = scan_forward(&sk_a, OFFCHAIN_TYPE_USEROP_SIGS);
    crate::fi::wait_random();
    let r2 = scan_reverse(&sk_b, OFFCHAIN_TYPE_USEROP_SIGS);
    if r1 != r2 {
        return u64::MAX;
    }
    r1
}

/// Bump the durable UserOp-signature tally for `slot_key` to `new_count`
/// (MEDIUM-2). Mirrors `offchain_count_bump`: monotonic (`Err(())` when
/// `new_count <= current`), F-12 slot_key input-redundancy, and a
/// read-back + sentinel-gated re-check so a glitched write that did not
/// land is rejected. The caller (cmd_sign_userop / batch) computes
/// `new_count = current + 1`, so a return of `Err` means flash trouble.
///
/// # Safety
/// Programs page 123.
pub unsafe fn userop_sigs_bump(slot_key: &[u8; 8], new_count: u64) -> Result<(), ()> {
    // F-12: input redundancy on slot_key (see offchain_count_bump).
    let sk_a: [u8; 8] = *slot_key;
    crate::fi::wait_random();
    let sk_b: [u8; 8] = *slot_key;
    if sk_a != sk_b {
        return Err(());
    }
    let slot_key = &sk_a;

    let pre = userop_sigs_read(slot_key);
    if new_count <= pre {
        return Err(());
    }
    let qw = entry_qw(slot_key, OFFCHAIN_TYPE_USEROP_SIGS, new_count);
    // SAFETY: forwarded contract.
    unsafe { write_entry(&qw)? };
    let post = userop_sigs_read(slot_key);
    if post != new_count {
        return Err(());
    }
    if crate::fi::check_true_into_sentinel(|| userop_sigs_read(slot_key) == new_count)
        != crate::fi::OK_SENTINEL
    {
        return Err(());
    }
    Ok(())
}

```


### From `docs/secure-elements/se050-factory-reset.md`

# SE050 Factory Reset — Design and Production Checklist

> **OID range note (2026-04-30 audit).** The OID values shown throughout this doc
> (`0x7B06_xxxx`) are from the **v3 era** and have since been retired. The shipping
> range is **v6 = `0x7B10_xxxx`**:
>
> | Symbol             | This doc (v3)   | Shipping (v6)   |
> |--------------------|-----------------|-----------------|
> | `USERID_OBJ`       | `0x7B06_0000`   | `0x7B10_0000`   |
> | `ENTROPY_OBJ`      | `0x7B06_0001`   | `0x7B10_0001`   |
> | `VK_OBJ`           | `0x7B06_0002`   | `0x7B10_0002`   |
> | `BOOTSTRAP_VK_OBJ` | `0x7B06_0003`   | `0x7B10_0003`   |
> | `ADMIN_WIPE_OBJ`   | `0x7B06_00A0`   | `0x7B10_00A0`   |
> | Canary objs        | `0x7B06_00B0…`  | `0x7B10_00B0…`  |
>
> Authoritative constants: `secure/src/se050/mod.rs:53,56,59,62,83`. Range
> history (v1 → v2 → v3 `0x7B06_xxxx` → v4 `0x7B0C_xxxx` → v5 → v6) is
> documented at `secure/src/se050/mod.rs:23-30`.
>
> **Admin PIN derivation has also evolved.** Historical §2 text described a
> TRNG-generated admin PIN persisted to flash page 125. The current PIN is
> root-derived via `secure/src/hw/secret_keys.rs::se050_admin_pin()` on the
> BHK axis (DHUK fallback when `bhk` is disabled).
> Page 125 still hosts the wipe flag, but the admin PIN no longer needs flash
> persistence — it's deterministic per device and re-derives on every boot.
> §2a's "future optimisation — HUK-SAES derivation" has effectively landed.
>
> The two-entry TAG_POLICY design, the wipe flow, and the round-trip selftest
> remain in the current implementation. The old page-125 PIN storage described
> in the historical section below is retired.
>
> **Current first-field credential axes (2026-07-15).** Factory transport
> credentials are derived from the factory-burned per-device OTP master via
> the `transport_*` helpers. The implemented `rdp2-self-lock` candidate rotates
> SE050 SCP03 and admin credentials to final BHK-axis derivations, and rotates
> the OPTIGA E140 PBS to a final DHUK derivation bound to a fresh TRNG salt
> persisted in the page-127 journal. It is implementation evidence, not a
> production-approved ceremony. Authenticated per-unit handoff and
> authenticate-before-rotate, durable old/new/KVN recovery, the exact E140
> lifecycle-versus-final-rotation order, and silicon receipts remain gates.

## Why this document exists

The PQSigner wallet uses a hardware-enforced PIN on the NXP SE050 secure
element (UserID at `0x7B06_0000`, max 10 attempts before permanent
lockout). After lockout, firmware must be able to wipe every stored
secret so the user can restore from their 24-word BIP-39 backup on the
same physical device. This file explains how that wipe is structured,
why the obvious alternatives don't work, and what needs to change when
moving from dev boards to production silicon.

## What we tried that did NOT work

### Approach 1 — bare `DeleteAll` APDU via `RESERVED_ID_FACTORY_RESET`

NXP's SE05x spec defines a single-APDU nuclear wipe:
`CLA=0x80 INS=0x04 P1=0x00 P2=0x2A`. It wipes everything in one shot but
requires an authenticated session against
`kSE05x_AppletResID_FACTORY_RESET = 0x7FFF_0205`. On the
OM-SE050ARD-E dev shield (SE050E2HQ1/Z01Z3), **customer writes to
`0x7FFF_0205` are rejected with `SW=0x6985`** ("conditions not
satisfied"). The slot is reserved for NXP personalisation at the chip
factory, and we get no access to it on dev parts.

Evidence: no example in `plug-and-trust` anywhere creates
`0x7FFF_0205`. The SetPlatformSCPRequest API at
`hostlib/hostLib/se05x_03_xx_xx/se05x_APDU_apis.h:385` mentions it only
as an auth requirement, never as a create target.

### Approach 2 — iterative delete under plain PlatformSCP03 channel auth

This is what `Se05x_API_DeleteAll_Iterative` does (see
`plug-and-trust/hostlib/hostLib/se05x/src/se05x_mw.c:22-78`). For each
object returned by `ReadIDList`, it calls `DeleteSecureObject` over the
current SCP03 channel. It works only for objects whose policy either
permits deletion under the default channel OR has no restrictive per-object
auth gate.

**It fails on every object that has `auth_obj_id = <UserID>` in its
TAG_POLICY** — SE050 enforces the policy regardless of channel, and
channel-level SCP03 auth does NOT implicitly satisfy a policy entry with
`auth_obj_id = 0x7FFF_0207` (that reserved ID is only used for
SetPlatformSCPRequest, not as a universal "admin" marker). After the
user PIN gets locked out, the UserID can no longer authenticate anyone,
so `delete_object_authed` can't run either. Every UserID-gated object
becomes unreachable.

## Historical v3 flash-PIN design (retired)

The following section preserves the original rationale for the two-entry
policy and crash-resumable wipe. Its TRNG-generated page-125 admin-PIN storage
is historical and must not be read as the current credential lifecycle; the
current axes and first-field candidate are summarized above and in the
production checklist.

Every gated user object carries a **two-entry TAG_POLICY**:

| Entry | `auth_obj_id`          | `ar_header`                          | Purpose                         |
|-------|------------------------|--------------------------------------|---------------------------------|
| 1     | UserID `0x7B06_0000`   | READ \| WRITE \| DELETE \| REQUIRE_SM| Normal operation (PIN-gated)    |
| 2     | ADMIN `0x7B06_00A0`    | DELETE \| REQUIRE_SM                 | PIN-lockout wipe                |

`ADMIN_WIPE_OBJ = 0x7B06_00A0` is a secondary UserID provisioned at
first boot with a 16-byte PIN generated via the STM32 TRNG and
persisted to secure flash page 125 (`0x0C0F_A000`):

```
// In secure/src/hw/flash.rs page 125 layout:
//   QW 0 (offset  0..15): admin PIN (16 bytes from rng::fill())
//   QW 1 (offset 16..31): wipe flag (byte 0: 0x00 armed / 0xFF blank)
```

The admin PIN never leaves the TrustZone secure world. On first boot
`Se050::provision()` checks `is_admin_pin_blank()`; if true, generates
a fresh PIN via `rng::fill()` and writes it to QW 0. On subsequent
boots it reads the existing PIN. The full page is erased as the final
step of any factory reset, so PIN + flag are atomically cleared together.

This approach is deliberately independent of the OPTIGA Platform Binding
Secret — an earlier iteration derived the admin PIN from the PBS, which
broke SE050-standalone builds (no PBS) and couldn't work for users who
have the SE050 shield without an OPTIGA chip attached. The current
design works for every combination (SE050 alone, dual-SE, future
variants) because the admin state lives on the STM32 side, where
secure flash is guaranteed to exist.

### Admin-wipe policy construction (apdu.rs)

```
TAG_POLICY value (18 bytes for 2-entry):
  [0x08] [auth1:4 BE] [ar1:4 BE]   ← entry 1
  [0x08] [auth2:4 BE] [ar2:4 BE]   ← entry 2
```

Entries are OR'd: if ANY entry's `auth_obj_id` is satisfied by the
current session AND that entry's `ar_header` permits the requested
operation, the operation succeeds. The admin entry has **only
ALLOW_DELETE + REQUIRE_SM** — never ALLOW_READ. That preserves the
hardware-enforced PIN gating on entropy: the admin credential can wipe
the chip but cannot exfiltrate the seed.

### Wipe flow

```
PIN attempt #10 fails
  ↓
SE050 hardware locks UserID (SW=0x6983 on next CreateSession)
  ↓
firmware: read admin_pin from flash page 125 QW 0
          arm wipe flag at page 125 QW 1 (1→0 bit-clear)
  ↓
SE050 admin session:
  CreateSession(ADMIN_WIPE_OBJ)
  VerifySessionUserID(admin_pin)
  DeleteSecureObject_authed(ENTROPY_OBJ)
  DeleteSecureObject_authed(VK_OBJ)
  DeleteSecureObject_authed(BOOTSTRAP_VK_OBJ)
  DeleteSecureObject_authed(USERID_OBJ)       ← user UserID
  DeleteSecureObject_authed(ADMIN_WIPE_OBJ)   ← self-delete
  CloseSession
  ↓
best-effort unauthenticated sweep (iterative_delete_all) for legacy stragglers
  ↓
erase_admin_page()  ← clears the wipe marker / legacy admin area
(dual-SE orchestrator also wipes OPTIGA user objects; page 126 is untouched)
  ↓
zeroize all SRAM state
  ↓
return PinLocked → NS side reboots into first-boot wizard
```

### Crash safety

The wipe flag at `ADMIN_PAGE_ADDR + 16` is armed via a 1→0 bit-clear
(NOR flash allows this without pre-erase, so the admin PIN at QW 0 is
preserved and the wipe routine can still authenticate). If power is
cut mid-wipe, the flag remains set on reboot. The boot path in
`secure/src/main.rs` checks `is_wipe_armed()` before any unlock attempt
and calls `factory_reset_admin()` again (idempotent — duplicate deletes
are harmless, the SCP03 session is re-established from scratch). The
flag is only cleared by the final `erase_admin_page()` call, which runs
after SE050 wipe is verified clean.

### Round-trip self-test during first-boot

`policy_roundtrip_selftest` writes a canary UserID + gated data object
to `0x7B06_00B0/B1` with the same two-entry policy template, then
exercises the admin-delete path end-to-end. If the canary survives, the
TLV byte layout is broken (has happened before — see git history for
the garbled-policy orphans at `0x7B00_xxxx`). First-boot provisioning
aborts with a fatal panic rather than shipping a wallet that cannot
recover from PIN lockout.

This is the guardrail that prevents a future refactor from
re-introducing the unwipeable-orphan problem.

## Production checklist

### 1. PlatformSCP03 keys

Published NXP keys are historical bring-up credentials, not the candidate
factory handoff. The candidate factory transport keyset comes from the
factory-burned per-device OTP master through
`transport_se050_scp03_{enc,mac,dek}()`; those labels are disjoint from every
final credential label. The final `se050_scp03_{enc,mac,dek}_key()` helpers
derive on the BHK axis (DHUK fallback only in builds without `bhk`).

The journaled `rdp2-self-lock` candidate implements the transport-to-final
rotation, but does not approve it for production. The separate
`se050-rotate-scp03` halt path remains sacrificial validation evidence, not the
field protocol. Production remains blocked on authenticated per-unit handoff
and authenticate-before-rotate, durable old/new/KVN recovery and atomicity,
the exact OPTIGA E140 lifecycle-versus-final-rotation order, and silicon
receipts. This document does not authorize `PUT KEY` on a real unit.

### 2. Lifecycle of ADMIN_WIPE_OBJ PIN

The admin PIN is reproducibly derived by
`hw::secret_keys::se050_admin_pin()` on the BHK axis and has no flash
representation. Page 125 carries the non-secret wipe marker/legacy hygiene
area; `erase_admin_page()` clears that marker but does not rotate the derived
credential. Re-pairing requires the reviewed BHK/root lifecycle, not a flash
PIN rewrite.

The factory transport admin PIN is a distinct OTP-master-derived credential
from `transport_se050_admin_pin()`. The production contract requires the
transport state to authenticate before it can be replaced with the final
BHK-axis admin PIN; that authenticate-before-rotate evidence and the
old/new/KVN recovery contract remain production gates.

### 2a. Transport-to-final admin rotation — implemented candidate

The final admin credential uses the BHK/DHUK SAES KDF with domain tag
`"pqsigner/se050-admin-pin-v1"`; in the intended `bhk` build this is the BHK
axis. The final root never leaves silicon, and only the derived credential is
presented inside the secure channel. The factory transport credential instead
uses the per-device OTP master and the disjoint
`"pqsigner/transport/se050-admin-pin-v1"` label. The candidate code performs
that replacement, but production approval still depends on the handoff,
authenticate-before-rotate, durable recovery, ordering, and silicon gates
listed above.

### 3. Attestation-based device pairing (not yet implemented)

Today we trust any SE050 that presents a valid SCP03 handshake. A
production build should also verify the SE050 certificate chain against
a pinned NXP root CA + a pinned per-device UID, to defend against
chip-swap attacks. This is orthogonal to factory reset but sits in the
same boot-time init path — bundle them.

### 4. UI for lockout warnings

`secure/src/nsc/cmd_request_unlock.rs` now shows "LAST ATTEMPT — wallet
wipes on fail" on the 9th consecutive wrong PIN. For production, also
show an educational screen during the wipe itself ("Wiping — do not
power off") and a post-wipe screen telling the user their wallet can be
restored from the 24-word backup (wallet address, bootstrap pubkey hash,
and on-chain state are all unchanged after restore).

### 5. Dev chips vs production chips

Do NOT reuse dev chips across firmware generations without a fresh
provision. Our earlier dev chip accumulated 6 unwipeable orphans at
`0x7B00_xxxx` / `0x7B06_0000` because older firmware created objects
without the admin-delete policy entry. Those objects remain stuck
forever on that specific chip — only a fresh OM-SE050ARD-E (or a real
production part) is clean.

For ongoing dev work on such a polluted chip, migrate the production
OID range (`0x7B06_xxxx` → `0x7B08_xxxx` or similar) to avoid slot
collisions. This is a separate one-time change; the admin-wipe design
itself does not depend on the OID range.

## What NOT to do

- **Do NOT remove the admin-delete policy entry.** Every object the
  firmware creates on SE050 must have two TAG_POLICY entries. Objects
  without entry 2 cannot be recovered from PIN lockout and are
  orphans-by-design.
- **Do NOT change the admin-PIN domain/root without a coordinated SE050
  reprovisioning ceremony.** Page 125 does not carry the PIN; erasing it only
  clears wipe/legacy state and cannot rotate the root-derived credential.
- **Do NOT skip the round-trip selftest.** It's the cheap insurance
  against re-introducing garbled-policy orphans on future builds.
- **Do NOT reuse the ADMIN_WIPE_OBJ PIN for user-facing operations.**
  The admin credential exists only to satisfy admin-delete policies;
  its ar_header grants only DELETE, never READ.
- **Do NOT try to provision `0x7FFF_0205` on dev chips.** Wastes time,
  always returns `SW=0x6985`. The FACTORY_RESET credential is
  NXP-controlled.
- **Do NOT run the wipe path without arming the flag first.** A power
  loss mid-wipe leaves the chip in a half-wiped state with no recovery
  signal. The flag is cheap and idempotent; always arm it first.
- **Do NOT bypass the admin-credential install during first-boot.**
  `Se050::provision()` runs `provision_admin` + `policy_roundtrip_selftest`
  automatically on any `stm32u585` target with SE050 — don't "optimise"
  it out. Skipping it ships a wallet that cannot recover from PIN lockout.

## File map

| Concern                       | File                                                       |
|-------------------------------|------------------------------------------------------------|
| TAG_POLICY byte layout        | `secure/src/se050/apdu.rs` (`build_policy`)                |
| UserID + data-obj creation    | `secure/src/se050/apdu.rs` (`write_userid`, `write_binary_gated`) |
| Admin credential provisioning | `secure/src/se050/mod.rs` (`provision_admin`, `store_objects`) — runs automatically inside `WalletStore::provision` on stm32u585 |
| Admin-delete wipe             | `secure/src/se050/mod.rs` (`admin_factory_reset`)          |
| Round-trip selftest           | `secure/src/se050/mod.rs` (`policy_roundtrip_selftest`)    |
| Admin credential + wipe flag  | `secure/src/hw/secret_keys.rs` (`se050_admin_pin`); page 125 retains only wipe-marker/legacy hygiene state (`erase_admin_page`, `arm_wipe_flag`, `is_wipe_armed`) |
| SE050 wipe entry point        | `secure/src/se050/mod.rs` `WalletStore::factory_reset_admin` |
| Dual-SE wipe orchestration    | `secure/src/dual_se.rs` `WalletStore::factory_reset_admin` (best-effort wipes OPTIGA + SE050; never erases page 126) |
| PIN-lockout trigger           | `secure/src/nsc/cmd_request_unlock.rs` (`trigger_lockout_wipe`) |
| Boot-time resume              | `secure/src/main.rs` (block after `load_pbs`)              |
| Flash layout (linker)         | `secure/memory-stm32u585.x` (`FLASH LENGTH = 1000K`, reserves pages 125-127) |

## References

- NXP UM11225 — SE050 User Manual (TAG_POLICY structure, ar_header bits)
- NXP `plug-and-trust/sss/ex/src/ex_sss_boot.c:94-114` — official factory reset is `DeleteAll_Iterative`, not bare `DeleteAll`
- NXP `plug-and-trust/hostlib/hostLib/se05x/src/se05x_mw.c:22-78` — iterative delete implementation, skips reserved ranges only
- NXP `plug-and-trust/hostlib/hostLib/inc/se05x_const.h:141-176` — `POLICY_OBJ_ALLOW_*` bit values
- PQSigner CLAUDE.md — invariants #1 (dual-chip split), #2 (hardware PIN gating), #3 (E2E encrypted tunnel), #4 (secrets in TrustZone only)


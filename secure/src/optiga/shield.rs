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
/// Records of headroom `OptigaTrustM::ensure_shield` keeps before a handshake
/// nonce could be reused (see [`handshake_nonce_reachable`]). It renegotiates
/// at the start of an operation, never inside one, so this must exceed the
/// records any single operation sends after its one `ensure_shield` call.
pub(crate) const HANDSHAKE_NONCE_HEADROOM: u32 = 64;

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
    /// Sequence MasterFinished was sent under (`enc_key`): the chip's
    /// `slave_seq`. A host record with this sequence would reuse its nonce.
    enc_handshake_seq: u32,
    /// Sequence SlaveFinished was sent under (`dec_key`): the chip's
    /// `master_seq`. A chip response with this sequence would reuse its nonce.
    dec_handshake_seq: u32,
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

/// Could the next record, or the chip's reply to it, come within `headroom`
/// records of reusing a handshake (key, nonce) pair?
///
/// Both sequence numbers come from the chip (audit F-1, DVT row 6.3; EVT
/// silicon returned unequal values in 2/2 handshakes). Infineon's reference
/// PRL, which ours follows, sends MasterFinished under the host key with nonce
/// `slave_seq` and then numbers host records from `master_seq + 1`; the chip
/// sends SlaveFinished under its key with nonce `master_seq` and numbers its
/// responses from `slave_seq + 1`. So when `slave_seq > master_seq` the host
/// record numbered `slave_seq` reuses MasterFinished's nonce, and when
/// `master_seq > slave_seq` the chip response numbered `master_seq` reuses
/// SlaveFinished's. The plaintext of both Finished messages is public, so a
/// reused nonce hands a bus tap that record's plaintext. Neither number can be
/// moved (the chip accepts records only 1..=3 ahead), so the defence is to
/// renegotiate before either counter can get there.
///
/// `next_tx` is the sequence the next host record uses; `last_rx` the last
/// authenticated chip sequence, whose next reply carries `last_rx + 1 ..=
/// last_rx + PRL_MAX_FORWARD_DELTA`. A handshake value already passed is
/// harmless: counters only increase.
pub(crate) const fn handshake_nonce_reachable(
    next_tx: u32,
    last_rx: u32,
    tx_handshake: u32,
    rx_handshake: u32,
    headroom: u32,
) -> bool {
    let tx = tx_handshake >= next_tx && tx_handshake - next_tx <= headroom;
    let rx = rx_handshake > last_rx
        && rx_handshake - last_rx <= PRL_MAX_FORWARD_DELTA.saturating_add(headroom);
    tx || rx
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
            enc_handshake_seq: 0,
            dec_handshake_seq: 0,
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
        self.enc_handshake_seq = 0;
        self.dec_handshake_seq = 0;
        self.active = false;
    }

    /// True when the session is within [`HANDSHAKE_NONCE_HEADROOM`] records
    /// of reusing a handshake nonce, so the caller should renegotiate before
    /// starting another operation (`OptigaTrustM::ensure_shield`).
    pub fn renegotiation_due(&self) -> bool {
        self.active
            && handshake_nonce_reachable(
                self.enc_seq,
                self.dec_seq,
                self.enc_handshake_seq,
                self.dec_handshake_seq,
                HANDSHAKE_NONCE_HEADROOM,
            )
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
        self.enc_handshake_seq = next_master_sequence.wrapping_sub(1);
        self.dec_handshake_seq = last_slave_sequence;
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

    /// `(enc_seq, dec_seq, enc_handshake_seq, dec_handshake_seq)` for the
    /// `rng-xor-probe` renegotiation soak (DVT 6.3). Bench only.
    #[cfg(feature = "rng-xor-probe")]
    pub(crate) fn sequence_snapshot(&self) -> (u32, u32, u32, u32) {
        (self.enc_seq, self.dec_seq, self.enc_handshake_seq, self.dec_handshake_seq)
    }

    /// Set the sequences the handshake Finished messages used, as `establish`
    /// does from the chip's `slave_seq` / `master_seq`. Host tests only.
    #[cfg(test)]
    pub(crate) fn set_handshake_sequences_for_test(&mut self, slave_seq: u32, master_seq: u32) {
        self.enc_handshake_seq = slave_seq;
        self.dec_handshake_seq = master_seq;
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
        self.enc_handshake_seq = 0;
        self.dec_handshake_seq = 0;

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

        // Audit F-1: never send a record whose sequence, or whose reply's
        // sequence window, reaches a nonce a handshake Finished message
        // already used under the same key. `ensure_shield` renegotiates well
        // before this; this is the exact backstop. Closing forces a fresh
        // handshake, as the threshold check above does.
        let handshake_nonce_hit = || {
            // SAFETY: plain reads of this session's own fields.
            let (tx, rx, tx_hs, rx_hs) = unsafe {
                (
                    core::ptr::read_volatile(&self.enc_seq),
                    core::ptr::read_volatile(&self.dec_seq),
                    core::ptr::read_volatile(&self.enc_handshake_seq),
                    core::ptr::read_volatile(&self.dec_handshake_seq),
                )
            };
            handshake_nonce_reachable(tx, rx, tx_hs, rx_hs, 0)
        };
        if handshake_nonce_hit() {
            self.active = false;
            return Err(ShieldError::NotActive);
        }
        crate::fi::wait_random();
        if handshake_nonce_hit() {
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

        // Audit F-1: a response numbered like SlaveFinished reuses its nonce.
        // `wrap_command` never solicits one; refuse it if it arrives anyway.
        if seq == self.dec_handshake_seq {
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
        // Remember which sequences the two Finished messages burned, so no
        // later record can reuse their (key, nonce) pairs (audit F-1).
        self.enc_handshake_seq = slave_seq;
        self.dec_handshake_seq = master_seq;
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

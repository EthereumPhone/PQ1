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
const SCTR_ALERT: u8 = 0x40;

/// Protocol version for pre-shared-secret mode.
const PROTOCOL_VERSION: u8 = 0x01;

/// TLS PRF label for Platform Binding key derivation.
const PRF_LABEL: &[u8] = b"Platform Binding";

/// Session key material length: 2×16 (keys) + 2×4 (nonces) = 40 bytes.
const SESSION_KEY_LEN: usize = 40;

/// Master random length.
const RANDOM_LEN: usize = 32;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum ShieldError {
    NotActive,
    HandshakeFailed,
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
    /// Decryption message sequence counter.
    dec_seq: u32,
    /// Whether the shielded connection is active.
    pub active: bool,
    /// Platform Binding Secret. 64 bytes per OPTIGA Trust M SRM §
    /// "Platform Binding Secret" ("It shall be 64 bytes …") — derived
    /// on demand from the OTP master via `hw::secret_keys::optiga_
    /// pairing_secret`.
    pbs: [u8; 64],
    /// Whether PBS has been loaded.
    pub pbs_loaded: bool,
}

impl ShieldedConnection {
    pub const fn new() -> Self {
        Self {
            enc_key: [0; 16],
            dec_key: [0; 16],
            enc_nonce_base: [0; 4],
            dec_nonce_base: [0; 4],
            enc_seq: 0,
            dec_seq: 0,
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
        self.dec_seq = 0;

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

        // HIGH-9 fix: Infineon specifies a renegotiation threshold
        // at `enc_seq >= 0xFFFFFFF0`. Beyond that the AEAD nonce
        // (nonce_base || seq) would wrap and repeat — CCM keystream
        // would be recovered. Force the connection closed so the
        // caller triggers a fresh handshake.
        if self.enc_seq >= 0xFFFF_FFF0 {
            self.active = false;
            return Err(ShieldError::NotActive);
        }

        let out_len = SC_HEADER_LEN + plaintext.len() + CCM_TAG_LEN;
        if out_len > out.len() {
            return Err(ShieldError::BufferOverflow);
        }

        // Header: SCTR + SeqNum
        out[0] = SCTR_RECORD_FULL;
        out[1] = (self.enc_seq >> 24) as u8;
        out[2] = (self.enc_seq >> 16) as u8;
        out[3] = (self.enc_seq >> 8) as u8;
        out[4] = self.enc_seq as u8;

        // Build nonce and AAD
        let nonce = Self::build_nonce(&self.enc_nonce_base, self.enc_seq);
        let aad = Self::build_aad(SCTR_RECORD_FULL, self.enc_seq, plaintext.len() as u16);

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

        self.enc_seq += 1;
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
    ) -> Result<usize, ShieldError> {
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

        // HIGH-10 fix: refuse replays. A MITM that captures a valid
        // response frame could otherwise inject it again at a later
        // point and short-circuit a fresh command. We expect each
        // response to bump dec_seq by exactly 1; anything with a
        // lower-or-equal seq is either a replay or a bug.
        if seq < self.dec_seq {
            return Err(ShieldError::DecryptFailed);
        }
        // Threshold enforcement (symmetric with enc_seq).
        if seq >= 0xFFFF_FFF0 {
            self.active = false;
            return Err(ShieldError::NotActive);
        }

        let ct_and_tag = &input[SC_HEADER_LEN..];
        let plaintext_len = ct_and_tag.len() - CCM_TAG_LEN;

        if plaintext_len > out.len() {
            return Err(ShieldError::BufferOverflow);
        }

        let nonce = Self::build_nonce(&self.dec_nonce_base, seq);
        let aad = Self::build_aad(SCTR_RECORD_FULL, seq, plaintext_len as u16);

        let ok = aes128_ccm_decrypt(
            &self.dec_key,
            &nonce,
            &aad,
            ct_and_tag,
            out,
        );

        if !ok {
            return Err(ShieldError::DecryptFailed);
        }

        self.dec_seq = seq.saturating_add(1);
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
                return Err(ShieldError::HandshakeFailed);
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
        if n < SLAVE_HELLO_LEN {
            secure_log!(
                "[OPTIGA/shield] SlaveHello too short ({} < {}), bytes=[{:02x}{:02x}{:02x}{:02x}...]",
                n, SLAVE_HELLO_LEN, resp[0], resp[1], resp[2], resp[3]
            );
            return Err(ShieldError::HandshakeFailed);
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
            .map_err(|_| ShieldError::HandshakeFailed)?;
        secure_log!(
            "[OPTIGA/shield] MasterFinished response n={}, SCTR={:02x}",
            n2, resp2[0]
        );

        // Step 5: Verify SlaveFinished.
        // Format: SCTR(0x08) | master_seq(4 BE) | ct(36) | MAC(8) = 49 B.
        // See `ifx_i2c_presentation_layer.c:559-607`.
        if n2 < SC_HEADER_LEN + CCM_TAG_LEN {
            return Err(ShieldError::HandshakeFailed);
        }
        if resp2[0] != SCTR_HANDSHAKE_FINISHED {
            secure_log!("[OPTIGA/shield] SlaveFinished SCTR unexpected: {:02x}", resp2[0]);
            return Err(ShieldError::HandshakeFailed);
        }
        let master_seq = u32::from_be_bytes([resp2[1], resp2[2], resp2[3], resp2[4]]);
        secure_log!("[OPTIGA/shield] master_seq={:#010x}", master_seq);

        let dec_nonce = Self::build_nonce(&self.dec_nonce_base, master_seq);
        let slave_ct = &resp2[SC_HEADER_LEN..n2];
        let slave_pt_len = slave_ct.len() - CCM_TAG_LEN;
        let dec_aad = Self::build_aad(SCTR_HANDSHAKE_FINISHED, master_seq, slave_pt_len as u16);

        let mut slave_plain = [0u8; 64];
        let ok = aes128_ccm_decrypt(
            &self.dec_key,
            &dec_nonce,
            &dec_aad,
            slave_ct,
            &mut slave_plain,
        );
        if !ok {
            secure_log!("[OPTIGA/shield] SlaveFinished decrypt FAILED");
            return Err(ShieldError::HandshakeFailed);
        }

        // Plaintext of SlaveFinished must be `random_S (32) || master_seq (4 BE)`.
        if slave_pt_len < 36 {
            return Err(ShieldError::HandshakeFailed);
        }
        let mut diff: u8 = 0;
        for i in 0..RANDOM_LEN {
            diff |= slave_plain[i] ^ random_s[i];
        }
        if diff != 0 {
            secure_log!("[OPTIGA/shield] SlaveFinished random_S mismatch");
            return Err(ShieldError::HandshakeFailed);
        }
        let echoed_master_seq = u32::from_be_bytes([
            slave_plain[32], slave_plain[33], slave_plain[34], slave_plain[35],
        ]);
        if echoed_master_seq != master_seq {
            secure_log!("[OPTIGA/shield] SlaveFinished master_seq mismatch");
            return Err(ShieldError::HandshakeFailed);
        }

        // Session established. Subsequent protected records use the
        // master_sequence_number counter (bumped before each send), and
        // the slave's responses carry their own slave_sequence_number we
        // extract on the fly in `unwrap_response`. We initialise enc_seq
        // = master_seq + 1 so the first `wrap_command` sends that value
        // (we use-then-increment). dec_seq=0 lets any seq ≥ 0 through;
        // the chip's slave_sequence_number monotonicity is what we rely
        // on for replay protection.
        self.enc_seq = master_seq.saturating_add(1);
        self.dec_seq = 0;
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

/// AES-128-CCM decrypt. Returns `true` if tag verification succeeds.
/// Writes plaintext to `out[..ct_and_tag.len() - CCM_TAG_LEN]`.
fn aes128_ccm_decrypt(
    key: &[u8; 16],
    nonce: &[u8; CCM_NONCE_LEN],
    aad: &[u8],
    ct_and_tag: &[u8],
    out: &mut [u8],
) -> bool {
    if ct_and_tag.len() < CCM_TAG_LEN {
        return false;
    }

    let ct_len = ct_and_tag.len() - CCM_TAG_LEN;
    let ciphertext = &ct_and_tag[..ct_len];
    let received_enc_tag = &ct_and_tag[ct_len..];

    let cipher = Aes128::new(key.into());

    // CTR decrypt: A_0 for tag, A_1.. for data
    let mut a_block = [0u8; AES_BLOCK];
    a_block[0] = 6; // q - 1
    a_block[1..1 + CCM_NONCE_LEN].copy_from_slice(nonce);

    // Decrypt tag with A_0
    set_counter(&mut a_block, 0);
    let mut s0 = a_block;
    let s0_block = aes::Block::from_mut_slice(&mut s0);
    cipher.encrypt_block(s0_block);
    let mut received_tag = [0u8; CCM_TAG_LEN];
    for i in 0..CCM_TAG_LEN {
        received_tag[i] = received_enc_tag[i] ^ s0[i];
    }

    // Decrypt ciphertext with A_1, A_2, ...
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

    // Recompute CBC-MAC over decrypted plaintext
    let expected_tag = ccm_cbc_mac(&cipher, nonce, aad, &out[..ct_len]);

    // Constant-time tag comparison
    let mut diff: u8 = 0;
    for i in 0..CCM_TAG_LEN {
        diff |= received_tag[i] ^ expected_tag[i];
    }
    diff == 0
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

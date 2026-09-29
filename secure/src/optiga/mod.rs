//! Infineon OPTIGA Trust M V3 secure element driver.
//!
//! Stores one half of the XOR-split BIP-39 entropy, protected by a
//! hardware-enforced PIN via the OPTIGA authorization-reference mechanism.
//!
//! Communication: I2C1 (PB8/PB9, shared with SE050) → IFX I2C protocol
//! (4-layer stack) → Shielded Connection (AES-128-CCM-8 with TLS-PRF-
//! derived session keys).
//!
//! # PIN scheme — HMAC challenge-response
//!
//! OPTIGA Trust M doesn't have a dedicated "verify PIN" opcode. Instead,
//! PIN gating uses the generic authorization-reference (Auto-Ref)
//! mechanism:
//!
//! 1. During provisioning we write the PIN-derived HMAC secret into the
//!    auth-ref OID (0xF1D0) and mark it with data type 0x31 (AUTHREF) and
//!    `Read = Never`. Under `optiga-hw-counter`, `Execute = LUC(E120)`;
//!    `Change = Auto(F1D0)` only in the `optiga-lock-operational` candidate
//!    profile and remains `Always` on the re-provisionable bench profile.
//!    The legacy non-hardware-counter path uses `Execute = Always` and is not
//!    production-eligible.
//! 2. During unlock:
//!    a. `GetRandom` — the chip returns a 32-byte challenge from its TRNG.
//!    b. Host computes `HMAC-SHA256(pin_secret, challenge)`.
//!    c. `DecryptSym` in HMAC-verify mode — the chip recomputes the HMAC
//!       using the stored secret and constant-time-compares. The firmware
//!       never sees the comparison result except as success/failure.
//! 3. On success, the session at 0xE100 is marked as having "verified"
//!    0xF1D0, and subsequent reads of user OIDs gated by `Auto(0xF1D0)`
//!    succeed within that session.
//!
//! # Admin recovery path
//!
//! The data OIDs at F1D1..F1D4 use `Change = Auto(F1D0) OR Conf(E140)`.
//! The PIN path unlocks normal operation; the `Conf` path lets the shielded
//! connection overwrite those data objects during factory reset, even when
//! the user has forgotten their PIN. F1D0 and the provisioning marker have
//! separate policies.
//!
//! Attempt limiting is feature-dependent. `optiga-hw-counter` uses the E120
//! silicon LUC as the lockout authority; the legacy non-production path uses
//! the firmware-managed counter at F1E1. In the hardware-counter profile F1E1
//! remains the boot-readable provisioning/reset sentinel, not lockout
//! authority. Production builds require `optiga-hw-counter`; the final
//! metadata/lifecycle ceremony and silicon receipts remain open.

pub mod i2c;
pub mod ifx_i2c;
pub mod apdu;
pub mod shield;
#[cfg(feature = "optiga-reset-oids")]
pub mod reset;
#[cfg(feature = "stm32u585")]
pub mod reset_pin;

use apdu::OptigaError;
use ifx_i2c::IfxState;
use shield::ShieldedConnection;
use zeroize::Zeroize;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum PIN attempts before lockout — shared with the rest of the wallet.
const MAX_ATTEMPTS: u8 = sphincs_tz_shared::MAX_ATTEMPTS;

/// Domain tag for deriving the PIN authorization secret.
const PIN_AUTH_DOMAIN: &[u8] = b"optiga-pin-auth-v1";

/// Counter sentinel written by `factory_reset()` so `is_provisioned()` can
/// distinguish a wiped chip from an in-use one after LcsO has been locked.
const RESET_SENTINEL: u8 = 0xFF;

// ---------------------------------------------------------------------------
// OptigaTrustM driver
// ---------------------------------------------------------------------------

/// OPTIGA Trust M secure element driver.
///
/// Caches the encrypted entropy blob, VK, and bootstrap VK in struct fields
/// after provisioning or unlock, so signing operations don't require
/// re-authenticating against the hardware.
pub struct OptigaTrustM {
    ifx: IfxState,
    shield: ShieldedConnection,
    ready: bool,
    entropy_blob_cache: [u8; crate::crypto::ENTROPY_BLOB_LEN],
    blob_cached: crate::fih::FihBool,
    vk_cache: [u8; 32],
    vk_cached: bool,
    bootstrap_vk_cache: [u8; 32],
    bootstrap_vk_cached: bool,
    remaining: u8,
}

impl OptigaTrustM {
    pub const fn new() -> Self {
        Self {
            ifx: IfxState::new(),
            shield: ShieldedConnection::new(),
            ready: false,
            entropy_blob_cache: [0; crate::crypto::ENTROPY_BLOB_LEN],
            blob_cached: crate::fih::FihBool::new_false(),
            vk_cache: [0; 32],
            vk_cached: false,
            bootstrap_vk_cache: [0; 32],
            bootstrap_vk_cached: false,
            remaining: MAX_ATTEMPTS,
        }
    }

    /// Initialize the OPTIGA Trust M: soft reset + OpenApplication.
    ///
    /// Called lazily on first use. Subsequent calls are no-ops.
    pub fn init(&mut self) -> Result<(), OptigaError> {
        if self.ready {
            return Ok(());
        }

        unsafe {
            // Pulse RST (PE0 = Arduino D6 on this board) low→high at
            // the top of init. At POR the STM32's PE0 is a floating
            // input; holding the line merely HIGH does not wake the
            // chip from a latched/locked state left over from a prior
            // session (observed on 2026-04-23 during dual-SE bring-up
            // — LA showed RST cleanly HIGH for 20 s, yet the chip
            // never ACK'd on I²C; a proper LOW→HIGH pulse is the only
            // thing that forces a fresh chip boot). `pin_diag::run`
            // is used instead of `reset_pin::hard_pulse` because the
            // former's longer "enable GPIOA/D/E clocks + two decoy
            // pulses + 50 ms priming" sequence is what empirically
            // produces a visible edge on this silicon / call-stack
            // (documented in `pin_diag.rs` module-level doc).
            //
            // BOARD-SPLIT (2026-08-31). That reasoning is iota2's, and so are
            // the pins: `pin_diag::run` hardcodes PA4/PD5/PE0 and never reads
            // `board::OPTIGA_RST`. On pq1 it would pulse PE0 (unbonded on the
            // 48-pin package), never touch the real reset (PA15), and drive
            // PA4 — which is the trusted display's `LCD_CS` there — under a
            // comment calling it "disconnected, harmless". So iota2 keeps the
            // empirically-validated sequence unchanged, and pq1 gets the
            // board-aware pulse, which is that same sequence minus the two
            // decoy pulses that only make sense on the dev board.
            #[cfg(all(feature = "stm32u585", not(feature = "board-pq1")))]
            crate::pin_diag::run();
            #[cfg(all(feature = "stm32u585", feature = "board-pq1"))]
            reset_pin::hard_pulse();

            // Post-reset settle: datasheet v3.70 Tables 13/14 require the
            // host to wait tSTARTUP ≥ 15 ms after power-on or the RST
            // rising edge, extended to 20 ms max when NVM programming was
            // pending before the reset. 8 M cycles is ≥ 50 ms wall-clock —
            // comfortable margin, and the probe retry loop below covers
            // anything slower.
            //
            // Use `cortex_m::asm::delay(N)` instead of a hand-rolled NOP
            // loop. LTO is legally allowed to drop the loop counter around
            // a `for _ in 0..N { nop() }` body (nop has no observable
            // side effect per the Rust abstract machine) and leave an
            // infinite `bl nop; b back` behind. `delay()` is implemented
            // with a volatile counter so it always runs the full count.
            cortex_m::asm::delay(8_000_000);

            // Retry with SHORT delays. The chip goes into sleep mode and
            // NACKs until woken by I2C address detection — each probe wakes
            // it, but if we wait too long between probes it may re-sleep.
            // Docs specify 500 µs retry interval (~80k cycles at 160 MHz).
            // Loop up to 2000 times = ~1 second total — covers sleep + the
            // tail of a cold boot.
            let mut acked = false;
            let mut ack_attempt = 0u32;
            for attempt in 0..2000u32 {
                if i2c::probe().is_ok() || i2c::probe_with_reg().is_ok() {
                    acked = true;
                    ack_attempt = attempt;
                    break;
                }
                cortex_m::asm::delay(80_000);
            }

            if !acked {
                secure_log!("[OPTIGA] Init: chip did not ACK after 2000 retries / ~1 s");
                i2c::scan();
                return Err(OptigaError::I2c);
            }
            secure_log!("[OPTIGA] Init: chip ACK'd at 0x30 after {} retries", ack_attempt);

            secure_log!("[OPTIGA] Init: soft reset...");
            if let Err(e) = self.ifx.soft_reset() {
                secure_log!("[OPTIGA] Init: soft_reset FAILED: {:?}", e);
                return Err(OptigaError::Transport);
            }

            secure_log!("[OPTIGA] Init: OpenApplication...");
            if let Err(e) = apdu::open_application(&mut self.ifx) {
                secure_log!("[OPTIGA] Init: OpenApplication FAILED: {:?}", e);
                return Err(e);
            }

            secure_log!("[OPTIGA] Init complete");
        }

        self.ready = true;
        Ok(())
    }

    /// Pulse the board's OPTIGA RST line low and re-run OpenApplication.
    ///
    /// The pin is iota2's PE0 (Arduino D6) or pq1's PA15 (`SE_RST`) — see the
    /// BOARD-SPLIT note on the pulse call below.
    ///
    /// Needed as a workaround for the 2-writes-per-session throttle on
    /// this specific OPTIGA Trust M dev board: after the chip accepts
    /// two consecutive SetData-family APDUs, all subsequent data APDUs
    /// either time out or return `Status=0xFF`. A real silicon reset
    /// via RST clears the throttle. NV OIDs survive; volatile state
    /// (strict locks, per-session counters) resets.
    #[cfg(feature = "stm32u585")]
    fn hard_reset_and_reinit(&mut self) -> Result<(), OptigaError> {
        secure_log!("[OPTIGA] hard-pulsing RST to clear session throttle");
        // Uses `pin_diag::run` instead of the cleaner `reset_pin::init +
        // hard_pulse` pair: an identical-looking implementation in
        // reset_pin.rs produces no visible edge on the logic analyzer when
        // called from this context — the pin_diag path (which additionally
        // enables GPIOA/GPIOD clocks and runs a priming delay) works
        // reliably. Root-caused to a silicon/timing quirk we haven't
        // fully isolated yet; documented in reset_pin.rs.
        //
        // BOARD-SPLIT (2026-08-31). The sentence that used to end this
        // paragraph — "the extra toggles of the disconnected candidate pins
        // (PA4/PD5/PE0) are harmless because those pins aren't wired to
        // anything" — is an iota2 statement, and this function runs at
        // RUNTIME (clearing the write throttle mid-session), not just at
        // boot. On pq1 PA4 is `LCD_CS`, the trusted display's chip-select,
        // and PE0 is not bonded at all, so on that board the "harmless"
        // decoys would strobe the display's CS during a signing session
        // while the real reset (PA15) went untouched.
        //
        // iota2 therefore keeps the empirically-validated path unchanged;
        // pq1 gets the board-aware pulse. CAVEAT, stated because the comment
        // above is a warning about exactly this: the reset_pin path is the
        // one that "produces no visible edge ... from this context" on iota2.
        // Whether that quirk reproduces on pq1 silicon is UNTESTED — the
        // throttle workaround has never run on that board. If pq1 shows the
        // 2-writes-per-session throttle failing to clear, this is the first
        // place to scope.
        #[cfg(not(feature = "board-pq1"))]
        crate::pin_diag::run();
        #[cfg(feature = "board-pq1")]
        // SAFETY: secure-world boot/session path, single-threaded; touches
        // only the RST pin's bits in its own port.
        unsafe {
            reset_pin::hard_pulse()
        };
        self.ifx = ifx_i2c::IfxState::new();
        self.ready = false;
        // An RST pulse wipes the chip's PRL session. Reflect that on the
        // host side so the next `ensure_shield()` runs a fresh handshake
        // — leaving `shield.active=true` would have us sending records
        // encrypted with keys the chip has discarded, and every APDU
        // would bounce with an integrity-violated alert. `pbs_loaded`
        // stays intact so the handshake can re-derive session keys.
        self.shield.active = false;
        self.init()
    }

    /// Draw `buf.len()` bytes from the OPTIGA Trust M hardware TRNG
    /// over the Shielded Connection. The bytes are NOT intended to be
    /// used in isolation — `hw::rng_strong` XOR-mixes this stream with
    /// the STM32 TRNG (and the SE050 TRNG in dual-SE builds) so a
    /// single broken or biased source cannot dictate the output.
    ///
    /// OPTIGA `GetRandom` accepts 8 ≤ size ≤ 256. For requests below 8
    /// bytes we pull 8 and truncate.
    pub fn random(&mut self, buf: &mut [u8]) -> Result<(), OptigaError> {
        if buf.is_empty() {
            return Ok(());
        }
        // CRIT-8: the chip-TRNG contribution must traverse the Shielded
        // Connection — a plaintext GetRandom lets an I2C MITM substitute
        // a fixed "random". `ensure_shield` is also what makes the call
        // work at all against a paired chip: once host/chip PRL state
        // diverges (chip dropped its session, or sits wedged in the
        // SCTR=0x40 alert state from an earlier failed handshake), every
        // mismatched exchange bounces with the 7-byte `08 40` alert —
        // observed on silicon 2026-06-12 in both directions (first-boot
        // wizard + the first post-NS-boot NSC rng call).
        //
        // Self-heal (one bounded retry): on any failure, drop `ready` +
        // `shield.active` so the second attempt re-inits — the RST pulse
        // + soft_reset in `init()` clears the chip's PRL/alert state
        // (work-todo 2026-05-12 + 2026-06-12 rows) — then re-handshakes.
        // A second failure surfaces as Err; `rng_strong::fill` fails
        // closed (no silent plaintext downgrade — see bb2615f6).
        let mut last_err = OptigaError::Shield;
        for attempt in 0..2u8 {
            // Each attempt starts from an explicit zero destination. A failed
            // or short response can therefore never leave a nonzero prefix for
            // the retry/caller to mistake for a complete TRNG contribution.
            buf.zeroize();
            crate::fi::zeroize_barrier();
            match self.random_shielded_once(buf) {
                Ok(()) => return Ok(()),
                Err(e) => {
                    if attempt == 0 {
                        secure_log!(
                            "[OPTIGA] random: {:?} — dropping PRL session, re-init + retry",
                            e
                        );
                        self.ready = false;
                        self.shield.active = false;
                    }
                    last_err = e;
                }
            }
        }
        buf.zeroize();
        crate::fi::zeroize_barrier();
        Err(last_err)
    }

    /// Reversible factory-line transport probe.
    ///
    /// Prodtest runs before any pairing secret is loaded and must not mutate
    /// persistent OPTIGA state.  Keep this separate from [`Self::random`]: the
    /// production RNG contribution is required to use the Shielded Connection,
    /// while this narrowly cfg-gated probe deliberately exercises only reset,
    /// OpenApplication, IFX-I2C framing, and a plaintext GetRandom command on a
    /// fresh factory part.
    #[cfg(feature = "prodtest")]
    pub(crate) fn prodtest_plain_random(
        &mut self,
        out: &mut [u8],
    ) -> Result<(), OptigaError> {
        if !(8..=256).contains(&out.len()) {
            return Err(OptigaError::BufferOverflow);
        }
        // A prodtest image must reach this method before any pairing setup.
        // Refuse instead of accidentally turning an established production
        // session into a plaintext downgrade.
        if self.shield.pbs_loaded || self.shield.active {
            return Err(OptigaError::Shield);
        }
        self.init()?;
        let written = unsafe { apdu::get_random_plain(&mut self.ifx, out)? };
        if written != out.len() {
            return Err(OptigaError::Transport);
        }
        Ok(())
    }

    /// One `init` → `ensure_shield` → `GetRandom` attempt; split out so
    /// [`Self::random`] can run it twice around the PRL self-heal.
    fn random_shielded_once(&mut self, buf: &mut [u8]) -> Result<(), OptigaError> {
        self.init()?;
        self.ensure_shield()?;
        unsafe {
            if buf.len() < 8 {
                let mut tmp = [0u8; 8];
                apdu::get_random(&mut self.ifx, &mut self.shield, &mut tmp)?;
                buf.copy_from_slice(&tmp[..buf.len()]);
            } else {
                apdu::get_random(&mut self.ifx, &mut self.shield, buf)?;
            }
        }
        Ok(())
    }

    /// Retired SetObjectProtected recovery evidence. The
    /// `OPTIGA_RESET_OIDS_RETIRED` compile fence makes this unreachable.
    ///
    /// Historical note: the original experiment intended to drop the
    /// `optiga-reset-oids` feature as soon as the chip was back
    /// in a writable state — the TA cert that authorises these manifests
    /// is a sample key from Infineon's example set, unsafe for production.
    #[cfg(feature = "optiga-reset-oids")]
    pub fn recover_burned_oids(&mut self) -> Result<(), OptigaError> {
        // Before anything else, configure PE4 (= Arduino D5 on the
        // B-U585I-IOT02A) as a GPIO output and drive it high — this
        // is wired to the OPTIGA MTR Express V3 board's RST pin, and
        // driving high explicitly tells the chip it's not in reset.
        #[cfg(feature = "stm32u585")]
        unsafe {
            reset_pin::init();
        }

        self.init()?;

        unsafe {
            secure_log!("[OPTIGA][reset] provisioning Trust Anchor at 0xE0E3");
            if let Err(e) = reset::provision_trust_anchor(&mut self.ifx, &mut self.shield) {
                secure_log!(
                    "[OPTIGA][reset] TA provisioning failed ({:?}); \
                    assuming already provisioned and continuing",
                    e
                );
            } else {
                secure_log!("[OPTIGA][reset] TA cert + metadata written");
            }

            // After the 604-byte TA cert write, the chip wedges — it ACKs
            // subsequent frames at DL layer but never sets RESP_READY in
            // I2C_STATE. A soft-reset-over-I²C doesn't recover it; only
            // a real silicon reset via the RST pin does. We also observe
            // that every successful SetObjectProtected puts the chip back
            // in the same wedged state, so we hard-pulse before EACH
            // manifest, not just once before the loop. The TA cert lives
            // in NV flash and survives the resets.
            let mut success: usize = 0;
            for entry in reset::iter_reset_entries() {
                #[cfg(feature = "stm32u585")]
                if let Err(e) = self.hard_reset_and_reinit() {
                    secure_log!(
                        "[OPTIGA][reset] re-init before OID 0x{:04X} FAILED: {:?}",
                        entry.oid, e
                    );
                    continue;
                }

                match apdu::send_protected_manifest(
                    &mut self.ifx,
                    &mut self.shield,
                    entry.manifest,
                    entry.fragment,
                ) {
                    Ok(()) => {
                        secure_log!("[OPTIGA][reset] OID 0x{:04X} reset OK", entry.oid);
                        success += 1;
                    }
                    Err(e) => {
                        secure_log!(
                            "[OPTIGA][reset] OID 0x{:04X} FAILED: {:?}",
                            entry.oid, e
                        );
                    }
                }
            }
            secure_log!("[OPTIGA][reset] {} OIDs reset", success);
        }

        Ok(())
    }

    /// Load the Platform Binding Secret into the Shielded Connection
    /// state.
    ///
    /// Post-work-todo-#24: the PBS is resolved from the per-device hardware
    /// root every boot via `hw::secret_keys::current_pbs` — no PBS flash seal,
    /// no blank-page check, no AES-GCM unseal. After a completed #36 first
    /// boot, `current_pbs` also binds the persisted page-127 TRNG salt; before
    /// that it selects the transport/bring-up derivation. The root depends on
    /// the build (see `hw::secret_keys` module docs):
    /// - `saes-dhuk` on (Tier-1 / current bring-up transport):
    ///   `SAES-CMAC(DHUK, …)` — the silicon DHUK, never CPU-visible. This is
    ///   the pre-rotation transport path. (This is the path
    ///   exercised by `make dual-se-bhk-e2e`; the bench OPTIGA on board
    ///   #1 was re-paired to its DHUK-derived PBS 2026-05-12.)
    /// - `otp-hardcoded-master-key` on (dev/bench): HKDF over the
    ///   compile-time ASCII OTP constant.
    /// - neither (legacy): HKDF over the per-board TRNG OTP master,
    ///   which `ensure_device_master` burns once on first boot.
    ///
    /// Under `optiga-no-shield` this is a no-op — we never attempt
    /// PRL on chips where E140 is unreachable. See
    /// `docs/secure-elements/optiga-brick-postmortem.md` §7.
    #[cfg(feature = "stm32u585")]
    pub fn load_pbs(&mut self) {
        #[cfg(feature = "optiga-no-shield")]
        {
            secure_log!("[OPTIGA] load_pbs skipped (feature optiga-no-shield)");
            return;
        }
        #[cfg(not(feature = "optiga-no-shield"))]
        {
            use zeroize::Zeroize;
            // work-todo #36: single source of truth. `current_pbs()` returns
            // the SALTED-final PBS once the first-boot rotation is complete
            // (journal ALL_DONE), else the unsalted value — byte-identical to
            // pre-#36 behaviour when the feature is off.
            match crate::hw::secret_keys::current_pbs() {
                Ok(mut pbs) => {
                    // Fingerprint log: first 8 bytes of the derived PBS.
                    // Stable across rebuilds iff the derivation root +
                    // label haven't changed. If this line ever differs
                    // between two boots of the same chip, the PBS we're
                    // about to hand to the PRL handshake will not match
                    // what the chip was paired with — and if E140 has
                    // been promoted to LcsO=op the rewrite is impossible.
                    // (At LcsO=Creation, `setup_pbs_no_handshake` will
                    // happily re-pair to the new value — that's exactly
                    // how board #1's bench OPTIGA got moved off the old
                    // `otp-hardcoded` PBS onto its DHUK-derived one.)
                    // The dev test constants live in source; printing 8
                    // bytes of a KDF output over them leaks nothing a
                    // code reader doesn't already have.
                    secure_log!(
                        "[OPTIGA] PBS fingerprint: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                        pbs[0], pbs[1], pbs[2], pbs[3],
                        pbs[4], pbs[5], pbs[6], pbs[7]
                    );
                    self.shield.load_pbs(&pbs);
                    pbs.zeroize();
                    secure_log!("[OPTIGA] PBS derived from hardware root and loaded");
                }
                Err(e) => {
                    // Only reachable if OTP itself failed (RNG failure on
                    // first-boot burn, ReadbackMismatch, etc.). Shielded
                    // Connection will be unavailable; the provisioning
                    // path + PIN flow surface a diagnostic upstream.
                    secure_log!("[OPTIGA] load_pbs FAILED: {:?}", e);
                }
            }
        }
    }

    #[cfg(not(feature = "stm32u585"))]
    pub fn load_pbs(&mut self) {
        secure_log!("[OPTIGA] load_pbs: non-stm32u585 build, no-op");
    }

    /// Ensure the shielded connection is active, establishing it on demand
    /// from the cached PBS.
    ///
    /// Under `optiga-no-shield` this is a no-op — we never attempt the PRL
    /// handshake, every APDU stays plaintext on I2C. Use this mode when
    /// `E140` is unreachable on a specific chip (e.g. the current bricked
    /// test chip), so that non-PRL paths (PIN HMAC verify, entropy
    /// read/write, factory reset of F1Dx) can still be exercised. See
    /// `docs/secure-elements/optiga-brick-postmortem.md` §7.
    pub(crate) fn ensure_shield(&mut self) -> Result<(), OptigaError> {
        #[cfg(feature = "optiga-no-shield")]
        {
            // Mode-of-operation: bus-level I2C encryption is intentionally
            // off. AC'd reads/writes rely on the authenticated-on-chip
            // path instead (PIN HMAC verify → Auto(F1DC) session state).
            return Ok(());
        }
        #[cfg(not(feature = "optiga-no-shield"))]
        {
            if !self.shield.active {
                if !self.shield.pbs_loaded {
                    return Err(OptigaError::Shield);
                }
                // The PRL state machine does NOT require E140 at LcsO=op —
                // this was an earlier misread of the SRM on our side. The
                // Infineon pairing example explicitly runs with E140 at
                // LcsO=Creation (see `example_pair_host_and_optiga_using_
                // pre_shared_secret.c:30-35`, `#define FINAL_LCSO_STATE
                // (LCSO_STATE_CREATION)`), and the presentation-layer code
                // (`ifx_i2c_presentation_layer.c:820-829`) has no LcsO check
                // in the handshake dispatch. The SRM "Pairing Use Case
                // Pre-conditions" explicitly requires `LcsO < operational`,
                // not `= operational`. Bumping LcsO=op is an irreversible
                // hardening primitive (it locks the PBS in place so only
                // `Conf(E140)` can rewrite it afterwards), but its exact actor
                // and order relative to the candidate salted-final rotation
                // are unresolved. The `optiga-lock-operational`
                // feature exists for controlled validation; it is NOT
                // production authority and is not a handshake prerequisite.
                unsafe {
                    // D1 follow-up: do not discard WHY the handshake failed.
                    // `HandshakeTransport` means the PRL exchange never got far
                    // enough to prove anything about the PBS — surface it as a
                    // transport fault so `is_inconclusive()` sees it and no
                    // caller can read it as "wrong PBS". Only
                    // `HandshakeRejected` (SlaveFinished failed to authenticate
                    // under keys derived from the loaded PBS) is an
                    // authoritative verdict. `map_err(|_| Shield)` collapsed
                    // both, which is how a bus fault could reach the E140
                    // rewrite.
                    self.shield.establish(&mut self.ifx).map_err(|e| match e {
                        shield::ShieldError::HandshakeTransport => OptigaError::Transport,
                        _ => OptigaError::Shield,
                    })?;
                }
                secure_log!("[OPTIGA/shield] PRL handshake OK — encrypted I2C active");
            }
            Ok(())
        }
    }

    /// Bring-up transport pairing: write the deterministic device-root PBS to
    /// E140 (plaintext, allowed at LcsO=Creation) BEFORE the legacy wizard draws
    /// any entropy, so that
    /// [`Self::random`]'s mandatory `ensure_shield` can handshake even
    /// on a factory-new chip whose E140 is blank. Idempotent — the
    /// provisioning flow's step 1 (`setup_pbs_no_handshake` inside
    /// `store_objects`) rewrites the same bytes again later; at
    /// LcsO=Creation the rewrite is always permitted. The trailing
    /// `hard_reset_and_reinit` clears the 2-writes-per-session throttle
    /// the E140 data+metadata writes just consumed (and any PRL/alert
    /// residue), leaving the chip clean for the first handshake.
    ///
    /// This is the pre-rotation transport pairing and grants no authority to
    /// lock E140 or provision a shipping unit. The separate journaled salted-
    /// final candidate exists, but its factory handoff, recovery proof,
    /// E140/SE050 order, and silicon validation remain OPEN.
    ///
    /// Under `optiga-no-shield` this is a no-op — those chips never run
    /// the PRL and `ensure_shield` is a no-op for them too.
    pub fn pair_for_first_boot(&mut self) -> Result<(), OptigaError> {
        #[cfg(feature = "optiga-no-shield")]
        {
            secure_log!("[OPTIGA] pair_for_first_boot skipped (optiga-no-shield)");
            Ok(())
        }
        #[cfg(not(feature = "optiga-no-shield"))]
        {
            self.init()?;
            secure_log!("[OPTIGA] pair_for_first_boot: writing E140 PBS (pre-wizard)");
            self.setup_pbs_no_handshake()?;
            #[cfg(feature = "stm32u585")]
            self.hard_reset_and_reinit()?;
            Ok(())
        }
    }

    /// work-todo #36 / #443: establish the shielded session under the factory
    /// **transport** PBS (`secret_keys::transport_optiga_pbs` — OTP-master-
    /// rooted, salt-independent, reproducible at RDP-2) **without touching
    /// E140**. Phase B step 5 calls this on the fresh path BEFORE the 3-source
    /// TRNG salt draw: `random()` requires a live shield, but `load_pbs()` runs
    /// only after Phase B completes (`main.rs`), and the in-ceremony shield
    /// otherwise comes up too late — inside `rotate_pbs_to_salted`, after the
    /// draw. Without this, the mandatory OPTIGA leg of the draw fails and the
    /// unit halts at `E0854`/`E0851` on every boot (#443 deterministic brick).
    ///
    /// This is a pre-rotation **liveness** check — a chip that no longer pairs
    /// under the transport PBS is caught here, before the salt is journaled — so
    /// the salt record is not spent on a chip that can't be rotated. It is NOT
    /// the E140 authenticate-before-rotate proof: that is the separate
    /// `TransportAuthProof` consumed immediately before the `SetData` in
    /// `rotate_pbs_to_salted` (the salt-journal write it precedes is not a
    /// credential). The D1 error split is preserved (`ensure_shield` maps a
    /// transport-class handshake failure to `Transport` = inconclusive/retry;
    /// only a genuine SlaveFinished MAC rejection reaches the caller as
    /// `Shield`).
    ///
    /// **Fresh-path only.** The state machine calls this in the `salt == None`
    /// arm. After a committed salt the chip may already be rotated, where a
    /// transport handshake would fail — the rotation self-establishes instead.
    #[cfg(all(feature = "stm32u585", feature = "rdp2-self-lock"))]
    pub(crate) fn establish_transport_shield(&mut self) -> Result<(), OptigaError> {
        use zeroize::Zeroize;
        // Same transport-establish sequence rotate_pbs_to_salted uses (its
        // TRANSPORT arm), but E140 is never written. `load_pbs` copies into the
        // shield state, so the local can be wiped immediately.
        let mut tr_pbs =
            crate::hw::secret_keys::transport_optiga_pbs().map_err(|_| OptigaError::Transport)?;
        self.shield.load_pbs(&tr_pbs);
        tr_pbs.zeroize();
        // Fresh chip session (clears any PRL/alert residue), then handshake.
        self.hard_reset_and_reinit()
            .and_then(|()| self.ensure_shield())
    }

    /// work-todo #36 first-boot: rotate the E140 Platform Binding Secret from
    /// the factory **transport** PBS to the **salted-final** PBS, two-phase.
    ///
    /// Resumable: probes the FINAL PBS first (if a shield already establishes
    /// under it, rotation completed on a prior boot → no-op). Otherwise it
    /// establishes the shield under the TRANSPORT PBS (authorising the E140
    /// rewrite via the `Change = LcsO<Op OR Conf(0xE140)` AC the factory
    /// metadata keeps), writes the salted-final PBS to E140, then re-shields
    /// under FINAL to **confirm** before returning.
    ///
    /// `salt` is the persisted (journal, RDP-2-hidden) 32-byte TRNG salt, so
    /// the FINAL PBS is deterministic across resumes. Silicon-validation
    /// deferred (see the #36 runbook): the SetData wedge (2–3 ops) timing and
    /// the shield re-establish after the failed FINAL probe.
    #[cfg(all(feature = "stm32u585", feature = "rdp2-self-lock"))]
    pub fn rotate_pbs_to_salted(&mut self, salt: &[u8; 32]) -> Result<(), OptigaError> {
        use zeroize::Zeroize;

        let mut final_pbs = crate::hw::secret_keys::optiga_pairing_secret_salted(salt)
            .map_err(|_| OptigaError::Transport)?;
        let mut tr_pbs =
            crate::hw::secret_keys::transport_optiga_pbs().map_err(|_| OptigaError::Transport)?;

        let result = (|| {
            // Resume / idempotence: FINAL PBS already establishes a shield?
            //
            // D1: the next branch REWRITES E140 — the operation that bricked
            // the bench chip (`docs/secure-elements/optiga-brick-postmortem.md`).
            // The old `.is_ok() && .is_ok()` let an I2C/IFX/CRC fault during a
            // read-only probe fall straight through to it. Classify: only an
            // answer the chip actually gave may say "not rotated yet"; a bus
            // fault means we learned nothing and must fail closed. The ceremony
            // is journal-resumable, so the next boot re-probes with a fresh
            // link.
            //
            // The `Shield` verdict is now earned, not assumed: `ensure_shield`
            // maps a transport-class handshake failure onto
            // `OptigaError::Transport`, so only a genuine cryptographic
            // rejection (SlaveFinished MAC failure under keys derived from the
            // loaded PBS) reaches the fall-through below.
            self.shield.load_pbs(&final_pbs);
            match self
                .hard_reset_and_reinit()
                .and_then(|()| self.ensure_shield())
            {
                Ok(()) => return Ok(()),
                Err(e) if e.is_inconclusive() => return Err(e),
                Err(_) => {}
            }

            // Establish under TRANSPORT to authorise the E140 rewrite. The PRL
            // SlaveFinished MAC under the transport PBS IS the
            // authenticate-before-rotate step; bind it to a proof the SetData
            // must consume, so a skipped/glitched handshake fails closed before
            // the destructive rewrite (named production gate).
            let mut proof = crate::scp03_logic::TransportAuthProof::pending(
                crate::scp03_logic::AUTH_CTX_PBS_TRANSPORT,
            );
            self.shield.load_pbs(&tr_pbs);
            self.hard_reset_and_reinit()?;
            let shield_res = self.ensure_shield();
            let shield_ok = shield_res.is_ok();
            proof.record(crate::scp03_logic::AUTH_CTX_PBS_TRANSPORT, || shield_ok);
            shield_res?; // propagate the D1-classified transport handshake error

            // Write the salted-final PBS to E140.
            // SAFETY: live shielded session under the current (transport) PBS;
            // single-threaded secure world.
            if proof.authorize_write(crate::scp03_logic::AUTH_CTX_PBS_TRANSPORT)
                != crate::fi::OK_SENTINEL
            {
                return Err(OptigaError::Shield);
            }
            unsafe {
                apdu::set_data_object(&mut self.ifx, &mut self.shield, apdu::OID_PBS, &final_pbs)?;
            }

            // Confirm: re-shield under FINAL. Only now is rotation "done".
            self.shield.load_pbs(&final_pbs);
            self.hard_reset_and_reinit()?;
            self.ensure_shield()?;
            Ok(())
        })();

        final_pbs.zeroize();
        tr_pbs.zeroize();
        result
    }

    /// Derive PBS from the configured device root and load it into the shield state
    /// WITHOUT touching E140 on the chip. For bring-up test paths where
    /// E140 is already provisioned from a prior boot — we only need the
    /// host-side PBS in place so `establish()` can run. Does nothing
    /// under `optiga-no-shield`.
    #[cfg(feature = "stm32u585")]
    pub(crate) fn load_pbs_from_device_root(&mut self) -> Result<(), OptigaError> {
        // work-todo #36: single source of truth (salted-final after rotation).
        let mut pbs = crate::hw::secret_keys::current_pbs()
            .map_err(|e| {
                secure_log!("[OPTIGA/bringup] current_pbs FAILED: {:?}", e);
                OptigaError::Transport
            })?;
        self.shield.load_pbs(&pbs);
        use zeroize::Zeroize;
        pbs.zeroize();
        secure_log!("[OPTIGA/bringup] current PBS loaded from configured device root (E140 untouched)");
        Ok(())
    }

    /// PBS provisioning without attempting the shielded-connection
    /// handshake. Writes the 32-byte Platform Binding Secret to OID
    /// 0xE140 and installs the PRL-compatible metadata, but does NOT
    /// call `shield.establish`. Used during bring-up while the PRL
    /// handshake itself is being debugged against real silicon.
    ///
    /// ## Source of the PBS (work-todo #24 + Tier-1)
    ///
    /// The PBS is derived on demand via
    /// `hw::secret_keys::optiga_pairing_secret` with label
    /// `"pqsigner/optiga-pbs-v1"`. The derivation root depends on the
    /// build (see `hw::secret_keys` module docs): `SAES-CMAC(DHUK, …)`
    /// on the silicon DHUK when `saes-dhuk` is on (Tier-1 / current
    /// bring-up transport; the separate salted-final candidate is selected
    /// only after its journal reaches completion),
    /// HKDF over the compile-time ASCII OTP constant under
    /// `otp-hardcoded-master-key`, or HKDF over the per-board TRNG OTP
    /// master otherwise (legacy — `ensure_device_master` burns it once
    /// on first boot). Two properties matter:
    ///
    /// - **Deterministic across firmware rebuilds.** The PBS is a pure
    ///   function of the device's hardware root + the label — both
    ///   stable for the device's lifetime. Any firmware reflash
    ///   reproduces the same bytes. The old `rng::fill`-generated PBS +
    ///   flash-page-126 AES-GCM seal is gone (`hw::flash::write_pbs`
    ///   deleted), along with its dependency on
    ///   `measured_boot::firmware_hash` inside the wrap key — that
    ///   coupling is what bricked bench units on every rebuild (see
    ///   `docs/secure-elements/optiga-brick-postmortem.md`). Switching roots between
    ///   builds (e.g. `otp-hardcoded` → `saes-dhuk`) changes the PBS;
    ///   that's a re-pair, only possible while `E140.LcsO=Creation` —
    ///   which is exactly how board #1's bench OPTIGA was moved onto its
    ///   DHUK-derived PBS on 2026-05-12 (a failed shielded handshake on
    ///   the stale PBS now correctly drops `ready`/`shield.active` so
    ///   the next `init()` re-establishes cleanly — see `factory_reset`).
    /// - **Legacy path self-provisions the master.** On a blank MCU with
    ///   neither `saes-dhuk` nor `otp-hardcoded-master-key`, the inner
    ///   `ensure_device_master` call inside `optiga_pairing_secret`
    ///   programs 32 TRNG bytes into OTP and locks the region. Under
    ///   `saes-dhuk` there is no OTP burn — the DHUK is silicon-fused.
    ///
    /// ## E140 lifecycle is deliberately not changed here
    ///
    /// Ordinary bring-up/field pairing never promotes E140 to Operational,
    /// even when `optiga-lock-operational` is present. The PRL handshake works
    /// at `LcsO < Operational`; freezing E140 is a distinct factory-side
    /// irreversible action whose exact order relative to the final credential
    /// rotation remains OPEN. A future reviewed ceremony may call the separate
    /// [`Self::ensure_pbs_lcso_operational`] primitive, but this routine only
    /// writes the transport PBS and its rotatable metadata. See
    /// `docs/secure-elements/optiga-brick-postmortem.md` §3, §5, §7 and
    /// `docs/archive/production-todo-retired-2026-07-19.md`.
    fn setup_pbs_no_handshake(&mut self) -> Result<(), OptigaError> {
        // Derive the PBS from the device hardware root on real
        // hardware (DHUK-SAES / OTP-const / OTP-master per build — see
        // `hw::secret_keys`); fall back to a TRNG-filled ephemeral
        // value on pure-host/QEMU builds (which don't exercise real
        // OPTIGA I/O anyway — the driver is `optiga-trust-m`-gated and
        // `stm32u585`-gated peripherals are what deliver APDUs).
        //
        // 64-byte size per OPTIGA Trust M SRM §"Platform Binding Secret".
        // work-todo #36: `current_pbs()` (single source of truth) so a wizard
        // re-provision after the first-boot rotation writes the SAME salted
        // value already at E140 — never downgrading it back to unsalted (the
        // brick-class hazard). Byte-identical to `optiga_pairing_secret()`
        // when `rdp2-self-lock` is off or the rotation hasn't completed.
        #[cfg(feature = "stm32u585")]
        let mut pbs = crate::hw::secret_keys::current_pbs()
            .map_err(|e| {
                secure_log!("[OPTIGA/prov] current_pbs FAILED: {:?}", e);
                OptigaError::Transport
            })?;
        #[cfg(not(feature = "stm32u585"))]
        let mut pbs = {
            let mut p = [0u8; 64];
            crate::rng::fill(&mut p).map_err(|_| OptigaError::Transport)?;
            p
        };

        unsafe {
            apdu::set_data_object(
                &mut self.ifx, &mut self.shield,
                apdu::OID_PBS, &pbs,
            )?;

            let (meta, meta_len) = apdu::build_metadata_pbs_final();
            apdu::set_metadata(
                &mut self.ifx, &mut self.shield,
                apdu::OID_PBS, &meta[..meta_len],
            )?;

            // Do not couple ordinary pairing to lifecycle authority.  The
            // factory actor is fixed, but its exact E140/rotation ordering is
            // still open; `ensure_pbs_lcso_operational` remains unwired until
            // that ceremony is reviewed and silicon-validated.
            secure_log!(
                "[OPTIGA/prov] E140 lifecycle unchanged; factory-side ratchet \
                 is a separate OPEN ceremony"
            );
        }

        self.shield.load_pbs(&pbs);
        pbs.zeroize();

        secure_log!("[OPTIGA] PBS provisioned (handshake deferred)");
        Ok(())
    }

    /// Bump E140 to `LcsO=Operational` if it isn't already.
    ///
    /// **NOT required for the PRL handshake** (earlier comment in this
    /// function claimed otherwise, incorrectly — see `ensure_shield` for
    /// the corrected rationale with references into the Infineon host
    /// library and SRM). This is an irreversible hardening primitive: once
    /// LcsO=op the chip stops accepting `Change` via `LcsO<op`, so E140
    /// can only be rewritten via `Conf(E140)` (shielded connection with
    /// the matching PBS). This primitive is intentionally unwired: the actor
    /// is factory-side, while the exact timing/order relative to final pairing
    /// rotation remains OPEN. A future ceremony must call it explicitly only
    /// after review and owner-authorized silicon validation. Ordinary pairing
    /// never reaches it.
    ///
    /// Reads metadata first and only writes when needed so we don't burn
    /// an NVM cycle on every boot once the chip is already Operational.
    /// Metadata reads are Change=ALW on the LcsO tag (SRM §"Metadata
    /// associated with data and key objects"), no shielded connection
    /// required.
    #[allow(dead_code)] // retained for explicit gated validation/future reviewed ceremony
    unsafe fn ensure_pbs_lcso_operational(&mut self) -> Result<(), OptigaError> {
        let mut meta = [0u8; 64];
        let n = apdu::get_metadata(
            &mut self.ifx, &mut self.shield,
            apdu::OID_PBS, &mut meta,
        )?;
        if apdu::is_metadata_operational(&meta, n) {
            secure_log!("[OPTIGA/shield] E140 already at LcsO=op");
            return Ok(());
        }
        secure_log!("[OPTIGA/shield] E140 LcsO<op; bumping to Operational");
        let (lock_meta, lock_len) = apdu::build_metadata_lock();
        apdu::set_metadata(
            &mut self.ifx, &mut self.shield,
            apdu::OID_PBS, &lock_meta[..lock_len],
        )?;
        Ok(())
    }

    /// Derive the 32-byte PIN authorization secret from the 8-digit PIN.
    fn derive_pin_secret(pin: &[u8; 8]) -> [u8; 32] {
        crate::crypto::kdf(PIN_AUTH_DOMAIN, pin, 0)
    }

    /// HMAC-SHA256(key, data) — 32-byte output.
    fn hmac_sha256(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
        use hmac::Mac;
        type HmacSha256 = hmac::Hmac<sha2::Sha256>;

        let mut mac = <HmacSha256 as Mac>::new_from_slice(key).unwrap();
        mac.update(data);
        let result = mac.finalize().into_bytes();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }

    /// Check if the device has been provisioned.
    ///
    /// Uses the F1E1 provisioning/reset sentinel as a liveness marker since
    /// LcsO can only go up — it stays Operational even after a factory
    /// reset, so a metadata check alone would mis-report a wiped chip as
    /// provisioned. The counter can hold:
    /// - `0x00..=0x0A` — normal provisioned state (usage counter value)
    /// - `0xFF` — factory-reset sentinel set by `factory_reset()`
    /// - read-error — object uninitialized, i.e. fresh chip
    ///
    /// Read access on the counter is `Always`, so no shielded connection or
    /// PIN is required.
    fn check_provisioned(&mut self) -> bool {
        // The counter read can hit the same SCTR=0x40 PRL-alert wedge that
        // `random()` self-heals against: once host/chip PRL state diverges
        // the chip bounces every exchange with the 7-byte `08 40` alert
        // (observed on bench board #1, 2026-06-29). The old single-shot
        // read mapped that bounce to `None` → "unprovisioned", dropping a
        // PROVISIONED wallet into the first-boot wizard — where a stray
        // "New Wallet" overwrites the seed. Mirror `random()`'s bounded
        // self-heal, and crucially distinguish a TRANSPORT wedge from a
        // CLEAN app-level "blank chip" answer so the two never conflate.
        for attempt in 0..2u8 {
            // init() each pass: after a drop below it RST-pulses +
            // soft-resets the chip, clearing the wedged PRL/`08 40` state.
            if self.init().is_err() {
                self.ready = false;
                self.shield.active = false;
                continue;
            }
            let mut buf = [0u8; 4];
            match unsafe {
                apdu::get_data_object(
                    &mut self.ifx,
                    &mut self.shield,
                    apdu::OID_COUNTER,
                    0,
                    1,
                    &mut buf,
                )
            } {
                // Clean read of a real counter value → provisioned (unless
                // it's the factory-reset sentinel written by factory_reset).
                Ok(n) if n > 0 => return buf[0] != RESET_SENTINEL,
                // Clean but empty read → genuinely blank/fresh chip.
                Ok(_) => return false,
                // Chip answered at the APP layer (non-zero OPTIGA status:
                // object uninitialised) → fresh chip. No point retrying a
                // clean answer.
                Err(OptigaError::Status(_)) | Err(OptigaError::NotProvisioned) => {
                    return false;
                }
                // TRANSPORT/shield/I2C/CRC failure = the PRL wedge. Drop the
                // session so the next init() RST-clears it, then retry once.
                Err(e) => {
                    secure_log!(
                        "[OPTIGA/prov-check] counter read {:?} — drop PRL, re-init + retry ({}/2)",
                        e,
                        attempt + 1
                    );
                    self.ready = false;
                    self.shield.active = false;
                }
            }
        }
        // Both passes hit a transport wedge (NOT a clean blank read — a
        // fresh chip answers at the app layer above). Fail SAFE: do not
        // report "blank", which would auto-launch the first-boot wizard and
        // risk overwriting a provisioned wallet on a glitch. Report
        // provisioned so boot routes to the unlock path, which fails cleanly
        // with NotProvisioned on a truly dead/blank chip instead of
        // re-provisioning. Recover a persistently wedged chip by power-cycling.
        secure_log!(
            "[OPTIGA/prov-check] counter unreadable after self-heal — assuming PROVISIONED (fail-safe; power-cycle if stuck)"
        );
        true
    }

    /// Lock an OID's lifecycle to Operational.
    ///
    /// **Irreversible** per SRM §"Life Cycle Status": `LcsO` is monotonic
    /// (`Creation → Initialization → Operational → Termination`, no
    /// reverse path). Once an OID is at Operational its metadata is
    /// frozen and can only be re-provisioned via a SetObjectProtected
    /// recovery flow authorised by a Trust Anchor — not something dev
    /// iteration can undo. See `docs/archive/production-todo-retired-2026-07-19.md`.
    ///
    /// Gated behind the `optiga-lock-operational` Cargo feature so that
    /// the default dev / Phase-A build leaves **all OIDs at
    /// `LcsO=Creation`**. Dev builds iterate freely on chip state; only
    /// explicitly authorized sacrificial-validation builds flip the feature
    /// on. A future production ceremony may call this primitive only after its
    /// actor/order and final-rotation recovery contract are reviewed and
    /// silicon-validated. See `docs/archive/work-todo-retired-2026-07-19.md` #24 P2 for the reversible
    /// test matrix and `docs/archive/production-todo-retired-2026-07-19.md` for the still-open one-way
    /// flow.
    unsafe fn lock_oid(&mut self, _oid: u16) -> Result<(), OptigaError> {
        #[cfg(not(feature = "optiga-lock-operational"))]
        {
            secure_log!(
                "[OPTIGA/prov] OID 0x{:04x} lock_oid SKIPPED \
                 (optiga-lock-operational OFF; LcsO stays at Creation, \
                 metadata still mutable)",
                _oid
            );
            Ok(())
        }
        #[cfg(feature = "optiga-lock-operational")]
        {
            let (lock_meta, lock_len) = apdu::build_metadata_lock();
            apdu::set_metadata(&mut self.ifx, &mut self.shield, _oid, &lock_meta[..lock_len])?;
            secure_log!(
                "[OPTIGA/prov] OID 0x{:04x} LcsO bumped to Operational (irreversible)",
                _oid
            );
            Ok(())
        }
    }

    /// Read back an OID's stored metadata, confirm it byte-matches the
    /// intended `expected_meta` on the security-relevant AC / DataType tags,
    /// and ONLY THEN ratchet `LcsO=Operational` via [`Self::lock_oid`].
    ///
    /// **Why this gate exists.** The OPTIGA silently accepts `SetMetadata`
    /// APDUs carrying access-condition constructs it will not honor — it
    /// returns OK while storing nothing, or a truncated/altered form. Because
    /// the `LcsO` ratchet is one-way (`docs/secure-elements/optiga-brick-postmortem.md` §1,
    /// §3), locking such a chip would freeze the WRONG access conditions
    /// forever — e.g. an F1D0 whose `Change` AC nobody can satisfy, bricking
    /// the PIN-HMAC secret. This helper refuses to lock unless the exact bytes
    /// we intended are confirmed present on-chip.
    ///
    /// Idempotent: an already-Operational OID is trusted from the prior
    /// provisioning run and skipped (its frozen metadata can't be rewritten,
    /// and re-verifying buys nothing).
    ///
    /// Without `optiga-lock-operational` this delegates to `lock_oid` (a
    /// no-op), so dev/bench builds are byte-for-byte unchanged.
    ///
    /// # Safety
    /// Touches the OPTIGA APDU stack; caller holds `&mut self`.
    unsafe fn verify_and_lock(
        &mut self,
        oid: u16,
        expected_meta: &[u8],
    ) -> Result<(), OptigaError> {
        #[cfg(not(feature = "optiga-lock-operational"))]
        {
            let _ = expected_meta;
            self.lock_oid(oid)
        }
        #[cfg(feature = "optiga-lock-operational")]
        {
            let mut stored = [0u8; 128];
            let n = apdu::get_metadata(&mut self.ifx, &mut self.shield, oid, &mut stored)?;
            if apdu::is_metadata_operational(&stored, n) {
                secure_log!(
                    "[OPTIGA/lock] OID 0x{:04x} already Operational — skip verify+lock (idempotent)",
                    oid
                );
                return Ok(());
            }
            if !apdu::metadata_matches_expected(&stored, n, expected_meta, expected_meta.len()) {
                secure_log!(
                    "[OPTIGA/lock] OID 0x{:04x} REFUSING LOCK — stored metadata does not match \
                     intended AC (chip silently rejected the write). stored={:02x?} expected={:02x?}",
                    oid, &stored[..n.min(48)], &expected_meta[..expected_meta.len().min(48)]
                );
                // 0xEB == "verify-before-lock mismatch": never lock a chip
                // whose AC we could not confirm. Fail closed.
                return Err(OptigaError::Status(0xEB));
            }
            secure_log!(
                "[OPTIGA/lock] OID 0x{:04x} metadata verified against intent — locking",
                oid
            );
            self.lock_oid(oid)
        }
    }

    /// Provision the auth-reference OID: write the PIN-derived secret,
    /// install AC + data-type, lock LcsO.
    ///
    /// Order matters (aligned with `provision_user_oid`, which was the
    /// fix identified in commit d8e54d7 "data-first write"): while the
    /// OID is at LcsO=Creation with default allow-all Change AC, the
    /// data write goes through plaintext. Installing the AUTHREF data-
    /// type metadata *before* the data is written fails on a fresh chip
    /// with Status=0xFF — the chip apparently refuses to apply
    /// `type=AUTHREF` to an empty OID.
    unsafe fn provision_auth_ref(&mut self, pin_secret: &[u8; 32]) -> Result<(), OptigaError> {
        secure_log!("[OPTIGA/prov] auth_ref: set_data_object");
        if let Err(e) = apdu::set_data_object(
            &mut self.ifx, &mut self.shield,
            apdu::OID_AUTH_REF, pin_secret,
        ) {
            secure_log!("[OPTIGA/prov] auth_ref set_data FAILED: {:?}", e);
            return Err(e);
        }

        // Inspect F1D0's current metadata. If LcsO is already Operational
        // (from a prior provisioning run before commit 0b412b4, where
        // `lock_oid` was unconditional), the one-way ratchet blocks any
        // `set_metadata` — we'd see Status(255) regardless of Change AC
        // or DataType. In that case the metadata is already in the exact
        // shape `build_metadata_auth_ref` would write (Change=ALW,
        // Read=NEV, Execute=ALW, DataType=AUTHREF) modulo chip-internal
        // size tags, so skipping the re-write is functionally
        // equivalent to re-applying it.
        let mut cur_meta = [0u8; 128];
        let cur_len = match apdu::get_metadata(
            &mut self.ifx, &mut self.shield,
            apdu::OID_AUTH_REF, &mut cur_meta,
        ) {
            Ok(n) => {
                secure_log!(
                    "[OPTIGA/prov] F1D0 current metadata ({}B): {:02x?}",
                    n, &cur_meta[..n.min(64)]
                );
                n
            }
            Err(e) => {
                secure_log!("[OPTIGA/prov] F1D0 get_metadata FAILED: {:?}", e);
                0
            }
        };

        if cur_len > 0 && apdu::is_metadata_operational(&cur_meta, cur_len) {
            // Under `optiga-hw-counter` this skip is only safe if the
            // current metadata ALREADY has the LUC Execute binding —
            // otherwise the chip has legacy non-LUC F1D0 frozen at
            // LcsO=Op and the hw-counter feature is inert. Surface
            // this loudly rather than continuing with what looks like
            // a hw-counter-enabled build but behaves like the soft
            // counter. There is no approved in-place recovery: the old
            // SetObjectProtected/`optiga-reset-oids` experiment was
            // mis-targeted and is compile-fenced. Stop and preserve this
            // part as evidence; a replacement ceremony remains OPEN.
            #[cfg(feature = "optiga-hw-counter")]
            {
                let luc_ok =
                    apdu::metadata_has_luc_execute(&cur_meta, cur_len, apdu::OID_PIN_CTR);
                // S-1: in the locked production profile a frozen F1D0 must ALSO
                // carry `Change=Auto(F1D0)`. A legacy chip frozen with
                // `Change=ALW` cannot be hardened in place (metadata immutable),
                // so accepting it would silently ship the very weakness S-1
                // closes — fail closed and force a fresh part / OID-range bump.
                #[cfg(feature = "optiga-lock-operational")]
                let change_ok = apdu::metadata_change_is_auto_authref(&cur_meta, cur_len);
                #[cfg(not(feature = "optiga-lock-operational"))]
                let change_ok = true;
                if !(luc_ok && change_ok) {
                    secure_log!(
                        "[OPTIGA/prov] FAIL: F1D0 at LcsO=Op without the \
                         expected LUC Execute + Auto(F1D0) Change AC — cannot \
                         harden in place. Use a fresh part / OID-range bump. \
                         See docs/secure-elements/optiga-brick-postmortem.md."
                    );
                    return Err(OptigaError::Status(0xE0));
                }
            }
            secure_log!(
                "[OPTIGA/prov] F1D0 at LcsO=Operational — metadata write \
                 blocked by one-way ratchet; skipping set_metadata + \
                 lock_oid (object already in final state)"
            );
            return Ok(());
        }

        #[cfg(feature = "optiga-hw-counter")]
        let (meta, meta_len) = apdu::build_metadata_auth_ref_luc();
        #[cfg(not(feature = "optiga-hw-counter"))]
        let (meta, meta_len) = apdu::build_metadata_auth_ref();
        secure_log!(
            "[OPTIGA/prov] F1D0 proposed metadata ({}B): {:02x?}",
            meta_len, &meta[..meta_len]
        );
        secure_log!("[OPTIGA/prov] auth_ref: set_metadata");
        if let Err(e) = apdu::set_metadata(
            &mut self.ifx, &mut self.shield,
            apdu::OID_AUTH_REF, &meta[..meta_len],
        ) {
            secure_log!("[OPTIGA/prov] auth_ref set_metadata FAILED: {:?}", e);
            return Err(e);
        }

        // Diagnostic readback: OPTIGA is known to accept SetMetadata APDUs
        // on unsupported AC constructs (returns OK, stores nothing). Log
        // what the chip actually stored so we can compare against the
        // "proposed" bytes and catch silent rejections.
        let mut after_meta = [0u8; 128];
        match apdu::get_metadata(
            &mut self.ifx, &mut self.shield,
            apdu::OID_AUTH_REF, &mut after_meta,
        ) {
            Ok(n) => {
                secure_log!(
                    "[OPTIGA/prov] F1D0 readback metadata ({}B): {:02x?}",
                    n, &after_meta[..n.min(64)]
                );
            }
            Err(e) => {
                secure_log!("[OPTIGA/prov] F1D0 readback FAILED: {:?}", e);
            }
        }

        secure_log!("[OPTIGA/prov] auth_ref: verify_and_lock");
        // S-1 brick-safety: confirm the F1D0 metadata we just wrote (incl. the
        // `Change=Auto(F1D0)` AC in the locked profile) actually landed before
        // the irreversible LcsO ratchet.
        if let Err(e) = self.verify_and_lock(apdu::OID_AUTH_REF, &meta[..meta_len]) {
            secure_log!("[OPTIGA/prov] auth_ref verify_and_lock FAILED: {:?}", e);
            return Err(e);
        }
        Ok(())
    }

    /// Provision one user data OID: write payload (while LcsO=Creation
    /// allows it), then install AC, then lock LcsO.
    ///
    /// Order matters: if we install `Change = Auto(F1DC) OR Conf(E140)`
    /// BEFORE writing the data, the chip immediately enforces that AC on
    /// the subsequent write (even in Creation state, in practice) and we
    /// get Status=0xff. Writing the data first, while default "allow-all"
    /// Creation-state ACs apply, succeeds.
    unsafe fn provision_user_oid(
        &mut self,
        oid: u16,
        data: &[u8],
        require_shielded_read: bool,
    ) -> Result<(), OptigaError> {
        secure_log!("[OPTIGA/prov] OID 0x{:04x}: set_data ({} bytes)", oid, data.len());
        if let Err(e) = apdu::set_data_object(&mut self.ifx, &mut self.shield, oid, data) {
            secure_log!("[OPTIGA/prov] OID 0x{:04x}: set_data FAILED: {:?}", oid, e);
            return Err(e);
        }

        // Same LcsO-ratchet guard as provision_auth_ref: if the OID was
        // bumped to Operational by a pre-0b412b4 run, re-writing the
        // metadata is forever blocked. The already-installed AC
        // (Change=Auto(F1D0) OR Conf(E140), Read depending on
        // `require_shielded_read`, Execute=NEV) is identical to what we
        // would write, so skipping is functionally equivalent.
        let mut cur_meta = [0u8; 128];
        let cur_len = apdu::get_metadata(
            &mut self.ifx, &mut self.shield, oid, &mut cur_meta,
        ).unwrap_or(0);
        if cur_len > 0 && apdu::is_metadata_operational(&cur_meta, cur_len) {
            secure_log!(
                "[OPTIGA/prov] OID 0x{:04x} at LcsO=Operational — \
                 skipping set_metadata + lock_oid",
                oid
            );
            return Ok(());
        }

        let (meta, meta_len) =
            apdu::build_metadata_protected(apdu::OID_AUTH_REF, require_shielded_read);
        if let Err(e) = apdu::set_metadata(&mut self.ifx, &mut self.shield, oid, &meta[..meta_len]) {
            secure_log!("[OPTIGA/prov] OID 0x{:04x}: set_metadata FAILED: {:?}", oid, e);
            return Err(e);
        }
        if let Err(e) = self.verify_and_lock(oid, &meta[..meta_len]) {
            secure_log!("[OPTIGA/prov] OID 0x{:04x}: verify_and_lock FAILED: {:?}", oid, e);
            return Err(e);
        }
        Ok(())
    }

    /// §32 duress variant of [`provision_user_oid`]: gate the OID's
    /// Read/Change AC on `authref_oid` (the duress F1D8) instead of the
    /// real F1D0, and NEVER lock (the duress OIDs must stay LcsO=Creation
    /// so re-provisioning / recovery is always possible — same constraint
    /// as the real OIDs under the default feature set, made explicit here).
    #[cfg(feature = "duress-pin")]
    unsafe fn provision_user_oid_authref(
        &mut self,
        oid: u16,
        data: &[u8],
        authref_oid: u16,
        require_shielded_read: bool,
    ) -> Result<(), OptigaError> {
        secure_log!("[OPTIGA/duress] OID 0x{:04x}: set_data ({} bytes)", oid, data.len());
        apdu::set_data_object(&mut self.ifx, &mut self.shield, oid, data)?;

        let mut cur_meta = [0u8; 128];
        let cur_len = apdu::get_metadata(
            &mut self.ifx, &mut self.shield, oid, &mut cur_meta,
        ).unwrap_or(0);
        if cur_len > 0 && apdu::is_metadata_operational(&cur_meta, cur_len) {
            secure_log!(
                "[OPTIGA/duress] OID 0x{:04x} at LcsO=Operational — skipping set_metadata",
                oid
            );
            return Ok(());
        }

        let (meta, meta_len) = apdu::build_metadata_protected(authref_oid, require_shielded_read);
        apdu::set_metadata(&mut self.ifx, &mut self.shield, oid, &meta[..meta_len])?;
        // Deliberately NO lock_oid — stay LcsO=Creation.
        Ok(())
    }

    // ---------------------------------------------------------------
    // Hardware PIN counter (`optiga-hw-counter`) — E120 + LUC binding.
    // ---------------------------------------------------------------
    //
    // Silicon-enforced Trezor-parity PIN lockout. The chip at 0xE120
    // is a monotonic Lifetime Usage Counter (data type UPCTR, 0x01)
    // whose 8-byte object carries `[current_u32_be | limit_u32_be]`.
    // Every HMAC-verify against F1D0 auto-increments the counter inside
    // the chip (the `Execute = LUC(E120)` AC on F1D0 is what wires
    // this). When `current == limit`, F1D0's Execute AC refuses auth
    // regardless of PIN bytes — Platform-Binding-Secret extraction
    // cannot bypass this because the reset path writes E120 via
    // Change=Auto(F1D0), which requires the very HMAC auth we're
    // trying to protect.
    //
    // See Trezor `core/embed/sec/optiga/optiga.c` for the reference
    // implementation (`optiga_reset_counter`, `OID_STRETCHED_PIN_CTR`).

    /// Lifetime-failure threshold for the silicon PIN counter.
    ///
    /// This is an emergency / anti-extraction backstop, NOT the
    /// user-facing 10-attempt lockout — MCU flash page 124 and the SE050
    /// UserID enforce that bound with reset-on-success (see
    /// `hw::flash::pin_attempts_{read,bump,reset}` and
    /// `nsc::gated_unlock`). Silicon counter's value-add is the case
    /// where an attacker extracts PBS and replays against the chip
    /// directly, bypassing the MCU gate — E120 then fires after
    /// `HW_PIN_CTR_LIMIT` lifetime attempts. 32 is well above the
    /// birthday budget of legitimate typo-bursts over the device
    /// lifetime yet well below any plausible brute-force attempt
    /// count.
    #[cfg(feature = "optiga-hw-counter")]
    pub const HW_PIN_CTR_LIMIT: u32 = 32;

    /// §32 duress LUC counter (E121) limit. UNLIKE the real E120 (limit
    /// 32, an enforced anti-extraction lockout), E121 is functionally
    /// UNENFORCED — firmware never reads it for lockout; it exists only so
    /// the duress F1D8 verify fires a LUC and is a timing twin of the real
    /// F1D0 verify. The limit must therefore never trip in practice.
    ///
    /// CRITICAL: E121 is bumped by EVERY F1D8 execute — including the
    /// failed duress verify that `unlock_duress` runs on a REAL-PIN entry
    /// (the no-short-circuit timing structure). That bump CANNOT be reset
    /// (E121.Change=Auto(F1D8) is not satisfied by a failed verify), so
    /// E121 climbs ~1 per unlock REGARDLESS of whether duress is ever
    /// used. The limit alone is what prevents a lifetime silicon-lockout
    /// of the duress AuthRef: 0x00FF_FFFF = 16,777,215 ⇒ ~460 years at an
    /// extreme 100 unlocks/day. (A duress-correct unlock additionally
    /// resets E121 to 0 — see `duress_read_half` — which bounds the
    /// decoy-heavy case, but the high limit is the load-bearing fix.)
    #[cfg(feature = "duress-pin")]
    pub const DURESS_CTR_LIMIT: u32 = 0x00FF_FFFF;

    /// Provision the silicon PIN counter at `apdu::OID_PIN_CTR` (0xE120).
    ///
    /// MUST be called BEFORE `provision_auth_ref` under this feature —
    /// F1D0's new metadata references E120 via `Execute = LUC(E120)`,
    /// and while referencing a non-existent counter is not strictly a
    /// brick, it would leave F1D0 inert until the counter is created.
    /// The LcsO ratchet on F1D0 is one-way, so ordering matters.
    ///
    /// Writes the 8-byte UPCTR data `[0,0,0,0, L,L,L,L]` first (allowed
    /// at the default Creation-state ALW Change AC), THEN installs the
    /// metadata that narrows Change to `Auto(OID_AUTH_REF)`. Installing
    /// metadata first would likely be accepted by the chip at Creation
    /// but mirrors the `provision_user_oid` observation that the
    /// reverse order triggers Status=0xff on some chips.
    #[cfg(feature = "optiga-hw-counter")]
    unsafe fn provision_hw_pin_counter(
        &mut self,
        limit: u32,
        pin_secret: &[u8; 32],
    ) -> Result<(), OptigaError> {
        // Idempotency pre-check: if E120 metadata is already exactly
        // what we'd install (Change=Auto(F1D0), Exec=ALW), the chip is
        // already correctly provisioned from a previous run — further
        // writes would be rejected because Change=Auto(F1D0) isn't
        // satisfied until PIN auth succeeds. This also serves as the
        // advisor-requested readback diagnostic for the metadata
        // actually stored on the chip.
        let mut pre_meta = [0u8; 128];
        let pre_len = apdu::get_metadata(
            &mut self.ifx, &mut self.shield,
            apdu::OID_PIN_CTR, &mut pre_meta,
        ).unwrap_or(0);
        secure_log!(
            "[OPTIGA/prov] hw-ctr 0x{:04x} pre-read metadata ({}B): {:02x?}",
            apdu::OID_PIN_CTR, pre_len, &pre_meta[..pre_len.min(64)]
        );
        let change_ok = pre_len > 0
            && apdu::metadata_change_is_auto_authref(&pre_meta, pre_len);
        let exec_ok = pre_len > 0
            && apdu::metadata_execute_is_always(&pre_meta, pre_len);
        if change_ok && exec_ok {
            secure_log!(
                "[OPTIGA/prov] hw-ctr 0x{:04x} already provisioned correctly (Change=Auto(F1D0), Exec=ALW) — skipping writes",
                apdu::OID_PIN_CTR
            );
            return Ok(());
        }
        if change_ok && !exec_ok {
            // BROKEN STATE: previous provisioning run wrote Exec=NEV
            // which blocks LUC from being able to increment E120 on
            // F1D0 DecryptSym. Recovery is possible because F1D0's
            // Change=ALW — we can temporarily strip the LUC binding,
            // auth via the non-LUC shape, then rewrite E120 metadata
            // with the correct Exec=ALW. See recover_hw_counter_metadata.
            secure_log!(
                "[OPTIGA/prov] hw-ctr 0x{:04x} BROKEN (Change=Auto(F1D0) but Exec!=ALW) — running recovery",
                apdu::OID_PIN_CTR
            );
            return self.recover_hw_counter_metadata(pin_secret);
        }

        let data = apdu::encode_pin_ctr(0, limit);
        secure_log!(
            "[OPTIGA/prov] hw-ctr 0x{:04x}: set_data ({}B, limit={})",
            apdu::OID_PIN_CTR, data.len(), limit
        );
        if let Err(e) = apdu::set_data_object(
            &mut self.ifx, &mut self.shield,
            apdu::OID_PIN_CTR, &data,
        ) {
            secure_log!("[OPTIGA/prov] hw-ctr set_data FAILED: {:?}", e);
            return Err(e);
        }

        // LcsO-ratchet skip (identical pattern to provision_user_oid).
        let mut cur_meta = [0u8; 128];
        let cur_len = apdu::get_metadata(
            &mut self.ifx, &mut self.shield,
            apdu::OID_PIN_CTR, &mut cur_meta,
        ).unwrap_or(0);
        if cur_len > 0 && apdu::is_metadata_operational(&cur_meta, cur_len) {
            secure_log!(
                "[OPTIGA/prov] hw-ctr 0x{:04x} at LcsO=Operational — \
                 skipping set_metadata",
                apdu::OID_PIN_CTR
            );
            return Ok(());
        }

        let (meta, meta_len) = apdu::build_metadata_pin_ctr();
        secure_log!(
            "[OPTIGA/prov] hw-ctr 0x{:04x} proposed metadata ({}B): {:02x?}",
            apdu::OID_PIN_CTR, meta_len, &meta[..meta_len]
        );
        if let Err(e) = apdu::set_metadata(
            &mut self.ifx, &mut self.shield,
            apdu::OID_PIN_CTR, &meta[..meta_len],
        ) {
            secure_log!("[OPTIGA/prov] hw-ctr set_metadata FAILED: {:?}", e);
            return Err(e);
        }

        // Diagnostic readback: same silent-accept concern as F1D0 —
        // OPTIGA may take unsupported AC constructs and not store them.
        let mut after_meta = [0u8; 128];
        match apdu::get_metadata(
            &mut self.ifx, &mut self.shield,
            apdu::OID_PIN_CTR, &mut after_meta,
        ) {
            Ok(n) => {
                secure_log!(
                    "[OPTIGA/prov] hw-ctr 0x{:04x} readback metadata ({}B): {:02x?}",
                    apdu::OID_PIN_CTR, n, &after_meta[..n.min(64)]
                );
            }
            Err(e) => {
                secure_log!(
                    "[OPTIGA/prov] hw-ctr 0x{:04x} readback FAILED: {:?}",
                    apdu::OID_PIN_CTR, e
                );
            }
        }

        // Deliberately NOT locking to LcsO=Op. Change AC is already
        // Auto(OID_AUTH_REF) and enforced at Creation too (per the
        // store_objects comment at mod.rs:731); locking would only
        // freeze the metadata shape, not the data. Keeping LcsO at
        // Creation leaves room for a future firmware to widen the
        // threshold without a factory-reset pass.
        Ok(())
    }

    /// Repair a chip whose E120 metadata was installed with the wrong
    /// Execute AC (NEV instead of ALW) by an earlier buggy provisioning
    /// run. Only reachable from `provision_hw_pin_counter` when the
    /// metadata readback says `Change=Auto(F1D0)` AND Exec is not ALW.
    ///
    /// Path exists because F1D0's Change AC is ALW — we can strip the
    /// LUC binding from F1D0 metadata without authentication, auth via
    /// the legacy 64-byte DecryptSym shape (which works because LUC is
    /// no longer on F1D0's Execute AC), then with F1D0 auth-state
    /// active satisfy E120's Change=Auto(F1D0) to install correct
    /// metadata, finally restore the LUC binding on F1D0.
    ///
    /// On success, the chip's E120 has Exec=ALW and F1D0's Execute AC
    /// is LUC(E120) again — the state we should have produced on fresh
    /// provisioning. On failure, F1D0 may be left in the no-LUC variant
    /// but the chip is still usable for PIN auth (just without silicon
    /// counter enforcement).
    ///
    /// S-1 INVARIANT: this recovery is reachable ONLY while F1D0 is still at
    /// LcsO=Creation (it rewrites F1D0 metadata, which the one-way ratchet
    /// forbids once locked). The factory provisioning order guarantees E120 is
    /// written correctly BEFORE F1D0 is locked, so under the
    /// `optiga-lock-operational` profile a locked F1D0 never reaches here —
    /// `provision_auth_ref`'s skip-guard returns early for an Operational F1D0.
    #[cfg(feature = "optiga-hw-counter")]
    unsafe fn recover_hw_counter_metadata(
        &mut self,
        pin_secret: &[u8; 32],
    ) -> Result<(), OptigaError> {
        use zeroize::Zeroize;

        // Step 1: strip LUC from F1D0. Allowed: F1D0 Change=ALW.
        secure_log!("[OPTIGA/recover] step 1: rewrite F1D0 metadata without LUC");
        let (no_luc_meta, no_luc_len) = apdu::build_metadata_auth_ref();
        apdu::set_metadata(
            &mut self.ifx, &mut self.shield,
            apdu::OID_AUTH_REF, &no_luc_meta[..no_luc_len],
        )?;

        // Step 2: auth via legacy 64B DecryptSym shape. Only possible
        // because F1D0 no longer has LUC binding after step 1.
        secure_log!("[OPTIGA/recover] step 2: auth F1D0 via legacy 64B shape");
        let mut host_nonce = [0u8; 16];
        let mut host_tag = [0u8; 16];
        crate::rng::fill(&mut host_nonce).map_err(|_| OptigaError::Transport)?;
        crate::rng::fill(&mut host_tag).map_err(|_| OptigaError::Transport)?;
        let mut chip_random = [0u8; 32];
        apdu::generate_auth_code(
            &mut self.ifx, &mut self.shield,
            apdu::OID_SESSION, &host_nonce, &mut chip_random,
        )?;
        let mut hmac_input = [0u8; 64];
        hmac_input[..16].copy_from_slice(&host_nonce);
        hmac_input[16..48].copy_from_slice(&chip_random);
        hmac_input[48..].copy_from_slice(&host_tag);
        let mut hmac = Self::hmac_sha256(pin_secret, &hmac_input);
        let verify_result = apdu::hmac_verify(
            &mut self.ifx, &mut self.shield,
            apdu::OID_AUTH_REF, apdu::OID_SESSION,
            &hmac_input, &hmac,
        );
        hmac.zeroize();
        hmac_input.zeroize();
        host_nonce.zeroize();
        host_tag.zeroize();
        chip_random.zeroize();
        verify_result?;
        secure_log!("[OPTIGA/recover] step 2: auth OK");

        // Step 3: rewrite E120 metadata. F1D0 auth-state active in
        // session so Change=Auto(F1D0) is satisfied.
        secure_log!("[OPTIGA/recover] step 3: rewrite E120 metadata with Exec=ALW");
        let (e120_meta, e120_len) = apdu::build_metadata_pin_ctr();
        apdu::set_metadata(
            &mut self.ifx, &mut self.shield,
            apdu::OID_PIN_CTR, &e120_meta[..e120_len],
        )?;

        // Step 4: restore LUC binding on F1D0. Change=ALW still.
        secure_log!("[OPTIGA/recover] step 4: restore F1D0 LUC binding");
        let (luc_meta, luc_len) = apdu::build_metadata_auth_ref_luc();
        apdu::set_metadata(
            &mut self.ifx, &mut self.shield,
            apdu::OID_AUTH_REF, &luc_meta[..luc_len],
        )?;

        secure_log!("[OPTIGA/recover] complete — hw-counter metadata fixed");
        Ok(())
    }

    /// Reset the silicon PIN counter back to `(0, HW_PIN_CTR_LIMIT)`.
    ///
    /// MUST be called inside a session that has already HMAC-verified
    /// `OID_AUTH_REF` this session — E120's Change AC is
    /// `Auto(OID_AUTH_REF)`, so without that the SetDataObject rejects
    /// (Sta=0xFF; Last Error Code 0x07, access conditions not
    /// satisfied). `authenticate_and_read` calls
    /// this right after a successful `hmac_verify` (same session, same
    /// AuthRef still authorized).
    #[cfg(feature = "optiga-hw-counter")]
    unsafe fn reset_hw_pin_counter(&mut self) -> Result<(), OptigaError> {
        let data = apdu::encode_pin_ctr(0, Self::HW_PIN_CTR_LIMIT);
        apdu::set_data_object(
            &mut self.ifx, &mut self.shield,
            apdu::OID_PIN_CTR, &data,
        )
    }

    /// Reset E120 to (0, limit) from the admin-wipe path, without needing
    /// the user's PIN. Mirrors Trezor's `optiga_pin_set(PIN_EMPTY, ...)`
    /// wipe sequence (`core/embed/sec/optiga/optiga.c:782-847`).
    ///
    /// Why this exists: the normal `reset_hw_pin_counter` call above
    /// requires F1D0 (AuthRef) to have just been successfully HMAC-
    /// verified — the counter's Change AC is `Auto(F1D0)`. During
    /// `factory_reset` we do NOT have the user's PIN, so we can't
    /// satisfy that AC by running the normal authenticate-with-user-
    /// PIN flow. Without this helper, E120's counter value survives
    /// every wipe cycle. After a few multi-wipe sequences
    /// (10 wrong → wipe, repeat) E120 saturates at `HW_PIN_CTR_LIMIT`
    /// and the `curr >= limit` pre-check in `authenticate_and_read`
    /// starts rejecting every subsequent auth, regardless of PIN —
    /// a soft-brick DoS.
    ///
    /// The trick: F1D0's Change AC is `ALW` (always writeable), which
    /// means we can rewrite F1D0's content to a transient, device-
    /// controlled secret without knowing the user's PIN. Once F1D0
    /// holds a value we know, we can HMAC-verify against it, opening
    /// F1D0's session. With F1D0 authenticated, the counter's Change
    /// AC is satisfied and `reset_hw_pin_counter` can write (0, limit).
    ///
    /// The `factory_reset` wipe loop that runs next overwrites F1D0
    /// with zeros anyway, so the transient secret only ever exists
    /// in the caller-owned zeroizing buffer and this function's HMAC
    /// computation; both are wiped before the reset returns.
    ///
    /// One E120 slot is consumed per call: the HMAC-verify step fires
    /// the LUC counter on F1D0's Execute AC (success path), but the
    /// subsequent `reset_hw_pin_counter` immediately snaps it back to
    /// 0. Net effect per wipe: E120 = 0 afterwards.
    ///
    /// Security review: the caller supplies a 32-byte value from the strict
    /// STM32 + OPTIGA + SE050 combiner. Keeping the draw at the dual-SE owner
    /// avoids re-entering/aliasing the global backend while `self` is already
    /// borrowed. If that draw fails, the caller skips this optional counter
    /// reset and still performs the destructive wipe; this helper never falls
    /// back to a platform-only authorization value.
    #[cfg(all(feature = "optiga-hw-counter", not(feature = "optiga-lock-operational")))]
    unsafe fn reset_e120_via_transient_auth(
        &mut self,
        transient_secret: &mut [u8; 32],
    ) -> Result<(), OptigaError> {
        use zeroize::Zeroize;

        // 1. The dual-SE owner has already filled `transient_secret` through
        //    rng_strong::fill_with_store (STM32 + OPTIGA + SE050). Refuse an
        //    error-wiped/invalid input instead of minting a weaker local draw.
        let mut nonzero = 0u8;
        for &byte in transient_secret.iter() {
            nonzero |= byte;
        }
        if nonzero == 0 {
            transient_secret.zeroize();
            crate::fi::zeroize_barrier();
            return Err(OptigaError::Transport);
        }

        // 2. Write them to F1D0 under the active Shielded Connection
        //    (Conf(E140)) — Change AC is ALW, so the write always
        //    succeeds regardless of LcsO state.
        secure_log!("[OPTIGA/wipe] transient-auth: writing random to F1D0");
        if let Err(e) = apdu::set_data_object(
            &mut self.ifx, &mut self.shield,
            apdu::OID_AUTH_REF, transient_secret,
        ) {
            transient_secret.zeroize();
            secure_log!("[OPTIGA/wipe] transient-auth: F1D0 write FAILED: {:?}", e);
            return Err(e);
        }

        // 3. Fetch 16 random bytes into the session nonce OID (same
        //    APDU shape the normal PIN unlock uses — Trezor parity).
        let mut nonce = [0u8; 16];
        if let Err(e) = apdu::get_random_auto_state(
            &mut self.ifx, &mut self.shield,
            apdu::OID_SESSION, &mut nonce,
        ) {
            transient_secret.zeroize();
            secure_log!("[OPTIGA/wipe] transient-auth: GetRandom FAILED: {:?}", e);
            return Err(e);
        }

        // 4. HMAC-SHA256(transient_secret, nonce) → 32B tag, then
        //    DecryptSym-auto-state against F1D0 with the 18B data
        //    block `(nonce_oid || nonce)`. Success opens F1D0's
        //    session. LUC fires on E120 (counter advances by 1).
        let mut hmac = Self::hmac_sha256(transient_secret, &nonce);
        transient_secret.zeroize();

        let verify_result = apdu::hmac_verify_auto_state(
            &mut self.ifx, &mut self.shield,
            apdu::OID_AUTH_REF, apdu::OID_SESSION,
            &nonce, &hmac,
        );
        nonce.zeroize();
        hmac.zeroize();

        if let Err(e) = verify_result {
            secure_log!("[OPTIGA/wipe] transient-auth: hmac_verify FAILED: {:?}", e);
            return Err(e);
        }

        // 5. F1D0 is now authenticated. Reset E120 to (0, limit).
        if let Err(e) = self.reset_hw_pin_counter() {
            secure_log!("[OPTIGA/wipe] transient-auth: reset_hw_pin_counter FAILED: {:?}", e);
            return Err(e);
        }

        secure_log!("[OPTIGA/wipe] transient-auth: E120 reset to (0, limit)");
        Ok(())
    }

    /// Read the silicon PIN counter, returning `(current, limit)` or
    /// `None` if the OID is unprovisioned / the read fails.
    /// Remaining attempts = `limit.saturating_sub(current)`.
    #[cfg(feature = "optiga-hw-counter")]
    pub unsafe fn read_hw_pin_counter(&mut self) -> Option<(u32, u32)> {
        let mut buf = [0u8; 8];
        match apdu::get_data_object(
            &mut self.ifx, &mut self.shield,
            apdu::OID_PIN_CTR, 0, 8, &mut buf,
        ) {
            Ok(8) => apdu::parse_pin_ctr(&buf),
            _ => None,
        }
    }

    /// PROBE ONLY (`duress-probe-e2e`, §32 duress-PIN feasibility):
    /// provision a SECOND AuthRef at `oid` with `Execute=ALW` (NO
    /// E120/LUC binding → it never bumps the silicon PIN counter) and
    /// `Change=ALW` (stays LcsO=Creation — re-writable, never locked).
    /// Mirrors `provision_auth_ref` but at an arbitrary OID with the
    /// non-LUC metadata. Deliberately does NOT call `lock_oid`.
    #[cfg(feature = "duress-probe-e2e")]
    pub unsafe fn probe_provision_duress_authref(
        &mut self,
        oid: u16,
        pin: &[u8; 8],
    ) -> Result<(), OptigaError> {
        use zeroize::Zeroize;
        self.ensure_shield()?;
        let mut secret = Self::derive_pin_secret(pin);
        let r = apdu::set_data_object(&mut self.ifx, &mut self.shield, oid, &secret);
        secret.zeroize();
        r?;
        // Non-LUC AuthRef metadata: Change=ALW / Read=NEV / Execute=ALW
        // / DataType=AUTHREF. Change=ALW keeps the OID at LcsO=Creation.
        let (meta, meta_len) = apdu::build_metadata_auth_ref();
        apdu::set_metadata(&mut self.ifx, &mut self.shield, oid, &meta[..meta_len])?;
        Ok(())
    }

    /// PROBE ONLY (`duress-probe-e2e`, §32 matched-LUC validation):
    /// provision a SECOND AuthRef at `authref_oid` (e.g. F1D8) bound to
    /// its OWN LUC counter at `ctr_oid` (e.g. E121) — the matched-LUC
    /// duress credential. Mirrors the real `provision_hw_pin_counter` +
    /// `provision_auth_ref` LUC path but at parameterized OIDs and with
    /// the simple (no idempotency/recovery) provisioning adequate for a
    /// single probe run. Order: counter DATA first (Change=ALW at
    /// Creation), then counter metadata (Change=Auto(authref_oid),
    /// Exec=ALW), then the AuthRef data + metadata (Execute=LUC(ctr_oid)).
    /// Stays LcsO=Creation throughout — never locks, fully recoverable.
    #[cfg(feature = "duress-probe-e2e")]
    pub unsafe fn probe_provision_duress_authref_luc(
        &mut self,
        authref_oid: u16,
        ctr_oid: u16,
        limit: u32,
        pin: &[u8; 8],
    ) -> Result<(), OptigaError> {
        use zeroize::Zeroize;
        self.ensure_shield()?;

        // 1. Counter data: [current=0, limit] (allowed at Creation ALW).
        let ctr_data = apdu::encode_pin_ctr(0, limit);
        apdu::set_data_object(&mut self.ifx, &mut self.shield, ctr_oid, &ctr_data)?;
        // 2. Counter metadata: Change=Auto(authref_oid), Exec=ALW.
        let (cmeta, clen) = apdu::build_metadata_pin_ctr_oid(authref_oid);
        apdu::set_metadata(&mut self.ifx, &mut self.shield, ctr_oid, &cmeta[..clen])?;

        // 3. AuthRef secret (PIN-derived HMAC key).
        let mut secret = Self::derive_pin_secret(pin);
        let r = apdu::set_data_object(&mut self.ifx, &mut self.shield, authref_oid, &secret);
        secret.zeroize();
        r?;
        // 4. AuthRef metadata: Change=ALW / Read=NEV / Execute=LUC(ctr_oid).
        //    The duress F1D8 twin is deliberately NEVER locked and is blanked
        //    via the ALW Change arm on the reset path, so it keeps `Change=ALW`
        //    (change_is_auto=false) — the S-1 Auto(F1D0) hardening applies only
        //    to the real F1D0.
        let (ameta, alen) = apdu::build_metadata_auth_ref_luc_oid(ctr_oid, false);
        apdu::set_metadata(&mut self.ifx, &mut self.shield, authref_oid, &ameta[..alen])?;
        Ok(())
    }

    /// Authenticate the DURESS AuthRef (F1D8, auto-state path firing
    /// LUC(E121)) with `duress_pin` and read back the decoy OPTIGA half
    /// (F1D9) AND the stored decoy master (F1DA). Mirrors the hw-counter
    /// arm of `authenticate_and_read` but for the duress credential set.
    /// Returns `(half_o, stored_decoy_master)`; `Err` (before any read)
    /// if the verify fails — so a real-PIN entry costs exactly one duress
    /// verify here, no read.
    ///
    /// On success it ALSO resets E121 to `(0, DURESS_CTR_LIMIT)` — the
    /// F1D8 auth-state just established satisfies E121.Change=Auto(F1D8),
    /// so this is the duress-side analogue of the real path's E120 reset.
    /// (Bounds the decoy-heavy case; real-entry E121 bumps are unresettable
    /// and bounded by the high limit instead — see `DURESS_CTR_LIMIT`.)
    ///
    /// Used by `DualSecureElement::unlock_duress` (P3) + the P2 recipe.
    #[cfg(feature = "duress-pin")]
    pub unsafe fn duress_read_half(
        &mut self,
        duress_pin: &[u8; 8],
    ) -> Result<([u8; 32], [u8; 32]), OptigaError> {
        use zeroize::Zeroize;
        self.ensure_shield()?;
        let mut nonce = [0u8; 16];
        apdu::get_random_auto_state(
            &mut self.ifx, &mut self.shield, apdu::OID_SESSION, &mut nonce,
        )?;
        let mut pin_secret = Self::derive_pin_secret(duress_pin);
        let mut hmac = Self::hmac_sha256(&pin_secret, &nonce);
        pin_secret.zeroize();
        let vr = apdu::hmac_verify_auto_state(
            &mut self.ifx, &mut self.shield,
            apdu::OID_DURESS_AUTH_REF, apdu::OID_SESSION, &nonce, &hmac,
        );
        nonce.zeroize();
        hmac.zeroize();
        vr?;
        let mut half_o = [0u8; 32];
        apdu::get_data_object(
            &mut self.ifx, &mut self.shield,
            apdu::OID_DURESS_ENTROPY, 0, 32, &mut half_o,
        )?;
        let mut stored_master = [0u8; 32];
        apdu::get_data_object(
            &mut self.ifx, &mut self.shield,
            apdu::OID_DURESS_MASTER_SECRET, 0, 32, &mut stored_master,
        )?;
        // Reset E121 (F1D8 auth-state active → Change=Auto(F1D8) satisfied).
        // Best-effort: the unlock already succeeded; a failed reset only
        // means E121 keeps climbing toward its (very high) limit.
        let ctr = apdu::encode_pin_ctr(0, Self::DURESS_CTR_LIMIT);
        let _ = apdu::set_data_object(
            &mut self.ifx, &mut self.shield, apdu::OID_PIN_CTR_DURESS, &ctr,
        );
        Ok((half_o, stored_master))
    }

    /// Verify-ONLY against the DURESS AuthRef (F1D8, auto-state, fires
    /// LUC(E121)) — no read. The §32 P3 timing PAD: on a duress-correct
    /// unlock the real F1D0 verify is skipped (so E120 never drifts), and
    /// this matched-LUC verify stands in for it as a byte-for-byte timing
    /// twin (validated on silicon 2026-05-20). `Ok(())` on success.
    #[cfg(feature = "duress-pin")]
    pub unsafe fn duress_verify(&mut self, duress_pin: &[u8; 8]) -> Result<(), OptigaError> {
        use zeroize::Zeroize;
        self.ensure_shield()?;
        let mut nonce = [0u8; 16];
        apdu::get_random_auto_state(
            &mut self.ifx, &mut self.shield, apdu::OID_SESSION, &mut nonce,
        )?;
        let mut pin_secret = Self::derive_pin_secret(duress_pin);
        let mut hmac = Self::hmac_sha256(&pin_secret, &nonce);
        pin_secret.zeroize();
        let vr = apdu::hmac_verify_auto_state(
            &mut self.ifx, &mut self.shield,
            apdu::OID_DURESS_AUTH_REF, apdu::OID_SESSION, &nonce, &hmac,
        );
        nonce.zeroize();
        hmac.zeroize();
        vr
    }

    /// PROBE ONLY: read an arbitrary LUC counter OID's `(current, limit)`.
    /// Generalises [`read_hw_pin_counter`] (pinned to E120) so the §32
    /// probe + provision-e2e can read E121 too. Read AC on E120..E123 is ALW.
    #[cfg(any(feature = "duress-probe-e2e", feature = "duress-provision-e2e"))]
    pub unsafe fn probe_read_counter(&mut self, ctr_oid: u16) -> Option<(u32, u32)> {
        self.ensure_shield().ok()?;
        let mut buf = [0u8; 8];
        match apdu::get_data_object(&mut self.ifx, &mut self.shield, ctr_oid, 0, 8, &mut buf) {
            Ok(8) => apdu::parse_pin_ctr(&buf),
            _ => None,
        }
    }

    /// PROBE ONLY (§32 timing): HMAC auth against the LUC-bound AuthRef
    /// at `oid` via the `auto_state` path — the EXACT production
    /// real-F1D0 verify (fires the E120 LUC). Used to measure whether
    /// the auto-state verify timing matches the plain `probe_hmac_auth_at`
    /// timing, which decides whether the option-B duress "pad" (a second
    /// plain duress verify) is a clean stand-in for the skipped real
    /// (auto-state) verify or needs a matched-LUC duress credential.
    #[cfg(feature = "duress-probe-e2e")]
    pub unsafe fn probe_hmac_auth_luc_at(
        &mut self,
        oid: u16,
        pin: &[u8; 8],
    ) -> Result<(), OptigaError> {
        use zeroize::Zeroize;
        self.ensure_shield()?;
        let mut nonce = [0u8; 16];
        apdu::get_random_auto_state(
            &mut self.ifx, &mut self.shield, apdu::OID_SESSION, &mut nonce,
        )?;
        let mut pin_secret = Self::derive_pin_secret(pin);
        let hmac = Self::hmac_sha256(&pin_secret, &nonce);
        pin_secret.zeroize();
        let r = apdu::hmac_verify_auto_state(
            &mut self.ifx, &mut self.shield, oid, apdu::OID_SESSION, &nonce, &hmac,
        );
        nonce.zeroize();
        r
    }

    /// PROBE ONLY: HMAC challenge-response auth against the AuthRef at
    /// `oid` via the non-LUC `hmac_verify` path (does NOT touch E120).
    /// Returns `Ok(())` on successful auth. Mirrors the non-hw-counter
    /// arm of `authenticate_and_read`, parameterised by OID.
    #[cfg(feature = "duress-probe-e2e")]
    pub unsafe fn probe_hmac_auth_at(
        &mut self,
        oid: u16,
        pin: &[u8; 8],
    ) -> Result<(), OptigaError> {
        use zeroize::Zeroize;
        self.ensure_shield()?;

        // input_data = host_nonce(16) || chip_random(32) || host_tag(16),
        // exactly as `authenticate_and_read`'s compound path.
        let mut host_nonce = [0u8; 16];
        let mut host_tag = [0u8; 16];
        crate::rng::fill(&mut host_nonce).map_err(|_| OptigaError::Transport)?;
        crate::rng::fill(&mut host_tag).map_err(|_| OptigaError::Transport)?;
        let mut chip_random = [0u8; 32];
        apdu::generate_auth_code(
            &mut self.ifx, &mut self.shield,
            apdu::OID_SESSION, &host_nonce, &mut chip_random,
        )?;

        let mut hmac_input = [0u8; 64];
        hmac_input[..16].copy_from_slice(&host_nonce);
        hmac_input[16..48].copy_from_slice(&chip_random);
        hmac_input[48..].copy_from_slice(&host_tag);

        let mut secret = Self::derive_pin_secret(pin);
        let hmac = Self::hmac_sha256(&secret, &hmac_input);
        secret.zeroize();

        let r = apdu::hmac_verify(
            &mut self.ifx, &mut self.shield,
            oid, apdu::OID_SESSION, &hmac_input, &hmac,
        );
        hmac_input.zeroize();
        host_nonce.zeroize();
        host_tag.zeroize();
        chip_random.zeroize();
        r
    }

    /// Provision the attempt counter: write 0, install AC, lock.
    unsafe fn provision_counter(&mut self) -> Result<(), OptigaError> {
        apdu::set_data_object(
            &mut self.ifx, &mut self.shield,
            apdu::OID_COUNTER, &[0u8],
        )?;

        // LcsO-ratchet guard (same rationale as provision_auth_ref /
        // provision_user_oid). F1E1's Change = Conf(E140) — still
        // writable via shield when LcsO < Op, but blocked at LcsO=Op.
        let mut cur_meta = [0u8; 128];
        let cur_len = apdu::get_metadata(
            &mut self.ifx, &mut self.shield,
            apdu::OID_COUNTER, &mut cur_meta,
        ).unwrap_or(0);
        if cur_len > 0 && apdu::is_metadata_operational(&cur_meta, cur_len) {
            secure_log!(
                "[OPTIGA/prov] OID 0x{:04x} (counter) at LcsO=Operational — \
                 skipping set_metadata + lock_oid",
                apdu::OID_COUNTER
            );
            return Ok(());
        }

        let (meta, meta_len) = apdu::build_metadata_counter();
        apdu::set_metadata(
            &mut self.ifx, &mut self.shield,
            apdu::OID_COUNTER, &meta[..meta_len],
        )?;

        // F1E1 is the boot-readable provisioned sentinel (Read=ALW,
        // Change=Conf(E140)); locking its metadata is safe because the
        // sentinel write in `factory_reset_body` is a DATA write satisfied by
        // the Conf(E140) shield arm, which still works at LcsO=Operational.
        self.verify_and_lock(apdu::OID_COUNTER, &meta[..meta_len])
    }

    /// Fail-closed placeholder for the S-2 trust-anchor pool.
    ///
    /// The candidate trust-anchor inventory for this SKU/revision is exactly
    /// `{0xE0E8, 0xE0E9, 0xE0EF}`. `0xE0E3` is a device-certificate object
    /// (`DataType=0x12`); `0xE0E4..=0xE0E7` are not members of the pool. The
    /// prior helper targeted those wrong objects and assumed that omitting a
    /// DataType tag from a metadata update removed an existing
    /// `DataType=TrustAnchor (0x11)`. That transition is not established by
    /// the current driver or silicon receipts.
    ///
    /// This function therefore performs **no APDU at all** and fails before a
    /// write. The matching compile-time fence in `nsc/mod.rs` prevents the
    /// feature pair from producing a runnable image. A future replacement must
    /// pin the SKU/revision and prove, fail-fast, the initial type, exact data
    /// write/readback, replacement type, ACs, and final lifecycle state before
    /// any irreversible lock. Until then S-2 remains a production blocker.
    ///
    /// # Safety
    /// Touches the OPTIGA APDU stack; caller holds `&mut self` and an active
    /// shielded connection.
    #[cfg(all(
        feature = "optiga-lock-operational",
        feature = "factory-production-irreversible-im-sure"
    ))]
    unsafe fn lockdown_ta_pool(&mut self) -> Result<(), OptigaError> {
        const TA_POOL: [u16; 3] = [0xE0E8, 0xE0E9, 0xE0EF];
        let _ = TA_POOL;
        secure_log!(
            "[OPTIGA/ta] REFUSED: E0E8/E0E9/E0EF neutralization lacks a \
             reviewed type/data/AC/lifecycle readback contract"
        );
        Err(OptigaError::Status(0xEC))
    }

    /// Full-device provisioning.
    ///
    /// Idempotent against a partially-provisioned device: if the PBS is
    /// already in place the shielded connection re-establishes using the
    /// cached copy, and the subsequent data writes go through because the
    /// user OIDs are `Change = Auto(F1D0) OR Conf(0xE140)` — the `Conf` arm
    /// is satisfied by the shielded connection.
    fn store_objects(
        &mut self,
        entropy: &[u8; 32],
        master_secret: &[u8; 32],
        vk: &[u8; 32],
        bootstrap_vk: &[u8; 32],
        pin: &[u8; 8],
    ) -> Result<(), OptigaError> {
        self.init()?;
        secure_log!("[OPTIGA/prov] init OK");

        // 1. PBS (plain write to E140 at LcsO=Creation). Unconditionally
        // runs on every provisioning attempt under `optiga-trust-m`:
        // setup_pbs_no_handshake is idempotent against LcsO=Creation
        // (Change AC defaults to ALW until metadata is installed, and
        // then the `LcsO<op OR Conf(E140)` branch allows the plaintext
        // re-write), so re-running it on a partially-provisioned chip
        // just rewrites the same 64 bytes.
        //
        // Pre-#24 this was gated on `!self.shield.pbs_loaded`, which
        // worked when `load_pbs` only set `pbs_loaded=true` after an
        // unsealed flash read succeeded. Post-#24, `load_pbs` always
        // succeeds (PBS is derived from the configured device root on every boot),
        // so that gate would now skip the chip-side write on every
        // fresh chip — which is exactly the bug surfaced on Phase-A
        // hardware validation of 2026-04-20.
        //
        // Under `optiga-no-shield` the entire PBS setup is skipped —
        // we never use shielded connection, so we never write E140.
        // Keeps a chip with a bricked E140 (LcsO=op with lost PBS)
        // usable for all non-PRL paths. See
        // `docs/secure-elements/optiga-brick-postmortem.md` §7.
        #[cfg(feature = "optiga-no-shield")]
        {
            secure_log!("[OPTIGA/prov] step 1 skipped (feature optiga-no-shield; PRL is disabled)");
        }
        #[cfg(not(feature = "optiga-no-shield"))]
        {
            secure_log!("[OPTIGA/prov] step 1: setup_pbs_no_handshake");
            if let Err(e) = self.setup_pbs_no_handshake() {
                secure_log!("[OPTIGA/prov] setup_pbs FAILED: {:?}", e);
                return Err(e);
            }
            // After PBS write (2 SetData ops) the chip refuses further
            // writes until it is hard-reset. Pulse RST (PE4) to clear
            // the wedge; NV OIDs (including the PBS we just wrote) survive.
            #[cfg(feature = "stm32u585")]
            self.hard_reset_and_reinit()?;
        }

        // Bring the Shielded Connection up now — every subsequent APDU
        // (auth_ref + user OIDs + counter) needs `Conf(E140)` satisfied
        // on re-provisioning. `send_command` auto-wraps once shield is
        // active. On a fresh chip the Change ACs on F1D1..F1D4 default
        // to ALW so the shield is technically optional, but bringing it
        // up unconditionally makes the flow identical on fresh and
        // partially-provisioned chips — and idempotency is the
        // non-negotiable contract (mod.rs:716-720). No-op under
        // `optiga-no-shield`.
        secure_log!("[OPTIGA/prov] step 1b: ensure_shield (pre-auth_ref)");
        self.ensure_shield()?;

        // 1c. (optiga-hw-counter) Silicon PIN counter MUST be provisioned
        //     BEFORE auth_ref — the F1D0 Execute AC will reference E120
        //     via LUC, and the one-way LcsO ratchet on F1D0 means we
        //     only get one shot at getting that reference right.
        //     Passes pin_secret so the recovery path (when a prior
        //     buggy provisioning left Exec=NEV on E120) can authenticate
        //     against F1D0 before rewriting E120 metadata.
        #[cfg(feature = "optiga-hw-counter")]
        {
            secure_log!("[OPTIGA/prov] step 1c: provision_hw_pin_counter (E120)");
            let mut pin_secret = Self::derive_pin_secret(pin);
            let result = unsafe {
                self.provision_hw_pin_counter(Self::HW_PIN_CTR_LIMIT, &pin_secret)
            };
            pin_secret.zeroize();
            if let Err(e) = result {
                secure_log!("[OPTIGA/prov] provision_hw_pin_counter FAILED: {:?}", e);
                return Err(e);
            }
            #[cfg(feature = "stm32u585")]
            {
                self.hard_reset_and_reinit()?;
                secure_log!("[OPTIGA/prov] post-hw-ctr: re-establishing shield");
                self.ensure_shield()?;
            }
        }

        // 2. Auth reference
        secure_log!("[OPTIGA/prov] step 2: provision_auth_ref");
        {
            let mut pin_secret = Self::derive_pin_secret(pin);
            let result = unsafe { self.provision_auth_ref(&pin_secret) };
            pin_secret.zeroize();
            if let Err(e) = result {
                secure_log!("[OPTIGA/prov] provision_auth_ref FAILED: {:?}", e);
                return Err(e);
            }
            #[cfg(feature = "stm32u585")]
            {
                self.hard_reset_and_reinit()?;
                secure_log!("[OPTIGA/prov] post-auth_ref: re-establishing shield");
                self.ensure_shield()?;
            }
        }

        // 3. User data. While shielded is disabled we drop the Conf(E140)
        // arm from Read AC — entropy/master_secret become Auto(F1D0) only,
        // same protection level as VK. I²C traffic is plaintext for now.
        // Cycle Close/Open between OIDs: on this chip, after ~3 consecutive
        // SetData operations the chip starts returning Status=0xff. The
        // pattern goes away if we release + reacquire the application
        // context, suggesting a per-session work buffer or transient-OID
        // slot gets exhausted otherwise.
        // Each user OID provision = 2 SetData writes (metadata + data),
        // and the chip wedges after 2 writes per session. Hard-pulse RST
        // between every OID so each provision starts in a fresh session.
        // The RST also wipes the chip's PRL session, so `hard_reset_and_
        // reinit` clears our `shield.active` flag and we re-handshake
        // before the next provision call (`Conf(E140)` satisfaction
        // requirement).
        macro_rules! prov_with_reset {
            ($name:literal, $call:expr) => {{
                secure_log!("[OPTIGA/prov] step: {}", $name);
                $call.map_err(|e| {
                    secure_log!("[OPTIGA/prov] {} write FAILED: {:?}", $name, e); e
                })?;
                #[cfg(feature = "stm32u585")]
                {
                    self.hard_reset_and_reinit()?;
                    secure_log!("[OPTIGA/prov] post-{}: re-establishing shield", $name);
                    self.ensure_shield()?;
                }
            }};
        }

        unsafe {
            prov_with_reset!("entropy", self.provision_user_oid(apdu::OID_ENTROPY, entropy, false));
            prov_with_reset!("master_secret", self.provision_user_oid(apdu::OID_MASTER_SECRET, master_secret, false));
            prov_with_reset!("vk", self.provision_user_oid(apdu::OID_VK, vk, false));
            prov_with_reset!("bootstrap_vk", self.provision_user_oid(apdu::OID_BOOTSTRAP_VK, bootstrap_vk, false));
            prov_with_reset!("counter", self.provision_counter());
        }

        // S-2 sacrificial candidate: neutralize the enumerated trust-anchor
        // slots after the reversible steps in this experimental sequence.
        // These feature gates do not make this a production ceremony or settle
        // E140/credential ordering, HSM policy, recovery, or complete slot
        // scope. Owner authorization naming a sacrificial part and reviewed
        // test plan are still required. An already-locked slot is skipped.
        #[cfg(all(
            feature = "optiga-lock-operational",
            feature = "factory-production-irreversible-im-sure"
        ))]
        unsafe {
            self.lockdown_ta_pool().map_err(|e| {
                secure_log!("[OPTIGA/prov] lockdown_ta_pool FAILED: {:?}", e);
                e
            })?;
        }

        // Stale-log hazard: this message used to say "6 OIDs written +
        // locked". Under the current feature set (`optiga-lock-
        // operational` OFF) and the LcsO-Op skip path, `lock_oid` is
        // either a no-op (feature off) or not called at all (object
        // already Op). Say exactly what happened.
        secure_log!(
            "[OPTIGA] Provisioning complete (data for 6 OIDs written; \
             no lock_oid calls this run — `optiga-lock-operational` \
             OFF and/or LcsO already Op)"
        );
        Ok(())
    }

    /// §32 duress (decoy) provisioning on OPTIGA. Mirrors the duress
    /// portion of [`store_objects`] for the SECOND credential set:
    ///   - E121 LUC counter (`Change=Auto(F1D8)`, `Exec=ALW`)
    ///   - F1D8 AuthRef (`Execute=LUC(E121)` — matched-LUC, validated on
    ///     silicon 2026-05-20) keyed by `duress_pin`
    ///   - 4 decoy data OIDs (half_O / master / vk / bvk) gated on F1D8
    ///
    /// Assumes the REAL wallet is already provisioned (PBS + shield up):
    /// duress provisioning runs immediately after `store_objects` in the
    /// same wizard step, so PBS/E140 + the shielded connection are live.
    /// Every credential stays LcsO=Creation — nothing is locked, so the
    /// decoy is fully re-provisionable / recoverable. Uses the same
    /// hard-reset-between-writes dance as `store_objects` (the chip wedges
    /// after ~2-3 consecutive SetData ops per session).
    #[cfg(feature = "duress-pin")]
    fn store_duress_objects(
        &mut self,
        half_o: &[u8; 32],
        master_secret: &[u8; 32],
        vk: &[u8; 32],
        bootstrap_vk: &[u8; 32],
        duress_pin: &[u8; 8],
    ) -> Result<(), OptigaError> {
        use zeroize::Zeroize;

        secure_log!("[OPTIGA/duress] store_duress_objects start");
        self.ensure_shield()?;

        // 1. E121 duress LUC counter — Change=Auto(F1D8), Exec=ALW.
        //    UNENFORCED limit (firmware never reads it for lockout); the
        //    duress unlock resets it. High limit so it never trips.
        //
        //    Idempotency (mirrors provision_hw_pin_counter): once E121 is
        //    Change=Auto(F1D8), a DATA re-write needs F1D8 auth (which we
        //    don't have on a fresh-mnemonic re-provision). So if E121 is
        //    already correctly gated, SKIP — its current value is
        //    immaterial (the counter is unenforced; a non-zero leftover
        //    from a prior run is harmless).
        let e121_already = {
            let mut m = [0u8; 128];
            let n = unsafe {
                apdu::get_metadata(&mut self.ifx, &mut self.shield, apdu::OID_PIN_CTR_DURESS, &mut m)
            }.unwrap_or(0);
            n > 0
                && apdu::metadata_change_is_auto_oid(&m, n, apdu::OID_DURESS_AUTH_REF)
                && apdu::metadata_execute_is_always(&m, n)
        };
        if e121_already {
            secure_log!("[OPTIGA/duress] E121 already gated on F1D8 — skipping (idempotent)");
        } else {
            unsafe {
                let ctr_data = apdu::encode_pin_ctr(0, Self::DURESS_CTR_LIMIT);
                apdu::set_data_object(
                    &mut self.ifx, &mut self.shield, apdu::OID_PIN_CTR_DURESS, &ctr_data,
                )?;
                let (cmeta, clen) = apdu::build_metadata_pin_ctr_oid(apdu::OID_DURESS_AUTH_REF);
                apdu::set_metadata(
                    &mut self.ifx, &mut self.shield, apdu::OID_PIN_CTR_DURESS, &cmeta[..clen],
                )?;
            }
            secure_log!("[OPTIGA/duress] E121 counter provisioned");
            #[cfg(feature = "stm32u585")]
            { self.hard_reset_and_reinit()?; self.ensure_shield()?; }
        }

        // 2. F1D8 duress AuthRef — Execute=LUC(E121).
        {
            let mut secret = Self::derive_pin_secret(duress_pin);
            let r = unsafe {
                apdu::set_data_object(
                    &mut self.ifx, &mut self.shield, apdu::OID_DURESS_AUTH_REF, &secret,
                )
            };
            secret.zeroize();
            r?;
            // Duress F1D8 keeps Change=ALW (change_is_auto=false): never locked,
            // blanked via ALW on reset. S-1 Auto hardening is real-F1D0 only.
            let (ameta, alen) =
                apdu::build_metadata_auth_ref_luc_oid(apdu::OID_PIN_CTR_DURESS, false);
            unsafe {
                apdu::set_metadata(
                    &mut self.ifx, &mut self.shield, apdu::OID_DURESS_AUTH_REF, &ameta[..alen],
                )?;
            }
            secure_log!("[OPTIGA/duress] F1D8 AuthRef (Execute=LUC(E121)) provisioned");
            #[cfg(feature = "stm32u585")]
            { self.hard_reset_and_reinit()?; self.ensure_shield()?; }
        }

        // 3. Decoy data OIDs, each gated on F1D8 (mirror the real layout's
        //    require_shielded_read=false). Hard-reset between each.
        macro_rules! duress_oid {
            ($name:literal, $oid:expr, $data:expr) => {{
                secure_log!("[OPTIGA/duress] write {}", $name);
                unsafe {
                    self.provision_user_oid_authref(
                        $oid, $data, apdu::OID_DURESS_AUTH_REF, false,
                    )
                }?;
                #[cfg(feature = "stm32u585")]
                { self.hard_reset_and_reinit()?; self.ensure_shield()?; }
            }};
        }
        duress_oid!("duress entropy", apdu::OID_DURESS_ENTROPY, half_o);
        duress_oid!("duress master", apdu::OID_DURESS_MASTER_SECRET, master_secret);
        duress_oid!("duress vk", apdu::OID_DURESS_VK, vk);
        duress_oid!("duress bvk", apdu::OID_DURESS_BOOTSTRAP_VK, bootstrap_vk);

        secure_log!("[OPTIGA/duress] store_duress_objects complete");
        Ok(())
    }

    /// Read the 1-byte attempt counter, returning `None` if the object is
    /// uninitialized (fresh chip) or the read fails for any other reason.
    unsafe fn read_counter_raw(&mut self) -> Option<u8> {
        let mut buf = [0u8; 4];
        match apdu::get_data_object(
            &mut self.ifx, &mut self.shield,
            apdu::OID_COUNTER, 0, 1, &mut buf,
        ) {
            Ok(n) if n > 0 => Some(buf[0]),
            _ => None,
        }
    }

    /// Authenticate with PIN and read every protected data object.
    ///
    /// Flow:
    /// 1. Ensure shielded connection
    /// 2. Read + gate on attempt counter
    /// 3. Write counter += 1 (decrement-before-verify pattern)
    /// 4. `GetRandom` for the HMAC challenge
    /// 5. Host computes `HMAC-SHA256(pin_secret, challenge)`
    /// 6. `DecryptSym` in HMAC-verify mode — chip recomputes and compares
    /// 7. On success: read entropy, master_secret, VK, bootstrap_vk
    /// 8. Reset counter to 0
    /// 9. Cache everything, return master_secret
    fn authenticate_and_read(&mut self, pin: &[u8; 8]) -> Result<[u8; 32], OptigaError> {
        secure_log!("[OPTIGA/auth] authenticate_and_read: start");
        self.init()?;
        // CRIT-8 requires every PIN-auth APDU to traverse the shielded
        // connection, including the TRNG challenge fetch. Re-establish
        // (or reuse the existing) session before any further APDU.
        self.ensure_shield()?;

        unsafe {
            // Under `optiga-hw-counter` the silicon counter at E120
            // replaces the F1E1 soft counter:
            //   - "attempts exceeded" gate is enforced by the chip via
            //     LUC(E120) on F1D0's Execute AC; a locked-out chip fails
            //     hmac_verify with Sta=0xFF (Last Error Code 0x0E, counter
            //     threshold exceeded) without consuming further silicon
            //     budget. The firmware-visible lockout verdict comes from
            //     the E120 read below, not from the status byte.
            //   - The pre-verify bump (and its CRIT-6 readback) is gone
            //     — silicon does the bump atomically, a glitch that
            //     suppresses it also suppresses the verify itself
            //     (same APDU, same path).
            //   - A separate "NotProvisioned" probe: read E120; if it
            //     returns (0, 0) or fails, the chip is unprovisioned.
            #[cfg(feature = "optiga-hw-counter")]
            {
                match self.read_hw_pin_counter() {
                    Some((_, 0)) | None => {
                        secure_log!("[OPTIGA/auth] hw-ctr unset → NotProvisioned");
                        return Err(OptigaError::NotProvisioned);
                    }
                    Some((curr, limit)) => {
                        secure_log!("[OPTIGA/auth] hw-ctr = {}/{}", curr, limit);
                        // SAFETY/COVERAGE: this gate is validated by
                        // inspection, not by an e2e run on silicon.
                        // Exercising it requires burning `limit` (=32)
                        // consecutive wrong PINs on a single bench chip,
                        // with unknown cumulative wear on the E120 OID
                        // from repeated reset-on-success cycles. We have
                        // one remaining provisioned TRUSTMV3SHIELDTOBO1;
                        // the risk of an unknown-unknown on the last
                        // bench chip outweighs the marginal coverage
                        // versus inspection + LUC increment proven
                        // by optiga-hw-counter-e2e. The silicon-side
                        // LUC enforcement itself (E120 increments on
                        // failed verify) is covered by that e2e; the
                        // firmware-side `curr >= limit` compare is a
                        // trivial conditional kept short on purpose.
                        if curr >= limit {
                            return Err(OptigaError::PinLocked);
                        }
                    }
                }
            }
            #[cfg(not(feature = "optiga-hw-counter"))]
            let _ = {
                let attempts = match self.read_counter_raw() {
                    Some(v) if v == RESET_SENTINEL => {
                        secure_log!("[OPTIGA/auth] counter = RESET_SENTINEL → NotProvisioned");
                        return Err(OptigaError::NotProvisioned);
                    }
                    Some(v) => {
                        secure_log!("[OPTIGA/auth] counter = {}", v);
                        v
                    }
                    None => {
                        secure_log!("[OPTIGA/auth] counter read returned None → NotProvisioned");
                        return Err(OptigaError::NotProvisioned);
                    }
                };
                if attempts >= MAX_ATTEMPTS {
                    return Err(OptigaError::PinLocked);
                }

                // 3. Bump counter BEFORE verify (so a power cut can't refund
                //    the attempt). CRIT-6 fix: add a read-back assertion
                //    that the written value actually landed — a glitch or
                //    bus-MITM that produces a nominal-success response for
                //    a failed write would otherwise leave the counter at
                //    `attempts` and allow a re-try. On mismatch we refuse
                //    the whole unlock and zeroize; the counter is advisory
                //    but the firmware-level assertion is not.
                let new_attempts = attempts + 1;
                secure_log!("[OPTIGA/auth] bumping counter to {}", new_attempts);
                if let Err(e) = apdu::set_data_object(
                    &mut self.ifx, &mut self.shield,
                    apdu::OID_COUNTER, &[new_attempts],
                ) {
                    secure_log!("[OPTIGA/auth] counter bump FAILED: {:?}", e);
                    return Err(e);
                }
                let readback = self.read_counter_raw().ok_or(OptigaError::PinLocked)?;
                if readback != new_attempts {
                    secure_log!(
                        "[OPTIGA/auth] counter readback mismatch: wrote {} read {} — PinLocked",
                        new_attempts, readback
                    );
                    return Err(OptigaError::PinLocked);
                }
            };

            // 4. Acquire auth-code session + HMAC verify.
            //
            // Under `optiga-hw-counter` the wire shape must match
            // Trezor's `optiga_set_auto_state` exactly (GetRandom with
            // no optional_data, 16B nonce, DecryptSym with a 18B data
            // block of `nonce_oid || nonce`). That specific shape is
            // what triggers LUC evaluation on F1D0's Execute AC — the
            // 64-byte compound shape used by the Infineon
            // `hmac_verify_with_authorization_reference.c` example
            // successfully authorizes F1D0 for subsequent reads on
            // this silicon but does NOT advance the LUC counter.
            // Verified 2026-04-22 by reading back stored E120 metadata
            // (`d3 03 40 e1 20` present) while observing E120.current
            // stayed at 0 after a failed auth.
            //
            // Non-hw-counter builds keep the original shape unchanged.
            #[cfg(feature = "optiga-hw-counter")]
            let (mut hmac, verify_result) = {
                let mut pin_secret = Self::derive_pin_secret(pin);

                let mut nonce = [0u8; 16];
                secure_log!("[OPTIGA/auth] GetRandom auto-state (nonce_oid=0xE100, 16B)");
                if let Err(e) = apdu::get_random_auto_state(
                    &mut self.ifx, &mut self.shield,
                    apdu::OID_SESSION, &mut nonce,
                ) {
                    pin_secret.zeroize();
                    secure_log!("[OPTIGA/auth] GetRandom auto-state FAILED: {:?}", e);
                    return Err(e);
                }

                let mut hmac = Self::hmac_sha256(&pin_secret, &nonce);
                pin_secret.zeroize();

                secure_log!(
                    "[OPTIGA/auth] DecryptSym auto-state verify (key=0xF1D0, data=18B, trezor shape)"
                );
                let r = apdu::hmac_verify_auto_state(
                    &mut self.ifx, &mut self.shield,
                    apdu::OID_AUTH_REF, apdu::OID_SESSION,
                    &nonce, &hmac,
                );
                nonce.zeroize();
                (hmac, r)
            };
            #[cfg(not(feature = "optiga-hw-counter"))]
            let (mut hmac, verify_result) = {
                // Infineon "hmac_verify_with_authorization_reference"
                // shape: input_data = host_nonce(16) || chip_random(32)
                //                     || host_tag(16).
                let mut host_nonce = [0u8; 16];
                let mut host_tag = [0u8; 16];
                crate::rng::fill(&mut host_nonce).map_err(|_| OptigaError::Transport)?;
                crate::rng::fill(&mut host_tag).map_err(|_| OptigaError::Transport)?;
                let mut chip_random = [0u8; 32];
                secure_log!("[OPTIGA/auth] GenerateAuthCode (session=0xE100, opt=16, random=32)");
                if let Err(e) = apdu::generate_auth_code(
                    &mut self.ifx, &mut self.shield,
                    apdu::OID_SESSION,
                    &host_nonce,
                    &mut chip_random,
                ) {
                    secure_log!("[OPTIGA/auth] GenerateAuthCode FAILED: {:?}", e);
                    return Err(e);
                }

                let mut hmac_input = [0u8; 64];
                hmac_input[..16].copy_from_slice(&host_nonce);
                hmac_input[16..48].copy_from_slice(&chip_random);
                hmac_input[48..].copy_from_slice(&host_tag);
                secure_log!(
                    "[OPTIGA/auth] input[0..4]={:02x}{:02x}{:02x}{:02x} (opt) / [16..20]={:02x}{:02x}{:02x}{:02x} (chip) / [48..52]={:02x}{:02x}{:02x}{:02x} (arb)",
                    hmac_input[0], hmac_input[1], hmac_input[2], hmac_input[3],
                    hmac_input[16], hmac_input[17], hmac_input[18], hmac_input[19],
                    hmac_input[48], hmac_input[49], hmac_input[50], hmac_input[51]
                );

                let mut pin_secret = Self::derive_pin_secret(pin);
                let hmac = Self::hmac_sha256(&pin_secret, &hmac_input);
                pin_secret.zeroize();

                secure_log!("[OPTIGA/auth] hmac_verify via DecryptSym (input=64B)");
                let r = apdu::hmac_verify(
                    &mut self.ifx, &mut self.shield,
                    apdu::OID_AUTH_REF,
                    apdu::OID_SESSION,
                    &hmac_input,
                    &hmac,
                );
                hmac_input.zeroize();
                host_nonce.zeroize();
                host_tag.zeroize();
                chip_random.zeroize();
                (hmac, r)
            };

            hmac.zeroize();

            match verify_result {
                Ok(()) => {
                    secure_log!("[OPTIGA/auth] hmac_verify OK");
                }
                Err(e) => {
                    secure_log!("[OPTIGA/auth] hmac_verify FAILED: {:?}", e);
                    // Diagnostics only (bring-up builds): fetch the chip's
                    // Last Error Code — 0x2F = authorization failure (wrong
                    // PIN), 0x0E = LUC threshold exceeded, 0x07 = access
                    // conditions not satisfied. Control flow deliberately
                    // does NOT branch on it: lockout is pre-checked via
                    // E120 above, and any chip-level refusal maps to
                    // PinIncorrect below.
                    #[cfg(feature = "debug-log")]
                    {
                        if let Some(lec) =
                            apdu::read_last_error(&mut self.ifx, &mut self.shield)
                        {
                            secure_log!("[OPTIGA/auth] last error code = 0x{:02x}", lec);
                        }
                    }
                    // `Sta` is only 0x00/0xFF on V3 silicon (see
                    // `apdu::parse_response`): a `Status(_)` here is "the
                    // chip answered no", which — with the lockout already
                    // pre-checked — means wrong PIN. Bus-level faults keep
                    // their own variants so callers can distinguish.
                    return Err(match e {
                        OptigaError::Status(_) => OptigaError::PinIncorrect,
                        other => other,
                    });
                }
            }

            // 7. Read protected data now that Auto(F1D0) is authorized
            let mut entropy = [0u8; 32];
            apdu::get_data_object(
                &mut self.ifx, &mut self.shield,
                apdu::OID_ENTROPY, 0, 32, &mut entropy,
            )?;

            let mut master_secret = [0u8; 32];
            apdu::get_data_object(
                &mut self.ifx, &mut self.shield,
                apdu::OID_MASTER_SECRET, 0, 32, &mut master_secret,
            )?;

            let mut vk = [0u8; 32];
            apdu::get_data_object(
                &mut self.ifx, &mut self.shield,
                apdu::OID_VK, 0, 32, &mut vk,
            )?;

            let mut bootstrap_vk = [0u8; 32];
            apdu::get_data_object(
                &mut self.ifx, &mut self.shield,
                apdu::OID_BOOTSTRAP_VK, 0, 32, &mut bootstrap_vk,
            )?;

            // 8. Reset counter now that we know the PIN was right.
            //    Under `optiga-hw-counter` the authoritative counter is
            //    E120 (silicon) — reset it via `reset_hw_pin_counter`,
            //    which SetDataObject-writes `[0,0,0,0, L,L,L,L]`.
            //    E120's Change AC is `Auto(OID_AUTH_REF)`, satisfied
            //    because the `hmac_verify` above just activated F1D0
            //    in this session. F1E1 stays written-zeroed on the
            //    non-hw-counter path for back-compat of factory_reset.
            #[cfg(feature = "optiga-hw-counter")]
            {
                if let Err(e) = self.reset_hw_pin_counter() {
                    secure_log!("[OPTIGA/auth] reset_hw_pin_counter FAILED: {:?}", e);
                    return Err(e);
                }
            }
            #[cfg(not(feature = "optiga-hw-counter"))]
            apdu::set_data_object(
                &mut self.ifx, &mut self.shield,
                apdu::OID_COUNTER, &[0u8],
            )?;

            // 9. Cache & return
            let blob = crate::crypto::encrypt_entropy_blob(&entropy, &master_secret);
            self.entropy_blob_cache.copy_from_slice(&blob);
            self.blob_cached.set_true();

            self.vk_cache.copy_from_slice(&vk);
            self.vk_cached = true;

            self.bootstrap_vk_cache.copy_from_slice(&bootstrap_vk);
            self.bootstrap_vk_cached = true;

            self.remaining = MAX_ATTEMPTS;

            entropy.zeroize();
            crate::fi::zeroize_barrier();
            vk.zeroize();
            bootstrap_vk.zeroize();

            secure_log!("[OPTIGA] Unlocked: entropy + VKs cached");
            Ok(master_secret)
        }
    }

    /// Admin factory reset — wipes every user-data OID via the shielded
    /// connection path (Conf(0xE140)), so it works even if the PIN is lost.
    ///
    /// Steps:
    /// 1. Ensure shielded connection active.
    /// 2. Overwrite F1D1..F1D4 with zeros (Change is satisfied by Conf).
    /// 3. Overwrite F1D0 (auth ref) with zeros (Change = Conf only).
    /// 4. Reset the attempt counter to 0 only when the dual-SE owner supplies
    ///    a strict three-source transient authorization value.
    ///
    /// After this the device reports `is_provisioned()` → false? Not
    /// quite: LcsO is still Operational and metadata is still in place.
    /// The next call to `provision()` will rewrite the data (the
    /// `Auto OR Conf` AC lets it through via Conf) and everything resumes
    /// normally. We deliberately leave LcsO alone — raising it is
    /// irreversible, and that would prevent future rotation.
    /// Factory reset — zero out F1D0..F1D4 and mark the counter as
    /// RESET_SENTINEL. Triggered by `trigger_lockout_wipe` on PIN
    /// exhaustion. Works at any LcsO (including Operational): LcsO=Op
    /// freezes metadata, not data, and every user OID's Change AC has
    /// a `Conf(E140)` arm satisfied by the Shielded Connection.
    ///
    /// # Preconditions
    /// - Caller must have called `init` previously or this call will
    ///   OpenApplication again (cheap).
    /// - `shield.pbs_loaded` must be true (set by `setup_pbs_no_handshake`
    ///   or `load_pbs_from_device_root`). `ensure_shield()` below will return
    ///   `OptigaError::Shield` otherwise — correct failure, not a
    ///   regression.
    ///
    /// Standalone callers intentionally skip the legacy E120 transient-auth
    /// reset rather than generating a platform-only authorization secret.
    /// Dual-SE callers use `DualSecureElement::reset_optiga_for_admin`, which
    /// supplies a value drawn from STM32 + OPTIGA + SE050.
    pub fn factory_reset(&mut self) -> Result<(), OptigaError> {
        self.factory_reset_with_optional_transient_secret(None)
    }

    /// Dual-SE factory reset entry: optionally reset E120 using a transient
    /// authorization value that the owning `DualSecureElement` already drew
    /// through the strict three-source combiner. This explicit handoff avoids
    /// borrowing the global backend recursively from inside `OptigaTrustM`.
    #[cfg(all(feature = "optiga-hw-counter", not(feature = "optiga-lock-operational")))]
    pub(crate) fn factory_reset_with_transient_secret(
        &mut self,
        transient_secret: &mut [u8; 32],
    ) -> Result<(), OptigaError> {
        self.factory_reset_with_optional_transient_secret(Some(transient_secret))
    }

    fn factory_reset_with_optional_transient_secret(
        &mut self,
        transient_secret: Option<&mut [u8; 32]>,
    ) -> Result<(), OptigaError> {
        // Run the reset body; on ANY error, drop the cached "chip is
        // ready" / "shield is up" state so the next `init()` does a real
        // soft_reset + re-handshake instead of early-returning. A failed
        // shielded handshake (e.g. the host computed a PBS the chip
        // doesn't hold — exactly what happens the first time a board
        // built with the old `otp-hardcoded-master-key`-derived PBS is
        // reflashed with the DHUK-derived one) leaves the chip's
        // presentation layer in an SCTR=0x40 alert state; without this,
        // every subsequent plain APDU bounces with the same alert and a
        // later `setup_pbs_no_handshake` (which would rewrite E140 with
        // the new PBS at LcsO=Creation) fails with `Transport`.
        let r = self.factory_reset_body(transient_secret);
        if r.is_err() {
            self.ready = false;
            self.shield.active = false;
        }
        r
    }

    fn factory_reset_body(
        &mut self,
        transient_secret: Option<&mut [u8; 32]>,
    ) -> Result<(), OptigaError> {
        self.init()?;
        // Bring the Shielded Connection up so every subsequent write
        // satisfies the `Conf(E140)` arm of the user OID's Change AC.
        // `authenticate_and_read` already brings it up on the PIN-lockout
        // path, but standalone/test callers may call `factory_reset`
        // directly — be explicit so correctness doesn't depend on caller
        // ordering.
        self.ensure_shield()?;

        // HIGH-18 fix: arm the shared wipe flag BEFORE starting any
        // destructive OID write. A power loss between two OID wipes
        // would otherwise leave OPTIGA in a half-wiped state where
        // (say) OID_ENTROPY is zeroed but OID_AUTH_REF is intact —
        // the next boot would successfully verify the stale PIN and
        // read zeros for entropy. Recovery on the next boot is
        // gated on `is_wipe_armed()` in main.rs so we just re-run
        // the same reset sequence (the Conf(E140) AC path still
        // works because PBS is intact).
        #[cfg(feature = "stm32u585")]
        unsafe {
            let _ = crate::hw::flash::arm_wipe_flag();
        }

        // Before wiping F1D0, reset E120 to (0, limit) via transient-
        // auth (Trezor parity). Without this step the silicon LUC
        // counter carries over every wipe and eventually saturates,
        // soft-bricking the device. Safe to fail tolerantly: if the
        // transient-auth step errors (transport glitch, chip state
        // issue), we still proceed with the wipe — the soft-brick
        // risk is probabilistic and a failed reset here just defers
        // the fix to the next wipe cycle, it doesn't corrupt anything.
        // Non-hw-counter builds skip this — the counter isn't
        // silicon-enforced on that path.
        //
        // S-1: ALSO skipped under `optiga-lock-operational`. The transient-auth
        // reset rewrites F1D0 (relies on `Change=ALW`), which is impossible once
        // F1D0 is `Auto(F1D0)`+locked. Under the locked profile E120 carry-over
        // is moot anyway: a forgotten-PIN wipe abandons this OID range (the seed
        // is destroyed below) and re-provisioning bumps to a fresh range rather
        // than resetting E120 in place.
        #[cfg(all(feature = "optiga-hw-counter", not(feature = "optiga-lock-operational")))]
        unsafe {
            if let Some(secret) = transient_secret {
                if let Err(e) = self.reset_e120_via_transient_auth(secret) {
                    secure_log!(
                        "[OPTIGA] Factory reset: E120 reset via transient-auth FAILED: {:?} — \
                         counter will carry over, next wipe cycle will retry",
                        e
                    );
                    // Fall through — do not abort the wipe.
                }
            } else {
                secure_log!(
                    "[OPTIGA] Factory reset: no three-source transient auth — \
                     skipping optional E120 reset and continuing wipe"
                );
            }
        }

        let blank = [0u8; 32];
        unsafe {
            // Write the sentinel FIRST so a crash mid-wipe still produces a
            // chip that boots as unprovisioned — the wizard on the next
            // boot will overwrite every OID cleanly. If we wrote the
            // sentinel last, a crash would leave stale user data behind a
            // "provisioned"-looking counter, reproducing the SE050 trap.
            apdu::set_data_object(
                &mut self.ifx, &mut self.shield,
                apdu::OID_COUNTER, &[RESET_SENTINEL],
            )?;

            // S-1: under the locked profile F1D0 is `Auto(F1D0)`+LcsO=Operational,
            // so this blank-write would FAIL (the reset path holds the shield but
            // has not HMAC-verified the PIN). We deliberately skip it — F1D0 holds
            // ONLY the PIN-HMAC key with Read=NEV, which is information-free once
            // the entropy shares it XORs against (F1D1 half_O + F1D2 master,
            // blanked just below via the Conf(E140) arm) are gone. Dev builds
            // (F1D0 Change=ALW) still blank it for hygiene.
            #[cfg(not(feature = "optiga-lock-operational"))]
            apdu::set_data_object(&mut self.ifx, &mut self.shield, apdu::OID_AUTH_REF, &blank)?;
            apdu::set_data_object(&mut self.ifx, &mut self.shield, apdu::OID_ENTROPY, &blank)?;
            apdu::set_data_object(&mut self.ifx, &mut self.shield, apdu::OID_MASTER_SECRET, &blank)?;
            apdu::set_data_object(&mut self.ifx, &mut self.shield, apdu::OID_VK, &blank)?;
            apdu::set_data_object(&mut self.ifx, &mut self.shield, apdu::OID_BOOTSTRAP_VK, &blank)?;
        }

        // §32: also blank the duress (decoy) OIDs. Best-effort (NOT `?`):
        // the real wipe above already succeeded, and a stale decoy half_o
        // left on OPTIGA reveals nothing once the SE050 decoy half is gone
        // (the admin-delete policy on the SE050 duress objects makes
        // `factory_reset_admin` delete them) — XOR split means one half is
        // information-free. We blank anyway for hygiene + parity. F1D8
        // (Change=ALW) and F1D9/F1DA/F1DB/F1D6 (Change=Auto(F1D8) OR
        // Conf(E140), satisfied by the shield) are all writable here; we
        // deliberately do NOT touch E121 (its Change=Auto(F1D8) has no
        // Conf escape, and it's an unenforced high-limit counter — its
        // stale value is harmless and its metadata must persist for the
        // re-provision idempotency skip). Re-provisioning the decoy after
        // a wipe rewrites all four via the same Conf(E140) path the real
        // OIDs use, so the wipe→re-provision recovery path is intact.
        #[cfg(feature = "duress-pin")]
        unsafe {
            let _ = apdu::set_data_object(&mut self.ifx, &mut self.shield, apdu::OID_DURESS_AUTH_REF, &blank);
            let _ = apdu::set_data_object(&mut self.ifx, &mut self.shield, apdu::OID_DURESS_ENTROPY, &blank);
            let _ = apdu::set_data_object(&mut self.ifx, &mut self.shield, apdu::OID_DURESS_MASTER_SECRET, &blank);
            let _ = apdu::set_data_object(&mut self.ifx, &mut self.shield, apdu::OID_DURESS_VK, &blank);
            let _ = apdu::set_data_object(&mut self.ifx, &mut self.shield, apdu::OID_DURESS_BOOTSTRAP_VK, &blank);
            secure_log!("[OPTIGA] Factory reset: duress OIDs blanked (best-effort)");
        }

        self.zeroize_caches_internal();
        self.remaining = MAX_ATTEMPTS;

        secure_log!("[OPTIGA] Factory reset complete");
        Ok(())
    }

    /// "Nuclear" counter wipe — forces F1E1 to RESET_SENTINEL without
    /// requiring a shielded connection, even on a chip where F1E1's
    /// Change AC has been previously set to `Conf(E140)` by full
    /// provisioning.
    ///
    /// Strategy (valid only at LcsO=Creation):
    /// 1. Rewrite F1E1 metadata with Change = Always (metadata itself is
    ///    always mutable at LcsO=Creation, regardless of the data Change AC).
    /// 2. Plaintext `set_data_object(F1E1, 0xFF)` — succeeds because the
    ///    step-1 metadata relaxed the gate.
    /// 3. Read back and verify F1E1 == RESET_SENTINEL.
    ///
    /// After this returns Ok, `check_provisioned()` reads F1E1, gets
    /// `0xFF`, and returns `false` — the next boot of the standalone
    /// build will run the first-boot wizard fresh.
    ///
    /// This function is the fallback used when the regular shielded
    /// `factory_reset` path cannot run because OTP is blank and the
    /// PBS-derived shield key can't be loaded (see the
    /// `optiga-factory-reset-hw` Makefile target).
    ///
    /// Preconditions:
    /// - Chip's OIDs must still be at LcsO=Creation (they are in every
    ///   build that doesn't enable `optiga-lock-operational`).
    /// - Intended to be called with `optiga-no-shield` active so
    ///   `ensure_shield()` is a no-op; the internal `set_metadata` and
    ///   `set_data_object` calls therefore traverse plaintext I2C.
    pub fn nuclear_reset_counter(&mut self) -> Result<(), OptigaError> {
        self.init()?;
        secure_log!("[OPTIGA/nuclear] init OK");

        // Step 1: relax F1E1's Change AC back to Always.
        let (relaxed_meta, meta_len) = apdu::build_metadata_relaxed();
        secure_log!(
            "[OPTIGA/nuclear] step 1: set_metadata(F1E1, Change=Always) len={}",
            meta_len
        );
        unsafe {
            apdu::set_metadata(
                &mut self.ifx,
                &mut self.shield,
                apdu::OID_COUNTER,
                &relaxed_meta[..meta_len],
            )?;
        }

        // Step 2: write RESET_SENTINEL. Plaintext now accepted.
        secure_log!("[OPTIGA/nuclear] step 2: set_data_object(F1E1, 0xFF)");
        unsafe {
            apdu::set_data_object(
                &mut self.ifx,
                &mut self.shield,
                apdu::OID_COUNTER,
                &[RESET_SENTINEL],
            )?;
        }

        // Step 3: verify.
        let counter = unsafe { self.read_counter_raw() };
        match counter {
            Some(v) if v == RESET_SENTINEL => {
                secure_log!("[OPTIGA/nuclear] step 3: F1E1 = 0xFF OK");
                Ok(())
            }
            other => {
                secure_log!(
                    "[OPTIGA/nuclear] step 3 FAILED: F1E1 = {:?}, expected 0x{:02x}",
                    other, RESET_SENTINEL
                );
                Err(OptigaError::Transport)
            }
        }
    }

    /// End-to-end roundtrip exercising the `factory_reset` primitive on a
    /// live chip. Scope is deliberately the wipe PRIMITIVE — NOT the
    /// PIN-lockout-triggers-wipe flow, which is a separate integration
    /// deferred to a later test.
    ///
    /// Flow:
    /// 1. Provision F1D0..F1D4 + F1E1 with known-distinct test vectors
    ///    via `store_objects` — the same code path production uses.
    /// 2. Call `authenticate_and_read(test_pin)` — must succeed and
    ///    return the exact `master_secret` we provisioned.
    /// 3. Call `factory_reset()` — the path `trigger_lockout_wipe`
    ///    invokes on PIN exhaustion.
    /// 4. Read F1E1 raw; must equal `RESET_SENTINEL` (0xFF).
    /// 5. Call `authenticate_and_read(test_pin)` again — must fail
    ///    with `OptigaError::NotProvisioned` (the sentinel path).
    /// 6. `check_provisioned()` must return false — the integration
    ///    contract that triggers the first-boot wizard on next boot.
    ///
    /// Uses real production OIDs (`apdu::OID_*`) because `factory_reset`
    /// hardcodes them. That means this test DESTROYS any wallet state
    /// already on the chip. Caller (the `make optiga-admin-wipe-e2e`
    /// target) is responsible for running on a dev bench chip.
    ///
    /// Idempotent across runs: `store_objects` is idempotent against a
    /// partially-provisioned chip (user OIDs' `Change = Auto(F1D0) OR
    /// Conf(E140)` — the Conf arm keeps data writable via the shield
    /// regardless of what the previous run left behind).
    ///
    /// LcsO-safety: all writes this test performs go through
    /// `set_data_object` or `set_metadata` (the latter with
    /// `lock_oid` gated behind `optiga-lock-operational`, which is NOT
    /// implied by `optiga-admin-wipe-e2e`). No OID is promoted to
    /// `LcsO=Operational` by running this test.
    #[cfg(feature = "optiga-admin-wipe-e2e")]
    pub fn run_admin_wipe_roundtrip(&mut self) -> Result<(), OptigaError> {
        self.init()?;

        // Distinct byte patterns so a mixed-up readback (e.g. returning
        // entropy when we asked for master_secret) is immediately visible.
        let entropy: [u8; 32] = [0x11; 32];
        let master_secret: [u8; 32] = [0x22; 32];
        let vk: [u8; 32] = [0x33; 32];
        let bootstrap_vk: [u8; 32] = [0x44; 32];
        let test_pin: [u8; 8] = *b"testopt!";

        // ---- 1. Provision with known test data ----
        secure_log!("[OPTIGA-E2E-ADMIN] step 1: provision via store_objects");
        self.store_objects(&entropy, &master_secret, &vk, &bootstrap_vk, &test_pin)?;
        secure_log!("[OPTIGA-E2E-ADMIN] step 1: provision OK");

        // ---- 2. Pre-wipe unlock must succeed AND return the right master_secret ----
        secure_log!("[OPTIGA-E2E-ADMIN] step 2: pre-wipe authenticate_and_read");
        let recovered = match self.authenticate_and_read(&test_pin) {
            Ok(ms) => ms,
            Err(e) => {
                secure_log!("[OPTIGA-E2E-ADMIN] step 2 FAILED: unlock pre-wipe returned {:?}", e);
                return Err(e);
            }
        };
        if recovered != master_secret {
            secure_log!("[OPTIGA-E2E-ADMIN] step 2 FAILED: master_secret mismatch");
            return Err(OptigaError::Shield);
        }
        secure_log!("[OPTIGA-E2E-ADMIN] step 2: pre-wipe unlock OK (master_secret matches)");

        // ---- 3. Run factory_reset (the path PIN lockout triggers) ----
        secure_log!("[OPTIGA-E2E-ADMIN] step 3: factory_reset");
        self.factory_reset()?;
        secure_log!("[OPTIGA-E2E-ADMIN] step 3: factory_reset OK");

        // ---- 4. Counter must now read RESET_SENTINEL (0xFF) ----
        //    Read AC on F1E1 is ALW, no shield or PIN required.
        let counter = unsafe { self.read_counter_raw() };
        match counter {
            Some(v) if v == RESET_SENTINEL => {
                secure_log!("[OPTIGA-E2E-ADMIN] step 4: counter = RESET_SENTINEL OK");
            }
            other => {
                secure_log!(
                    "[OPTIGA-E2E-ADMIN] step 4 FAILED: counter = {:?}, expected 0x{:02x}",
                    other, RESET_SENTINEL
                );
                return Err(OptigaError::Shield);
            }
        }

        // ---- 5. Post-wipe unlock must return NotProvisioned ----
        //    This is the key integration contract: the sentinel path in
        //    `authenticate_and_read` short-circuits BEFORE bumping the
        //    counter, so a wiped chip cannot have its lockout counter
        //    re-exhausted by an attacker spamming unlock attempts.
        secure_log!("[OPTIGA-E2E-ADMIN] step 5: post-wipe authenticate_and_read");
        match self.authenticate_and_read(&test_pin) {
            Err(OptigaError::NotProvisioned) => {
                secure_log!("[OPTIGA-E2E-ADMIN] step 5: unlock returned NotProvisioned OK");
            }
            Ok(_) => {
                secure_log!("[OPTIGA-E2E-ADMIN] step 5 FAILED: unlock SUCCEEDED after wipe");
                return Err(OptigaError::Shield);
            }
            Err(e) => {
                secure_log!(
                    "[OPTIGA-E2E-ADMIN] step 5 FAILED: unlock returned {:?} (expected NotProvisioned)",
                    e
                );
                return Err(e);
            }
        }

        // ---- 6. is_provisioned() must return false ----
        //    Boot-path contract: main.rs checks this to decide whether to
        //    run the first-boot wizard. If it still returns true after
        //    factory_reset, the wizard would be skipped on next boot and
        //    the device would sit in a wiped-but-locked state.
        if self.check_provisioned() {
            secure_log!("[OPTIGA-E2E-ADMIN] step 6 FAILED: check_provisioned() returned true after wipe");
            return Err(OptigaError::Shield);
        }
        secure_log!("[OPTIGA-E2E-ADMIN] step 6: check_provisioned() = false OK");

        // ---- 7. Post-test hygiene: leave page 125 alone ----
        //    Earlier iteration of this test called `erase_admin_page()`
        //    here to clear the wipe-in-progress flag that
        //    `factory_reset` arms. The problem: on a dual-SE bench
        //    chip, page 125 ALSO holds the SE050 admin PIN. Erasing
        //    it from an OPTIGA-only test silently breaks any
        //    subsequent dual-SE admin-wipe test on the same chip (SE050
        //    objects survive with stale user PIN; admin-auth delete has
        //    no PIN to use).
        //
        //    The armed flag is vestigial in an OPTIGA-only build —
        //    the boot-time resume path at main.rs is gated on
        //    `any(feature = "se050", feature = "dual-se")`. On the
        //    next OPTIGA-only boot it's inert. On a later dual-SE
        //    flash against the same chip it would fire an extra
        //    `factory_reset_admin`, which is idempotent (page 125
        //    admin PIN either present → uses it, or blank → iterative
        //    sweep). So leaving the flag armed is harmless; erasing
        //    it cross-contaminates the SE050 admin slot.
        //
        //    Conclusion: flag stays armed. Dual-SE admin-wipe test
        //    does its own cleanup including page-125 erase at the
        //    right moment.

        Ok(())
    }

    fn zeroize_caches_internal(&mut self) {
        self.entropy_blob_cache.zeroize();
        self.blob_cached.set_false();
        self.vk_cache.zeroize();
        self.vk_cached = false;
        self.bootstrap_vk_cache.zeroize();
        self.bootstrap_vk_cached = false;
        // MEDIUM-1 (audit secret-lifecycle 20260611): also tear down the
        // live Shielded-Connection session keys so they don't outlive the
        // unlock session in SRAM. Lock / idle-wipe / panic reach here via
        // `nsc::zeroize_sensitive_state`; `ensure_shield` re-handshakes on
        // the next OPTIGA APDU.
        self.shield.zeroize_session();
    }
}

// ---------------------------------------------------------------------------
// WalletStore implementation
// ---------------------------------------------------------------------------

use crate::secure_element::{SeError, UnlockError, WalletStore};

impl WalletStore for OptigaTrustM {
    fn is_provisioned(&mut self) -> bool {
        self.check_provisioned()
    }

    fn provision(
        &mut self,
        entropy: &[u8; 32],
        master_secret: &[u8; 32],
        vk: &[u8; 32],
        bootstrap_vk: &[u8; 32],
        pin: &[u8; 8],
    ) -> Result<(), SeError> {
        self.store_objects(entropy, master_secret, vk, bootstrap_vk, pin)
            .map_err(|_| SeError::InternalError)?;

        self.vk_cache.copy_from_slice(vk);
        self.vk_cached = true;
        self.bootstrap_vk_cache.copy_from_slice(bootstrap_vk);
        self.bootstrap_vk_cached = true;
        self.remaining = MAX_ATTEMPTS;

        Ok(())
    }

    #[cfg(feature = "duress-pin")]
    fn provision_duress(
        &mut self,
        entropy: &[u8; 32],
        master_secret: &[u8; 32],
        vk: &[u8; 32],
        bootstrap_vk: &[u8; 32],
        duress_pin: &[u8; 8],
    ) -> Result<(), SeError> {
        // `entropy` here is OPTIGA's decoy half_O (DualSE pre-split it).
        self.store_duress_objects(entropy, master_secret, vk, bootstrap_vk, duress_pin)
            .map_err(|_| SeError::InternalError)
    }

    #[cfg(feature = "duress-pin")]
    fn duress_is_provisioned(&mut self) -> bool {
        if self.init().is_err() {
            return false;
        }
        if self.ensure_shield().is_err() {
            return false;
        }
        // Liveness via the duress AuthRef metadata (Read on F1D8 data is
        // NEV, but metadata is always readable). Non-empty metadata at
        // F1D8 == the decoy credential set was provisioned.
        let mut meta = [0u8; 128];
        matches!(
            unsafe {
                apdu::get_metadata(
                    &mut self.ifx, &mut self.shield, apdu::OID_DURESS_AUTH_REF, &mut meta,
                )
            },
            Ok(n) if n > 0
        )
    }

    fn unlock(&mut self, pin: &[u8; 8]) -> Result<[u8; 32], UnlockError> {
        self.authenticate_and_read(pin).map_err(|e| match e {
            OptigaError::PinIncorrect => {
                if self.remaining > 0 {
                    self.remaining -= 1;
                }
                UnlockError::PinIncorrect
            }
            OptigaError::PinLocked => UnlockError::PinLocked,
            _ => UnlockError::InternalError,
        })
    }

    fn read_entropy_blob(&mut self, buf: &mut [u8]) -> Result<usize, SeError> {
        if !self.blob_cached.is_true_fi() || buf.len() < crate::crypto::ENTROPY_BLOB_LEN {
            return Err(SeError::SlotNotFound);
        }
        buf[..crate::crypto::ENTROPY_BLOB_LEN]
            .copy_from_slice(&self.entropy_blob_cache);
        Ok(crate::crypto::ENTROPY_BLOB_LEN)
    }

    fn read_vk(&mut self, buf: &mut [u8]) -> Result<usize, SeError> {
        if !self.vk_cached || buf.len() < 32 {
            return Err(SeError::SlotNotFound);
        }
        buf[..32].copy_from_slice(&self.vk_cache);
        Ok(32)
    }

    fn read_bootstrap_vk(&mut self, buf: &mut [u8]) -> Result<usize, SeError> {
        if !self.bootstrap_vk_cached || buf.len() < 32 {
            return Err(SeError::SlotNotFound);
        }
        buf[..32].copy_from_slice(&self.bootstrap_vk_cache);
        Ok(32)
    }

    fn remaining_attempts(&mut self) -> u8 {
        self.remaining
    }

    fn sync_remaining_with_mcu(&mut self, mcu_used: u8) {
        let mcu_remaining = MAX_ATTEMPTS.saturating_sub(mcu_used);
        if mcu_remaining < self.remaining {
            self.remaining = mcu_remaining;
        }
    }

    fn zeroize_caches(&mut self) {
        self.zeroize_caches_internal();
    }

    fn random(&mut self, buf: &mut [u8]) -> Result<(), SeError> {
        OptigaTrustM::random(self, buf).map_err(|_| SeError::InternalError)
    }

    fn random_optiga(&mut self, buf: &mut [u8]) -> Result<(), SeError> {
        OptigaTrustM::random(self, buf).map_err(|_| SeError::InternalError)
    }

    fn pin_attempt_count(&mut self) -> Option<u8> {
        // MEDIUM-1 (audit pin-unlock 20260625): under `optiga-hw-counter`
        // (the production config) the authoritative lockout is the silicon
        // LUC at E120; the F1E1 soft counter is frozen at its provisioned 0
        // (it doubles as the is_provisioned liveness sentinel and is never
        // bumped/reset on this path). Reading F1E1 here made the boot
        // reconcile compare page-124 against a CONSTANT — a dead detector
        // that also false-wiped on a benign wrong-PIN-then-reboot. Return
        // the live E120 `current` (attempts used) instead, so the MCU↔OPTIGA
        // directional rollback check is meaningful. Page 124 is precharged,
        // so MCU-leading states are conservatively charged and only E120
        // leading page 124 proves rollback. The
        // read needs the shielded link, so bring it up first; if it can't be
        // established (early boot / unprovisioned chip) return None so the
        // reconcile treats the leg as "unavailable, skip" rather than
        // agreeing on a stale 0.
        #[cfg(feature = "optiga-hw-counter")]
        {
            if self.ensure_shield().is_err() {
                return None;
            }
            // SAFETY: exclusive `&mut self`; touches the OPTIGA APDU stack.
            match unsafe { self.read_hw_pin_counter() } {
                // (curr, 0) or None ⇒ unprovisioned / read failure.
                Some((_, 0)) | None => None,
                // Saturate to the user-facing MAX_ATTEMPTS scale (E120 limit
                // is 32, MCU page-124 caps at 10) before the directional
                // `e120_used > mcu_used` comparison.
                Some((curr, _limit)) => Some(curr.min(MAX_ATTEMPTS as u32) as u8),
            }
        }
        #[cfg(not(feature = "optiga-hw-counter"))]
        {
            // SAFETY: `read_counter_raw` touches the OPTIGA APDU stack;
            // we hold `&mut self` so exclusive access is established.
            unsafe { self.read_counter_raw() }
        }
    }

    fn factory_reset_admin(&mut self) -> Result<(), SeError> {
        self.factory_reset().map_err(|_| SeError::InternalError)
    }
}

#[cfg(feature = "e2e-test")]
impl OptigaTrustM {
    /// e2e-only counterpart of `Se050::_e2e_force_remaining_to_max`.
    /// Mirrors the post-reboot stale-cache state without power-cycling
    /// the board. See the SE050 version for full rationale.
    pub fn _e2e_force_remaining_to_max(&mut self) {
        self.remaining = MAX_ATTEMPTS;
    }
}

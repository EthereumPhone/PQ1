//! Negative coverage for `pqsigner-hal`.
//!
//! Each test here names an assumption the HAL spec (and the CLAUDE.md
//! invariants the secure world enforces on top of it) holds, and
//! asserts that the assumption is actually enforced — either by the
//! type system (`static_assertions::assert_not_impl_any!`) or at
//! runtime.
//!
//! The HAL crate is trait-only, so its negative surface is small:
//! mostly "this derive must not be present" and "this stable contract
//! must not silently shift". That is *exactly* the kind of thing a
//! refactor can break without anyone noticing — these tests exist to
//! make that loud.

use pqsigner_hal::{
    BootStage, BootStateData, Buttonset, HalError, KeySelector, Otp, OtpRange, SpiBus, TamperCause,
};
use static_assertions::{
    assert_impl_all, assert_not_impl_any, const_assert, const_assert_eq,
};

// ===========================================================================
// FAMILY 1 — Secret-typed derives MUST NOT exist on `KeySelector`
// ===========================================================================
//
// `KeySelector::Software(&[u8; 32])` carries a reference to a raw
// AES-256 key. The source file calls this out explicitly:
//
//     // Intentionally NOT `Debug`: the `Software` variant carries a
//     // key reference and a derived `Debug` impl would print it.
//
// If a future refactor (or a careless `#[derive(Debug)]` for "easier
// logging") adds these impls, the secure world can leak a Software key
// via any `debug!`, `dbg!`, or `assert_eq!` failure that prints the
// selector. The same logic forbids `PartialEq`/`Eq`: a derived
// equality impl on a Software-key reference is a non-constant-time
// byte compare — a textbook timing oracle.

#[test]
fn negative_key_selector_must_not_impl_debug() {
    // Compile-time assertion via static_assertions.
    // If this trait bound starts to hold, the build breaks here
    // citing "secret-key leakage via Debug — see src/lib.rs comment".
    assert_not_impl_any!(KeySelector<'static>: core::fmt::Debug);
}

#[test]
fn negative_key_selector_must_not_impl_partial_eq() {
    // A `==` on `KeySelector::Software(&k1) == KeySelector::Software(&k2)`
    // would compare two AES-256 keys in non-constant time, exposing a
    // first-differing-byte timing oracle.
    assert_not_impl_any!(KeySelector<'static>: core::cmp::PartialEq);
}

#[test]
fn negative_key_selector_must_not_impl_eq() {
    assert_not_impl_any!(KeySelector<'static>: core::cmp::Eq);
}

#[test]
fn negative_key_selector_must_not_impl_hash() {
    // Hashing a Software key with the default hasher would leak via
    // any data structure that prints its keys on debug.
    assert_not_impl_any!(KeySelector<'static>: core::hash::Hash);
}

#[test]
fn negative_key_selector_must_not_impl_display() {
    assert_not_impl_any!(KeySelector<'static>: core::fmt::Display);
}

// ===========================================================================
// FAMILY 2 — Non-secret derive contracts MUST be preserved
// ===========================================================================
//
// These are the inverse: types whose derives are required (callers
// rely on them). A future "let's drop Debug to save binary size" pass
// would silently break logging — pin it down here.

#[test]
fn negative_hal_error_must_impl_debug_eq_copy() {
    assert_impl_all!(HalError: core::fmt::Debug, core::cmp::Eq, Copy, Clone);
}

#[test]
fn negative_otp_range_must_impl_debug_eq_copy() {
    assert_impl_all!(OtpRange: core::fmt::Debug, core::cmp::Eq, Copy, Clone);
}

#[test]
fn negative_tamper_cause_must_impl_debug_eq_copy() {
    assert_impl_all!(TamperCause: core::fmt::Debug, core::cmp::Eq, Copy, Clone);
}

#[test]
fn negative_buttonset_must_impl_default_debug_eq_copy() {
    assert_impl_all!(Buttonset: Default, core::fmt::Debug, core::cmp::Eq, Copy, Clone);
}

#[test]
fn negative_boot_state_data_must_impl_default_debug_eq_copy() {
    assert_impl_all!(BootStateData: Default, core::fmt::Debug, core::cmp::Eq, Copy, Clone);
}

#[test]
fn negative_boot_stage_must_impl_debug_eq_copy() {
    assert_impl_all!(BootStage: core::fmt::Debug, core::cmp::Eq, Copy, Clone);
}

// ===========================================================================
// FAMILY 3 — `Buttonset::default()` MUST NOT report a pressed button
// ===========================================================================
//
// CLAUDE.md, Invariant #4 ("All secrets only in TrustZone secure
// world") is enforced in part by the trusted-UI confirm dialog
// (`secure/src/ui/confirm.rs`) reading button state through this
// trait. If `Buttonset::default()` were ever `{ left: true, right: true }`,
// an early-boot poll (before GPIO is wired) would return a "both
// buttons held" event that the confirm-UI could interpret as the user
// agreeing to a sign. The trait spec is silent on what `default()`
// means, but the safe choice — and the existing one — is "no input".
// Pin it.

#[test]
fn negative_buttonset_default_is_not_pressed() {
    let b = Buttonset::default();
    assert!(
        !b.left,
        "Buttonset::default().left must be false — a default-pressed button could spoof a trusted-UI confirm"
    );
    assert!(
        !b.right,
        "Buttonset::default().right must be false — see CLAUDE.md trusted-UI invariant"
    );
}

#[test]
fn negative_boot_state_data_default_is_all_zero() {
    let d = BootStateData::default();
    for (i, &b) in d.raw.iter().enumerate() {
        assert_eq!(
            b, 0,
            "BootStateData::default().raw[{i}] must be 0 — a non-zero default would be ambient data that the FSBL could mistake for a prior boot record",
        );
    }
}

// ===========================================================================
// FAMILY 4 — `BootStage::ALL` is the documented boot ordering
// ===========================================================================
//
// CLAUDE.md "Lifecycle" pins the boot order: Clocks → SAU/GTZC →
// crypto self-tests → buses → UI → SE. The `BootStage::ALL` array is
// the machine-readable form of that. If anyone reorders the array
// "for tidiness" or drops a stage during a refactor, the secure-world
// `for stage in BootStage::ALL { … }` loop would silently bring up
// peripherals in the wrong order — e.g. crypto self-tests before SAU
// is locked down. Pin the exact sequence.

#[test]
fn negative_boot_stage_all_has_exactly_six_entries() {
    const_assert_eq!(BootStage::ALL.len(), 6);
    assert_eq!(BootStage::ALL.len(), 6);
}

#[test]
fn negative_boot_stage_all_exact_documented_order() {
    let expected = [
        BootStage::Clocks,
        BootStage::TrustZone,
        BootStage::Crypto,
        BootStage::Buses,
        BootStage::Ui,
        BootStage::Se,
    ];
    assert_eq!(
        BootStage::ALL, expected,
        "BootStage::ALL reordered — CLAUDE.md Lifecycle says \
         Clocks → TrustZone → Crypto → Buses → Ui → Se. Reordering can \
         (e.g.) run the SAES self-test before SAU lockdown."
    );
}

#[test]
fn negative_boot_stage_all_covers_every_variant() {
    // Match exhaustively to guarantee any future enum-variant addition
    // forces a corresponding `ALL` update (this match will fail to
    // compile when a new BootStage is added without a corresponding
    // arm — that is the desired forcing function).
    let mut seen = [false; 6];
    for stage in BootStage::ALL {
        let idx = match stage {
            BootStage::Clocks => 0,
            BootStage::TrustZone => 1,
            BootStage::Crypto => 2,
            BootStage::Buses => 3,
            BootStage::Ui => 4,
            BootStage::Se => 5,
        };
        assert!(
            !seen[idx],
            "BootStage::{stage:?} appears twice in ALL — duplicates would re-run a boot stage"
        );
        seen[idx] = true;
    }
    assert!(
        seen.iter().all(|&b| b),
        "BootStage::ALL is missing at least one variant: {seen:?}"
    );
}

// ===========================================================================
// FAMILY 5 — `HalError` variant identity is stable
// ===========================================================================
//
// Drivers map peripheral faults to one of these variants. If two
// variants ever started comparing equal (e.g. someone accidentally
// re-uses a discriminant) the secure world's branch on `match err`
// would mis-classify the fault. Pairwise distinctness.

#[test]
fn negative_hal_error_pairwise_distinct() {
    let all = [
        HalError::BusFault,
        HalError::Timeout,
        HalError::BadParam,
        HalError::Unsupported,
        HalError::Corrupt,
    ];
    for i in 0..all.len() {
        for j in (i + 1)..all.len() {
            assert_ne!(
                all[i], all[j],
                "HalError::{:?} must not compare equal to HalError::{:?}",
                all[i], all[j]
            );
        }
    }
}

#[test]
fn negative_otp_range_named_distinct_from_reserved() {
    // `Reserved(_)` is for "future use" but must never collide with a
    // named range — otherwise a fuzzed `Reserved(0)` could be routed
    // to the AntiRollback partition.
    assert_ne!(OtpRange::AntiRollback, OtpRange::Reserved(0));
    assert_ne!(OtpRange::MasterKey, OtpRange::Reserved(1));
    assert_ne!(OtpRange::BhkProvisioned, OtpRange::Reserved(2));
    // And payload-distinct Reserved values must not collapse.
    assert_ne!(OtpRange::Reserved(0), OtpRange::Reserved(1));
    assert_ne!(OtpRange::Reserved(0), OtpRange::Reserved(255));
}

#[test]
fn negative_tamper_cause_other_distinct_from_named() {
    assert_ne!(TamperCause::BackupVoltage, TamperCause::Other(0));
    assert_ne!(TamperCause::LseClock, TamperCause::Other(1));
    assert_ne!(TamperCause::CryptoFault, TamperCause::Other(2));
    assert_ne!(TamperCause::DebugWhileLocked, TamperCause::Other(3));
    assert_ne!(TamperCause::Other(0), TamperCause::Other(1));
}

// ===========================================================================
// FAMILY 6 — Size / layout: secret-bearing variant doesn't bloat the type
// ===========================================================================
//
// `KeySelector::Software(&[u8; 32])` stores a reference, not the bytes
// inline. If a refactor turned it into `Software([u8; 32])` the
// 32-byte payload would sit on the stack on every call site — and a
// stack-leak (e.g. from a panic backtrace under `debug-log`) would
// expose the key. Pin the size to "just a pointer + discriminant".

#[test]
fn negative_key_selector_does_not_inline_software_key() {
    let sz = core::mem::size_of::<KeySelector<'static>>();
    // On 64-bit hosts: 8 (pointer) + a few bytes of discriminant.
    // On 32-bit hosts: 4 + discriminant. The 32-byte inline form
    // would be at least 32 bytes plus padding.
    let ptr = core::mem::size_of::<&'static [u8; 32]>();
    assert!(
        sz <= ptr * 2 + 8,
        "KeySelector<'_> grew to {sz} bytes — likely someone inlined the \
         Software key by value, which puts raw key bytes on the stack of \
         every Saes::aes256_ecb call site. Keep it as a reference.",
    );
    const_assert!(core::mem::size_of::<KeySelector<'static>>() <= 32);
}

// ===========================================================================
// FAMILY 7 — `Platform` aggregate associated-type bounds
// ===========================================================================
//
// `Platform`'s associated types are bound by their per-peripheral
// trait (`type Rng: Rng`, etc.). If anyone weakens a bound (drops
// `: Rng` from the associated type because "it's already a trait
// type"), the secure world can plug in any concrete type with the
// right name — including one that doesn't actually satisfy the trait.
// The compile-time check below proves the bounds still hold.

#[test]
fn negative_platform_associated_types_carry_trait_bounds() {
    // Type-level proof: a generic over `P: Platform` can invoke the
    // per-peripheral trait methods directly on its associated types.
    // If the bounds were dropped the helpers below would fail to
    // compile.
    fn _take_rng<P: pqsigner_hal::Platform>(p: &mut P) {
        let r: &mut P::Rng = p.rng();
        let mut buf = [0u8; 1];
        // This call requires `P::Rng: Rng`.
        let _ = <P::Rng as pqsigner_hal::Rng>::fill(r, &mut buf);
    }
    fn _take_sha<P: pqsigner_hal::Platform>(p: &mut P) {
        let s = p.sha256();
        <P::Sha256 as pqsigner_hal::Sha256>::init(s);
        let _ = <P::Sha256 as pqsigner_hal::Sha256>::finalize(s);
    }
    fn _take_otp<P: pqsigner_hal::Platform>(p: &mut P) {
        let o = p.otp();
        let mut buf = [0u8; 1];
        <P::Otp as pqsigner_hal::Otp>::read(o, OtpRange::AntiRollback, &mut buf);
    }
    fn _take_boot<P: pqsigner_hal::Platform>(p: &mut P) {
        let b = p.boot_state();
        let _ = <P::BootState as pqsigner_hal::BootState>::read(b);
    }
    // Just exercising compile-time coherence; no runtime call needed.
    let _ = _take_rng::<crate::DummyForTraitBounds>;
    let _ = _take_sha::<crate::DummyForTraitBounds>;
    let _ = _take_otp::<crate::DummyForTraitBounds>;
    let _ = _take_boot::<crate::DummyForTraitBounds>;
}

// A throwaway Platform impl so the function pointers above resolve.
// Kept minimal — these methods will never be called.
pub struct DummyForTraitBounds;
pub struct DummyRng;
pub struct DummySha;
pub struct DummySaes;
pub struct DummyFlash;
pub struct DummyOtp;
pub struct DummyBoot;
pub struct DummyTamp;
pub struct DummyMask;
pub struct DummyI2c;
pub struct DummySpi;
pub struct DummyButtons;
pub struct DummyUart;

impl pqsigner_hal::Rng for DummyRng {
    fn fill(&mut self, _buf: &mut [u8]) -> Result<(), HalError> {
        Ok(())
    }
}
impl pqsigner_hal::Sha256 for DummySha {
    fn init(&mut self) {}
    fn update(&mut self, _: &[u8]) {}
    fn finalize(&mut self) -> [u8; 32] {
        [0; 32]
    }
}
impl pqsigner_hal::Saes for DummySaes {
    fn aes256_ecb(
        &mut self,
        _: KeySelector<'_>,
        _: &[u8; 16],
        _: &mut [u8; 16],
    ) -> Result<(), HalError> {
        Ok(())
    }
    fn cmac_dhuk(&mut self, _: &[u8], _: &mut [u8; 16]) -> Result<(), HalError> {
        Ok(())
    }
}
impl pqsigner_hal::Flash for DummyFlash {
    fn read(&self, _: u16, _: u16, _: &mut [u8]) {}
    fn program(&mut self, _: u16, _: u16, _: &[u8]) -> Result<(), HalError> {
        Ok(())
    }
    fn erase_page(&mut self, _: u16) -> Result<(), HalError> {
        Ok(())
    }
}
impl pqsigner_hal::Otp for DummyOtp {
    fn read(&self, _: OtpRange, _: &mut [u8]) {}
    fn burn_once(&mut self, _: OtpRange, _: &[u8]) -> Result<(), HalError> {
        Ok(())
    }
}
impl pqsigner_hal::BootState for DummyBoot {
    fn read(&self) -> BootStateData {
        BootStateData::default()
    }
    fn write(&mut self, _: BootStateData) {}
}
impl pqsigner_hal::Tamp for DummyTamp {
    fn arm(&mut self) {}
    fn check(&mut self) -> Option<TamperCause> {
        None
    }
}
impl pqsigner_hal::ConsumptionMask for DummyMask {
    fn randomize(&mut self) {}
}
impl pqsigner_hal::I2cBus for DummyI2c {
    fn xfer(&mut self, _: u8, _: &[u8], _: &mut [u8]) -> Result<usize, HalError> {
        Ok(0)
    }
}
impl pqsigner_hal::SpiBus for DummySpi {
    fn xfer(&mut self, _: &[u8], _: &mut [u8]) -> Result<(), HalError> {
        Ok(())
    }
}
impl pqsigner_hal::Buttons for DummyButtons {
    fn poll(&mut self) -> Buttonset {
        Buttonset::default()
    }
}
impl pqsigner_hal::Uart for DummyUart {
    fn write(&mut self, _: &[u8]) {}
}
impl pqsigner_hal::Platform for DummyForTraitBounds {
    type Rng = DummyRng;
    type Sha256 = DummySha;
    type Saes = DummySaes;
    type Flash = DummyFlash;
    type Otp = DummyOtp;
    type BootState = DummyBoot;
    type Tamp = DummyTamp;
    type ConsumptionMask = DummyMask;
    type I2c = DummyI2c;
    type Spi = DummySpi;
    type Buttons = DummyButtons;
    type Uart = DummyUart;
    fn rng(&mut self) -> &mut DummyRng {
        unimplemented!()
    }
    fn sha256(&mut self) -> &mut DummySha {
        unimplemented!()
    }
    fn saes(&mut self) -> &mut DummySaes {
        unimplemented!()
    }
    fn flash(&mut self) -> &mut DummyFlash {
        unimplemented!()
    }
    fn otp(&mut self) -> &mut DummyOtp {
        unimplemented!()
    }
    fn boot_state(&mut self) -> &mut DummyBoot {
        unimplemented!()
    }
    fn tamp(&mut self) -> &mut DummyTamp {
        unimplemented!()
    }
    fn consumption_mask(&mut self) -> &mut DummyMask {
        unimplemented!()
    }
    fn i2c(&mut self) -> &mut DummyI2c {
        unimplemented!()
    }
    fn spi(&mut self) -> &mut DummySpi {
        unimplemented!()
    }
    fn buttons(&mut self) -> &mut DummyButtons {
        unimplemented!()
    }
    fn uart(&mut self) -> &mut DummyUart {
        unimplemented!()
    }
}

// ===========================================================================
// FAMILY 8 — `Otp::burn_once` monotonicity contract
// ===========================================================================
//
// The trait doc says: "calling [burn_once] twice for the same fuse
// word with disagreeing data must return `HalError::Unsupported`."
// That's a contract on every impl. We can't test all impls from here,
// but we can prove the contract is testable by exercising it against
// a hand-rolled impl that honours it, and asserting that the
// `Unsupported` variant is the agreed-upon rejection signal (rather
// than `BadParam`, which would be confusable with a length error).

#[test]
fn negative_otp_burn_once_rejects_disagreeing_rewrite() {
    struct ContractOtp {
        burnt: Option<Vec<u8>>,
    }
    impl pqsigner_hal::Otp for ContractOtp {
        fn read(&self, _: OtpRange, _: &mut [u8]) {}
        fn burn_once(&mut self, _: OtpRange, data: &[u8]) -> Result<(), HalError> {
            match &self.burnt {
                None => {
                    self.burnt = Some(data.to_vec());
                    Ok(())
                }
                Some(prev) if prev.as_slice() == data => Ok(()),
                Some(_) => Err(HalError::Unsupported),
            }
        }
    }
    let mut o = ContractOtp { burnt: None };
    assert_eq!(o.burn_once(OtpRange::MasterKey, &[1, 2, 3]), Ok(()));
    assert_eq!(o.burn_once(OtpRange::MasterKey, &[1, 2, 3]), Ok(()));
    assert_eq!(
        o.burn_once(OtpRange::MasterKey, &[1, 2, 4]),
        Err(HalError::Unsupported),
        "OTP rewrite with disagreeing bits must signal Unsupported \
         (NOT BadParam, NOT Corrupt) so the secure world can branch on \
         'this fuse was already burnt' vs 'caller passed garbage'.",
    );
}

// ===========================================================================
// FAMILY 9 — `SpiBus::xfer` documented length-equality contract
// ===========================================================================
//
// The trait doc says: "impls require `w.len() == r.len()`." A
// length-mismatch impl would clock garbage on either MOSI or MISO.
// Pin the documented rejection signal so future impls don't return
// e.g. `Timeout` instead.

#[test]
fn negative_spi_mismatched_lengths_rejected() {
    struct ContractSpi;
    impl pqsigner_hal::SpiBus for ContractSpi {
        fn xfer(&mut self, w: &[u8], r: &mut [u8]) -> Result<(), HalError> {
            if w.len() != r.len() {
                return Err(HalError::BadParam);
            }
            Ok(())
        }
    }
    let mut s = ContractSpi;
    let mut r = [0u8; 3];
    assert_eq!(
        s.xfer(&[1, 2], &mut r),
        Err(HalError::BadParam),
        "SpiBus::xfer with w.len() != r.len() must be rejected — clocking \
         mismatched lengths writes/reads undefined bytes on the bus.",
    );
}

// ===========================================================================
// FAMILY 10 — `Sha256::finalize` returns exactly 32 bytes
// ===========================================================================
//
// Return type is `[u8; 32]` already, but this test pins the *call
// site* contract: the secure-world `crate::crypto` consumers treat
// the output as a full SHA-256 digest. If anyone widens the signature
// to `[u8; N]` for some other N, the C10 hash chain breaks. A static
// size assertion makes the breakage land here and not in `c10_sign`.

#[test]
fn negative_sha256_finalize_output_is_32_bytes() {
    fn assert_finalize_returns_32<S: pqsigner_hal::Sha256>(s: &mut S) -> [u8; 32] {
        s.finalize()
    }
    struct ZeroSha;
    impl pqsigner_hal::Sha256 for ZeroSha {
        fn init(&mut self) {}
        fn update(&mut self, _: &[u8]) {}
        fn finalize(&mut self) -> [u8; 32] {
            [0; 32]
        }
    }
    let out = assert_finalize_returns_32(&mut ZeroSha);
    assert_eq!(out.len(), 32);
    const_assert_eq!(core::mem::size_of::<[u8; 32]>(), 32);
}

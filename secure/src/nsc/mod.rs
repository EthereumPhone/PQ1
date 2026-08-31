//! Secure gateway with trusted-UI sign confirmation.
//!
//! Two transports, selected at compile time by the `stm32u585` feature:
//!
//!   * **QEMU mps2-an505** (`not(feature = "stm32u585")`): SysTick-polled
//!     shared-memory mailbox. This is the workaround for QEMU 8.2.2's
//!     broken SG instruction check — `poll_gateway()` runs from the
//!     SysTick handler, reads `CMD`/`ARG0..2` out of NS SRAM, runs
//!     [`dispatch`], writes `RESULT`, and raises `DONE`.
//!   * **Real STM32U585** (`feature = "stm32u585"`): proper ARMv8-M
//!     CMSE `cmse-nonsecure-entry` veneers. The `--cmse-implib` linker
//!     pass emits SG stubs for every `nsc_*` entry point below into
//!     `veneers.o`; the non-secure crate links against that implib and
//!     calls them as regular `extern "C"` functions. There is no
//!     mailbox and no SysTick poll — NS issues `BLXNS` → SG →
//!     secure-state-handler → `BXNS` synchronously. The `cmd_*`
//!     handlers are shared across both transports; the only thing that
//!     changes is who pulls the trigger.
//!
//! Gateway commands are defined in `sphincs_tz_shared::CMD_*`; the
//! authoritative table lives in `CLAUDE.md`. Each command has its own
//! `cmd_*.rs` handler that the QEMU [`dispatch`] and STM32U585 CMSE
//! veneers below both call into.
//!
//! ## Layout
//!
//! This module is split along command boundaries so each `cmd_*` handler
//! lives in its own file and the shared plumbing (state, pointer
//! validation) lives alongside. Adding a new gateway command means
//! creating a new `cmd_*.rs` submodule, adding a match arm in
//! [`dispatch`] (and a CMSE veneer on stm32u585), and wiring up a new
//! `CMD_*` constant in `sphincs_tz_shared`.
//!
//!   * [`state`]         — single `SecureState` singleton + `with_state`
//!     closure accessors. The one and only place `static mut` lives.
//!   * [`ptr_validate`]  — NS SRAM/flash pointer + length validators.

mod cmd_get_init_code;
mod cmd_get_remaining;
mod cmd_get_wallet_address;
mod cmd_is_unlocked;
mod cmd_lock;
mod cmd_offchain_status;
mod cmd_offchain_sync;
mod cmd_request_unlock;
mod cmd_sign_offchain;
mod cmd_sign_userop;
#[cfg(feature = "erc7730-forced-blind")]
mod cmd_sign_userop_forced;
mod cmd_sign_userop_batch;
#[cfg(feature = "e2e-test")]
mod cmd_test_pin_lockout;
#[cfg(all(feature = "stm32u585", feature = "e2e-test"))]
mod cmd_tzic_status;
#[cfg(feature = "prodtest")]
mod prodtest;

// Firmware-update commands. Only built for the STM32U585 target
// because they depend on the bank-2 flash / OTP primitives that the
// QEMU build doesn't model.
#[cfg(feature = "stm32u585")]
mod cmd_fw_abort;
#[cfg(feature = "stm32u585")]
mod cmd_fw_begin;
#[cfg(feature = "stm32u585")]
mod cmd_fw_chunk;
#[cfg(feature = "stm32u585")]
mod cmd_fw_commit;
#[cfg(feature = "stm32u585")]
mod cmd_fw_status;

mod batch_trailers;
mod factory_calldata;
mod ns_ptr;
mod ptr_validate;
mod sig_wrapper;
mod state;
mod trailer;

// Coldcard-class configuration fence: a production claim is valid only when
// the hardware platform and the complete three-source entropy backend are
// selected by value. In particular, `mode-production` without `stm32u585`
// would compile `rng.rs`'s QEMU `/dev/urandom` backend; checking only that an
// RNG-related macro/feature exists is not sufficient evidence of its value.
#[cfg(all(
    feature = "mode-production",
    any(
        not(feature = "stm32u585"),
        not(feature = "dual-se"),
        not(feature = "optiga-trust-m"),
        not(feature = "se050"),
    ),
))]
compile_error!(
    "PRODUCTION_ENTROPY_BACKENDS_REQUIRED: mode-production requires the \
     stm32u585 hardware TRNG plus dual-se (OPTIGA Trust M + SE050). Refusing \
     a production-declared image that could select host randomness or omit a \
     mandatory hardware entropy source."
);

// Refuse to build hardware images that also enable any of the dev-only
// features. `debug-log` and `ui-semihosting` leak secure-world state via
// the semihosting channel; `ui-mirror` streams the OLED over RTT;
// `ui-capture` emits per-frame SHA-256 fingerprints over the secure-log
// channel; `mock-se` substitutes an in-SRAM fake SE; the rest each
// replace some part of the production trust model with a dev-only
// shortcut. Any of these on a `stm32u585` release build is a
// ship-blocker.
//
// Hardware test images opt in by also enabling `e2e-test` (which exposes
// `set_e2e_unlocked` so the automated harness never needs to drive the
// PIN UI). `e2e-test` is the unambiguous "not-shippable" marker, so when
// it's on we permit the other dev features needed to drive the tests
// (`make e2e-hw`, `make test-key-speed`). CI must still gate shipped
// firmware on `e2e-test` being OFF.
#[cfg(all(
    feature = "stm32u585",
    not(debug_assertions),
    not(feature = "e2e-test"),
    not(feature = "dev-testkey"),
    any(
        feature = "debug-log",
        feature = "ui-semihosting",
        feature = "ui-capture",
        feature = "mock-se",
        feature = "otp-hardcoded-master-key",
        feature = "saes-self-test",
        feature = "uart-console",
        feature = "boot-pulse",
        feature = "bhk-hardcoded-master-key",
        feature = "se050-rotate-scp03",
        feature = "se050-scp03-allow-factory-fallback",
        feature = "sca-trigger",
        feature = "ui-oled-bench",
    )
))]
compile_error!(
    "Hardware release builds (stm32u585 + !debug_assertions) must not enable \
     debug-log / ui-semihosting / ui-mirror / ui-capture / mock-se / \
     otp-hardcoded-master-key / bhk-hardcoded-master-key / saes-self-test / \
     uart-console / boot-pulse / se050-rotate-scp03 / \
     se050-scp03-allow-factory-fallback / sca-trigger. These \
     features leak secure-world state, replace the SE with a mock, replace \
     the per-device OTP master key or BHK with a shared compile-time \
     constant, halt the boot flow after a diagnostic, stream diagnostic \
     bytes on PA9 UART, pulse PE13 with boot-progress markers, perform a \
     one-shot irreversible SCP03 key-rotation ceremony then halt, fall back \
     to the published AN12436 factory SCP03 keys on a derived-key mismatch \
     (a fail-OPEN that hands the SE050 channel to attacker-known keys), or \
     toggle a GPIO around security-critical primitives so a ChipWhisperer / \
     NewAE-Scaffold rig can sync trace captures (a fatal leak on a \
     production unit). ERC-7730 dev provenance is guarded separately by the \
     generated root fence plus the mode-production fence below. Hardware test \
     images may opt in by also enabling \
     `e2e-test` (auto-provisioning, non-interactive) or `dev-testkey` \
     (interactive UI, OTP substituted with a compile-time constant)."
);

// ML-KEM inner-wrap ship gate (#28 piece 2b). `mlkem-inner-wrap` routes the
// dual-SE provision/reconstruct through the ML-KEM hybrid wrap, but its
// ct-store (`pq_wrap::ct_store`) is currently SRAM-backed — a QEMU-validation
// stand-in that is LOST on reboot, so a real device could provision but never
// unlock after a power cycle. The persistent flash ct-store + on-silicon
// validation of the hardware key path are piece 2b-d (NOT done). Forbid it on a
// production hardware release; single-boot bench/test images (e2e-test /
// dev-testkey) may opt in to validate the wrap on silicon. NOTE: the QEMU
// dev-key path (`pq_wrap::device_keys` under `not(stm32u585)`) is structurally
// impossible here — a hardware image is always `stm32u585`, which selects the
// real `hw::secret_keys` derivation, never the deterministic dev keys.
#[cfg(all(
    feature = "mlkem-inner-wrap",
    feature = "stm32u585",
    not(debug_assertions),
    not(feature = "e2e-test"),
    not(feature = "dev-testkey"),
))]
compile_error!(
    "mlkem-inner-wrap (#28 piece 2b) must not be in a production hardware \
     release: its ct-store is SRAM-backed (QEMU-validation only — lost on \
     reboot, so unlock-after-power-cycle would fail), and the persistent flash \
     ct-store + on-silicon hardware-key validation (piece 2b-d) are not done. \
     Bench it via a single-boot hardware test image (e2e-test / dev-testkey)."
);
// Belt-and-braces: the canonical ship profile must never carry it.
#[cfg(all(feature = "mode-production", feature = "mlkem-inner-wrap"))]
compile_error!(
    "mode-production and mlkem-inner-wrap are mutually exclusive (#28 piece \
     2b-d not done — SRAM ct-store). Remove mlkem-inner-wrap from production."
);

// Tier-1 channel-key REQUIRE-fence (finding F8c). The denylist fence above
// stops dev/leaky features shipping; this one stops a shipping dual-SE image
// going out with NON-Tier-1 channel-key roots. Without `saes-dhuk`,
// hw::secret_keys::derive_into uses the legacy OTP-master + HKDF arm (not
// SAES-CMAC(DHUK)); without `se050-derived-scp03`, se050::scp03::load_platform_keys
// returns the PUBLISHED AN12436 factory SCP03 keys. A default `make release`
// previously compiled both legacy roots silently — contrary to invariant #3
// (E2E-encrypted SE tunnels; no attacker-known keys on the channel). Make a
// missed opt-in a build error rather than a silent factory-key ship.
//
// Scoped to shipping dual-SE images (the production target). Bench/test images
// opt out via `e2e-test` / `dev-testkey` (the same not-shippable markers the
// denylist fence honours). `bhk` is intentionally NOT required here: enabling
// it without phase-2B silicon provisioning produces zero-keyed derivations, so
// the Tier-2 SE050 split stays a tracked follow-up, not a ship gate.
#[cfg(all(
    feature = "stm32u585",
    not(debug_assertions),
    not(feature = "e2e-test"),
    not(feature = "dev-testkey"),
    feature = "dual-se",
    any(not(feature = "saes-dhuk"), not(feature = "se050-derived-scp03")),
))]
compile_error!(
    "Shipping dual-SE hardware builds (stm32u585 + dual-se + !debug_assertions) \
     must enable BOTH `saes-dhuk` and `se050-derived-scp03` (Tier-1 channel-key \
     roots). Without `saes-dhuk` the SE-tunnel/pairing keys derive from the \
     legacy OTP-master + HKDF path instead of SAES-CMAC(DHUK); without \
     `se050-derived-scp03` the SE050 SCP03 channel uses the PUBLISHED AN12436 \
     factory keys — both violate invariant #3 (no attacker-known keys on the SE \
     channel). Add `saes-dhuk,se050-derived-scp03` to the build (they are in the \
     default RELEASE_FEATURES). Bench/test images opt out with `e2e-test` or \
     `dev-testkey`. Note: `bhk` (Tier-2 SE050 split) is a separate follow-up and \
     must NOT be enabled until phase-2B BHK provisioning exists, or derivations \
     are zero-keyed."
);

// Dedicated guard: `mode-production` + `erc7730-dev-unattested` is a
// contradictory trust claim. This feature does NOT relax an on-device
// attestation gate (none exists); it makes the display state that the
// firmware-pinned Merkle root was generated under the dev-unattested host
// policy. `db_roots.rs` carries a second, generated fence tying the feature to
// the exact root provenance. Production must use a genuinely ERC-8176-verified
// root and must never show the dev warning.
#[cfg(all(
    feature = "mode-production",
    feature = "erc7730-dev-unattested",
))]
compile_error!(
    "mode-production and erc7730-dev-unattested are mutually exclusive. \
     The feature truthfully marks a dev-unattested pinned catalogue and renders \
     its warning page; it does not enable or bypass an on-device verifier. \
     Shipping firmware requires a root generated by real ERC-8176 EAS \
     signature/identity verification, then must drop this feature."
);

// Production liveness fence. The secure-owned IWDG bounds a wedged NS USB
// loop, noninteractive gateway work, and disabled-interrupt deadlocks. Trusted
// physical-input waits receive only the independently idle-bounded exception
// in `hw::iwdg`; omitting the feature silently removes that fail-safe.
#[cfg(all(
    feature = "mode-production",
    feature = "stm32u585",
    not(feature = "iwdg"),
))]
compile_error!(
    "stm32u585 + mode-production requires `iwdg`. The production watchdog \
     bounds NS/secure hangs; trusted-UI waits remain limited by the 120 s \
     secure inactivity timer. Build both worlds through `make release`, which \
     enables the matching NS heartbeat feature."
);

// Forced blind adds signing authority and therefore has a narrower production
// configuration than ordinary clear signing. `iwdg` implies the exact
// STM32U585 Secure-alias implementation and the compile-time-pinned
// GTZC1_TZSC_SECCFGR1 bit-7 image in `sau.rs`; `ui-lcd` implies the physical
// GPIO buttons. P73S/Bloom are unconditional generated roots and the positive
// feature itself co-embeds P73K, so there is no permissive runtime artifact
// selector to fence here. The canonical production bundle separately keeps
// this feature forbidden until implementation review and #79 silicon closure.
#[cfg(all(
    feature = "mode-production",
    feature = "erc7730-forced-blind",
    any(
        not(feature = "stm32u585"),
        not(feature = "iwdg"),
        not(feature = "ui-lcd"),
    ),
))]
compile_error!(
    "ERC7730_FORCED_BLIND_PRODUCTION_PREREQUISITES: mode-production + \
     erc7730-forced-blind requires stm32u585, iwdg with Secure-only \
     GTZC1 bit-7 attribution/Secure alias, and the physical ui-lcd/button \
     backend. P73S/Bloom/P73K remain fixed generated artifacts. This source \
     fence is not #79 CPU/GPDMA silicon-denial evidence."
);

// Dedicated guard: `otp-hardcoded-master-key` + `optiga-lock-operational` is
// a specifically catastrophic combination. The lock feature irreversibly
// ratchets protected user-object metadata while the hardcoded-master-key
// feature makes the PBS a compile-time constant shared by every such device.
// Anyone knowing that constant can satisfy Conf(E140), so the supposedly
// locked object policy would be rooted in a published credential. Ordinary
// pairing no longer ratchets E140 itself, but this combination remains unsafe.
#[cfg(all(
    feature = "otp-hardcoded-master-key",
    feature = "optiga-lock-operational",
))]
compile_error!(
    "otp-hardcoded-master-key and optiga-lock-operational are mutually \
     exclusive. Enabling both would irreversibly lock protected objects while \
     their Conf(E140) authority is rooted in a shared compile-time PBS, \
     effectively publishing the Shielded Connection credential."
);

// The retained S-2 helper previously targeted the wrong OIDs and treated an
// omitted DataType tag as if it removed an existing TrustAnchor type. OPTIGA
// metadata updates are not yet proven to provide that replacement semantics,
// so compiling the would-be ceremony is unsafe. Keep the exact candidate
// inventory in the fail-closed helper for future silicon work, but do not emit
// a runnable irreversible image until type transition, data readback,
// lifecycle, and AC verification are all specified and validated.
#[cfg(all(feature = "mode-production", feature = "optiga-trust-m"))]
compile_error!(
    "OPTIGA_S2_PRODUCTION_BLOCKED: the real type-0x11 trust-anchor pool \
     E0E8/E0E9/E0EF and the device-certificate retype boundary remain OPEN. \
     No production OPTIGA image may compile until the exact closure ceremony \
     is implemented, reviewed, and silicon-validated. Enabling an \
     irreversible acknowledgement or `optiga-lock-operational` does not \
     satisfy this gate."
);

#[cfg(all(
    feature = "optiga-lock-operational",
    feature = "factory-production-irreversible-im-sure"
))]
compile_error!(
    "OPTIGA_TA_POOL_LOCKDOWN_BLOCKED: the S-2 trust-anchor neutralization \
     helper is not executable authority. The candidate pool is exactly \
     E0E8/E0E9/E0EF, but safe DataType replacement plus data/AC/lifecycle \
     readback has not been specified or silicon-validated. Do not build an \
     irreversible image until that ceremony is separately reviewed."
);

// Prodtest is a reversible acceptance-test image.  It must never share a
// build with a persistent-root, option-byte/shipping, SE-rotation, lifecycle,
// or factory ceremony path.  In particular, an acknowledgement feature is
// not authority to consume the BHK first write (which runs before prodtest's
// main-loop short-circuit) or mutate either secure element.  The safe prodtest
// profile uses `dev-testkey`; an unqualified prodtest build would use the real
// OTP-master path and is rejected here as well.
#[cfg(all(
    feature = "prodtest",
    any(
        feature = "bhk",
        feature = "se050-rotate-scp03",
        feature = "optiga-lock-operational",
        feature = "factory-provisioning",
        feature = "factory-provisioning-rehearsal",
        feature = "factory-production-irreversible-im-sure",
        feature = "mode-production",
        feature = "rdp-enforce-halt",
        feature = "tamp-wipe",
        feature = "tzic-wipe",
        not(any(feature = "dev-testkey", feature = "otp-hardcoded-master-key")),
    )
))]
compile_error!(
    "PRODTEST_PERSISTENT_ACTION_FORBIDDEN: `prodtest` is a reversible \
     acceptance-test profile and is unconditionally incompatible with real \
     BHK/OTP roots, option-byte or shipping profiles, SE key rotation, OPTIGA \
     lifecycle ratchets, persistent tamper-wipe handlers, and factory \
     ceremony features. An irreversible \
     acknowledgement does not relax this fence. Use the non-persistent \
     `prodtest,dev-testkey` profile; run any destructive experiment only in a \
     separately reviewed, owner-authorized sacrificial harness."
);

// Direct-Cargo defence for single-purpose reset/wipe/provision/stress images.
// These features replace normal boot with code that mutates persistent MCU or
// secure-element state. They are useful only as named bench harnesses and can
// never be composed with a production image, even if some other quarantine
// would also reject today's build.
#[cfg(all(
    feature = "mode-production",
    any(
        feature = "se050-factory-reset",
        feature = "se050-reset-e2e",
        feature = "se050-admin-wipe-e2e",
        feature = "se050-crash-safety-e2e",
        feature = "se050-admin-extract-attempt-e2e",
        feature = "se050-stress",
        feature = "optiga-admin-wipe-e2e",
        feature = "optiga-nuclear-reset",
        feature = "dual-se-admin-wipe-e2e",
        feature = "optiga-hw-counter-e2e",
        feature = "duress-probe-e2e",
        feature = "duress-provision-e2e",
        feature = "pin-gate-e2e",
        feature = "dual-se-multi-unlock-e2e",
    )
))]
compile_error!(
    "PRODUCTION_DESTRUCTIVE_HARNESS_FORBIDDEN: mode-production cannot include \
     any reset, wipe, persistent provisioning, stress, counter-mutation, or \
     stateful E2E harness. Use each feature only through its named bench target \
     and never on a unit intended to ship."
);

// Dedicated guard: `fw-rollback-e2e` is a dev/test image that embeds the dev
// vendor SIGNING seed and replaces `main()` with a self-contained
// anti-rollback test that halts. It must never coexist with `mode-production`.
#[cfg(all(feature = "mode-production", feature = "fw-rollback-e2e"))]
compile_error!(
    "mode-production and fw-rollback-e2e are mutually exclusive. \
     fw-rollback-e2e embeds the development vendor signing seed and short- \
     circuits boot into a firmware anti-rollback test — never a shipping image."
);

// Firmware-rollback backend quarantine. The legacy hardware implementation
// treated one ECC-protected OTP quad-word as a reusable per-bit tally, but
// STM32U585 user OTP permits only one program operation per 128-bit QW.
// FA-1.5 (Draft 1.1 §14 L4375) removed that runtime floor writer from
// `cmd_fw_commit` (the handler now refuses fail-closed; no epoch-bump
// success path exists in any build). Draft 1.1 remains the research
// candidate for replacement interfaces and deliberately leaves approval
// plus physical journal/ECC/OTP/resource gates open. It is not
// implementation authority.
//
// Shipping builds are blocked unconditionally. Bench images must carry a
// conspicuous no-behaviour-change opt-in (normally inherited from debug-log,
// mock-se, e2e-test, or otp-hardcoded-master-key). Factory provisioning is
// blocked separately because its entry and completion receipts reprogram the
// same OTP QW and therefore cannot complete on this MCU.
//
// CARVE-OUT (issue #541; see `secure/build.rs` for the full statement):
// the named §5 warning-build measurement profile links conservative
// reservation stubs that fail closed at runtime and has NO reachable
// epoch-bump success path — it is explicitly not a target of this
// quarantine.
#[cfg(all(feature = "mode-production", feature = "stm32u585"))]
compile_error!(
    "FW_ROLLBACK_PRODUCTION_BLOCKED: the legacy firmware rollback path \
     reprograms ECC-protected OTP quad-words. Approve and implement the \
     replacement contract, then close OPEN-JRN-HW/DUR, OPEN-FLASH-HW, \
     OPEN-ECC, OPEN-RAM, OPEN-OTP, release/factory, and silicon gates before \
     removing this fence."
);
#[cfg(all(
    feature = "stm32u585",
    not(feature = "mode-production"),
    not(feature = "legacy-fw-rollback-unsafe")
))]
compile_error!(
    "FW_ROLLBACK_UNSAFE_OPT_IN_REQUIRED: non-shipping STM32U585 builds that \
     still contain the legacy firmware rollback backend must explicitly \
     enable `legacy-fw-rollback-unsafe`."
);
#[cfg(all(feature = "stm32u585", feature = "factory-provisioning"))]
compile_error!(
    "FW_ROLLBACK_FACTORY_BLOCKED: factory provisioning and rehearsal are \
     disabled until the factory receipt stops reprogramming one write-once \
     STM32U585 OTP quad-word."
);

// Dedicated guard: `mode-production` + `ui-noop` (trusted-UI finding UI2,
// work-todo #12c). `ui-noop` is the silent headless Display/Input backend used
// only by dev/test targets (all of which also carry `e2e-test`/`mock-se`).
// Under the scroll-to-end `confirm()`, its `wait_button` returns `(Right,Short)`
// forever, so a headless build cannot obtain a genuine physical confirm — every
// sign would hang, or, if the hang were "fixed" by returning `(Right,Long)`,
// AUTO-CONFIRM every signature with zero physical consent (a total trusted-path
// bypass). A shipping image MUST drive a real display backend (`ui-lcd`).
#[cfg(all(feature = "mode-production", feature = "ui-noop"))]
compile_error!(
    "mode-production and ui-noop are mutually exclusive. ui-noop is the silent \
     headless UI backend (dev/test only): it cannot obtain a genuine physical \
     confirm — every sign would hang, or auto-confirm with zero user consent if \
     the hang were 'fixed'. Ship with a real display backend (`ui-lcd`)."
);

// Dedicated guard: `fwup-transport-e2e` is the over-USB FW-update transport
// e2e test. It short-circuits CMD_FW_COMMIT to stop *before* the OTP
// rollback-floor bump + boot-state write + sys_reset, so the chip stays
// reflashable. That short-circuit must never reach a shipping image — a
// production COMMIT that skips OTP would never raise the rollback floor.
#[cfg(all(feature = "mode-production", feature = "fwup-transport-e2e"))]
compile_error!(
    "mode-production and fwup-transport-e2e are mutually exclusive. \
     fwup-transport-e2e short-circuits CMD_FW_COMMIT before the OTP \
     bump + reboot so the test chip stays reflashable — never a shipping image."
);

// MED-2 ship gate (audits/tz-tamper-debug-20260611): `e2e-test` and
// `dev-testkey` are the two dev escape hatches that ship FIXED secrets —
// `e2e-test` auto-provisions a fixed mnemonic + PIN and short-circuits every
// secure-side confirm()/enter_pin(); `dev-testkey` substitutes the per-device
// OTP master key with a compile-time constant (it pulls in
// `otp-hardcoded-master-key`). Both turn OFF the main hardware-release fence
// above (it excludes them at the `not(feature = "e2e-test")` /
// `not(feature = "dev-testkey")` lines so `make e2e-hw` / `make
// play-hw-display` can drive the tests), so nothing else catches them in a
// shipping image. `mode-production` is the explicit "this is a shipping
// build" declaration; it must reject both. We key on `mode-production` ALONE
// (not the broader `stm32u585 + !debug_assertions` hardware-release condition
// used by the denylist above and one arm of the S-3 fence) because
// stm32u585+release+e2e-test IS the legitimate `make e2e-hw` hardware-test
// image. The belt-and-braces companion is `make prod-check`, which resolves
// the actual shipping feature set (catching a release built WITHOUT
// mode-production too) and is wired into `make release` + CI.
#[cfg(all(feature = "mode-production", feature = "e2e-test"))]
compile_error!(
    "mode-production and e2e-test are mutually exclusive (ship gate MED-2). \
     e2e-test auto-provisions a FIXED test mnemonic + PIN and short-circuits \
     every secure-side confirm()/enter_pin() — never a shipping image. Build \
     hardware-test images with `stm32u585,e2e-test` (no mode-production)."
);

#[cfg(all(
    feature = "mode-production",
    feature = "erc7730-nested-calldata-test-fixture"
))]
compile_error!(
    "mode-production cannot activate the synthetic ERC-7730 nested-calldata enrollment"
);
#[cfg(all(feature = "mode-production", feature = "dev-testkey"))]
compile_error!(
    "mode-production and dev-testkey are mutually exclusive (ship gate MED-2). \
     dev-testkey substitutes the per-device OTP master key with a shared \
     compile-time constant (via otp-hardcoded-master-key), so every unit built \
     with it derives identical admin / SCP03 / PBS secrets — never a shipping \
     image."
);

// S-3 ship-blocker: a production OPTIGA build MUST use the silicon E120 LUC
// counter (`optiga-hw-counter`). Without it the only PIN-attempt cap is the
// firmware soft counter at F1E1 + the MCU page-124 counter — both of which a
// desoldered / PBS-extracting bench attacker bypasses entirely (F1D0.Execute is
// ALW, so the chip answers unbounded HMAC-verify queries), giving an unbounded
// PIN brute force. Because the PIN is shared with the SE050, that defeats the
// whole wallet. Hardware TEST images may opt out via `e2e-test` / `dev-testkey`
// (they deliberately exercise the soft path); SHIPPING images may not.
#[cfg(all(
    feature = "optiga-trust-m",
    any(
        feature = "mode-production",
        all(feature = "stm32u585", not(debug_assertions)),
    ),
    not(feature = "e2e-test"),
    not(feature = "dev-testkey"),
    not(feature = "optiga-hw-counter"),
))]
compile_error!(
    "Production OPTIGA builds require `optiga-hw-counter` (ship-blocker S-3). \
     Without it the PIN attempt cap is a firmware soft counter the chip does \
     not enforce, so a desoldered / PBS-extracting bench attacker gets \
     unbounded HMAC-verify attempts against F1D0 and can brute-force the PIN. \
     Enable `optiga-hw-counter`, or build a non-shipping test image with \
     `e2e-test` / `dev-testkey`."
);

// S-2 quarantine: the retired recovery feature writes sample-certificate
// material and type-0x11 metadata to E0E3, but the observed object is a full
// type-0x12 device certificate.  The operation is therefore mis-targeted and
// destructive even in a dev build.  Keep the source only as incident evidence;
// no Cargo profile may compile it into a runnable image until a replacement is
// separately specified, reviewed, and authorized for named sacrificial parts.
#[cfg(feature = "optiga-reset-oids")]
compile_error!(
    "OPTIGA_RESET_OIDS_RETIRED: `optiga-reset-oids` is a mis-targeted E0E3 \
     recovery experiment and is unconditionally quarantined. The observed \
     E0E3 is a full type-0x12 device certificate, not the type-0x11 anchor \
     assumed by this path. No dev, test, factory, or production build may \
     execute it."
);

// S-1 candidate-profile diagnostic: the currently modeled hardened metadata
// uses `Change = Auto(F1D0)` + LcsO=Operational under
// `optiga-lock-operational` (the `Auto(F1D0)` bytes are wired at
// `optiga/apdu.rs:1080`). Without that class of closure F1D0 can remain
// rewritable: a desoldered-OPTIGA bench
// attacker overwrites the AuthRef HMAC key with a chosen one, self-authenticates,
// resets the E120 LUC counter, and brute-forces the PIN without bound — and
// because the PIN is shared with the SE050, that defeats the whole wallet.
//
// This diagnostic is DELIBERATELY keyed to `mode-production` ALONE — NOT the
// `all(stm32u585, not(debug_assertions))` belt-and-braces the S-2/S-3 fences
// use. `optiga-lock-operational` performs an IRREVERSIBLE LcsO ratchet (OPTIGA
// SRM: LcsO is monotonic, no reverse path), so it must never be added merely to
// clear this diagnostic or to a dev/test RELEASE hardware build:
// `make e2e-hw` / `play-hw-display` build `--release` (so `not(debug_assertions)`)
// WITHOUT `mode-production`, and forcing the ratchet on them would brick dev
// bench chips. The final E140 actor/order, credential rotation, recovery, and
// complete metadata ceremony remain OPEN. This fence models a candidate
// baseline; it grants no hardware, factory, or shipment authority.
//
// NOTE: this fence does not *fix* S-1. Closing S-1 requires a reviewed final
// lifecycle plus owner-authorized sacrificial validation. The unconditional
// rollback quarantine separately keeps current production images unavailable.
#[cfg(all(
    feature = "mode-production",
    feature = "optiga-trust-m",
    not(feature = "optiga-lock-operational"),
))]
compile_error!(
    "Candidate OPTIGA profile is incomplete without a reviewed S-1 metadata \
     closure. `optiga-lock-operational` is an irreversible sacrificial-test \
     candidate, NOT a production fix or instruction: do not enable it merely \
     to clear this diagnostic. The final E140/credential ordering and recovery \
     ceremony remain OPEN, and current production remains quarantined."
);

// work-todo #36 ship gate: a production build MUST enable `rdp2-self-lock`,
// the first-boot RDP-2 self-lock + on-device pairing rotation. Devices ship at
// RDP-0 (batch-uniform, user-verifiable over SWD before first power); the first
// field boot verifies the ship option-byte profile, self-locks RDP-2, and
// rotates the SE pairing secrets off the factory transport keysets — before
// the seed wizard. Without this feature a shipped unit would stay at RDP-0
// (debug open) forever and keep the public transport keysets as its live
// pairing secrets.
//
// Keyed to `mode-production` rather than `not(debug_assertions)`: release-mode
// bench builds are not shipping images. The converse guard immediately below
// also rejects `rdp2-self-lock` without `mode-production`, so the two features
// are coupled and no bench/dev build can carry the irreversible path.
#[cfg(all(feature = "mode-production", not(feature = "rdp2-self-lock")))]
compile_error!(
    "Production builds require `rdp2-self-lock` (work-todo #36): the first field \
     boot self-locks RDP Level 2 and rotates the SE pairing secrets off the \
     factory transport keysets, before the seed wizard. Without it a shipped \
     unit stays at RDP-0 (debug port open) with the public transport keysets as \
     its live SCP03/PBS/admin secrets. Release-mode bench builds remain outside \
     `mode-production` and therefore cannot carry the self-lock feature."
);

// The converse is equally important: never produce a flashable image carrying
// the irreversible self-lock path unless it is the explicit production
// configuration. Compile-only coverage lives in the pure host model while the
// production build remains quarantined by the independent rollback gate.
#[cfg(all(feature = "rdp2-self-lock", not(feature = "mode-production")))]
compile_error!(
    "RDP2_SELF_LOCK_REQUIRES_MODE_PRODUCTION: `rdp2-self-lock` contains the \
     irreversible RDP=0xCC and secure-element rotation path and must not compile \
     into a bench/dev image. Use the pure first_boot host tests until the \
     production rollback quarantine is closed."
);

// work-todo #36 anti-footgun: `rdp2-self-lock` must NEVER compile into a
// dev / QEMU / bench / test image — its first boot programs RDP=0xCC
// (irreversible) and rotates SE keys against the factory transport state. A
// bench board is not in that state, so a production FSBL on it would brick.
// `mock-se` / `*-hardcoded-master-key` would make the "rotate off the real
// transport keysets" step meaningless.
#[cfg(all(
    feature = "rdp2-self-lock",
    any(
        feature = "e2e-test",
        feature = "dev-testkey",
        feature = "mock-se",
        feature = "otp-hardcoded-master-key",
        feature = "bhk-hardcoded-master-key",
        feature = "factory-provisioning",
    ),
))]
compile_error!(
    "`rdp2-self-lock` (work-todo #36) is incompatible with dev/test features \
     (e2e-test / dev-testkey / mock-se / otp-hardcoded-master-key / \
     bhk-hardcoded-master-key / factory-provisioning). Its first \
     boot performs the IRREVERSIBLE RDP=0xCC burn and rotates SE pairing \
     secrets against the factory transport state — a bench/QEMU/test board is \
     not in that state and would self-brick. Build the production image without \
     these features, or a dev image without `rdp2-self-lock`."
);

// work-todo #36 config guard: `rdp2-self-lock` requires `dual-se`. Phase B
// rotates BOTH secure elements' pairing secrets (SE050 SCP03/admin + OPTIGA
// PBS) off the factory transport keysets. Without `dual-se` the Phase-B glue
// is compiled out while Phase A would still program RDP-2 — locking the device
// without ever provisioning it. `dual-se` is the shipping seed-split config
// (invariant #1) anyway, so this only rules out a broken bench combination.
#[cfg(all(feature = "rdp2-self-lock", not(feature = "dual-se")))]
compile_error!(
    "`rdp2-self-lock` (work-todo #36) requires `dual-se`: first-boot Phase B \
     rotates BOTH SEs' pairing secrets off the factory transport keysets. \
     Without `dual-se` the rotation glue is compiled out while Phase A still \
     locks RDP-2 — locking the device without provisioning it."
);

// SCA ship-blocker (audit secret-lifecycle 20260611, MEDIUM-3): a production
// hardware build MUST enable the power-consumption mask (`consumption-mask`).
// The ~7 s SPHINCS+C10 keygen/sign produces a characteristic power-draw
// signature a bench CPA/DPA rig can correlate against the WOTS chain seeds and
// FORS leaf secrets. `consumption-mask` drives a TIM2-CH1 PWM on PA5 whose duty
// is re-randomised from the SysTick handler, so the signature stays
// uncorrelated across the whole signing window; without it the only sign-path
// SCA defenses are the F-16 shuffle and the F-17 rate limiter. This mirrors the
// S-3 `optiga-hw-counter` pattern: the feature is not auto-composed, the fence
// forces a shipping build to opt in. Hardware TEST images may opt out via
// `e2e-test` / `dev-testkey` (they run non-shipping paths and keep timing
// deterministic); SHIPPING images may not.
#[cfg(all(
    feature = "stm32u585",
    not(debug_assertions),
    not(feature = "e2e-test"),
    not(feature = "dev-testkey"),
    not(feature = "consumption-mask"),
))]
compile_error!(
    "Production hardware builds (stm32u585 + !debug_assertions) require \
     `consumption-mask` (ship-blocker; audit secret-lifecycle 20260611 \
     MEDIUM-3). Without it the SPHINCS+C10 keygen/sign window runs with an \
     undiluted power signature, exposing the WOTS/FORS secrets to a bench \
     CPA/DPA attacker. Enable `consumption-mask` (it implies `stm32u585`; its \
     TIM2-CH1 PWM mask runs on PA5 — free on iota2, but SPI1_SCK, the LCD \
     clock, on pq1, so a shipping pq1 image needs the mask repointed first — \
     see the board fence in hw/consumption_mask.rs for why that is a hardware \
     decision and not a constant swap), or build a non-shipping test image \
     with `e2e-test` / `dev-testkey`."
);

// MEDIUM-1 ship-blocker (audit tz-tamper 20260611): a production hardware
// build MUST enable tamper monitoring AND the production intrusion-response
// escalation on BOTH detectors — TAMP (`tamp` + `tamp-wipe`) and the GTZC1
// illegal-access controller (`tzic-wipe`). Without `tamp` the device does
// ZERO tamper detection; with `tamp` but without `tamp-wipe` / `tzic-wipe` a
// detected tamper (voltage / clock glitch, ITAMP9 crypto-peripheral-fault FI
// canary, SWD-at-RDP>0) or an NS->secure illegal access is merely logged and
// the device continues — the zeroize-SRAM + arm-wipe-flag + reset response
// (`hw::tzic::trigger_intrusion_wipe`) never fires, so a fault-injection
// campaign against the SAES/PKA/TRNG gets unbounded attempts with no penalty.
// Keyed on `dual-se` (the production seed-split SE config, invariant #1) so
// the fence targets shipping images only and never forces a brick-on-tamper
// response onto mock / single-SE bench builds — mirrors how the
// `optiga-hw-counter` / `se050-derived-scp03` fences key on their backend.
// These features are not auto-composed, so the fence forces a shipping build
// to opt in. Hardware TEST images may opt out via `e2e-test` / `dev-testkey`
// (they keep the log-only path so a probe-rs glitch session doesn't wipe the
// bench chip).
#[cfg(all(
    feature = "dual-se",
    any(
        feature = "mode-production",
        all(feature = "stm32u585", not(debug_assertions)),
    ),
    not(feature = "e2e-test"),
    not(feature = "dev-testkey"),
    not(all(feature = "tamp", feature = "tamp-wipe", feature = "tzic-wipe")),
))]
compile_error!(
    "Production dual-SE builds require `tamp` + `tamp-wipe` + `tzic-wipe` \
     (ship-blocker; audit tz-tamper 20260611 MEDIUM-1). Without them a \
     detected tamper (voltage/clock glitch, ITAMP9 crypto-peripheral fault, \
     SWD-at-RDP>0) or an NS->secure illegal access is only logged — the \
     zeroize-SRAM + arm-wipe-flag + reset intrusion response never fires, so \
     a fault-injection campaign gets unbounded attempts with no penalty. \
     Enable `tamp` + `tamp-wipe` + `tzic-wipe` (add `tamp-irq` for \
     lowest-latency response), or build a non-shipping test image with \
     `e2e-test` / `dev-testkey`."
);

// HIGH-1 ship-blocker (audit se-tunnels 20260611): a candidate production
// configuration MUST at minimum root its current transport SCP03 channel in
// per-device derived transport keys (`se050-derived-scp03`), not
// the published AN12436 factory keyset. Without the feature,
// `scp03::load_platform_keys` returns `PLATFORM_{ENC,MAC,DEK}` — the public
// SE050C2 OEF-0xA201 constants — and `establish()` derives the session keys from
// them, so a logic analyzer on I2C1 reconstructs `s_enc`/`s_rmac` from the
// on-wire SCP03 handshake challenges and DECRYPTS `half_E` (the SE050 seed share)
// out of every unlock. `scp03_logic.rs` says it outright: such a channel is
// "plaintext-equivalent to a bus sniffer with the datasheet". Invariant #3 break;
// weakens #1. Mirrors the S-3 `optiga-hw-counter` pattern — the feature is not
// auto-composed, so this fence records a candidate-profile prerequisite. It
// does not authorize the sacrificial `se050-rotate-scp03` PUT KEY path or any
// write to a real unit. This fence is necessary but not sufficient:
// it does not implement the still-open fresh-TRNG production-final rotation,
// durable public state, cut recovery, or coordinated E140 ordering. `dual-se`
// implies `se050`, so this also covers the candidate dual-chip build. NOTE:
// fencing out the *fallback* fail-OPEN
// (`se050-scp03-allow-factory-fallback`, above) shut the back door; this shuts
// the front door — shipping with the feature simply OFF. Hardware TEST images
// may opt out via `e2e-test` / `dev-testkey`.
#[cfg(all(
    feature = "se050",
    any(
        feature = "mode-production",
        all(feature = "stm32u585", not(debug_assertions)),
    ),
    not(feature = "e2e-test"),
    not(feature = "dev-testkey"),
    not(feature = "se050-derived-scp03"),
))]
compile_error!(
    "Candidate SE050 profile is incomplete without non-public SCP03 transport \
     keys (ship-blocker; audit se-tunnels 20260611 HIGH-1). Without \
     `se050-derived-scp03` the static keys are the \
     PUBLISHED AN12436 factory constants (`PLATFORM_{ENC,MAC,DEK}`), so the SE050 \
     secure channel is plaintext-equivalent to a bus sniffer holding the \
     datasheet: a logic analyzer on I2C1 reconstructs the session keys from the \
     on-wire SCP03 handshake challenges and decrypts `half_E` out of every unlock \
     (invariant #3 break, weakens #1). The existing derived-key/PUT-KEY path is \
     sacrificial evidence only; do not run it or enable features merely to clear \
     this diagnostic. The fresh-TRNG final rotation, durable state, cut recovery, \
     and coordinated E140 ordering remain OPEN; current production is quarantined."
);

// MEDIUM-1 ship-blocker (audit se-tunnels 20260611): `optiga-no-shield` turns
// `ensure_shield()` into a no-op and routes every OPTIGA APDU through the
// plaintext `send_command` branch, so `half_O` (the OPTIGA seed share) and the
// PIN-auth HMAC challenge/response transit I2C in cleartext — a bus attacker
// reads the OPTIGA seed share directly off the wire (invariant #3 break, weakens
// #1). It is a dev affordance for a bricked/unreachable E140 and must never reach
// a shipping image. Same shape as the S-2 `optiga-reset-oids` fence. Hardware
// TEST images may opt out via `e2e-test` / `dev-testkey`.
#[cfg(all(
    feature = "optiga-no-shield",
    any(
        feature = "mode-production",
        all(feature = "stm32u585", not(debug_assertions)),
    ),
    not(feature = "e2e-test"),
    not(feature = "dev-testkey"),
))]
compile_error!(
    "`optiga-no-shield` must not ship (ship-blocker; audit se-tunnels 20260611 \
     MEDIUM-1): it disables the Shielded Connection entirely, so `half_O` and the \
     PIN-auth APDUs transit I2C in plaintext and a bus attacker reads the OPTIGA \
     seed share directly off the wire (invariant #3 break, weakens #1). Drop \
     `optiga-no-shield` from production builds, or build a non-shipping test image \
     with `e2e-test` / `dev-testkey`."
);

// ---------------------------------------------------------------------------
// UI-axis mutual exclusivity (Phase 2)
//
// `ui-semihosting`, `ui-oled`, and `ui-noop` are mutually exclusive UI
// *backends* — exactly one provides the `Display` and `Input` types that
// `secure/src/ui/mod.rs` re-exports. The `ui-mirror` flag sits on top of
// `ui-oled` (it implies it) and `ui-capture` sits on top of any backend
// (it emits a SHA-256 hash of every flushed frame as a side effect), so
// those two compose with the backend axis rather than competing with it.
//
// Combining two backends compiles today (the first cfg-match wins
// silently), which is footgun-shaped. This fence makes "two backends"
// a build error.
// ---------------------------------------------------------------------------

#[cfg(all(feature = "ui-semihosting", feature = "ui-noop"))]
compile_error!(
    "UI backends `ui-semihosting` and `ui-noop` are mutually exclusive. \
     Pick exactly one."
);

#[cfg(all(feature = "ui-lcd", feature = "ui-semihosting"))]
compile_error!(
    "UI backends `ui-lcd` and `ui-semihosting` are mutually exclusive. \
     Pick exactly one."
);

#[cfg(all(feature = "ui-lcd", feature = "ui-noop"))]
compile_error!(
    "UI backends `ui-lcd` and `ui-noop` are mutually exclusive. Pick exactly \
     one. (`ui-lcd` became a standalone Display backend in Phase C; the old \
     Phase A/B `ui-lcd`+`ui-noop` pairing is no longer valid.)"
);

// `ui-capture` hashes whatever buffer a backend hands `capture::emit`, and the
// backends hand it different things: `ui-semihosting` passes the 64-byte
// character grid, this OLED backend passes its 512-byte SSD1306 page buffer,
// and `ui-lcd` does not call emit at all. Combining them would produce a
// [UI-FP] fingerprint stream matching neither `tests/ui_fixtures.json` nor the
// LCD's silence — a green-looking capture run that compares nothing.
#[cfg(all(feature = "ui-oled-bench", feature = "ui-capture"))]
compile_error!(
    "`ui-oled-bench` and `ui-capture` are incompatible: capture fingerprints the \
     backend's own framebuffer, and this backend's is the 512-byte SSD1306 page \
     buffer rather than the character grid the fixtures were recorded against. \
     Capture runs belong on `ui-semihosting`."
);

#[cfg(all(feature = "ui-oled-bench", feature = "ui-lcd"))]
compile_error!(
    "UI backends `ui-oled-bench` and `ui-lcd` are mutually exclusive. Pick exactly \
     one. (`ui-oled-bench` became a standalone Display backend in Phase C; the old \
     Phase A/B `ui-oled-bench`+`ui-lcd` pairing is no longer valid.)"
);

#[cfg(all(feature = "ui-oled-bench", feature = "ui-semihosting"))]
compile_error!(
    "UI backends `ui-oled-bench` and `ui-semihosting` are mutually exclusive. Pick exactly \
     one. (`ui-oled-bench` became a standalone Display backend in Phase C; the old \
     Phase A/B `ui-oled-bench`+`ui-semihosting` pairing is no longer valid.)"
);

#[cfg(all(feature = "ui-oled-bench", feature = "ui-noop"))]
compile_error!(
    "UI backends `ui-oled-bench` and `ui-noop` are mutually exclusive. Pick exactly \
     one. (`ui-oled-bench` became a standalone Display backend in Phase C; the old \
     Phase A/B `ui-oled-bench`+`ui-noop` pairing is no longer valid.)"
);

// At least one UI backend must be selected when targeting actual hardware
// or QEMU. (Pure `cargo test -p sphincs-tz-secure --tests` builds run on
// the host with neither stm32u585 nor any UI backend — those are exempt
// because they exercise pure-logic modules only.)
#[cfg(all(
    not(test),
    target_arch = "arm",
    not(any(
        feature = "ui-semihosting",
        feature = "ui-noop",
        feature = "ui-lcd",
        feature = "ui-oled-bench",
    ))
))]
compile_error!(
    "Exactly one UI backend must be selected: `ui-semihosting`, `ui-noop`, \
     `ui-lcd`, or `ui-oled-bench` (bench-only SSD1306, PROD_FORBIDDEN). \
     (`ui-capture` composes with any backend.)"
);

// ---------------------------------------------------------------------------
// Secure-element-axis mutual exclusivity (Phase 2)
//
// `dual-se` is the explicit "both production SEs simultaneously" build,
// implemented as `dual-se = ["optiga-trust-m", "se050"]`. Outside of
// `dual-se`, exactly one of {mock-se, se050, optiga-trust-m}
// must be selected.
//
// The selection is done in `secure/src/main.rs` today by a chain of
// `#[cfg(all(feature = "mock-se", not(feature = "se050"), ...))]` blocks
// (negative-condition voting) — i.e., simultaneous selection compiles
// silently with a "first match wins" semantics. Make it loud here.
// ---------------------------------------------------------------------------

#[cfg(all(feature = "mock-se", feature = "se050"))]
compile_error!(
    "Secure-element backends `mock-se` and `se050` are mutually exclusive. \
     Pick exactly one."
);

#[cfg(all(feature = "mock-se", feature = "optiga-trust-m"))]
compile_error!(
    "Secure-element backends `mock-se` and `optiga-trust-m` are mutually \
     exclusive. Pick exactly one. (Note: `dual-se` implies both `optiga-trust-m` \
     and `se050`, so combining `mock-se` with `dual-se` is also forbidden.)"
);

// At least one SE backend must be selected when targeting hardware or QEMU.
#[cfg(all(
    not(test),
    target_arch = "arm",
    not(any(
        feature = "mock-se",
        feature = "se050",
        feature = "optiga-trust-m",
        feature = "dual-se",
    ))
))]
compile_error!(
    "Exactly one secure-element backend must be selected: `mock-se`, \
     `se050`, `optiga-trust-m`, or `dual-se`."
);

#[cfg(not(feature = "stm32u585"))]
use sphincs_tz_shared::{
    NscStatus, CMD_GET_INIT_CODE, CMD_GET_REMAINING, CMD_GET_WALLET_ADDRESS, CMD_IS_UNLOCKED,
    CMD_LOCK, CMD_NONE, CMD_OFFCHAIN_STATUS, CMD_OFFCHAIN_SYNC, CMD_REQUEST_UNLOCK,
    CMD_SIGN_OFFCHAIN, CMD_SIGN_USEROP, CMD_SIGN_USEROP_BATCH, SHARED_MAILBOX_BASE,
};

// ---------------------------------------------------------------------------
// Shared-memory mailbox layout (QEMU NS SRAM, derived from shared crate
// constants). Only used on the QEMU transport; the STM32U585 build uses
// CMSE veneers and never touches the mailbox.
// ---------------------------------------------------------------------------

#[cfg(not(feature = "stm32u585"))]
const SHARED_CMD: *mut u32 = SHARED_MAILBOX_BASE as *mut u32;
#[cfg(not(feature = "stm32u585"))]
const SHARED_ARG0: *mut u32 = (SHARED_MAILBOX_BASE + 4) as *mut u32;
#[cfg(not(feature = "stm32u585"))]
const SHARED_ARG1: *mut u32 = (SHARED_MAILBOX_BASE + 8) as *mut u32;
#[cfg(not(feature = "stm32u585"))]
const SHARED_ARG2: *mut u32 = (SHARED_MAILBOX_BASE + 12) as *mut u32;
#[cfg(not(feature = "stm32u585"))]
const SHARED_RESULT: *mut u32 = (SHARED_MAILBOX_BASE + 16) as *mut u32;
#[cfg(not(feature = "stm32u585"))]
const SHARED_DONE: *mut u32 = (SHARED_MAILBOX_BASE + 20) as *mut u32;

/// Arguments handed to a `cmd_*` handler. On the QEMU transport these
/// are read out of the shared mailbox in [`poll_gateway`] before
/// dispatch runs (a TOCTOU snapshot so NS can't race the validator).
/// On the STM32U585 CMSE transport they're just the three `u32`
/// register arguments of the `nsc_*` veneer wrapped into a struct so
/// the shared `cmd_*::run` bodies can stay identical across transports.
pub(super) struct GatewayArgs {
    pub(super) arg0: u32,
    pub(super) arg1: u32,
    pub(super) arg2: u32,
}

// ---------------------------------------------------------------------------
// Public API consumed by `secure/src/main.rs`
// ---------------------------------------------------------------------------

/// Whether the device is currently unlocked (PIN verified this session).
pub fn is_unlocked() -> bool {
    state::peek_state(|s| s.pin_verified.is_true_fi())
}

/// Shared TOCTOU snapshot buffer for the three mutually-exclusive sign
/// handlers (`cmd_sign_userop`, `cmd_sign_userop_batch`,
/// `cmd_sign_offchain`). Each used to own a private `static mut SNAP_BUF`
/// sized to its own protocol maximum (≈25 KB / ≈41 KB / ≈5.7 KB). Because
/// the dispatcher is single-threaded and non-reentrant (see
/// [`HandlerGuard`] / [`handler_is_busy`]) exactly one of these handlers
/// can be live at a time, so the three buffers were never simultaneously
/// in use — they only ever cost permanent BSS.
///
/// Reserving all three independently pushed `.bss` up against the top of
/// the 128 KB secure SRAM, leaving the deep `cmd_sign_userop` register-slot
/// path (slot keygen + bootstrap keygen + two FI-doubled C10 signs, each
/// holding several KB of stack buffers) with too little stack headroom: at
/// its deepest the stack grew down past the BSS top and clobbered the
/// adjacent `state::SLOT_CACHE` (its discriminant zeroed → `None`), making
/// the Type-2 sign read an empty cache and return `InternalError`. Folding
/// the snapshots into one buffer sized to the largest claimant reclaims the
/// two idle copies (~31 KB of BSS) and restores ample stack headroom.
///
/// Each handler still validates its own payload length against its own
/// protocol-max constant before copying; a `const` assert in each pins
/// that constant ≤ [`SIGN_SNAP_BUF_LEN`] so an oversized handler can never
/// silently overrun the shared buffer.
pub(super) const SIGN_SNAP_BUF_LEN: usize =
    sphincs_tz_shared::SIGN_USEROP_BATCH_MAX_PAYLOAD_LEN;

/// The shared snapshot storage itself. Only ever borrowed (filled, parsed,
/// then wiped) inside a single handler invocation, under the non-reentrant
/// dispatcher — never aliased across handlers.
pub(super) static mut SIGN_SNAP_BUF: [u8; SIGN_SNAP_BUF_LEN] = [0u8; SIGN_SNAP_BUF_LEN];

/// HIGH-7 guard: depth counter incremented on handler entry,
/// decremented on exit. SysTick refuses to wipe when depth > 0 so
/// a long-running signing handler that holds stack-local copies of
/// secrets can't have the BSS copy zeroed out from underneath it
/// (which would leave the stack copies disagreeing with the state
/// the user just had wiped — a classic aliasing-under-ISR bug).
///
/// Stored as `AtomicU32` so the entry-side `fetch_add(1)` is a
/// single LDREX/STREX RMW. An earlier plain-`static mut` version had
/// a tiny but real race window between the read of the old value
/// and the write of `+1` where SysTick could observe `depth == 0`,
/// run idle-wipe, then resume — leaving the handler operating on
/// wiped state. The wipe is fail-safe (the handler bails out at the
/// pin-verified check) but the race violates the docstring promise
/// that "SysTick refuses to wipe when depth > 0".
static HANDLER_DEPTH: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

/// Guard type: increment on construction, decrement on drop.
pub(crate) struct HandlerGuard;

impl HandlerGuard {
    /// RAII guard — call at the top of every long-running gateway
    /// handler (sign, request_unlock). Drop at function exit.
    pub(crate) fn enter() -> Self {
        HANDLER_DEPTH.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
        HandlerGuard
    }
}

impl Drop for HandlerGuard {
    fn drop(&mut self) {
        // Saturating decrement via CAS loop. `fetch_sub` would
        // underflow if Drop ever runs more times than `enter`
        // (cannot happen in safe Rust, but stays conservative).
        use core::sync::atomic::Ordering;
        let mut cur = HANDLER_DEPTH.load(Ordering::SeqCst);
        loop {
            let next = cur.saturating_sub(1);
            match HANDLER_DEPTH.compare_exchange_weak(
                cur, next, Ordering::SeqCst, Ordering::SeqCst,
            ) {
                Ok(_) => return,
                Err(observed) => cur = observed,
            }
        }
    }
}

/// Read the current handler-busy depth from a SysTick handler.
pub fn handler_is_busy() -> bool {
    HANDLER_DEPTH.load(core::sync::atomic::Ordering::SeqCst) > 0
}

/// Test-only helper: stamp the secure-side master secret and mark the
/// device unlocked directly, skipping the interactive PIN dialog. Used
/// by the `e2e-test` boot path; compiled out of every other build.
#[cfg(feature = "e2e-test")]
pub fn set_e2e_unlocked(master: [u8; 32]) {
    state::with_state(|s| s.mark_unlocked(master));
}

/// Set the gateway to "unlocked" state with the given master secret.
/// Used by the first-boot wizard to auto-unlock after provisioning.
pub fn unlock_with_master(master: [u8; 32]) {
    state::with_state(|s| s.mark_unlocked(master));
}

/// Install a master secret after a genuine successful PIN verification and,
/// when the default-off forced-blind feature is selected, arm exactly one
/// volatile forced attempt.
///
/// This is deliberately separate from [`unlock_with_master`] and
/// [`set_e2e_unlocked`].  First-boot auto-unlock, provisioning/test helpers,
/// and every other non-PIN unlock must remain Disarmed.  The three current
/// callers sit immediately inside successful `gated_unlock` result arms;
/// host source-call-graph tests pin that exclusivity.
#[inline(never)]
pub(crate) fn unlock_after_verified_pin(master: [u8; 32]) -> u32 {
    state::with_state(|s| {
        s.mark_unlocked(master);

        #[cfg(feature = "erc7730-forced-blind")]
        {
            let armed = s.forced_attempt.arm_forced_attempt_after_pin();
            // Fail-in: only the exact OK sentinel preserves the newly
            // unlocked session.  A bad/invalid/readback-faulted arm destroys
            // the secret and returns the Hamming-distant failure sentinel.
            if armed == crate::fi::OK_SENTINEL {
                return crate::fi::OK_SENTINEL;
            }
            s.zeroize_sensitive();
            crate::fi::FAIL_SENTINEL
        }

        #[cfg(not(feature = "erc7730-forced-blind"))]
        {
            // Feature-off semantics are the pre-existing generic unlock.
            crate::fi::OK_SENTINEL
        }
    })
}

/// Gated unlock — every PIN verify MUST go through this.
///
/// Wraps the raw `WalletStore::unlock` with the MCU-side attempt
/// counter at secure-flash page 124:
///
///   1. Check the counter. If ≥ MAX_ATTEMPTS, refuse — return
///      `PinLocked`. Caller is responsible for running
///      `trigger_lockout_wipe` on that signal.
///   2. **Pre-commit**: bump the counter BEFORE calling the SE
///      driver. A power loss or glitch between here and the chip
///      verify leaves the attempt charged. Without this, an
///      attacker who reliably cuts power mid-verify could brute-
///      force without burning MCU attempts.
///   3. Call `WalletStore::unlock`. On `Ok`, erase the counter
///      (fresh start); on `Err`, leave the bump committed. If the
///      erase itself fails, refuse with `InternalError` (fail-closed)
///      rather than release the master with the counter still charged
///      — a swallowed reset failure would drift a correct-PIN device
///      toward a spurious lockout/wipe (F17/SCAFI-5).
///   4. If the flash bump itself fails (PROGERR or post-write
///      readback mismatch), refuse the attempt with
///      `InternalError`. Prevents the "glitch flash writes to
///      burn SE attempts without MCU attempts" attack.
///
/// QEMU (no `stm32u585`): passthrough — no flash, no counter, just
/// `se.unlock(pin)`. The counter gate is a production hardware
/// hardening; dev QEMU builds don't need it.
///
/// See `trigger_lockout_wipe` in `cmd_request_unlock.rs` for the
/// wipe path that follows from `PinLocked`.
///
/// # Safety
/// Caller must hold exclusive access to `se` (the `static mut
/// crate::SE` driver). Production callers obtain this via the
/// single-threaded gateway dispatcher; tests construct a dedicated
/// `WalletStore` instance. Touches secure-flash page 124 via the
/// `flash` driver on `stm32u585` — preconditions for those writes
/// are documented in `hw::flash`.
pub unsafe fn gated_unlock(
    se: &mut impl crate::secure_element::WalletStore,
    pin: &[u8; 8],
) -> Result<[u8; 32], crate::secure_element::UnlockError> {
    use crate::secure_element::UnlockError;

    // §18 P1 — entry jitter. The PIN gate is linear from its external
    // trigger (USB `CMD_REQUEST_UNLOCK` dispatch, boot-unlock, PendSV
    // re-unlock) to the F-15 sentinel check, with no internal shuffle
    // like the sign path's F-16. A profiled single-fault attacker
    // (Masaryk-thesis class, ~76 % on STM32U5) lands a glitch at a
    // FIXED offset from that trigger. `wait_random()` here desyncs the
    // absolute trigger→gate offset by 0..255 loop iterations
    // (~0..19 µs at 160 MHz). This is a meaningful window against an
    // UNCALIBRATED single-shot attacker but does NOT defeat a
    // profile-then-attack rig with multi-attempt statistical recovery
    // — the F-15 sentinel + F-17 rate limiter are the load-bearing
    // defenses there. `#[inline(never)]` on both `wait_random` and
    // `wait_random_loop` keeps this a real `bl` (a glitch that skips
    // the call skips only the jitter, not the gate that follows).
    crate::fi::wait_random();

    #[cfg(feature = "stm32u585")]
    {
        // F-15 hardening: double-read the page-124 counter to defend
        // against a value-fault that clamps the load register, then
        // route the "below lockout" predicate through the F-2
        // sentinel-encoding pattern. The conditional below becomes
        // FAIL-IN: a single-fault that skips the gate evaluates the
        // sentinel comparison against a garbage register value (which
        // is overwhelmingly unlikely to coincide with OK_SENTINEL),
        // so the firmware falls through to `Err(PinLocked)` instead
        // of into the bump+verify branch. A flash-side glitch that
        // underreports the counter on one read is caught by the
        // mismatch check.
        let pre_count_a = crate::hw::flash::pin_attempts_read();
        crate::fi::wait_random();
        let pre_count_b = crate::hw::flash::pin_attempts_read();
        if pre_count_a != pre_count_b {
            return Err(UnlockError::PinLocked);
        }
        let pre_count = pre_count_a;

        // Affirmative "allowed to proceed" — Hamming-distant sentinel
        // returned only on a clean `pre_count < MAX_ATTEMPTS`. The
        // caller compares the value rather than branching on a bool.
        let allowed = crate::fi::check_true_into_sentinel(
            || pre_count < sphincs_tz_shared::MAX_ATTEMPTS,
        );
        if allowed != crate::fi::OK_SENTINEL {
            return Err(UnlockError::PinLocked);
        }

        // MEDIUM-2 (audit pin-unlock 20260625): FAIL-IN the pre-commit
        // bump, mirroring the sentinel'd `allowed` gate above. `pin_attempts_bump`
        // (now `#[inline(never)]`) programs the next QW and internally verifies
        // the post-bump count; here we ALSO require — through the Hamming-distant
        // sentinel — that the counter advanced by EXACTLY one relative to
        // `pre_count`. The secure default is the `!= OK_SENTINEL` refusal: a
        // single glitch that skips the `bl pin_attempts_bump` (leaving a stale
        // `Ok`) or skips a refusal branch leaves the re-read count == `pre_count`,
        // so `bumped` lands != OK_SENTINEL and we refuse WITHOUT calling the SE —
        // the old `if ….is_err() { return }` shape let a skipped branch fall
        // through into `se.unlock` with page-124 uncharged.
        //
        // NB: `check_true_into_sentinel` invokes its closure TWICE. The single
        // mutating `pin_attempts_bump()` call therefore happens once, ABOVE the
        // closure; the closure only RE-READS the counter (a side-effect-free
        // flash read), so there is no double-bump.
        let bump_result = crate::hw::flash::pin_attempts_bump();
        let bumped = crate::fi::check_true_into_sentinel(|| {
            // SAFETY: `pin_attempts_read` is a side-effect-free flash read;
            // exclusive SE/flash access holds via the single-threaded
            // dispatcher. The closure is a safe context (the enclosing
            // `unsafe fn` body's implicit unsafe does not extend into it),
            // so the read needs its own `unsafe` block.
            bump_result == Ok(pre_count + 1)
                && unsafe { crate::hw::flash::pin_attempts_read() } == pre_count + 1
        });
        if bumped != crate::fi::OK_SENTINEL {
            // Flash write fault (PROGERR / readback mismatch), a faulted or
            // skipped bump, or the counter did not advance by exactly one.
            // Refuse without ever calling the SE driver.
            return Err(UnlockError::InternalError);
        }
    }

    // Trezor-parity: randomise the timing of the SE-side PIN compare
    // so a clock-aligned EM glitch can't reliably target the SE I2C
    // transaction. The SE silicon's own PIN-compare is constant-time,
    // but the MCU-side I/O setup (clock to-the-SE, SCP03 setup) is
    // not — `wait_random` perturbs that window. Symmetric `wait_random`
    // on the other side of the call would also defend a fault on the
    // result code's arrival back into r0.
    crate::fi::wait_random();
    // §32 P3 — duress-first dispatch (timing-uniform). Try the DECOY
    // credential first; on a match, run a matched-LUC pad (a 2nd duress
    // verify, standing in for the SKIPPED real verify so E120 never
    // drifts) and return the decoy master. On no match, fall through to
    // the real unlock. Both correct paths execute the same op-count
    // (4 SE verifies + 2 reads) so an observer cannot tell real-correct
    // from duress-correct by total unlock latency (deniability). A
    // duress-correct unlock resets the MCU counter exactly like a real
    // success (handled by the shared post-match logic below) — else the
    // lockout state would distinguish duress from real.
    #[cfg(feature = "duress-pin")]
    let result = match se.unlock_duress(pin) {
        Ok(mut m) => {
            // §32 P5: duress matched. If the device is configured for
            // wipe-on-duress, WIPE both wallets and report PinLocked
            // instead of opening the decoy. Timing uniformity is NOT
            // required here (the wipe IS the outcome — by the time an
            // observer notices the latency, the secret is already gone),
            // so we skip the duress_pad. The downstream Err arm returns
            // PinLocked WITHOUT resetting page-124 (the wipe is terminal).
            //
            // F26/LIFE-1 (cut point B): FAIL-IN shape. The decoy release
            // — the attacker's bypass target under coercion — is the
            // EXPLICIT conditional riding the Hamming-distant sentinel
            // (which double-reads the mode byte with a wait_random
            // between); the wipe is the fall-through. A skipped/garbled
            // branch or a faulted read lands on WIPE, never on decoy.
            // The read itself is fail-closed (`is_duress_wipe_mode`:
            // only a pristine-blank QW means decoy).
            #[cfg(feature = "stm32u585")]
            let open_decoy = crate::fi::check_true_into_sentinel(|| {
                !crate::hw::flash::is_duress_wipe_mode()
            });
            #[cfg(not(feature = "stm32u585"))]
            let open_decoy = crate::fi::check_true_into_sentinel(|| true);
            if open_decoy == crate::fi::OK_SENTINEL {
                se.duress_pad(pin);
                Ok(m)
            } else {
                use zeroize::Zeroize;
                m.zeroize();
                crate::fi::zeroize_barrier();
                secure_log!("[NSC] duress=wipe configured — wiping device");
                let _ = se.factory_reset_admin();
                Err(UnlockError::PinLocked)
            }
        }
        Err(_) => se.unlock(pin),
    };
    #[cfg(not(feature = "duress-pin"))]
    let result = se.unlock(pin);
    crate::fi::wait_random();

    // FI guard: capture the discriminant twice, separated by
    // `wait_random()`, and route the verdict through the
    // hamming-distant sentinel in `fi::check_true`. A single
    // glitch that turns an `Err` into an `Ok` selection would have
    // to also defeat both `is_ok()` re-evaluations and the sentinel
    // compare. This raises the cost of the "wrong PIN unlocks +
    // resets the counter" attack from a single fault to a multi-
    // fault sequence; the SE silicon counter still rate-limits at
    // the cryptographic gate.
    //
    // Note: if `result` is `Ok(_)` with garbage master_secret
    // (because the SE driver itself was glitched at the chip
    // boundary), the downstream AES-GCM entropy_blob decrypt MAC
    // check will reject it. This FI guard is defense in depth, not
    // a primary gate.
    let is_ok_1 = result.is_ok();
    crate::fi::wait_random();
    let is_ok_2 = result.is_ok();
    // Sentinel-encoded verdict (not a bare `bool`) — a glitch on this call or
    // on the `match`'s guard then almost certainly yields a value `!= OK_SENTINEL`
    // and so falls to the `Ok(_) => InternalError` arm rather than `Ok(master)`.
    let verdict = crate::fi::check_true_into_sentinel(|| is_ok_1 && is_ok_2);

    match result {
        Ok(master) if verdict == crate::fi::OK_SENTINEL => {
            // F17/SCAFI-5: do NOT swallow a page-124 reset failure.
            // The pre-commit above charged the counter BEFORE the SE
            // verify; a silently-failed reset leaves it charged after
            // a CORRECT PIN, so N good unlocks accumulate N markers →
            // spurious 10-attempt lockout → trigger_lockout_wipe (a
            // silent self-brick with no diagnostic). FAIL-IN like the
            // bump gate above: the refusal is the fall-through, the
            // `Ok(master)` release rides on the Hamming-distant
            // sentinel. Nothing was stamped into SecureState yet, so
            // failing closed here costs only a retry.
            #[cfg(feature = "stm32u585")]
            {
                let reset_result = crate::hw::flash::pin_attempts_reset();
                let reset_ok =
                    crate::fi::check_true_into_sentinel(|| reset_result.is_ok());
                if reset_ok != crate::fi::OK_SENTINEL {
                    return Err(UnlockError::InternalError);
                }
            }
            Ok(master)
        }
        Ok(_) => {
            // FI inconsistency between the two reads of `result.is_ok()` (or a
            // glitched `verdict`) — refuse without resetting the MCU counter.
            // Counter stays bumped from the pre-commit above.
            Err(UnlockError::InternalError)
        }
        Err(e) => Err(e),
    }
}

/// Boot-time directional rollback check between MCU page 124 and the readable
/// OPTIGA attempt counter (E120 LUC under `optiga-hw-counter`; F1E1 only in a
/// non-production soft-counter build). Because `gated_unlock` precharges page
/// 124 before SE verification, benign states have `mcu >= e120`: equality
/// after both advances, or an MCU lead after a cut/transport error. Only
/// `e120 > mcu` proves page-124 rollback and triggers the wipe.
///
/// This is deliberately not described as three-way boot reconciliation. The
/// production SE050 UserID policy denies an attempt-attribute read with
/// `SW=0x6986`, so `Se050::pin_attempt_count` returns `None`. SE050 still
/// participates in every ordinary PIN attempt, independently enforces its
/// max-10 lockout, and maps `AuthMethodBlocked` to the wipe path. Making its
/// counter boot-readable requires a separately reviewed policy/backend and
/// silicon decision; a VERIFY probe would itself consume an attempt.
///
/// On an unprovisioned/backend-unavailable boot, no readable SE leg means no
/// comparison is possible and the function logs and returns. For a future
/// multi-SE backend where both counters are safely readable,
/// `pin_attempt_counts_divergent` remains an additional tamper input.
///
/// Called once per boot from `main.rs` after SE init but before
/// the gateway accepts any unlock command. On tamper detection it
/// triggers `factory_reset_admin` + zeroizes SRAM secrets — same
/// path as `trigger_lockout_wipe`.
#[cfg(feature = "stm32u585")]
pub unsafe fn reconcile_pin_attempts<S>(se: &mut S)
where
    S: crate::secure_element::WalletStore,
{
    let mcu = crate::hw::flash::pin_attempts_read();
    let se_used = se.pin_attempt_count();
    let se_split = se.pin_attempt_counts_divergent();

    // If no readable SE leg exists (shield not yet up, or an unprovisioned chip
    // at first boot) there is nothing to compare. Skip — but loudly, so the
    // lost cross-check is visible rather than silently mistaken for
    // agreement on a frozen value.
    let se_count = match se_used {
        Some(s) => s,
        None => {
            #[cfg(feature = "debug-log")]
            secure_log!("[reconcile] SE attempt-counter leg unavailable — cross-check skipped");
            return;
        }
    };

    // Pre-commit invariant: MCU page-124 is bumped BEFORE the SE verify, so in
    // every benign state MCU LEADS (or equals) the SE counter — `mcu == se`
    // (the verify ran and both advanced) or `mcu == se + 1` (a power-cut or a
    // transport error in the sub-ms window between the MCU bump and the
    // SE-silicon bump). The SE counter EXCEEDING MCU is therefore the
    // unambiguous tamper signal: it means page-124 was rolled back
    // out-of-band (e.g. a TZ-bypass flash erase) while the SE silicon retained
    // its count. Comparing `se > mcu` (NOT `se != mcu`) is what lets the live
    // E120 leg detect the rollback WITHOUT false-wiping on benign power-cuts
    // or flaky-I2C retries (which only ever make MCU lead, never the SE).
    let mcu_vs_se = se_count > mcu;
    let tamper = mcu_vs_se || se_split;

    // FI hardening (audit pin-unlock 20260625): route the "no tamper, safe to
    // continue boot" verdict through the Hamming-distant sentinel and FAIL-IN.
    // The secure default is to WIPE: a single glitch that flips a real
    // disagreement to `tamper = false` lands a value != OK_SENTINEL and falls
    // through to the wipe path below rather than silently booting a tampered
    // device. (Recomputed twice inside `check_true_into_sentinel`; `tamper` is
    // a pure local, so the double evaluation has no side effect.)
    let safe = crate::fi::check_true_into_sentinel(|| !tamper);
    if safe == crate::fi::OK_SENTINEL {
        return;
    }

    crate::ui::show_status("TAMPER DETECT", "wiping...");
    #[cfg(feature = "debug-log")]
    secure_log!(
        "[reconcile] MCU={} SE_used={:?} SE_split={} → wipe",
        mcu, se_used, se_split
    );
    let _ = se.factory_reset_admin();
    let _ = crate::hw::flash::pin_attempts_reset();
    crate::ui::show_status("WIPED", "tamper signal");
}

/// QEMU / non-stm32u585 stub. No flash, no real SE counter to read.
#[cfg(not(feature = "stm32u585"))]
pub unsafe fn reconcile_pin_attempts<S>(_se: &mut S)
where
    S: crate::secure_element::WalletStore,
{
}

/// Zeroize all sensitive global state. Called from the panic handler,
/// the inactivity wipe, and the cancel/idle-wipe branches of every
/// interactive dialog.
pub fn zeroize_sensitive_state() {
    // Panic/tamper paths do not unwind RAII guards. Revoke the watchdog's
    // trusted-UI wait exception before wiping secrets so a fault inside an
    // input backend cannot keep the watchdog fed until the 120 s idle limit.
    crate::timeout::clear_trusted_ui_wait();
    state::with_state(|s| s.zeroize_sensitive());
    // SAFETY: category 5 — exclusive mutable borrow of the
    // `static mut crate::SE` driver. Single-threaded secure world,
    // non-reentrant gateway: nothing else touches the SE while this
    // wipe runs. `zeroize_caches` clears the SE wrapper's in-RAM
    // session state without issuing any I2C traffic.
    unsafe {
        use crate::secure_element::WalletStore;
        (&mut *core::ptr::addr_of_mut!(crate::SE)).zeroize_caches();
    }
}

/// Initialize the shared-memory mailbox by clearing CMD/RESULT/DONE.
/// Must be called once during boot before [`poll_gateway`]. QEMU-only;
/// the STM32U585 CMSE path has no mailbox and no boot-time init.
#[cfg(not(feature = "stm32u585"))]
pub fn init_gateway() {
    // SAFETY: category 2 (QEMU transport — shared-memory mailbox in
    // NS SRAM). The mailbox base/end pair is a compile-time constant
    // from `sphincs_tz_shared`; we are writing to fixed addresses
    // inside that NS region. Volatile stores ensure the cleared
    // values land in memory before NS reads them. Called exactly
    // once during secure-world boot, before NS is allowed to run.
    unsafe {
        core::ptr::write_volatile(SHARED_CMD, CMD_NONE);
        core::ptr::write_volatile(SHARED_RESULT, 0);
        core::ptr::write_volatile(SHARED_DONE, 0);
    }
}

/// Poll the mailbox once and, if a command is pending, dispatch it to
/// the right `cmd_*` handler, write the result word, raise DONE, and
/// clear CMD. The dispatch runs to completion without yielding — the
/// single-threaded invariant the whole state/sign machinery relies on.
/// QEMU-only; never called on the STM32U585 CMSE path.
#[cfg(not(feature = "stm32u585"))]
pub fn poll_gateway() {
    // SAFETY: category 2 (QEMU mailbox path). All eight pointers point
    // into a compile-time-fixed NS-SRAM mailbox region — no runtime
    // validation needed because the addresses are not derived from
    // attacker-supplied input. Volatile reads form the TOCTOU snapshot
    // (CMD + ARG0..2 captured atomically before `dispatch` runs, so NS
    // can't race the validator). Volatile writes commit the response in
    // the ordered sequence RESULT → DONE → clear CMD so NS never sees
    // DONE=1 with stale RESULT.
    unsafe {
        let cmd = core::ptr::read_volatile(SHARED_CMD);
        if cmd == CMD_NONE {
            return;
        }

        let args = GatewayArgs {
            arg0: core::ptr::read_volatile(SHARED_ARG0),
            arg1: core::ptr::read_volatile(SHARED_ARG1),
            arg2: core::ptr::read_volatile(SHARED_ARG2),
        };

        let result = dispatch(cmd, &args);

        core::ptr::write_volatile(SHARED_RESULT, result);
        // Order matters: write RESULT before DONE so NS can't see DONE=1
        // with stale RESULT. Then clear CMD last so NS can issue another.
        core::ptr::write_volatile(SHARED_DONE, 1);
        core::ptr::write_volatile(SHARED_CMD, CMD_NONE);
    }
}

/// Route a single mailbox command to its handler. All commands run with
/// exclusive access to `SecureState` for the duration of dispatch (see
/// the non-reentrant invariant on [`poll_gateway`]).
/// Route a mailbox command to its `cmd_*::run` handler (QEMU only).
///
/// # Safety
/// Called only from `poll_gateway`, which holds the single-threaded
/// invariant: no other gateway dispatch is concurrently in flight.
/// Each `cmd_*::run` is itself `unsafe fn` because of `static mut`
/// driver state and NS pointer derefs — see their per-fn `# Safety`
/// docs.
#[cfg(not(feature = "stm32u585"))]
unsafe fn dispatch(cmd: u32, args: &GatewayArgs) -> u32 {
    match cmd {
        CMD_GET_REMAINING => cmd_get_remaining::run(),
        CMD_REQUEST_UNLOCK => cmd_request_unlock::run(),
        CMD_SIGN_USEROP => cmd_sign_userop::run(args),
        CMD_SIGN_USEROP_BATCH => cmd_sign_userop_batch::run(args),
        CMD_GET_WALLET_ADDRESS => cmd_get_wallet_address::run(args),
        CMD_GET_INIT_CODE => cmd_get_init_code::run(args),
        CMD_SIGN_OFFCHAIN => cmd_sign_offchain::run(args),
        CMD_OFFCHAIN_STATUS => cmd_offchain_status::run(args),
        CMD_OFFCHAIN_SYNC => cmd_offchain_sync::run(args),
        CMD_IS_UNLOCKED => cmd_is_unlocked::run(),
        CMD_LOCK => cmd_lock::run(),
        #[cfg(feature = "e2e-test")]
        sphincs_tz_shared::CMD_TEST_PIN_LOCKOUT => cmd_test_pin_lockout::run(),
        // Prodtest commands — only present in the `prodtest` build
        // profile, never in production firmware.
        #[cfg(feature = "prodtest")]
        sphincs_tz_shared::CMD_PRODTEST_GET_ID => prodtest::cmd_get_id_run(args),
        #[cfg(feature = "prodtest")]
        sphincs_tz_shared::CMD_PRODTEST_DISPLAY_PATTERN => {
            prodtest::cmd_display_pattern_run(args)
        }
        #[cfg(feature = "prodtest")]
        sphincs_tz_shared::CMD_PRODTEST_SAES_SELFTEST => {
            prodtest::cmd_saes_selftest_run(args)
        }
        #[cfg(feature = "prodtest")]
        sphincs_tz_shared::CMD_PRODTEST_BHK_SELFTEST => {
            prodtest::cmd_bhk_selftest_run(args)
        }
        #[cfg(feature = "prodtest")]
        sphincs_tz_shared::CMD_PRODTEST_FLASH_RW => prodtest::cmd_flash_rw_run(args),
        #[cfg(feature = "prodtest")]
        sphincs_tz_shared::CMD_PRODTEST_TRNG_SAMPLE => {
            prodtest::cmd_trng_sample_run(args)
        }
        #[cfg(feature = "prodtest")]
        sphincs_tz_shared::CMD_PRODTEST_OPTIGA_HANDSHAKE => {
            prodtest::cmd_optiga_handshake_run(args)
        }
        #[cfg(feature = "prodtest")]
        sphincs_tz_shared::CMD_PRODTEST_SE050_HANDSHAKE => {
            prodtest::cmd_se050_handshake_run(args)
        }
        #[cfg(feature = "prodtest")]
        sphincs_tz_shared::CMD_PRODTEST_USB_LOOPBACK => {
            prodtest::cmd_usb_loopback_run(args)
        }
        #[cfg(feature = "prodtest")]
        sphincs_tz_shared::CMD_PRODTEST_BUTTON_TEST => {
            prodtest::cmd_button_test_run(args)
        }
        _ => NscStatus::InternalError as u32,
    }
}

// ---------------------------------------------------------------------------
// CMSE veneers — STM32U585 hardware transport
// ---------------------------------------------------------------------------
//
// Each function below is an ARMv8-M Security Extension entry point. The
// linker's `--cmse-implib` pass emits an SG stub for every one into
// `veneers.o`; that implib gets linked into the non-secure world, so NS
// resolves a normal `extern "C"` symbol at the stub address and calls it
// with `BLXNS`. The stub issues `SG`, switches to secure state, clears
// caller-saved registers, and transfers control here. On return the
// compiler emits `BXNS` back to NS.
//
// The bodies are intentionally thin: each one constructs a `GatewayArgs`
// snapshot and delegates straight to the same `cmd_*::run` handler the
// QEMU `dispatch()` path uses, so handler semantics stay identical
// across transports.
//
// Categories of `unsafe` in this section:
//
// 1. **CMSE veneers (`extern "cmse-nonsecure-entry" fn`)** — irreducible
//    category 1. The function signature is generated by the
//    `cmse-nonsecure-entry` attribute and is structurally `extern "C"`
//    with the TrustZone non-secure-entry calling convention. The linker
//    emits an SG stub in `veneers.o`; NS calls the stub via `BLXNS`,
//    the stub issues `SG`, switches to secure state, clears caller-
//    saved registers, and transfers control here. Cannot be made safe
//    without breaking the TrustZone ABI.
//
// 2. **`unsafe { cmd_*::run(...) }` calls** — each `cmd_*::run` is
//    `unsafe fn` because of its `static mut` driver access (`SE`,
//    `SLOT_CACHE`, `SNAP_BUF`, `FW_UPDATE`) and NS pointer derefs.
//    The CMSE veneer is the unique caller in production; the
//    single-threaded non-reentrant dispatcher invariant (no two
//    veneers in flight at once) makes the `unsafe` block sound — see
//    each handler's own `# Safety` doc-comment for the per-handler
//    precondition list.

/// CMD_GET_REMAINING — returns the remaining PIN attempts.
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_get_remaining_attempts() -> u32 {
    secure_log!("[NSC] get_remaining_attempts");
    let r = unsafe { cmd_get_remaining::run() };
    secure_log!("[NSC] get_remaining_attempts -> {}", r);
    r
}

/// CMD_REQUEST_UNLOCK — secure UI prompts for PIN, never crosses NS.
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_request_unlock() -> u32 {
    secure_log!("[NSC] request_unlock");
    let r = unsafe { cmd_request_unlock::run() };
    secure_log!("[NSC] request_unlock -> {}", r);
    r
}

/// CMD_SIGN_USEROP — unified Type 1 / Type 2 sign command.
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_sign_userop(
    payload_ptr: u32,
    sig_out_ptr: u32,
    total_len: u32,
) -> u32 {
    secure_log!("[NSC] sign_userop (len={})", total_len);
    let args = GatewayArgs { arg0: payload_ptr, arg1: sig_out_ptr, arg2: total_len };
    let r = unsafe { cmd_sign_userop::run(&args) };
    secure_log!("[NSC] sign_userop -> {}", r);
    r
}

/// CMD_SIGN_USEROP_BATCH — atomic multi-call sign command. Same
/// Type 1 / Type 2 wire output as `nsc_sign_userop`; payload differs
/// (header + N inner-tx blocks). See `cmd_sign_userop_batch.rs` for
/// the contract.
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_sign_userop_batch(
    payload_ptr: u32,
    sig_out_ptr: u32,
    total_len: u32,
) -> u32 {
    secure_log!("[NSC] sign_userop_batch (len={})", total_len);
    let args = GatewayArgs { arg0: payload_ptr, arg1: sig_out_ptr, arg2: total_len };
    let r = unsafe { cmd_sign_userop_batch::run(&args) };
    secure_log!("[NSC] sign_userop_batch -> {}", r);
    r
}

/// CMD_IS_UNLOCKED — return 1 if unlocked, 0 if locked.
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_is_unlocked() -> u32 {
    secure_log!("[NSC] is_unlocked");
    let r = unsafe { cmd_is_unlocked::run() };
    secure_log!("[NSC] is_unlocked -> {}", r);
    r
}

/// CMD_LOCK — zeroize secrets and lock the device.
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_lock() -> u32 {
    secure_log!("[NSC] lock");
    let r = unsafe { cmd_lock::run() };
    secure_log!("[NSC] lock -> {}", r);
    r
}

/// Register the NS USB-loop heartbeat counter address with the secure
/// IWDG watcher. Called once from NS boot. `addr` is the address of the
/// NS `static mut` heartbeat counter; the secure side range-validates
/// it against NS SRAM before storing. Returns 0 on success, 1 if the
/// address failed validation. Gated on `iwdg` on both sides so a
/// non-iwdg build links no dangling veneer symbol.
#[cfg(all(feature = "stm32u585", feature = "iwdg"))]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_register_heartbeat(addr: u32) -> u32 {
    secure_log!("[NSC] register_heartbeat(0x{:08x})", addr);
    // TZ4 / work-todo #12b: validate the NS-supplied 4-byte heartbeat address
    // through the SAME FI-doubled NS-pointer typestate every other veneer uses
    // (`validate_read` runs `validate_ns_read_ptr` twice through
    // `check_true_into_sentinel`). This adds the shared-mailbox-disjoint check
    // and the hardware `TT`/SAU reclassification that iwdg's inline window check
    // lacked, and requires two coordinated faults to bypass. `iwdg`'s own
    // alignment+window check stays as defense-in-depth (and covers the 4-byte
    // alignment the `read_volatile(_ as *const u32)` in SysTick relies on).
    if ns_ptr::NsPtr::<u8>::new(addr).validate_read(4).is_err() {
        return 1;
    }
    if crate::hw::iwdg::register_ns_heartbeat(addr) {
        0
    } else {
        1
    }
}

/// CMD_TEST_PIN_LOCKOUT — non-interactive brute-force verification.
/// Destructive (locks SE050 silicon + maxes MCU counter); only built
/// under `e2e-test`. See `cmd_test_pin_lockout.rs` for the contract.
#[cfg(all(feature = "stm32u585", feature = "e2e-test"))]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_test_pin_lockout() -> u32 {
    secure_log!("[NSC] test_pin_lockout");
    let r = unsafe { cmd_test_pin_lockout::run() };
    secure_log!("[NSC] test_pin_lockout -> {}", r);
    r
}

/// CMD_TZIC_STATUS — read the GTZC1 illegal-access counter.
///
/// Non-destructive, no PIN required: returns the running u32 count of
/// NS→SECURE access violations the TZIC IRQ has logged since boot.
/// Pairs with the `gtzc-test` NS validation driver — see
/// `cmd_tzic_status.rs`.
#[cfg(all(feature = "stm32u585", feature = "e2e-test"))]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_tzic_status() -> u32 {
    let r = unsafe { cmd_tzic_status::run() };
    secure_log!("[NSC] tzic_status -> {}", r);
    r
}

// ---------------------------------------------------------------------------
// Prodtest CMSE veneers (`prodtest` feature)
// ---------------------------------------------------------------------------

/// CMD_PRODTEST_GET_ID (100) — read STM32 UID + firmware version.
#[cfg(feature = "prodtest")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_prodtest_get_id(out_ptr: u32) -> u32 {
    let args = GatewayArgs {
        arg0: 0,
        arg1: out_ptr,
        arg2: 0,
    };
    let r = unsafe { prodtest::cmd_get_id_run(&args) };
    secure_log!("[NSC] prodtest_get_id -> {}", r);
    r
}

/// CMD_PRODTEST_DISPLAY_PATTERN (101) — render NV3007 LCD test pattern.
#[cfg(feature = "prodtest")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_prodtest_display_pattern(in_ptr: u32) -> u32 {
    let args = GatewayArgs {
        arg0: in_ptr,
        arg1: 0,
        arg2: 0,
    };
    let r = unsafe { prodtest::cmd_display_pattern_run(&args) };
    secure_log!("[NSC] prodtest_display_pattern -> {}", r);
    r
}

/// CMD_PRODTEST_SAES_SELFTEST (102) — DHUK fingerprint.
#[cfg(feature = "prodtest")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_prodtest_saes_selftest(out_ptr: u32) -> u32 {
    let args = GatewayArgs {
        arg0: 0,
        arg1: out_ptr,
        arg2: 0,
    };
    let r = unsafe { prodtest::cmd_saes_selftest_run(&args) };
    secure_log!("[NSC] prodtest_saes_selftest -> {}", r);
    r
}

/// CMD_PRODTEST_BHK_SELFTEST (103) — BHK fingerprint.
#[cfg(feature = "prodtest")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_prodtest_bhk_selftest(out_ptr: u32) -> u32 {
    let args = GatewayArgs {
        arg0: 0,
        arg1: out_ptr,
        arg2: 0,
    };
    let r = unsafe { prodtest::cmd_bhk_selftest_run(&args) };
    secure_log!("[NSC] prodtest_bhk_selftest -> {}", r);
    r
}

/// CMD_PRODTEST_FLASH_RW (104) — flash R/W round-trip on the test page.
#[cfg(feature = "prodtest")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_prodtest_flash_rw(in_ptr: u32) -> u32 {
    let args = GatewayArgs {
        arg0: in_ptr,
        arg1: 0,
        arg2: 0,
    };
    let r = unsafe { prodtest::cmd_flash_rw_run(&args) };
    secure_log!("[NSC] prodtest_flash_rw -> {}", r);
    r
}

/// CMD_PRODTEST_TRNG_SAMPLE (105) — N bytes from MCU TRNG.
#[cfg(feature = "prodtest")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_prodtest_trng_sample(in_ptr: u32, out_ptr: u32) -> u32 {
    let args = GatewayArgs {
        arg0: in_ptr,
        arg1: out_ptr,
        arg2: 0,
    };
    let r = unsafe { prodtest::cmd_trng_sample_run(&args) };
    secure_log!("[NSC] prodtest_trng_sample -> {}", r);
    r
}

/// CMD_PRODTEST_OPTIGA_HANDSHAKE (106) — exercise OPTIGA I²C + APDU.
#[cfg(feature = "prodtest")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_prodtest_optiga_handshake(out_ptr: u32) -> u32 {
    let args = GatewayArgs {
        arg0: 0,
        arg1: out_ptr,
        arg2: 0,
    };
    let r = unsafe { prodtest::cmd_optiga_handshake_run(&args) };
    secure_log!("[NSC] prodtest_optiga_handshake -> {}", r);
    r
}

/// CMD_PRODTEST_SE050_HANDSHAKE (107) — exercise SE050 T=1' + APDU.
#[cfg(feature = "prodtest")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_prodtest_se050_handshake(out_ptr: u32) -> u32 {
    let args = GatewayArgs {
        arg0: 0,
        arg1: out_ptr,
        arg2: 0,
    };
    let r = unsafe { prodtest::cmd_se050_handshake_run(&args) };
    secure_log!("[NSC] prodtest_se050_handshake -> {}", r);
    r
}

/// CMD_PRODTEST_USB_LOOPBACK (108) — echo N bytes for USB integrity.
#[cfg(feature = "prodtest")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_prodtest_usb_loopback(
    in_ptr: u32,
    out_ptr: u32,
    n: u32,
) -> u32 {
    let args = GatewayArgs {
        arg0: in_ptr,
        arg1: out_ptr,
        arg2: n,
    };
    let r = unsafe { prodtest::cmd_usb_loopback_run(&args) };
    secure_log!("[NSC] prodtest_usb_loopback({}) -> {}", n, r);
    r
}

/// CMD_PRODTEST_BUTTON_TEST (109) — 3-step LEFT/RIGHT/BOTH verification.
#[cfg(feature = "prodtest")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_prodtest_button_test(out_ptr: u32) -> u32 {
    let args = GatewayArgs {
        arg0: 0,
        arg1: out_ptr,
        arg2: 0,
    };
    let r = unsafe { prodtest::cmd_button_test_run(&args) };
    secure_log!("[NSC] prodtest_button_test -> {}", r);
    r
}

// ---------------------------------------------------------------------------
// Firmware-update CMSE veneers
// ---------------------------------------------------------------------------

/// CMD_FW_BEGIN — initiate firmware-update streaming session.
/// arg0 = manifest_ptr, arg2 = MANIFEST_SIZE (8192).
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_fw_begin(manifest_ptr: u32, manifest_len: u32) -> u32 {
    let args = GatewayArgs {
        arg0: manifest_ptr,
        arg1: 0,
        arg2: manifest_len,
    };
    unsafe { cmd_fw_begin::run(&args) }
}

/// CMD_FW_CHUNK — stream one image chunk. arg0 = chunk_ptr, arg2 = chunk_len.
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_fw_chunk(chunk_ptr: u32, chunk_len: u32) -> u32 {
    let args = GatewayArgs {
        arg0: chunk_ptr,
        arg1: 0,
        arg2: chunk_len,
    };
    unsafe { cmd_fw_chunk::run(&args) }
}

/// CMD_FW_COMMIT — finalize staged update. No args.
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_fw_commit() -> u32 {
    let args = GatewayArgs { arg0: 0, arg1: 0, arg2: 0 };
    unsafe { cmd_fw_commit::run(&args) }
}

/// CMD_FW_STATUS — read update progress. arg1 = out_ptr.
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_fw_status(out_ptr: u32) -> u32 {
    let args = GatewayArgs { arg0: 0, arg1: out_ptr, arg2: 0 };
    unsafe { cmd_fw_status::run(&args) }
}

/// CMD_FW_ABORT — discard partial update.
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_fw_abort() -> u32 {
    unsafe { cmd_fw_abort::run() }
}

/// CMD_GET_WALLET_ADDRESS — compute CREATE2-predicted wallet address for
/// `account_index` (0..=255). Account 0 is the legacy single-account
/// derivation; higher indices yield independent on-chain wallets from
/// the same BIP-39 seed. `show = 1` routes the derived address through
/// the trusted-OLED confirm (#472) before any NS-bound write.
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_get_wallet_address(
    out_ptr: u32,
    account_index: u32,
    show: u32,
) -> u32 {
    secure_log!("[NSC] get_wallet_address (acct={})", account_index);
    let args = GatewayArgs { arg0: out_ptr, arg1: account_index, arg2: show };
    let r = unsafe { cmd_get_wallet_address::run(&args) };
    secure_log!("[NSC] get_wallet_address -> {}", r);
    r
}

/// CMD_GET_INIT_CODE — return the 4280-byte ERC-4337 initCode for
/// `(account_index, chain_id)`. Companion uses it to get accurate
/// gas estimates for first-deploy UserOps; the same bytes are
/// emitted by the deploy path of `CMD_SIGN_USEROP`. See the command
/// docs in `shared::CMD_GET_INIT_CODE`.
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_get_init_code(
    in_ptr: u32,
    out_ptr: u32,
    in_len: u32,
) -> u32 {
    secure_log!("[NSC] get_init_code (len={})", in_len);
    let args = GatewayArgs { arg0: in_ptr, arg1: out_ptr, arg2: in_len };
    let r = unsafe { cmd_get_init_code::run(&args) };
    secure_log!("[NSC] get_init_code -> {}", r);
    r
}

/// CMD_SIGN_OFFCHAIN — sign an EIP-1271 hash with the slot key.
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_sign_offchain(
    in_ptr: u32,
    out_ptr: u32,
    in_len: u32,
) -> u32 {
    secure_log!("[NSC] sign_offchain (len={})", in_len);
    let args = GatewayArgs { arg0: in_ptr, arg1: out_ptr, arg2: in_len };
    let r = unsafe { cmd_sign_offchain::run(&args) };
    secure_log!("[NSC] sign_offchain -> {}", r);
    r
}

/// CMD_OFFCHAIN_STATUS — read the firmware's per-slot off-chain state.
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_offchain_status(
    in_ptr: u32,
    out_ptr: u32,
    in_len: u32,
) -> u32 {
    let args = GatewayArgs { arg0: in_ptr, arg1: out_ptr, arg2: in_len };
    unsafe { cmd_offchain_status::run(&args) }
}

/// CMD_OFFCHAIN_SYNC — bump the firmware's per-slot `last_userop_count`
/// to a companion-supplied floor. See `cmd_offchain_sync::run` for the
/// full rationale (firmware-reflash recovery).
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_offchain_sync(in_ptr: u32, in_len: u32) -> u32 {
    let args = GatewayArgs { arg0: in_ptr, arg1: 0, arg2: in_len };
    unsafe { cmd_offchain_sync::run(&args) }
}

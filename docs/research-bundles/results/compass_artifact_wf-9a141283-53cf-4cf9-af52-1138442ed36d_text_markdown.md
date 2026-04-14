# Hardening PQSigner OS against fault injection on STM32U585

**A single random fault during SLH-DSA signing enables universal forgery with >90% probability, and verify-after-sign does not catch it.** This finding from Genêt (TCHES 2023) and confirmed by RFC 9814 (July 2025) fundamentally changes the countermeasure strategy for code path #2. Meanwhile, a 2024 Masaryk University thesis demonstrated **76% success rate** voltage-glitching a PIN check bypass on the STM32U5A9 (same Cortex-M33 core as the STM32U585) using a $500 ChipWhisperer Husky. The STM32U585's SESIP Level 3 certification provides meaningful but not absolute protection — your three code paths each require distinct layered software countermeasures, and your hardware defaults (BOR Level 0, IWDG unconfigured, SRAM ECC off) must change before any software hardening matters.

---

## The STM32U5 is demonstrably glitchable

The most directly relevant attack research is Oliver Simonik's 2024/2025 thesis at Masaryk University, which targeted the **STM32U5A9** (the same Cortex-M33 core and security IP as your STM32U585) using both voltage glitching (ChipWhisperer Husky) and EMFI (PicoEMP). A simplified PIN check was bypassed at **76% success rate** via voltage glitch — the fault model is instruction skip on the conditional branch evaluating the PIN comparison. Both EMFI and voltage glitching produced viable faults, and in some cases the chip leaked unexpected extra memory data beyond the intended output.

This directly contradicts Ledger's 2024 claim that "no fault injection attack has been made public" on the STM32U5. It has, and your identical core is vulnerable.

The broader Cortex-M33 threat landscape is severe. The **μ-Glitch** paper (USENIX Security 2023, Saß et al.) demonstrated that multi-glitch attacks can fully bypass TrustZone-M on the NXP LPC55S69 and STM32L5 — both Cortex-M33 devices with TrustZone. Their key finding: **4 consecutive voltage faults** defeated NXP's "duplicate register" countermeasure (designed specifically against single-fault attacks) with a success window of ~1.5 days of automated searching. The μ-Glitch team's 50× search speedup algorithm makes multi-fault attacks practical even against targets with redundant checks.

The dominant fault model across all recent publications is **instruction skip**: a voltage dip or EM pulse during fetch/decode causes the pipeline to execute a NOP instead of the target instruction. On ARM Thumb-2, a single glitch can skip multiple instructions because the 16-bit instruction encoding is smaller than the 32-bit fetch width (Moro et al.). GlitchResistor (Spensky et al., DSN 2021) measured **100% success rate** bypassing unprotected conditional branches on Cortex-M with an **8 clock-cycle attack window**. A secondary model — data corruption — shows ~30% "register sweeping to 0x0" (NDSS 2024 bus fault paper), where load instructions return all-zeros regardless of actual memory contents.

For **EMFI** specifically, the CanSecWest 2024 talk by VoidStar demonstrated full RDP bypass on STM32F4 using a PicoEMP with automated 3D-printer probe positioning. EMFI is preferred over voltage glitching in practice because it causes fewer permanent device failures. **LFI** (laser) remains the most precise attack — Riscure has reported breaking FI-hardened wallet firmware (Coldcard) using multiple precisely-timed laser faults — but requires die decapsulation and $50K+ equipment.

---

## SLH-DSA's devastating fault vulnerability changes everything about code path #2

The most consequential finding for PQSigner OS is that **SLH-DSA is uniquely fragile against fault injection among all NIST PQC standards**. The "Grafting Trees" attack (Castelnovi-Martinelli-Prest, PQCrypto 2018) showed that faulting any non-top hash computation during signing lets an attacker construct a universal forgery — the ability to sign arbitrary messages — without recovering the secret key. Genêt's comprehensive analysis (TCHES 2023) proved this works with **>90% probability for any single random bit flip anywhere in signing**, regardless of hash function, parameter set, or whether hedged signing is used.

**RFC 9814 (IETF, July 2025) explicitly warns**: "Verifying a signature before releasing the signature value is a typical fault-attack countermeasure; however, this countermeasure is **not effective for SLH-DSA**." This is because faulty SLH-DSA signatures often still pass standard verification — the verification algorithm simply follows the faulted computation path and arrives at the correct root. Saarinen's SLotH analysis (NIST 5th PQC Conference 2024) independently confirms: "A 'sign-then-verify' operation unfortunately does not detect a faulty signature."

The only reliable software countermeasure is **full double-computation**: sign the message twice with independent computation paths, compare the two signatures byte-by-byte, and release only if they match exactly. This roughly doubles signing time. For SLH-DSA-SHA2-128f on Cortex-M4 at 168 MHz, the pqm4 benchmarks show ~3.1 seconds per signature, so double-computation costs ~6.2 seconds total. On the STM32U585 at 160 MHz, expect similar figures.

A September 2025 paper (Boy et al., "SLasH-DSA") demonstrated **software-only** universal forgery against SLH-DSA using Rowhammer — no physical access required — achieving forgery in 1–8 hours against OpenSSL 3.5.1. While Rowhammer is less relevant to your SRAM-based MCU (no DRAM), it underscores that SLH-DSA fault sensitivity is not merely a theoretical concern.

---

## Your hardware defaults are dangerously insecure

Before discussing software countermeasures, your STM32U585's **factory-default configuration** has critical gaps that must be addressed:

**BOR (Brown-Out Reset)** is at Level 0 (~1.7V threshold). This means the MCU continues executing with VDD as low as 1.7V — well within the range where voltage glitches produce reliable instruction skips. Set `BOR_LEV` to **Level 3 (~2.5V) or Level 4 (~2.8V)** in the `FLASH_OPTR` option byte. This single change dramatically narrows the attacker's voltage glitch window by triggering a reset before VDD drops enough for fault injection. BOR is always-on and cannot be software-bypassed.

**PVD (Programmable Voltage Detector)** should be enabled at the highest practical threshold below nominal VDD, generating an EXTI interrupt that triggers immediate secret erasure. The STM32U5 additionally has **temperature and upper-VDD threshold monitors** that feed directly into the TAMP (tamper detection) subsystem — these are disabled by default and should be enabled, as they detect the thermal and voltage anomalies that accompany fault injection attempts.

**IWDG** should be configured as a **hardware watchdog** (`IWDG_SW=0` in `FLASH_OPTR`) with a **short timeout** (100–500ms). Hardware watchdog mode starts the watchdog at reset and cannot be disabled by software — if a fault injection causes the CPU to hang or loop, the IWDG forces a reset. Enable IWDG operation in Stop and Standby modes via `IWDG_STOP` and `IWDG_STDBY` bits.

**SRAM ECC** for SRAM2 and SRAM3 must be enabled via option bytes (`SRAM2_ECC`, `SRAM3_ECC` in `FLASH_OPTR`). Flash ECC (SECDED) is always active but the double-error NMI handler must be implemented — on ECCD, immediately erase secrets and reset. Single-error corrections (ECCC) should be logged as potential attack indicators.

**CSS (Clock Security System)** on HSE should be enabled (`RCC_CR.CSSON=1`) to detect clock glitching. CSS on LSE is connected to internal tamper event ITAMP3 and should be enabled for RTC/tamper subsystem integrity.

**TAMP** internal tampers (ITAMP1 for VBAT voltage, ITAMP2 for temperature, ITAMP3 for LSE CSS) should all be enabled with automatic erasure of backup registers, SRAM2, and crypto keys on detection.

---

## The countermeasure toolkit ranked by cost-effectiveness

Each pattern below is evaluated against four fault classes: single voltage glitch (SVG), double voltage glitch (DVG), EMFI, and LFI.

**Magic-constant state variables** replace booleans with multi-bit values like `0xCAFE_BABE` (unlocked) and `0x10AF_B0DA` (locked), where the default is always the secure state. A register swept to 0x0 or 0xFFFF_FFFF never matches the "insecure" magic. This is the highest cost-benefit countermeasure — zero runtime overhead, defends against SVG and data corruption, partially effective against EMFI. Does not defend against targeted LFI producing exact magic values. MCUboot uses **0x1AAA_AAAA** (success) and **0x1555_5555** (failure) — high Hamming distance from each other, from zero, and from all-ones.

**Complement storage** (MCUboot's "double variables") stores each critical value alongside its XOR complement (value ^ 0xBEEF). Before use, verify `val == (msk ^ MASK)`. Detects single data corruption, register sweeping, and most EMFI-induced bit flips. Costs **2× storage** per protected variable and ~5 extra instructions per validation. Ineffective against coordinated multi-glitch corrupting both val and msk simultaneously.

**Redundant volatile reads with fail-in comparison** (NCC Group CM-1-C) reads the same value 2–3 times via `core::ptr::read_volatile`, then uses logical OR for closed-state checks ("if any read is wrong, fail") and logical AND for open-state checks ("all reads must agree to open"). This is the core NCC Group pattern and provides **double-glitch resistance**: skipping any single comparison or corrupting any single read still triggers the secure path. Costs ~3× read time. Critical implementation detail: use `core::ptr::read_volatile` (which maps to LLVM volatile loads that cannot be eliminated by GVN) rather than `core::hint::black_box` (which the Rust docs explicitly state "does not offer any guarantees for cryptographic or security purposes").

**Random delays** insert variable-length NOP sleds using the DWT cycle counter or TRNG before security-critical operations. This desynchronizes the attacker's glitch timing relative to external triggers (SPI/I2C/GPIO edges). Moderately effective against voltage glitch and clock glitch; less effective against attackers with EM side-channel capability who can observe the delay duration. Costs variable execution time (up to ~255 iterations).

**Control flow integrity step counters** (MCUboot's FIH_CALL pattern) maintain a global counter incremented before each critical function call and decremented on return. After the call, verify the counter returned to its pre-call value. Detects function-skip faults where a glitch causes the entire function call to be NOPed. Costs ~4 instructions per protected call/return. Does not detect faults within the called function's body.

**Inline assembly for critical comparisons** provides the highest per-check assurance by preventing all compiler optimizations and giving exact control over instruction placement. Reserve this for the most critical checks (key validation, lockout triggers). Example: two `cmp`/`bne` pairs in `asm!()` with `udf #0` (HardFault) on failure. Costs maintainability and portability.

---

## Code path #1: Seed XOR-reconstruction in `DualSecureElement::unlock`

The threat here is a single glitch skipping the cross-verification branch (`if !match_ok` or `if !consistent`) to allow a tampered SE to inject a known half without detection. The `blob_cached = true` single-bool write is also a glitch target.

**Countermeasure architecture** (five layers):

First, replace all boolean state variables with `FihInt` magic-constant types. `match_ok` should never be a `bool` — it should be a `FihInt` initialized to `FIH_FAILURE` (0x1555_5555) and only set to `FIH_SUCCESS` (0x1AAA_AAAA) after passing all checks. `blob_cached` must become a `FihInt` with complement storage, not a bare `bool`.

```rust
use core::ptr::{read_volatile, write_volatile};
use core::arch::asm;

const FIH_SUCCESS: u32 = 0x1AAA_AAAA;
const FIH_FAILURE: u32 = 0x1555_5555;
const FIH_MASK: u32    = 0x0000_BEEF;

#[repr(C)]
pub struct FihInt {
    val: u32,
    msk: u32,
}

impl FihInt {
    #[inline(always)]
    pub fn failure() -> Self {
        FihInt { val: FIH_FAILURE, msk: FIH_FAILURE ^ FIH_MASK }
    }
    #[inline(always)]
    pub fn set_success(&mut self) {
        unsafe {
            write_volatile(&mut self.val, FIH_SUCCESS);
            write_volatile(&mut self.msk, FIH_SUCCESS ^ FIH_MASK);
        }
    }
    #[inline(always)]
    pub fn is_success(&self) -> bool {
        let v = unsafe { read_volatile(&self.val) };
        let m = unsafe { read_volatile(&self.msk) };
        let check1 = v == FIH_SUCCESS;
        let check2 = m == (FIH_SUCCESS ^ FIH_MASK);
        let v2 = unsafe { read_volatile(&self.val) };
        let m2 = unsafe { read_volatile(&self.msk) };
        // All four must agree — fail-out (AND) for open state
        check1 && check2 && (v2 == FIH_SUCCESS) && (m2 == (FIH_SUCCESS ^ FIH_MASK))
    }
}
```

Second, implement a **CFI step counter** through the entire unlock flow. Each critical stage (read OPTIGA, read SE050, XOR-reconstruct, derive master_secret, cross-verify, encrypt blob) increments the counter. After the flow completes, verify the counter matches the expected step count.

```rust
pub struct CfiCounter {
    actual: u32,
    complement: u32,
}

impl CfiCounter {
    pub fn new() -> Self { CfiCounter { actual: 0, complement: !0u32 } }

    #[inline(always)]
    pub fn step(&mut self) {
        let a = unsafe { read_volatile(&self.actual) };
        unsafe { write_volatile(&mut self.actual, a.wrapping_add(1)) };
        let c = unsafe { read_volatile(&self.complement) };
        unsafe { write_volatile(&mut self.complement, c.wrapping_sub(1)) };
    }

    #[inline(always)]
    pub fn verify(&self, expected: u32) {
        let a = unsafe { read_volatile(&self.actual) };
        let c = unsafe { read_volatile(&self.complement) };
        if a != expected || c != !expected {
            panic_and_wipe();
        }
        // Redundant check — double-glitch resistant
        let a2 = unsafe { read_volatile(&self.actual) };
        let c2 = unsafe { read_volatile(&self.complement) };
        if a2 != expected || c2 != !expected {
            panic_and_wipe();
        }
    }
}
```

Third, the **cross-verification itself** must use the fail-in pattern. The `subtle::ConstantTimeEq` result should be read, stored as a `FihInt`, then re-verified:

```rust
// After ct_eq comparison
let ct_result = derived_key.ct_eq(&expected_key);
random_delay(); // desync glitch timing from I2C completion

let mut match_result = FihInt::failure(); // default: FAIL
if bool::from(ct_result) {
    match_result.set_success();
}

// Fail-in: ANY failure → wipe
if !match_result.is_success() {
    panic_and_wipe();
}
// Temporal separation — random delay between checks
random_delay();
// Second independent check
if !match_result.is_success() {
    panic_and_wipe();
}
```

Fourth, **redundant volatile reads of SE outputs** should compare the half read from each SE against a second read. If the SE protocol doesn't support re-reading, hash the received half immediately and store the hash alongside the value; before XOR-reconstruction, re-hash and compare. This detects SRAM corruption between receive and use.

Fifth, `blob_cached` must be a `FihInt` and every check of its state must use the double-read pattern. The write must be followed by a read-back verification:

```rust
// After encrypting and storing blob
self.blob_cached.set_success();
// Read-back verify
if !self.blob_cached.is_success() {
    panic_and_wipe();
}
```

---

## Code path #2: SLH-DSA signature — double-compute, never verify-after-sign

This is the most critical code path. **Do not implement verify-after-sign as your primary countermeasure.** RFC 9814 and Genêt (TCHES 2023) have proven that faulty SLH-DSA signatures pass standard verification with significant probability. A faulted signature that verifies correctly still enables the Grafting Trees attack — the attacker extracts intermediate WOTS+ chain values from the faulty signature to construct universal forgeries.

The **required countermeasure** is full double-computation with glitch-resistant comparison:

```rust
/// Sign message using SLH-DSA-SHA2-128f with double-computation.
/// Returns signature only if both computations produce identical results.
#[inline(never)]
pub fn sign_double_compute(
    sk: &SlhDsaSecretKey,
    msg: &[u8],
    sig_buf: &mut [u8; SLH_DSA_SIG_LEN],
) -> Result<(), SignError> {
    let mut cfi = CfiCounter::new();

    // First computation
    random_delay();
    cfi.step(); // step 1
    let mut sig1 = [0u8; SLH_DSA_SIG_LEN];
    slh_dsa_sign_internal(sk, msg, &mut sig1)?;
    cfi.step(); // step 2

    // Second computation — use DIFFERENT stack/heap region
    // to prevent single EMFI from corrupting both
    random_delay();
    cfi.step(); // step 3
    let mut sig2 = [0u8; SLH_DSA_SIG_LEN];
    slh_dsa_sign_internal(sk, msg, &mut sig2)?;
    cfi.step(); // step 4

    // Constant-time comparison with FihInt result
    let ct_match = sig1.ct_eq(&sig2);
    let mut sigs_match = FihInt::failure();
    if bool::from(ct_match) {
        sigs_match.set_success();
    }

    // Double-check with fail-in before release
    if !sigs_match.is_success() {
        zeroize_and_abort(&mut sig1, &mut sig2);
        return Err(SignError::FaultDetected);
    }
    random_delay();
    if !sigs_match.is_success() {
        zeroize_and_abort(&mut sig1, &mut sig2);
        return Err(SignError::FaultDetected);
    }

    // CFI verification — all 4 steps must have executed
    cfi.verify(4);

    // Gate release behind magic constant
    let mut release_gate = FihInt::failure();
    release_gate.set_success();

    if !release_gate.is_success() {
        zeroize_and_abort(&mut sig1, &mut sig2);
        return Err(SignError::FaultDetected);
    }

    // Volatile write to NS memory
    unsafe {
        core::ptr::copy_nonoverlapping(
            sig1.as_ptr(),
            sig_buf.as_mut_ptr(),
            SLH_DSA_SIG_LEN,
        );
    }

    // Zeroize working copies
    sig1.zeroize();
    sig2.zeroize();

    Ok(())
}
```

**Critical implementation details for double-computation:**

The two signing calls should operate on **separate memory regions** to prevent a single spatially-localized EMFI pulse from corrupting both. On STM32U585 with 786 KB SRAM split across SRAM1–SRAM4, place `sig1` in SRAM1 and `sig2` in SRAM3 using linker section attributes. With SLH-DSA-SHA2-128f signatures at **17,088 bytes** each, this requires ~34 KB of SRAM for the double buffers.

Both signing calls must use the **same** `opt_rand` value for deterministic comparison. Generate the random nonce once, store it, and pass it to both calls. If using hedged signing (recommended for side-channel resistance), the randomness must be captured before the first call and replayed for the second.

**Optionally** add verify-after-sign as a **third** layer (defense in depth), but understand it catches only a fraction of faults. The verify costs only ~4% of signing time for the "f" parameter sets, so the marginal cost is trivial:

```rust
// Optional third layer — catches some faults that double-compute misses
// (e.g., persistent fault affecting both computations identically)
let verify_ok = slh_dsa_verify(&pk, msg, sig_buf);
if !verify_ok {
    // This ALONE is insufficient — faulty sigs often verify.
    // But it catches persistent faults and gross corruption.
    zeroize_and_abort(sig_buf);
    return Err(SignError::VerifyFailed);
}
```

**Performance budget**: SLH-DSA-SHA2-128f signing on Cortex-M4 at 160 MHz takes approximately **3.1 seconds**. Double-computation costs **~6.2 seconds**. Adding verify costs an additional **~0.13 seconds**. Total: ~6.3 seconds per hardened signature. This is acceptable for a hardware wallet where the user physically confirms each transaction.

---

## Code path #3: PIN-lockout trigger in `cmd_request_unlock.rs`

The `if new_remaining == 0` comparison is a classic single-glitch target — an instruction skip changes "execute lockout wipe" to "continue normally." The `Err(UnlockError::PinLocked)` match arm is equally vulnerable.

**Countermeasure architecture** (four layers):

First, **invert the comparison logic to fail-in**. Instead of checking "if remaining == 0, then wipe", check "if remaining != 0, then continue" — using the NCC Group OR-based fail-in pattern where any anomaly triggers the secure path:

```rust
const ATTEMPTS_ALIVE_MAGIC: u32 = 0x3C96_A55A; // "attempts remain"
const ATTEMPTS_DEAD_MAGIC: u32  = 0xC369_5AA5; // "attempts exhausted"

#[inline(never)]
pub fn check_pin_and_enforce_lockout(
    pin: &[u8],
    se: &mut SecureElement,
) -> Result<(), UnlockError> {
    random_delay(); // desync from USB packet arrival

    let result = se.verify_pin_with_chip(pin);
    let new_remaining = se.get_remaining_attempts();

    // Store remaining as FihInt
    let mut state = FihInt::failure(); // default: DEAD/locked

    // Read remaining via volatile, twice
    let r1 = unsafe { read_volatile(&new_remaining) };
    let r2 = unsafe { read_volatile(&new_remaining) };

    // Fail-in: ANY indication of lockout → wipe
    // Using OR logic: if r1 == 0 OR r2 == 0 OR r1 != r2 → wipe
    if r1 == 0 || r2 == 0 || r1 != r2 {
        trigger_lockout_wipe_hardened();
        return Err(UnlockError::PinLocked);
    }

    // Only if remaining > 0 AND consistent, mark alive
    if r1 > 0 && r2 > 0 && r1 == r2 {
        state.set_success();
    }

    // Check the Err variant — fail-in
    match result {
        Err(UnlockError::PinLocked) => {
            trigger_lockout_wipe_hardened();
            return Err(UnlockError::PinLocked);
        }
        Err(e) => {
            // Any other error: still check remaining
            if !state.is_success() {
                trigger_lockout_wipe_hardened();
            }
            return Err(e);
        }
        Ok(()) => {
            // PIN correct — but STILL verify remaining is sane
            if !state.is_success() {
                trigger_lockout_wipe_hardened();
                return Err(UnlockError::PinLocked);
            }
        }
    }

    random_delay();

    // Final redundant check before returning success
    if !state.is_success() {
        trigger_lockout_wipe_hardened();
        return Err(UnlockError::PinLocked);
    }

    Ok(())
}
```

Second, **harden `trigger_lockout_wipe` itself** to be glitch-resistant. The function must be resilient to instruction skips within its body:

```rust
#[inline(never)]
fn trigger_lockout_wipe_hardened() -> ! {
    // Set lockout flag FIRST (complement storage)
    let mut lockout_flag = FihInt::failure();
    lockout_flag.set_success(); // "lockout active"

    // Wipe SRAM2 (secrets)
    wipe_sram2();
    // Redundant wipe
    wipe_sram2();

    // Verify wipe occurred (read-back check)
    if !verify_sram2_zeroed() {
        // If wipe failed, trigger hardware tamper
        trigger_hardware_tamper();
    }

    // Erase backup registers via TAMP
    erase_backup_registers();

    // Force system reset via IWDG or NVIC
    unsafe {
        // Write invalid key to IWDG to force immediate reset
        write_volatile(0x4000_3000 as *mut u32, 0x0000_0000);
        // Also trigger NVIC system reset
        core::arch::asm!(
            "dsb sy",
            "ldr r0, =0xE000ED0C", // AIRCR
            "ldr r1, =0x05FA0004", // SYSRESETREQ
            "str r1, [r0]",
            "dsb sy",
            "2: b 2b", // infinite loop if reset doesn't happen
            options(noreturn)
        );
    }
}
```

Third, the **remaining-attempts counter** stored in the SE should be read back after each decrement and verified. Use the SE's attestation mechanism (SE050 attestation or OPTIGA `checkChip`) to authenticate the response — a glitched host MCU accepting a forged "3 attempts remaining" response when the SE actually returned 0 is a real threat vector.

Fourth, add a **software monotonic counter shadow** in the TAMP backup registers. Each PIN attempt increments this counter. On boot, compare the shadow counter against the SE's counter — if the shadow shows more attempts than the SE, a rollback or glitch has occurred and the device should wipe.

---

## Preventing rustc/LLVM from defeating your countermeasures

The compiler is your first adversary. LLVM's GVN (Global Value Numbering), DSE (Dead Store Elimination), and SimplifyCFG passes are designed to eliminate exactly the redundancy that FI countermeasures rely on. The Rust ecosystem currently has **no dedicated crate** for fault injection resistance — this is a significant gap.

**`core::ptr::read_volatile` is your foundation.** LLVM's specification guarantees that volatile loads are never eliminated by GVN or CSE. This is the only mechanism with a formal guarantee in the LLVM IR specification. Every security-critical read must use `read_volatile`. Every security-critical write must use `write_volatile` followed by a `read_volatile` verification.

**`core::hint::black_box` is explicitly unsafe for security purposes.** The Rust standard library documentation states: "This function does not offer any guarantees for cryptographic or security purposes." It is a best-effort optimization barrier only. Do not rely on it.

**Inline assembly (`core::arch::asm!`)** provides the strongest guarantee: the compiler cannot modify, reorder, or eliminate assembly instructions. For the most critical comparisons (lockout checks, signature release gates), write the comparison in assembly:

```rust
/// Double-check equality in assembly — compiler cannot optimize away
#[inline(always)]
pub unsafe fn asm_double_check_eq(value: u32, expected: u32) {
    core::arch::asm!(
        "cmp {val}, {exp}",
        "bne 2f",        // first check
        "nop",           // temporal separation
        "cmp {val}, {exp}",
        "bne 2f",        // second check
        "b 3f",          // both passed
        "2:",
        "udf #0",        // HardFault on failure
        "3:",
        val = in(reg) value,
        exp = in(reg) expected,
        options(nostack, preserves_flags)
    );
}
```

**Compiler barriers** between redundant checks prevent reordering. Use `asm!("", options(nostack))` (without `nomem`) as a memory clobber — LLVM treats this as potentially reading/writing any memory location, preventing reordering of volatile operations across the barrier.

**`#[inline(never)]`** prevents inlining but does NOT prevent interprocedural analysis. LLVM can still propagate constants and derive function attributes across `noinline` boundaries. For stronger isolation, place FI-critical functions in a **separate crate compiled without LTO**, or combine `#[inline(never)]` with `#[no_mangle]`.

A key finding from ARM/Linaro's TF-M testing: code compiled with **`-O0` is more resilient** against fault injection than `-O2`/`-O3` due to redundant stack spills and reloads. However, `-O0` produces much larger binaries. The practical approach is to compile FI-critical modules at `-O1` or use per-function optimization attributes, while relying on explicit volatile operations and assembly barriers rather than debug-build redundancy.

---

## Layered defense architecture for PQSigner OS

The complete hardening strategy combines hardware configuration changes with software countermeasures at three levels:

**Hardware layer (must be configured before RDP Level 2 lock)**. Set BOR to Level 4 (~2.8V). Enable PVD at threshold just below 3.3V nominal with interrupt-driven secret erasure. Enable hardware IWDG with 250ms timeout. Enable SRAM2/SRAM3 ECC. Enable all internal TAMP events (ITAMP1–ITAMP3 minimum). Enable CSS on HSE and LSE. Mandate SCP03 on SE050 (`kSE05x_PlatformSCPRequest_REQUIRED`) and Shielded Connection on OPTIGA Trust M with lifecycle set to Operational. Configure flash secure watermarks to protect all firmware containing crypto operations.

**Software structural layer**. All security-critical booleans become `FihInt` with complement storage. All security-critical comparisons use the NCC Group double-check pattern with volatile reads. Random delays precede every security-critical branch. CFI step counters span every multi-stage security flow. The NMI handler (triggered by ECCD double-bit errors) must immediately erase all secrets and reset. The HardFault handler must do the same — `udf #0` in assembly guards is the last line of defense.

**Protocol layer**. Verify SE050 attestation signatures on every response using the attestation public key. Verify OPTIGA Trust M chip identity via `checkChip()` challenge-response on every session. Maintain shadow monotonic counters in TAMP backup registers for PIN attempts. After every SE communication, insert a random delay before acting on the response to desynchronize any glitch triggered by I2C clock edges.

No software countermeasure is absolute — the μ-Glitch paper proved that 4 coordinated voltage faults can defeat even multi-layer software defenses. The goal is to raise the attack cost beyond "ChipWhisperer Husky + afternoon of work" (current cost for unprotected STM32U5) to "custom multi-fault platform + weeks of effort + die decapsulation" — a barrier that excludes all but nation-state attackers or dedicated research labs. For those threat levels, the dual SE architecture provides the final backstop: even if the Cortex-M33 is fully compromised, the master secret exists only as XOR-split halves inside two EAL6+ certified secure elements that resist physical attacks independently.

## Conclusion

Three findings should reshape PQSigner OS's security design. First, SLH-DSA's verify-after-sign failure is not a theoretical edge case but a documented, standards-acknowledged vulnerability — the double-computation pattern is mandatory, not optional, and RFC 9814 says so explicitly. Second, the STM32U5 is empirically glitchable at 76% success rate with commodity tools when factory defaults are used, but **BOR Level 4 + PVD + hardware IWDG** dramatically shrink the viable attack window before any software countermeasure is even considered. Third, the NCC Group principle of "fail-in using OR, fail-out using AND" with volatile reads is the single most cost-effective software pattern — it provides double-glitch resistance at ~3× read cost per check, and unlike `core::hint::black_box`, its compiler resistance is guaranteed by the LLVM volatile semantics specification. The combination of these hardware and software measures, implemented in the specific Rust patterns shown above for each code path, raises PQSigner OS from "afternoon hack" to "serious research project" on the attack difficulty scale.
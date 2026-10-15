# PQ1 / PQSigner OS — EVT Red-Teaming Plan

**Status:** draft for the first EVT (engineering validation test) hardware build
**Target:** PQ1 hardware wallet — STM32U585 (Cortex-M33, TrustZone) + OPTIGA Trust M V3 + SE050, SPHINCS+C10-only, ERC-4337 v0.6
**Author:** generated from a codebase deep-dive (2026-06-12)
**Scope:** what to attack, how, with which instrument, and the pass/fail bar — once the EVT board is provisioned and bumped to RDP-2.

> This plan is the bench-attack companion to the existing paper audits in `docs/security/audits/`,
> `docs/security/security-review-2026-05.md`, and `docs/security/threat-model.md`. Those reason about the
> design; this document is about putting probes on copper and glitches on rails.

---

## 0. How to read this document

Each subsystem below is written as:

- **Property** — the security claim we are trying to falsify.
- **Test** — the concrete red-team action.
- **Instrument** — what gear actually measures it (this matters — see §3).
- **Pass / Fail** — the observable bar.
- **Status / caveats** — what's known-fixed, known-open, or untested on silicon.

A recurring theme: **a logic analyzer proves channel confidentiality, not secret quality.**
Anything encrypted-on-the-wire or internal-to-the-die (entropy, keys, PIN compare) is
invisible to passive bus capture *by design*; testing it needs a separate instrumented
build or a glitch/SCA rig. §3 makes this split explicit so tests are pointed at the right tool.

---

## 1. Device-under-test prerequisites

The EVT unit should be in the **shipping configuration** for most tests, because the point
is to attack what customers receive:

- `mode-production` (no `debug-log`, `e2e-test`, `mock-se`, `otp-hardcoded-master-key`, `ui-capture`).
- `dual-se` + `stm32u585` + `optiga-hw-counter` + `consumption-mask` + `tamp` + `tamp-wipe` + `tzic-wipe`.
- Both SEs provisioned with **device-unique** SCP03 / Shielded-Connection secrets (NOT the
  published NXP/Infineon factory defaults — see §5.1).
- The approved rollback backend and its exact OTP map provisioned under a
  separately reviewed ceremony. The legacy OTP-master/floor layout is not an
  EVT prerequisite and grants no burn authority.
- For post-lock tests only, a device that reached **RDP-2 through the approved
  first-field RDP2 self-lock** under an exact owner authorization. This is not an
  instruction for a fixture-side RDP transition.

**Provision a second, sacrificial unit at RDP-0/1** for the tests that RDP-2 locks you out of:
raw-entropy statistical capture (§4.1), SWD-based counter manipulation (§6.3), and any
instrumented build that dumps per-source TRNG bytes. RDP-2 protects the device by locking out
exactly the introspection some of these tests need — so split the fleet by test goal.

**Expect to destroy parts.** Several high-value tests (desolder-OPTIGA, decap, OTP brownout)
are one-shot. Budget ≥3 sacrificial units beyond the RDP-2 "production-config" unit.

---

## 2. Threat model recap (what the attacker is assumed to have)

From `docs/security/threat-model.md`. The companion app and the entire Non-Secure (NS) world are
**fully attacker-controlled** — that is the *primary* surface and needs no physical access.
Physical attackers add: bus probing, glitch injection (voltage/clock/EM), decap, and chip
desoldering. The single-fault assumption is the design baseline; this campaign deliberately
also probes **two-fault** combinations, since most gates are now single-fault-hardened (§9).

Highest-value targets, in order:
1. The BIP-39 seed (reconstructed in S-SRAM) — breaks everything downstream.
2. Either entropy half (`half_O` on OPTIGA, `half_E` on SE050) **plus** a PIN brute-force path.
3. DHUK / OTP-master / SE channel keys — unlock the SE secrets.
4. A WYSIWYS gap — sign something the user didn't see (no key extraction required).

---

## 3. Instruments and what each can actually prove

| Instrument | Proves | Cannot prove |
|---|---|---|
| **Logic analyzer / scope on I²C1, I²C2, LCD SPI, USB** | Channel confidentiality (ciphertext + MAC on the wire), protocol sequencing, "no plaintext secret on any bus", timing of phases | RNG quality (entropy is encrypted or internal), key values, anything inside the die |
| **Instrumented RDP-0 build + entropy dump → NIST/AIS-31 suites** | TRNG statistical health, per-source independence | Nothing about the production-config device's runtime behaviour |
| **Voltage/clock/EM glitch rig (ChipWhisperer / NewAE Scaffold / EMFI probe)** | Fault-injection resistance (gate skips, sentinel bypass, counter rollback) | Confidentiality; needs the `sca-trigger` GPIO or a power-signature trigger to sync |
| **Power/EM CPA-DPA rig (current probe + scope + capture tooling)** | Side-channel leakage of WOTS/FORS secrets during signing | Logic-level behaviour; this is analog, not a digital LA |
| **Bench SE rig (desoldered chip on a breadboard with pull-ups + 3V3)** | Whether a removed SE defends itself standalone (OPTIGA S-1/S-2/S-3) | In-system behaviour |
| **USB host fuzzer (pyusb / WebHID companion)** | NS/gateway parsing robustness, TOCTOU, idle-timeout policy | Anything requiring physical access |

**Rule of thumb:** if the value you want to observe is supposed to be secret, the LA will
show you ciphertext or nothing — that's a *pass for confidentiality*, not a measurement of
the secret. Point a different instrument at the secret's quality.

### 3.1 On-hand bench instrument — Rigol MHO934

The team's primary scope is a **Rigol MHO934** (350 MHz, 4 GSa/s, 12-bit, 4 analog + 16 digital
channels, Wi-Fi/BT, USB-C, optional AFG). It is unusually well-suited here because it doubles as a
**logic analyzer** *and* a **power-analysis front end** in one box — the 12-bit vertical resolution
(vs the usual 8-bit) is what makes it usable for SCA, and the 16 digital channels cover all three
serial buses at once.

| Capability of the MHO934 | What it covers in this plan | Gear it still needs |
|---|---|---|
| 16 digital ch + serial decode (I²C/SPI) | §5.1, §5.2 bus confidentiality; §5.3 "no MCU PIN compare"; §6.2/§7.7 LCD-SPI; §4.2 bus check | SOIC clips / SE050-ARD breakout; flying leads |
| 4 analog ch, 12-bit, 4 GSa/s | §4.4 SPHINCS leakage map (SPA); §4.4/§6.7 CPA/DPA; §5.5 SE VERIFY timing; §6.7 PA5 mask scope | shunt (1–10 Ω) **or** current probe; low-noise diff amp; the `sca-trigger` GPIO |
| Optional AFG | crude VCC glitching for §6.3/§9 (drive a crowbar MOSFET) | crowbar MOSFET board; better: a real glitcher |
| Wi-Fi/BT/USB-C | headless trace offload to the capture/CPA host | — |

**What the scope alone cannot do** (so budget accessories): no EM injection; power SCA needs a
shunt or current probe in the core supply; FI *exploitation* needs a real glitcher
(ChipWhisperer-Husky / NewAE Scaffold) — the AFG only does crude VCC crowbar; a cheap **H-field
near-field probe** is a high-value add-on for localized EM SCA on the HASH/SAES/PKA blocks without
cutting the rail.

**Team workstream split** (four owners, mapped to the sections below):

- **(A) Bus / logic — start here, scope-only.** §5.1, §5.2, §5.3, §7.7, §4.2 bus checks. Cheapest,
  highest signal: directly falsifies Invariants #3/#4 and catches a debug/bring-up build that leaks
  a secret on the wire before EVT ships. Needs only clips.
- **(B) Power SCA.** §4.4 (build the SPHINCS leakage/trigger map first — it's the prerequisite for
  everything in C and D), CPA on the C10 secret-seed/WOTS path and on SAES-DHUK (§6.5), mask
  on/off quantification (§6.7).
- **(C) Timing.** §5.5 SE VERIFY right-vs-wrong-PIN deltas; firmware `ct_eq` variance (§8.x).
- **(D) Fault injection.** §6.3, §9 two-fault campaign — *aimed by (B)'s leakage map*; AFG-crowbar
  for first light, glitcher for real campaigns.

### 3.2 On-hand FI rig (2026-07) — Scaffold + FaultyCat, all on one USB host

The "real glitcher" §3.1 defers to is now on the bench, alongside the Rigol, **all driven from one
Linux host over USB** — so the sweep/capture/classify loop is fully scriptable (see
`tools/bench/` once stood up):

| Instrument | Role in this plan | Control from the host |
|---|---|---|
| **Ledger Donjon Scaffold** (voltage glitcher + FPGA timing + bus instrument + ST-bootloader) | The **voltage-crowbar** campaigns: flash/OTP torn-write (§6.4), SE050 PUT-KEY atomicity (§5.7), the Šimoník-shape RDP-2 / PIN glitch (§6.6). Its `PulseGenerator` gives sub-ns `delay`/`width`; its `STM32` class reads/writes flash+OTP over the ST USART bootloader; it can instrument I²C to trigger on an exact APDU. | `scaffold` Python API (`/home/nicola/repos/scaffold/api`); `Scaffold()`, `PulseGenerator.delay/width`, glitch-clock `div_a/div_b/glitch_count` |
| **Electronic Cats FaultyCat** (EMFI, PicoEMP lineage, RP2040) | The **electromagnetic** campaigns: the µ-Glitch-shape RDP-2 / TrustZone-config attack (§6.6), tamper-canary triggering (§6.3). Non-invasive — no decap, coil over the die. | `faultycmd` CLI over serial (`/home/nicola/repos/faultycat/tools/faultycmd`): `--pulse-count`, `--pulse-timeout` |
| **Rigol MHO934** (§3.1) | Capture (12-bit SCA traces + 16-ch LA) and the AWG for a delayed trigger/crude crowbar drive. | SCPI over USBTMC (pyvisa) — *[bench params pending research]* |

**Trigger spine.** The firmware already exposes `sca-trigger` (`secure/src/hw/sca_trigger.rs`): a GPIO
that rises on entry to a guarded primitive and falls on exit — an LVCMOS sync input for Scaffold's
trigger and the scope. It is **production-fenced** (`compile_error!` in `nsc/mod.rs` alongside
`debug-log`), so every FI campaign runs a bench image and then re-confirms the gate survives in the
production binary. The offset-sweep is: arm on the `sca-trigger` rising edge → sweep
`delay × width × intensity` → classify the outcome → log. FaultyCat adds the XY coil position as a
fourth sweep axis.

**Epistemics — carried from `docs/verification/hardware-assumption-boundary-2026-07-17.md` §0.** These
campaigns *falsify*, they never *validate*. A sweep that fails to break RDP-2 bounds disbelief on our
parts, at our voltages/temperatures — it is never a ∀-proof that RDP-2 holds. The flip side is the
one that changes the product: a **successful** glitch (an RDP-2 downgrade, a reachable torn PUT KEY)
is not a doc update, it is a ship decision — see the evil-maid trace in that doc's §5.

### 3.3 Binding to the HW-ASSUME ledger — every named test has a home here

`contracts/verification/docs/HW_ASSUMPTIONS.json` (gate: `make -C contracts/verification
verify-hw-assumptions`) names a *falsifying test* for each hardware assumption. This table is the
missing link between that ledger and these procedures: it is what turns "5 of 12 rows are bare-TCB
with no runnable test" into a sequenced bench program. **Nothing here validates a premise** — the
gate checks the ledger's hygiene, and the bench can only try to break each row.

| `HW-ASSUME-*` | Falsifying test | Procedure | Instrument | Falsified if… | Parts |
|---|---|---|---|---|---|
| `PUTKEY-ATOMIC` **(highest leverage)** | cut power mid-PUT-KEY, probe ENC/MAC and DEK independently | **§5.7 (new)** | Scaffold crowbar on SE050 Vdd + I²C trigger | ENC/MAC read final while DEK still transport | sacrificial SE050s |
| `QW-ATOMIC` | cut VDD across a QW program/erase; classify readback | **§6.4** | Scaffold crowbar; probe-rs for the reset-only half | any readback is neither old, new, nor a clean ECC fault | sacrificial U585s |
| `OTP-ONEWAY` | reprogram an already-programmed QW; and torn half-burn | **§6.4** | firmware only (reject) + Scaffold (half-burn) | a second program of a complete QW is *accepted* | ~21 shots / usable board |
| `RDP2` **(headline red-team)** | offensive FI campaign, both shapes | **§6.6** | FaultyCat EMFI (µ-Glitch shape) + Scaffold voltage (Šimoník shape) | flash readout, or a TrustZone-M/SAU disable, at RDP-2 | sacrificial U585s |
| `DHUK-RDP12` | fingerprint at RDP-1, self-lock RDP-2, fingerprint again | **§6.5** | no FI; `saes-self-test-hw` + `rdp2-self-lock` | the two fingerprints differ (DHUK changes across the lock) | 1 sacrificial part, one shot |
| `DHUK-UNIQUE` | more boards; require distinct RDP-1 fingerprints | **§6.5** | no FI | two dies produce the same fingerprint | ≥3 boards |
| `TRNG-ENTROPY` | SP 800-90B EA over raw samples from our config | **§4.1** | no FI; RDP-0 dump | min-entropy below the design floor | non-destructive |
| `CMSE-SAU` | extend the enforcement test per attribution rule | **§6.1** | `gtzc-enforcement-hw` | any NS access to a secure peripheral succeeds | non-destructive |
| `REV-U` | boot and read `DBGMCU_IDCODE` | **DONE — `hw::dbgmcu`** (A4a) | no FI | the bench dies are not rev U (0x3003) | non-destructive |
| `OEM2-ABSENT` | probe OEM1/OEM2 lock bits; check CubeIDE default pw | **§6.6** | no FI (option-byte read) | any unit ships with an OEM key provisioned | non-destructive |
| `SE050-CERT-VERSION` | read the applet/config version off the part | **§5.5** | no FI | the part is not the certified JCOP4 config | non-destructive |
| `SE-INTERNALS` | per-property silicon E2E (permanent bare-TCB) | **§5.1–5.5** | LA + SE stress | a policy the datasheet promises is not enforced | some destructive |

When a procedure below is turned into a runnable `make` target, set that row's
`falsifying_test.make_target` in the ledger and flip `exists` to `true` — the `verify-hw-assumptions`
C4 check enforces that a claimed target is real, so the ledger cannot get ahead of the bench.

---

## 4. Crypto core: RNG, seed, key derivation, FI

### 4.1 Seed-entropy RNG quality — **the headline RNG question**

**Property.** The "New Wallet" seed is full-entropy: `STM32 TRNG ⊕ OPTIGA GetRandom ⊕ SE050
GetRandom`, XOR-folded, fail-closed on any source error, all-zero rejected.
Path: `secure/src/rng_strong.rs` → `secure/src/rng.rs` → `secure/src/hw/rng.rs` +
SE fold in `secure/src/dual_se.rs::random()`. Consumed by the wizard at
`secure/src/main.rs` (`SetupChoice::Create`).

**The LA cannot test this.** The STM32 TRNG never leaves the die; the OPTIGA/SE050 GetRandom
responses cross I²C **encrypted** under Shielded Connection / SCP03. On the production unit you
capture ciphertext, which looks random whether the underlying TRNG is healthy or stuck.

**Test (requires instrumented RDP-0/1 build).**
1. Build a diagnostic image that dumps, over UART/USB, the raw per-source streams **before**
   the fold: STM32-only, OPTIGA-only, SE050-only, and the folded output. (Seed from
   `tools/dev_fixture_keygen/` and the on-silicon `secure/src/se050_stress/tests/trng.rs`
   χ²/block-degeneracy probe, which already does this for SE050.)
2. Capture ≥10 MB per source. Run **NIST SP 800-22, Dieharder, `ent`**, and the **SP 800-90B /
   AIS-31** estimators. **Test each source independently** — the XOR masks a single biased
   source, so per-source testing is what catches it.

   **Verified tooling + the STM32U5 limitation that shapes this test** *(2026-07-17 bench research,
   high-confidence, primary-sourced):*
   - **The STM32U5 RNG exposes only *conditioned* 32-bit output** — there is no raw-noise-source
     API in the public HAL (`HAL_RNG_GenerateRandomNumber` returns conditioned data). SP 800-90B's
     noise-source tests want **≥1,000,000 *raw*, pre-conditioning samples** (`SP 800-90B §3.1.1`),
     which we therefore **cannot cheaply obtain from the production part**. So the "run 90B
     ourselves on the STM32 source" step is *not* straightforwardly available for the STM32 TRNG —
     it applies cleanly to the **OPTIGA/SE050** `GetRandom` streams (conditioned SE output, tested
     as black-box quality) but the STM32 leg leans on ST's own validation, below.
   - **ST already holds a NIST ESV Entropy Certificate — #E11 ("STM32U5x TRNG", Physical noise
     source, conformance SP 800-90B, validated 2022-12-16, UL Verification Services).** It has no
     published Public Use Document, so exact device enumeration is unconfirmed, but by Operating
     Environment ("STM32U5x") and elimination of the later U5-subfamily certs it is the U585 cert
     (`HW-ASSUME-TRNG-ENTROPY`, corrected from the earlier "no ESV certificate" claim). The
     residual red-team action is therefore **config**, not statistics: confirm the firmware selects
     the *certified* RNG config (ST's `HAL_RNG_SetCertifiedNISTConfig` equivalent — RM0456 RNG_CR),
     not a candidate/custom one.
   - **Tools (installed/fetchable):** NIST `SP800-90B_EntropyAssessment` — `ea_iid -i <file> <bps>`
     (IID path) / `ea_non_iid -i <file> <bps>` (conservative min-entropy; source also accepts `-q`);
     the restart test needs the row/column datasets. AIS-31 open reference suite:
     `mjosaarinen/ais31-testsuite` (BSI Java reference, wants 5,220,000 bits). These are the right
     estimators for the SE `GetRandom` streams and for any raw dump ST's tooling can produce.
3. Confirm the STM32 silicon health monitors fire: perturb the RNG clock and confirm
   `SEIS/CEIS` latch and `hw::rng::fill` returns `Err` (fail-closed), per the recovery logic
   in `secure/src/hw/rng.rs`.

**Test (production unit, fail-closed behaviour).**
- Glitch one SE's I²C during a sign's `opt_rand`/seed draw and confirm the call **aborts loudly**
  (`rng_strong::fill` → `Err` → wizard shows "RNG failed, retry"), never silently degrading to
  fewer sources. `dual_se.rs::random()` requires *both* SEs.
- Induce a stuck-at-0 and confirm the all-zero acceptance gate in `rng_strong.rs` rejects.

**Pass.** Each source passes the statistical batteries standalone; any source fault aborts the
operation; all-zero is refused.

**Caveats / known gaps.**
- **Width/packing class (the Trail-of-Bits "short-sleeve RSA" bug) is NOT present** — the one
  risky transition (32-bit `RNG_DR` → byte buffer in `hw/rng.rs`) uses `to_le_bytes()` and
  copies all four bytes; the SE fold is byte-indexed. Re-verify after any refactor of that loop.
- **The all-zero gate does NOT detect a *structured* failure** (e.g. 3-of-4 bytes zero). RNG
  correctness here rests on the packing code being right, not on a runtime gate. This is the
  exact failure mode of the ToB bug — keep it in regression tests.
- **OPTIGA `get_random` silently truncates a short chip response** (`optiga/apdu.rs`
  `payload.len().min(out.len())`, caller discards the length) — a glitched/short OPTIGA reply
  leaves the tail of its contribution zero and still returns `Ok`, quietly dropping that byte
  range from 3 sources to 2 (STM32 ⊕ SE050). Output stays unpredictable (STM32 covers every
  byte) but it violates the documented strict "both-or-fail" semantics; the SE050 driver
  already guards this exact case. **Red-team action:** glitch OPTIGA to a short response, confirm
  whether bytes silently drop a source. *(Fix candidate: mirror the SE050 short-response check.)*

### 4.2 Dual-SE XOR seed split (Invariant #1)

**Property.** `half_O` on OPTIGA, `half_E` on SE050; neither chip alone reveals any bit.
Reconstruction `full = half_O ⊕ half_E` in S-SRAM with an FI cross-check (derive master, compare
to stored master with two constant-time compares). `secure/src/dual_se.rs` (provision + unlock).

**Tests.**
- **Single-chip extraction (destructive).** Decap/extract one chip's stored half; confirm it is
  uniformly random and yields zero information about the seed without the other half.
- **Reconstruction glitch.** Glitch the XOR or the master cross-check at unlock; confirm the
  sentinel-gated compare fails closed (no unlock on mismatch).
- **Bus check.** LA on both I²C buses during unlock: confirm neither half ever crosses to the
  *other* chip's bus, and neither chip ever receives the full entropy (Invariant #1).

**Pass.** One half is independent of the seed; mismatch → lockout; halves never co-mingle on a bus.

**Caveat.** The "single-chip break is harmless" claim only holds once the OPTIGA ship-blockers
(§5.4) are closed. Until then, a desoldered OPTIGA + shared-PIN brute-force cascades to defeat
SE050 and recover the full seed — see `project_se_removal_invariant` and `docs/security/threat-model.md`.

### 4.3 Key derivation (KDF tags, BIP-39 → C10)

**Property.** Deterministic, domain-separated derivation in `domain/src/lib.rs` (re-export shim
`secure/src/crypto.rs`). Bootstrap master is immutable per wallet; slot keys are chain-bound
(same `slot_index` on different `chain_id` → different keys). CREATE2 salt = `sha256(masterPkSeed‖masterPkRoot)`.

**Tests (mostly functional, on instrumented build).**
- Derive slot keys for `(chain=1,slot=0)` vs `(chain=2,slot=0)`; confirm they differ.
- Confirm Account 0 reproduces the legacy byte-for-byte derivation (KDF tags `"sphincs-c6-v1"` etc.).
- Confirm master secret never persists in plaintext flash/SRAM after lock (dump and search).

**Caveat (carry-over audit item H-1).** The entropy-blob AES-GCM nonce is *derived* from the
master secret, not random. Not a break (master differs per unlock), but verify the nonce changes
across unlocks; flagged for the next storage-format bump.

### 4.4 Signature FI hardening — verify-before-release (Invariant: never skip)

**Property.** Every Type-1/Type-2 sig is double-computed, byte-compared, then **verified before
release**, gated by FI sentinels, with a control-flow-integrity (CFI) counter over the critical
steps and a fresh `opt_rand` + shuffle seed per signature. `secure/src/fi.rs`,
`secure/src/crypto.rs` (`c10_sign_verified*`).

**Tests (glitch rig, use the `sca-trigger` GPIO to sync — note it is fenced out of production,
so run these on a `dev-testkey`/bench image, then re-confirm the gate exists in the prod binary).**
- Skip the double-compute / `ct_eq`; expect sentinel-gated reject.
- Skip the `verify(...)` call; expect the sentinel check to catch the missing verify.
- Fault the verify boolean to "true"; `black_box` + sentinel encoding should defeat a single
  register skip.
- Skip any single CFI step (rate-limit, opt_rand fill, shuffle, sign_a, sign_b, ct_eq,
  verify-gate); expect the final CFI sum mismatch to abort.
- **Two-fault:** skip both `ct_eq` and `verify`; this is the realistic attack and the design
  explicitly requires two coordinated faults.

**Pass.** No single fault releases an unverified signature; two-fault combinations do not either
within the timing window you can achieve.

**Side-channel (separate CPA/DPA rig).** Power/EM-probe a full SPHINCS+C10 sign (~1–3 s) and
attempt to recover WOTS/FORS secrets. Confirm `consumption-mask` (TIM2 PWM on PA5) is active and
that shuffle decorrelates traces. Note: the STM32 HASH peripheral is a timing accelerator, **not**
a DPA barrier — masking is the only SCA mitigation today.

---

## 5. Secure elements & channel security

### 5.1 SE050 SCP03 confidentiality — **closes the pending S-5 silicon item**

**Property.** SCP03 negotiated at `P1=0x33` (C-MAC + C-DEC + R-MAC + R-ENC); the response phase
is ciphertext + 8-byte R-MAC, so `half_E` is never plaintext on I²C2. `secure/src/se050/scp03.rs`,
`secure/src/se050/apdu.rs`. **This is the explicit "still pending" verification in CLAUDE.md.**

**Test (logic analyzer — this is the LA's sweet spot).**
- Capture I²C2 across a full unlock cycle (`read_authed(ENTROPY_OBJ)`).
- Confirm the **command** phase: header plaintext, body encrypted + C-MAC.
- Confirm the **response** phase: 8-byte MCV/R-MAC + ciphertext body + SW — **no `half_E`
  plaintext anywhere**. Decrypt offline with the session S-ENC key to prove the entropy is only
  recoverable with the session key.

**Pass.** Response is ciphertext + R-MAC; sweeping the whole capture finds no half_E / PIN / key
bytes. **This directly retires S-5.**

### 5.2 OPTIGA Shielded Connection confidentiality

**Property.** TLS-PRF + AES-128-CCM-8 over IFX I²C. The factory transport PBS
derives from the per-device OTP master; the candidate final PBS derives from
DHUK plus a non-secret TRNG salt persisted in the page-127 journal. Flash page
126 is the wrapped SE050 BHK, not PBS storage; application payloads
(half_O at F1D1, PIN-related OIDs) encrypted on I²C1. `secure/src/optiga/{shield,apdu,ifx_i2c}.rs`.

**Test (LA on I²C1).** Capture `establish()` + first encrypted GetDataObject. Confirm handshake
(MasterHello/SlaveHello) is the only plaintext; all post-handshake OID reads/writes are CCM
ciphertext. Sweep for `half_O`, PBS, AuthRef, PIN bytes — none should appear.

**Caveat / open.** The Shielded-Connection handshake (`MasterFinished`/`SlaveFinished`) has been
flaky on the bench (see `docs/secure-elements/optiga-bringup-status.md`); a full encrypted round-trip on real
silicon may still need to be confirmed. If the handshake doesn't complete, the LA test for §5.2
cannot run — fix the handshake first.

### 5.3 Three-way PIN-attempt enforcement + directional boot cross-check (Invariant #2)

**Property.** PIN comparison stays in SE silicon. `gated_unlock` precharges the
MCU page-124 counter; an ordinary wrong PIN then exercises OPTIGA F1D0/E120
and the SE050 UserID. Page 124 and SE050 enforce the user-facing 10-attempt
bound; E120 is a separate 32-lifetime-attempt anti-extraction backstop. At boot
the production firmware can read page 124 and E120 and wipes only when
`E120_used > page124_used`; an MCU lead is the fail-closed power-cut/transport
window. The SE050 UserID attempt attribute is policy-denied (`SW=0x6986`), so
it is not a boot-reconciliation input. `secure/src/nsc/mod.rs`
(`gated_unlock`, `reconcile_pin_attempts`), `secure/src/hw/flash.rs`.

**Tests.**
- **10-wrong-PIN brick (functional, on a sacrificial provisioned unit).** Drive 10 wrong PINs;
  confirm every attempt consumes page 124, E120, and the SE050 UserID path and
  that SE050/page-124 exhaustion bricks + admin-wipes both SEs.
  (`make pin-gate-wipe-e2e` is the QEMU analogue; do it on silicon here.)
- **Readable-counter rollback → tamper.** Externally reset MCU page 124 (SWD,
  RDP-0 unit) while E120 is non-zero; reboot; confirm `E120_used >
  page124_used` detects the rollback and wipes. Separately demonstrate that a
  benign MCU lead after a cut does not false-wipe.
- **Glitch `gated_unlock` pre-commit.** Glitch to skip the page-124 bump or flip the verdict;
  confirm the FI sentinels + double-read counter + FihBool `pin_verified` fail closed (single
  fault insufficient).
- **No software compare.** LA confirms the PIN bytes go *to* the SE and only a verdict returns —
  the MCU never compares the PIN.

**Pass.** Every ordinary wrong attempt consumes all three paths; SE050 locks at
10; page-124 rollback behind E120 wipes; a benign MCU lead does not; no single
fault unlocks; PIN is never compared in MCU.

**Caveat.** This is not three-way boot reconciliation. The SE050 attempt count
cannot be read under its production UserID policy without changing the policy
or consuming an attempt. Any design that adds a readable SE050 boot leg is a
separate architecture/policy decision requiring adversarial and silicon
review; do not weaken UserID policy merely to make the documentation symmetric.

### 5.4 OPTIGA shipping-state lockdown — **S-1 / S-2 / S-3 ship-blockers**

These are the **biggest open hardware-security items** and the highest-confidence physical attack
chain. All three must close before any device ships; the EVT is where you *prove the attack* (on a
pre-fix unit) and later *prove the fix* (on a locked unit). See the `EthereumPhone/PQ1` issue
tracker — production items under label `source:production-todo`, ship blockers under `ship-blocker`.

- **S-1 — F1D0 `Change = ALW`.** A desoldered OPTIGA lets a bench attacker overwrite F1D0 with a
  chosen HMAC key, self-auth, reset E120, and brute-force PINs unbounded. (`secure/src/optiga/apdu.rs`.)
- **S-2 — the type-`0x11` Protected-Update pool is not production-closed.** The observed E0E3 is a
  full type-`0x12` device certificate; the retired public-sample helper targeting it is a no-op, not
  the live anchor path. Pin and close `{E0E8,E0E9,E0EF}` and prevent device-certificate retyping.
  **S-1 alone is insufficient; S-2 must close simultaneously.** (`EthereumPhone/PQ1`, label `ship-blocker`.)
- **S-3 — `optiga-hw-counter` must be mandatory.** Without the E120 hardware counter, a
  PBS-leaking/desoldered attacker gets unbounded HMAC attempts.

**Test (desolder a sacrificial OPTIGA onto a bench I²C rig).**
1. `GetMetadata(0xF1D0)` → confirm `Change` AC (pre-fix: `ALW`; post-fix: `Auto(F1D0)` + LcsO=Op).
2. Attempt to overwrite F1D0 with a chosen key with no auth → must **fail** on a fixed unit.
3. Exercise the reviewed negative Protected-Update vectors against the pinned E0E8/E0E9/E0EF
   inventory → attacker-controlled anchors/manifests must **fail**; E0E1..E0E3 must remain
   device-certificate surfaces and reject retyping.
4. Confirm `optiga-hw-counter` is compiled in (the `compile_error!` fence in `nsc/mod.rs` is
   present — see §10) and that the E120 LUC, not the F1E1 soft counter, bounds attempts.

**Pass.** On the shipping-config unit: F1D0 is not overwritable, the sample-key manifest is
rejected, and PIN attempts are hardware-counter-bound. **Until then this is the #1 EVT finding to
reproduce and then re-test after the fix.**

**Verify the fences actually cover S-1.** `nsc/mod.rs` carries many `compile_error!` ship-blocker
fences (hw-counter, derived-scp03, tamp-wipe, consumption-mask, debug features). The lockstep audit
noted that **S-1's `optiga-lock-operational` may not be compile-fenced** — i.e. a production build
could theoretically ship with `Change=ALW`. Confirm at build time: try a `mode-production dual-se`
build *without* the lockdown feature and check whether it compiles. If it does, that's a gap to close.

### 5.5 SE050 UserID provisioning (S-6 / S-7)

**Property.** Admin cannot delete-and-substitute the user UserID (S-6 fixed: user UserID's
admin-delete policy is `None`); `max_attempts=0` is rejected for the user PIN (S-7a). Data objects
keep the admin-delete (DoS-wipe) path. `secure/src/se050/mod.rs`, `docs/secure-elements/se050-userid-pin-auth.md`.

**Tests.**
- From an admin session, attempt `delete_object(USERID_OBJ)` → must fail (`SW≠Ok`; expect `0x6986`).
- Attempt to create a user UserID with `max_attempts=0` → must fail `InvalidParam`.
- **S-7d silicon receipt (resolved 2026-05-28):** driving a UserID to
  `auth_attempts == max_attempts` produced `SW=0x6986`; commit `ef3d00da`
  records the mapping to `AuthMethodBlocked`. A future LA rerun is replication,
  not the source of the current claim.

**Pass.** Substitution attack structurally closed; empirical lockout SW matches the firmware mapping.

### 5.6 Factory SCP03 / pairing secrets are device-unique

**Property.** The published NXP AN12436 / Infineon sample keys must never be a
production credential. The implemented first-field candidate uses
OTP-master-derived factory transport credentials, then rotates SE050 to
unsalted BHK-rooted final SCP03/admin credentials and OPTIGA to a DHUK +
persisted-TRNG-salt final PBS. Production additionally requires authenticated
handoff, recovery after every cut point, a reviewed E140 ordering, silicon
evidence, and explicit approval; deterministic device uniqueness alone is not
a pass.

**Test.** First confirm `se050-scp03-allow-factory-fallback` is fenced out and
that neither tunnel accepts published/sample credentials. After the final
candidate is authorized for silicon validation, cut power at every durable-state and chip-update
boundary, prove recovery never re-enables transport keys, and confirm two units
receive distinct final credentials while retaining only the non-secret
recovery state needed to reconstruct them. Exercise the reviewed E140
order on sacrificial silicon.

**Pass.** Final credentials are per-device and non-public: SE050 is rooted in
the post-lock BHK, while OPTIGA is rooted in per-die DHUK plus the persisted
fresh salt. Every power cut recovers or fails closed without restoring
transport credentials; both tunnels reconnect after a clean ceremony; the
reviewed lifecycle order holds on silicon. Until then HIGH-1 remains open.

### 5.7 SE050 key-rotation atomicity — **`HW-ASSUME-PUTKEY-ATOMIC`, the highest-leverage bench test**

**Why this one first among the SE tests.** The entire first-boot transport→final rotation
(`secure/src/first_boot/`, `se050/mod.rs::rotate_scp03_transport_to_final`) rests on a single silicon
premise, and formalising it reduced ~2000 lines of driver crash-safety to one falsifiable sentence
(`docs/verification/hardware-assumption-boundary-2026-07-17.md` §1(e)). From
`scp03_logic.rs::build_put_key_apdu`: all three key blocks — ENC ‖ MAC ‖ DEK — ride **one** PUT KEY
APDU (`P2=0x81`) replacing KVN `0x0B` **in place**. The resume probe
(`establish_with(final_enc, final_mac)`) proves **ENC+MAC only** — the DEK is never probed — and the
KVN is `0x0B` before *and* after, so it cannot disambiguate. If PUT KEY is atomic, the probe is sound.
If it is not, a device can boot with ENC+MAC final but a **DEK still derived from the factory-known
transport root**, and the resume path reports "already rotated" over it.

**Property.** An SE050 PUT KEY (`P1=0x0B`, `P2=0x81`, three key blocks, in-place KVN) is
all-or-nothing across the SE050's internal NVM commit.

**Setup.** Bench image that drives one PUT KEY and halts. Instrument I²C2 (Scaffold or the MHO934's
LA) to detect the PUT KEY command bytes; the crowbar target is the **SE050's own Vdd rail** (it is a
separate package — glitch its supply, not the STM32's). The commit window is after the last APDU byte
is ACKed and before the SE050's success SW; sweep the crowbar `delay` across it.

**Tests.**
1. **Baseline (no glitch):** drive the rotation, then probe ENC/MAC (SCP03 establish under final) and
   **DEK independently** — the DEK wraps future key blocks, so probe it by attempting a PUT KEY whose
   blocks are wrapped under the *candidate-final* DEK and reading the SW. Confirm all three are final.
2. **Torn campaign:** crowbar at swept offsets across the commit window; after each, cold-boot and
   run the same independent ENC/MAC vs DEK probe. Classify each part: {all-transport, all-final,
   **ENC/MAC-final-DEK-transport**, unreadable/bricked}.
3. Repeat across ≥5 sacrificial SE050s to bound the reachable-state set.

**Falsified if** any part lands in **ENC/MAC-final-DEK-transport** — that is the exact state the
resume probe cannot see, and it means final-rotation is not crash-safe against a mid-APDU power cut.

**Pass** (for this bench, on these parts) if the outcome is only ever all-transport or all-final —
which would let the "atomic durable old/new/KVN recovery proof" ship-gate cite silicon evidence
instead of an assumption. **This does not prove atomicity** (§3.2 epistemics); it fails to falsify it.

**Ledger.** `HW-ASSUME-PUTKEY-ATOMIC` (bare-TCB). A confirmed torn DEK is a **ship-blocker**, not a
finding to file for later: it means the SE050 leg of the pairing can be left on a factory-known key by
a single well-timed brown-out.

---

## 6. Platform isolation, boot, tamper, OTP

### 6.1 TrustZone / GTZC peripheral isolation (Invariant #4)

**Property.** AES/HASH/RNG/PKA/SAES + I²C1/I²C2 are SECURE; USB OTG is NS. NS access to a secure
peripheral RAZ-faults and bumps `hw::tzic::VIOLATION_COUNT`. `secure/src/sau.rs`. **Silicon-validated
2026-05-20** (`make gtzc-enforcement-hw` PASSED 7/7; USB still enumerates as `1209:7051`).

**Tests.**
- **Re-run `gtzc-enforcement-hw` on the EVT** — confirm all 7 secure peripherals RAZ-fault on NS
  access and the violation IRQ fires (1 per probe). This is a regression gate, not new work.
- **Glitch the SAU/GTZC config write at boot** and confirm enforcement still holds (or boot aborts).
- Confirm USB still enumerates with the GTZC config live.

**Pass.** 7/7 RAZ-faults; USB enumerates.

**Open follow-up.** **TAMP lives in GTZC2** and its SECCFGR wiring is a documented follow-up
(`sau.rs`). Confirm the TAMP path's isolation separately (§6.3).

### 6.2 Measured boot / FSBL fingerprint

**Target property.** After the production geometry, WRP/option-byte ceremony,
resource, and silicon gates close, the immutable FSBL and the secure world must
independently render the **same** 8-word BIP-39 fingerprint for the active slot;
divergence means the slot or one renderer is lying. The current legacy bench
FSBL exercises the rendering path but is not evidence of production
immutability. `secure/src/measured_boot.rs`, `fsbl/`,
`docs/security/measured-boot.md`.

**Tests.**
- Corrupt the secure image in flash (glitch a write, or a malformed `CMD_FW_CHUNK`); reboot;
  confirm the rendered fingerprint changes (tamper detectable by comparison).
- LCD-SPI capture during the fingerprint render: confirm the 8 words shown on the NV3007 LCD match the
  SPI bus exactly (no hidden/extra content), and constant-time word lookup (`word_bytes_at`).

**Pass.** Divergence is visible; display bus matches the screen.

**Known gaps (from `docs/security/audits/boot-fsbl-*.md`).**
- **No shipping build exists.** The default EVT/bring-up profile is monolithic;
  legacy bench FSBL/A/B exercises are not a production trust root. Confirm the
  exact candidate boot path and receipts before assigning production authority.
- **Divergence detection is HUMAN-ONLY** — there is no automated on-device comparator between the
  FSBL row and the secure-world row. A user who doesn't compare gets no protection. Note this as a
  residual; an automated comparator is open work.
- MEDIUM-1 (fingerprint base now derived from `__vector_table`, not hardcoded `FLASH_BASE`) is fixed
  (commit `fa9345d6`) — regression-check it survived.

### 6.3 Tamper response (TAMP + TZIC intrusion wipe)

**Property.** On a confirmed tamper, production dual-SE images escalate to
`tzic::trigger_intrusion_wipe` (zeroize SRAM, arm page-125 wipe flag, reset → boot-time wipe
finishes SE factory_reset + page-124 erase). Forced ON via the `nsc/mod.rs` fence
(`tamp` + `tamp-wipe` + `tzic-wipe`). `secure/src/hw/tamp.rs`, `secure/src/hw/tzic.rs`.

**Tests (glitch / physical).**
- **ITAMP9 (crypto-peripheral fault) canary.** Glitch SAES/AES/PKA/TRNG during a crypto op; confirm
  the tamper flag sets and — on the production image — the wipe fires (a single glitch costs the
  attacker the whole secret state). On a bench (`tamp-wipe` off) it's log-only — confirm that too,
  so you understand the dev-vs-prod difference.
- **ITAMP1 (brownout/voltage).** Inject a VDD/backup-domain transient; confirm ITAMP1 fires.
- **ITAMP6 (SWD at RDP>0).** On an RDP-1 unit, attempt SWD; confirm ITAMP6 fires. On RDP-2, confirm
  the programmer is hardware-refused.
- **TZIC NS→S illegal access** → confirm it routes to the same wipe escalation.

**Pass.** Tamper events fire their flags; production image escalates to an irreversible wipe;
attacker does not get unbounded glitch attempts.

**Caveat.** Tune false-positive sensitivity: a too-trigger-happy ITAMP9 under a noisy bench supply
could brick units during legitimate validation. Characterise the threshold on the EVT.

### 6.4 OTP rollback floor / anti-brick (one-way)

> **NO-GO until separately authorized.** The legacy unary tally and idempotent
> re-burn assumptions below are invalid for STM32U585 OTP quad-words. Production
> is compile-blocked. Draft 1.1 proposes replacement interfaces but remains an
> unapproved research candidate; its physical codec and this sacrificial-
> silicon section remain open. Nothing in this document authorizes an OTP
> write; follow the named-board/exact-QW gate in
> `docs/security/a-b-firmware-rollback-architecture.md` Section 13.

**Target property.** The typed security-epoch floor never decreases; ordinary
same-epoch releases issue zero OTP writes; an epoch bump uses only fresh,
complete 128-bit QWs through the approved replicated/interruption-safe codec.

**Tests.**
- Install vN (floor → N-1); replay an older signed manifest → must reject at `FW_BEGIN`.
- Reinstall vN (floor stays N-1) then v(N+1) (floor → N) — confirm each boots (no brick).
- **`OTP-ONEWAY`, no glitcher needed:** firmware attempts a second program of an already-complete
  quad-word and reads `FLASH_SR`. A *virgin* QW can hold 21 shots — `otp.rs:32` maps 336 B / 21
  unallocated QWs — so this fits on a **usable** board. Falsified if a second program of a complete
  QW is *accepted* (the whole one-way premise, and the D4 fix, rest on it PGSERR-ing).
- **`QW-ATOMIC`, Scaffold crowbar:** cut VDD at swept sub-µs offsets across a QW program *and* a page
  erase; classify every readback into {old, new, clean ECC-fault, **other**}. "Other" falsifies the
  contract. The **recovery-logic half needs no glitcher** — reset (probe-rs / `SYSRESETREQ`) at
  swept delay, reboot, assert recovery lands old-or-new-or-fail-closed; only the analog torn-write
  half needs the crowbar. This is the premise the page-123 TLC pilot's FINDING 1 is *equivalent to*.
- **`QW-ATOMIC` on the device master — the D4 shape specifically (sacrificial):** the master spans
  **two** QWs and takes two programs (`otp.rs::burn_device_master`). Crowbar between them, cold-boot,
  and confirm the D4 fix holds: `is_device_master_burned()` must classify the half-blank region as
  `Partial` (not `Complete`), `read_device_master()` must refuse it, and the burn must complete the
  virgin QW. Falsified if a half-burnt master reads as complete — pre-fix, that silently rooted every
  SE transport credential in a **128-bit** master. The fix is host-tested + mutation-checked; this is
  its silicon confirmation.

**Pass.** Available only after an exact rollback architecture digest is
implementation-approved and its journal/ECC/OTP, resource, factory, and
silicon gates close; no downgrade, no fallback retirement before the health
contract, and no uncertain QW reuse. The `OTP-ONEWAY` / `QW-ATOMIC` classification tests above are
*independent* of that gate — they characterise the silicon, they do not authorize a production OTP
write — and can run first.

### 6.5 SAES / DHUK key derivation (Tier-1 KDF)

**Property.** DHUK never appears in CPU-visible memory; subkeys via SAES-CMAC(DHUK). Self-test:
SW-key round-trip + DHUK≠SW domain separation + DHUK round-trip. `secure/src/hw/saes.rs`,
`saes_cmac.rs`, `secret_keys.rs`, `huk.rs`.

**Tests.**
- `make saes-self-test-hw`: confirm PASS + a stable DHUK fingerprint across reboots.
- **`DHUK-UNIQUE` (no FI, ≥3 boards):** the fingerprint must differ per die at RDP-1 (it is a shared
  ST constant at RDP-0). Two dies producing the same RDP-1 fingerprint falsifies per-die uniqueness.
  Currently validated at n=2 — this raises it.
- **`DHUK-RDP12` — one shot per part, IRREVERSIBLE (sacrificial):** the single test that settles a
  named open ambiguity. Is `SAES-CMAC(DHUK,·)` identical at RDP-1 and RDP-2 on the *same* die? No
  board in this project has ever been at RDP-2 (an RDP-2 part cannot be regressed — that is the whole
  point), and the first-boot ceremony is self-consistent either way, so **no functional test will
  ever surface this — only a deliberate probe can.** Procedure: capture the fingerprint at RDP-1
  (`saes-self-test-hw`; it reaches the ST-LINK VCP even at RDP≥1 per `main.rs`), then self-lock to
  RDP-2 (`rdp2-self-lock` Phase A programs RDP=0xCC), then capture again on the locked part.
  Falsified if the two fingerprints **differ**. Note the *consequence direction*: if they differ,
  that is fail-secure for the RDP-2→RDP-1 downgrade route (an attacker computes `f(DHUK_RDP1,salt) ≠
  PBS` and both tunnels stay shut) but does NOT help against a runtime TrustZone-M disable at RDP-2 —
  see `HW-ASSUME-DHUK-RDP12`.
- Glitch the `SR.KEYVALID` gate / CCF completion during a DHUK op; confirm bus-error/timeout and
  (if enabled) ITAMP9.
- Confirm bank-1 page 126 (the wrapped SE050 BHK) is ciphertext off a
  desoldered MCU. OPTIGA PBS has no flash page: test its domain derivation,
  non-persistence, and Shielded-Connection behavior separately.

**Pass.** Self-test passes; DHUK never materialises in readable memory; glitch faults are caught;
per-die uniqueness holds at n≥3; the RDP-1/RDP-2 fingerprint relationship is recorded (either answer
is informative — the point is that today it is *unmeasured*).

**Caveat.** Confirm whether production `secret_keys` call sites are actually routed through
SAES-CMAC(DHUK) yet, or still on the legacy OTP-master+HKDF path (the SAES path landed behind a
feature gate; the flip is tracked work). Test whichever is live in the EVT image.

### 6.6 RDP-2 / debug lockdown + feature gating

**Property.** RDP-2 disables SWD/JTAG (irreversible). The `compile_error!` fences in `nsc/mod.rs`
forbid `debug-log`/`e2e-test`/`mock-se`/`otp-hardcoded-master-key`/`ui-capture`/`ui-semihosting`/
`uart-console`/`sca-trigger`/etc. on production. `docs/security/HARDENING.md`.

**Tests.**
- On the RDP-2 unit, attempt SWD/JTAG attach → hardware-refused.
- **Build-time:** attempt a `--release stm32u585` build with each forbidden feature → must
  `compile_error!`. (This is a CI gate; re-confirm on the exact EVT image's feature set.)
- Confirm the shipped binary contains no semihosting/UART debug strings (grep the ELF).
- **`OEM2-ABSENT`:** read the OEM1/OEM2 key-lock option bits on every unit — a shipped unit must have
  **no** OEM key provisioned (`shared/src/lockdown.rs::oem_locks_absent`). Separately, probe whether
  any CubeIDE-touched bench board carries ST's **default OEM2 password** (UM3387 reports the CubeIDE
  init script sets one) — that would be a live RDP-2→RDP-1 regression credential on our own bench.
  Falsified if any unit ships with an OEM key, or a bench board carries the default password.

**Pass.** Debug ports dead; forbidden features don't compile into production; no debug strings ship;
no OEM key provisioned.

#### 6.6.1 RDP-2 offensive downgrade — **`HW-ASSUME-RDP2`, the highest-leverage unverifiable premise**

The one the whole design leans on, and the one the field has not answered for the U5. From the
boundary doc §5: RDP-2 downgradability is *"an unanswered question only your bench can settle"* — every
public STM32 RDP glitch result targets F1/F2/F4/L0/L5, **not** the U5. Two shapes to attempt, with the
two instruments that match the two published sibling results:

- **EM shape (FaultyCat) — the µ-Glitch attack.** µ-Glitch (USENIX Sec 2023) disabled TrustZone-M on
  the **STM32L5**, the Cortex-M33 sibling of the U585, by EM-faulting the SAU / TZ-config load, and
  claimed transferability to "conceptionally similar ICs" citing ST's joint L5/U5 TrustZone app note.
  FaultyCat is exactly that tool shape. Sweep coil XY position × pulse timing over the boot-time
  option-byte / SAU / GTZC configuration window (aim with the `sca-trigger` on `sau::init`).
- **Voltage shape (Scaffold) — the Šimoník attack.** Šimoník (Masaryk 2025) hit ~76% voltage-glitch
  bypass of a PIN check on the **STM32U5A9**, our part's own sibling. Crowbar the STM32 Vcore across
  the PIN-compare / `gated_unlock` verdict window and across the RDP-check read.

**Falsified if** either yields flash readout at RDP-2, a TrustZone-M / SAU disable, or a PIN-gate
bypass — any of which is a **ship-blocking** result (§3.2). This is an open-ended campaign, not a
quick win; budget sacrificial parts and treat a null result as *bounds-disbelief-on-our-parts*, never
proof. Whatever the outcome, it directly sets how much trust the dual-SE XOR split must carry
independent of the MCU — the §5 evil-maid trace in the boundary doc turns on exactly this.

### 6.7 Consumption mask / SCA jitter

**Property.** TIM2 CH1 PWM on PA5, xorshift-randomised duty, seeded from `rng_strong`; mandatory in
production (fence). `secure/src/hw/consumption_mask.rs`.

**Tests.** Scope PA5 — confirm the duty varies and is uniformly distributed (no PRNG bias). Run the
CPA/DPA campaign of §4.4 with the mask on vs off and quantify the decorrelation. Glitch the seed
draw at init and confirm the mask doesn't get stuck.

**Pass.** Mask is active, unbiased, and measurably raises the CPA trace count.

---

## 7. Clear-signing / WYSIWYS (no key extraction needed)

Core property: every signable artifact is decoded and rendered in S-world before confirm; the
companion can never substitute a hash or hide intent for a known shape. Many gaps here were
recently fixed — the EVT job is to **regression-test the fixes with real malicious payloads over USB**
and confirm true intent renders or it falls *loudly* to blind-sign.

### 7.1 Native-value invariant (CRITICAL class — fixed)

A `call{value}` must always render a "! NATIVE ETH" page. Fixed via dispatcher-level
`enforce_native_value_page` in `secure/src/tx/display/mod.rs` (commit-era fix
`project_erc20_unknown_hidden_value`). **Test:** drive non-zero `tx.value` through *every* renderer
(value transfer, erc20 known/unknown, blind, Safe, ERC-7730, typed-call, batch) and confirm the
value page appears each time. **Pass:** no path hides native value.

### 7.2 Safe SafeTx clear-sign

- **Refund block (HIGH — fixed):** non-zero `gasToken`/`gasPrice`/`refundReceiver` must render a
  loud 2-page refund block (`project_safe_refund_wysiwys_gap`). Craft a token-refund SafeTx; confirm.
- **multiSend (`0x8d80ff0a`) clear-signs per record** (shipped 2026-06-12, `secure/src/tx/eip712/safe/multi_send.rs`) — it is NOT a blind-sign path any more. The bar: each packed record is strictly decoded (per-record `operation==0`, ≤6 records, exact framing) and routed through the same inner ladder (ERC-20 / ETH / Safe-mgmt / CoW / loud per-record blind) with divider pages; `operation==1` (DELEGATECALL) is accepted ONLY against the three pinned canonical `MultiSendCallOnly` deployments; ANY framing/rule violation or page-budget overflow must **refuse to sign** (a DELEGATECALL is never blind-signed). **Test:** craft (a) a well-formed batch → per-record clear-sign with dividers; (b) a record with `operation==1` to a non-pinned address → refuse; (c) over-long / malformed framing → refuse. **Fail:** a silent benign render of an undecoded/rule-violating batch, OR a refusal of a valid batch. (`operation==0` calls to a MultiSend address stay loud blind-sign — under CALL the Safe isn't msg.sender for the records.)
- **Safe-wrapped CoW pre-sign:** confirm the order binds to `orderUid.owner == the Safe` and renders
  Safe context + full order intent. `secure/src/tx/eip712/safe/cow_binding.rs`.

### 7.3 CowSwap order binding — **native on-device decode**

The EIP-712 `GPv2Order` is verified in S-world (`secure/src/tx/eip712/cowswap/`) and the order payload is decoded on-device, with token name/symbol/decimals from the firmware-pinned `ERC20_DB_ROOT`. Incomplete registry-known Aave formats refuse. **Test:** construct a settlement calldata whose decoded order differs from the rendered intent (wrong token, amount, or receiver) and confirm `cowswap/verify.rs` rejects it; also confirm an unknown sell/buy token falls to a loud page rather than a friendly-but-wrong symbol. **Pass:** no benign-display/malicious-sign order verifies.

### 7.4 ERC-7730 / typed-call

- Walker slot-confusion and tuple-member completeness were fixed (`project_erc7730_walker_slot_confusion`,
  `project_erc7730_tuple_member_completeness_gap`; root regen `…→d510982a`). Confirm the descriptor
  root on the EVT matches the fixed build. Craft a descriptor that signs a tuple member without
  showing it → dbgen completeness lint should make this un-buildable; on-device walker bounds should
  reject hazardous paths and fall to blind-sign.
- Typed-call ABI parser caps (`MAX_ARGS`, nesting, arena): exceed each → must fall to blind-sign.

### 7.5 Off-chain (EIP-1271 / ERC-6492) domain separation

The raw32 UserOp-forgery (CRITICAL) is fixed by on-device `replay_safe_hash` nesting for kind=0/2
(`project_offchain_raw32_userop_forgery`). **Test:** request RAW32 over `sphincsDigest(drainOp)` and
confirm the firmware nests it (so the signed value is computationally separated from any on-chain
`sphincsDigest` (cross-hash separation, `∨ BreaksHash`)) and shows a loud blind page. Also retest the `account_deployed` FI-OOB fix
(`project_offchain_account_deployed_fi_oob`): glitch the deployed/counterfactual size selector and
confirm no OOB write across the NS/secure SRAM boundary.

### 7.6 Paymaster authorization — **open MEDIUM to confirm on silicon**

Only the **SHA-256 of `paymasterAndData`** crosses the wire (`cmd_sign_userop.rs` offset 244..276);
the firmware never decodes or renders the paymaster address/selector. A malicious companion that
relies on a pre-existing paymaster allowance could, in principle, substitute `paymasterAndData` to
redirect gas/allowance, bounded by the displayed worst-case-fee cap and any existing allowance.
**Test:** with a real ERC-20 paymaster and a pre-existing allowance, confirm whether the device ever
shows a paymaster page (it doesn't today) and whether a substituted paymaster within the fee cap can
divert funds on-chain. **This is the one clear-sign item still worth a fresh on-device + on-chain
investigation.**

### 7.7 NV3007 LCD trusted-display bus

LA on the LCD SPI during high-value signs: confirm every rendered character appears on the bus and
**no secret** (PIN, mnemonic word, key) ever crosses the display bus. Confirm seed-wizard decoy
mnemonics and PIN entry don't leak via timing or render order.

---

## 8. NS gateway, USB, firmware update, counters

### 8.1 NSC gateway / NS pointer validation (Invariant #4)

**Property.** `NsPtr<T>` typestate forces validation before deref; checks are null/bounds/overflow/
range/mailbox-exclusion, plus the ARMv8-M `TT` instruction for live SAU classification; double-
validated with `wait_random` between and sentinel-gated (HIGH-1 hardening). NS buffers copied to
S-stack before parse. `secure/src/nsc/{ns_ptr,ptr_validate,mod}.rs`.

**Tests (USB fuzzer + glitch rig).**
- Fuzz every `cmd_*` handler with null, just-below-base, arithmetic-wraparound, secure-straddling,
  and mailbox-overlapping pointers → all must reject with `InvalidPointer`, none deref.
- TOCTOU: flip the SAU classification mid-validation (RDP-0 unit) → second TT must catch it.
- Glitch a single validation sentinel → second sentinel + register scrub should hold (two faults
  required).

**Pass.** All malformed pointers reject; no single-fault deref of a secure/NS-straddling pointer.

### 8.2 USB protocol robustness

**Property.** APDU-v2 over HID (`CLA=0xF0`), command/response chaining up to 8192 B; OTG forced
device-mode, SOF interrupt masked (USB timing side-channel). `nonsecure/src/usb/`,
`docs/companion/usb-protocol-v2.md`.

**Tests.** Oversized (>8192) APDUs, malformed chaining (stale partial reassembly), response-drain
races → graceful reject, no overflow/DoS. Glitch the OTG `FDMOD`/SOF-mask config writes → confirm
the device doesn't fall into host mode or re-open the SOF side-channel.

### 8.3 Firmware update replay / rollback

> **Software review only; no silicon authority.** The V1/75-byte path and its
> OTP tally are legacy bench code and production-fenced. Draft 1.1 proposes a
> slot-bound manifest-v6 plus typed marker/selector/floor state, but is an
> unapproved research candidate and grants no implementation authority.

**Property under review.** A vendor-authenticated candidate manifest tuple cannot
retire the confirmed fallback before the health contract; ordinary same-epoch
releases perform zero floor writes; PIN is required on every FW command.
`secure/src/fw_update/`, `fw-manifest/`, `fwsign/`, `fsbl/`.

**Tests.** Replay an old signed manifest; reject a retired epoch; single-fault
glitch the verify; cut power at every PENDING/ATTEMPTED/CONFIRMED marker and
floor-establishment transition in the candidate state machine; confirm no
pre-CONFIRMED transition retires the fallback. Corrupt staged bytes and require
the image re-hash to reject. These are software/model tests until the later
silicon gate is separately authorized.

**Pass.** Not currently claimable for production. Software tests must reject
replay/downgrade/single-fault bypass; physical floor/ECC/interruption properties
remain gated to the later named sacrificial-silicon phase.

### 8.4 Off-chain counters / combined cap (Invariants #7, #9)

**Property.** Page-123 log-structured per-slot counter; `MAX_OFFCHAIN_GAP=100`; combined cap with
on-chain uses; monotonic, unresettable. `secure/src/offchain_state.rs`.

**Tests.** Exhaust the gap (101st unbacked sig rejects); exceed the combined cap; **glitch a
counter flash write + power-cycle** and confirm the page-123 self-heal no longer bulk-erases live
counters (HIGH-1 fix `6041f07a` gates the erase on `has_live_entries`) — i.e. a fault can't roll all
slot budgets back to zero. Confirm a network-retry of the same off-chain request yields a *different*
monotonic count (replay-evident).

**Pass.** Caps enforced; no fault rolls counters back; counts are monotonic.

### 8.5 Inactivity timeout / signing window

**Property.** 120 s S-only TIM timeout; NS pings do **not** reset it; `HandlerGuard` prevents the
idle-wipe ISR from zeroizing SRAM while a long sign holds stack copies. `secure/src/timeout.rs`.

**Tests.** Loop `GET_REMAINING` from NS during the window → timeout must still fire at 120 s. Glitch
the `HandlerGuard` depth check during a multi-second keygen → confirm the ISR doesn't wipe mid-sign
(would corrupt the derivation). Confirm continuous *signing* legitimately extends the window (by
design).

---

## 9. Fault-injection primitives — coverage map

The codebase is single-fault-hardened across critical gates; the realistic threat is **two
coordinated faults**. Prioritise these combinations on the glitch rig:

| Target | Single-fault defense | Two-fault test |
|---|---|---|
| `gated_unlock` verdict | F-15 double-read counter + FihBool `pin_verified` + sentinel | Skip bump *and* force verdict sentinel |
| NS pointer validation | F-8 double-validate + `wait_random` + sentinel + register scrub | Skip 2nd validate *and* stale OK_SENTINEL |
| Signature verify-before-release | double-compute + verify-gate sentinel + CFI counter | Skip `ct_eq` *and* `verify` |
| FW signature verify | `check_true_into_sentinel` double-eval | Skip verify *and* force sentinel |
| Counter monotonicity | F-12 forward+reverse scan readback | Corrupt write *and* glitch readback |
| Rate limiter (F-17) | SysTick min-delay | Zero the timer *and* skip the wait |

`secure/src/fi.rs` is the primitive library (sentinels, `wait_random`, CFI counter,
`zeroize_barrier`). Use the `sca-trigger` GPIO on a bench image to sync captures, then re-confirm the
gate exists in the production binary (the trigger itself is fenced out of production).

---

## 10. Ship-blocker verification checklist (build + bench)

Confirm on the actual EVT image / unit:

- [ ] **S-1** OPTIGA F1D0 `Change ≠ ALW` (Auto(F1D0) + LcsO=Op); desolder-overwrite fails. **And** a
      `compile_error!` fence requires the lockdown feature in production (verify it isn't missing).
- [ ] **S-2** exact E0E8/E0E9/E0EF type-0x11 inventory is closed under the reviewed factory
      policy; E0E1..E0E3 remain type-0x12 and cannot be retyped; attacker manifests are rejected.
- [ ] **S-3** `optiga-hw-counter` compiled in (fence present); E120 LUC (not F1E1) bounds attempts.
- [ ] **S-5** SE050 SCP03 response is ciphertext + R-MAC on I²C2 (LA-confirmed) — **retire the
      pending item**.
- [ ] **S-6** Admin cannot delete-substitute the user UserID (`SW=0x6986`).
- [ ] **S-7d** Empirical lockout SW matches the `AuthMethodBlocked` mapping (LA-captured).
- [ ] **Channel keys** are device-unique (not published NXP/Infineon defaults); fallback fenced out.
- [ ] **GTZC** 7/7 RAZ-fault (`gtzc-enforcement-hw`); USB enumerates; TAMP/GTZC2 isolation confirmed.
- [ ] **Tamper** `tamp`+`tamp-wipe`+`tzic-wipe` active; ITAMP9 escalates to wipe.
- [ ] **Consumption-mask** active and unbiased; measurably raises CPA trace count.
- [ ] **Debug** RDP-2 set; forbidden features `compile_error!`; no debug strings in the ELF.
- [ ] **Boot** confirm monolithic-vs-A/B reality; note the human-only fingerprint comparison gap.
- [ ] **CowSwap (native decode)** order binding uses
      `cowswap/verify.rs` to cross-check the canonical order against the
      calldata and token metadata against the pinned `ERC20_DB_ROOT` (§7.3).

---

## 11. Suggested campaign phasing

**Phase 0 — bring-up & non-destructive (days 1–3).**
Run the existing on-silicon self-tests (`gtzc-enforcement-hw`, `saes-self-test-hw`, the SE050 TRNG
stress probe, `pin-gate-*-e2e`). LA-capture the SCP03 and Shielded-Connection channels (§5.1, §5.2 →
retire S-5). USB-fuzz the gateway (§8.1–8.2). Craft the WYSIWYS malicious payloads (§7) over WebHID.

**Phase 1 — entropy & functional crypto (days 3–6).**
Instrumented RDP-0 build: raw-entropy capture → NIST/AIS-31 per source (§4.1). KDF/slot-binding and
counter-cap functional tests (§4.3, §8.4). Firmware replay/downgrade (§8.3).

**Phase 2 — destructive physical (days 6–10).**
Desolder-OPTIGA S-1/S-2/S-3 chain (§5.4) — the headline. Decap for single-half extraction (§4.2).
OTP brownout (§6.4). These consume sacrificial units.

**Phase 3 — glitch & SCA (days 10–15, needs the rig).**
Two-fault campaign per §9 (gated_unlock, pointer validation, sign verify, FW verify). CPA/DPA on
signing with mask on/off (§4.4, §6.7). Tamper-canary glitches (§6.3).

**Phase 4 — synthesis.**
File each confirmed finding against the ship-blocker checklist (§10); re-test every fix on a freshly
locked unit before sign-off.

---

## 12. References

- Invariants & threat model: `docs/security/threat-model.md`, `README.md`
- Audits: `docs/security/audits/{crypto-core,fault-injection,pin-unlock-lockstep,counter-replay-state,boot-fsbl,gateway-parsing,wysiwys-clearsign,sig-domain-separation}-*.md`
- Security review + ship blockers: `docs/security/security-review-2026-05.md`, `EthereumPhone/PQ1` issues (labels `source:production-todo`, `source:work-todo`, `ship-blocker`)
- SE bring-up: `docs/secure-elements/optiga-bringup-status.md`, `docs/secure-elements/optiga-brick-postmortem.md`, `docs/secure-elements/se050-userid-pin-auth.md`, `docs/secure-elements/se050-stress-harness.md`
- Hardening / boot: `docs/security/HARDENING.md`, `docs/security/measured-boot.md`, `docs/firmware/reproducible-builds.md`
- Known-vuln write-ups: `docs/VULN-*.md`, `docs/PROOF-*.md`
- Stress / fixtures: `secure/src/se050_stress/`, `tools/dev_fixture_keygen/`

> **Line-number note.** File paths in this plan are reliable; specific line numbers drift with the
> tree — confirm against the current source when you sit down at the bench.

---

## 13. Verified bench parameters & prior art (2026-07 research)

Primary-sourced facts for the campaigns above, so bench time isn't spent re-deriving them. Each is
marked with its confidence; the two **negatives** are as load-bearing as the positives.

### 13.1 Rigol MHO934 — the copy-paste SCA/LA capture recipe *(high confidence)*

The exact device is covered by the official **RIGOL MHO900 Programming Guide** (© 2026; its model
list enumerates MHO984/MHO954/**MHO934**). Control it from the capture host with **pyvisa +
pyvisa-py** over USBTMC (`USB0::0x1AB1::<pid>::<serial>::INSTR`) or raw TCP `SOCKET` — no vendor
driver needed (Rigol's proprietary TMC driver is deprecated). The USB VID is `0x1AB1`; the **PID is
not in any datasheet — read it off the bench** (`lsusb -v`, look for `bInterfaceClass 0xFE`
subclass `0x03`; the in-tree Linux `usbtmc` module binds `/dev/usbtmc0`).

Deep-memory single-shot capture (RAW mode **requires the STOP state**):

```
:STOP
:WAVeform:SOURce CHANnel1
:WAVeform:MODE RAW            # RAW = full internal memory; NORMal caps at 1000 pts
:WAVeform:FORMat BYTE         # 8-bit, fastest — fine for a first-order T-test / CPA.
                             # Use WORD for the full 12-bit ADC when SNR is marginal.
:WAVeform:STARt 1
:WAVeform:STOP  <memory_depth>
:WAVeform:PREamble?          # -> format,type,points,count,xinc,xorig,xref,yinc,yorig,yref
:WAVeform:DATA?              # -> '#9NNNNNNNNN' TMC header, then the raw bytes
```

Parse the `#9` + 9-digit-count TMC header off the front before handing bytes to numpy. **In RAW
mode scale from the PREamble, not from the timebase:** `v = (raw - YORigin - YREFerence)*YINCrement`,
`t = XORigin + i*XINCrement` (RAW `XINCrement = 1/SampleRate`). Arm each shot with `:SINGle`.
lascar/scared consume the resulting numpy arrays directly. Source:
<https://www.rigol.com/dam/global/downloads/brochures/en/program-guide/oscilloscopes/MHO900-ProgrammingGuide.pdf>

### 13.2 STM32U5 FI prior art — the two sibling results, and the confirmed gap *(high confidence)*

- **µ-Glitch (USENIX Sec 2023, arXiv:2302.06932) — the FaultyCat/EMFI shape for §6.6.1.** On the
  **STM32L5** (Cortex-M33 sibling), it disabled TrustZone-M by faulting the **SAU** and the
  **Global TrustZone Controller (GTZC)** configuration and the `BXNS` transition. **Critically it
  needs FOUR coordinated voltage faults off a *single* trigger** (avg ~1 day to land) — so the
  multi-fault requirement is itself a real countermeasure, and a single-fault campaign that finds
  nothing is not reassuring here. It claims transferability to "conceptionally similar ICs" citing
  ST's joint L5/U5 TrustZone app note — which is precisely why the U5 is worth attempting.
- **Šimoník (Masaryk 2025) — the Scaffold/voltage shape for §6.6.1.** ~**76%** success
  voltage-glitching a *Basic PIN Check* on an **STM32U5A9NJ** (MB1829, SatoshiLabs-supplied), vs
  **1.1%** with EM-FI on the same target, using a ChipWhisperer Husky. (The thesis' low-level
  numbers — glitch width/offset/voltage, whether VCAP caps were removed — are behind a JS session
  gate and were **not** extractable; get them from the PDF at the bench.)
- **NEGATIVE, and it is the point: no public STM32U5-family RDP-2 downgrade or protected-flash-
  readout result exists (2024–2026).** Actively searched (Trezor Safe 5, U5A9, TraceRip). This is a
  *gap, not evidence of safety* — §6.6.1 is genuinely novel work, and either outcome is publishable.
- **Crowbar injection point is part-specific — do NOT assume VCAP/Vcore.** The "glitch the VCAP
  pins" recipe (verified on STM32F401/F4) was **refuted as a universal rule**; the U5's core-supply
  topology differs. Identify the right rail on a sacrificial U585 first.

### 13.3 EMFI / voltage-glitch safety and target prep *(high confidence)*

- **FaultyCat/PicoEMP is an operator HV hazard.** It generates **~250 V, uncalibrated**, and —
  unlike a ChipSHOUTER — has **no missing-tip failsafe**: it will charge and fire with no coil
  attached. Treat the tip as live; discharge before handling. Sequence: **ARM** (HV charges, CHG
  LED at ~240 V) → **PULSE**.
- **Decoupling-cap removal sharpens the glitch** (small capacitance ⇒ steep V drop — SEC Consult
  SecGlitcher), but leave enough that the board still boots; over-shorting trips any PMIC and can
  damage the part.
- **Damage modes make sacrificial parts mandatory:** a mistimed glitch can corrupt option bytes to
  *random* RDP/WRP values or trigger an **irreversible flash mass-erase** (Anvil Secure, STM32F4).
  Never run OTP/RDP-2 campaigns on a part you want back.
- **Sweep = offset × width × intensity, reset-per-shot** (ChipWhisperer `GlitchController` is the
  canonical loop); add coil-XY as a 4th axis for FaultyCat. Realistic hit rates are single-digit
  percent — budget thousands of shots.
- **NEGATIVE: there is no published guidance on protecting the soldered OPTIGA/SE050 from collateral
  damage during board-level MCU glitching.** This is an open risk for our specific board — a coil or
  crowbar aimed at the STM32 can disturb an adjacent SE. Mitigate empirically: local coil placement,
  shielding, monitor SE liveness between shots, and keep the SE-specific tests (§5.7) on a rig that
  glitches the **SE's own rail**, not the whole board.

### 13.4 What did not survive verification

The research refuted 6 of 29 claims — recorded so they aren't reintroduced: the universal
"VCAP/Vcore is the STM32 crowbar point" (part-specific), an over-specific SECGlitcher RDP recipe, and
`ea_restart`'s exact flag string (confirm from the tool's `--help`). Full adjudication is in the
2026-07-17 bench-research transcript.

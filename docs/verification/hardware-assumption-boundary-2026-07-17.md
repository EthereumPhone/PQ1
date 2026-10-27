# The honest hardware boundary — what PQSigner can and cannot ever prove about silicon

**Snapshot date: 2026-07-17.** Program/epistemology layer. This document states the
**ceiling** of the verification effort against the six hardware surfaces currently held as
bare assumption, so that no claim written elsewhere in this repo — README, `THE_CLAIM.md`,
a release note, a marketing line — can exceed it by accident.

It is the synthesis layer over the 2026-07-17 external-tooling survey (≈45 adjudicated
tool/paper claims across ARMv8-M ISA, device models, flash/OTP crash consistency, secure
elements, methodology, Rust-embedded FV, and SCA/FI). **It does not re-derive that survey.**
Where a finding is cited below it is cited by its survey id (A*, B*, C-*, D*, E*, F*, G*).

**Evidence tiers within this document — they are not uniform, read the marker:**

| Marker | Meaning |
|---|---|
| **[code]** | Read from this tree by the author this pass; every `file:line` claim about PQSigner is this tier. |
| **[tool]** | A binary was run on this box by the author this pass. Specifically: the Kani seam proof (`0/52 checks, 0.18s`) and the BINSEC thumb/CMSE probe in follow-up #6. |
| **[survey]** | Sourced by a research agent and then adversarially re-checked by an independent agent that fetched the primary source itself. This covers the ~45 external tool/paper claims (Reid's bug counts, µ-Glitch, Šimoník, Sabt–Traoré, TickTock, PoWER, the CC certificate numbers, EUCLEAK's scope). Rigorous, but **not author-verified** — treat as good secondary evidence, and re-check before any of it becomes load-bearing for a public claim. |

Where **[tool]** and **[survey]** disagree, **[tool]** wins and the disagreement is recorded
rather than silently resolved — see follow-up #6, where the author's own probe **withdrew** a
survey correction.

Companion docs — read them, do not duplicate them:

- [`hardware-formalization-survey-2026-07-17.md`](./hardware-formalization-survey-2026-07-17.md) — **the survey itself**: what tool exists per surface, with URLs; the negative results; the refuted-claims table; the ranked build proposals; and the delta vs the 47-surface inventory. This document is its epistemology layer.
- [`fv-surface-expansion-inventory-2026-07-16.md`](./fv-surface-expansion-inventory-2026-07-16.md) — the 47 verifiable surfaces (what to build).
- [`formal-verification-assurance-expansion-2026-07-15.md`](./formal-verification-assurance-expansion-2026-07-15.md) — the roadmap; §P1.9 already declares peripheral behaviour, CMSE instruction semantics and silicon errata out of scope. This document is the *justification* for that decision and its precise price.
- [`../../contracts/verification/docs/THREAT_CLAIM_MAP.md`](../../contracts/verification/docs/THREAT_CLAIM_MAP.md) — the threat→claim coverage index. Every surface below should eventually carry a row there.
- [`../../contracts/verification/docs/TRUST_ASSUMPTIONS.md`](../../contracts/verification/docs/TRUST_ASSUMPTIONS.md) — the contract-side TCB inventory. Its §Out-of-scope **excludes firmware**; the assumptions below are the firmware-side hole it leaves, and today they have no ledger. That is the single largest structural gap this document identifies.

---

## §0. The frame, and the evidence tiers

**You cannot formally verify silicon you did not design.** Nobody does. seL4 — the most
heavily verified OS kernel in existence, ~20 person-years — assumes "the hardware works
correctly... not tampered with, and working according to specification... run within its
operating conditions" and assumes DMA away entirely (E1/F9). Trusted Firmware-M, the ARM
reference secure firmware for our exact core class and with a platform port for our exact
dev board, has **no** formal isolation proof at all and justifies S/NS isolation by "fully
enumerated and audited" (A8/E5/G13). CompCert's residual bugs all lived in the unverified
last mile at the machine boundary (E7). Pancake — the 2025 state of the art in verified
device drivers — trusts its device model by explicit statement: "we trust the device not
to malfunction... Verification of the device hardware... would be needed to gain further
assurance" (B1). Even Termite, the flagship device-model-driven effort, never implemented
the one step that would have validated its model against RTL (B3).

So the only honest frame, everywhere below, is:

> **Verify software AGAINST a hardware contract you wrote down. Then validate the contract
> empirically. The contract stays an assumption forever.**

PQSigner is not behind the field here. It is at the field's ceiling on several surfaces and
ahead of TF-M on others (`make gtzc-enforcement-hw`'s 7/7 RAZ-fault test is stronger
evidence than TF-M publishes for the same property). What PQSigner lacks is not tools; it
is a **ledger** that names each assumption, its owner, and the test that could falsify it.

### Tiers

The task framing asked for six tiers. They map onto the existing
[`THREAT_CLAIM_MAP.md`](../../contracts/verification/docs/THREAT_CLAIM_MAP.md) /
[`ASSURANCE_CASE.md`](../../contracts/verification/docs/ASSURANCE_CASE.md) §0 legend as
follows — **use the existing letters in rows; this table exists only to stop a parallel
taxonomy from being minted.**

| Tier (this doc) | Existing legend | Means | Strength |
|---|---|---|---|
| kernel-proof | `K` | machine-checked ∀ over an extracted/modelled artifact, `#print axioms` clean | strongest available; still relative to its axioms |
| bounded | `C` | Kani/CBMC bounded MC, KAT, corpus | ∀ up to a bound; sound within it |
| model+validation | *(new: `M`)* | a written contract/model + a **differential test that runs and can fail** against code or silicon | only as good as the falsifying test — see §2 |
| silicon-test | `silicon-E2E` | a positive on-hardware test on our parts | bounds disbelief; never a ∀ |
| certificate-cited | `T` (subtype) | third-party lab attestation (CC/PSA/SESIP/ESV) | attestation of bounded expert effort; **not a proof, and EUCLEAK proves it (D4)** |
| bare-TCB | `T` | asserted, discharged by nothing but the datasheet | zero assurance; must be *named* |

`M` is new and is the tier this document argues most of the hardware work can reach — and
the tier that most easily degenerates into theatre (§2).

---

## §1. The six surfaces

Summary first. Detail follows.

| # | Surface | Strongest honest evidence achievable | Tier ceiling | Residual that is assumption **forever** |
|---|---|---|---|---|
| (a) | OTP one-way / monotone fuse | Contract in Rust behind the HAL seam + Kani-proven driver logic + a per-part destructive silicon probe | `C` + `silicon-E2E` (n=few) | Fuse physics; that a QW that programmed once cannot ever be re-driven; ECC line semantics; that a *brownout-torn* burn is detectable |
| (b) | Flash program/erase atomicity, torn write, ECC, brownout | PoWER-style crash model (chunk=16 B QW) + TLA+/TLC ordering + read-back-verify + a power-cut rig on sacrificial parts | `K`/`C` for logic, `M` + `silicon-E2E` for the contract | The chunk-atomicity premise itself; ECC behaviour on a torn QW; marginal-cell read stability after brownout |
| (c) | ARMv8-M ISA / CMSE veneer / SAU-IDAU-GTZC | Linker/window compile-time asserts + `make gtzc-enforcement-hw` + a hand-written SAU/GTZC attribution contract | `silicon-E2E` + `M`; **never `K`** | CMSE instruction semantics; SAU/IDAU composition as ST wired it; the entire GTZC peripheral |
| (d) | I2C + T=1' / IFX-I2C framing, retry, guard time | TLA+ model of the framing/retry FSM + Kani on pure framing/CRC + differential replay against a captured bus trace | `C` + `M` | Bus electrical behaviour; SE-side timing; that a 50 µs guard-time violation is benign-or-detected |
| (e) | OPTIGA / SE050 black-box APDU + LcsO | Silicon E2E per property + certificate citation, correctly scoped | `silicon-E2E` + `T`; **never above** | Everything inside the die. There is no path. This is permanent. |
| (f) | SAES/DHUK/BHK, TAMP, TRNG, HASH, RCC | KAT self-tests + fingerprint distinctness + NIST EA suite over our own TRNG samples + SVD-diff of transcribed addresses | `silicon-E2E` + `C` (gate) | DHUK per-die uniqueness and unextractability; TRNG entropy; that SAES leaks nothing exploitable; every ST erratum not yet published |

### (a) OTP one-way / monotone-fuse semantics

**Achievable.** The decidable half is large and currently unproven. `secure/src/hw/otp.rs`
(765 lines) already *asserts* the correct silicon fact in prose — "An OTP quad-word may be
programmed only once; it is not a reusable bank of individually programmable fuse bits...
after the first program of a quad-word, a later bit-clear or full-zero program raises
PROGERR" — and correctly rejected the naive unary tally on that basis. Turn that prose into
a Rust `Otp` model impl behind the (currently unwired) HAL seam and Kani-prove the driver
logic against it (F1: demonstrated on this box, 242 checks, 62 s). That converts three
things from prose to bounded theorems: monotonicity of the anti-rollback floor;
half-burn detection (`is_device_master_burned()` returning true on any non-0xFF word — a
decidable predicate Kani would refute or confirm against the model); and the crash
contract, which has a canonical shape to copy — Ariadne's `incr` postcondition
(`V() ⇒ ctr+1; else ctr ∨ ctr+1`) plus a ghost recovery state machine, mechanised in F* by
Ahman et al. (C-09) and portable into Lean or TLA+ without adopting F*.

**Residual forever.** Fuse physics. That a burn is irreversible is a property of the cell,
attested by ST's prose and by nothing else we can obtain. OpenTitan shows this is an
*encoding-design* question **only for whoever owns the tapeout** (C-07): their A/B lifecycle
words survive a second program because the silicon creator chose the ECC polynomial and the
netlist constants pre-tapeout. On COTS STM32U585 the ECC is computed by hardware over each
128-bit line and we choose nothing. For us it is a yes/no silicon fact, and the answer is
"no, you may not reprogram".

**Falsifying test that can actually fail.** Deliberately half-program an OTP quad-word on a
sacrificial U585, attempt completion, and record `FLASH_SR` PGSERR/WRPERR and the read-back.
This is worth doing precisely because the widely-cited ST community thread on stuck
half-quad-words (C-10) does **not** settle the mechanism: ST confirmed the issue and fixed
it *in STM32CubeProgrammer v2.19.0*, and stated no root cause. A tool-side fix is consistent
both with "the words were never latched and the fixed tool completes them" and with "the
silicon strands them". That thread also concerns the host SWD programming path, not our
firmware path. Do not cite it as silicon semantics in either direction.

**Tier ceiling: `C` (logic) + `silicon-E2E` (n=1, destructive) over a `bare-TCB` physical premise.**

### (b) Flash program/erase atomicity, torn write, ECC, brownout

**Achievable, and the best-value surface in the six.** PoWER (C-02, OSDI 2025) is the
framework-shaped match: crash consistency via ordinary Hoare logic + ghost state, chunked at
the device's atomic persistence granularity, with corruption modelled on a **separate axis**
from crash atomicity — which is exactly the axis the existing page-123 TLC pilot abstracts
away. Its `const_persistence_chunk_size()` is a named parameter (8 for PM); STM32's quad-word
is 16. Three things must be **added**, not swapped: 1→0-only bit semantics, 8 KiB page erase,
and ECC-locks-a-programmed-word. That last one is not additive — PoWER's
`can_result_from_partial_write` is a strict two-outcome disjunction (chunk == pre ∨ chunk ==
post), and a torn STM32 quad-word admits a **third** outcome: an ECC fault on read, neither
old nor new. Extending that touches PoWER's core disjunction. Note also that Verus is absent
from this box and PoWER's own limitations section rules out quantifier-weak tools (so Kani is
likely not a PoWER host) — this is a genuine install-and-pilot, matching the inventory's
`verus-power-flash-journal-pilot` row.

The cheaper, already-available slice: extend the page-123 TLC pilot with a torn-QW fault
action, which the existing model cannot express, and Kani the page-124 scan/bump
monotonicity behind a model `Flash`.

**Residual forever.** The chunk-atomicity premise. Tseng/Grupp/Swanson (DAC 2011, C-06) is
frequently cited as refuting it — it does not, for us. Its retroactive-corruption finding is
explicitly MLC-scoped ("This assumption is incorrect for MLC devices") and structurally
requires two logical pages sharing a cell; its "cells move in both directions" is a hedged
inference from MLC reference-voltage switching; and all 11 devices under test are raw NAND
with no NOR and no ECC. STM32U585 flash is embedded ECC-protected NOR. The paper's own §5
preserves log-structured recovery for SLC. **Do not cite C-06 as a refutation of our flash
premise.** Cite it for its real lesson: fault-injection models need input from real hardware
measurements to be representative.

**Falsifying test — and it splits into a free half and a paid half** *(costing corrected
2026-07-17)*:

- **The recovery-logic half needs ZERO new hardware.** Trigger a reset (probe-rs, or an on-device
  `SYSRESETREQ`/watchdog) at swept delays across a program/erase, reboot, and check that recovery
  lands in old-or-new-or-fail-closed. This reaches **D4** and the page-123/124 recovery paths today,
  on a bench board we already have. It does **not** model brownout — a reset is not a power cut, and
  the flash controller may complete the operation — so it bounds the *logic*, not the *analog*.
  (Note the LA1010 on the bench is **read-only** and cannot glitch; it is an observer, not a rig.)
- **Only the analog torn-write half needs a glitcher**: cut VDD at swept sub-µs offsets across a
  quad-word program and across a page erase; classify every read-back into old / new / ECC-fault /
  other. "Other" falsifies the contract. This is the single most valuable piece of hardware evidence
  PQSigner could buy — the exact instrument C-06 says the field needs and Ferrite (C-05) declined to
  build.

**Convergence worth acting on:** the **ChipWhisperer-Husky + shunt** already recommended *adopt-now*
for SCA/FI in `security-tooling-sota-2026-06.md` §4 is the same instrument that makes these crash
contracts falsifiable (glitch output → crowbar on VDD), and Donjon's **Scaffold** "can also instrument
the OPTIGA/SE050 I2C buses" — i.e. it serves `HW-ASSUME-PUTKEY-ATOMIC` too. **One rig, two assurance
programs.** The FI bench purchase is not a separate line item from this document's recommendations.

**Tier ceiling: `K`/`C` for the journal logic; `M` + `silicon-E2E` for the contract; the
premise stays `bare-TCB`.**

### (c) ARMv8-M ISA / CMSE veneer / SAU-IDAU-GTZC

**This is a closed question. Record it as closed, not as backlog.**

There is no public formal ARMv8-M model, in any framework. This is not a gap in our search
and not an effort problem — it is an ARM business decision, and every downstream tool dies
with it as a single point of failure:

- ARM's public machine-readable/ASL releases are **A-profile only** (A1). ARM's internal
  v8-M ASL exists and was validated to a high standard — Reid, OOPSLA 2017 (A3/E2/G2): 59
  properties, ~315 verification conditions, 299 proved, 12 bugs found including 2 security
  bugs, all fixed by ARM. It has never been released.
- `rems-project/sail-arm` is A-profile only: `arm-v8.5-a`, `arm-v9.3-a`, `arm-v9.4-a`, and
  its own README scopes it to "the Arm A-profile architecture specification" (A4/E3/G3). Its
  models are auto-translated from ARM's *internal* ASL under bilateral agreement.
- Therefore Isla (A5) and Islaris (A6) — the symbolic-execution and machine-code-proof
  layers — have nothing to consume. Islaris's own demonstrated envelope is 64-bit
  little-endian A-profile with "scaling remains future work"; we are 32-bit thumbv8m.
- Binary tooling agrees: BINSEC has no M-profile decoder (survey + the repo's own
  2026-06 SOTA doc); angr/VEX has no v8-M security-extension decode (A11); Ghidra decodes
  M-profile but implements the stack-limit registers as uninterpreted pcodeops and has no
  SG/TT definition at all (A10); ARMORY stops at ARMv7-M (G7); FiSim hardcodes `UC_MODE_ARM`
  and never selects M-class (G8).
- Even a hypothetical Sail v8-M model would deliver only the **ARM** part. The IDAU is
  IMPLEMENTATION DEFINED (ST's), and **GTZC is an ST peripheral that appears in no ARM
  specification at all** — and GTZC is where our actual enforcement lives
  (`secure/src/sau.rs` wires `GTZC1_TZSC_SECCFGR{1,3}`). So the surface would remain only
  half-addressed in the best case.

Two things are nevertheless achievable and neither is a proof about silicon.

1. **Software-side, decidable, `C`-tier:** the SAU/GTZC **configuration logic** — the
   computation of the register values — is ordinary bit-packing over integers. TickTock
   (F4/F5, SOSP 2025) proved exactly this shape for Tock's MPU with Flux and found **5
   previously-unknown bugs in MPU-configuring code** plus 2 in interrupt handling. Its
   hardware contract was **60 lines of trusted, unchecked, hand-lifted spec**, validated by
   differential testing on real hardware. That is the honest template, and its target — an
   MPU-config file — is the direct analogue of our 572-line `sau.rs`. Note TickTock is
   ARMv7-M and its FluxArm covers no security extension; only the *method* transfers.
2. **Silicon-side, `silicon-E2E`:** `make gtzc-enforcement-hw` already does the right thing
   — 7/7 secure peripherals RAZ-fault on NS access with the violation IRQ counted. That is a
   positive test, not a ∀, and it is *stronger than the industry reference publishes*.

**Residual forever.** CMSE instruction semantics; SAU/IDAU composition as ST implemented it;
the entire GTZC block; every unpublished erratum. `S-NS-SECRET-LEAK` and `S-SRAM-NS-READ`
stay `silicon-E2E` + `bare-TCB` permanently.

**Tier ceiling: `C` for config logic, `silicon-E2E` for enforcement. `K` is unreachable —
permanently, absent an ARM release we do not control.**

### (d) I2C physical + IFX-I2C / T=1' driver framing, retry, guard time

**Achievable.** Three separable pieces:

- **Pure framing/CRC, `C`-tier, available today with no seam work.** `se050/t1oi2c.rs`'s
  `crc16` / `build_frame` / `validate_frame` are pure functions over byte slices. Kani them
  now. This is the cheapest real win in the document.
- **The framing/retry FSM, `M`-tier.** TLA+/TLC is installed and already piloted. Model the
  block layer — sequence bit, chaining, R-blocks, retry, WTX — and check progress + no-lost-
  block + no-duplicate-apply. Note the literature offers **nothing to reuse**: Chouali et al.
  (D9) is the only formal T=1 model found, and it models block/last-block/ack alternation
  only — zero occurrences of I/R/S-blocks, sequence numbers, EDC, chaining, resynch, retry,
  WTX or guard timing across the whole paper. It is not a head start.
- **The OPTIGA presentation layer.** Infineon's I2C Protocol v2.03 spec **is public and
  wire-complete** (§6: PVER negotiation, TLS-PRF-SHA256 → 40-byte keyblock, PCTR/SCTR,
  finished messages, record encryption) (D2). This matters: our existing
  `optiga_shield_handshake.pv` states in its own docstring that it is derived from
  `shield.rs` and abstracts the framing. **A model derived from our driver can only prove we
  modelled ourselves consistently.** Re-deriving it from the vendor spec makes
  driver-vs-spec divergence detectable. That is a real upgrade and it is buildable now.
  **Update 2026-07-17 (post-landing):** landed as `optiga_shield_handshake_vendor.pv`
  (`9ec109ad`), re-derived from Infineon's reference implementation
  (`ifx_i2c_presentation_layer.c`, v5.6.0). It immediately falsified the driver-derived
  model's invented host nonce: injective host agreement is TRUE there and **FALSE** under
  the vendor derivation — the host contributes no freshness (playbook SE5 / OP17-2).

**Residual forever.** Bus electrical behaviour; the SE's side of the timing contract; that a
50 µs guard-time violation is benign or loudly detected. Note there is **no public security
analysis of OPTIGA's Shielded Connection whatsoever** (D2) — the SCP03 leg has a published
proof (D1, Sabt & Traoré), the OPTIGA leg has nothing. That asymmetry belongs in a
`THREAT_CLAIM_MAP` row.

**Falsifying test.** Logic-analyser capture of a real session; replay against the model;
divergence falsifies. Guard-time violation injection on the bench.

**Tier ceiling: `C` (framing) + `M` (FSM, spec-derived) over `bare-TCB` electricals.**

### (e) OPTIGA Trust M / SE050 black-box APDU + lifecycle

**Permanent. There is no formalization path and none will appear.**

- No RTL, ever. Every technique that could genuinely discharge this — HIVE's firmware/RTL
  co-verification (B14), OpenTitan's FPV of its own lc_ctrl (C-08), Silveroak/Cava (B15),
  Termite's model-check-spec-against-RTL step (B3) — requires design source. Infineon and
  NXP will not supply it. This is a business fact, not an effort estimate.
- **Certificates do not close it, and the scope boundary is sharp.**
  - OPTIGA: BSI-DSZ-CC-0961 EAL6+/ALC_FLR.1 covers the **IC platform** — hardware + IC
    dedicated software (BOS, Flash Loader, RMS) + Infineon crypto libraries — on a 16-bit
    Intel-80251-compatible core. The Trust M **applet**, its object/OID model, LcsO
    lifecycle, and the Shielded Connection are IC *Embedded Software*, **above** the
    certified boundary; the report assigns application data handling to the environment
    (`OE.Resp-Appl`). Also: V4-2019 **expired 2024-12-17**; the current cert is V7-2024. Any
    repo doc citing V4 cites a dead certificate (D3).
  - SE050: NSCIB-CC-180212-CR5 is genuinely stronger — the TOE includes JCVM/JCRE/JCAPI and
    the GP Framework, i.e. the OS layer that enforces our UserID PIN policy. But it carries
    two caveats that bite exactly where we would want it: **"The strength of the
    cryptographic algorithms and protocols was not rated in the course of this evaluation"**
    — so it does **not** discharge SCP03 — and "Not all key sizes... have sufficient
    cryptographic strength to satisfy the AVA_VAN.5 'high attack potential'". It also covers
    only JCOP 4 SE050 v4.7 R2.00.11/R2.03.11; **we have not confirmed our bench part matches
    that version.** *(UPDATE 2026-10-19: the bench and production part is the same SE050E2,
    `SE050E2HQ1/Z01Z3Z`, IoT applet 7.2.0. Whether its JCOP release is inside this TOE, or is
    covered by a separate SE050E certificate, is still unchecked; it needs the card-manager CPLC
    read, DVT checklist 6B.1.)* SecureBox permits "execution of non-certified native software within the
    TOE" (D6).
  - At EAL6 a formal security policy model **is** mandatory (ADV_SPM.1 is in the EAL6/EAL7
    packages). But under CC 3.1 its scope was an ST-author *assignment*, and under the
    JIL/EUCC CC:2022 interpretation the prescribed minimum is a named sub-TSF —
    MPU/MMU + code loader for ICs, the application firewall for Java Card. **None of that
    scope covers OPTIGA's LcsO ratchets or SE050's APDU/policy behaviour** (D7). The artifact
    is confidential regardless; we would never hold it.
  - **EUCLEAK is the ceiling-setter.** A non-constant-time modular inversion in the Infineon
    cryptolib — in NinjaLab's exact words, a vulnerability "that went unnoticed for **14 years
    and about 80 highest-level Common Criteria certification evaluations**" (AVA_VAN.4/5, the
    highest attack-potential rating that exists) (D4). Scope it precisely: the attack was
    **demonstrated on a YubiKey 5Ci (Infineon SLE78)**, and NinjaLab states the vulnerability
    "extends to the more recent Infineon Optiga Trust M and Infineon Optiga TPM security
    microcontrollers" — i.e. for our part it is **tested-and-suspected, not demonstrated**.
    Do not write "our OPTIGA is EUCLEAK-vulnerable"; write what NinjaLab wrote.
    Scoping, honestly: it is **not** a live break of our path — we are
    SPHINCS+C10-only (invariant #5), our OPTIGA driver implements exactly six APDUs
    (OpenApplication/GetDataObject/SetDataObject/SetObjectProtected/GetRandom/DecryptSym) and
    never invokes ECDSA signing, and the tunnel is symmetric. Its value is epistemic and
    absolute: **any row that says "discharged by EAL6+" is wrong.**

**Achievable.** Per-property silicon E2E on our own parts, which the repo already does well:
`make optiga-hw-counter-e2e`, `make pin-gate-wipe-e2e`, and — the best artifact in the tree —
`make se050-admin-extract-attempt-e2e`, which proves on silicon that an authenticated admin
session can DELETE but not READ a user-PIN-gated object (`SW=0x6986`), with the delete in the
same session proving the refusal was a genuine read-deny and not a bogus authentication.
**That test is the model of what everything else here should look like**: a security claim,
a test that could fail, and a control that proves the test isn't vacuous.

**Tier ceiling: `silicon-E2E` + correctly-scoped `T`. Nothing above, forever.**

### (f) SAES/DHUK/BHK, TAMP, TRNG, HASH, RCC

Mixed, and the least uniform surface.

- **SAES/DHUK — the strongest empirical position in the repo.** Per-die DHUK is *empirically
  validated*: two B-U585I boards both produce ST's substituted constant `117d822a62a50830`
  at RDP0, and **distinct** fingerprints at RDP1 (`ea86dbc4586953a6` vs `002202686b06dcf6`),
  falsifying the alternative hypothesis that DHUK is a global ST constant at all RDP levels.
  That is a real falsifiable test that could have failed and nearly did — it caught the
  RDP0-constant class of mistake before Tier-2 BHK landed against it. It remains n=2, and
  says nothing about RDP2 (see §5).
- **TRNG — the weakest row, and it is under-defended.** `hal/src/lib.rs` obliges every `Rng`
  impl to satisfy "NIST SP 800-90B post-conditioning" while `rng.rs` implements **no health
  tests** — no repetition-count, no adaptive-proportion, not even RM0456's recommended
  consecutive-`RNG_DR`-differ check — and `RNG_CR_NIST_DEFAULT = 0x00F0_0D00` is an
  empirically-corrected magic constant. EverCrypt (E12), the most sophisticated verified-crypto
  project in existence, **scoped randomness out of its API entirely** rather than axiomatize
  the RNG boundary — which is authoritative calibration that the *entropy source* is
  genuinely un-axiomatizable, and simultaneously an argument that the *health tests* (ordinary
  decidable software) should be implemented rather than left as an unimplementable obligation
  in the contract. This is aggravated in a way EverCrypt never faces: `rng_strong::fill` feeds
  an **irreversible** OTP master burn. A silent bias at burn time is undetectable and
  unrecoverable, and it roots every SE pairing secret. On certification: **no ESV certificate
  names the STM32U585**, though E11 ("STM32U5x TRNG", Rev B, 12/2022) carries an Operating
  Environment of "STM32U5x advanced Arm-based 32-bit MCU" and is by elimination the only
  candidate cert for U585 — the later certs enumerate other sub-families (U5Fx/5Gx, U59x/5Ax,
  U535x/545x). E11 has no published Public Use Document, so its device list is unenumerated
  and the Rev-B match to our silicon is unconfirmed; `RNG_VERR` would settle it. Regardless,
  SP 800-90B validation is *statistical estimation by an accredited lab*, never a proof
  (G11). We can self-run the NIST EA suite (v1.1.8) over our own samples: that is
  `silicon-E2E` evidence, not a formalization path.
- **TAMP — the least-exercised code in the tree.** Log-only by default; `tamp-wipe` is forced
  ON for shipping dual-SE images and has never been silicon-validated; the driver was
  based at the wrong address (`0x5600_4400`) and `tamp.rs` itself records that this "went
  unnoticed" because TAMP is log-only. There is no `make tamp-*-hw`.
- **Address transcription — cheap, high-value, and 3-for-3 against us.** MMIO base addresses
  are hand-transcriptions of RM0456, and this repo has three recorded transcription failures:
  TAMP based at the wrong address (silent, because never exercised); GTZC TZSC writes landing
  on the TZIC base and silently no-op'ing; ICACHE off by `0x400` causing HardFaults. This is
  CompCert's `TargetPrinter` failure mode exactly (E7) — mechanical transcription at the
  proof↔machine boundary, wrong in rarely-exercised paths, caught only by execution. **And
  there is no SVD in-tree to cross-check against** (no `*.svd`, no PAC dep) even though
  `stm32-rs` publishes a patched U585 SVD (3.7 MB, 202 peripherals, NS + SEC_* aliases)
  covering SAES/HASH/RNG/PKA/FLASH/GTZC/TAMP/RCC/I2C/SPI/TIM/USART/ICACHE/PWR, and
  `saes.rs` **already cites the generated PAC as an authoritative source**. The artifact is
  not missing; the automated diff is. Scope honestly: the SVD does **not** contain SAU, MPU,
  NVIC, SCB, UID or OTP — so `sau.rs` is only half-checkable — and it encodes **layout, not
  behaviour** (SAES `KEYSEL` is present at bitOffset 28/width 3 with a tautological
  description and **no** enumeratedValues, i.e. the SVD does not say that KEYSEL selects
  Software/DHUK/BHK — the entire security semantics of the Tier-1 KDF) (B10). This is a
  transcription lint, not verification, and it would have caught all three historical bugs.

**Tier ceiling: `silicon-E2E` + `C`-tier gates. The DHUK-unextractability and TRNG-entropy
premises stay `bare-TCB` forever.**

---

## §2. Where formalization buys something, and where it is theatre

**Brutal version:** modelling a device we cannot inspect, and then proving the driver
against that model, **relocates the assumption from the driver to the model and launders it
as a proof**. If the model is written by the same person who wrote the driver, from the same
datasheet reading, and nothing can contradict it, the exercise has produced a second copy of
the belief and a certificate that the two copies agree. That is negative value: it is
strictly worse than an honest prose assumption, because it *looks* like evidence.

PERRY (B11) is the canonical demonstration: it infers a peripheral model **from the vendor
driver**, so the model encodes the driver's belief — which is precisely the belief in doubt.
Its own fidelity metric is 74.24% of unit tests passing unaided. Kobeissi's *Verification
Theatre* (E11) is the same failure at the software boundary, with real CVEs: a verified
crypto library whose F* spec of an AVX2 intrinsic computed `x·x` instead of `x·y`, shielded
by `opaque_to_smt` and asserted through val-without-let axioms. **A false axiom lets the
solver derive anything.** Our hardware contract *is* an axiomatization of the machine, and
we have a live instance of the exact failure mode:

> `hal/src/lib.rs` declares itself the specification and asserts that programming an
> already-cleared bit is a no-op. `secure/src/hw/flash.rs:723-729` asserts that ECC **locks**
> the value and forbids re-programming. **Both cannot be true.** The page-124 PIN-counter
> design depends on which. And because `secure/Cargo.toml` has **no dependency on `hal/`**,
> nothing — not the compiler, not CI, not a reviewer — detects the contradiction. An unsound
> axiom with no gate.

**And the repo has already proved, once, that a model at the wrong granularity is worse than no
model.** The pretty abstraction for OTP is a monotone bit-lattice: bits go 1→0 and never back. On
STM32U585 that abstraction is **true** — and the design built on it was **invalid**. The rejected
legacy anti-rollback tally (`hw/otp.rs`, `rollback_floor_once`) encoded the version as a count of
cleared bits (`count += w.count_zeros()`, `MAX_FW_VERSION = ROLLBACK_WORDS * 32`), which requires
clearing one more bit in an already-programmed quad-word. The silicon forbids exactly that: *"An OTP
quad-word may be programmed **only once**… A target quad-word must be **virgin**. Reprogramming a
partially programmed OTP quad-word — including an additional bit-clear — raises [PGSERR]… the
quad-word is lost; **it must not be retried or interpreted as a bit count**"* (otp.rs:4-12, 61-68).
The binding constraint was never bit monotonicity; it was **quad-word program-once**. A bit-lattice
model would have issued a clean green for an irreversible operation that bricks parts. `bump_to` is
now `unsafe` and production-compile-blocked.

The lesson generalises to every surface here, and it is the reason "wire the seam and model the
device" is not automatically progress: **a hardware model pitched above the granularity at which the
silicon actually commits does not merely fail to help — it launders a design error into a proof.**
Model at the commit granularity (quad-word, one APDU, one bus transaction) or do not model.

**And the repo did not apply its own lesson to the master key.** *(Author-verified 2026-07-17;
surfaced by the survey's completeness critic.)* `hw/otp.rs::burn_device_master()` programs the
32-byte master as **two separate quad-word writes**:

```rust
let r0 = unsafe { program_otp_qw(MASTER_KEY_ADDR,      &qw0) };  // bytes  0..16
let r1 = unsafe { program_otp_qw(MASTER_KEY_ADDR + 16, &qw1) };  // bytes 16..32
```

It has a same-run readback guard (*"catches brown-out mid-program"*, comparing `readback == key`).
That guard is good and it **never runs across a reset**. A power cut between the two programs leaves
QW0 burned and QW1 virgin, and on the next boot:

- `is_device_master_burned()` returns **`true`** — it scans all 8 words and returns true on **any**
  word `!= 0xFFFF_FFFF` (otp.rs:504-509), so one programmed quad-word is enough;
- `burn_device_master()` therefore returns `Err(AlreadyBurned)` and **never completes or retries**;
- `first_boot`'s Step-1 precondition is exactly this boolean (`first_boot/mod.rs:218` →
  `state.rs:157`), so the ceremony proceeds;
- `secret_keys.rs:448` reads `[QW0 ‖ 0xFF×16]` and derives **every** SE transport credential
  (SCP03 enc/mac/dek, admin PIN, OPTIGA PBS) from it.

Result: the device master silently and permanently drops from 256 to **128 bits** of entropy — the
upper half is the known constant `0xFF×16` — with no detection and no path to repair. Honest severity:
128 bits is not a practical break (and AES-128 credentials cap there anyway), so this is a **loss of
designed margin, not a compromise** — but it is silent, irreversible, and it roots every SE pairing
secret. The worse branch is a torn *QW0*: an ECC-poisoned word still reads non-`0xFF`, still returns
`burned = true`, and may read unstably ⇒ nondeterministic credentials or a brick.

This is the thesis in one function. The abstraction is a **boolean** — `burned?` — over a device that
commits at **quad-word** granularity; `FirstBootHw::otp_master_burned() -> bool` is the outcome-type
defect of §2.1 in its most consequential instance, on the one path that is irreversible.

**FIXED 2026-07-17 (`a53aefc3`), and the fix is the method in miniature.** The rule moved into a pure,
MMIO-free `crate::otp_state` — the same split, and the same rationale, as the existing `flash_policy`
module: *"keeping the policy free of MMIO makes the exact boundary behaviour executable on the host;
the hardware driver consumes the validated capability."* `MasterKeyState { Virgin, Partial, Complete }`
is classified **per quad-word**; `read_device_master()` refuses anything not `Complete` (the barrier
that makes the defect unreachable — no caller can obtain a half-blank master, so none can root a
credential in one); `is_device_master_burned()` now means `Complete`, fail-closed at every call site;
`master_key_state()` double-reads with an FI delay and fails closed on disagreement — deliberately
*not* `rollback_floor`'s `max(a,b)` vote, because that conservative-HIGH bias is correct for a
monotonic admission check and wrong for an irreversible write. `burn_device_master()` **completes** a
`Partial` region rather than refusing it, and programs quad-words sequentially, aborting on the first
error (it previously ran both programs before inspecting either result, so a failed QW0 was still
followed by a QW1 program — compounding a recoverable tear into a `Complete`-looking region with an
ambiguous QW0).

Note what made the fix verifiable, because it is this document's whole argument: the rule is now
**executable on the host**, so it carries eight behavioural tests (plus an exhaustive 2^8
blank/programmed sweep) instead of `include_str!` greps — and it is **mutation-checked**: reverting
to the old per-bit rule turns 6 of 8 RED. Before the extraction, the only available guard was a
source-text assertion, which is exactly the false-green this document warns about. The seam was not
optional bookkeeping; it was the difference between a proof and a grep.

Residual, unchanged and now explicit: the fix rests on `HW-ASSUME-OTP-ONEWAY` and
`HW-ASSUME-QW-ATOMIC`. A *torn QW0* — ECC-poisoned, reading non-`0xFF` but unstable — still
classifies as programmed; the double-read catches instability, but an ECC-corrected-but-wrong value
reads stably and is undetectable in software. That is silicon evidence (C8's ~21-shot probe), not
code.

### The criterion

> **A model earns assurance only in proportion to what could contradict it.** Every model
> row must name a **falsifying test that runs and can fail**. A model with no such test is
> theatre.

There are exactly two things a hardware model can be pinned to, and a model needs at least one:

1. **Pinned to the code.** The seam must be *wired*, so that model ≠ code is a build failure
   or an unavoidable review event. This is what the unwired HAL seam denies us today, and it
   is why wiring it is not merely "an enabler for Kani" — **it is the mechanism that makes
   the contract falsifiable at all.** Note the honest limit: with the seam wired, Kani checks
   driver logic against a hand-written mock. That is the software half. It says nothing about
   silicon.
2. **Pinned to silicon.** A differential test that generates cases *from the model* and runs
   them on the part, where a divergence falsifies the model (or exposes silicon). This is the
   herdtools7/diy7 tradition (E10) — the *method*, not the tool: diy7/litmus7/herd7 target
   multiprocessor shared-memory and have no purchase on a single-core M33, so nothing is
   adapted; a PQSigner conformance harness would be a fresh build.

Both routes are legitimate. What is not legitimate is a third: a model validated only
against its author's datasheet reading. Termite (B3) is the cautionary case — the team that
most wanted the spec↔RTL check *never implemented it*, and their two evaluated devices were
proprietary so they could not have run it anyway; for one they derived the model from the
existing Linux driver, i.e. circular. Pancake (B1) is the honest case: hand-written model,
explicitly trusted, stated in the paper.

### Scored: what is theatre and what is not, in this repo

| Work | Verdict | Why |
|---|---|---|
| Kani over `t1oi2c` `crc16`/`build_frame`/`validate_frame` | **Not theatre** | Pure functions. No model. Proves what it says. |
| Kani over page-124 scan/bump behind a *wired* `Flash` model | **Not theatre, conditionally** | Only once the seam is wired. As a parallel reimplementation beside a 2243-line driver with nothing detecting drift, it is theatre — and it currently under-models the security-load-bearing part (the F-15.r5 forward+reverse FI double-scan with fail-closed-to-CAPACITY, which is what page-124 exists to defend). |
| TLA+ page-123 crash-atomicity (done) | **Not theatre** | Confirmed the SIGS-first ordering claim over 1M states. Honest about its own gap: no per-entry integrity → HW premise. |
| Re-deriving `optiga_shield_handshake.pv` from Infineon I2C Protocol v2.03 §6 | **Not theatre — DONE 2026-07-17** | Landed as `optiga_shield_handshake_vendor.pv` (`9ec109ad`, from Infineon's reference implementation); the external ground truth immediately diverged — it caught the driver model's invented host nonce (inj-agreement FALSE vendor-side). |
| The current `optiga_shield_handshake.pv` | **Borderline theatre** | Derived from `shield.rs`; abstracts the framing. Proves self-consistency. Its own docstring says so — which is why it is borderline and not disqualifying. **2026-07-17: banner-marked do-not-cite for freshness/replay after the vendor re-derivation falsified its host-freshness result; secrecy/non-injective-auth results stand.** |
| A hand-written SAU/IDAU/CMSE contract with no silicon differential | **Theatre** | Nothing could contradict it. `make gtzc-enforcement-hw` is worth more. |
| Modelling OPTIGA/SE050 internals | **Theatre, unconditionally** | Pure relocation. No test can reach inside the die. Surface (e) is silicon-E2E-or-nothing. |
| SVD-diff of hand-transcribed MMIO addresses | **Not theatre** | External artifact; the diff can fail; it would have caught 3 historical bugs. |
| Citing "EAL6+" against S-OPTIGA-TA-BYPASS | **Theatre** | Out of TOE scope, and EUCLEAK proves the scheme misses 14-year constant-time defects. |
| `make se050-admin-extract-attempt-e2e` | **The gold standard** | Security claim + a test that fails if the policy regresses + a control (same-session DELETE) proving the refusal was real. |
| `first_boot::state::run` + `power_cut_at_every_boundary_converges` | **Not theatre for the sequencer; uninformative about the rotations** | See §2.1 — the harness is real and exhaustive, but its fake models each SE rotation as an idempotent boolean assignment, so the probe-and-branch that carries all the risk is unreachable from it. |

### §2.1 The sharpest in-repo instance: an exhaustive crash test that cannot reach the risk

`secure/src/first_boot/state.rs` already **is** the pattern this document recommends: a trait seam
(`FirstBootHw`), a **pure sequencer** (`pub fn run(hw: &mut dyn FirstBootHw)`, state.rs:155) that the
production impl (`first_boot/mod.rs:185`) drives, and a host test
`power_cut_at_every_boundary_converges` (state.rs:526) that enumerates **every** durable op boundary
and cuts at each, asserting ALL_DONE convergence and "no step ran more than twice". This is good
engineering and the test is genuinely exhaustive over what it models.

It is green anyway, because the model is optimistic at the **outcome type**. `FirstBootHw`'s methods
return `Result<(), FirstBootError>`, and the fake's SE rotation (state.rs:363-372) is:

```rust
self.se050_keys_final = true;    // durable SE-side effect
self.tick();                     // cut AFTER the effect, before the journal commit — modelled!
```

The fake *does* model "SE committed, MCU never journaled". On resume the step re-runs and the bool is
set again — **idempotent by assignment**. But the real rotation (`se050/mod.rs:372-395`) achieves
idempotence by a **probe-and-branch**: establish SCP03 under the FINAL keys; if that works, return
"already rotated"; else re-link and establish under TRANSPORT and PUT KEY. That path depends on
`establish` failing *cleanly* under the wrong key, on `link_bringup` resyncing after a failed
establish, on the SE not penalising failed establishes, and on PUT KEY being all-or-nothing. **None
of it is reachable from `FakeHw`.** The trait's contract pushes all of it into prose (state.rs:114-117:
*"Implementations MUST make the rotation methods idempotent + two-phase … on resume try FINAL first,
fall back to TRANSPORT"*) — i.e. into the one place that cannot be checked. `rdp2-self-lock` is
production-only and incompatible with every dev/test feature, so the branch has no silicon test either.

This is not a new gap: CLAUDE.md already names **"atomic durable old/new/KVN recovery proof"** as an
open production gate. What is new is *why the existing harness cannot reach it* — and that the fix is
the outcome type, not more tests. An outcome algebra that distinguishes `Acked` /
`DefinitelyNotApplied` / `MayHaveApplied` (and a probe result that distinguishes `Rejected` from
`Inconclusive`) would have **forced** the fake to model the ambiguity, and the existing exhaustive-cut
harness would then reach the gate for free.

**Corollary — three sites collapse `Inconclusive` into `Rejected`, and the collapse drives a write:**

| Site | Code | Consequence of a transport glitch |
|---|---|---|
| `se050/mod.rs:375` | `if establish_with(final_enc, final_mac).is_ok() { return Ok(()) }` | falls through to the TRANSPORT branch ⇒ attempts PUT KEY |
| `se050/mod.rs:440` | `if !check_exists(ADMIN_WIPE_OBJ).unwrap_or(false) { write_userid_unlimited(...) }` | `false` = "object missing" ⇒ **drives a create/write** |
| `optiga/mod.rs:585` | `if hard_reset_and_reinit().is_ok() && ensure_shield().is_ok() { return Ok(()) }` | ⇒ falls through to the **E140 rewrite** branch — the brick-risk operation (`docs/secure-elements/optiga-brick-postmortem.md`) |

A probe that cannot say "I don't know" will say "no", and "no" here means *mutate*.

Two structural additions follow, and both are cheap:

- **The `tla2tools.jar` is not durable.** A pilot result that cannot be re-run is a
  verification claim with no executable evidence — the exact thing `verify-ledger-consistency`
  exists to prevent.
- **Own the ledger discipline.** OpenTitan (E4) makes its countermeasure list a **build
  input** with a *bidirectional* RTL↔Hjson cross-check: an RTL `// SEC_CM:` tag with no
  entry errors, and an entry absent from RTL also errors. Only that pattern transfers (we
  can never FPV our silicon; they designed theirs). Bind it to GSN's typed Assumption node
  (E9) — with the honest caveat that GSN's `A` node is *definitionally unsubstantiated*, so a
  premise validated by test is a Goal+Solution, not an Assumption — and to seL4's discipline
  of stating machine-interface assumptions **in formal logic** and discharging them one at a
  time as tooling allows (E1/F9). TF-M's "Transferred" marker (E5) is a free primitive: it
  names a downstream owner for what we cannot mitigate. PQSigner already has better bones
  than TF-M here (`THREAT_CLAIM_MAP` + `AXIOM_STATUS` + `verify-ledger-consistency` are
  ID'd, owned, falsifiable rows that TF-M's prose lacks) — it just stops at the firmware
  boundary.

---

## §3. What "we verified the driver against a device model" entitles you to say

The verb "verified" must **never** appear unqualified next to a hardware surface. Use these
matched pairs. Left column is defensible today or on completion of the named work; right
column is an overclaim and must be caught in review.

| Entitled | Overclaim — do not write |
|---|---|
| "The page-123 counter logic is machine-checked to preserve monotonicity and crash-recovery-to-old-or-new **relative to a written flash model** stating quad-word program granularity, 1→0-only bit transitions, and page erase. That model is an assumption about ST silicon, validated by *[named test]*, not a proof about it." | "We formally verified our flash driver." / "Our counters are provably crash-safe." |
| "`make gtzc-enforcement-hw` demonstrates on our silicon that 7/7 secure peripherals RAZ-fault on NS access and raise the GTZC violation IRQ." | "TrustZone isolation is verified." / "Invariant #4 is proven." |
| "No formal ARMv8-M model exists publicly, so CMSE and SAU/IDAU semantics are assumptions in our TCB. We hold them by silicon test and by ARM's own machine-checked validation of the specification (Reid, OOPSLA 2017) — which validated the *spec*, not any implementation, and not at the SAU/CMSE level." | "The ARM architecture is formally verified, therefore our TrustZone usage is sound." |
| "Per-die DHUK uniqueness is empirically validated across two boards at RDP1 (distinct fingerprints) against a shared ST constant at RDP0. n=2." | "DHUK is unique per die." (unqualified — it is n=2, and unmeasured at RDP2) |
| "The SE050's OS and GlobalPlatform framework — the layer enforcing our UserID PIN policy — hold a CC EAL6+ certificate for JCOP 4 SE050 v4.7 R2.00.11/R2.03.11. The certificate explicitly does **not** rate cryptographic protocol strength, so it does not cover SCP03-as-deployed." | "Our secure elements are EAL6+ certified." / "SCP03 is certified." |
| "SCP03 has a published game-based security proof (Sabt & Traoré, SSR 2016) for the protocol **as specified**. Our driver's padding, timing and error handling are outside that proof — which is exactly where SCP02's real break lived (a padding oracle)." | "SCP03 is proven secure, so our tunnel is secure." |
| "OPTIGA's Shielded Connection has **no** public security analysis. We model it symbolically against Infineon's public I2C Protocol v2.03 §6." | "Both SE tunnels are formally verified." |
| "An authenticated SE050 admin session can DELETE but cannot READ the user-PIN-gated half — demonstrated on silicon, with a same-session DELETE as the control." | "An attacker with the admin credential cannot extract the seed." (true of *this test*, on *these parts*, under *this policy* — say that) |
| "The device is designed so that a compromise of the MCU still requires defeating both SEs' PIN gates." | "Neither chip alone reveals any bit of the seed." — **strictly true chip-locally, and misleading if read as system-level information-theoretic security. See §4/§5.** |

Three banned constructions, permanently:

1. **"Formally verified" with no object.** Always: verified *what*, against *what model*, up
   to *what bound*, discharged by *what axioms*.
2. **"Certified therefore secure."** EUCLEAK (D4) is the standing refutation.
3. **"Proven" applied to any silicon behaviour.** We never prove silicon. We test it.

---

## §4. Which invariants rest on silicon, and how much of each

The question below is: **what fraction of the invariant's weight is discharged by something
other than an assumption about a die we did not design?** The percentages are **qualitative
judgment, not measurement** — read them as High/Medium/Low. They are written as numbers only
to force a ranking; do not quote them as figures.

| Inv | Statement | Silicon-dependent? | Weight on silicon | The load-bearing assumption |
|---|---|---|---|---|
| **#1** | Dual-chip seed split | **Yes, wholly** | ~90% | That an attacker cannot extract `half_O` from OPTIGA or `half_E` from SE050 by physical means. The XOR is arithmetic (trivially correct); everything protecting it is silicon. |
| **#2** | Hardware PIN gating, three-way consumption, directional boot cross-check | **Yes, wholly** | ~95% | That SE PIN compare + attempt counters are honest and monotone under glitch; that E120 LUC advances; that page-124 flash program is durable and monotone. The *directional reconcile logic* is decidable software (`C`-tier reachable); the *counters* are not. |
| **#3** | E2E encrypted SE tunnels | **Yes** | ~70% | SCP03-as-specified has a proof (D1); OPTIGA Shielded has none (D2). Both rest on the SE implementing its side correctly and on DHUK/BHK secrecy. The 2026-07-07 ML-KEM descope makes **per-device final rotation load-bearing** for the accepted Grover-2⁶⁴ residual — i.e. it moved weight *onto* silicon (DHUK). |
| **#4** | All secrets only in TrustZone secure world | **Yes, wholly** | ~85% | CMSE + SAU/IDAU + GTZC semantics — surface (c), permanently unformalizable. The *pointer-validation* half is genuinely `C`-tier (Kani-proven + Miri-checked `ns_ptr_validate`), which is the ~15%. |
| **#5** | One signature primitive: SPHINCS+C10 | **No** | ~0% | Code and contract property. `K`/`B`-tier. Silicon-independent. |
| **#6** | Bootstrap keys immutable per-wallet | **No** | ~0% | CREATE2 + contract structure. `K`/`B`-tier. |
| **#7** | Per-chain caps monotonic, unresettable | **No** | ~0% | On-chain. `K`-tier (`Invariants.lean:385/855`). |
| **#8** | Stateless slot selection | **No** | ~0% | Firmware structure; decidable. |
| **#9** | Off-chain counter, combined cap | **Partly** | ~40% | The *policy* is decidable software and on-chain-backstopped (`K`). The *durability* of page 123 under crash/torn write/ECC is surface (b). The TLC pilot's finding stands: no per-entry integrity → hardware premise; invariant #9 + the on-chain cap are jointly load-bearing. |

The pattern is stark and worth stating plainly: **invariants #5–#7 are proven (`K`/`B`, with
cites); #8 is decidable firmware structure but carries no proof cite today — decidable is not
proven, and it should either get one or stop being counted as closed. Invariants #1–#4 are
essentially assumed.** Everything the FV stack has actually closed sits on the chain side.
Everything that protects the seed sits on silicon. That asymmetry is
structural, not a work-planning failure — surface (e) has no path, and surface (c) has no
path either. It is the reason the honest headline is a claim about the *wallet contract*,
not about the *device*.

### One precise wart in invariant #1, for the record

Reading `secure/src/dual_se.rs`: OPTIGA is provisioned with `half_O` **and** with
`master_secret = kdf("sphincs-master", full_entropy, 0)` — a value derived from the **whole**
entropy — while SE050 holds `half_E` and `kdf("sphincs-master", half_e, 0)`, derived only
from its own half. The asymmetry is real: **OPTIGA-alone** holds a check function on the
full seed, so extracting OPTIGA alone reduces the seed to a computational search rather than
leaving 2²⁵⁶ equally likely candidates; **SE050-alone** does not.

Do **not** dramatize this. Invariant #1 as written — "Neither chip alone reveals any bit" —
is a **chip-local** statement and it holds strictly: `half_O` alone reveals nothing.
Moreover the regression is **redundant**, because the system was never
information-theoretically secure at the system level anyway: the wallet's `masterPkRoot` is
a **public, on-chain commitment** to the seed (the CREATE2 salt is
`sha256(masterPkSeed‖masterPkRoot)`). Anyone who knows the wallet address and one half can
already mount exactly the same offline search. `master_secret` on OPTIGA only makes each
guess *cheaper* to check than the PBKDF2 + C10 keygen chain would be — a per-guess-cost
regression against a 2²⁵⁶-classical / 2¹²⁸-Grover search, not an independent break.

The honest statement, which belongs in `THREAT_CLAIM_MAP` and in a work-todo row rather than
evaporating here: **the XOR split is computational, not information-theoretic, at the system
level — by construction, because the derived public key is published. Its value is that it
forces an attacker to defeat both SEs' access control, or to do an infeasible offline
search.** That is still the right architecture. It is just not the claim "information-
theoretic split" would license, and that phrase should never be used.

---

## §5. The uncomfortable question: is the XOR split contingent on RDP-2 holding?

**Answer: it depends entirely on the attacker model, and the two answers are opposite. Both
must be stated or the claim is dishonest.**

### First, the facts, separated from the inference

Two **stacked** contingencies, routinely conflated:

1. **Can RDP-2 be downgraded on the U5 at all?** No published RDP break against the STM32U5
   exists. The nearest results: SySS (2025-06) glitched RDP 2→1 on the **STM32L051**
   (Cortex-M0+) and dumped flash via a second glitch on the bootloader's software-enforced
   `READ_MEMORY` RDP check (G12). µ-Glitch (USENIX Sec 2023) **disabled TrustZone-M on the
   STM32L5 — a Cortex-M33 part** — by faulting SAU and the Global TZ Configuration, and
   claims transferability to "conceptionally similar ICs", citing ST's joint L5/U5 TrustZone
   app note. Šimoník (Masaryk, 2025) achieved **76% voltage-glitch bypass of a PIN check on
   the STM32U5A9** — a sibling of our U585 — but on simplified target code, with decoupling
   caps removed, and **it is not an RDP break**. The honest position: **U5 is proven
   glitch-vulnerable at the core level; U5 RDP-2 is not proven breakable.**

   **CORRECTION 2026-07-17 (author-verified, supersedes the survey's G10).** There are **two**
   ST certificates and the earlier read checked the wrong one. The PSA Certified entry's TOE is
   **"STM32U585 TFM" = TF-M v1.3.0**, which we do not run — correctly dismissed. But a
   **silicon-scoped SESIP certificate also exists and it does apply to us**:

   > **SESIP-2400133-01** (TrustCB, issued 2025-05-22, **valid to 2027-03-28**; lab **SGS
   > Brightsight**; **SESIP3 + Physical Attacker Resistance + Software Attacker Resistance:
   > Isolation of Platform**), Security Target **TN1545 Rev 3** (public).
   > **TN1545:728 — *"The platform does not include any firmware component and the implemented
   > hardware is not reprogrammable."*** ⇒ unlike the TF-M cert, the TOE is the die itself.

   This is genuine, correctly-scoped `T`-tier evidence for RDP-2 and it is **better than the
   absence argument §5 previously leaned on** — the Physical Attacker Resistance package
   (TN1545: redundancy checks against RDP/HDP deconfiguration by physical tampering or
   perturbation; transient-perturbation detection in SAES/PKA) was evaluated **at RDP-2**.
   Three caveats keep it from being more than `T`:

   1. **It pins a die revision we never check.** TN1545 fixes **REV_ID `0x3003` (rev U)** at
      `0xE004_4002`. We probe **DEV_ID `0x482` only** (`docs/security/production-security.md`,
      `docs/security/threat-model.md`). A cert for rev U says nothing about the rev X/W parts on
      the bench. **Add the REV_ID check and record our dies' revisions.**
   2. **We deliberately ship OUTSIDE the certified configuration** — see the OEM2KEY deviation
      below. The evaluated config is not ours.
   3. **EUCLEAK's lesson applies unchanged**: a lab evaluation is bounded expert effort, not a
      proof. ~80 evaluations at the highest attack-potential rating missed a 14-year defect.

   **The OEM2KEY deviation — name it, do not inherit silently.** TN1545:912 —
   *"In the certified configuration, the Integrator allows the platform to regress to RDP Level 1
   when the TOE secret **OEM2KEY** is successfully provisioned, and the **OEM2LOCK** option bit is
   set."* TN1545:921 — *"If the Integrator sets RDP to Level 2 without programming the OEM2KEY the
   product is locked, and it is not possible to change the RDP level."* **That locked state is
   exactly what we mandate**: `shared/src/lockdown.rs:99-104` — *"A shipped unit must have NO OEM
   key provisioned — otherwise a transit attacker could pre-plant an OEM2 password enabling a
   later RDP-2 → RDP-1 regression"* — enforced by `oem_locks_absent()`. So **we are deliberately
   stricter than the evaluated configuration, for a documented threat-model reason** (and the
   cert's "field return of platform" SFR correspondingly does not hold for us — no RMA path).
   This is a *good* posture and a *bad* thing to leave implicit: the certificate's claims were
   established for a configuration that permits the regression we forbid. Record it as a named
   deviation, not as inherited assurance.

2. **If RDP-2 were downgraded to RDP-1, would DHUK still be usable?** **We do not know, and
   it flips the answer.** The empirical record is n=2 boards at RDP0 (shared constant) and
   RDP1 (distinct per die). **No board in this project has ever been at RDP-2** — an RDP-2
   part cannot be regressed, which is the entire point. ST's documented behaviour ("SAES will
   use a constant value instead of DHUK at RDP0. The real DHUK activates at RDP ≥ 1") implies
   DHUK(RDP1) == DHUK(RDP2), and `saes.rs:338` records it that way. CLAUDE.md's shipping
   model says "only then [at RDP-2] is the per-die DHUK **final**", which reads the other
   way. Both readings are consistent with everything measured. **Register this as a named,
   testable open assumption:**

   > **HW-ASSUME-DHUK-RDP12.** `SAES-CMAC(DHUK, ·)` produces identical output at RDP-1 and
   > RDP-2 on the same die. **Status: unmeasured. Source: ST prose only. Falsifying test:
   > fingerprint one sacrificial die at RDP-1, self-lock to RDP-2, fingerprint again;
   > divergence falsifies. Cost: one part, one shot, irreversible.**
   > **UPDATE 2026-10-27:** under the owner direction to install DHUK(RDP-1)-derived final SE keys at the
   > factory (`docs/security/user-device-verification.md` § USB path), FALSE would be **fatal**: the RDP-2
   > self-lock would cut every unit off from its own SEs. That turns this into a hard prerequisite.
   > **Consequence if FALSE (good for us):** a 2→1 downgrade is *fail-secure* for SE
   > pairing — the attacker computes `f(DHUK_RDP1, salt) ≠ PBS`, unwraps the page-126 BHK to
   > garbage, and both tunnels stay shut. **Do not over-read this consolation: it protects
   > only against the RDP-*downgrade* route. A runtime TrustZone-M disable at RDP-2 (the
   > µ-Glitch shape, no downgrade at all) uses DHUK(RDP-2) directly and is unaffected by this
   > assumption either way.**
   > **Consequence if TRUE (assume this):** the downgrade preserves the derivation and the
   > trace below applies.

   Note the first-boot ceremony is self-consistent either way — it locks RDP-2 in Phase A
   and wraps/derives in Phase B, both at RDP-2 — so no functional test will ever surface
   this. **Only a deliberate probe can.** This is the archetype of an assumption whose
   falsifying test costs a part and can be run exactly once per part.

   The RDP→0 path is separately and structurally fail-secure: it mass-erases flash (taking
   pages 123–127, the salt, and the wrapped BHK) **and** collapses DHUK to ST's shared
   constant `117d822a62a50830`. The readout path that grants full flash access is exactly
   the path that destroys the material needed to talk to the SEs.

### Trace: assume RDP-2 falls to RDP-1 with secure-world code execution (worst case)

Grant the attacker everything: 2→1 downgrade, a second glitch or a µ-Glitch-class TrustZone
bypass, arbitrary code with SAES access, and HW-ASSUME-DHUK-RDP12 true.

They obtain: the firmware image; page 126 (DHUK-wrapped BHK) and page 127 (TRNG salt); the
page-123/124 counters; a `SAES-CMAC(DHUK, ·)` oracle **on that die only** — DHUK bytes never
enter CPU-visible memory and cannot be exfiltrated, replayed on another die, or emulated.
From the oracle: the OPTIGA final PBS, hence a Shielded session; the unwrapped BHK, hence
SE050 SCP03 + admin.

They do **not** obtain `half_O` or `half_E`. Those live in the SEs behind SE-silicon PIN
gating. **The attacker has become a legitimate MCU and nothing more.** What remains standing:

- The SE050 UserID PIN gate, enforced in SE silicon: ~10 attempts before auto-brick.
- The OPTIGA E120 LUC: a 32-lifetime-attempt anti-extraction backstop.
- The empirically validated read-deny: with the admin credential (recoverable from a DHUK
  leak by construction), the attacker can **DELETE** the half — a DoS/brick — but **cannot
  READ** it (`SW=0x6986`, `make se050-admin-extract-attempt-e2e`, validated 2026-05-11 with
  a same-session DELETE as the control).
- Therefore: ~10 guesses against a 6-digit PIN ⇒ ~1-in-10⁵ to extract; otherwise the wallet
  bricks. Or an offline 2²⁵⁶-classical / 2¹²⁸-Grover search against the public on-chain key.

**So for a smash-and-grab attacker (stolen device, no return visit): the XOR split's value is
NOT contingent on RDP-2. It is precisely the layer designed to survive an MCU compromise, and
it does. This is the architecture working as intended, and it is the strongest thing this
document says.**

### The other attacker model, where the honest answer is ugly

**Evil-maid / supply-chain interception.** The attacker has the device *before the user does*
or *between uses*, and the user comes back. They do not need the seed. They downgrade RDP,
replace the firmware with a backdoored signer that behaves normally, restore RDP-2 (or not),
and return the device. The user types the PIN into the attacker's code. The attacker's code
holds a valid MCU identity, opens both tunnels, passes both PIN gates with the *correct* PIN,
reconstructs the entropy, and exfiltrates it — or simply signs a drain transaction while
displaying the user's intended one.

**The XOR split provides exactly zero protection here.** Both halves are handed over on
demand, by design, to whatever code runs on the MCU. This is precisely the shape of Ledger
Donjon's Trezor Safe 3 result: they did not break the OPTIGA; they read the MCU-flash-resident
pairing secret and reprogrammed the chip, "preserving the full impression of an authentic
device", with attestation fully intact (D5). Their structural point applies verbatim to any
SE-attestation scheme: **it authenticates the SE, not the microcontroller, and does not
attest to what software is running on the latter.**

PQSigner is structurally better than the Safe 3 on the specific mechanism — there is no
factory-held final pairing secret and no plaintext static secret in MCU flash; the PBS is
DHUK-derived per die and page 126 holds only a wrapped blob. That raises the bar from "read
32 bytes of flash" to "obtain code execution on the die". It does not change the conclusion.

Against evil-maid, the **only** defences are:

1. **RDP-2 holding** (which is a bare assumption about ST silicon that we cannot verify, on
   a family with a published TrustZone-M glitch on its M33 sibling and a 76% PIN-glitch on
   its own sibling), and
2. **A measured boot the user actually verifies** — the 8-word BIP-39 fingerprint. And here
   the honest statement is uncomfortable: **the FSBL is explicitly "not yet an immutable
   production trust root"** (its geometry, WRP/option-byte ceremony, link/resource gates and
   silicon receipts are all open), the secure-world row is advisory, and the whole control
   depends on a human comparing eight words against a value they memorised. If the attacker
   controls the FSBL, they control the fingerprint.

### Verdict

> **The dual-SE XOR split is not contingent on RDP-2 for its designed purpose — surviving an
> MCU compromise by a device thief — and it demonstrably delivers there.**
>
> **It is entirely contingent on RDP-2 (plus an immutable measured boot that the user
> actually checks) against an attacker who gets the device, modifies it, and gives it back.
> Against that attacker the split is worth nothing, because the user willingly supplies the
> one secret it is gated on.**
>
> **And RDP-2 is a bare, unverifiable assumption about ST silicon** — held today by the
> absence of a published U5 RDP break, on a family with a *proven* core-level glitch
> vulnerability and a *proven* TrustZone-M disable on its M33 sibling. It is the single
> highest-leverage unverifiable premise in the entire design, and it protects the attack
> class that a hardware wallet is most often actually subjected to.

---

## §6. Named open assumptions this document registers

**These rows are now a machine-checked artifact, not this table.** They live in
[`contracts/verification/docs/HW_ASSUMPTIONS.json`](../../contracts/verification/docs/HW_ASSUMPTIONS.json),
gated by `make -C contracts/verification verify-hw-assumptions` (wired into `ci.yml`'s
`invariant-gates`, which has no path filter — see the note there for why *not* `lean-fv.yml`).

The gate cannot check the premises; there is no `#print axioms` for a die. It checks the
ledger's **hygiene**, which is the part that rots: every evidence anchor still resolves in the
file it names (so a row cannot quietly go stale when code moves out from under it); any row
claiming a runnable falsifying test names a **real** make-target (a claimed test that cannot be
run reads as evidence and is not); and — the load-bearing one, the only transferable half of
OpenTitan's bidirectional RTL↔Hjson countermeasure cross-check, since we can never FPV our
silicon and they designed theirs — **the set of `HW-ASSUME` ids in the ledger is exactly the set
cited across the tree.** A citation with no row is an unledgered assumption; a row nobody cites
is dead weight. Six self-test mutations assert the gate bites.

Current state: **12 rows — 5 `bare-tcb`, 2 `vendor-doc`, 3 `silicon-tested`, 1 `cert-cited`,
1 `code-enforced`; only 3 have a runnable falsifying test.** That ratio is the finding, and it
is now a number that CI recomputes rather than a claim in a document.

The table below is the human-readable snapshot. Promote each row to `docs/work-todo.md` and to a
`THREAT_CLAIM_MAP` row; do not let them evaporate here.

| Id | Assumption | Status | Falsifying test | Cost |
|---|---|---|---|---|
| `HW-ASSUME-DHUK-RDP12` | `SAES-CMAC(DHUK,·)` identical at RDP-1 and RDP-2 on one die | unmeasured; ST prose only | fingerprint at RDP-1 → self-lock RDP-2 → fingerprint | 1 sacrificial part, one shot |
| `HW-ASSUME-QW-ATOMIC` | A quad-word program is old-or-new under power loss; a torn QW is read-back-detectable or ECC-faults | asserted in `flash.rs`; **contradicted by `hal/src/lib.rs`**; untested | power-cut rig, swept sub-µs offsets, classify readback | rig + sacrificial parts |
| `HW-ASSUME-OTP-ONEWAY` | An OTP QW programmed once can never be re-driven; a half-burn is detectable | prose; ST thread (C-10) settles nothing. **D4 shows the half-burn is currently NOT detectable in our code** | half-program a QW, attempt completion, record PGSERR + readback | **~21 shots on a still-usable board — NOT a sacrificial part** (corrected: `otp.rs:32` maps `176..512` = 336 B = **21 unallocated quad-words**). 2-3 d |
| `HW-ASSUME-DHUK-UNIQUE` | DHUK is per-die and unextractable | per-die: validated n=2 at RDP1. Unextractable: bare-TCB | more boards; decap is out of scope | low / N/A |
| `HW-ASSUME-CMSE-SAU` | CMSE/SAU/IDAU/GTZC behave per RM0456 + DDI0553 | `gtzc-enforcement-hw` 7/7 (positive test only) | extend the enforcement test per attribution rule; **no ∀ is reachable** | low |
| `HW-ASSUME-TRNG-ENTROPY` | STM32U585 TRNG meets SP 800-90B in our `RNG_CR` config | **no ESV cert names U585**; E11 covers "STM32U5x" but has no PUD; **no health tests implemented** | self-run NIST EA v1.1.8 over our samples; read `RNG_VERR` to match E11's Rev B | days |
| `HW-ASSUME-SE050-CERT-VERSION` | Our SE050 is JCOP 4 v4.7 R2.00.11/R2.03.11 | **unconfirmed** — the cert covers nothing else | read the applet/config version off the part | hours |
| `HW-ASSUME-RDP2` | RDP-2 resists voltage glitching on the U5 | **`T` — SESIP-2400133-01 / TN1545 Rev 3, SESIP3 + Physical Attacker Resistance, SGS Brightsight, evaluated at RDP-2, valid to 2027-03-28** — *but* pinned to **rev U (REV_ID `0x3003`)** which we do not check, and evaluated in the OEM2KEY config we deliberately do not ship. Independently: no published U5 RDP break; U5 core-level glitch **proven**; M33-sibling TrustZone-M disable **proven** | offensive FI campaign on sacrificial parts | high |
| `HW-ASSUME-REV-U` | Our dies are rev U (REV_ID `0x3003`), the only revision SESIP-2400133-01 covers | **unchecked** — we probe DEV_ID `0x482` only | read `0xE004_4002` on every bench die; add a boot/production probe | hours |
| `HW-ASSUME-OEM2-ABSENT` | No OEM2KEY is provisioned on a shipped unit (`lockdown.rs:99`, `oem_locks_absent()`) — **stricter than, and outside, the certified configuration** | design-enforced; **not** covered by the SESIP evaluation | probe OEM1LOCK/OEM2LOCK on every unit at production test; and probe whether any CubeIDE-touched bench board carries ST's default OEM2 password | low |
| `HW-ASSUME-PUTKEY-ATOMIC` | An SE050 PUT KEY (`P1=0x0B`, `P2=0x81`, three key blocks ENC‖MAC‖DEK, in-place KVN) is **all-or-nothing** across the SE's NVM commit | **bare-TCB, and load-bearing.** See below — the whole first-boot rotation reduces to it | drive PUT KEY, cut power mid-APDU, then probe ENC/MAC **and DEK independently**; a die with final ENC/MAC but transport DEK falsifies it | rig + sacrificial parts |
| `HW-ASSUME-SE-INTERNALS` | OPTIGA/SE050 behave per datasheet inside the die | **permanently bare-TCB**; certificates do not cover the applet/OS behaviour we rely on | none exists — silicon-E2E per property only | N/A |

**Why `HW-ASSUME-PUTKEY-ATOMIC` is the worked example this whole document argues for.** From
`secure/src/scp03_logic.rs:231`, all three key blocks ride **one** PUT KEY APDU replacing KVN `0x0B`
**in place**; the resume probe (`se050/mod.rs:375`) establishes SCP03 with `final_enc, final_mac` and
therefore proves **ENC + MAC only** — the DEK is never probed — and the KVN is `0x0B` before *and*
after, so it cannot disambiguate transport from final. Therefore:

> If PUT KEY is atomic, the probe is sound: one APDU, so ENC+MAC final ⟹ all three final.
> If it is not, then *ENC+MAC-final-with-DEK-still-transport* is reachable; the probe reports
> "already rotated → resume"; `run` commits `DONE_SE050_KEYS`; and the device proceeds with a mixed
> keyset whose DEK — the key that wraps all future key blocks — is still derived from the
> **factory-known** transport root.

That is the payoff of the method, stated exactly. Formalisation does **not** verify the SE050. It
reduces the crash-safety of a multi-thousand-line rotation path to **one sentence about silicon that
a power-cut rig can try to falsify** — and it tells you precisely which two values to probe
independently. Note this is a *sharpening* of CLAUDE.md's already-named "atomic durable old/new/KVN
recovery proof" gate, not a new discovery.

### Non-assumption follow-ups surfaced here (promote, do not lose)

1. **Wire the HAL seam.** Not merely a Kani/Miri enabler — it is what makes the contract
   falsifiable and would surface the live `hal` vs `flash.rs` ECC contradiction as a review
   event instead of an invisible unsound axiom.
2. **Fix or waive the SP 800-90B obligation** in `hal/src/lib.rs`. Implement the health tests
   (decidable software) or delete the obligation. Today the contract asserts something the
   code does not do, and the code feeds an irreversible OTP burn.
3. **Vendor the `stm32-rs` patched U585 SVD and diff it** against every hand-transcribed base
   address in `secure/src/hw/*`. Hours of work; 3-for-3 against our transcription history.
   Scope: does not cover SAU/MPU/NVIC/SCB/UID/OTP, and encodes layout only.
4. **Kani `t1oi2c`'s `crc16`/`build_frame`/`validate_frame`.** Pure functions; no seam work.
5. **Re-derive `optiga_shield_handshake.pv` from Infineon I2C Protocol v2.03 §6** rather than
   from `shield.rs`. **DONE 2026-07-17** (`9ec109ad`): `optiga_shield_handshake_vendor.pv`,
   re-derived from the vendor reference implementation — it caught the driver-derived model's
   invented host nonce (inj-agreement TRUE there, FALSE vendor-side; SE5 / OP17-2).
6. **`shipping-thumb-ct-binsec`: the inventory's framing is still wrong, but do NOT propagate
   the "BINSEC decodes Thumb fine, only CMSE fails" correction — it does not reproduce.**
   *(Author-run on this box, 2026-07-17, superseding the workflow's G1 claim.)* The survey
   asserted BINSEC decodes plain Thumb-2 and emits `unimplemented` only on `sg`/`bxns`/`tt`,
   implying the real boundary is CMSE rather than thumbv8m. Reproducing it against the same
   probe ELF (`plain: adds/eors/bx`; `cmse_sg: sg/nop/bxns`; `cmse_tt: tta/ttat/bx`, built
   `.arch armv8-m.main`):
   - BINSEC **does** expose `-arm-supported-modes {both|thumb|arm}` (default `arm`). So the
     2026-06 SOTA doc's flat "there is no ARMv8-M / Cortex-M / M-profile decoder" is imprecise
     about the *option surface* — a thumb mode exists.
   - But in `thumb` mode BINSEC emits `unimplemented` **uniformly — including on the plain
     `adds`/`eors`/`bx` function** — at every entry tried (`0x0/0x1`, `0x6/0x7`, `0xe/0xf`),
     then dies with `Fatal error: … disasm_core.ml … Assertion failed`. The plain and CMSE
     cases are **indistinguishable**. In `arm`/`both` mode it reads the Thumb bytes as ARM and
     reports "Unknown ARM instruction".
   - **Therefore the SOTA doc's operational verdict (BINSEC NO-GO for our thumbv8m ELF)
     stands, and the survey's refinement is withdrawn.** The inventory row is still wrong —
     but for the original reason, not a CMSE-specific one.
   - Untouched and still open: whether `cargo-checkct` uses a BINSEC frontend at all (it may
     be an independent engine, in which case BINSEC's decoder has no bearing on `make checkct`),
     and whether `make checkct` actually runs green here. **Verify both before editing the
     other two docs.** Nothing here is propagated yet, by design.
7. **Fix the OPTIGA CC citation** — V4-2019 expired 2024-12-17; cite V7-2024, and scope it to
   the IC platform, never the applet.
8. **Make `tla2tools.jar` durable.**
9. **Give TAMP a silicon test.** `tamp-wipe` is forced ON for shipping dual-SE images, has
   never run on silicon, and its driver was based at the wrong address for an unknown period
   precisely because nothing exercised it.
10. **Stop collapsing `Inconclusive` into `Rejected` at the three probe sites** (§2.1
    corollary). Introduce a probe result that can say "I don't know", and make the
    don't-know branch retry read-only probes rather than fall through to a mutation. This is
    a small, local, high-value change and it is a prerequisite for the first-boot ceremony's
    named production gate. Cheapest first step: the three `.is_ok()` / `unwrap_or(false)`
    call sites are the entire surface.
11. **Model the T=1'/IFX-I2C framing FSM — the layer every PIN attempt and every PUT KEY
    crosses, and the only one still unmodelled.** The SCP03/Shielded *crypto* is modelled;
    the framing that carries it is not. `se050/t1oi2c.rs` is a textbook **alternating-bit
    protocol**: `PCB_I_SEQ = 0x40` with `ns`/`nr` that "toggle 0/1", R-block acks,
    `MAX_WTX_RETRIES = 500`. That 1-bit sequence number is precisely the mechanism by which a
    lost response could cause a **duplicate apply** of an already-executed command — i.e. a
    double-charged PIN attempt or a re-issued PUT KEY. TLA+/TLC is installed and already
    piloted; this is the classic TLC target and the literature offers nothing to reuse (D9).
12. **Bind the GTZC receipt to the shipping feature combo.** `make gtzc-enforcement-hw` builds
    with `mock-se,ui-semihosting,debug-log,e2e-test,stm32u585,otp-hardcoded-master-key` — *not*
    the shipping combo — while `sau.rs` carries 12 `cfg(feature)` gates including
    `spi1-arduino` inside the peripheral security config (sau.rs:281,387). So the register
    image is feature-conditional and the receipt is taken on a build we do not ship, with
    nothing checking the two agree. Emit the SAU/GTZC register image as a build artifact per
    feature combo and gate that the production image matches the tested one. This is the
    concrete, cheap instance that justifies roadmap §P1.9's "exact production register images
    and feature combinations" — and it composes with the existing compile-time interval
    assert at `sau.rs:58-64` (proto NS windows ⊆ SAU NS regions), which is already the right
    kernel and simply needs extending.

---

## §7. The one-paragraph version

PQSigner's chain-side invariants (#5–#8) are proven. Its seed-side invariants (#1–#4) are
assumed, and will be assumed forever, because they rest on silicon nobody outside ST,
Infineon and NXP can inspect. That is the industry ceiling, not a local failure — the
reference ARMv8-M secure firmware has no isolation proof either, and ~80 evaluations at the
highest CC attack-potential rating on earth missed a non-constant-time modular inversion in
the Infineon cryptolib for 14 years (demonstrated on a YubiKey; NinjaLab reports it extends
to our OPTIGA part, on an ECDSA path invariant #5 means we never invoke). What we can
honestly do is: write each hardware contract down as
an explicit artifact; wire the seam so code-vs-contract drift is detectable; prove the
decidable logic against the contract with the tools already installed; and validate each
contract with a silicon test that can fail. What we must never do is model a device we cannot
inspect and call the resulting agreement a proof. The one thing that should keep us up at
night is not in the FV backlog at all: **against an attacker who takes the device, modifies
it, and returns it, the dual-SE split is worth nothing, and everything rests on RDP-2 and on
eight words the user has to actually check — on a boot chain we have not yet made
immutable.**

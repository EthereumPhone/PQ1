# Production Security — synthesis of 2026-04-14 research round

This document consolidates findings from 4 parallel AI deep-research
sessions (bundles A, B, C, D — prompt E has not yet run) into a single
actionable reference. It is *not* the code; it is the distilled plan.
Implementation tasks track in `docs/work-todo.md` items #18-22.

Raw research results live under `docs/research-bundles/results/`. Each
finding below cites the responsible bundle plus any verification caveats.

**Scope of this doc:** threats, mitigations, and architectural decisions
that the research round surfaced. For the staged brownout-hardening
rollout see `docs/brownout-hardening.md`. For the SE050 PIN-lockout
factory-reset design see `docs/se050-factory-reset.md`.

---

## 1. Top 5 critical findings (do these before anything else)

1. **SLH-DSA verify-after-sign is inadequate**. Current code assumes
   signing the blob, re-verifying, and failing closed is enough. Per
   RFC 9814 and Genêt (TCHES 2023) a single fault during SLH-DSA
   signing produces a signature that often still verifies. Double-
   compute on disjoint SRAM regions + constant-time compare is the
   only defence. Cost: ~6 s per signature at SHA2-128f — acceptable.
   *Source: bundle A.*

2. **We are currently signing deterministically (OptRand = 0)**. This
   enables PRF(SK.seed) recovery via horizontal DPA on unprotected
   Cortex-M33 in 1-10 traces against Saarinen's 2024 TVLA baseline.
   Every signature must draw a fresh 16 B (128f) / 24 B (192f) from
   STM32 TRNG as OptRand. One-line fix with massive SCA impact.
   *Source: bundle C.*

3. **NXP SE050 SCP03 keys are the published factory defaults**. Until
   we rotate them per-device, anyone with a logic analyzer + the
   Global Platform default key list can decrypt our I2C bus. The
   research provides the published key values from AN12436 and the
   exact PUT KEY rotation sequence. Must execute at factory per
   device. *Source: bundle B.*

4. **USB path has two concrete silicon-errata bugs** we have not
   addressed: DWC2 TxFIFO write atomicity (ES0499 §2.26.x) and ZLP
   race leaking stale FIFO data. The latter is a **data-leak** from
   the USB controller's own SRAM under specific SNAK/CNAK/EPENA
   timing. Both fixable in driver code. *Source: bundle D.*

5. **Masaryk University 2024/2025 thesis demonstrates 76% PIN-glitch
   bypass on STM32U5A9** — same Cortex-M33 family as our U585. Factory
   defaults (BOR=0, IWDG off, ECC off, TAMP off) are the attack
   surface. Our Stage 1 brownout work partially addresses this;
   Stage 2 needs to land before any talk of production. *Source:
   bundle A + C.*

## 2. Per-topic summary

### 2.1 Fault injection (bundle A → todo #18)

**Threat model**: voltage glitch, EMFI, laser FI, Rowhammer. The U5 has
no public glitch bypass yet but sits on the same core as the demonstrated
Masaryk attack; presumed vulnerable until proven otherwise. We can't
rely on silicon.

**Mandatory mitigations**:

- **SLH-DSA double-compute** with disjoint SRAM regions for the two
  computations. Compare via constant-time compare; release only on
  match. Verify-after-sign does NOT substitute.
- **FihInt complement-storage** (0x1AAA_AAAA / 0x1555_5555 magic
  constants XOR'd with a mask) for every security-critical boolean:
  `pin_verified`, `blob_cached`, `match_ok`, signature-release gate.
- **PIN lockout fail-in**: current code is `if remaining == 0, wipe`
  — single glitch can skip. Invert to `if remaining != 0, continue;
  else wipe` so a skipped branch fails safe (wipes).
- **Volatile reads only** on security-critical values. `core::ptr::
  read_volatile` has a formal LLVM IR guarantee; `core::hint::
  black_box` explicitly has "no guarantees for cryptographic purposes"
  per Rust stdlib docs.
- **Hardware supervisor config** (overlaps with todo #21):
  - BOR_LEV = 3 or 4 in option bytes
  - IWDG_SW = 0 (hardware watchdog, 100-500 ms)
  - SRAM2_ECC = 1, SRAM3_ECC = 1 (ECC is OFF by default on U5)
  - SRAM2_RST = 0 (auto-erase on reset)
  - PVD enabled at highest threshold below 3.3 V
  - TAMP ITAMP1-3 enabled with automatic backup-domain erasure
  - CSS on HSE

**Strongly recommended**:

- Control-flow-integrity step counters (increment before critical
  call, decrement after, fail on mismatch).
- Random delays from TRNG before critical comparisons.
- Redundant volatile reads (2-3×) with OR-based fail-in logic.

**Cost**: ~6 s per signature (double-compute), +~5 instructions per
protected boolean (FihInt). Acceptable for a wallet UX.

### 2.2 Production key management (bundle B → todo #20)

**Big picture**: Trezor Safe 5 uses single-SE + binding; we extend to
dual-SE + signed binding record + OTP anchor + monotonic counter.

**Factory provisioning — two-stage RDP flow**:

Stage 1 at RDP0 (debug attached):
1. Read all 3 UIDs (STM32 at `0x0BFA_0700`, SE050 via GetInfo, OPTIGA
   OID `0xE0C2`).
2. Derive per-device SCP03 keys: `enc = AES_CMAC(FMK, "SCP03-ENC" ||
   SE050_UID)`, similarly for MAC and DEK.
3. Rotate SE050 SCP03 via PUT KEY (INS=0xD8) from KVN=0x0B → KVN=0x11.
4. Provision OPTIGA PBS (TRNG ⊕ STM32 RNG, 64 bytes). Apply metadata
   lock: `LcsO=Operational`, `Read=Never`, `Change=Conf(0xE140)`.
   **Irreversible.**
5. Create binding record, ECDSA-P256 sign with provisioner key.
6. Store binding 3× (STM32 flash wrapped, SE050 object 0x10000001,
   OPTIGA OID 0xF1D1). SHA-256 anchor → OTP bytes 6-37.
7. Burn OTP provisioned flag.

Stage 2 at RDP1+ (after reset):
8. Wrap MasterKey with real DHUK via SAES. **DHUK at RDP0 is a known
   constant**; wrapping there achieves nothing.
9. Two-level wrap: DHUK-ECB(MasterKey) → HKDF(MasterKey, purpose) →
   AES-GCM(per-use key, SCP03/PBS/binding payload). Single-level ECB
   has no integrity.
10. Burn RDP Level 2 (permanent, irreversible).

**Boot-time anti-swap**:
- Read all 3 UIDs, verify signature, verify OTP anchor hash.
- Mismatch → erase Key Pages + wipe SE050 + permanent brick.
- Boot overhead ~500 ms – 1.2 s (acceptable).

**Cited NXP default SCP03 keys** (from AN12436, per research):
```
ENC = 85 2B 59 62 E9 CC E5 D0 BE 74 6B 83 3B CC 62 87
MAC = DB 0A A3 19 A4 08 69 6C 8E 10 7A B4 E3 C2 6B 47
DEK = 4C 2F 75 C6 A2 78 A4 AE E5 C9 AF 7C 50 EE A8 0C
```

⚠ **Verify against current AN12436** before using. Research cited
"Rev 2.4" which is unverified and may be wrong. Same caveat for SAES
register bit fields (`KEYSEL`, `KMOD`, `KEYSIZE`) — the research author
explicitly flagged those as uncertain; cross-check with CMSIS header
`stm32u585xx.h` before writing SAES code.

**Firmware upgrade path**: blob magic 0x504B4559 + version byte +
HKDF label. On boot, if `blob.version < current`, re-wrap with new
HKDF label and flash new format. STM32U585 DHUK does not rotate per
firmware, unlike STM32H5, so migration is simple.

**Anti-rollback**: OPTIGA monotonic counter at OID `0xF1E0`,
Conf(0xE140)-protected. Reject firmware with `fw_version < counter`.

### 2.3 Side-channel (bundle C → todo #18)

**Threat surface**: PRF(SK.seed) leaks the master secret via horizontal
DPA on unprotected Cortex-M33. Saarinen's CRYPTO 2024 SLotH paper
reports t-stat = 24.5 at 1000 traces — catastrophic leakage.

**Mitigations that stack**:

- **OptRand mandatory** (see section 1). Breaks determinism,
  prevents chosen-message PRF recovery.
- **Signing rate limit + 2^16 rotation**: 1 sig/sec, 500/day, hard
  rotate after 2^16 signatures per key. ERC-4337 wallets unlikely to
  exceed 100 sigs/day.
- **WOTS chain + FORS tree shuffling** via Fisher-Yates, TRNG-seeded.
  Negligible perf cost (<2%); breaks trace alignment for profiled DPA.
- **Zeroize + DSB barrier** after every signing call. Use `zeroize`
  crate; follow with `core::sync::atomic::compiler_fence(SeqCst)` +
  `__dsb(0xF)` to prevent SRAM residue.
- **GTZC peripheral lockdown**: lock HASH / RNG / SAES to secure
  privileged mode so non-secure world cannot DMA-snoop (BUSted!
  style attacks). Affects every NSC gateway entry.

**Architectural decision pending — SHAKE vs SHA2-256 parameter set**:

| | SLH-DSA-SHA2 | SLH-DSA-SHAKE |
|---|---|---|
| HASH peripheral support | Yes (not DPA-resistant per UM3370) | No (software SHAKE required) |
| Masking cost | 3-5× (inefficient on Cortex-M33) | 1.5-2× (cleaner) |
| PRF-tree (Fluhrer 2024) | No | Yes (≤5 contexts per intermediate, 1.7× overhead) |
| Backward compat with on-chain verifier | Tied to current contract | Requires contract change |

Recommendation: evaluate SHAKE migration before Stage 2 implementation.
If on-chain verifier can be parameterised, SHAKE is the materially-
stronger SCA posture.

**HASH peripheral**: **provides zero DPA protection** per UM3370.
Useful for performance (~66 cycles/block) and timing-channel elimination
only. Software countermeasures remain mandatory.

**Caveats on numerical claims**: the research cites "SLotH" and
"SLasH-DSA 2025" papers with specific trace-count numbers. SLotH
(CRYPTO 2024) is a known title; exact TVLA numbers should be verified
against the paper. SLasH-DSA (2025) is future-dated relative to the
research AI's knowledge cutoff and **may be hallucinated** — do not
cite in commit messages or user-facing docs without verifying.

### 2.4 USB hardening (bundle D → todo #19)

**Threat surface**: only external interface; primary remote attack
vector. Host computer is untrusted by design.

**DWC2 silicon bugs (STM32U5 errata ES0499)**:

- **§2.26.x TxFIFO write atomicity**: CPU must not access any other
  endpoint's CSR between successive 32-bit pushes to one TxFIFO.
  Violation corrupts `DIEPTSIZx.XFRSIZ` to zero. Mitigation: single-
  packet transfers (`DIEPTSIZ.XFRSIZ = DIEPCTL.MPSIZ`); no interleaving
  in ISR.
- **§2.26.x ZLP race**: under specific SNAK/CNAK/EPENA timing the
  controller sends a stale TX-FIFO data packet instead of a ZLP,
  **leaking data from a different session**. Mitigation: enforce
  AHB-cycle delays in the SNAK/CNAK/EPENA sequence per errata; flush
  all FIFOs on USB reset via `GRSTCTL.RXFFLSH | GRSTCTL.TXFFLSH`
  with TXFNUM=0x10.

⚠ Research cited exact §2.26.3 and §2.26.2 section numbers. These are
**plausible but unverified** — confirm against the actual ES0499 PDF
before citing in code comments. Treat the concrete advice (sequence
SNAK/CNAK/EPENA, flush FIFOs on reset, atomic TxFIFO writes) as sound
regardless of exact section numbering.

**USB stack hardening patterns**:

- **FI-resistant `min()` everywhere a control-transfer length is
  clamped**. Pattern:
  ```rust
  fn fi_min(a: usize, b: usize) -> usize {
      let r = core::cmp::min(a, b);
      if r > a || r > b {
          return if a < b { a } else { b };
      }
      r
  }
  ```
  Defeats Colin O'Flynn USENIX WOOT 2019 EMFI-on-branch attack.
  Post-transfer verification: assert `DIEPTSIZ.XFRSIZ` did not exceed
  declared length.
- **Bounded APDU reassembly**: enforce `4 ≤ declared_len ≤ 4096` at
  seq=0; 5 s timeout with buffer scrub; abort if seq=0 arrives
  mid-reassembly (sets anomaly counter for diagnostics).
- **HID OUT rate limiter**: token bucket, ~200 reports/sec sustained,
  bucket 64. NAK endpoint when empty.
- **APDU CLA/INS allowlist** at non-secure *before* any NSC gateway
  call. Reject malformed APDUs before they cross the trust boundary.
- **Response-buffer locking** for 17,088-byte SLH-DSA signatures.
  Chunked via ISO 7816 `SW=0x61xx` (GET_RESPONSE), 30 s timeout,
  scrub on anything other than GET_RESPONSE arriving.

**Runtime config**:
- `OTG_GUSBCFG.FDMOD = 1` (device-only).
- `OTG_GINTMSK`: disable SOFM (timing side-channel), MMISM (OTG),
  PRTIM (host). Enable WUIM / OEPINTM / IEPINTM / ENUMDNEM / USBRSTM
  / USBSUSPM / RXFLVLM.
- FIFO sizing per RM0456 formula with ≥30% safety margin.
- IWDG 2 s timeout, kicked per USB transaction.

**NSC gateway hygiene** (every command):
1. `cmse_check_address_range` on every NS pointer.
2. Copy-in to secure SRAM (TOCTOU defense).
3. Process secure copy, never trust original.
4. Copy-out result if needed.
5. Clear all registers before BXNS return.

**OTG_FS architectural advantage**: no DMA engine. All USB data is
CPU-mediated → TrustZone/GTZC memory protections apply to every byte.
Do NOT migrate to OTG_HS without re-doing the threat analysis — HS has
DMA and loses this property.

⚠ **Hallucination flagged**: the research cites `CVE-2026-4179` for a
"Zephyr STM32 USB device driver infinite loop." No such CVE exists in
the National Vulnerability Database as of the research cutoff — the
format is right but the ID is fabricated. Do **not** reference this
CVE in code comments or public docs. The structural advice (IWDG
timeout, bounded reassembly, rate limiter) stands regardless.

### 2.5 Supply-chain attestation (bundle E → not yet run)

Prompt E exists as `docs/research-bundles/E-supply-chain.md` but has
not been run through deep research yet. When run, findings fold into
todo #22 and potentially update item #20 (binding record + boot-time
anti-swap design may need revision).

## 3. Hallucination + verification log

The research-round prompts told the AI to cite primary sources and
say "I don't know" rather than guess. Across the 4 responses, here's
what we flagged as needing verification *before* committing to code:

| Claim | Source | Status | Action |
|---|---|---|---|
| `CVE-2026-4179` (Zephyr STM32 USB) | bundle D | **Hallucinated** (future-dated CVE) | Do not cite |
| ES0499 §2.26.2 / §2.26.3 exact section numbers | bundle D | Plausible, unverified | Verify against ES0499 PDF before referencing in code |
| NXP AN12436 "Rev 2.4" SCP03 default keys | bundle B | Plausible, unverified | Confirm against current NXP AN12436 revision |
| STM32U585 SAES bit fields (KEYSEL/KMOD positions) | bundle B | Explicitly flagged as unknown by research | Cross-check CMSIS `stm32u585xx.h` |
| RFC 9814 on SLH-DSA verify-after-sign | bundle A | Future-dated (July 2025) relative to AI knowledge cutoff | Verify on IETF datatracker; treat claim as "likely true per Genêt TCHES 2023 even if RFC number is wrong" |
| Masaryk U 76% PIN-glitch on STM32U5A9 (Simonik thesis) | bundle A | Plausible, unverified | Search Masaryk thesis repo before citing |
| Saarinen SLotH CRYPTO 2024 TVLA numbers | bundle C | Paper is real; specific numbers unverified | Read paper before committing architecture on t=24.5 figure |
| Fluhrer PRF-tree ePrint 2024/500 (1.7× overhead) | bundle C | Plausible, unverified | Cost-benefit decision depends; verify paper |
| Boy et al. "SLasH-DSA" 2025 Rowhammer universal forgery | bundle A + C | Future-dated, likely hallucinated | Treat as unverified until verified |
| Genêt "Grafting Trees" TCHES 2023 | bundle A | Real, well-known | Safe to cite |
| Colin O'Flynn "MIN()imum Failure" USENIX WOOT 2019 | bundle D | Real | Safe to cite |
| Thomas Roth TrustZone-M on SAM L11 at 36C3 | bundle D | Real | Safe to cite |

General rule for future commits: if we're going to cite a paper /
CVE / errata section in source code comments or external docs,
**independently verify first**. The deep-research round correctly
surfaced the threats + mitigations; it occasionally fabricates the
exact citation for those threats.

## 4. Implementation sequencing

See todo items #18-22 for the full work list. Suggested phasing:

**Phase 1 — Stage 2 brownout foundation (todo #21)** — ~1 week
Landing BOR/IWDG/ECC/PVD/TAMP/CSS at factory defaults to secure config.
Everything that follows depends on this.

**Phase 2 — SCA mandatory-minimums (todo #18 P0 items)** — ~1 week
OptRand + double-compute + FihInt + PIN lockout fail-in. No SHAKE
migration yet; it's the architectural question for Phase 4.

**Phase 3 — USB hardening (todo #19)** — ~1 week
FI-resistant min + bounded reassembly + rate limiter + DWC2 errata
workarounds. Independent of Phases 1-2.

**Phase 4 — Architectural decision: SHAKE vs SHA2** — design work,
not code. Requires on-chain verifier assessment. Blocks the final
SLH-DSA parameter pin for production.

**Phase 5 — Production key management (todo #20)** — ~2-3 weeks
Host-side provisioning tooling, two-stage RDP flow, binding record,
anti-swap boot verification. Largest single item.

**Phase 6 — Run bundle E + apply findings (todo #22)** — TBD
Supply-chain attestation; likely augments Phase 5.

Total ≈ 6-8 weeks of focused work to reach production-ready security
posture, excluding the on-chain verifier work for a SHAKE migration.

## 5. What this doc is NOT

- Not a code specification — see `docs/work-todo.md` for actionable
  tasks with file paths, and the code itself once implemented.
- Not a threat model — see `docs/HARDENING.md` and `CLAUDE.md`
  invariants. This doc documents *mitigations* surfaced by research,
  not the overall threat taxonomy.
- Not a replacement for primary-source documentation — every register
  name / protocol detail cited here should be verified against ST
  RM0456, NXP UM11225, Infineon OPTIGA Trust M User Manual, etc.
  before code lands. The research gave us direction; the primary
  sources give us correctness.

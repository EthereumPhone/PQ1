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
   only defence. Cost: ~2 s per signature at C10 (double-compute) — acceptable.
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

6. **OPTIGA Shielded-Connection pairing secret is sealed to flash
   under a wrap key that mixes in `measured_boot::firmware_hash()`.**
   Any firmware update — a one-byte edit is enough — changes the
   hash, changes the wrap key, fails AES-GCM authentication on the
   next boot, and renders the chip-side PBS permanently unreachable.
   Every production customer would brick on their first update. We
   already reproduced the failure on a bench chip whose pairing is
   now unrecoverable (§1 of `docs/optiga-brick-postmortem.md`). Fix
   is a Trezor-style OTP-derived PBS with HKDF-scoped subkeys, no
   flash seal, plus re-rooting `hw/huk.rs` off the OTP master instead
   of `firmware_hash`. See §2.6. *Source: bench failure, 2026-04-17;
   Trezor STM32U5 reference (`core/embed/sec/secret_keys/stm32u5/`).*

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

**Cost**: ~2 s per signature (double-compute), +~5 instructions per
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

**Architectural decision pending — SHAKE vs SHA2-256 parameter set**
(historical framing; see closing note below):

| | SLH-DSA-SHA2 | SLH-DSA-SHAKE |
|---|---|---|
| HASH peripheral support | Yes (not DPA-resistant per UM3370) | No (software SHAKE required) |
| Masking cost | 3-5× (inefficient on Cortex-M33) | 1.5-2× (cleaner) |
| PRF-tree (Fluhrer 2024) | No | ⚠ **Citation unverified** — see §3 |
| Backward compat with on-chain verifier | Tied to current contract | Requires contract change |

Recommendation: evaluate SHAKE migration before Stage 2 implementation.
If on-chain verifier can be parameterised, SHAKE is the materially-
stronger SCA posture.

**⚠ Caveat on SHAKE migration analysis**: the Fluhrer ePrint 2024/500
"PRF-tree with 1.7× overhead, backward-compatible" citation that
bundle C used to argue for SHAKE is **not verifiable** per the
2026-04-15 verification round (see §3). Treat the SHAKE-vs-SHA2
decision as open — do NOT commit to SHAKE on the basis of Fluhrer's
claimed overhead figure. Independent analysis of SLH-DSA-SHAKE-128f
performance + masking cost on Cortex-M33 is needed before this
decision is production-ready. The qualitative argument (SHAKE is
easier to mask than SHA-256) still holds; the specific 1.7× overhead
number does not.

> **Update 2026-04-30 (audit overlay).** The all-C10 cutover (commit
> `7b2a339`, 2026-04-17) locked the parameter set to **SPHINCS+C10 over
> SHA-256** (`sig_len = 4008 B`, `h=18, d=2, a=11, k=13, w=8, l=43,
> target_sum=205`). The on-chain verifier (`SPHINCsC10Asm.sol`) is
> SHA-256-only and reuses the EVM SHA-256 precompile. SHAKE migration is
> therefore deferred indefinitely — it would require a fresh on-chain
> verifier, fresh wallet addresses (CREATE2 salt depends on master keys),
> and a factory redeploy. The qualitative SCA argument still motivates
> independent masking work on the SHA-256 path, not a primitive swap.

**HASH peripheral**: **provides zero DPA protection** per UM3370.
Useful for performance (~66 cycles/block) and timing-channel elimination
only. Software countermeasures remain mandatory.

**Caveats on numerical claims**: the research cites "SLotH" and
"SLasH-DSA 2025" papers with specific trace-count numbers. Author
plausibility and paper existence confirmed for SLotH; exact TVLA
numbers and the SLasH-DSA paper remain unverified per §3. The
qualitative conclusion (unprotected Cortex-M33 leaks PRF(SK.seed)
catastrophically) is defensible; the specific trace-count bounds
should not be cited as pinpoint figures.

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

### 2.5 Supply-chain attestation (bundle E → todo #22)

Bundle E surfaces a **triple-UID binding manifest** as the load-bearing
defence — no shipping wallet currently does this, and it closes the
single-chip-replacement attack surface that has bitten every existing
wallet (Trezor Safe 3 via Ledger Donjon glitch on the STM32-OPTIGA
pre-shared secret; Ledger Snake demo via arbitrary MCU code while SE
attestation passed; ColdCard via firmware factory-reset without
changing the tamper bag). Bundle B (§2.2) already specified per-device
SCP03 rotation + OPTIGA PBS lock + ECDSA-P256 binding record; bundle E
**extends** that with SLH-DSA manifest replacement, firmware-hash
inclusion, transparency log, and a WebUSB user-verification ceremony.

**What Bundle E adds on top of Bundle B:**

1. **SLH-DSA-128s factory manifest** replaces Bundle B's ECDSA-P256
   binding record. Post-quantum resistant; signature is ~7.8 KB
   (fine — it's stored once, read on every boot). The factory HSM
   signing key runs through an M-of-N ceremony with geographically
   distributed shares.
2. **CBOR manifest schema** with explicit fields:
   ```
   {
     manifest_type:        "PQS-BIND-v1",
     se050_uid:            <18 B from SE050 IDENTIFY>,
     optiga_uid:           <27 B from OID 0xE0C2>,
     stm32_uid:            <12 B from 0x0BFA_0590>,
     firmware_hash:        SHA3-256(firmware_image),   // NEW vs Bundle B
     firmware_version:     <monotonic counter>,
     device_serial:        SHA3-256(se050_uid || optiga_uid || stm32_uid),
     production_ts:        <ISO 8601>,
     manifest_version:     1,
     factory_pubkey_fp:    SHA3-256(factory_pubkey)[:16]
   }
   ```
   Firmware-hash inclusion means the manifest also acts as a measured-
   boot anchor — ties chip identity to a specific firmware build.
3. **SE050 boot-time attestation** via `Se05x_API_ReadObject_W_Attst`
   with caller-supplied 16-byte freshness nonce. Returns 18-byte
   chipId + ECDSA-SHA256 signature over response. Verify signature
   chains to NXP root CA. ⚠ **Variant constraint**: only SE050 C/E/F
   have pre-provisioned attestation certs at OID `0xF0000013`; variants
   A/B/D have keys but no cert. Confirm we're on C/E/F before relying
   on attestation.
4. **OPTIGA boot-time attestation** via `optiga_crypt_ecdsa_sign` with
   key at OID `0xE0F0`, cert read from OID `0xE0E0`, chains to
   Infineon OPTIGA ECC Root CA 2. Same freshness nonce across both SEs.
5. **STM32U585 anti-counterfeit probes** at boot (detect remarked
   chips / clones):
   - CPUID / DBGMCU_IDCODE — expect Cortex-M33 r0p4, DEV_ID `0x482`.
     Read at `0xE0044000`.
   - UID register at `0x0BFA_0590`: validate lot bytes are printable
     ASCII (`0x20`..`0x7E`), wafer number < 25, UID not all-0 or
     all-0xFF.
   - DHUK probe via SAES: run a DHUK-gated op, verify output against
     factory-recorded expected value.
   - Errata fingerprinting: `DBGMCU_DBG_AUTH_DEVICE.AUTH_ID` reads
     zero at RDP0 (documented silicon quirk); a clone "fixing" this
     outs itself. MSI-frequency low-drift (up to 25%) and ICACHE/
     DCACHE behavior on Stop mode exit are mask-specific.
   - Flash ECC: AN5342 documents SEC-DED; test last-64KB-block of
     SRAM3 behavior.
6. **Transparency log**: append-only record of every device serial +
   manifest hash. Published (Merkle-anchored per the research's
   suggestion; exact scheme TBD). Enables detection of rogue
   production runs — any device with valid manifest but missing from
   log fails the ceremony, even if factory HSM is compromised.
7. **WebUSB box-opening ceremony** at `verify.pqsigner.io`:
   - Browser sends fresh random challenge via WebUSB.
   - Both SEs sign it (SE050 with NXP-attested key; OPTIGA with
     Infineon-attested key).
   - Website verifies both signatures independently chain to their
     respective pinned root CAs, and that the UIDs match the binding
     manifest, and the manifest's SLH-DSA signature verifies against
     the published factory pubkey.
   - Customer sees green-checkmark + device serial without installing
     any tool.

**Boot-time verification ceremony** (runs in secure world before
entropy reconstruction):
1. Read STM32 UID from `0x0BFA_0590`.
2. Load binding manifest from secure flash.
3. Verify SLH-DSA-128s signature with factory pubkey (stored in
   write-protected OTP).
4. Compare manifest.stm32_uid against hardware. Halt on mismatch.
5. Probe SE050 (I2C addr `0x48`, IoT applet AID), attested read with
   fresh nonce, extract chipId. Compare against manifest.se050_uid
   AND against SE050's own signed chipId. Halt on mismatch.
6. Probe OPTIGA (I2C addr `0x30`), read UID from `0xE0C2`, ECDSA-sign
   same nonce with `0xE0F0`. Compare to manifest.optiga_uid. Halt.
7. Compute SHA3-256 of firmware image; compare to
   manifest.firmware_hash. Halt on mismatch.
8. Check monotonic anti-rollback counter (from Bundle B).
9. Set ATTESTATION_PASSED; proceed to normal boot.

Failure at any step → permanent lockdown: neither SE releases entropy
half; USB reports specific failure reason (manifest invalid / UID
mismatch / firmware hash mismatch / etc.).

**Hallucination flags from Bundle E** (fold these into the verification
log in §3 below):

- **"Ledger Donjon March 2025 attack on Trezor Safe 3"** — cited as
  justification for the Tier B threat tier but no link / ticket /
  blog post reference. Future-dated relative to the AI's training
  cutoff (Feb 2025). **Treat as unverified**; the technical threat
  model holds regardless but this specific attack should not be cited
  as proof without verification.
- **"Trezor Safe 7"** — claimed to add TROPIC01 for dual attestation.
  Does not exist as a shipping product as of knowledge cutoff. Safe 5
  is the current Trezor flagship. **Omit from comparison tables**
  until it actually ships.
- **"Masaryk University 2024/2025 thesis by Oliver Simonik"** — 76%
  PIN-glitch on STM32U5A9. Plausible but unverified (no link /
  repository citation).
- **"BlaatSchaap research"** on STM32F103 clone detection — plausible
  but unverified pseudonymous researcher.
- **"TheCharlatan May 2020 ColdCard firmware-reset attack"** —
  plausible but unverified (no link).
- **ES0499 specific bit positions** cited in the chip-ID probe list
  (`AUTH_ID` bitfield behavior at RDP0, MSI frequency anomaly) —
  plausible but unverified; cross-check against current ES0499 PDF
  before implementing.
- **STM32U5 clone "do not exist as of early 2025"** — properly
  hedged as absence-of-evidence rather than evidence-of-absence.
  Treat as current best-available assessment, not a guarantee.

**ECDSA vs SLH-DSA binding signature decision**:
Bundle B used ECDSA-P256 for the binding record because it's small and
SE050/OPTIGA can do it natively. Bundle E argues SLH-DSA-128s is more
defensible long-term (PQ-resistant, no key-extraction from factory HSM
via Shor). Since we're already computing SLH-DSA on the MCU for
transaction signing, adding SLH-DSA verification of the manifest at
boot is free. Recommendation: **go with Bundle E's SLH-DSA manifest**;
retire Bundle B's ECDSA binding record design. This is a material
change to work-todo #20 scope.

### 2.6 Device root-key architecture (work-todo #24)

**Threat context.** The OPTIGA Trust M pairing-secret flow that landed
during early bring-up (`setup_pbs_no_handshake`, `hw/huk.rs`, flash page
126) has a concrete reliability failure: every legitimate firmware
update bricks the device. The bench chip that surfaced this is
permanently unpaired for Shielded Connection. Fixing the underlying
root-key architecture before silicon ships is a production gate.

Full root-cause analysis: `docs/optiga-brick-postmortem.md`.

**The bug in two sentences.** The Platform Binding Secret is generated
from the STM32 TRNG and persisted to flash page 126 under an AES-256-
GCM seal whose wrap key mixes in `measured_boot::firmware_hash()`. Any
firmware rebuild — a one-byte diff is enough — changes the hash,
changes the key, fails GCM authentication on next boot, leaves the
chip-side PBS (which is locked at LcsO=Operational) reachable only to
a PBS value the MCU can no longer reconstruct. One-way brick of the
bus-encryption path.

**Architectural response — Trezor's layered root-key model on STM32U5.**

Reading `~/repos/trezor-firmware/core/embed/sec/{secret_keys,secret,
secure_aes}/stm32u5/` shows Trezor stacks three keys:

| Layer | What | When generated | Software access | Survives FW update |
|---|---|---|---|---|
| **DHUK** | Factory-fused 256-bit per-chip key in ST silicon | At wafer test (ST) | SAES-only (`CRYP_KEYSEL_HW`); never in memory | Yes |
| **BHK** | 32 B of device TRNG in HDP-protected flash page, loaded into TAMP backup registers at boot | First boot, on-device | SAES-only after `TAMP_SECCFGR.BHKLOCK`; software can't read post-boot | Yes (regeneration = factory reset) |
| **OTP master** | 32 B of device TRNG in flash OTP block | First boot, on-device (`secret_keys.c:177-194`) | Readable by secure-world firmware | Yes (OTP is permanent per silicon) |

Trezor derives per-purpose keys (OPTIGA pairing, TROPIC01 pairing,
storage salt, NRF auth, MCU device-auth) from the OTP master via HMAC.
The DHUK and BHK additionally encrypt the OTP master and other secrets
at rest in the "secret" flash page, so a flash dump alone doesn't leak
raw key bytes.

**Our staged adoption plan.**

*Stage 1 — OTP-derived master with HKDF subkey layer* (this doc
landing + current implementation). Reserve bytes 128..160 of STM32U585
OTP (two quad-words past the rollback tally) for a 32-byte device
master key. On first secure-world boot, if the region is unburned,
fill 32 bytes from STM32 TRNG and program (irreversible). On every
subsequent boot, `read_device_master` returns those 32 bytes. A new
`secure/src/hw/secret_keys.rs` exposes domain-labelled HKDF-SHA256
subkeys: `optiga_pairing_secret`, `se050_scp03_enc_key`,
`se050_scp03_mac_key`, `tropic01_pairing_key`. `setup_pbs_no_handshake`
consumes `optiga_pairing_secret` instead of `rng::fill`; the flash-
page-126 AES-GCM seal is deleted outright. `hw/huk.rs::derive_device_
key` re-roots off the OTP master — the line that reads `h.update(&fw_
hash)` becomes `h.update(&hw::otp::read_device_master())`. `measured_
boot::firmware_hash()` is preserved unchanged: it still drives the 8-
BIP-39-word OLED attestation and will feed the #22 supply-chain
manifest; it just stops being an input to wrap-key derivation. Closes
the brick scenario.

*Stage 2 — SAES + BHK uplift* (merges with work-todo #7 HUK-SAES).
Port Trezor's BHK pattern: first-boot TRNG into an HDP-protected flash
page, load into TAMP backup registers at boot, set `TAMP_SECCFGR.BHKL
OCK` so secure-world code can only *use* the key via SAES, not read
it. Wrap the OTP master with DHUK at rest so a chip decap alone
doesn't yield the raw bytes. The `secret_keys::*` API surface stays
unchanged — OPTIGA / SE050 / Tropic drivers do not move.

**Why first-boot self-provisioning beats a factory-burn workflow** for
an open-source wallet: the TRNG output only ever exists on the user's
own hardware, never passes through the vendor's hands, and the factory
does not need to hold or protect any per-device secret. The customer
can independently verify on unboxing that OTP is still unburned before
powering the device up, which is a stronger property than trusting a
factory tamper-evident bag. This matches Trezor's `flash_otp_is_locked
? read : (fill + write + lock)` pattern exactly (`secret_keys.c:177-
194`). The residual supply-chain concern is that "first boot" must
happen on a device running our signed firmware — otherwise an attacker
who intercepts the device pre-first-boot could flash a key-exfiltrating
stub, boot once to capture TRNG, then restore the real firmware.
Defence stack: secure boot (work-todo #13) + tamper-evident packaging
+ a user-side verification script that confirms the binding manifest
(work-todo #22) matches the device before first power-on.

**Testing posture — hardcoded key during bring-up.** Until we are
confident the derivation is stable across rebuilds, we do *not* want
to burn real OTP on our dev bench. `secure/Cargo.toml` gains an
`otp-hardcoded-master-key` Cargo feature, OFF by default. When
enabled, `read_device_master` returns a fixed 32-byte constant
(deliberately distinctive byte pattern so it cannot be confused for a
real key in logs), `is_device_master_burned` returns true, and
`ensure_device_master` is a no-op. A loud boot-time warning via
`secure_log!` flags the insecure configuration. A `compile_error!`
guard fails the build if the feature is set without `debug-log` or
`e2e-test` also enabled (i.e. on a production profile). Flip the
feature off and the first-boot TRNG path takes over. We validate end-
to-end on a fresh OPTIGA chip only after the hardcoded path is proven
stable across reflashes with differing firmware hashes.

**Extraction cost across layers.**

| Attacker capability | Stage-1 OTP master | Stage-2 OTP master under SAES | Stage-2 BHK post-lock |
|---|---|---|---|
| Secure-world RCE, read memory | Reads the 32 bytes directly via `read_volatile(0x0BFA_0080)` | Same — OTP remains plain-readable; DHUK wrap protects only at rest | Cannot read; can only USE via SAES on this device |
| Flash-dump + transplant to second board | UID of target board is wrong → derived keys wrong anyway; not viable | Same, with DHUK also wrong → ciphertext undecipherable on target | Same, and BHK never lived in transferable flash |
| Debug port after RDP regression | OTP survives RDP regression | Same | BHK regeneration on RDP2→0 wipes TAMP-backed key |
| Decap + microprobe OTP cells | Feasible ($10–100K, destructive, single device) | Same, then attacker still needs DHUK from silicon | BHK lives transiently in TAMP; substantially harder |
| Supply-chain attacker between factory and user | No key on-device yet; attacker can substitute their own TRNG | Same | Same |

Stage 1 solves the brick. Stage 2 additionally raises the bar from
"secure-world RCE = remote key exfiltration" to "attacker must keep
running code on *this specific device* for every signature they want
to forge" — a qualitative change in the attacker cost model.

**Files touched in Stage 1.**

- `secure/src/hw/otp.rs` — add `read_device_master`, `burn_device_
  master`, `is_device_master_burned`, `ensure_device_master`.
- `secure/src/hw/secret_keys.rs` *(new)* — HKDF-SHA256 wrappers.
- `secure/src/hw/mod.rs` — register `secret_keys` module.
- `secure/src/hw/huk.rs` — swap `firmware_hash` → OTP master in
  `derive_device_key`.
- `secure/src/optiga/mod.rs` — rewrite `setup_pbs_no_handshake`,
  simplify `load_pbs`.
- `secure/src/hw/flash.rs` — delete `read_pbs` / `write_pbs` /
  `erase_pbs_page` / `PBS_PAGE_ADDR` / `PbsLoadError` / `PBS_WRAP_
  DOMAIN` / `PBS_BLOB_LEN` / `is_pbs_blank`.
- `secure/Cargo.toml` — drop `optiga-bringup-fresh`, add `otp-
  hardcoded-master-key`.
- `secure/src/measured_boot.rs` — unchanged (keeps driving OLED
  attestation + #22 manifest).

## 3. Hallucination + verification log

The research-round prompts told the AI to cite primary sources and
say "I don't know" rather than guess. Across the 5 responses, here's
the status of every flagged citation — after a 2026-04-15 verification
round of web searches.

**Lesson learned from this verification round**: most of our initial
hallucination-flagging was wrong. We called items hallucinated because
they were future-dated relative to our own model's training cutoff;
they were actually real publications from after the cutoff. Be less
aggressive flagging things as fabricated in future rounds — verify
first, flag second.

| Claim | Source | **Verification status (2026-04-15)** | Action |
|---|---|---|---|
| `CVE-2026-4179` (Zephyr STM32 USB infinite loop) | bundle D | ✅ **REAL**. Published 2026-03-16. Zephyr advisory `GHSA-9xg7-g3q3-9prf`, CWE-835, CVSS 6.1. Affects Zephyr ≤ 4.3.0 drivers/usb/device/usb_dc_stm32.c. | Safe to cite. Note advisory is about `usb_write()` from ISR + `k_yield()`, not explicitly malicious USB host — read the GHSA before re-describing. |
| `CVE-2021-42553` (STM32Cube USB Host buffer overflow) | bundle D | ✅ **REAL**. NVD, CVSS 9.8 CRITICAL. | Safe to cite. |
| **RFC 9814** (SLH-DSA verify-after-sign inadequate) | bundle A | ✅ **REAL**. Proposed Standard, July 2025. §5 quote: *"Verifying a signature before releasing the signature value is a typical fault-attack countermeasure; however, this countermeasure is not effective for SLH-DSA."* | Safe to cite — directly supports the double-compute mandate. |
| NXP **AN12436** SCP03 default keys (ENC/MAC/DEK) | bundle B | ✅ **REAL**. Latest revision is Rev 2.4 (8 July 2024). All three hex values match byte-for-byte against earlier retrievable rev 1.6. | Safe to cite. |
| STM32U5 **errata ES0499** existence | bundle D | ✅ **REAL**, Rev 11 (December 2025) current. §2.2.15 confirmed verbatim ("OTG_FS is reset by OTGRST and DCMI_PSSIRST bits"). | Cite ES0499 safely. |
| ES0499 specific sub-section numbers (§2.26.2, §2.26.3, §2.26.4, §2.26.5) | bundle D | 🟡 **Partially verified.** USB OTG errata is indeed in ES0499; exact sub-section numbering could not be confirmed from public search snippets. May have shifted between revisions. | Download Rev 11 and pin citations to it before quoting section numbers in code. |
| **AN5342** (Flash ECC / SRAM ECC option bytes) | bundle A | ✅ **REAL**. Title: "How to use ECC management for internal memories protection on STM32 MCUs." Originally STM32H7-focused, broadened to multi-series. | Cite safely. Some STM32U5-specific ECC detail lives in RM0456 rather than AN5342; open current AN5342 to confirm U585-specific option-byte wording. |
| **RM0456** covers SAES peripheral | bundle B | ✅ **REAL**. Confirmed. | Safe to cite. Pin latest revision number when writing code against specific bit fields. |
| STM32U585 SAES bit fields (KEYSEL / KMOD positions) | bundle B | 🟡 Research author explicitly flagged as unknown; confirmation not attempted in this verification round. | Cross-check CMSIS `stm32u585xx.h` before writing SAES code. |
| **Ledger Donjon March 2025 Trezor Safe 3** glitch | bundle E | ✅ **REAL**. Blog post dated March 12, 2025 at `ledger.com/why-secure-elements-make-a-crucial-difference-to-hardware-wallet-security`. TRZ32F429 voltage-glitched, pre-shared secret extracted from flash, firmware attestation bypassed. Trezor's own confirmation at `trezor.io/vulnerability/donjon-s-trezor-safe-3-evaluation`. | Safe to cite. |
| **Trezor Safe 7** with TROPIC01 | bundle E | ✅ **REAL**. Announced October 21, 2025 (`trezor.io/trezor-safe-7`; `tropicsquare.com/news-and-events/...trezor-safe-7`). Shipping late 2025 / early 2026. Transparent secure element + EAL6+ secondary SE (dual attestation). | Safe to cite. This is the closest existing product to our PQSigner OS architecture. |
| **Trezor Safe 5** uses STM32U5 | bundle E | ✅ **REAL**. Confirmed via Trezor product page + Ledger blog. | Safe to cite. |
| Ledger Donjon 2025 statement that "no public fault injection attack on STM32U5" | bundle E | ✅ **REAL**. Exact quote in the Ledger blog post (`ledger.com/why-secure-elements-make-a-crucial-difference...` March 12, 2025). Note: **already superseded by the Simonik thesis** below. | Safe to cite, but qualify that it was true as of publication and has since been invalidated. |
| **Masaryk U Simonik thesis** 76% PIN-glitch on STM32U5A9 | bundle A / C / E | ✅ **REAL**. Bachelor's thesis by Oliver Simonik at Masaryk U on fault injection against STM32U5 (Trezor Safe 5). Referenced at `it4sec.substack.com/p/fault-injection-attack-on-the-stm32u5`. Thesis PDF on `is.muni.cz` (not directly retrieved this round — verify the URL before quoting page numbers). | Safe to cite. This is the empirical demonstration that STM32U5 is **not** glitch-immune. |
| **BlaatSchaap** STM32F103 clone research | bundle E | ✅ **REAL**. `blaatschaap.be/identifying-32f103-clones/` + multi-part Cortex-M series. Uses CPUID/ROMTABLE differences. Specific r2p1 vs r1p1 exact revision strings not confirmed this round. | Safe to cite for the approach; verify exact revision strings against primary source. |
| **TheCharlatan May 2020 ColdCard firmware-reset** | bundle E | ✅ **REAL**. `thecharlatan.ch/COLDCARD-Supply-Chain/`. | Safe to cite. |
| **Saleem Rashid 2018 Ledger Nano Snake demo** | bundle E | ✅ **REAL**. `saleemrashid.com/2018/03/20/breaking-ledger-security-model/`; Krebs on Security coverage. | Safe to cite. |
| **wallet.fail at 35C3** | bundle D | ✅ **REAL**. `media.ccc.de/v/35c3-9563-wallet_fail`. December 2018 CCC. | Safe to cite. |
| **SiliconToaster** (Ledger Donjon EMFI tool) | bundle D / E | ✅ **REAL**. `github.com/Ledger-Donjon/silicon-toaster`, LGPLv3, Hardwear.io 2020 paper (`eprint.iacr.org/2020/1115`). | Safe to cite. |
| **"Extraktor" Ledger Donjon ~$100 glitch board** | bundle D | ❌ **Cannot confirm** this specific tool name. Not found in Donjon's public repos / blog. Likely misremembering of SiliconToaster (which *is* real) or a non-public internal tool. | Do **not** cite "Extraktor" by name; say "published Ledger Donjon glitching tooling" if referring to the general capability. |
| **CanSecWest 2024 / VoidStar STM32F4 RDP bypass** | bundle D / E | ✅ **REAL**. Matthew Alt (VoidStar Security LLC), talk title "Glitching in 3D: Low-Cost EMFI Attacks." `secwest.net/presentations-2024/glitching-in-3d-low-cost-emfi-attacks`, `voidstarsec.com`. | Safe to cite. |
| "Riscure LFI on ColdCard" | bundle D / E | 🔴 **Attribution WRONG.** The ColdCard Mk2 ATECC508A single-laser-shot + Mk3 ATECC608A multi-shot attacks were done by **Ledger Donjon (Olivier Hériveaux)**, NOT Riscure. See `blog.coinkite.com/laser-fault-injection/`, SSTIC 2020/2021 papers, `ledger.com/blog/coldcard-pin-code`. | Correct attribution when citing. Research content is correct; credit is wrong. |
| **Colin O'Flynn "MIN()imum Failure" USENIX WOOT 2019** | bundle D | ✅ **REAL**. Safe to cite. |
| **Thomas Roth TrustZone-M on SAM L11 at 36C3** | bundle D | ✅ **REAL**. `media.ccc.de/v/36c3-10859-trustzone-m_eh...`. |
| **Saß et al. μ-Glitch USENIX Security 2023** | bundle A | ✅ **REAL**, 4-fault TrustZone-M bypass demonstrated. Safe to cite. |
| **Spensky et al. GlitchResistor DSN 2021** | bundle A | ✅ **REAL**. Specific "100% success at 8-cycle window" figure not reverified, but paper exists and characterises success rates in this ballpark. |
| **Genêt "Grafting Trees" TCHES 2023** | bundle A | ✅ **REAL**. Paper by Aymeric Genêt, TCHES 2023, single-fault universal-forgery via grafting subtree into SPHINCS+ hypertree. Safe to cite; this is the canonical reason verify-after-sign doesn't save SLH-DSA. |
| **Kannwischer et al. COSADE 2018** (DPA on SPHINCS-256 BLAKE) | bundle C | ✅ **REAL**. Springer LNCS 10815. ~10k traces for 32-bit chunk is consistent with paper. |
| **Saarinen "SLotH" CRYPTO 2024** + specific TVLA numbers (t=24.5 at 1k traces) | bundle C | 🟡 Saarinen's work on PQC side-channels is real. The specific SLotH paper title + exact numerical claims could not be independently confirmed in this verification round. | Verify against the actual paper before committing architectural decisions that depend on the trace-count figure. |
| **Fluhrer ePrint 2024/500** — PRF-tree 1.7× overhead, backward-compat | bundle C | ❌ **Does not exist as described** per verification agent. The claim "backward-compatible PRF-tree" is technically implausible — changing PRF tree structure changes verification output. | **Do not base architectural decisions on this citation** until verified. Treat SHAKE migration discussion as open question pending an independent reference. |
| **Belenky et al. TCHES 2023 / COSADE 2021** specific trace counts (275K / 30K) | bundle C | 🟡 Author works on side-channels; specific trace counts unverified. | Treat as indicative rather than pinpoint benchmarks. |
| **Boy et al. "SLasH-DSA 2025" Rowhammer universal forgery** | bundle A / C | 🟡 **Uncertain.** Post-May-2025 cutoff. OpenSSL SLH-DSA support shipped in OpenSSL 3.5 early 2025, so an attack paper in 2025 is plausible, but neither we nor our verification agents could confirm its existence. | Do not cite until independently found. The underlying Rowhammer-vs-PQ-signing threat class is real regardless. |
| **Fox-IT AES-256 EM attack** (5 min at 1 m) | bundle C | ✅ **REAL**. Fox-IT whitepaper by Ramsay & Van Woudenberg, 2017. Safe to cite. |
| **Kraken Security Labs Trezor glitching** ($75, 15 min) | bundle D | ✅ **REAL**. January 2020 disclosure. Safe to cite. |
| **NCC Group "CM-1-C" pattern label** | bundle A | 🟡 NCC Group's multi-part fault-injection-countermeasures series is real (`research.nccgroup.com/2021/07/08/software-based-fault-injection-countermeasures-part-2-3/`) and covers complement-storage + redundant-check patterns. The specific "CM-1-C" identifier could not be located. | Cite the NCC Group series by URL; do not cite "CM-1-C" by name. |
| **MCUboot magic constants 0x1AAA_AAAA / 0x1555_5555** | bundle A | ✅ **REAL**. Documented in MCUboot design docs; values chosen specifically for fault-injection hardening. Safe to cite. |
| **Ringzer0 PicoEMP STM32F4 RDP bypass** | bundle D | 🟡 PicoEMP (by Colin O'Flynn / NewAE) is real; STM32F4 RDP EMFI bypasses exist; specific claim of "Ringzer0 + PicoEMP + 3D printer automated scanning" could not be tied to a specific publication. | Cite PicoEMP generically; don't invent specific research attributions. |

**Bottom line**: of the 30+ technical references in the 5 research
bundles, fewer than a handful are actual hallucinations. The round
was more accurate than my initial skepticism suggested. Going
forward: verify-then-flag, not flag-then-verify.

## 4. Implementation sequencing

See todo items #18-24 for the full work list. Suggested phasing:

**Phase 0 — Device root-key architecture (todo #24)** — ~3 days
Land `hw/otp.rs` master-key API (read / burn / ensure) + `hw/secret_
keys.rs` HKDF subkeys + OPTIGA `setup_pbs_no_handshake` rewrite +
`hw/huk.rs` re-root off `firmware_hash`. Delete `PBS_PAGE_ADDR` flash-
seal infrastructure and the `optiga-bringup-fresh` Cargo feature.
Closes the production-breaking firmware-update brick (§2.6). Unblocks
#7 (HUK-SAES) and #20 (factory provisioning) downstream. Initial
testing under `otp-hardcoded-master-key`; real OTP burn proven on a
fresh OPTIGA shield before this phase is considered complete.

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

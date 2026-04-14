# AI Research Briefing — PQSigner OS

*Purpose: a self-contained project briefing suitable for pasting into
any AI research session (Claude web Deep Research, Gemini Deep Research,
ChatGPT Deep Research, etc.) so the model starts with correct
architectural facts instead of rediscovering — or worse, guessing
wrong — them. This file is kept current; treat the commit that edited
it last as the source of truth.*

---

## 1. What the project is, in five bullets

- **Post-quantum ERC-4337 smart-wallet firmware** for the STM32U585
  (Cortex-M33 with ARM TrustZone) on the B-U585I-IOT02A Discovery
  board. Target form factor is a dedicated hardware-wallet device with
  **USB-C as the only external interface** (no Bluetooth, no
  Ethernet, no UART exposed to the host).
- **Dual secure element** architecture, not single-SE:
  **NXP SE050** (I2C1, addr `0x48`) + **Infineon OPTIGA Trust M V3**
  (I2C1, addr `0x30`). Both chips are mandatory; they hold XOR-split
  entropy. Neither alone reveals any bit of the seed.
- **Signatures are post-quantum (SLH-DSA / SPHINCS+ SHA2-128f today,
  migrating to SHA2-192f for production).** Because no commercial
  secure element can currently compute SLH-DSA, signing runs on the
  Cortex-M33 core inside TrustZone secure world. The secure elements
  act as *gated storage* of the BIP-39 entropy, not as signing
  accelerators. The seed therefore must transit STM32 SRAM during the
  active signing window (~120 s idle timeout, then zeroize).
- **TrustZone partition**: secure world (flash bank 1 `0x0C000000`,
  SRAM1 `0x3000_0000`) owns all crypto, PIN verification, and
  persistent secrets. Non-secure world (flash bank 2, SRAM2) owns UI,
  USB transport, transaction parsing, and ZK-proof verification
  scaffolding. Crossings go through 6 NSC gateway commands; pointer
  validation + TOCTOU-safe copy-to-secure-stack on every entry.
- **Bootstrap signer (ML-DSA-44)** never rotates — it owns the wallet
  address via CREATE2 on the on-chain factory. **Main signer (SLH-DSA)**
  is per-chain, per-epoch, rotates every ~2^20 signatures. Both
  hashes of public keys are anchored on-chain; there's no classical
  secp256k1/P-256 fallback anywhere in the contract.

## 2. Hardware that matters for any research

| Element | Spec | Role |
|---|---|---|
| MCU | STM32U585AII6Q (LQFP144, 2 MB flash, 786 KB SRAM) | Main compute + TrustZone + supervisor |
| Cortex-M33 core | ARMv8-M at 160 MHz | Hosts SLH-DSA signing in secure world |
| SE050 | NXP EdgeLock, I2C, EAL6+ | Stores `half_E` of XOR-split entropy; hardware PIN gate |
| OPTIGA Trust M V3 | Infineon, I2C, EAL6+ | Stores `half_O` of XOR-split entropy; shielded connection |
| On-board STSAFE-A110 | On I2C2 | **Unused** today (probe-only feature) — potential future attestation root |
| OLED | SSD1306, I2C (shared bus with SE050/OPTIGA at 400 kHz) | Trusted display in secure world |
| Buttons | 2× GPIO (PI2 left, PA15 right) | Trusted input in secure world |
| USB | OTG FS peripheral, USB-C connector | Only host interface. Ledger APDU + custom framing |
| VBAT | **CR1220 holder, unpopulated by default** | Backup domain power (needed for Stage 4) |

**Voltage supervision state (as of this briefing):**
- BOR, PVD, SRAM2/SRAM3/BackupSRAM ECC, IWDG, PVM all at **factory
  defaults** = effectively off/minimum. Stage 1 of the brownout
  roadmap added reset-cause classification and verified flash writes;
  Stage 2 will turn on BOR3, PVD, ECC, and wire an NMI handler. See
  `docs/brownout-hardening.md` for the full 5-stage plan.

**Reset behaviour (empirically verified on this board):**
- `probe-rs reset` = SWD SYSRESETREQ. Classified as `ResetCause::Software`
  via `RCC_CSR=0x14004400`. Does not cut USB Vbus → SE050 shield stays
  powered across the reset (separate chip, not dependent on STM32 state).
- NRST user button (B2) = hardware reset pin. Slightly more thorough
  than `probe-rs reset`. Still doesn't cut USB.
- USB unplug = true cold cycle of both MCU and SE050. Validated in the
  `se050-crash-safety-e2e` test to survive full power-loss mid-wipe.

## 3. Architectural boundaries and trade-offs we have accepted

These are load-bearing decisions — research that contradicts them is
not useful.

1. **Seed transits STM32 SRAM during signing.** Unavoidable until a
   commercial secure element supports SLH-DSA. Mitigations already in
   place: TrustZone isolation, `ZeroizeOnDrop`, signature verify-before-
   release (fault-injection guard), 120 s idle timeout. Future: SRAM2
   relocation + hardware auto-erase (Stage 2), HUK-SAES wrapping.
2. **SE050 release the seed to authenticated firmware.** SE050's value
   isn't "seed never leaves silicon" — it's hardware PIN gate + XOR
   storage. Research that says "do all signing on SE050" is a category
   error for a PQ wallet.
3. **Dual SE means split threat model.** An attacker who extracts one
   chip's contents in isolation gets nothing — only the XOR of both
   halves reveals entropy. That changes what attacks matter: single-
   chip invasive attacks are less critical than dual-chip or
   PCB-level interposer attacks.
4. **USB-C is the only host interface.** No network attack surface
   except via the host computer. USB stack hardness matters a lot; UART
   / JTAG / SWD are production-locked (RDP2, nothing exposed to the
   outside of the enclosure).
5. **We accept that "attacker with EAL6+ decapping capability" wins.**
   Out-of-scope for our threat model. In-scope: everyone with a logic
   analyzer, USB gadget, glitch generator, or purchased/stolen wallet
   who can't afford an ion-beam workstation.
6. **Bootstrap PK hash is immutable after first boot.** The wallet
   address derives from it via CREATE2; changing it breaks identity.
   Any future anti-cloning / attestation design must work around this.

## 4. Current implementation state — what exists, what's missing

**Implemented and validated on hardware (master branch):**
- Dual-SE provisioning + PIN-gated unlock with XOR entropy
  reconstruction in STM32 SRAM.
- SE050 PIN-lockout factory reset via secondary admin UserID
  (`0x7B06_00A0`), admin PIN stored in secure flash page 125,
  two-entry TAG_POLICY on every user object. Full design +
  production checklist: `docs/se050-factory-reset.md`.
- SCP03 authenticated+encrypted channel on SE050. **Using NXP default
  static keys** — not rotated per device. Production plan: rotate +
  HUK-SAES wrap, tracked as `docs/work-todo.md` item 7.
- Shielded Connection on OPTIGA Trust M with Platform Binding Secret
  (PBS) in secure flash page 126.
- SLH-DSA-SHA2-128f signing with verify-before-release.
- ZK clear-signing (Groth16 + Poseidon) for Aave v3 calldata.
- 6-command NSC gateway with pointer validation and TOCTOU-safe
  copy-in.
- Firmware measurement: SHA-256 of secure-flash region → 8 BIP-39
  words on OLED at boot. Companion host tool (`fwmeasure`) for
  reproducible-build comparison.
- **Brownout Stage 1**: reset-cause classification, verified flash
  writes, `stm32-harden-opts` option-byte target (not yet applied on
  any dev board).

**Designed but not implemented:**
- Brownout Stages 1.5–5 (see `docs/brownout-hardening.md`).
- Hash-signature firmware update model (ML-DSA-44 signs the
  measurement hash; `docs/work-todo.md` item 14).
- Immutable bootloader in WRP-locked flash (`docs/work-todo.md` item 15).
- HUK-SAES key wrapping for SCP03 and PBS keys (item 7).
- SE attestation: verifying NXP / Infineon cert chains against
  pinned roots at boot (items 8/10).
- BIP-85 path-structured multi-chain signers (implemented; not yet
  stress-tested).
- SE050 + OPTIGA attempt-counter sync (single-SE lockout is solved;
  dual-SE coordinated lockout is not yet transactional).
- Signed firmware update protocol over USB with brownout-safe
  flashing (item 14).
- Active tamper mesh on enclosure PCB (out-of-firmware).

**Explicitly decided against:**
- Any classical (secp256k1 / P-256 / Ed25519) transaction signer.
- Any secret storage in non-secure world, even transient.
- Software PRNG (all randomness from STM32 TRNG + HSI48).
- Heap allocation in secure world (`#![no_std]`, stack-only).

## 5. Facts corrected after prior research rounds

Listed here so future research doesn't re-derive them from scratch.

| Claim | Correction | Source |
|---|---|---|
| "ECC is always-on in hardware on all SRAM blocks" | Only SRAM1 has always-on ECC. SRAM2, SRAM3, Backup SRAM require option bytes `SRAM2_ECC` / `SRAM3_ECC` / `BKPSRAM_ECC`. Factory default = **off**. | AN5342 |
| Backup SRAM at `0x4002_4000` | `0x4003_6400` (NS alias) on U5. The `0x4002_4000` address is the F4xx family. | Zephyr RTOS ST commits; U5 memory map |
| Flash ECC 9 bits per 64-bit sub-word | 9 bits per **128-bit quad-word** (137 bits total). Torn QW writes double-error on the whole word, not per 64-bit half. | RM0456 |
| PVD bit field `PLS[2:0]` | `PVDLS[2:0]` on U5 (L4-era docs called it `PLS`). | RM0456 |
| BOR4 at ~3.0 V | ~2.8 V. | U5 datasheet |
| BOR3 required for flash writes | Flash supports program/erase down to V<sub>DD</sub> = 1.71 V. BOR3 is a best-practice design margin, not an ST spec. | U5 datasheet |
| B-U585I-IOT02A ships with CR2032 battery | Board has a **CR1220** holder and it is **unpopulated by default**. | B-U585I-IOT02A schematic / user manual |
| Page erase ~3-4 ms | Typical 1.5 ms (10k cycles), 1.7 ms (100k cycles). 3-4 ms is worst-case max at high temp + end-of-life. | U5 datasheet |
| SRAM2_RST erases on "every reset" | Specifically: BOR, pin, software, IWDG, WWDG, OBL. NOT standby-wakeup or backup-domain-only resets. | RM0456 |

**Relevant errata (ES0499):**
- §2.2.7/2.2.8: backup-domain reset can produce unpredictable values when VBAT + VDD share a source.
- §2.2.10: system reset during Stop 2 with SRAM power-down can permanently lock device (fixed in die rev cut 3.3).
- §2.2.23: SRAM ECC status flags only update when matching interrupt is enabled. Pure polling silently misses errors.
- IWDG Early-Wakeup Interrupt does not function in Stop modes (not fixed).

## 6. Known threats already catalogued

(So research can focus on *new* threats rather than re-listing these.)

- **Voltage glitching on RDP byte read during boot** — dominant historical STM32 attack; STM32U5 has no public bypass as of 2025. Our planned defenses: BOR4, PVD, tamper monitors, option-byte RDP Level 2 with OEM1LOCK for production.
- **EMFI** — possible against U5 core; no public attack. Defended via internal tamper (temp/voltage/clock), optional tamper mesh on production PCB.
- **Power/EM side-channel on software crypto** — SLH-DSA on Cortex-M33 emits EM. Mitigation status unclear; needs dedicated research (see Prompt C below).
- **Fault injection on signature verify / PIN compare** — partially mitigated (verify-before-release); need systematic double-glitch patterns everywhere (Prompt A).
- **I2C bus interposer between MCU and SE** — defended by SCP03 with auth + encrypt on every APDU. Keys need rotation for production (Prompt B).
- **Dark Skippy / anti-klepto nonce exfiltration** — ECDSA-specific, does not apply to SLH-DSA (stateless hash-based signatures have no nonce). **Irrelevant to us.** Stating this explicitly so future research doesn't chase it.
- **Cold boot / Volt Boot / UnTrustZone SRAM residue** — minimize seed time in SRAM; Stage 2 moves secrets to SRAM2 with hardware auto-erase.
- **USB stack CVEs** — CVE-2021-42553 (STM32Cube USB Host Library) and similar. Our USB stack is custom — needs audit (Prompt D).
- **Supply chain / counterfeit chips** — STM32 family heavily counterfeited; production plan is authorized-distributor sourcing + boot-time chip-ID verification (Prompt E).
- **Seed entropy collection** — currently STM32 TRNG + HSI48. Multi-source mixing (STM32 TRNG XOR SE050 TRNG XOR OPTIGA TRNG) is designed but not yet implemented.

## 7. Open architectural questions we are actively researching

These are where research effort should go. Each subsection is a
**drop-in prompt** for an AI research session.

**For tools that accept only one attachment per session** (Claude web,
etc.), we've pre-built self-contained bundle files under
`docs/research-bundles/`. Each bundle combines the question + a
condensed version of this briefing + the relevant code excerpts into a
single ~50-120 KB markdown file. Upload the bundle as the only
attachment, and the session has everything it needs. See
`docs/research-bundles/README.md` for the mapping.

The prompts below are the same questions, kept here for reference.

---

### Prompt A — Fault-injection resistance for PQ signing + PIN path

**Context:** See the "What the project is" + "Architectural trade-offs"
sections above. Key facts: SLH-DSA signing runs on Cortex-M33 core in
TrustZone secure world; PIN verify is delegated to SE silicon
(hardware-constant-time); seed reconstruction from XOR halves happens
in STM32 SRAM during active signing window. Stage 2 of our brownout
roadmap will add PVD + ECC, but does NOT yet add glitch countermeasures.

**Research question:**
Given the 2024-2025 state of voltage / EMFI / laser fault injection
against STM32 Cortex-M33 designs, what is the minimum set of
**software** glitch countermeasures we should add to these three flows:

1. The seed XOR-reconstruction code path in `secure/src/dual_se.rs`
   (`unlock()` function — reads half_O and half_E, reconstructs
   full entropy, derives master_secret, caches encrypted blob).
2. The SLH-DSA signature verify-before-release guard in
   `secure/src/nsc/sign_and_emit.rs` — currently a single compare;
   should be double-glitch-resistant.
3. The PIN-lockout trigger in `secure/src/nsc/cmd_request_unlock.rs`
   — single-glitch inversion of "remaining == 0" check currently
   blocks the factory reset.

Give us **concrete Rust code patterns** (redundant volatile reads,
complement-storage, magic-constant comparisons, random-delay
templates, NCC-Group-style double-check idioms). For each pattern,
identify which fault classes it defends against (single-shot voltage
glitch, double-shot, EMFI, LFI) and which it doesn't. Rank by
cost/benefit.

Out of scope: hardware countermeasures (tamper mesh, bulk cap,
external voltage supervisor) — those are tracked separately.

---

### Prompt B — Production key management for SCP03 + PBS + HUK-SAES

**Context:** See "Current implementation state" — specifically, SCP03
on SE050 uses NXP default static keys today (`0x40 0x41 0x42 …`), and
OPTIGA's Platform Binding Secret is per-device-random but stored as
raw bytes in secure flash page 126. HUK-SAES wrapping is listed as
work-todo item 7 but unimplemented. STM32U585 has the SAES peripheral
and a Hardware Unique Key per chip (not readable by firmware; only
usable as a KEK via SAES). `docs/se050-factory-reset.md` §2a has a
brief future-optimisation note.

**Research question:**
Design a production provisioning + runtime key-management protocol
that:

1. Rotates SE050 SCP03 static ENC/MAC keys from NXP defaults to
   per-device-unique at chip personalization, storing the new keys
   on the STM32 side HUK-SAES-wrapped (never in plaintext flash).
2. Wraps the OPTIGA PBS the same way.
3. Handles the PQSigner firmware upgrade / field-update case: if a
   newer firmware includes a different HUK-SAES domain tag, how does
   it recover existing users' keys without requiring chip reset?
4. Establishes a verifiable per-device attestation chain that binds
   the physical SE050 + OPTIGA UIDs to the STM32 chip-unique-ID, so
   that swap attacks (desolder the SE from a victim device, put it in
   the attacker's device) fail at boot.

Constraints: all key rotation must happen during one-time device
provisioning at the factory (no field rekey). Out-of-band key
transport channels (a secure provisioner machine) are acceptable.
Recovery from a bricked HUK (chip replacement) is NOT required — the
wallet can be treated as "dead, restore from seed backup on a new
device".

Deliverables: a concrete protocol diagram + flash-layout sketch + the
minimum STM32U585 SAES API usage pattern. Reference implementations
from other hardware wallets / secure-provisioning frameworks are
useful.

---

### Prompt C — Side-channel landscape for SLH-DSA on Cortex-M33

**Context:** See section 3 trade-off #1 — our seed transits STM32
SRAM during signing. The signing algorithm is SLH-DSA-SHA2-128f
(migrating to SHA2-192f for production). The chip has hardware AES
(SAES) and PKA, but SLH-DSA is pure hashing (thousands of SHA-256
invocations per signature). The `slh-dsa` crate runs at `opt-level=3`
with whatever its upstream constant-time story is.

**Research question:**
What side-channel attacks (power, EM, cache, timing, μarch) have been
demonstrated or are theoretically plausible against hash-based
signature schemes (SPHINCS+ / SLH-DSA) on ARM Cortex-M33-class chips?

Specifically:

1. Does the published academic literature include practical SLH-DSA
   SCA key-recovery attacks? If so, what are the noise thresholds
   (number of traces, signal-to-noise ratios, distance constraints)?
   If not, what's the closest analogue (SPHINCS-variant attacks,
   generic hash-based-sig attacks, WOTS chain extraction)?
2. Which specific operations within an SLH-DSA signature are the
   most leak-prone? (Candidates: FORS leaf computation exposing SK
   bits; WOTS chain walks exposing step counts; HT layer transitions;
   PRF evaluations consuming the master seed.)
3. Is the SHA-256 hardware accelerator on STM32U585 (HASH peripheral)
   SCA-hardened? If we route SLH-DSA's hashing through it instead of
   software SHA-256, does that eliminate the main leak surface or
   just move it?
4. What's the realistic signature cap per device before SCA traces
   make key recovery feasible? (Our design rotates the main signer
   every ~2^20 signatures; is that already too many?)

Deliverables: a catalogued threat list with severity + mitigation
per item, plus a specific recommendation on whether migration to
SHA2-192f (roughly 2× signing time, 2× signature size) meaningfully
improves the SCA posture or is orthogonal.

---

### Prompt D — USB stack hardening for a USB-C-only hardware wallet

**Context:** The device exposes USB OTG FS on USB-C as its ONLY host
interface. No UART, no BT, no NFC. The USB stack today is custom:
Ledger-compatible APDU framing over HID for compatibility with
existing wallet-host software, plus a custom PQSigner-native protocol
for our own companion app (`docs/usb-protocol-v2.md`). The host
software running on the user's computer is not trusted — it's
potentially the primary attack vector.

**Research question:**
Audit the known attack surface of USB-stack implementations on
STM32 Cortex-M MCUs and recommend hardening for our situation.

Specifically:

1. Known CVEs and proof-of-concept exploits against STM32 USB
   peripherals (STM32Cube USB libraries, RTOS USB drivers, HID
   descriptor parsers). Focus on 2023-2025. Include buffer overflows,
   double-frees, descriptor confusion, any fault-injection-on-USB
   attacks (Colin O'Flynn's EMFI-on-USB work and descendants).
2. Which USB descriptor parsing paths are highest-risk for a custom
   stack that handles both HID and a custom vendor protocol? Where
   are the usual lurking bugs (endpoint count overflow, string
   descriptor length misparse, SETUP-stage DMA corruption, etc.)?
3. What's the minimum set of sanity checks to place between the USB
   ISR and our firmware's APDU handler to resist malformed or
   adversarial host behaviour?
4. Is there an argument for implementing USB in a separate
   co-processor (e.g. on a tiny MCU beside the STM32) with a serial
   shim, to shrink the attack surface on the crypto-hosting chip?

Deliverables: a CVE catalogue with applicability notes ("this affects
our stack", "this affects STM32Cube but we don't use it", etc.), a
ranked hardening checklist, and an architectural recommendation on
co-processor USB.

---

### Prompt E — Supply-chain + provisioning attack landscape

**Context:** A PQ wallet's on-chain identity (address) is derived
from the CREATE2 hash of the bootstrap public key hash. This
bootstrap PK hash is generated at first boot via the STM32 TRNG and
stored in SE050. If an attacker swaps the SE050 between a stolen
wallet and their own at any point from manufacturing through
customer-delivery, they can compromise a user who thinks they're
receiving a fresh device.

**Research question:**
Map the supply-chain + provisioning threat model for a hardware
wallet that uses SE050 + OPTIGA in a TrustZone STM32U585, shipping
through conventional retail/e-commerce channels, and recommend a
provisioning + attestation protocol that defeats each class of
attacker.

Specifically:

1. What's known about counterfeit STM32U5 supply in 2024-2025?
   Are there reports of clones (GD32/CS32/APM32 style) in the U5
   family yet, or only older F/L-series? What boot-time probes
   reliably detect clones?
2. NXP offers a cert chain from SE050 UID up to an NXP root CA.
   How reliable is this for anti-clone? What's the threat model for
   SE050 extraction + re-implantation in a different physical wallet?
3. Same question for OPTIGA Trust M cert chain.
4. What do Ledger, Trezor, Coinkite, Foundation etc. actually do at
   provisioning to attest "this is a genuine factory-sealed device"
   to a customer opening the box? What failure modes have been
   discovered in those schemes (historical + 2024-2025)?
5. Given our dual-SE architecture, is there an additional attestation
   advantage from cross-binding SE050-UID + OPTIGA-UID + STM32-UID
   in a signed manifest that must match at every boot?

Deliverables: a ranked attacker list (opportunistic re-seller;
sophisticated interdictor; nation-state with factory access), the
attestation protocol that defeats each, and a specific
"box-opening" user ceremony that demonstrates genuine-ness to the end
customer without requiring them to run an independent tool.

---

## 8. Style guidance for research output

- **Cite specific document sections** (RM0456 §11, AN5342 §4, ES0499
  §2.2.x, NXP UM11225, Infineon documentation) — not just "per ST
  documentation." If you can't find a primary source for a claim, say
  so.
- **Flag hallucination-prone content.** If you're citing an app-note
  revision number, datasheet page number, or CVE ID and you're not
  sure of the exact value, prefer "per AN5342" over "AN5342 Rev 8 §4.1
  p.32". We'd rather not have to verify every number.
- **Say "I don't know"** on questions that aren't answerable from
  public sources. Better than guessed facts that get compiled into
  firmware.
- **Concrete code / register values** where the answer is
  implementable. Hand-wave answers ("use double-glitch resistance")
  without specifics are not useful.
- **Check architecture before giving advice.** If a recommendation
  requires us to "move signing to the secure element," that's wrong
  for our setup — the SE can't do PQ. Read the trade-offs section.

## 9. File map for navigating the repo

| Concern | Path |
|---|---|
| This briefing | `docs/ai-research-briefing.md` |
| Threat model + architecture | `README.md`, `docs/architecture.md`, `CLAUDE.md` |
| Brownout hardening (5-stage plan) | `docs/brownout-hardening.md` |
| SE050 PIN-lockout factory reset | `docs/se050-factory-reset.md` |
| SE050 native UserID PIN design | `docs/se050-userid-pin-auth.md` |
| Side-channel + FI hardening reqs | `docs/HARDENING.md` |
| Work backlog + provisioning TODOs | `docs/work-todo.md` |
| ERC-4337 wallet contract | `contracts/smart-wallet/src/` |
| Secure world entry | `secure/src/main.rs` |
| NSC gateway (6 commands) | `secure/src/nsc/` |
| Crypto primitives + SLH-DSA derivation | `secure/src/crypto.rs` |
| Dual-SE coordination | `secure/src/dual_se.rs` |
| SE050 driver (T1oI2C + SCP03 + APDUs) | `secure/src/se050/` |
| OPTIGA Trust M driver | `secure/src/optiga/` |
| Reset-cause classification (Stage 1) | `secure/src/reset_cause.rs` |
| Verified flash writes (Stage 1) | `secure/src/hw/flash.rs` |
| TrustZone SAU/GTZC config | `secure/src/sau.rs` |

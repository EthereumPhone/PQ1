# PQSigner OS — Threat Model

**Status:** living document. Updated 2026-05-12.
**Scope:** the full firmware + hardware product. STM32U585 (Cortex-M33, TrustZone) host MCU, Infineon OPTIGA Trust M V3 + NXP EdgeLock SE050 secure elements, on-chain ERC-4337 v0.6 smart wallet (`PQSmartWallet`).
**Companion documents:** `docs/HARDENING.md` (hardening requirements — *what* we do), `docs/production-security.md` (research synthesis — *which mitigations* we landed and why), `CLAUDE.md` invariants (the non-negotiable contracts), this doc (*who* attacks *what*, with *what capability*, and how each attack is stopped or accepted).

This document is **falsifiable by design.** Every claim of the form "attacker X cannot do Y" can be tested by an attacker performing X and observing Y. The pre-production sections list known regressions plainly — anything labelled "PROD-INVARIANT" must hold on a shipping unit; anything labelled "PRE-PROD-CAVEAT" is a knowingly-live regression that production CI gates against.

---

## 1. Methodology

We use STRIDE-shaped surface enumeration but the framing is deliberately attacker-capability-driven rather than threat-type-driven. The reason: a wallet's job is to refuse a specific list of attackers along a specific list of dimensions, not to chase a generic spoofing/tampering taxonomy that doesn't carve at the joints of an embedded PQ stack.

For each attack we record:

- **Surface** — the data path or component the attacker reaches.
- **Adversary tier** required (T0…T7, defined in §4).
- **Mitigation** — the in-tree mechanism(s) that defeat it, with code-path references.
- **Empirical verification** — the test or measurement that backs the claim.
- **Residual risk** — what's still possible if every mitigation lands.

Attacks the design *does not* defend against are written down in §10 with the same rigour as the ones it does. A threat model that omits its scope boundary is propaganda.

---

## 2. Assets and Sensitivity Classes

| Class | Asset | Where it lives | Loss impact |
|---|---|---|---|
| **S0 — fund-equivalent** | `bip39_seed` (64 B), reconstructed `entropy` (32 B), `masterSk` C10 (96 B working, ~ 4 KB derivation state), `slotSk` C10, `master_secret` and `slot_master` derivation pivots | OPTIGA + SE050 (XOR split at rest); S-SRAM transiently during signing | Total: attacker can spend every wallet ever derived from this seed across every chain |
| **S1 — single-account-equivalent** | A single `(account_index, chain_id, slot_index)` slotSk in S-SRAM during a single signing window | S-SRAM only, ≤ 120 s after each sign | One chain's funds on one account until on-chain cap (≤ 65 536 spends) is reached |
| **S2 — channel-equivalent** | OPTIGA Platform Binding Secret (PBS), SE050 SCP03 ENC/MAC/DEK, SE050 admin UserID | STM32 OTP-derived (Tier-1 DHUK) — never persisted in plaintext | Bus-snoop / channel-impersonation against this device only. Does **not** alone unlock funds — see §6 |
| **S3 — auth-equivalent** | User PIN (raw), PIN-derived auth ref values stored in OPTIGA F1D0 + SE050 UserID | SE silicon (never MCU, never NS) | Online brute-force: 10 attempts → factory wipe (see §7.4) |
| **S4 — identity-equivalent** | Per-die DHUK (factory-fused), BHK (Stage 2 planned), STM32 OTP master, factory-burnt vendor pubkey hash | STM32 silicon — DHUK only accessible via SAES, never as memory | Decap-class only; downstream wraps fail open if extracted but the on-device PIN gate (§7.4) still applies |
| **S5 — integrity-equivalent** | Firmware secure/nonsecure images, FSBL, on-chain bytecode at the deployed proxy + factory + implementation + verifier addresses, vendor C10 signing key (off-device, HSM) | Flash (FSBL: WRP1A-locked pages 0–3), on-chain CREATE2-derived addresses, vendor HSM | Persistent backdoor or substituted code path; downstream affects S0–S3 |
| **S6 — availability** | Three-way PIN counters, on-chain per-chain caps, page-123 offchain counter | MCU page 124, OPTIGA E120 LUC, SE050 UserID, on-chain storage | Brick (DoS) — funds frozen but not extracted. Note: bricking is a *defence outcome*, not an attack outcome we care about preventing |
| **S7 — privacy** | Wallet on-chain identity ↔ user, list of signed transactions, BIP-39 measurement words | On-chain (public), local OLED (transient), companion app (depends on app) | Surveillance / deanonymisation; not financial loss |

The shipping invariant is: **no attack that does not break at least one S4 asset AND the S3 asset (user PIN) AND the S5 firmware integrity reaches an S0 asset.** The dual-SE split, the three-way PIN gate, and the FI-hardened verify-before-release together encode that invariant in silicon-anchored code.

---

## 3. Trust Boundaries

A boundary is *non-trivial* when its two sides are governed by different keys, different code, different vendors, or different physical chips. Boundaries are the only places where exploitable mismatches live.

| Boundary | Crossing format | Direction(s) of trust | Code path |
|---|---|---|---|
| **B-USB** Companion ↔ device | USB HID, APDU v2 (`nonsecure/src/usb/{commands,hid,transport}.rs`) | Device trusts companion *only* for non-secret metadata (chain_id, slot_index, flags, displayed tx fields); never for secret material | NS-side parser → NSC veneer |
| **B-NSC** NS ↔ S (TrustZone-M) | CMSE `cmse-nonsecure-entry` veneers on STM32U585; shared-memory mailbox on QEMU | S **never** trusts NS pointers, lengths, or contents without validation + copy-in | `secure/src/nsc/{ptr_validate,ns_ptr}.rs`; every `cmd_*::run` copies NS buffers to S-stack before parse |
| **B-UI** S ↔ user (OLED + 2 buttons) | Trusted-path dialogs (`secure/src/ui/{confirm,pin_entry,seed_wizard}.rs`); buttons + OLED are S-owned peripherals via GTZC | User trusts what they see; S trusts only what they physically pressed | NS opinion of a button press is ignored — the S-only TIM2 inactivity timer is not reset by NS pings (§7.6) |
| **B-OPT** S ↔ OPTIGA Trust M V3 | OPTIGA Shielded Connection (TLS-PRF + AES-128-CCM-8); PBS provisioned at factory under Tier-1 DHUK-derived wrap | S trusts OPTIGA only for the `half_O` bits it returns under successful E120/F1D0 silicon-gated read | `secure/src/optiga/{shield,apdu,ifx_i2c}.rs` |
| **B-SE0** S ↔ SE050 | SCP03 (AES-CMAC + AES-CBC); admin UserID derived from OTP master via `secret_keys`; user UserID is the PIN-derived bytes | S trusts SE050 only for `half_E` bits returned under successful user-UserID read | `secure/src/se050/{scp03,apdu,t1oi2c}.rs` |
| **B-OTP** S firmware ↔ STM32 OTP | One-way SAES-CMAC(DHUK, label‖ctr) key derivation; OTP master in OTP block, vendor-pubkey hash planned | OTP is silicon-immutable post-burn | `secure/src/hw/{otp,huk,secret_keys}.rs` |
| **B-FW** Vendor HSM ↔ device | SPHINCS+C10 signature over 75-byte preimage `"PQFW_V1"‖version_be‖secure_hash‖nonsecure_hash`; vendor public key compiled into FSBL | Device trusts only payloads whose C10 sig verifies under the pinned vendor key | `fsbl/`, `fwsign/`, `fw-manifest/` |
| **B-CHAIN** Device ↔ on-chain wallet contract | C10 signature wrapped in `SignatureWrapper(uint256 ownerIndex, bytes c10Sig)`; per-chain `slot_entropy = sha256(slot_master‖"slot_entropy"‖chain_id_be8‖slot_index_be4)` so the slot keypair is chain-bound | Contract verifies the C10 sig stateless against the wrapper's `ownerIndex` lookup; trust crosses only via the wallet's own storage | `contracts/smart-wallet/src/{PQSmartWallet,PQSmartWalletFactory,verifiers/SPHINCsC10Asm}.sol` |
| **B-FAB** Factory ↔ device (provisioning) | One-shot: SE050 PUT KEY rotation, OPTIGA PBS install + E140 `LcsO=Operational` lock, STM32 OTP master burn, RDP0 → RDP1 → RDP2 sequence | Trust is anchored once; subsequent boot-time attestation (§7.11) re-verifies | Two-stage RDP flow in `docs/production-security.md §2.2` |
| **B-TZ-S** S code ↔ S code (privilege tiers) | **PLANNED** — Trezor-style MPU banking + secure-privileged/secure-non-privileged SAES key tiers. Currently absent: a bug in any S-world code can call `secret_keys::derive_into{,_bhk}` directly | Within S, one privilege level today | `docs/trezor-comparison.md §3.2` — tracked, not yet landed |

Every boundary either has a cryptographic authenticator on each side, a hardware-enforced permission, or both. Boundaries with neither (e.g. B-UI button press) are sized to be self-evident to the user (you physically pressed a button — there is no impersonation surface inside the S-only TIM-driven timer).

---

## 4. Adversary Tiers

Capabilities stack: a Tn attacker has every capability of T₀ … T_{n−1}. We do **not** define "T-everything" — different attacks need different tiers, and the design's security claim is exactly which tier each S-class asset survives.

### T0 — Remote / software only
No physical access. Can run any code on the companion host, MITM the USB link, supply arbitrary APDUs, supply arbitrary on-chain data, MITM the bundler / paymaster, supply malicious chain RPC responses, run unlimited offline computation on harvested signatures and on harvested traffic.

Models: rogue companion app, supply-chain-compromised npm package on the dapp side, hostile mempool observer, a quantum-equipped harvester collecting USB traffic and on-chain calldata for later analysis.

### T1 — Casual physical (powered-off device)
T0 + has the device in hand for hours, powered off; can connect USB, plug into a strange charger, push buttons. No bench equipment, no soldering, no opening.

Models: stolen wallet from a coat pocket; a customs officer with cable but no toolchain; a roommate with a laptop.

### T2 — Bench attacker (powered-on, no FI)
T1 + can power the board, scope I²C/USB lines, attach a logic analyzer, JTAG/SWD probe (defeated by RDP-2 in prod), pop the case, drop in alternate firmware to NS pins, swap a passive component, remove and replace a chip with a hot-air station.

Models: chip-swap supply-chain attack mid-transit; an evil-maid who can revisit the device repeatedly while powered; a forensic-lab opponent below the cost of fault injection.

### T3 — Fault injection (FI) / side-channel analysis (SCA)
T2 + voltage glitch, EMFI rig (ChipShouter / SiliconToaster), laser FI on a decapped die, Rowhammer-on-bus equivalents; horizontal/vertical DPA on the power rail; EM SCA against the package; TVLA / template SCA on harvested traces.

Models: Ledger Donjon March 2025 Trezor Safe 3 voltage-glitch; Masaryk U Simonik thesis 76% PIN-glitch on STM32U5A9; Saarinen "SLotH" CRYPTO 2024 on SLH-DSA PRF.

### T4 — Invasive silicon (decap + microprobe)
T3 + chemical/laser decap, FIB, SEM, microprobing. Tens to hundreds of thousand-dollar budget, destroys the unit, single shot per device.

Models: state-actor lab attempting OTP master extraction or DHUK readout.

### T5 — Coercion (rubber-hose / shoulder-surf)
Attacker physically present, can compel user to enter PIN, observe entry, threaten until cooperation.

Models: $5-wrench, drug interrogation, shoulder-surf in coffee shop.

### T6 — Supply chain
Capability between factory and unboxing: substitute firmware, substitute chips, intercept first-boot, ship a clone with valid-looking attestation, compromise the factory HSM or provisioning station.

Models: customs intercept; compromised contract manufacturer; rogue insider with provisioning-station access; vendor HSM extraction.

### T7 — Cryptographically-relevant quantum computer (CRQC)
Can run Shor on captured classical public keys / signatures (no impact here — there are no classical signatures in the trust path) and Grover against symmetric primitives with 2× root speedup.

Models: a near-term CRQC harvested everything from the day-one launch; a far-future CRQC against decade-old captured traffic.

---

## 5. Security Claims (the falsifiable contract)

Each claim is the conjunction of all attacks an attacker must execute to violate it. These are the load-bearing statements of the whole product.

**Claim 1 — Single-chip break is harmless.**
> An attacker who fully owns *one* of {OPTIGA, SE050} but not the other and not the MCU recovers **zero** bits of `bip39_seed`.

Mechanism: XOR entropy split. `half_O` and `half_E` are independent random; `entropy = HKDF(half_O XOR half_E)`. A break on either chip yields one uniformly-random 32-byte string. Falsifiable by extracting one chip's plaintext and confirming statistical independence from the seed.

**Claim 2 — DHUK / BHK leak is not fund-extracting.**
> An attacker with a Tier-1 DHUK extraction (or future BHK extraction) gains the SE050 admin UserID and the OPTIGA PBS for *this device only*. They can **brick** the device by issuing admin `DELETE` against `half_E`. They **cannot READ** `half_E` — the user-PIN gate is enforced in SE silicon, not by the encrypted channel.

Mechanism: SE050 PIN policy template (`apdu::build_policy`, `se050/apdu.rs:339-365`) splits ACs across two entries — user has `READ|WRITE|DELETE|REQUIRE_SM`, admin has only `DELETE|REQUIRE_SM`. Falsifiable by `make se050-admin-extract-attempt-e2e` — already validated 2026-05-11 on B-U585I-IOT02A board #1, ST-LINK SN `0029…3838` (see `docs/production-security.md §2.6 "Empirically validated"`). On OPTIGA, `half_O` sits under `Auto(F1D0)` AuthRef with E140 (PBS) authenticating only the channel — the read AC is a different mechanism with the same property; an analogous E2E for OPTIGA is on the list.

**Claim 3 — PIN brute force costs at most 10 wrong attempts before factory wipe.**
> Online brute force is hard-capped at 10 wrong PINs against the strictest counter of the three (MCU page 124, OPTIGA E120 LUC, SE050 UserID). Offline brute force against any persisted PIN representation is structurally impossible — the PIN never leaves SE silicon.

Mechanism: three-way lockstep + `nsc::gated_unlock` pre-commit + `factory_reset_admin` on strike #10. Falsifiable by `make pin-gate-hw-counter-e2e` and `make pin-gate-wipe-e2e`.

**Claim 4 — Forged C10 signature requires breaking SPHINCS+ or stealing the seed.**
> No signing path admits a signature whose owner-key was not derived from a successful unlock against this device's silicon-anchored entropy halves. EIP-1271 path forbids `ownerIndex == 0`; Type 1 path bumps `bootstrapUses` regardless of revert; Type 2 path bumps `slotUses[i]`.

Mechanism: `validateUserOp` ABI-decodes `SignatureWrapper(uint256 ownerIndex, bytes signatureData)` and dispatches stateless to `c10Verifier` (`SPHINCsC10Asm.sol`). The verifier is single — no fallback verifier path, no toggle. Verify-before-release on the device side double-checks the just-produced signature under FI-hardened sentinels (`crypto::c10_sign_verified*`).

**Claim 5 — Cross-chain replay is structurally impossible.**
> A C10 signature produced for `(account_index_A, chain_id_A, slot_index_A)` does not verify against `(account_index_A, chain_id_B, slot_index_A)`.

Mechanism: slot keys are chain-bound — `slot_entropy = sha256(slot_master‖"slot_entropy"‖chain_id_be8‖slot_index_be4)`. Different `chain_id` ⇒ different sk ⇒ different pkRoot ⇒ on-chain `ownerAtIndex[slot_index]` differs ⇒ verify fails. CREATE2 still pins to the same address on every chain because the address depends only on `(masterPkSeed, masterPkRoot)` and the bootstrap key is chain-agnostic.

**Claim 6 — On-chain cap is monotonic and unresettable.**
> `bootstrapUses < 65_536` and `slotUses[i] + offchainSigCount[i] < 65_536` are invariants of contract storage with no `reset*` / `increase*` path. Exhausted chains stay frozen.

Mechanism: `PQMultiOwnable` (ERC-7201 storage) + no admin path in `PQSmartWallet`. Falsifiable by attempting to author a UserOp post-cap and observing it revert.

**Claim 7 — Quantum harvester cannot recover the seed.**
> A CRQC adversary who recorded every byte of USB traffic, every byte of I²C traffic, every byte of on-chain calldata and every block since launch recovers **zero** seed bits.

Mechanism: every primitive in the trust path is post-quantum.
- Signing: SPHINCS+C10 (hash-based, no number-theoretic assumption, no quantum speedup beyond Grover-on-hash).
- Inner channel wraps (planned): ML-KEM-1024-encapsulated + AES-256-GCM-sealed before SE channel; today the SE channels carry plaintext halves under classical AEAD, which is a PRE-PROD-CAVEAT (§9.1).
- Symmetric: AES-256, SHA-256/512, HMAC-SHA256, HKDF-SHA256, PBKDF2-HMAC-SHA512 — all with key sizes sized so Grover leaves ≥ 128-bit effective security.
- Address derivation, EVM hashing: SHA-256 and Keccak-256 — both quantum-resistant under Grover-only.

Until the ML-KEM-1024 inner wrap lands, the residual is "a CRQC adversary who captured the OPTIGA Shielded Connection TLS-PRF/CCM-8 handshake or SE050 SCP03 handshake from this device's lifetime traffic can in principle decrypt the bus and read the relevant entropy half." This is the residual Claim 7 acknowledges.

**Claim 8 — Firmware-update path admits only payloads signed by the pinned vendor key.**
> A FW-update commit only succeeds if the C10 signature over `"PQFW_V1"‖version_be‖secure_hash‖nonsecure_hash` verifies under the FSBL-pinned vendor public key. Downgrade is rejected by a monotonic counter.

Mechanism: `fsbl/` immutable bootloader, `fw-manifest/` verify chain, OPTIGA monotonic counter (E1E0) cross-checked at COMMIT. FSBL pages are WRP1A-locked. Falsifiable by attempting a flashing of an unsigned or downgraded blob.

**Claim 9 — Trusted UI faithfully renders signed semantics.**
> Whatever the OLED shows in a confirm screen is exactly what the signed `userOpHash` preimage commits to; the user pressing both buttons binds their consent to the displayed bytes.

Mechanism: the confirmation page renderer (`secure/src/tx/display/*`) runs in S-world, reads from the S-stack copy of the parsed UserOp, displays from S-owned OLED via S-driven SPI/I²C. The page-renderer code is what hashes into `userOpHash` (i.e. there is no second path that displays one thing and signs another). For ERC-20 the recipient symbol/decimals come from a Merkle-verified bundle (`secure/src/erc20/` checks against the firmware-baked `ERC20_DB_ROOT`); unknown contracts fall through to "⚠ BLIND SIGNING". For ZK clear-signed paths, the string is signed by a Groth16 proof that the calldata semantically equals the string. Falsifiable by constructing a malicious bundle and observing rejection.

---

## 6. Cross-cutting Defence Architecture

Three patterns appear across every attack. They are the spine of the design.

### 6.1 Dual-residency rule (the XOR split)
*Every fund-equivalent secret must require both of {OPTIGA, SE050} to recover. Neither chip alone reveals any bit.* This rule is enforced at provisioning (`dual_se::provision`) and at every unlock (`reconstruct_entropy = HKDF(half_O XOR half_E)`). It is what reduces the attack from "compromise one chip" (well-precedented in the literature — Ledger Donjon, Trezor Safe 3) to "compromise two chips from two vendors of two architectures simultaneously."

### 6.2 PIN gate in silicon (the three-way lockstep)
*PIN compare always happens inside SE silicon, never in MCU code.* MCU page 124 is an additional FI-hardened pre-commit counter that fails-closed on power glitch mid-verify. SE050 UserID and OPTIGA F1D0 (bound to E120 LUC) are silicon-monotonic. `CMD_GET_REMAINING` returns the minimum; on any one reaching `MAX_ATTEMPTS=10`, `factory_reset_admin` wipes both SEs and page-124. This makes every attack against the PIN an online attack — there is no offline ciphertext or hash to grind.

### 6.3 Verify-before-release with double-compute (the FI guard)
*Every Type 1 / Type 2 signature is computed twice on disjoint SRAM regions, the two outputs are compared in constant time, and the signature is released only on byte-equal match plus a verify-after-sign hash check.* RFC 9814 §5 explicitly notes that verify-after-sign alone is insufficient for SLH-DSA against single-fault forgery (Genêt TCHES 2023). We do **both**: double-compute closes the Genêt grafting attack; verify-after-sign closes simpler glitches. Code: `crypto::c10_sign_verified*` + FI sentinels in `secure/src/fi.rs`.

These three patterns mean: every named attacker tier must beat *both* a silicon barrier and a code barrier to reach an S0 asset. There is no single-failure point in the system above the silicon-physical layer.

---

## 7. Attack Surfaces and Per-Surface Defences

### 7.1 Seed at rest

| Attack | Tier | Mitigation | Residual |
|---|---|---|---|
| Flash dump of MCU | T2 | The seed never persists on MCU flash. `entropy` is reconstructed in S-SRAM at unlock and zeroized on lock/timeout/tamper/brownout. | Nothing recoverable from MCU flash dump |
| Flash dump of OPTIGA (decap) | T4 | Yields only `half_O` — XOR-independent of `half_E` (Claim 1) | `half_O` alone is uniformly random |
| Flash dump of SE050 (decap) | T4 | Yields only `half_E` — same | `half_E` alone is uniformly random |
| Both chips decapped | T4 + T4 | XOR halves recoverable; user PIN gate still applies. SE050 user-UserID read AC blocks `half_E` even with admin auth (validated, Claim 2). OPTIGA F1D0 AuthRef gate blocks `half_O` similarly. So even decapping both chips, the attacker still needs to *use* the chip with its silicon-enforced PIN gate. | Realistic state-actor capability; cost dominated by getting past two different silicon PIN gates each capped at 10 attempts |

### 7.2 Seed in transit (SE channels)

| Attack | Tier | Mitigation | Residual |
|---|---|---|---|
| I²C bus snoop (logic analyzer on traces) | T2 | OPTIGA Shielded Connection (TLS-PRF + AES-128-CCM-8, PBS-keyed); SE050 SCP03 (AES-CMAC + AES-CBC, ENC/MAC/DEK rotated per-device at factory) | Classical-AEAD-only today; planned ML-KEM-1024 inner wrap will leave only PQ-ciphertext on the bus (§7.14) |
| MITM with replayed handshake | T2 | SCP03 mutual auth + Shielded Connection's PBS-anchored TLS-PRF; freshness nonce on each session | None known once factory-default keys are rotated (PRE-PROD-CAVEAT until factory provisioning lands — §9.2) |
| Bus desync / glitch the SE response | T3 | Channel MAC fails ⇒ APDU rejected; tamper response invokes lockout | Untested at production hardness |
| Channel key extraction from MCU OTP | T4 | DHUK only accessible via SAES (peripheral, not memory); BHK uplift (Stage 2) further hardens to "key must be *used* on this specific device" | A decap-class extraction of DHUK is the entry to the residual of Claim 2 — bricks possible, funds not extractable |

### 7.3 Seed in use (S-SRAM during signing)

| Attack | Tier | Mitigation | Residual |
|---|---|---|---|
| Cold-boot attack on SRAM | T2 | Inactivity timeout (120 s) on S-only TIM; `zeroize::ZeroizeOnDrop` on every secret type with compiler fences (`zeroize` crate's IR-level fences, not `core::hint::black_box`); on lock the whole `master_secret` + `SLOT_CACHE` are wiped | The 120-s window is a UX concession. A T3 attacker hitting the window with a freezer trick is the residual; tightenable to e.g. 30 s |
| Read S-SRAM from NS world | T0 (firmware) | GTZC TZSC marks Secure SRAM secure; SAU regions enforce; MPU regions enforced in both worlds | **PRE-PROD-CAVEAT** §9.3: TZSC config currently regressed — see CLAUDE.md "Pre-Production Caveats" |
| DMA-master into Secure SRAM from NS | T0 | All DMA controllers blocked unless their instance is Secure (per HARDENING §4.1) | Pending TZSC restore per §9.3 |
| Bus-snoop the SAES output during signing | T3 | SAES outputs DHUK-keyed values inside the peripheral; never as a bus-visible byte | EM SCA of the SAES is research-relevant; consumption mask (TIM2 CH1 PWM, `hw/consumption_mask.rs`) randomises the power footprint |
| Side-channel on the SPHINCS+C10 PRF | T3 | OptRand mandatory: 16-byte fresh per-signature randomness from STM32 TRNG breaks chosen-message PRF recovery (Saarinen SLotH defence) | Software masking on the SHA-256 hot loop is a hardening-pass item; HASH peripheral has no DPA resistance per UM3370 |

### 7.4 PIN guessing

| Attack | Tier | Mitigation | Residual |
|---|---|---|---|
| Online brute force (USB-driven) | T0 / T1 | Three-way lockstep, 10-attempt hard cap → factory wipe | At most 10 attempts before destructive lockout |
| Offline brute force against stored representation | — | No stored PIN representation exists outside SE silicon; the SE silicon compares constant-time + decrements its own counter | Structurally impossible |
| Power-glitch mid-verify to skip the counter bump | T3 | `gated_unlock` pre-commits the counter bump to MCU page 124 *before* the SE driver call; fail-in pattern (`if remaining != 0, continue; else wipe`); FI-hardened complement-storage on the success flag | Untested against state-actor FI; ITAMP9 (crypto-peripheral fault) wired (planned) catches SAES/PKA glitches |
| Shoulder-surf + force device unlock | T5 | Architecturally out of scope (§10.1) | Coercion defeats every PIN-gated system |
| Replay a captured authenticated channel | T2 | Each SCP03 / Shielded Connection session has fresh handshake; no replay window | None |

### 7.5 NSC gateway (NS → S boundary)

The 18 gateway commands (`CMD_GET_REMAINING`, `…SIGN_USEROP`, `…SIGN_OFFCHAIN`, `CMD_FW_*`, etc.) are the only legitimate way for NS code to influence S behaviour. Every command surface is treated as fully hostile NS input.

| Attack | Tier | Mitigation | Residual |
|---|---|---|---|
| NS supplies a pointer into Secure memory to trick S into reading its own SRAM into an "input buffer" | T0 (firmware) | `NsPtr<T>` typestate validates pointer ranges against NS regions only; failure returns `NscStatus::InvalidPtr` before any deref | Bug in `ptr_validate` is a CVE class — fuzzer corpus is a tracked gap (`docs/trezor-comparison.md §2.4`) |
| TOCTOU — NS races to mutate the buffer after S validates but before S reads | T0 | Every cmd handler copies NS buffers to S-stack before parse | Untested under adversarial NS — fuzzer would catch missed paths |
| Length-confusion — NS lies about a length field to over- or under-read | T0 | Each parser validates length against the declared wire-format (e.g. `data_len ≤ 4096`) before any other byte | `data_len` is `u16 BE`, fits any sane MAX |
| NS spams gateway to drain entropy / battery | T0 | Inactivity timer is S-only; NS pings do NOT reset it. Rate limiter on USB OUT (`docs/production-security.md §2.4`) — planned | Battery drain is not a fund threat |
| NS panics S code via crafted input | T0 | `#![deny(clippy::indexing_slicing)]`, custom panic handler that zeroizes secrets before halting; every NSC entry returns `NscStatus` not Rust `Result` so panics cannot escape | Persistent panic = brick (DoS) — not fund-extracting |
| NS exploits a heap | — | Structurally impossible: `#![no_std]`, no allocator, no `Vec`/`Box`/`String` | None |

### 7.6 Trusted UI / display deception (blind-sign or display-vs-sign mismatch)

The single biggest attack class against hardware wallets historically: the device signs X while displaying Y. Most exploits work by giving the device unfamiliar calldata that bypasses the display pipeline.

| Attack | Tier | Mitigation | Residual |
|---|---|---|---|
| Companion supplies forged calldata; device shows a friendly string and signs malicious bytes | T0 | The string and the signed `userOpHash` are derived from the *same* S-stack copy. The render path *is* the hash path. | A *parser* bug that decodes one way and displays another is the residual; covered by typed-call ABI tests + EIP-712 vectors in `secure/src/tx/eip712/{cowswap,safe}/` |
| ERC-20 with a spoofed token contract address | T2 (chain) | ERC-20 metadata bundle is Merkle-verified against the firmware-baked `ERC20_DB_ROOT`; unknown tokens fall through to "⚠ BLIND SIGNING" warning | Unknown contracts still sign — user must reject blind-sign or use clear-sign |
| Hostile dapp tricks user into clear-signing wrong semantics | T0 | ZK clear-sign Groth16 proof: the string is cryptographically certified to be a faithful ABI interpretation of the raw calldata. VK pool is Merkle-rooted into S-flash, so even a compromised NS cannot substitute a malicious VK | Per-protocol — today Aave V3 supply; expansion is a feature-add, not a security gap |
| NS fakes a "user pressed both buttons" to S | T0 (firmware) | The confirm dialog reads buttons via S-owned GPIO; NS cannot drive the GPIO. The inactivity timer is S-only TIM-driven; NS pings do not reset it. | Tamper of S-owned GPIO is a T2+ surface |
| NS races / spoofs the OLED to show a friendly screen | T0 | OLED bus (SPI for SSD1306 variant) is S-owned via GTZC | Pending TZSC restore (§9.3) |
| EIP-1271 path used to authorise arbitrary action (Replay against a different chain or wallet) | T0 | EIP-1271 verifier nests the raw hash via Solady EIP-712 with `chainId` and `address(this)` baked in; bootstrap key (`ownerIndex == 0`) forbidden on this path | Mismatch between companion's wrapping and on-device wrapping would refuse to validate — handler hashes the same way |

### 7.7 Firmware integrity (boot)

| Attack | Tier | Mitigation | Residual |
|---|---|---|---|
| Reflash NS or S image with a malicious one | T2 | FSBL verifies SPHINCS+C10 sig over the 75-byte preimage against the pinned vendor key; only highest-version valid A/B slot is selected | Pending: `FLASH_OTP_BLOCK_VENDOR_PK_HASH` (Trezor §1.2 pattern) to bind FSBL to a specific vendor key under RDP-2 regression |
| Substitute the FSBL itself | T2 | FSBL pages 0–3 are WRP1A-locked; runtime firmware cannot write them | Pre-RDP-2 access can replace FSBL — this is exactly the supply-chain class (§7.11) |
| Downgrade to a vulnerable older firmware | T2 | OPTIGA monotonic counter (E1E0, Conf(0xE140)-protected) rejects `fw_version < counter`; STM32 OTP rollback fuses as the silicon-anchored layer | None below the OTP fuse budget |
| Boot a substituted image with valid old vendor sig | T2 | The vendor key is one and only one; rotating would require a vendor-key migration design we have not built | Vendor-key compromise = full break (§10.5) |
| Run a debug image with `debug-log`/`e2e-test` on a production unit | T2 | `compile_error!` fences in `nsc/mod.rs` and the `saes-self-test` runner; CI gates production on these flags OFF; user-visible measured-boot 8-BIP-39 words diverge for any feature-flag flip | Pending: vendor-pk-hash OTP lock as a second wall against feature-flag-confusion-by-reflash |

### 7.8 Firmware update channel

Each update arrives as a streaming `BEGIN → CHUNK* → COMMIT` over `CMD_FW_*`. PIN unlock is required on every command. The preimage is intentionally minimal — `"PQFW_V1" || fw_version_be || secure_hash || nonsecure_hash` — so any auditor can reconstruct it from `(version, secure.elf, nonsecure.elf)` alone. There is no manifest parser in the signed preimage.

| Attack | Tier | Mitigation | Residual |
|---|---|---|---|
| Inject a chunk mid-stream | T0 | Chunks accumulate into staging area; COMMIT verifies SHA-256 of staged image against the signed hashes before any write to active flash | None |
| MITM the update bytes | T0 | Sig binds to `secure_hash` and `nonsecure_hash` — bit-flip of any byte fails verify | None |
| Replay an old signed update | T0 | OPTIGA monotonic counter (E1E0) rejects | None below decap-of-OPTIGA |
| Glitch the COMMIT verify | T3 | FI sentinels on the verify pass; double-checked verify; ITAMP9 (planned) catches crypto-peripheral fault | Untested at production hardness |
| Brick by mid-update power loss | T2 (accidental) | A/B slot model: COMMIT only ever activates a slot whose verify passed; the other slot is unchanged | Brownout hardening Stage 2 closes the BOR + IWDG + ECC + PVD + TAMP defaults gap |

### 7.9 Fault injection (FI)

The Masaryk U Simonik 2024/2025 thesis (76% PIN-glitch on STM32U5A9, same Cortex-M33 family as ours) means we *do not* treat the U5 as glitch-immune. Defence stacks per `docs/production-security.md §2.1`.

| Attack | Tier | Mitigation | Residual |
|---|---|---|---|
| Voltage / EMFI glitch to skip the PIN-check branch | T3 | Fail-in pattern (`if remaining != 0, continue; else wipe`); MCU page-124 pre-commit before SE driver call; FihInt complement-storage (0x1AAA_AAAA / 0x1555_5555) on `pin_verified`, `blob_cached`, `match_ok` | Tested against home-equipment glitching; not yet against state-actor lab |
| SLH-DSA single-fault grafting (Genêt 2023) | T3 | Double-compute on disjoint SRAM regions + constant-time compare; signature released only on byte-equal match | RFC 9814 §5 explicitly endorses double-compute as the only defence; verify-after-sign alone is insufficient |
| Skip the on-chain cap check via glitch (off-target) | — | The cap is enforced in Solidity at on-chain execution; the device cannot be glitched into producing a sig that the chain accepts past the cap | Chain is the authority for the cap; device-side glitch cannot loosen it |
| ITAMP-class crypto-peripheral fault (SAES/PKA/TRNG glitch) | T3 | Planned ITAMP9 enable wires SAES/AES/PKA/TRNG fault detection to `trigger_lockout_wipe()` per Trezor `tamper.c:140-166` pattern | PRE-PROD-CAVEAT: TAMP driver currently log-only — `tamp` feature flag must flip to wipe before production |
| Rowhammer-on-bus equivalents | T3 | SRAM2/SRAM3 ECC option bytes (Stage-2 brownout hardening) | Pending option-byte flip on factory line |
| Random-delay glitch sentinel (`wait_random` style) | T3 | Planned — Trezor `random_delays.c:186-202` pattern with the double-invariant `i + j == wait` under volatile pair | Tracked in `docs/trezor-comparison.md §2.6` |

### 7.10 Side-channel analysis (SCA)

`Saarinen "SLotH" CRYPTO 2024` reports catastrophic horizontal-DPA leakage of `PRF(SK.seed)` on unprotected Cortex-M33. The U585 HASH peripheral provides **zero** DPA protection (per ST UM3370) — it's a timing / performance accelerator, not an SCA defence.

| Attack | Tier | Mitigation | Residual |
|---|---|---|---|
| Horizontal DPA on signing power trace to recover `SK.seed` | T3 | OptRand mandatory — 16-byte fresh per-signature randomness breaks chosen-message PRF recovery; WOTS+/FORS shuffling (Fisher-Yates, TRNG-seeded) breaks trace alignment; consumption mask (TIM2 CH1 PWM, `hw/consumption_mask.rs`) randomises the power footprint | Software SHA-256 masking is a long-tail item; HASH peripheral has no DPA resistance |
| Template attack on SHA-256 hot loop | T3 | Same — consumption mask + OptRand + shuffling. Production C10 keygen is ~ 7 s (long SCA window); slot keygen ~ 1 s | Untested at lab hardness |
| Cache-timing leakage of secret-dependent branches | T3 | `#![deny(clippy::indexing_slicing)]`, `subtle` for constant-time compare, no secret-dependent branches in `sphincs-c10/` (audit-reviewed line-by-line) | New code touching secrets must be audited the same way; tracked as a permanent review gate |
| EM SCA from outside the case | T3 | Consumption mask + the deliberate non-determinism of OptRand; EM is harder than power for an unshielded board but possible | A skilled lab is the residual |
| Rate-limit / signature quota | T3 (mitigates) | Signing rate-limit + hard rotate after 2^16 signatures per key (on-chain cap is a belt-and-braces here) | None |

### 7.11 Chip swap, clone, and supply chain

| Attack | Tier | Mitigation | Residual |
|---|---|---|---|
| Mid-transit swap of OPTIGA | T2 / T6 | Boot-time attestation: fresh nonce → OPTIGA ECDSA-signs with `0xE0F0`, cert chains to Infineon Trust M Root CA 2; per-die UID at OID `0xE0C2` compared against factory-pinned value (planned binding manifest, `docs/production-security.md §2.5`) | PRE-PROD-CAVEAT: per-device binding manifest not yet landed |
| Mid-transit swap of SE050 | T2 / T6 | Same shape with SE050 attestation via `Se05x_API_ReadObject_W_Attst`; chipId at IDENTIFY compared against factory-pinned; **variant constraint** — only SE050 C/E/F have factory attestation certs at OID `0xF0000013`; A/B/D do not. We use C-class. | PRE-PROD-CAVEAT: per-device binding manifest not yet landed |
| Mid-transit swap of STM32 (recap'd remarked chip) | T2 | Anti-counterfeit probes — CPUID/DBGMCU_IDCODE expected r0p4/`0x482`; UID register validated (lot ASCII range, wafer < 25, not all-0/all-FF); DHUK probe via SAES against factory-recorded fingerprint; ICACHE/DCACHE Stop-mode quirk fingerprints | Tracked in `docs/production-security.md §2.5`; specific bit positions need cross-check vs ES0499 |
| Clone with valid-looking attestation from a stolen factory HSM key | T6 | Per-device binding record stored 3× (STM32 flash wrapped, SE050 object 0x10000001, OPTIGA OID 0xF1D1); SHA-256 anchor written to OTP bytes 6-37; transparency-log Merkle anchor (planned) catches devices missing from log | Until transparency log lands, a single HSM compromise can produce valid devices. Plan = SLH-DSA-128s factory manifest under M-of-N HSM ceremony |
| Pre-first-boot intercept (flash a key-exfiltrating stub, boot once to capture TRNG, restore real FW) | T6 | Defence stack: secure-boot chain + tamper-evident packaging + WebUSB box-opening ceremony at `verify.pqsigner.io` that re-verifies all three UIDs + manifest sig + firmware hash | Honest residual — first-boot self-provisioning is strictly stronger than factory-burn (vendor never holds a key), but it does require trust that "first boot" runs on signed firmware |
| Compromised provisioning station | T6 | Clean-room provisioning; HSM-backed per-device key generation; per-device transparency-log entry catches rogue runs | A compromise window taints every device that passes through it during the window |
| Chip swap **after** the user owns the device | T2 | After provisioning, each chip's UID is pinned to MCU flash; on next boot a swapped chip fails attestation → permanent lockdown | Untested in mainline boot today (boot-time attestation is planned, not landed) — PRE-PROD-CAVEAT §9.4 |

### 7.12 On-chain (smart-wallet / replay / forgery)

The on-chain contracts (`PQSmartWallet`, `PQSmartWalletFactory`, `PQMultiOwnable`, `verifiers/SPHINCsC10Asm`) are part of the trust path: a bug in the verifier is a fund-equivalent break.

| Attack | Tier | Mitigation | Residual |
|---|---|---|---|
| Forge a C10 sig that the on-chain verifier accepts | T7 | Verifier is the canonical stateless C10 verify (Yul-coded, single immutable for all three paths). Reviewed; covered by `forge test -vv`; differential-tested against the host-side Rust verifier | A novel break in SPHINCS+C10 is a research event — see §10.6 |
| Submit a Type 1 sig whose bootstrap key wasn't ever provisioned | T0 | Bootstrap pubkey is pinned in `initCode` via CREATE2 salt commitment; mismatched bootstrap pubkey ⇒ CREATE2-derived address ≠ `sender` ⇒ EntryPoint rejects | Structurally impossible at the protocol layer |
| Re-use a Type 2 sig across two UserOps (replay) | T0 | UserOpHash binds chain_id (via EIP-712), nonce (monotonic), `sender`, entryPoint, calldata. Two distinct UserOps ⇒ two distinct hashes | None |
| Use an EIP-1271 `isValidSignature` path to authorise a UserOp | T0 | `validateUserOp` ABI-decodes `SignatureWrapper` and dispatches by `ownerIndex`; the EIP-1271 view function is a different entry, returns the magic / null bytes only, never bumps counters | None |
| Authorise EIP-1271 with the bootstrap key (`ownerIndex == 0`) | T0 | `isValidSignature` explicitly rejects `ownerIndex == 0` (one-sentence guard) | None |
| Exhaust off-chain counter to roll back a slot | T0 | `executeWithOffchainCount` enforces monotonic update of `offchainSigCount[i]` + re-checks combined cap inside the execution phase | None |
| Sign EIP-1271 for a slot that was never registered (post-restore on a new chain) | T0 | Firmware-side `CMD_SIGN_OFFCHAIN` refuses if slot is unregistered for `(account_index, chain_id)`; forces a Type 1 rotation via `CMD_SIGN_USEROP` first | None |
| Cross-chain key replay | T0 | Slot keys are chain-bound (Claim 5); the same `slot_index` on a different chain yields a different pubkey | None |
| Migrate to a v0.7/v0.8 EntryPoint | — | Architecturally forbidden: same 24 words → same address on every chain depends on the v0.6 EntryPoint address baked into `initCode`, the userOpHash preimage, and the factory. If v0.6 bundlers sunset, fall back to direct EOA-bundled execution against the same wallet | Frozen by Claim 6 / Invariant #6 in CLAUDE.md |
| Bundler / paymaster front-runs to drain | — | UserOp execution semantics protect against re-ordering; paymaster only sponsors gas, cannot modify call payload | None at the protocol layer |
| MEV / sandwich attack on a transaction | T0 | Out of scope — wallet signs what user confirms. MEV is a dapp / chain-level concern, not a wallet concern | Not a fund-extraction class against the wallet |

### 7.13 USB and host-side compromise

USB is the only external interface and the primary T0 attack vector. The host is **untrusted by design** — we treat the companion app the same way a CA treats a TLS client.

| Attack | Tier | Mitigation | Residual |
|---|---|---|---|
| Malicious companion forges signing requests | T0 | Every signed payload reaches the user's eyes on the trusted UI before any signing key is touched; user must confirm via S-owned buttons. The trusted display IS the signing oracle (§7.6) | User must actually read the screen — UX residual |
| ZLP race / DWC2 TxFIFO atomicity (ES0499 §2.26.x) leaks stale FIFO data from a prior session | T0 (device side) | Driver enforces single-packet transfers (`DIEPTSIZ.XFRSIZ = DIEPCTL.MPSIZ`), no interleaving in ISR, flushes all FIFOs on USB reset (`GRSTCTL.RXFFLSH | TXFFLSH` with TXFNUM=0x10) | Confirm against ES0499 Rev 11 — research-cited sub-section numbers partially verified |
| Stuck-NS via flood of OUT reports | T0 | HID OUT rate limiter — token bucket ~200 reports/s sustained, bucket 64; NAK when empty; IWDG 2 s timeout kicks per USB transaction | Battery / DoS only |
| Buffer overflow in APDU reassembly | T0 | Bounded APDU reassembly: `4 ≤ declared_len ≤ 4096` at seq=0; 5 s timeout with buffer scrub; abort if seq=0 arrives mid-reassembly | Fuzz coverage is a tracked gap (`docs/trezor-comparison.md §2.4`) |
| EMFI on `min()` length-clamping (Colin O'Flynn WOOT 2019) | T3 | FI-resistant `fi_min` pattern (`if r > a || r > b { return min }`); post-transfer assert `DIEPTSIZ.XFRSIZ` did not exceed declared length | Production hardness untested |
| Host-side keylogger captures PIN typing | T5 (effectively) | The PIN is **never** typed on the host. PIN entry is via on-device buttons through the trusted UI dialog (`secure/src/ui/pin_entry.rs`). The host never sees a PIN byte. | None — the host is never on the PIN path |
| BadUSB injects HID keystrokes simultaneously | T1 | Device buttons are S-owned GPIO — host cannot synthesize button presses. NS code reading buttons is irrelevant since the S-only confirm dialog reads them itself | None |
| Migration to OTG_HS (which has DMA) | — | Architectural ban — we use OTG_FS deliberately so all USB data is CPU-mediated and GTZC/TZ protections apply to every byte | Tracked invariant — do not migrate |

### 7.14 Quantum (CRQC)

| Attack | Tier | Mitigation | Residual |
|---|---|---|---|
| Shor against classical signature in the trust path | T7 | None exist. All signatures are SPHINCS+C10. | None |
| Shor against SE classical channel keys captured from historical traffic | T7 | Today: SE channels (CCM-8 / SCP03) are classical AEAD with classical key agreement (TLS-PRF). A CRQC can break the channel key agreement and decrypt historical bus traffic, recovering whatever entropy half was transmitted. Planned: ML-KEM-1024 inner wrap — `half_O` and `half_E` are encapsulated + AES-256-GCM-sealed *before* the SE channel; the SE channel then carries opaque PQ ciphertext. | PRE-PROD-CAVEAT §9.1 |
| Grover against 128-bit symmetric primitives | T7 | All symmetric primitives sized so Grover leaves ≥ 128-bit effective. AES-256, SHA-256, HMAC-SHA256 all qualify | None |
| Grover-on-hash against the SPHINCS+C10 preimage | T7 | C10 is sized as SHA-256-based at the post-Grover effective level | None |
| Quantum key search against the device's per-slot `slot_entropy` | T7 | `slot_entropy` is a 256-bit SHA-256 output — quantum search effective bit-strength = 128 bits | None |

### 7.15 Physical destructive (decap, microprobe, FIB)

| Attack | Tier | Mitigation | Residual |
|---|---|---|---|
| Decap STM32 to probe OTP master | T4 | DHUK wrap of OTP-master at rest (Stage 2) raises bar; BHK (Stage 2) becomes "must keep code running on this specific device" | Tier-4 lab is the residual; cost dominated by single-shot per-device, destructive |
| Decap OPTIGA to extract `half_O` | T4 | EAL 6+ rated; without `half_E` extraction the seed is XOR-blind | Two-chip decap is the brute-force lower bound |
| Decap SE050 to extract `half_E` | T4 | EAL 6+ rated; same as above | Two-chip decap is the brute-force lower bound |
| FIB read of TAMP backup registers (BHK) | T4 | Post-Stage 2 — TAMP-BHK with `TAMP_SECCFGR.BHKLOCK` makes BHK SAES-only; FIB on TAMP backup registers is the residual surface | Tier-4, single-shot per device |

### 7.16 Coercion

| Attack | Tier | Mitigation | Residual |
|---|---|---|---|
| Rubber-hose ($5 wrench) | T5 | Architecturally **out of scope** (HARDENING §13.1) | Plain truth: no PIN-gated system survives coercion |
| Shoulder-surf during PIN entry | T5 | On-device button entry without echo; minimum PIN length; eventual progressive delay between attempts (in S-world before the SCP03 handshake) | None besides UX |
| Duress PIN / decoy wallet | T5 | Not currently implemented; architectural option per HARDENING §5.3 | If shipped, would let users hand over a low-value subset under coercion |

---

## 8. Cross-cutting Invariants (do not regress)

These are the load-bearing invariants. The numbered list mirrors CLAUDE.md "Non-Negotiable Invariants" — repeated here so the threat-model document is self-contained and so each invariant carries its threat-model justification.

1. **Dual-chip seed split.** Defends Claim 1. Defeats single-chip-vendor-class breaks (Ledger Donjon March 2025 on Trezor Safe 3 is a single-chip break; harmless under our split).
2. **Hardware PIN gating, three-way lockstep.** Defends Claim 3. Defeats software-side PIN-compare bugs (the historical mode of failure for most pre-SE wallets).
3. **E2E encrypted SE tunnels.** Defends §7.2 row 1. Defeats unaided I²C bus snoop and replay.
4. **All secrets only in TrustZone secure world.** Defends §7.5 and §7.3 row 2. Defeats every NS-side firmware compromise from being seed-extracting.
5. **One signature primitive: SPHINCS+C10.** Defends Claim 7 (no classical signature in the trust path) and Claim 4 (no second verifier to backdoor). Defeats Shor against the signing path.
6. **Bootstrap C10 keys immutable per-wallet.** Defends Claim 6 cross-chain address stability. Defeats a class of "rotate to a new key" social-engineering scams.
7. **Per-chain caps monotonic, unresettable.** Defends Claim 6 / §7.12. Defeats off-chain rollback / reset attacks.
8. **Stateless slot selection.** Defeats per-signature flash-state corruption attacks — the only per-signature flash state is the page-123 EIP-1271 counter; everything else is companion-supplied and re-derived in SRAM.
9. **Off-chain sig counter, combined cap.** Defeats EIP-1271 over-spending; defeats post-restore unregistered-slot signing.

The hardening regressions that knowingly violate one or more of these are listed in §9.

---

## 9. Pre-Production Caveats (knowingly live regressions)

Each item here is a regression we accept *only* on the bring-up branch. CI gates production builds against them.

### 9.1 ML-KEM-1024 inner wrap is not yet implemented
*Affects Claim 7 only on captured bus traffic.* Today, `half_O` and `half_E` cross I²C protected only by the classical SE channels. A future CRQC adversary who recorded the bus traffic of a device's lifetime can break the channel key agreement and read the halves. Plan: ML-KEM-1024-encapsulate + AES-256-GCM-seal each half *before* the SE channel; channel then carries opaque PQ ciphertext. Tracked in `docs/work-todo.md`.

### 9.2 Factory provisioning (per-device SCP03 + PBS) is not yet automated
*Affects Claim 2 against any device that has not been hand-rotated.* Until the two-stage RDP factory flow lands (`docs/production-security.md §2.2`), un-rotated bench boards use the NXP factory-default SCP03 keys (published in AN12436) for SE050 SCP03 and a development OPTIGA PBS. **Pre-production only.** No shipping device passes QA without the rotation ceremony.

### 9.3 TZSC peripheral allowlist is regressed to all-NS
*Affects Invariant #4.* `secure/src/sau.rs` clears `GTZC1_TZSC_SECCFGR{1,2,3}` to 0 because USB OTG FS is on AHB2 (governed by GTZC2 — base address not yet confirmed; first guess bus-faulted). I²C1 / AES / HASH / PKA / SAES / RNG reachable from NS until restored. Fix: adopt Trezor's per-peripheral S-allowlist (`docs/trezor-comparison.md §1.1`).

### 9.4 Boot-time SE attestation is not yet landed
*Affects §7.11 — chip-swap defence is provisioning-time only today, not runtime-recurring.* The full binding manifest + boot-time triple-UID verification per `docs/production-security.md §2.5` is the production gate.

### 9.5 TAMP IRQ handler is log-only
*Affects FI residual in §7.9.* `secure/src/hw/tamp.rs` currently logs on tamper events rather than invoking `trigger_lockout_wipe()`. The Trezor `tamper.c:140-166` pattern (ITAMP1-3, ITAMP5-9, ITAMP11) needs to be ported and the IRQ handler must wipe before production.

### 9.6 Debug logging may ship in this branch
`debug-log` allowed on hardware in current bring-up; `secure_log!` in the wizard; NS pre-USB register dumps; DHCSR-gated semihosting prints in `hw::hash::init_clock`. CI must gate production on `debug-log` / `e2e-test` / `mock-se` / `otp-hardcoded-master-key` / `ui-capture` OFF. The `compile_error!` fences in `nsc/mod.rs` and the `saes-self-test` runner enforce most of this.

### 9.7 Domain-separation tags are sticky-but-renamable
The tag `"sphincs-c6-v1"` is historical (was a different parameter set when written; now C10). Do not rename mid-bring-up (re-provisions every bench board); coordinated cleanup pre-launch is fine. **PROD-INVARIANT after first shipment** — once a device exists with funds, the tag is frozen forever (Invariant #6 cross-chain address stability depends on it).

### 9.8 Vendor-pubkey OTP hash lock is not yet burned
A re-flashed FSBL today could substitute a different vendor key and the device would not refuse. Defence: `FLASH_OTP_BLOCK_VENDOR_PK_HASH` per `docs/trezor-comparison.md §1.2`. Production gate.

### 9.9 MPU privilege-banking is absent
S-world has one privilege tier. Any S-world code can call `secret_keys::derive_into{,_bhk}`. The Trezor pattern (`secure_aes` exposes key-selectors at two privilege tiers + MPU `MODE_APP_SAES` band) raises the bar to "an exploitable S-world bug must also be in privileged-S, not just any-S." Hardening-pass item, not a bring-up blocker.

---

## 10. Residual Risks (out of scope / unmitigated)

The following are *honestly* out of scope. Listing them is the point — a threat model that omits its boundary is propaganda.

### 10.1 Coercion (T5)
No PIN-gated system survives a user being compelled to unlock it. Architecturally fixable only with multi-party approval (e.g. m-of-n co-signers, off-device for the rest); we do not currently ship that.

### 10.2 Two simultaneous decap-class breaks (T4 + T4)
Even with the dual-SE split, a state-actor lab that destructively decaps *both* the OPTIGA and the SE050 of the same device, defeats the silicon-anchored PIN gate inside each (10-attempt cap is per-chip per-physical-device; SE silicon PIN compare is destructive on failure), and reconstructs both halves recovers the seed. Cost: hundreds of thousand-dollar per-device, destructive. Out of scope.

### 10.3 Vendor HSM compromise (T6)
If the SPHINCS+C10 vendor signing key is extracted from the off-device HSM, an attacker can sign arbitrary firmware updates. Defence is HSM-based custody + M-of-N ceremony (planned for the binding-manifest factory key); production deployment plan must apply the same custody to the firmware-signing key. The on-device boot path verifies the signature; it has no defence against a legitimate-looking signature from the vendor key.

### 10.4 Supply-chain compromise pre-first-boot (T6)
A device intercepted between factory and unboxing, with the case opened, a different firmware flashed, booted once to capture TRNG, then restored to look factory-fresh, would be a clone with attacker-known root keys *if* the OTP master burn-on-first-boot ran under attacker firmware. Defence stack: secure-boot chain + tamper-evident packaging + WebUSB box-opening ceremony at `verify.pqsigner.io` that re-verifies all three UIDs + manifest sig + firmware hash. The defence is *not* cryptographic; it is procedural + a UX honesty layer.

### 10.5 Quantum-relevant break of SHA-256
Grover halves the effective bit strength of any preimage / hash search. We size all symmetric primitives to 256 bits so the post-Grover effective is 128 bits, which is the accepted PQ-symmetric baseline. A *novel* break of SHA-256 collision resistance or preimage resistance below √n is out of scope.

### 10.6 Cryptanalytic break of SPHINCS+C10
A novel attack on the SPHINCS+ family — beyond the well-understood single-fault grafting that we defend with double-compute — would be a research event. We track NIST PQC announcements; the C10 parameter set is the FIPS-205 round-3 finalist at our chosen security level. No known break below the parameter-set's design security.

### 10.7 MEV / front-running / on-chain ordering attacks
Out of scope of the wallet. The wallet signs what the user confirms on the trusted UI; chain-level ordering / sandwiching is a dapp / chain-level concern. Mitigation lives in dapp UX (slippage limits in calldata that the trusted UI displays correctly via §7.6), not in the wallet.

### 10.8 Privacy / deanonymisation (S7)
A passive on-chain observer can correlate a wallet's deterministic CREATE2 address across chains. The same 24 words → same address on every chain is a *feature* (recovery UX); the privacy cost is acknowledged. Mitigation must come from off-device tooling (per-tx address rotation requires breaking Claim 6, which we explicitly do not do).

### 10.9 Stuck-in-display-pipeline bugs
If a future contract uses ABI patterns the typed-call parser doesn't handle, the user sees "⚠ BLIND SIGNING" and signs at their own risk. We do not ship a typed-call parser that decodes unfamiliar ABIs into friendly strings without ZK proofs (§7.6). This is a *feature* — refusing to invent a display is safer than inventing one wrongly.

### 10.10 Bugs in our dependencies
`sphincs-c10/` is in-tree and reviewed line-by-line. `bls12_381_pka/` is a forked dependency for the ZK clear-sign path. `bip39/` is in-tree. Every external crate that touches secrets is pinned and reviewed. Despite that, "every shipped wallet vulnerability in history" is implementation bug. The honest residual is: an implementation bug in a code path we have not yet audited or that lands post-audit is the most likely failure mode. Mitigation = external audit before shipping + bug bounty + gradual rollout, per HARDENING §12.

---

## 11. Empirical Verification

These are tests that *back* threat-model claims, not just unit tests. Each is reproducible from the Makefile.

| Test | Falsifies | Status |
|---|---|---|
| `make e2e` | Gateway sign path under mock SEs in QEMU | Passing |
| `make e2e-hw` | Gateway sign path on real STM32U585 + dual-SE | Passing 2026-05-12 |
| `make pin-gate-hw-counter-e2e` | Claim 3 — three-way lockstep | Passing |
| `make pin-gate-wipe-e2e` | Claim 3 — 10-wrong factory wipe + page-124 erase | Passing |
| `make se050-admin-extract-attempt-e2e` | Claim 2 — admin can DELETE but not READ user-PIN-gated secrets on SE050 | Passing 2026-05-11 |
| `make saes-self-test-hw` | SAES driver + DHUK round-trip + 8-byte fingerprint cross-board consistency | Passing |
| `make optiga-hw-counter-e2e` | OPTIGA E120 LUC + F1D0 binding | Passing |
| `forge test -vv` (in `contracts/smart-wallet`) | Claims 4, 5, 6 on-chain | Passing |
| `cargo test -p sphincs-tz-secure --tests --release` | Pure-logic primitives, NIST PQC test vectors | Passing |
| `make test-key-speed` | DWT-timed signing bench; SCA-window characterisation | Passing |

Tests that *should* exist but don't yet:

- libFuzzer / cargo-fuzz harnesses against `parse_cmd_sign_userop_input(&[u8])` and the APDU parser (`docs/trezor-comparison.md §2.4`).
- An analogous `make optiga-admin-extract-attempt-e2e` mirroring the SE050 test for Claim 2's OPTIGA side.
- A scripted FI sweep — voltage glitch on the PIN-verify branch — even at home-equipment hardness, to characterise residual against §7.4 / §7.9.
- Zeroization-verification SRAM scan after every signing test (HARDENING §11).
- Screenshot-hash UI regression covering every confirm-dialog state, including blind-sign and ZK clear-sign paths (`docs/trezor-comparison.md §2.3`).

---

## 12. Roadmap to Production Posture

In approximate phasing — the source of truth is `docs/work-todo.md`, this is the threat-model lens on the same work.

1. **Phase 0 — Device root-key architecture (work-todo #24).** Closes the OPTIGA-PBS-firmware-hash brick (§7.7 / §9.5-related). Lands `hw/otp.rs` master + `hw/secret_keys.rs` HKDF subkeys + OPTIGA `setup_pbs_no_handshake` rewrite + `hw/huk.rs` re-root. **Landed** (Tier 1 SAES-CMAC(DHUK)).
2. **Phase 1 — Stage 2 brownout foundation (work-todo #21).** BOR/IWDG/ECC/PVD/TAMP/CSS at production defaults. Closes Masaryk-class glitch attacks (§7.9). Tracked.
3. **Phase 2 — SCA mandatory minimums (work-todo #18 P0).** OptRand + double-compute + FihInt + PIN-lockout fail-in. Closes §7.10 and §7.4. Largely landed; FihInt complement-storage pass in progress.
4. **Phase 3 — USB hardening (work-todo #19).** FI-resistant min + bounded reassembly + DWC2 errata workarounds. Closes §7.13.
5. **Phase 4 — Factory provisioning (work-todo #20).** Two-stage RDP flow + SCP03 rotation + PBS install + binding record. Closes §7.11 + §9.2.
6. **Phase 5 — Supply-chain attestation (work-todo #22).** SLH-DSA binding manifest + boot-time triple-UID + transparency log + WebUSB ceremony. Closes §9.4 + tightens §7.11.
7. **Phase 6 — ML-KEM-1024 inner wrap.** Closes §9.1; makes Claim 7 unconditional rather than conditional on no-CRQC-during-device-lifetime.
8. **Phase 7 — MPU privilege banking + vendor-pk-hash OTP lock + ITAMP9 → wipe + fuzz corpus.** Closes §9.5, §9.8, §9.9 and the listed empirical-test gaps.

Production-ship is gated on Phases 0–6. Phase 7 is a hardening pass that does not block first shipment but is required before public bug-bounty announcement.

---

## 13. Glossary and Cross-References

- **BHK** — Boot Hardware Key. 32 B of TRNG in HDP-protected flash, loaded into TAMP backup registers at boot, SAES-only after lock. STM32U585 hardware feature.
- **CMSE** — Cortex-M Security Extensions. ARMv8-M's secure-gateway / `cmse-nonsecure-entry` veneer mechanism.
- **DHUK** — Device Hardware Unique Key. Factory-fused 256-bit per-chip key in ST silicon. SAES-only access; at RDP0 is an ST-substituted constant shared across bench boards; per-die uniqueness only kicks in at RDP ≥ 1.
- **GTZC** — Global TrustZone Controller. Per-peripheral S/NS attribution on STM32U5.
- **HSM** — Hardware Security Module. Off-device vendor signing key custody.
- **LUC** — Lifetime Usage Counter. OPTIGA Trust M E120 silicon-monotonic counter, bound to F1D0 AuthRef's Execute access.
- **NSC** — Non-Secure Callable. The narrow gateway region between TrustZone-S and TrustZone-NS code.
- **PBS** — Platform Binding Secret. OPTIGA Shielded-Connection key, OTP-derived via Tier-1 SAES-CMAC(DHUK).
- **RDP** — Readout Protection. STM32 levels 0/1/2 — 2 is irreversible and disables debug.
- **SAES** — Secure AES. STM32U585 AES peripheral with hardware-key selectors (`Software`, `DHUK`, `BHK`, `DHUK^BHK`); keys never appear as bus-visible bytes.
- **SAU** — Security Attribution Unit. ARMv8-M memory-attribution to S/NS/NSC at region granularity.
- **SCP03** — GlobalPlatform Secure Channel Protocol 03. AES-CMAC + AES-CBC channel used by SE050.
- **TAMP** — Tamper / Backup-domain Anti-tamper. STM32 peripheral with ITAMP1-13 internal sources + external pins; production must wire to `trigger_lockout_wipe()`.
- **TZSC** — TrustZone Security Controller. The GTZC sub-block governing per-peripheral attribution.

Cross-references:
- `CLAUDE.md` — non-negotiable invariants, lifecycle, wire formats, key derivation.
- `docs/HARDENING.md` — hardening requirements as a checklist.
- `docs/production-security.md` — research-round synthesis with citations.
- `docs/trezor-comparison.md` — pattern audit against Trezor firmware.
- `docs/optiga-brick-postmortem.md` — concrete worked example of a class-of-failure we redesigned around.
- `docs/firmware-update.md` — FW-update threat model deep-dive.
- `docs/se050-userid-pin-auth.md`, `docs/optiga-bringup-status.md` — SE-specific design notes.
- `docs/work-todo.md` — actionable tasks tracking the roadmap in §12.

---

## 14. One-line Summary

**To extract funds from a shipping PQSigner OS device, an adversary must simultaneously break (a) the OPTIGA silicon PIN gate, (b) the SE050 silicon PIN gate, and (c) either the STM32U585 firmware integrity chain or its silicon-side OTP — each of which has its own monotonic 10-attempt destructive wipe — and must do all of this before any of the three counters strike out *or* the device's 120-second inactivity timer wipes S-SRAM, and must do it without leaving a measured-boot fingerprint that the user can see on the trusted OLED.**

If any one of those three barriers holds, funds stay.

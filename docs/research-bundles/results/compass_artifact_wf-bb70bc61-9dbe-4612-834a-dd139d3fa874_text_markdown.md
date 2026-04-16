# Trezor Safe 7 vs PQSigner OS: a dual-SE security engineering comparison

**The Trezor Safe 7 and PQSigner OS share a remarkably similar hardware skeleton — both run Cortex-M33 + TrustZone, both employ dual secure elements, and both perform blockchain signing on the MCU rather than inside an SE.** The architectural divergence is in *what* each device optimizes for: Trezor ships a polished, battle-tested classical-signing product with PQ boot-chain hardening, while PQSigner bets the entire signing path on post-quantum algorithms via ERC-4337 smart accounts. Neither dominates across all twelve dimensions. Trezor leads convincingly on UX, supply-chain attestation, physical security, firmware verifiability, and open-source maturity. PQSigner leads on quantum-resistant signing posture, seed-at-rest isolation, and native account-abstraction integration. Both have significant open problems that deserve honest disclosure.

The Trezor Safe 7 was announced October 21, 2025 at SatoshiLabs' "Trustless by Design" event in Prague, with US shipping from November 23, 2025 at $249. It is the first consumer hardware wallet to ship with the Tropic Square TROPIC01 open-architecture secure element and a hybrid classical+PQ boot chain.

---

## 1. Secure-element strategy: same pattern, different seed model

Both wallets employ a **dual-SE architecture with an STM32U5-family Cortex-M33 MCU**, but the SE selection and seed-protection model differ materially.

**Trezor Safe 7** pairs a **Tropic Square TROPIC01** (open-architecture, RISC-V IBEX core, no CC certification) with an **Infineon OPTIGA Trust M V3** (EAL6+, NDA-free but closed firmware). TROPIC01 handles PIN gating via physically irreversible one-time slots, device attestation via X.509 certificates in OTP memory, entropy generation via TRNG+PUF, and contributing a secret to the seed-decryption key derivation. OPTIGA provides an independent PIN attempt counter and a second attestation layer. Communication with TROPIC01 uses a **Noise_KK1_25519_AESGCM_SHA256** secure channel (AES-256-GCM with forward secrecy), presented at CHES 2024. The **seed itself is stored encrypted on MCU flash**, with the decryption key derived from the user's PIN combined with secrets held in both SEs via PBKDF2-HMAC-SHA256.

**PQSigner OS** pairs an **NXP SE050** (EAL6+, I²C, GP SCP03) with an **Infineon OPTIGA Trust M V3** (EAL6+, Shielded Connection using AES-128-CCM-8). Neither SE stores the seed in encrypted form on its behalf. Instead, the BIP-39 entropy is **XOR-split**: half_E on SE050, half_O on OPTIGA. The full entropy exists only in STM32U585 secure-world SRAM during an active signing window (~120s idle timeout), then is zeroized. No seed material persists on MCU flash at any time.

The architectural consequence is significant. In Trezor's model, an attacker who extracts MCU flash obtains the encrypted seed and needs SE secrets plus PIN brute-force to decrypt it. The Ledger Donjon demonstrated exactly this chain on the Trezor Safe 3 (STM32F429, March 2025): voltage-glitch MCU → extract pre-shared secret → bypass attestation → compromise device while passing all Trezor Suite checks. Safe 7's STM32U5G is resistant to this specific glitch, but the **encrypted-seed-on-MCU** model means future MCU attacks remain the bottleneck. In PQSigner's model, an MCU flash dump reveals **zero seed material** — both SEs from different vendors must be independently compromised to recover entropy. However, PQSigner's seed transits SRAM during the signing window, creating a temporal exposure window that Trezor avoids because its MCU never holds the full unencrypted seed outside of active signing either (both reconstruct the working key in SRAM).

**TROPIC01's open design** is a genuine differentiator — its RTL, RISC-V firmware, SPECT coprocessor firmware, and SDK are published on GitHub (github.com/tropicsquare). Analog IP blocks (PUF, TRNG, flash) remain closed due to third-party licensing. PQSigner's SE050 and OPTIGA both have closed-source firmware, with only public datasheets available. The trade-off: TROPIC01 lacks CC certification (Tropic Square rejects security-through-obscurity), while both of PQSigner's SEs carry EAL6+.

**Attack classes where each wins.** Trezor's open-SE model defeats attacks that exploit opaque SE firmware bugs (because the digital logic is auditable). PQSigner's XOR-split defeats MCU-flash-extraction attacks (no seed on MCU at rest). Trezor's TROPIC01 physically irreversible PIN slots defeat counter-reset attacks better than PQSigner's firmware-managed decrement-before-auth counter at OPTIGA OID 0xF1D5. PQSigner's dual-EAL6+ SEs from different vendors provide formally certified tamper resistance that TROPIC01 (uncertified) cannot claim.

---

## 2. Cryptographic algorithms diverge on the quantum question

**Trezor Safe 7** signs blockchain transactions with **secp256k1 ECDSA** (Bitcoin, Ethereum), **BIP-340 Schnorr** (Taproot), **Ed25519** (Solana, Cardano, Stellar), and **NIST P-256 ECDSA**. All use RFC 6979 deterministic nonces. These are battle-tested schemes with decades of cryptanalysis. PQ cryptography is used exclusively for internal operations: **SLH-DSA-128** (FIPS 205) for boardloader→bootloader verification, **ML-DSA-44** (FIPS 204) for device attestation certificates, and a hybrid EdDSA+SLH-DSA scheme for firmware updates. Blockchain signing remains entirely classical. Trezor's stated position is that PQ transaction signing will be enabled via firmware updates when blockchains adopt PQ verification.

**PQSigner OS** signs all transactions with **SLH-DSA-SHA2-128f** (FIPS 205, migrating to 192f), uses **ML-DSA-44** for bootstrap signing, and **has no classical signer anywhere in the signing path**. This is possible because PQSigner targets ERC-4337 smart accounts exclusively — the on-chain `validateUserOp()` function verifies SLH-DSA signatures, not the EVM's native ecrecover. Key derivation flows from 24-word BIP-39 entropy through a PQ-specific path to deterministic SLH-DSA keypairs.

The honest trade-off: Trezor's classical algorithms are **universally supported** by every blockchain, exchange, and counterparty. Signature size is **64–65 bytes**. PQSigner's SLH-DSA-SHA2-128f produces **17,088-byte** signatures (~267× larger); migration to 192f yields **35,664-byte** signatures (~557× larger). On Ethereum L1, calldata gas for a single PQSigner signature is **~273,408 gas** (128f) vs **~1,024 gas** for ECDSA — over 13× the base cost of a simple ETH transfer, just for the signature. On L2s where calldata dominates fees, this cost premium is amplified further. PQSigner's design accepts this cost as the price of quantum resistance; blockchains may eventually add PQ precompiles that reduce verification gas, but none exist today.

SLH-DSA's side-channel profile is **structurally more favorable** than ECDSA for timing and cache attacks — implementations are naturally constant-time with no secret-dependent branches. However, the PRF function that converts SK.seed into WOTS+/FORS secret values is vulnerable to differential power analysis (many invocations with the same secret, different known inputs). Fault attacks are also concerning: a single random bit flip during SLH-DSA signing can enable universal forgery (Genêt, TCHES 2023). PQSigner acknowledges SLH-DSA SCA hardening as a planned stage (stage 5 of 5) not yet implemented.

---

## 3. Seed storage and recovery: features vs minimalism

**Trezor Safe 7** stores seeds encrypted on MCU flash. Default backup format is **SLIP-39** (Shamir, 20-word single share), with multi-share support (up to 16 shares, configurable threshold like 2-of-3 or 3-of-5). BIP-39 (12/18/24 words) is supported for legacy restore. **Passphrase** ("hidden wallet") support is included — up to 50 ASCII characters, entered on-device via touchscreen or on host, creates a completely separate wallet per passphrase. Passphrase is never stored on device. Backup verification ("Check backup") works entirely on-device without host connection — a significant UX improvement. Recovery entry happens on the touchscreen with auto-matching word tiles. Staggered multi-share recovery is supported: the device can be disconnected and taken to different share locations while maintaining recovery state.

**PQSigner OS** stores 24-word BIP-39 entropy as an XOR-split across two SEs. No SLIP-39, no passphrase support (both noted as "yet"). Recovery means entering 24 BIP-39 words which are re-split and stored across SEs. The same 24 words deterministically produce the same PQ keys (SLH-DSA keypair derived from the entropy), which map to the same ERC-4337 smart-account address via deterministic CREATE2 from the bootstrap public key. The recovery contract is preserved because the derivation path is deterministic: same entropy → same ML-DSA-44 bootstrap key → same CREATE2 address → same on-chain account with its full transaction history and asset balances.

Trezor's recovery ecosystem is **substantially richer**: Shamir backup provides geographic distribution of shares, passphrase provides plausible deniability and additional entropy, and on-device backup verification eliminates a class of "backup gone stale" failures. PQSigner's minimalist approach reduces attack surface (fewer features = fewer bugs) but leaves users without industry-standard backup resilience tools.

---

## 4. PIN security converges on hardware enforcement

Both devices implement **hardware-enforced PIN gating across dual SEs**, making them meaningfully stronger than single-SE or software-counter designs.

**Trezor Safe 7** uses a sequential dual-SE PIN flow: the MCU sends the PIN-derived value to TROPIC01, which mixes its own secret and consumes a **physically irreversible one-time slot** (not a counter — a physical fuse-like mechanism that cannot be reset by any means). The transformed value then goes to OPTIGA Trust M, which verifies against its own independent, non-resettable secure-memory counter. After **10 incorrect attempts**, the device wipes. PIN length up to **50 digits**. Neither SE learns the actual PIN value. The physically irreversible slot mechanism in TROPIC01 is novel among commercial SEs and makes counter-reset attacks (a real concern with flash-based counters) architecturally impossible.

**PQSigner OS** uses SE050's UserID mechanism (**max 10 attempts**, hardware-enforced) and OPTIGA's authentication reference with a firmware-managed decrement-before-auth counter at OID 0xF1D5. An admin-wipe secondary UserID enables post-lockout recovery. Both counters are hardware-backed, but the OPTIGA counter relies partly on firmware logic for the decrement-before-auth pattern, which is a slightly weaker guarantee than TROPIC01's physical irreversibility. The SE050 UserID counter is a standard JCOP mechanism with strong tamper resistance (EAL6+).

Both architectures defeat software-only PIN brute-force and require compromising two independent SE chips from different manufacturers. **TROPIC01's physical one-time slots provide the strongest anti-reset guarantee in the comparison**, though PQSigner's dual-EAL6+ certification provides stronger formal assurance of tamper resistance around the counters themselves.

---

## 5. Firmware update: Trezor's mature model vs PQSigner's measurement-based approach

**Trezor Safe 7** implements a **three-stage boot chain**: an immutable, write-protected boardloader verifies the bootloader using hybrid EdDSA + SLH-DSA-128 signatures; the bootloader verifies firmware via Ed25519 multi-party signatures (≥2 independent SatoshiLabs key holders must sign); firmware headers include version fields with rollback protection (downgrades below critical-fix versions are rejected). The device **ships without firmware** — firmware is installed during first setup via Trezor Suite, which itself validates the binary. Reproducible builds are **working**: Nix+Docker produces byte-identical firmware except for a 65-byte signature block; users can zero out the signature and compare SHA-256 hashes. All verification runs on the **MCU** (boardloader code), not the SEs. This is a known limitation — if the MCU is compromised before the boardloader runs (pre-boot attack), the SE cannot independently verify firmware integrity.

**PQSigner OS** uses a **measured-boot** model: at boot, the firmware computes a SHA-256 hash over its own image and displays it as **8 BIP-39 words** on the OLED. The user visually compares these words against output from a host-side verification tool. This provides a human-in-the-loop integrity check that doesn't depend on any signing keys — the measurement is self-evident. Firmware is flashed via ST-LINK (JTAG/SWD), not USB DFU, eliminating USB-based firmware injection attacks. Planned enhancements include ML-DSA-44-signed measurement hashes (signing the hash, not the binary, so reproducible-build verification is straightforward) and RDP Level 2 lockout (disabling debug access permanently). Reproducible builds are **planned but not shipped**.

For a paranoid user, Trezor's model offers **stronger guarantees today**: reproducible builds let anyone verify the shipping binary matches source, the hybrid PQ boot chain protects against future quantum attacks on the signing keys, and the multi-party signing ceremony prevents single-point key compromise. PQSigner's measured-boot is elegant but relies on the user actually performing visual comparison (a human reliability problem) and lacks automated verification until ML-DSA-44-signed hashes ship.

---

## 6. Supply-chain attestation: shipped vs planned

**Trezor Safe 7** implements multi-layer attestation: TROPIC01 stores X.509 certificates in OTP memory (written during manufacturing) and performs signed challenge-response. OPTIGA provides independent attestation. The MCU contributes ML-DSA-44 attestation. Trezor Suite verifies all three layers against SatoshiLabs' root public keys on first connection. The device ships without firmware, so a device arriving with pre-installed firmware is immediately suspect. Physical indicators include holographic tamper-evident seals.

This system is the strongest attestation scheme in any shipping hardware wallet, but it is not without precedent failure. **The Ledger Donjon Safe 3 attack (March 2025)** demonstrated that MCU compromise could bypass the attestation completely — the attacker extracted the pre-shared secret between OPTIGA and MCU, reprogrammed the MCU, and the device passed all Trezor Suite authenticity checks while running malicious firmware. This attack exploited the STM32F429's vulnerability to voltage glitching. **Safe 7 mitigates this** by using the STM32U5G (no publicly known fault-injection attacks) and adding TROPIC01 as a second, independent attestation layer that the MCU cannot impersonate without access to TROPIC01's OTP-stored private keys.

**PQSigner OS** plans dual-SE UID certificate chains (NXP root for SE050, Infineon root for OPTIGA) plus an STM32-UID cross-binding (work-todo #22). **No attestation is implemented today.** This means a supply-chain attacker could currently replace the entire firmware, substitute SEs, or repackage the device without any cryptographic detection mechanism. This is PQSigner's single largest security gap relative to Trezor.

Against an interdiction attacker (Mallory who intercepts and repackages the device in transit), **Trezor Safe 7's triple-layer attestation is clearly superior**. PQSigner's planned dual-SE UID chain, once implemented, would provide comparable cryptographic assurance for SE genuineness but would still lack the MCU-layer attestation that Safe 7 provides via ML-DSA-44 certificates.

---

## 7. Physical and side-channel security: production device vs development board

This comparison is the most asymmetric of all twelve dimensions. **Trezor Safe 7 is a shipping consumer product** in an anodized aluminum unibody with IP67 rating, Gorilla Glass 3, and a TROPIC01 SE that integrates active shield/mesh, voltage glitch detection, temperature anomaly sensing, laser detection, EM pulse detection, memory encryption (ISAP with PUF-derived keys), address scrambling, ECC on memory, and an alarm mode that rejects all commands for a configurable period when an attack is detected. The STM32U5G MCU adds TrustZone, a PKA with documented side-channel resistance, hardware unique key (HUK), and active tamper detection. OPTIGA contributes its own voltage/temperature/laser sensors.

**PQSigner OS runs on a B-U585I-IOT02A Discovery board** — an unshielded, exposed development board. Stage 1 of a 5-stage brownout hardening roadmap has landed (reset-cause classification, verified flash writes). Stages 2–5 are planned: BOR/PVD/IWDG/TAMP/ECC configuration, fault-injection countermeasures, and SLH-DSA SCA hardening. The project explicitly acknowledges the absence of hardware tamper switches, active mesh, and decap defense.

There is no contest on this axis today. **Trezor Safe 7 wins by multiple orders of magnitude on physical security maturity.** PQSigner's roadmap is credible (the STM32U585 supports all the planned hardening features), but shipping a security-critical device on an unmodified dev board with exposed JTAG headers and no physical tamper detection is not yet in the same category. PQSigner's planned RDP Level 2 (permanently disabling debug access) would close the most critical gap, but the exposed PCB, lack of enclosure, and absence of anti-tamper sensors remain fundamental limitations for physical attack resistance.

---

## 8. Open-source depth and external review track record

**Trezor** has maintained fully open-source firmware (GPLv3) since 2014, the longest track record of any hardware wallet. The crypto library is MIT-licensed. The Safe 7 adds TROPIC01's open digital design (RTL, firmware, SPECT compiler, SDK — all on GitHub). Reproducible builds work today. However, **no formal third-party security audit reports have been publicly published** for any Trezor product. Security validation comes entirely from the bug bounty program and ad-hoc responsible disclosures by external researchers (Kraken, Ledger Donjon, wallet.fail, Christian Reitter, Saleem Rashid, and others). This is a surprising gap for a 10+ year-old product line. The TROPIC01 has received one published evaluation (Contentwise Tech, January 2025) covering SDK and architecture but not physical penetration testing. Closed components include OPTIGA Trust M firmware and TROPIC01's analog IP blocks.

**PQSigner OS** firmware is fully open-source with no NDA components in the firmware code path. However, it depends on **closed-source SE firmware on both the SE050 and OPTIGA Trust M** — the same OPTIGA firmware that Trezor also depends on, plus NXP's proprietary JCOP stack. No third-party audits, no bug bounty program, no reproducible builds yet.

"Verifiable hardware wallet" means different things for each project. For Trezor, it means: you can read the firmware source, reproduce the binary, and inspect the TROPIC01 digital logic — but you must trust OPTIGA's closed firmware, TROPIC01's analog IP, and the absence of hardware backdoors (no CC certification on TROPIC01 to provide independent assurance). For PQSigner, it means: you can read the firmware source, but you must trust both SEs' closed firmware stacks and cannot yet verify the binary matches source. **Trezor's verifiability story is materially stronger today**, primarily because reproducible builds and TROPIC01's open design address the two weakest links in the traditional hardware-wallet trust model.

---

## 9. Account abstraction and smart-contract integration: PQSigner's structural advantage

**Trezor Safe 7** operates as an **EOA (Externally Owned Account) signer**. It supports EIP-712 typed-data signing with structured display (domain, message fields shown on device) and was enhanced in firmware v25.9 to display message hashes. It works with Safe (Gnosis) multisig wallets via MetaMask or WalletConnect, and with 70,000+ dApps via WalletConnect. It does **not** natively construct, parse, or clear-sign ERC-4337 `UserOperation` structures. There is no publicly announced ERC-4337 roadmap. The device signs raw EOA transactions or EIP-712 payloads; any AA integration is handled entirely by the companion wallet application.

**PQSigner OS** is a **native ERC-4337 smart-account signer**. The device constructs and signs UserOperations directly. The on-chain smart account's `validateUserOp()` verifies SLH-DSA signatures. The bootstrap ML-DSA-44 key deterministically generates the smart-account address via CREATE2 on all EVM chains. On-device **Groth16 ZK clear-signing** for Aave v3 (with CowSwap planned) means the device can verify that the transaction's calldata matches the user-visible intent — a meaningful anti-phishing measure that goes beyond EIP-712's structured display. Key rotation is natively supported: PQ keys can be rotated on-chain without changing the account address, a capability that EOA wallets fundamentally cannot offer.

The feasibility caveat on Groth16: proof generation for non-trivial circuits on a Cortex-M33 (160 MHz, ~786 KB SRAM) is extremely constrained. The STM32U585 can likely handle Groth16 **verification** (3 pairings, ~200–500ms) or proof generation for very small circuits, but not circuits with more than a few thousand constraints. The practical architecture likely involves the companion app generating the proof and the device verifying it on its trusted display — a reasonable design if documented clearly.

PQSigner is **structurally better positioned for the smart-wallet/AA world** because it was designed for it from the ground up. Trezor would need to add UserOperation parsing, PQ signature support, and smart-account address derivation to its firmware — all possible via updates, but none trivial.

---

## 10. UX and ergonomics: polish vs prototype

This dimension is the widest gap in the entire comparison and favors Trezor overwhelmingly.

**Trezor Safe 7** has a **2.5-inch, 520×380 color touchscreen** at 700 nits with Gorilla Glass 3 and haptic feedback. Transaction confirmation involves reviewing recipient, amount, and fee on the trusted display with ~3–4 taps. PIN entry is on-device via touchscreen. Bluetooth 5.0+ enables wireless operation with encrypted THP protocol. Qi2 wireless charging and a LiFePO₄ battery (**330 mAh**) allow untethered use. The device weighs 45g in an aluminum unibody at 75.4×44.5×8.3mm. Recovery word entry uses auto-matching word tiles on the touchscreen. Backup verification works entirely on-device.

**PQSigner OS** uses an **SSD1306 128×64 monochrome OLED** — 20× fewer pixels than Trezor's display. USB-C is the only interface; no wireless, no battery. The B-U585I-IOT02A Discovery board is ~66×53mm but with exposed headers, debug connectors, and no enclosure. Recovery and PIN entry rely on the constrained display and limited input mechanisms.

The **signature-size ergonomic penalty** is real and quantifiable. A PQSigner SLH-DSA-128f signature (**17,088 bytes**) takes ~267 USB HID packets at 64 bytes each with ~1ms polling intervals, adding **~267ms** of transfer latency. SLH-DSA-192f (**35,664 bytes**) adds ~557ms. ECDSA's 64 bytes transfer in a single packet. On top of USB latency, SLH-DSA signing computation itself takes multiple seconds on Cortex-M33. Mempool propagation is slower with 17–35 KB payloads. L2 inclusion costs are dominated by calldata: **~273,408 gas** for a 128f signature vs ~1,024 gas for ECDSA, making every PQSigner transaction roughly **$0.50–$5+ more expensive** at typical gas prices depending on network conditions.

---

## 11. Design patterns PQSigner should adopt from Trezor

These are concrete, implementable items where Trezor's approach is demonstrably superior:

- **SLIP-39 Shamir backup.** Geographic distribution of recovery shares is a solved problem. PQSigner's single-24-word backup is a single point of failure. SatoshiLabs invented SLIP-39; PQSigner should implement it (the spec is MIT-licensed, available at github.com/satoshilabs/slips/blob/master/slip-0039.md).

- **Passphrase support.** An additional entropy input that creates plausible deniability and protects against $5-wrench attacks. Trezor supports up to 50-character passphrases entered on-device. PQSigner's architecture can accommodate this as an additional input to the key derivation function.

- **Reproducible builds (shipped, not planned).** Trezor's Nix+Docker pipeline with byte-identical output (minus 65-byte signature) is the gold standard. PQSigner should prioritize this above most other roadmap items — without reproducible builds, the measured-boot 8-word display is the only verification mechanism, and it requires manual human comparison.

- **Ship-without-firmware anti-interdiction pattern.** Trezor Safe 7 leaves the factory with no firmware; first-boot installs it via Trezor Suite. This eliminates firmware-tampering during shipping as an attack vector. PQSigner should adopt this: flash firmware on first connection via the companion app, not pre-loaded.

- **On-device backup verification without host.** Trezor's "Check backup" flow lets users verify their recovery phrase matches the stored seed without connecting to any computer. PQSigner's constrained display makes this harder but not impossible — a word-by-word confirmation flow on the OLED would work.

- **Hybrid PQ boot chain.** Trezor's boardloader uses EdDSA + SLH-DSA-128 — dual verification that survives both quantum and classical attacks on the signing keys. PQSigner's planned ML-DSA-44-signed measurement hash is good but should consider a hybrid scheme for defense in depth.

- **Published security disclosure page.** Trezor maintains a comprehensive past-security-issues page with every reported vulnerability, its severity, and resolution. PQSigner should establish this practice from day one.

---

## 12. What PQSigner does that Trezor cannot easily retrofit

Several PQSigner architectural decisions are **structurally locked out** by Trezor's current design:

- **PQ-only signing path.** Trezor's entire ecosystem — Trezor Suite, supported blockchains, exchange integrations — depends on classical ECDSA/EdDSA. Switching to PQ-only signing would break compatibility with every supported chain. PQSigner avoids this by targeting ERC-4337 smart accounts exclusively, where the signature scheme is enforced by the smart contract, not the protocol.

- **XOR-split seed across two SEs.** Trezor's seed is stored encrypted on MCU flash with SE secrets contributing to the decryption key. Retrofitting to an XOR-split-across-SEs model would require changing the seed storage format, the PIN verification flow, and the recovery mechanism — a breaking change for existing users.

- **Native ERC-4337 UserOperation construction and signing.** Trezor would need to add UserOp parsing, gas-estimation integration, bundler communication awareness, and smart-account address derivation to its firmware. This is a substantial engineering effort that competes with maintaining support for 10,000+ existing coin/token configurations.

- **On-device ZK clear-signing.** Verifying Groth16 proofs of transaction intent on the trusted display requires pairing-friendly curve arithmetic that Trezor's firmware does not currently implement. Adding BN128/BLS12-381 pairing to the firmware is feasible (the STM32U5G's PKA could help) but would require significant cryptographic engineering and audit.

- **Deterministic cross-chain account identity from a single bootstrap key.** PQSigner's CREATE2-derived address is the same on every EVM chain by construction. Trezor's EOA addresses are chain-agnostic for EVM chains (same secp256k1 key = same address), but smart-account addresses with PQ verification logic and key-rotation capability are architecturally different.

- **On-chain key rotation without account migration.** Because PQSigner's account is a smart contract, the signing key can be rotated by a governance transaction without moving assets. Trezor EOA accounts cannot rotate keys — a compromised key means the account is permanently compromised and all assets must be moved.

---

## Summary comparison table

| Dimension | Trezor Safe 7 | PQSigner OS | Edge | Confidence |
|---|---|---|---|---|
| **1. Secure-element strategy** | TROPIC01 (open, no CC) + OPTIGA (EAL6+). Seed encrypted on MCU flash. Noise secure channel (AES-256-GCM, forward secrecy). | SE050 (EAL6+) + OPTIGA (EAL6+). Seed XOR-split across SEs, never on MCU flash. Shielded Connection (AES-128-CCM-8). | **Draw** — Trezor wins on SE transparency and secure-channel strength; PQSigner wins on seed-at-rest isolation and dual-EAL6+ certification. | Medium |
| **2. Cryptographic algorithms** | secp256k1, Ed25519, Schnorr, P-256 for blockchain. SLH-DSA-128 + ML-DSA-44 for internal verification. | SLH-DSA-SHA2-128f (→192f) for all transactions. ML-DSA-44 for bootstrap. No classical signer. | **Depends on threat timeline** — Trezor is universally compatible today; PQSigner is quantum-resistant today. | High |
| **3. Seed storage & recovery** | SLIP-39 (default, up to 16 shares), BIP-39, passphrase, on-device backup check. Seed encrypted on MCU. | BIP-39 only, XOR-split across SEs, no SLIP-39, no passphrase. Deterministic PQ key recovery. | **Trezor** — richer recovery options, better resilience against backup loss. | High |
| **4. PIN security** | Dual-SE hardware. TROPIC01 physical one-time slots (irreversible). OPTIGA non-resettable counter. 10 attempts → wipe. | SE050 UserID (10 attempts) + OPTIGA firmware-managed counter. Admin-wipe recovery path. | **Trezor** (slight) — physically irreversible slots > firmware-managed counter. Both strong. | Medium |
| **5. Firmware update model** | 3-stage boot, hybrid EdDSA+SLH-DSA-128, multi-party signing, reproducible builds working, ships without FW. | Measured boot (8-BIP-39-word SHA-256 display), ST-LINK flash, ML-DSA-44 signing planned, no repro builds yet. | **Trezor** — mature, verifiable, PQ-hardened boot chain shipping today. | High |
| **6. Supply-chain attestation** | Triple-layer: TROPIC01 X.509 + OPTIGA + MCU ML-DSA-44. Ships without FW. Holographic seal. (Safe 3 bypass disclosed.) | Planned dual-SE UID cert chains + STM32 cross-binding. **Not implemented yet.** | **Trezor** — implemented vs not-yet-implemented. | High |
| **7. Physical / side-channel** | TROPIC01: active shield, laser/voltage/EM/temp detection, memory encryption, ECC. Aluminum unibody, IP67. | Dev board. Stage 1/5 brownout hardening. No tamper sensors, no enclosure, no active mesh. | **Trezor** — shipping consumer product vs exposed development board. | High |
| **8. Open-source / reproducibility** | FW fully open (GPLv3). TROPIC01 digital design open. Repro builds working. No published formal audits. OPTIGA FW closed. | FW fully open. Both SE firmwares closed. No repro builds. No audits. | **Trezor** — TROPIC01 openness + repro builds > PQSigner's closed-SE dependency. | Medium |
| **9. AA / smart-contract integration** | EOA signer. EIP-712 clear-sign. No native ERC-4337. Works with Safe/Argent via WalletConnect. | Native ERC-4337. PQ-only smart account. Groth16 ZK clear-signing. CREATE2 cross-chain identity. Key rotation. | **PQSigner** — purpose-built for the smart-wallet world. | High |
| **10. UX / ergonomics** | 2.5" color touch, 520×380, haptic, BLE, Qi2, battery, 64-byte sigs, aluminum, IP67. | 128×64 OLED, USB-C only, dev board, 17–35 KB sigs, ~267ms–557ms USB transfer overhead, higher gas cost. | **Trezor** — consumer-grade UX vs bare-board prototype. | High |
| **11. What PQSigner should steal** | SLIP-39, passphrase, repro builds, ship-without-FW, on-device backup check, hybrid PQ boot, security disclosure page. | — | — | — |
| **12. What Trezor can't easily adopt** | — | PQ-only signing, XOR-split seed, native ERC-4337, ZK clear-signing, on-chain key rotation, CREATE2 identity. | — | — |

---

## Both projects share open problems worth naming

Neither project has solved everything. **Trezor Safe 7** still performs all blockchain signing on the MCU, meaning an MCU compromise exposes signing keys in SRAM — the same architectural weakness that Ledger has criticized across all Trezor generations. TROPIC01 lacks CC certification, meaning its tamper-resistance claims rest on open-design auditability rather than formal third-party evaluation. No formal security audit has ever been published for any Trezor product — a remarkable gap for a decade-old market leader. The Bluetooth 5.0+ interface expands the wireless attack surface even with THP encryption.

**PQSigner OS** has no supply-chain attestation, no reproducible builds, no physical enclosure, incomplete side-channel hardening (1 of 5 stages), no Shamir backup, no passphrase support, and gas costs that make every transaction materially more expensive than classical alternatives. The SLH-DSA SCA hardening gap (particularly DPA resistance of the PRF function and fault-attack vulnerability documented by Genêt 2023) is a genuine concern for a device that performs all PQ signing on an unshielded MCU. The Groth16 ZK clear-signing claim needs public documentation of circuit sizes and whether proof generation or only verification occurs on-device, given Cortex-M33 memory and compute constraints.

Both projects depend on closed-source Infineon OPTIGA Trust M firmware for critical security functions — a shared trust assumption that neither can independently verify.

## Conclusion

Trezor Safe 7 is a polished, shipping product with the strongest supply-chain attestation, physical security, firmware verifiability, and UX of any hardware wallet on the market. Its introduction of TROPIC01 and hybrid PQ boot verification genuinely advances the state of the art. PQSigner OS makes a structurally different bet: that quantum-resistant signing, native account abstraction, and XOR-split seed isolation matter more than classical compatibility and consumer polish. Both bets are defensible. The Trezor Safe 7 is the better hardware wallet to buy today. PQSigner OS is the more interesting architecture for the post-quantum, smart-account future — but it must ship attestation, reproducible builds, and physical hardening before that architecture translates into real-world security superiority.
# Supply-chain threat model and attestation protocol for PQSigner OS

**A dual-secure-element hardware wallet binding SE050, OPTIGA Trust M, and STM32U585 UIDs in a factory-signed manifest can defeat every attacker class below nation-state HSM compromise.** No shipping hardware wallet implements this triple-bind today — Ledger, Trezor, and ColdCard all rely on single-SE attestation, leaving MCU replacement and chip transplant as viable attack surfaces. PQSigner OS's architecture creates a novel defense: each boot cryptographically verifies that all three silicon identities match an SLH-DSA-signed manifest created during factory provisioning. This report details the threat landscape, the attestation gaps in current products, and a concrete protocol that closes them.

The recommended protocol combines three independent certificate chains (NXP root CA, Infineon root CA, factory SLH-DSA root) into a single verification ceremony that runs at every boot and communicates results over USB-C. The XOR-split entropy design means attestation failure automatically prevents seed reconstruction — neither SE alone holds usable key material.

---

## Ranked attacker tiers and what each can realistically accomplish

Three attacker classes define the threat model, each with progressively greater capability and correspondingly different mitigation requirements.

**Tier A — Opportunistic reseller.** This attacker buys or steals devices and tampers before resale. Capabilities include opening packaging, basic soldering, and loading pre-configured seeds via USB. They cannot write firmware, desolder BGA/QFN components, or perform voltage glitching. Historical examples include the **2021 fake Ledger Nano X campaign**, where scammers mailed devices containing flash drives with fake Ledger Live software to victims of the 2020 data breach, and the **fake Trezor One clones** manufactured in China with near-identical packaging but different holographic seals. This tier relies on social engineering — the device appears genuine, and the victim enters their recovery phrase into a malicious application.

**Tier B — Sophisticated interdictor.** This attacker intercepts devices in transit and has a moderate lab: hot-air rework station, JTAG/SWD probes, oscilloscope, and firmware reverse-engineering skills. They can desolder and resolder QFN packages, attempt voltage glitching on the MCU, and flash modified firmware. The **Kaspersky-documented fake Trezor Model T** exemplifies this tier: attackers replaced the STM32F427 with an STM32F429 (RDP set to 0), pre-loaded a backdoored bootloader (version 2.0.4, deliberately never released by SatoshiLabs), and knew the private key before selling the device. Ledger Donjon's **March 2025 attack on Trezor Safe 3** also falls here — they voltage-glitched the STM32 MCU to extract the pre-shared secret linking MCU to OPTIGA, enabling firmware replacement while the OPTIGA's attestation still passed.

**Tier C — Nation-state with factory access.** This attacker can intercept before provisioning, compromise supply chains at NXP/Infineon/ST, or coerce factory employees. They have FIB (focused ion beam) capability, access to silicon design databases, and potentially the ability to issue fraudulent certificates. The primary threat is compromising the factory HSM that signs binding manifests, enabling production of devices with valid attestation but backdoored firmware.

| Tier | Representative attack | Required capability | Multi-chip binding defeated? |
|------|----------------------|---------------------|------------------------------|
| A | Pre-loaded seed, fake packaging | Physical access, basic tools | **Yes** — cannot forge manifest signature |
| B | MCU replacement, firmware backdoor, chip transplant | Rework station, JTAG, glitching | **Yes** — UID mismatch on any replaced chip; STM32U5 RDP2 resists known glitching |
| C | HSM compromise, rogue factory line | Factory access, state-level lab | **Partially** — requires transparency log and operational security to detect |

---

## STM32U5 clones do not exist yet, but detection probes are still essential

**No confirmed clones of the STM32U5 family exist as of early 2025.** Chinese clone manufacturers (GigaDevice, CKS/CETC, Geehy, WCH, MindMotion) have extensively cloned the STM32F103 and partially cloned the STM32F4 series, but the Cortex-M33 with TrustZone, hardware crypto accelerators (AES with DPA resistance, PKA, OTFDEC), and the **DHUK (Device Hardware Unique Key)** present an engineering barrier that makes silicon-level cloning economically impractical. The more realistic counterfeit risk for STM32U585 is **remarked parts** — lower-spec U5 variants relabeled as U585 — sourced from unauthorized distributors.

Boot-time detection should still be implemented as defense-in-depth. The most reliable probes for the STM32U585:

**CPUID and DBGMCU_IDCODE verification.** The Cortex-M33 core revision on genuine STM32U585 is **r0p4** (per ES0499). The DBGMCU_IDCODE at `0xE0044000` should return DEV_ID **0x482** with a REV_ID matching known silicon revisions (X, W, or U). On the extensively-cloned STM32F103, all known clones use Cortex-M3 **r2p1** while genuine parts use **r1p1** — the single most reliable detection method, discovered by the BlaatSchaap research project.

**DHUK via SAES peripheral.** The STM32U585's DHUK is a factory-programmed **256-bit key that is never directly readable by software**. It can only be used indirectly through the Secure AES (SAES) peripheral for encryption operations XORed with a Boot Hardware Key. A clone cannot replicate a genuine DHUK without access to ST's programming infrastructure. Attempting a DHUK-gated operation and verifying the output against a factory-recorded expected value provides unforgeable silicon authentication.

**UID register validation.** The 96-bit UID at `0x0BFA0590` encodes wafer coordinates, wafer number, and lot number in ASCII. Validation checks should confirm lot number bytes are printable ASCII (0x20–0x7E), wafer number is reasonable (typically under 25), and the UID is neither all-zeros nor all-ones. The CH32F103 clone notoriously returns `0xFFFFFFFF` for serial number fields.

**Flash ECC behavior.** Per AN5342, the STM32U5 implements SEC-DED ECC on both flash and SRAM. SRAM3's last 64 KB block serves as ECC redundancy storage and is inaccessible for normal data. Testing access to this region provides a structural verification that a clone would fail unless it replicated ST's exact memory architecture.

**Errata fingerprinting.** ES0499 documents that the `AUTH_ID` bitfield in `DBGMCU_DBG_AUTH_DEVICE` reads zero at RDP Level 0 — a silicon bug. A clone that "fixed" this erratum would expose itself. Similarly, the documented MSI frequency anomaly (up to 25% low for 100 µs after exiting Stop 3) and ICACHE/DCACHE corruption on Stop mode exit are mask-specific behaviors that would require intimate knowledge of ST's RTL to replicate.

---

## SE050 attestation is strong for chip genuineness but blind to board identity

The NXP SE050 uses a **three-level PKI** pre-provisioned at the factory. The NXP Root CA signs an Intermediate CA certificate, which signs a device-unique leaf certificate containing an **ECC NIST P-256 public key**. The corresponding private key is stored at object ID `0xF0000012` and can never be extracted. Only SE050 variants **C, E, and F** include pre-provisioned attestation certificates (at object ID `0xF0000013`); variants A/B/D have attestation keys but no certificates — a critical selection consideration for PQSigner OS, which should specify variant **C or F**.

The attestation flow works by requesting an "attested read" of any secure object. The SE050 computes a signature over the concatenation of the request command hash, the object value, the **18-byte chip UID**, object attributes (including origin: PROVISIONED/GENERATED/EXTERNAL), object size, and a 12-byte monotonic timestamp. The signature uses the attestation key and includes 16 bytes of caller-supplied freshness data to prevent replay. Verification requires chaining the device certificate to NXP's published root CA and confirming the signature over the attested data.

```c
// Core attestation API call
Se05x_API_ReadObject_W_Attst(
    &session, objectID, 0, 0,
    kSE05x_AppletResID_ATTESTATION,  // 0xF0000012
    kSE05x_AttestationAlgo_EC_SHA_256,
    random_nonce, 16,                // caller-provided freshness
    data, &dataLen,
    attributes, &attrLen,
    timestamp, &tsLen,
    chipId, &chipIdLen,              // returns 18-byte UID
    signature, &sigLen               // ECDSA-SHA256 signature
);
```

**The critical gap is board binding.** The SE050 is an HXQFN20 package (3×3 mm) that can be desoldered and resoldered with standard rework equipment. It has no mechanism to detect it has been moved to a different PCB. The chip's attestation will still pass verification because the chip IS genuine — its identity, keys, and certificates travel with it. The default SCP03 platform keys are published in AN12436 and provide zero transplant resistance unless rotated. **For PQSigner OS, SCP03 key rotation during provisioning is mandatory** to create a shared secret between the MCU and SE050, but the binding manifest provides the stronger guarantee because SCP03 keys on the MCU side can potentially be extracted via flash readout if RDP is defeated.

The SE050 holds **CC EAL 6+ certification with AVA_VAN.5** — the highest vulnerability analysis level in Common Criteria, covering invasive probing, FIB modification, laser fault injection, DPA/SPA side-channel attacks, and electromagnetic analysis. Key extraction requires state-level resources and is not guaranteed to succeed even then.

---

## OPTIGA Trust M provides independent attestation with configurable platform binding

The Infineon OPTIGA Trust M V3 uses its own independent three-level PKI: **Infineon OPTIGA ECC Root CA 2** → **Infineon OPTIGA Trust M CA 300** (intermediate) → device-unique leaf certificate. The device certificate at OID `0xE0E0` contains an ECC NIST P-256 public key, with the corresponding private key at OID `0xE0F0`. The 27-byte coprocessor UID is stored at OID `0xE0C2` (first 25 bytes are the hardware identifier; last 2 bytes encode the embedded software build number).

Verification follows a standard challenge-response protocol: the host generates a random nonce, hashes it with SHA-256, and sends it to the OPTIGA for signing via `optiga_crypt_ecdsa_sign()`. The host then extracts the public key from the device certificate, verifies the ECDSA signature, and validates the certificate chain against Infineon's published root CA. The Arduino library's `checkChip()` method implements this entire flow as a single API call.

**OPTIGA Trust M V3's distinguishing feature is Shielded Connection** — an encrypted, integrity-protected I2C channel based on a **Platform Binding Secret (PBS)** stored at OID `0xE140`. During factory provisioning, the host MCU and OPTIGA establish a shared secret via TRNG-generated randomness. Once the PBS lifecycle is set to "operational," it can only be updated through the protected update mechanism. Data objects can have access conditions requiring `Conf(0xE140)`, meaning they are only accessible under an active shielded connection. This creates genuine board binding: transplanting the OPTIGA to a different MCU breaks the shared PBS, causing shielded-connection-protected operations to fail.

**However, this binding is not configured by default.** The factory-shipped OPTIGA has PBS in "initialization" lifecycle state, and access conditions for the primary certificate and signing key are set to "Always." PQSigner OS must explicitly configure PBS during provisioning, set access conditions on critical OIDs to require shielded connection, and transition the lifecycle to operational. The OPTIGA holds **CC EAL 6+** certification (BSI-DSZ-CC-0961) with the same class of physical attack resistance as the SE050.

---

## Current hardware wallets leave exploitable attestation gaps

**Ledger** pioneered SE-based attestation and remains the strongest single-SE implementation. Each device generates a secp256k1 keypair inside the ST31/ST33 secure element during manufacturing. Ledger's HSM signs the device public key with an Issuer key, creating a certificate stored on the device. At runtime, Ledger Live sends a challenge; the device returns an ephemeral key signed by the device key plus the Issuer Certificate; the HSM verifies the chain. Ledger distributes attestation keys in batches of ~10,000 units to prevent individual device tracking. **The weakness**: Saleem Rashid (2018) and wallet.fail demonstrated that the STM32 MCU can run arbitrary code (including Snake) while the SE attestation still passes — the SE verifies only that the flash image the MCU *reports* is correct, which the MCU can fake. The SE's keys remain protected, but the MCU-controlled display and user interface are not attested.

**Trezor Safe 3** added an OPTIGA Trust M SE for attestation, but **Ledger Donjon proved in March 2025** that this authenticates only the OPTIGA, not the MCU or its firmware. They voltage-glitched the STM32 MCU to extract the pre-shared secret linking MCU and OPTIGA, enabling firmware replacement while the OPTIGA attestation still passed. Trezor Safe 5's upgrade to the STM32U5 MCU closes this specific glitching vector (no publicly known fault injection attacks on STM32U5), and **Trezor Safe 7** adds a second SE (TROPIC01) for dual attestation — the closest existing design to PQSigner OS's dual-SE architecture, though it still does not implement UID-binding manifests.

**ColdCard's bag number system** writes a unique serial number into MCU OTP flash at the factory; users verify it matches the tamper-evident bag on first boot. TheCharlatan demonstrated in May 2020 that loading custom firmware could factory-reset the device (by setting PIN to all zeros) without changing the bag number, reducing supply chain security to the physical tamper-evidence of the plastic sleeve itself — which can be defeated "with household tools by cutting open at the bottom with a sharp knife and resealing with heat."

**Foundation Passport** stores a supply chain private key in the ATECC608B SE during manufacturing. During setup, the user scans a QR code containing a public key; the device generates four verification words that the user enters into Foundation's website. The MCU is locked to RDP Level 2 and paired to the SE via a random pairing secret used as a MAC. Foundation's US-based assembly (New Hampshire) and fully open-source firmware provide additional supply chain transparency. No documented attacks exist against Passport's attestation, though the smaller market likely contributes.

The **key lesson across all vendors**: single-SE attestation proves the SE is genuine but does not bind the SE to a specific MCU or PCB. Every documented supply chain attack on hardware wallets has exploited this gap — replacing or reprogramming the MCU while leaving the SE intact.

---

## The triple-bind attestation protocol for PQSigner OS

The proposed protocol creates a **factory-signed CBOR manifest** binding all three chip UIDs — SE050 (18 bytes), OPTIGA Trust M (27 bytes), and STM32U585 (12 bytes) — along with the firmware hash and version counter. The manifest is signed with **SLH-DSA-128s** (SPHINCS+ with 128-bit security, ~7,856-byte signatures), making it resistant to both classical and quantum attacks. The factory signing key resides in an air-gapped HSM under M-of-N key-share ceremony control.

### Factory provisioning sequence

The provisioning station reads all three chip UIDs over their respective interfaces, computes SHA3-256 of the firmware image, and constructs the binding manifest:

```
BindingManifest (CBOR) = {
  manifest_type:     "PQS-BIND-v1",
  se050_uid:         <18 bytes from SE050 IDENTIFY>,
  optiga_uid:        <27 bytes from OID 0xE0C2>,
  stm32_uid:         <12 bytes from 0x0BFA0590>,
  firmware_hash:     SHA3-256(firmware_image),
  firmware_version:  <monotonic counter>,
  device_serial:     SHA3-256(se050_uid || optiga_uid || stm32_uid),
  production_ts:     <ISO 8601 timestamp>,
  manifest_version:  1,
  factory_pubkey_fp: SHA3-256(factory_pubkey)[:16]
}
```

The provisioning station then: (1) signs the manifest with the factory SLH-DSA-128s key, (2) writes the signed manifest to SE050 as a binary secure object, (3) writes a copy to OPTIGA Trust M data object, (4) writes a copy to STM32 internal flash, (5) rotates SE050 SCP03 platform keys from defaults to a unique per-device key derived from the pairing, (6) configures OPTIGA PBS at OID `0xE140` and transitions lifecycle to operational, (7) sets STM32 RDP to Level 2, (8) records the device serial and manifest hash to a **public transparency log**.

### Boot-time verification ceremony

Every boot executes in the STM32U585's TrustZone Secure World:

1. Secure bootloader reads its own UID from `0x0BFA0590` (3 × 32-bit words)
2. Loads binding manifest from internal flash
3. Verifies SLH-DSA-128s signature using factory public key (embedded in write-protected OTP)
4. Compares `stm32_uid` field against hardware — **halt on mismatch**
5. Initializes I2C to SE050 (address 0x48), selects IoT applet (`A0000003965453000000010300000000`), requests attested read with fresh 16-byte nonce — response includes chipId (18-byte UID) in the signed attestation
6. Compares `se050_uid` against manifest and against chipId in the SE050's ECDSA-signed attestation response — **halt on mismatch**
7. Initializes I2C to OPTIGA (address 0x30), opens application, reads UID from OID `0xE0C2`, requests ECDSA signature on the same nonce using device key at `0xE0F0`
8. Compares `optiga_uid` against manifest — **halt on mismatch**
9. Verifies firmware hash: `SHA3-256(firmware_image) == manifest.firmware_hash` — **halt on mismatch**
10. Checks monotonic anti-rollback counter
11. Sets `ATTESTATION_PASSED` flag; transitions to Normal World

**If any check fails, the device enters permanent lockdown.** Neither SE releases its half of the XOR-split BIP-39 entropy. The USB-C interface reports the specific failure reason (manifest signature invalid, SE050 UID mismatch, OPTIGA UID mismatch, MCU UID mismatch, or firmware hash mismatch).

### Why this defeats each attacker tier

**Against Tier A (opportunistic reseller):** Cannot modify firmware (secure boot rejects unsigned images). Cannot pre-load a seed (entropy split across two SEs, reconstructed only after attestation passes). Cannot forge the binding manifest (requires factory signing key). Cannot even power the device into a usable state without attestation passing.

**Against Tier B (sophisticated interdictor):** Replacing the MCU triggers UID mismatch. Transplanting either SE triggers UID mismatch. Replacing all three chips requires forging an SLH-DSA signature — computationally infeasible. The STM32U5 at RDP Level 2 has **no publicly known voltage-glitching bypass** (explicitly noted by Ledger Donjon when analyzing the Trezor Safe 5, which uses the same MCU family). Even if RDP2 were bypassed in the future, the attacker would need the factory signing key to create a new valid manifest for modified firmware.

**Against Tier C (nation-state):** The protocol alone is insufficient. Required operational mitigations include: **append-only transparency log** of all device serials and manifest hashes (enables detection of rogue production runs), **M-of-N key ceremony** for the factory HSM with geographically distributed key shares, **dual-person integrity** controls on the provisioning line, and **certificate transparency** for factory signing certificates. The multi-chip binding still provides value even here: it prevents rogue employees from building off-books devices using spare parts, since every UID triple must appear in the transparency log.

---

## Box-opening ceremony proves genuineness through USB-C alone

Since PQSigner OS has USB-C as its only external interface and no screen, the attestation ceremony communicates via USB.

**Automatic self-attestation.** On first USB-C connection, the device enumerates as a USB CDC (serial) + WebUSB device. It runs the full boot verification sequence and emits a structured attestation report over USB serial:

```
=== PQSigner OS Attestation ===
Status:  AUTHENTIC
Serial:  A7F2-3B91-CC04
SE050:   ✓ UID verified, NXP cert chain valid
OPTIGA:  ✓ UID verified, Infineon cert chain valid
MCU:     ✓ UID verified, DHUK operational
Firmware: v1.0.0 (SHA3: 8a3c...f291)
Manifest: Valid (Factory Key FP: 7b2e...d804)
================================
```

**WebUSB browser verification (no install required).** The user opens `https://verify.pqsigner.io` in Chrome/Edge. The website uses the WebUSB API to send a fresh random challenge directly to the device. Both SEs sign the challenge — the SE050 with its NXP-attested key (verifiable against NXP's published root CA), the OPTIGA with its Infineon-attested key (verifiable against Infineon's published root CA). The website independently verifies: (1) both SE attestation signatures chain to their respective vendor root CAs, (2) both UIDs in the signed responses match the UIDs in the binding manifest, (3) the binding manifest's SLH-DSA signature verifies against the published factory public key. The page displays a green checkmark with the device serial number.

**The device proves its own authenticity** because three independent trust anchors converge: NXP's root CA vouches for the SE050, Infineon's root CA vouches for the OPTIGA, and the factory's SLH-DSA key vouches for the binding of all three chips. An attacker would need to compromise all three root-of-trust chains simultaneously to forge a passing attestation.

**Anti-replay protection** is layered: the SE050 includes a monotonic timestamp counter and 16 bytes of caller-supplied freshness in every attestation signature; the OPTIGA signs a fresh challenge with its device key; the WebUSB verifier generates a new random challenge for each session.

---

## Conclusion: what makes the triple-bind architecture novel

No shipping hardware wallet implements cryptographic binding of multiple chip UIDs in a factory-signed manifest. Ledger's model proves only that its SE is genuine. Trezor's model (even with dual SEs in Safe 7) proves only that individual SEs are genuine — the MCU remains a weak link, as Ledger Donjon demonstrated by extracting the MCU-OPTIGA pre-shared secret via voltage glitching. ColdCard's bag number system reduces to physical tamper-evidence of a plastic sleeve.

PQSigner OS's triple-bind manifest transforms the attack economics fundamentally. A Tier B attacker who can replace a single chip (the proven attack surface for every existing hardware wallet) gains nothing — the replacement chip's UID will not match the SLH-DSA-signed manifest, and forging that signature requires the factory HSM. The dual-SE entropy split adds a second layer: even if attestation were somehow bypassed, neither SE alone holds a usable seed.

The remaining vulnerability is the factory signing key itself. Against Tier C attackers, the defense shifts from cryptographic protocol to operational security: M-of-N key ceremonies, transparency logs, and geographic distribution of key shares. The append-only transparency log is particularly important — it converts a stealthy key compromise into a detectable event, because any device not in the log fails verification even if its manifest signature is valid. This creates a system where the cryptographic protocol handles Tiers A and B definitively, while the operational framework makes Tier C attacks detectable rather than preventable — which, for a nation-state threat model, is the realistic security goal.
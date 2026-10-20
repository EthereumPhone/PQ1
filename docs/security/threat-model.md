# PQSigner OS — Threat Model

**Status:** living document. Updated 2026-05-12; 2026-07-07 (ML-KEM inner wrap descoped — §9.1 residual ACCEPTED by owner; Claim 7 + T7 table reworded accordingly); 2026-10-13 (#855, Ledger Donjon report — PIN credentials made die-bound, salted and per-chip; Claims 1–3, §7.1, §7.4 and one §8 row corrected, each with a dated note saying what was false before).
**Scope:** the full firmware + hardware product. STM32U585 (Cortex-M33, TrustZone) host MCU, Infineon OPTIGA Trust M V3 + NXP EdgeLock SE050 secure elements, on-chain ERC-4337 v0.6 smart wallet (`PQSmartWallet`).
**Companion documents:** `docs/security/HARDENING.md` (hardening requirements — *what* we do), `docs/security/production-security.md` (research synthesis — *which mitigations* we landed and why), `CLAUDE.md` invariants (the non-negotiable contracts), this doc (*who* attacks *what*, with *what capability*, and how each attack is stopped or accepted).

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
| **S2 — channel-equivalent** | OPTIGA Platform Binding Secret (PBS), SE050 SCP03 ENC/MAC/DEK, SE050 admin UserID | The factory-burned per-device OTP master derives the transport SCP03/admin/PBS credentials. The implemented first-field candidate creates the BHK after RDP2, rotates SE050 to unsalted BHK-rooted final credentials, and rotates OPTIGA to a final PBS derived from DHUK plus a page-127-persisted TRNG salt. Handoff/recovery, exact E140 order, silicon evidence, and production approval remain OPEN. No plaintext channel key is intended to persist. | Bus-snoop / channel-impersonation against this device only. Does **not** alone unlock funds — see §6 |
| **S3 — auth-equivalent** | User PIN (raw), PIN-derived auth ref values stored in OPTIGA F1D0 + SE050 UserID | SE silicon (never MCU, never NS) | Online brute-force: 10 attempts → factory wipe (see §7.4) |
| **S4 — identity-equivalent** | Per-die DHUK (factory-fused), factory transport OTP master, BHK target, candidate rollback-floor OTP records, candidate vendor-key identity | STM32 silicon / protected state. DHUK is SAES-only; the BHK lifecycle exists in code but its production first-write flow is not approved. The factory-burned OTP master is transport-only; field auto-burn or reuse as a final root is rejected. The unary rollback tally is production-rejected, while Draft 1.1's physical OTP allocation and vendor-key binding remain OPEN. | Decap-class only for established silicon roots; candidate OTP/vendor records carry no production authority until their backend and ceremony close. The on-device PIN gate (§7.4) remains independently required. |
| **S5 — integrity-equivalent** | Firmware secure/nonsecure images, FSBL, on-chain bytecode at the deployed proxy + factory + implementation + verifier addresses, vendor C10 signing key (off-device, HSM) | Flash (current FSBL geometry is legacy bench-only; Draft 1.1 protection/layout is unapproved), on-chain CREATE2-derived addresses, vendor HSM | Persistent backdoor or substituted code path; downstream affects S0–S3 |
| **S6 — availability** | PIN-attempt controls, on-chain per-chain caps, page-123 offchain counter | MCU page 124, OPTIGA E120 LUC, SE050 UserID, on-chain storage | Brick (DoS) — funds frozen but not extracted. Note: bricking is a *defence outcome*, not an attack outcome we care about preventing |
| **S7 — privacy** | Wallet on-chain identity ↔ user, list of signed transactions, BIP-39 measurement words | On-chain (public), local NV3007 LCD (transient), companion app (depends on app) | Surveillance / deanonymisation; not financial loss |

The shipping invariant is: **no attack that does not break at least one S4 asset AND the S3 asset (user PIN) AND the S5 firmware integrity reaches an S0 asset.** The dual-SE split, three-way per-attempt PIN consumption, and FI-hardened verify-before-release together encode that invariant in silicon-anchored code. Boot reconciliation is narrower: a directional page124/E120 check with no SE050 attempt-count input.

---

## 3. Trust Boundaries

A boundary is *non-trivial* when its two sides are governed by different keys, different code, different vendors, or different physical chips. Boundaries are the only places where exploitable mismatches live.

| Boundary | Crossing format | Direction(s) of trust | Code path |
|---|---|---|---|
| **B-USB** Companion ↔ device | USB HID, APDU v2 (`nonsecure/src/usb/{commands,hid,transport}.rs`) | Device trusts companion *only* for non-secret metadata (chain_id, slot_index, flags, displayed tx fields); never for secret material | NS-side parser → NSC veneer |
| **B-NSC** NS ↔ S (TrustZone-M) | CMSE `cmse-nonsecure-entry` veneers on STM32U585; shared-memory mailbox on QEMU | S **never** trusts NS pointers, lengths, or contents without validation + copy-in | `secure/src/nsc/{ptr_validate,ns_ptr}.rs`; every `cmd_*::run` copies NS buffers to S-stack before parse |
| **B-UI** S ↔ user (NV3007 LCD + 2 buttons) | Trusted-path dialogs (`secure/src/ui/{confirm,pin_entry,seed_wizard}.rs`); buttons + LCD are S-owned peripherals via GTZC | User trusts what they see; S trusts only what they physically pressed | NS opinion of a button press is ignored — the S-only TIM2 inactivity timer is not reset by NS pings (§7.6) |
| **B-OPT** S ↔ OPTIGA Trust M V3 | OPTIGA Shielded Connection (TLS-PRF + AES-128-CCM-8). The factory prepares the chip on an OTP-master-derived transport PBS; the first-field candidate rotates to a final PBS derived from per-die DHUK plus a page-127-persisted TRNG salt after RDP2. The exact E140 lifecycle-versus-rotation order remains OPEN and silicon-gated. | S trusts OPTIGA only for the `half_O` bits it returns under successful E120/F1D0 silicon-gated read | `secure/src/optiga/{shield,apdu,ifx_i2c}.rs` |
| **B-SE0** S ↔ SE050 | SCP03 (AES-CMAC + AES-CBC). The factory installs OTP-master-derived transport keys/admin credential; the first-field candidate creates the BHK and rotates to unsalted BHK-rooted final SCP03/admin material. The user UserID is PIN-derived. | S trusts SE050 only for `half_E` bits returned under successful user-UserID read | `secure/src/se050/{scp03,apdu,t1oi2c}.rs` |
| **B-OTP** S firmware ↔ STM32 OTP | The factory burns the per-device transport master before shipment; field auto-burn and final-root reuse are forbidden. Candidate one-way rollback-floor records and vendor-key binding remain separate. The unary tally is production-fenced; Draft 1.1's physical codec, allocation, interruption handling, and factory procedure remain OPEN. | Field firmware may consume only the already-provisioned transport master; no other immutable authority exists before the reviewed backend, exact map, and owner-authorized ceremony close | `secure/src/hw/otp.rs`; `docs/security/a-b-firmware-rollback-architecture.md` |
| **B-FW** Vendor HSM ↔ device | Candidate: SPHINCS+C10 signature over Draft 1.1's proposed 121-byte, slot-bound `PQFW_V6` preimage; vendor public key compiled into FSBL | Draft 1.1 is not implementation-approved; production is compile-blocked until exact-digest approval plus manifest-v6, journal/ECC/OTP, FLASH, RAM/stack, release-policy, factory, and silicon gates close | `docs/security/a-b-firmware-rollback-architecture.md`, `fsbl/`, `fwsign/`, `fw-manifest/` |
| **B-CHAIN** Device ↔ on-chain wallet contract | C10 signature wrapped in `SignatureWrapper(uint256 ownerIndex, bytes c10Sig)`; per-chain `slot_entropy = sha256(slot_master‖"slot_entropy"‖chain_id_be8‖slot_index_be4)` so the slot keypair is chain-bound | Contract verifies the C10 sig stateless against the wrapper's `ownerIndex` lookup; trust crosses only via the wallet's own storage | `contracts/smart-wallet/src/{PQSmartWallet,PQSmartWalletFactory,verifiers/SPHINCsC10Asm}.sol` |
| **B-FAB** Factory ↔ device (provisioning) | Future reviewed ceremony; current legacy receipt is quarantined | No factory trust anchor or RDP2 authority exists until the replacement receipt/ordering and silicon evidence are approved | `docs/provisioning/factory-provisioning.md`, Draft 1.1 §13 candidate |
| **B-TZ-S** S code ↔ S code (privilege tiers) | **PLANNED** — Trezor-style MPU banking + secure-privileged/secure-non-privileged SAES key tiers. Currently absent: a bug in any S-world code can call `secret_keys::derive_into{,_bhk}` directly | Within S, one privilege level today | `docs/architecture/trezor-comparison.md §3.2` — tracked, not yet landed |

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

Mechanism: XOR entropy split. `half_O` and `half_E` are independent random and `entropy = half_O XOR half_E` (`secure/src/dual_se.rs`). A break on either chip yields one uniformly-random 32-byte string. Falsifiable by extracting one chip's plaintext and confirming statistical independence from the seed.

> **UPDATE 2026-10-13 (#855, Ledger Donjon report) — this claim was false as built until this date.** The split itself was sound, but each chip also held the PIN in a form that needed nothing from the microcontroller: the SE050 user UserID was the raw eight digits, and OPTIGA F1D0 was one unsalted, unkeyed `SHA-256("optiga-pin-auth-v1" ‖ PIN ‖ 0)`. Reading either chip gave the PIN (directly, or by an offline search of 10^8 values in about a minute, with no counter involved), and the PIN opened the other chip on the first try. A single-chip break was therefore a full break for an attacker holding the device.
>
> What a chip holds now (`secure/src/pin_credential.rs`, `secure/src/pin_gate.rs`):
>
> | Chip | Stored | What it gives an attacker who has no device key |
> |---|---|---|
> | OPTIGA | F1D0 = `PRF(device_key, "…pin-cred-O…" ‖ salt ‖ PIN)`; `half_O XOR PRF(device_key, "…pin-mask-O…" ‖ salt ‖ PIN)`; `master_secret = SHA-256("sphincs-master" ‖ entropy ‖ 0)`; the two verifying keys | No way to test a PIN guess offline; nothing that the SE050 accepts |
> | SE050 | user UserID = `PRF(device_key, "…pin-cred-E…" ‖ salt ‖ PIN)`; `half_E XOR PRF(device_key, "…pin-mask-E…" ‖ salt ‖ PIN)`; the two verifying keys | No way to test a PIN guess offline; nothing that the OPTIGA accepts |
>
> `device_key` is the silicon DHUK, reachable only through the SAES peripheral; `salt` is 32 random bytes in secure flash page 125. The PIN comparison still happens inside each chip (invariant #2); only the value presented changed.
>
> **What remains for a single-chip attacker.** Emulate the extracted chip and let the genuine device compute the credential for each PIN typed in. Page 124 allows ten such guesses, then the device wipes. Three rules keep that at **ten guesses in total, not ten per wipe**:
>
> 1. Every wipe arms the wipe-in-progress flag and then destroys the salt before it sends anything to a chip.
> 2. Page 124 is reset after a wipe only once the salt is verified gone (`hw::flash::pin_attempts_reset_after_wipe`). If the salt could not be destroyed, the chips are still wiped, the wipe reports failure, and the counter stays at its limit, so the next boot wipes again.
> 3. Every provisioning first retires any salt already on flash and draws a new one. Without this an attacker emulating both chips could provision a throwaway wallet with a PIN they know under the old salt, unlock it to reset the counter, and carry on guessing.
>
> **Exception: the duress PIN.** A decoy unlock resets page 124 by design, so that the counter does not give the decoy away. An attacker who holds a chip's contents *and* knows the duress PIN can therefore alternate nine guesses with one decoy unlock for as long as they like; page 124 no longer bounds them. What is left is the attempt counter of whichever chip is still genuine, and only when the emulator lets a guess reach it. This is a property of the duress design, not of #855, and is open.
>
> **What this does not cover.** (a) Code execution in the secure world, or extraction of the DHUK, *plus* one chip's contents: the attacker can then compute the PRF and search the PIN offline (Ledger Donjon scenario C; see Claim 2). (b) `master_secret` on the OPTIGA is a hash of the full entropy — it reveals no bit of it, but it lets someone who already has a candidate seed confirm it. (c) Bench builds: `e2e-test` / `otp-hardcoded-master-key` use a fixed public salt and (for the latter) a constant PRF key, and at RDP-0 the DHUK is a constant shared by every part; none of those is die-bound. Production refuses to derive below RDP-2.
>
> **Evidence level.** The derivation, the per-chip images, the salt lifecycle (including torn writes and power loss mid-destroy), and replays of report scenarios A and B run as host tests (`pin_credential::tests`, `pin_salt::tests`); the firmware wiring is type-checked across every secure-element feature combination and pinned as source text (`pin_gate_wiring_pure_tests`). **Nothing here has been run on silicon yet.** Unmeasured on this project's parts: the 16-byte SE050 user UserID with `max_attempts = 10`; programming zeros over a programmed flash quad-word (RM0456 Rev 7 §7.3.7); how a torn quad-word reads back (if it raises an ECC NMI rather than reading as data, every scan of the salt log would reset); and the device-key PRF itself producing different credentials on two boards. The host tests pass their own PRF, so they say nothing about which key the firmware uses; that rests on the source pins and on silicon. The production mint check (refuse below RDP-2) has never executed in any buildable image, and with #268 open a production image could not reach RDP-2 at all, so it would refuse to provision: fail-closed, but unproven.
>
> **What falsifies this claim (run these).** `cargo test -p sphincs-tz-secure … pin_credential:: pin_salt:: pin_gate_wiring` for the properties; `make check-pin-credential-rules` for the semgrep tripwires; `make verify-pin-credential-gates` to confirm each guard goes red when its defect is put back (scripts/pin_credential_mutations.json lists them). On silicon, still to be written: provision, dump what each chip was given over a logic analyser inside the tunnels' plaintext view, and confirm two boards differ.

**Claim 2 — DHUK / BHK leak is not fund-extracting.**
> An attacker with a Tier-1 DHUK extraction (or future BHK extraction) gains the SE050 admin UserID and the OPTIGA PBS for *this device only*. They can **brick** the device by issuing admin `DELETE` against `half_E`. They **cannot READ** `half_E` — the user-PIN gate is enforced in SE silicon, not by the encrypted channel.

> **UPDATE 2026-10-13 (#855) — narrower than it reads.** The PIN credentials are now PRF outputs under the DHUK. An attacker who has extracted the DHUK (or runs code in the secure world) can therefore compute the credential for any PIN guess. Presented to a chip online, guesses are still capped by that chip's own counter, so the sentence above holds for a DHUK extraction *alone*. Combined with the contents of **one** secure element — which include that chip's credential — the same attacker can search all 10^8 PINs offline, then derive the other chip's credential and both half masks. "DHUK leak is not fund-extracting" is therefore true only while both secure elements are intact. Before #855 one chip's contents gave the PIN with no DHUK at all, so this is strictly better than what shipped in the tree, but it is a real limit on this claim.

Mechanism: SE050 PIN policy template (`apdu::build_policy`, `se050/apdu.rs:339-365`) splits ACs across two entries — user has `READ|WRITE|DELETE|REQUIRE_SM`, admin has only `DELETE|REQUIRE_SM`. Falsifiable by `make se050-admin-extract-attempt-e2e` — already validated 2026-05-11 on B-U585I-IOT02A board #1, ST-LINK SN `0029…3838` (see `docs/security/production-security.md §2.6 "Empirically validated"`). On OPTIGA, `half_O` sits under `Auto(F1D0)` AuthRef with E140 (PBS) authenticating only the channel — the read AC is a different mechanism with the same property; an analogous E2E for OPTIGA is on the list.

**Claim 3 — PIN brute force costs at most 10 wrong attempts before factory wipe.**
> Each ordinary attempt precharges MCU page 124 and exercises OPTIGA E120 plus
> SE050 UserID. Page 124 and SE050 independently enforce the user-facing
> max-10 bound; E120 is a separate silicon-monotonic backstop. At boot,
> firmware reads page 124 and E120 and wipes only if E120 is ahead. The SE050
> remaining-attempt attribute is policy-denied (`0x6986`) and is not a boot
> reconciliation input. Offline brute force against the PIN material persisted
> in a secure element requires the microcontroller's device key (corrected
> 2026-10-13, see the note below).

> **UPDATE 2026-10-13 (#855, Ledger Donjon report).** This claim used to end "Offline brute force against persisted PIN material is structurally impossible because the PIN never leaves SE silicon." Both halves were wrong: the SE050 held the raw PIN and the OPTIGA an unkeyed hash of it, so anyone who read either chip could recover the PIN offline with no attempt consumed. Each chip now holds only `PRF(device_key, label ‖ salt ‖ PIN)` with a different label per chip, so the stored value cannot be searched without the DHUK. The ten-attempt bound also now covers an attacker who emulates an extracted chip: every wipe destroys the salt before it sends anything to a chip, page 124 is reset only once the salt is verified gone, and every provisioning draws a new salt, so the bound is ten guesses in total (with one exception, an attacker who also knows the duress PIN; see Claim 1). Details, residuals and the evidence level are in the note under Claim 1.

Mechanism: three-way per-attempt enforcement, `nsc::gated_unlock` pre-commit,
and `factory_reset_admin` on strike #10, with the directional MCU/E120 boot
check described above. `make pin-gate-hw-counter-e2e` falsifies only the
per-attempt, in-run desynchronization-recovery, and simulated cache-resync
portion; `make pin-gate-wipe-e2e` falsifies the ten-wrong lockout/wipe portion.
The directional boot predicate needs a separate cold-reboot silicon receipt
and remains OPEN.

**⚠️ PROVISIONAL — currently violated by ship blocker S-1 (`EthereumPhone/PQ1`, label `ship-blocker`).** **S-5 + S-6 RESOLVED 2026-05-28**, see closure notes below. Against a *desoldered-OPTIGA bench-rig* attacker (i.e. the threat that motivates the LUC at all), the OPTIGA leg of this claim does not hold in the current build: `F1D0.Change = ALW` (`secure/src/optiga/apdu.rs:930`, `:1059`) lets an attacker overwrite F1D0 with a chosen key, self-auth, and reset E120 indefinitely. On-board ordinary attempts still consume all three controls; firmware-side `gated_unlock` precharges MCU page 124 and SE050 independently enforces max-10, while E120 is a 32-use backstop. This is per-attempt composition, not symmetric three-counter boot reconciliation. Until S-1 is closed (F1D0 metadata tightened to `Auto(F1D0)` + LcsO ratchet), read this claim as "10 wrong PINs against MCU + SE050; OPTIGA contributes belt-and-braces *on-board* only." Re-establishing the OPTIGA desoldered-chip claim requires closing S-1 and re-running `pin-gate-hw-counter-e2e` against a ratcheted, owner-authorized sacrificial part with the tightened metadata.

**S-5 closure (2026-05-28):** `secure/src/se050/scp03.rs` now negotiates `P1=0x33` (full C-MAC + C-DEC + R-MAC + R-ENC); `scp03::unwrap_response` decrypts + R-MAC-verifies every response. `half_E` is no longer plaintext on the I²C bus during legitimate unlocks. Logic-analyzer silicon-verification still required to fully close the audit step. See `docs/security/security-review-2026-05.md` §C-7.

**S-6 closure (2026-05-28):** `store_objects` and `store_duress_objects` pass `None` for the user / duress UserID's admin-delete policy entry; admin can no longer delete + recreate USERID_OBJ to substitute the PIN. Data objects retain the admin entry so DoS-wipe still works. Trade-off: post-lockout, the chip is single-use (USERID_OBJ stays orphaned; OID range bump required to re-provision). NXP's bare `DeleteAll` APDU is gated on `RESERVED_ID_FACTORY_RESET = 0x7FFF0205` chip credential we don't hold — full-chip factory reset from firmware is out of scope. See `docs/security/security-review-2026-05.md` §C-8 + the updated Claim 5 below.

> **UPDATE 2026-10-13 (#912).** This holds for shipping images. Bench images (`e2e-test` / `otp-hardcoded-master-key`) create the user and duress UserID *with* the admin-delete entry, through one constant (`se050::USERID_ADMIN_DELETE`) that a production build asserts is `None`. On a bench image the admin credential derives from a public constant, so S-6 protects nothing there, and an undeletable UserID was costing boards: the bench clean-up had to guess its value and every wrong guess spends one of its ten attempts for good.

**Claim 5 (revised 2026-05-28) — Post-lockout secret state on SE050: *data destroyed, UserID orphaned*.** When the SE050 UserID hits `auth_attempts == max_attempts`, the UserID locks (policy denies further VERIFY). `admin_factory_reset` then opens an admin session against `ADMIN_WIPE_OBJ` and deletes every data object (ENTROPY_OBJ, VK_OBJ, BOOTSTRAP_VK_OBJ — they still carry the admin-delete policy entry per the post-S-6 design); the chip enforces those deletes because the policy explicitly authorises admin. **The data is destroyed in this path.** USERID_OBJ itself remains on chip in its locked state because the post-S-6 policy gives admin NO delete authority on it (S-6's whole point — closes the substitution attack). So the chip is single-use after lockout: the seed half is gone (Claim 7 + the safety contract), but USERID_OBJ at `0x7B10_0000` is now an immutable, locked auth object gating nothing. Re-provisioning the same chip requires bumping the firmware OID range (v6 → v7) so a fresh UserID can live at a different OID; bumping the range is a one-line firmware change but does not recover the original chip's v6 OIDs. **The previous Claim 5 wording ("orphaned, not erased") referred to the pre-S-6 / pre-S-7b state where `iterative_delete_all` Pass 2 silently failed and data survived — that path is closed:** Pass 2 still requires PIN-verified session for UserID self-delete (which lockout precludes), but data wipe via `admin_factory_reset` is the explicit destroy path now, not Pass 2's UserID self-delete. NXP's bare `DeleteAll` APDU (`80 04 00 2A`, AN12413 §4.19.5) would wipe USERID_OBJ too but requires `RESERVED_ID_FACTORY_RESET` chip credential not exposed to our firmware; documented as out-of-scope.

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

Mechanism: no primitive in the trust path gives a quantum adversary better than Grover.
- Signing: SPHINCS+C10 (hash-based, no number-theoretic assumption, no quantum speedup beyond Grover-on-hash).
- SE channels: symmetric-rooted key agreement only (OPTIGA PBS = per-device DHUK-derived pre-shared secret → TLS-PRF; SE050 SCP03 = per-device static AES keys → CMAC KDF). **No public-key handshake crosses the bus**, so recorded traffic contains nothing Shor-breakable; the only attack on a capture is Grover key search on the AES-128 session key.
- Symmetric: AES-256, SHA-256/512, HMAC-SHA256, HKDF-SHA256, PBKDF2-HMAC-SHA512 — all with key sizes sized so Grover leaves ≥ 128-bit effective security.
- Address derivation, EVM hashing: SHA-256 and Keccak-256 — both quantum-resistant under Grover-only.

**Accepted residual (owner decision 2026-07-07, was PRE-PROD-CAVEAT §9.1):** the entropy halves cross I²C under AES-128 session encryption (Shielded Connection CCM-8 / SCP03), so an adversary who physically tapped the bus during a live unlock holds ciphertext attackable at ~2⁶⁴ serial Grover operations per session — NIST Category 1, the same floor as C10's n=16 signatures — and must break both tunnels independently (XOR split, Claim 1). Two conditions keep this acceptance sound: (a) per-device SCP03/PBS rotation (§9.2 ceremony) — session keys derive deterministically from the statics with **no forward secrecy**, so fleet-shared statics would degrade a tapped session to a classical decrypt (the ProVerif `scp03_handshake.pv` static-leak residual); (b) the payload exposure stays unlock-time-only (no half ever crosses outside an authenticated session). The formerly-planned ML-KEM-1024 inner wrap that would have lifted this above the Cat-1 floor is descoped; the prototype is retained feature-gated (`docs/security/ml-kem-inner-wrap.md`).

**Claim 8 — Firmware-update path admits only payloads signed by the pinned vendor key.**
> **Candidate claim, not a current shipping or implementation claim:** a manifest-v6 update is
> admitted only when its C10 signature verifies under the FSBL-pinned vendor
> key and the typed selector/floor state admits its `(release, epoch)` tuple.

Candidate mechanism: immutable FSBL + Draft-1.1 manifest-v6 verification and typed marker/selector/floor interfaces. The runtime may seal a candidate CONFIRMED only after the candidate health flow; only the FSBL may establish `security_epoch - 1`. The eventual approved FSBL range must be protected in both physical banks; the current legacy bench range does not settle candidate geometry or factory authority. Draft 1.1 remains an unapproved research candidate.

> **SHIP BLOCKER (2026-07-14, verified against RM0456 and source).** The implemented V1 path is not a sound production anti-rollback backend. `cmd_fw_commit.rs` raises the floor before candidate health, defeating try-once recovery, and `hw/otp.rs` attempts to reprogram ECC-protected STM32U585 OTP quad-words as a bit tally. There is no OPTIGA firmware-version counter. Draft 1.1 proposes replacement software interfaces but is not implementation-approved; journal hardware/durability, FLASH mutation closure, ECC, OTP codec/capacity, RAM/stack, release policy, factory authority, and silicon evidence remain open. Production, FSBL-release, factory receipts, and RDP2 authority are compile/process blocked meanwhile.

**Claim 9 — Trusted UI faithfully renders signed semantics.**
> Whatever the NV3007 LCD shows in a confirm screen is exactly what the signed `userOpHash` preimage commits to; the user pressing both buttons binds their consent to the displayed bytes.

Mechanism: the confirmation page renderer (`secure/src/tx/display/*`) runs in S-world, reads from the S-stack copy of the parsed UserOp, displays from the S-owned NV3007 LCD via S-driven SPI. The page-renderer code is what hashes into `userOpHash` (i.e. there is no second path that displays one thing and signs another). For ERC-20 the recipient symbol/decimals come from a Merkle-verified bundle (`secure/src/erc20/` checks against the firmware-baked `ERC20_DB_ROOT`); unknown contracts fall through to "⚠ BLIND SIGNING". For structured clear-signed paths (Safe SafeTx / multiSend, CoW `GPv2Order`, ERC-7730 descriptors, typed-call ABI) the payload is decoded **natively on-device** in S-world and the decode is cross-checked against the signed bytes (e.g. `cowswap/verify.rs` binds the rendered order to the settlement calldata; the Safe EIP-712 hash is recomputed locally). Falsifiable by constructing a malicious bundle/calldata and observing rejection.

---

## 6. Cross-cutting Defence Architecture

Three patterns appear across every attack. They are the spine of the design.

### 6.1 Dual-residency rule (the XOR split)
*Every fund-equivalent secret must require both of {OPTIGA, SE050} to recover. Neither chip alone reveals any bit.* This rule is enforced at provisioning (`dual_se::provision`) and at every unlock (`reconstruct_entropy = HKDF(half_O XOR half_E)`). It is what reduces the attack from "compromise one chip" (well-precedented in the literature — Ledger Donjon, Trezor Safe 3) to "compromise two chips from two vendors of two architectures simultaneously."

### 6.2 PIN gate in silicon (three-way per-attempt consumption)
*PIN compare always happens inside SE silicon, never in MCU code.* Each ordinary
attempt consumes page-124, OPTIGA E120/F1D0 authorization, and SE050 UserID.
Page-124 and SE050 enforce the max-10 policy; E120 is a 32-use silicon backstop.
`CMD_GET_REMAINING` reports a conservative user-facing runtime status, not a
three-silicon boot receipt. Boot reads page-124 and live E120 directionally and
wipes if E120 use leads page-124; an MCU lead is retained after cuts/errors.
SE050's attempt-count attribute is policy-denied and is not a boot input, while
blocked authentication still maps to wipe. This keeps PIN attacks online; it
does not claim symmetric three-way boot reconciliation.

### 6.3 Verify-before-release with double-compute (the FI guard)
*Every Type 1 / Type 2 signature is computed twice on disjoint SRAM regions, the two outputs are compared in constant time, and the signature is released only on byte-equal match plus a verify-after-sign hash check.* RFC 9814 §5 explicitly notes that verify-after-sign alone is insufficient for SLH-DSA against single-fault forgery (Genêt TCHES 2023). We do **both**: double-compute closes the Genêt grafting attack; verify-after-sign closes simpler glitches. Code: `crypto::c10_sign_verified*` + FI sentinels in `secure/src/fi.rs`.

These three patterns mean: every named attacker tier must beat *both* a silicon barrier and a code barrier to reach an S0 asset. There is no single-failure point in the system above the silicon-physical layer.

---

## 7. Attack Surfaces and Per-Surface Defences

### 7.1 Seed at rest

| Attack | Tier | Mitigation | Residual |
|---|---|---|---|
| Flash dump of MCU | T2 | The seed never persists on MCU flash. `entropy` is reconstructed in S-SRAM at unlock and zeroized on lock/timeout/tamper/brownout. | Nothing recoverable from MCU flash dump |
| Flash dump of OPTIGA (decap) | T4 | Yields `half_O XOR mask_O`, the F1D0 credential, a SHA-256 of the entropy and the verifying keys. The credential and mask are `PRF(DHUK, label ‖ salt ‖ PIN)` (#855), so none of it yields the PIN or anything the SE050 accepts without the microcontroller (Claim 1) | Ten PIN guesses in total against the genuine device with the chip emulated. **Before 2026-10-13 this row said "yields only `half_O`"; the dump also held an unkeyed hash of the PIN, searchable offline in about a minute** |
| Flash dump of SE050 (decap) | T4 | Yields `half_E XOR mask_E`, the user UserID credential and the verifying keys — same construction, different labels | Same. **Before 2026-10-13 the dump held the raw PIN** |
| Both chips decapped | T4 + T4 | The two stored halves do not XOR to the entropy: each is masked with a PIN-keyed PRF output under the DHUK (#855). Recovering the seed additionally needs the device key and the PIN | With the chips' contents the attacker still needs the microcontroller: ten PIN guesses in total against the genuine device with both chips emulated. With the microcontroller's DHUK as well, an offline search of 10^8 PINs. **Before 2026-10-13 this row claimed the attacker "still needs to use the chip with its silicon-enforced PIN gate"; in fact the two dumps XORed straight to the entropy** |

### 7.2 Seed in transit (SE channels)

| Attack | Tier | Mitigation | Residual |
|---|---|---|---|
| I²C bus snoop (logic analyzer on traces) | T2 | OPTIGA Shielded Connection (TLS-PRF + AES-128-CCM-8, PBS-keyed); SE050 SCP03 (AES-CMAC + AES-CBC). The intended product ships OTP-master-derived transport credentials at RDP0; the first-field candidate rotates SE050 to BHK-rooted finals and OPTIGA to a salted-DHUK final PBS. | Symmetric-rooted AEAD; a capture is attackable only via Grover-2⁶⁴ on the session key — ACCEPTED residual (§7.14, §9.1; owner 2026-07-07). Per-device rotation is load-bearing (no forward secrecy in either KDF); the code exists but its handoff/recovery, silicon, and production gates remain open. |
| MITM with replayed handshake | T2 | SCP03 mutual auth + Shielded Connection's PBS-anchored TLS-PRF; freshness nonce on each session | None known once transport credentials are rotated per device (PRE-PROD-CAVEAT until the candidate is approved and silicon-validated — §9.2) |
| Bus desync / glitch the SE response | T3 | Channel MAC fails ⇒ APDU rejected; tamper response invokes lockout | Untested at production hardness |
| Channel key extraction from MCU OTP | T4 | DHUK only accessible via SAES (peripheral, not memory); BHK uplift (Stage 2) further hardens to "key must be *used* on this specific device" | A decap-class extraction of DHUK is the entry to the residual of Claim 2 — bricks possible, funds not extractable |

### 7.3 Seed in use (S-SRAM during signing)

| Attack | Tier | Mitigation | Residual |
|---|---|---|---|
| Cold-boot attack on SRAM | T2 | Inactivity timeout (120 s) on S-only TIM; `zeroize::ZeroizeOnDrop` on every secret type with compiler fences (`zeroize` crate's IR-level fences, not `core::hint::black_box`); on lock the whole `master_secret` + `SLOT_CACHE` are wiped | The 120-s window is a UX concession. A T3 attacker hitting the window with a freezer trick is the residual; tightenable to e.g. 30 s |
| Read S-SRAM from NS world | T0 (firmware) | GTZC TZSC marks Secure SRAM secure; SAU regions enforce; MPU regions enforced in both worlds | **PRE-PROD-CAVEAT** §9.3: TZSC config currently regressed — see CLAUDE.md "Pre-Production Caveats" |
| DMA-master into Secure SRAM, the OTP or the UID from NS | T0 (firmware; needs non-secure code execution) | **No non-secure DMA master exists (#982, 2026-10-18).** Secure boot makes every GPDMA1 (16) and LPDMA1 (4) channel secure and privileged and locks that with `RCFGLOCKR`, reads it back fail-closed, and secures the TZSC-attributable masters DMA2D/SDMMC1/SDMMC2 (`sau::stm32::secure_dma_masters`, `SECCFGR3_IMAGE`) before NS boots; once a channel is secure its RCC reset/clock bits are secure too, so NS cannot reset the lock away. An NS access to a channel register raises TZIC IER4 `GPDMA1IE` (escalated under `tzic-wipe`) | The SAU filters only the CPU, and the OTP/UID/system-memory area has no secure-only option at all (RM0456 Table 71): before the fix a privileged NS GPDMA channel read the UID and OTP verbatim on EVT silicon (DVT 3.9), and the OTP holds the factory transport master until first-boot rotation. Fixed and silicon-verified on EVT-3D21 (DVT 3.9: all 28 NS DMA cases move nothing, the lock survives an NS RCC reset attempt). LPDMA1's illegal-access event is in GTZC2 TZIC, which is not configured (LPDMA1 reaches only SRAM4/AHB3). |
| Hold the 120 s idle wipe off from NS: a non-secure exception preempts a gateway handler and parks, keeping it "busy" (#981) | T0 (firmware; needs a hostile or compromised signed non-secure image) | Two independent bounds (2026-10-18). (1) IWDG: while a handler is busy the NS heartbeat is not progress, so the 30 s busy cap binds and the watchdog resets the device. (2) SysTick: once the idle wipe has been deferred by a busy handler for 30 s (5 s while a trusted dialog claims to be waiting), the ISR zeroizes and resets, independent of the IWDG and of anything NS writes (`timeout::wipe_defer_step`) | Before the fix a parked handler with a bumped heartbeat held an unlocked session 206 s past the deadline on EVT silicon. After: reset at ~35 s (IWDG build) and at idle ≈ 150 s with the IWDG compiled out (DVT 13.10). A reset during a parked flash write can tear it, as the IWDG always could (F3). Masking NS exceptions during veneers (`BASEPRI_S`) remains the open #846 decision. |
| Nested gateway entry: a non-secure exception handler calls a second gateway entry while a handler is parked in a dialog, and rewrites the shared request buffer after the user confirmed (#846) | T0 (firmware; needs a hostile or compromised signed non-secure image) | The gateway is one-at-a-time by construction: every `cmse-nonsecure-entry` function and the idle re-unlock dialog take `nsc::GATEWAY_GATE` first, and a nested entry is refused before it reads an argument (`secure/src/gateway_gate.rs`). Backstop in the single-sign handler: the calldata is committed before any page is built, the displayed fingerprint must equal that commitment, and the private copy that is hashed for signing must decode back to it (`aa/src/execute_bind.rs`). The batch handler has its own commit and re-bind | Not exercised end to end: the QEMU mailbox cannot nest calls, and a silicon test needs a non-secure fixture that installs a `SysTick_NS` handler. If the gate is skipped by a fault: (1) two exactly timed buffer swaps before the dialog (after the commitment, and again before the fingerprint) would still show one calldata and sign another; (2) under `ui-px` the screen transcript shares the same buffer and is outside the backstop, so a nested call could replace the screens and leave the calldata untouched. The idle re-unlock dialog can still run on top of a preempted short handler (#152); the gate only keeps the non-secure world out during it |
| Bus-snoop the SAES output during signing | T3 | SAES outputs DHUK-keyed values inside the peripheral; never as a bus-visible byte | EM SCA of the SAES is research-relevant; consumption mask (TIM2 CH1 PWM, `hw/consumption_mask.rs`) randomises the power footprint |
| Side-channel on the SPHINCS+C10 PRF | T3 | OptRand mandatory: 16-byte fresh per-signature randomness from STM32 TRNG breaks chosen-message PRF recovery (Saarinen SLotH defence) | Software masking on the SHA-256 hot loop is a hardening-pass item; HASH peripheral has no DPA resistance per UM3370 |

### 7.4 PIN guessing

| Attack | Tier | Mitigation | Residual |
|---|---|---|---|
| Online brute force (USB-driven) | T0 / T1 | Three-way per-attempt consumption; page-124 + SE050 max-10 policy → factory wipe; E120 adds a 32-use backstop | At most 10 ordinary wrong attempts before destructive lockout; boot cross-check remains directional page124/E120 |
| Offline brute force against stored representation | T4 (one SE read out) | Each chip stores only `PRF(DHUK, label ‖ salt ‖ PIN)` with its own label (#855, `secure/src/pin_credential.rs`). The DHUK is reachable only through the SAES peripheral of this microcontroller, so the stored value cannot be searched off the device. Host tests replay the search with and without the device key | Possible for an attacker who has the DHUK or runs code in the secure world *and* has one chip's contents (Claim 2). **Before 2026-10-13 this row said "structurally impossible"; it was a one-minute search for anyone who read either chip** |
| Online guessing with an extracted chip emulated | T4 | Each PIN typed makes the device compute and present that PIN's credential to the emulator, which compares. Page 124 is charged before every attempt. Every wipe destroys the salt before it sends anything to a chip; page 124 is reset after a wipe only once the salt is verified gone; every provisioning draws a new salt | Ten guesses in total, unless the attacker also knows the duress PIN (a decoy unlock resets page 124 by design; Claim 1). Untested on silicon |
| Power-glitch mid-verify to skip the counter bump | T3 | `gated_unlock` pre-commits the counter bump to MCU page 124 *before* the SE driver call; fail-in pattern (`if remaining != 0, continue; else wipe`); FI-hardened complement-storage on the success flag | Untested against state-actor FI; ITAMP9 (crypto-peripheral fault) wired (planned) catches SAES/PKA glitches |
| Shoulder-surf + force device unlock | T5 | Architecturally out of scope (§10.1) | Coercion defeats every PIN-gated system |
| Replay a captured authenticated channel | T2 | Each SCP03 / Shielded Connection session has fresh handshake; no replay window | None |

### 7.5 NSC gateway (NS → S boundary)

The 18 gateway commands (`CMD_GET_REMAINING`, `…SIGN_USEROP`, `…SIGN_OFFCHAIN`, `CMD_FW_*`, etc.) are the only legitimate way for NS code to influence S behaviour. Every command surface is treated as fully hostile NS input.

| Attack | Tier | Mitigation | Residual |
|---|---|---|---|
| NS supplies a pointer into Secure memory to trick S into reading its own SRAM into an "input buffer" | T0 (firmware) | `NsPtr<T>` typestate validates pointer ranges against NS regions only; failure returns `NscStatus::InvalidPtr` before any deref | Bug in `ptr_validate` is a CVE class — fuzzer corpus is a tracked gap (`docs/architecture/trezor-comparison.md §2.4`) |
| TOCTOU — NS races to mutate the buffer after S validates but before S reads | T0 | Every cmd handler copies NS buffers to S-stack before parse | Untested under adversarial NS — fuzzer would catch missed paths |
| Length-confusion — NS lies about a length field to over- or under-read | T0 | Each parser validates length against the declared wire-format (e.g. `data_len ≤ 4096`) before any other byte | `data_len` is `u16 BE`, fits any sane MAX |
| NS spams gateway to drain entropy / battery | T0 | Inactivity timer is S-only; NS pings do NOT reset it. Rate limiter on USB OUT (`docs/security/production-security.md §2.4`) — planned | Battery drain is not a fund threat |
| NS panics S code via crafted input | T0 | `#![deny(clippy::indexing_slicing)]`, custom panic handler that zeroizes secrets before halting; every NSC entry returns `NscStatus` not Rust `Result` so panics cannot escape | Persistent panic = brick (DoS) — not fund-extracting |
| NS exploits a heap | — | Structurally impossible: `#![no_std]`, no allocator, no `Vec`/`Box`/`String` | None |

### 7.6 Trusted UI / display deception (blind-sign or display-vs-sign mismatch)

The single biggest attack class against hardware wallets historically: the device signs X while displaying Y. Most exploits work by giving the device unfamiliar calldata that bypasses the display pipeline.

| Attack | Tier | Mitigation | Residual |
|---|---|---|---|
| Companion supplies forged calldata; device shows a friendly string and signs malicious bytes | T0 | The string and the signed `userOpHash` are derived from the *same* S-stack copy. The render path *is* the hash path. | A *parser* bug that decodes one way and displays another is the residual; covered by typed-call ABI tests + EIP-712 vectors in `secure/src/tx/eip712/{cowswap,safe}/` |
| ERC-20 with a spoofed token contract address | T2 (chain) | ERC-20 metadata bundle is Merkle-verified against the firmware-baked `ERC20_DB_ROOT`; unknown tokens fall through to "⚠ BLIND SIGNING" warning | Unknown contracts still sign — user must reject blind-sign or use clear-sign |
| Hostile dapp tricks user into clear-signing wrong semantics | T0 | Native on-device decode cross-checked against the signed bytes: Safe/CoW EIP-712 verified in S-world, ERC-20 metadata + ERC-7730 descriptors Merkle-rooted into S-flash (a compromised NS cannot substitute a malicious descriptor/root). Anything undecodable falls to loud blind-sign, never a friendly-but-wrong string | Per-protocol coverage expands as a feature-add, not a security gap |
| NS fakes a "user pressed both buttons" to S | T0 (firmware) | The confirm dialog reads buttons via S-owned GPIO; NS cannot drive the GPIO. The inactivity timer is S-only TIM-driven; NS pings do not reset it. | Tamper of S-owned GPIO is a T2+ surface |
| NS races / spoofs the LCD to show a friendly screen | T0 | The NV3007 LCD SPI bus is S-owned via GTZC | TZSC enforcement silicon-validated 2026-05-20 (§9.3) |
| EIP-1271 path used to authorise arbitrary action (Replay against a different chain or wallet) | T0 | EIP-1271 verifier nests the raw hash via Solady EIP-712 with `chainId` and `address(this)` baked in; bootstrap key (`ownerIndex == 0`) forbidden on this path | Mismatch between companion's wrapping and on-device wrapping would refuse to validate — handler hashes the same way |
| **Error-mimicry / attention exhaustion** — companion engineers repeated signing ceremonies ("transaction failed, please sign again") until the user stops reading, or mutates the payload between retries | T0 | **NONE TODAY — added 2026-07-31.** A trusted display defeats display *substitution*; it does nothing against a host that manufactures the *occasion* to sign. This is the shape of the Radiant Capital compromise (Oct 2024, $50M): the front-end showed legitimate transactions while malicious payloads went to the signers, and routine-looking failure errors harvested repeat signatures across retries. Tenderly simulation showed nothing; the post-mortem records that the compromise was undetectable in manual review. | **OPEN.** Proposed mitigation is a signing-ceremony anomaly layer (repeat-prompt detector, semantic-equality retry flag, error-budget → PIN re-entry), all state S-SRAM-only so invariant #8 is untouched. Tracked in the issue tracker; not implemented, and this row must not be read as if it were. |

### 7.7 Firmware integrity (boot)

| Attack | Tier | Mitigation | Residual |
|---|---|---|---|
| Reflash NS or S image with a malicious one | T2 | Draft 1.1 proposes FSBL verification of SPHINCS+C10 over the exact slot-bound manifest-v6 preimage; current V1 path is bench-only and production-fenced | Candidate approval, V6 implementation, physical FLASH + RAM/stack gates, and production-key ceremony remain open |
| Substitute the FSBL itself | T2 | The eventual approved FSBL range must be WRP-protected in both physical banks; the current pages-0..3 linker layout is legacy bench-only | Draft 1.1 geometry, FLASH/RAM fit, exact option bytes, factory receipt, and silicon evidence remain open (§7.11) |
| Downgrade to a vulnerable older firmware | T2 | Draft 1.1 proposes admission only for `security_epoch > rejected_through_epoch`; ordinary same-epoch releases consume no OTP | Candidate approval, physical floor codec, crash-safe establishment, capacity, and silicon evidence are OPEN; production is blocked |
| Boot a substituted image with valid old vendor sig | T2 | The vendor key is one and only one; rotating would require a vendor-key migration design we have not built | Vendor-key compromise = full break (§10.5) |
| Run a debug image with `debug-log`/`e2e-test` on a production unit | T2 | `compile_error!` fences in `nsc/mod.rs` and the `saes-self-test` runner; CI gates production on these flags OFF; user-visible measured-boot 8-BIP-39 words diverge for any feature-flag flip | Pending: vendor-pk-hash OTP lock as a second wall against feature-flag-confusion-by-reflash |

### 7.8 Firmware update channel

The legacy bench transport streams `BEGIN → CHUNK* → COMMIT` over `CMD_FW_*`
with PIN unlock required on every command. Its `PQFW_V1` preimage and rollback
backend are production-fenced. Draft 1.1 proposes an exact 121-byte,
slot-bound `PQFW_V6` preimage plus typed marker/selector/floor interfaces, but
is not implementation-approved; the physical and resource backends remain OPEN.

| Attack | Tier | Mitigation | Residual |
|---|---|---|---|
| Inject a chunk mid-stream | T0 | Chunks accumulate into staging area; COMMIT verifies SHA-256 of staged image against the signed hashes before any write to active flash | None |
| MITM the update bytes | T0 | Sig binds to `secure_hash` and `nonsecure_hash` — bit-flip of any byte fails verify | None |
| Replay an old signed update | T0 | Target selector/floor rejects retired security epochs and orders releases within an epoch | Replacement backend not yet implemented; legacy path must not ship |
| Glitch the COMMIT verify | T3 | FI sentinels on the verify pass; double-checked verify; ITAMP9 (planned) catches crypto-peripheral fault | Untested at production hardness |
| Brick by mid-update power loss | T2 (accidental) | Target contract preserves the confirmed fallback through PENDING/ATTEMPTED and establishes the floor only after CONFIRMED | Unimplemented journal/ECC/OTP recovery is production-blocking; legacy floor ordering can retire the unchanged fallback |

### 7.9 Fault injection (FI)

The Masaryk U Simonik 2024/2025 thesis (76% PIN-glitch on STM32U5A9, same Cortex-M33 family as ours) means we *do not* treat the U5 as glitch-immune. Defence stacks per `docs/security/production-security.md §2.1`.

| Attack | Tier | Mitigation | Residual |
|---|---|---|---|
| Voltage / EMFI glitch to skip the PIN-check branch | T3 | Fail-in pattern (`if remaining != 0, continue; else wipe`); MCU page-124 pre-commit before SE driver call; FihInt complement-storage (0x1AAA_AAAA / 0x1555_5555) on `pin_verified`, `blob_cached`, `match_ok` | Tested against home-equipment glitching; not yet against state-actor lab |
| SLH-DSA single-fault grafting (Genêt 2023) | T3 | Double-compute on disjoint SRAM regions + constant-time compare; signature released only on byte-equal match | RFC 9814 §5 explicitly endorses double-compute as the only defence; verify-after-sign alone is insufficient |
| Skip the on-chain cap check via glitch (off-target) | — | The cap is enforced in Solidity at on-chain execution; the device cannot be glitched into producing a sig that the chain accepts past the cap | Chain is the authority for the cap; device-side glitch cannot loosen it |
| ITAMP-class crypto-peripheral fault (SAES/PKA/TRNG glitch) | T3 | Planned ITAMP9 enable wires SAES/AES/PKA/TRNG fault detection to `trigger_lockout_wipe()` per Trezor `tamper.c:140-166` pattern | PRE-PROD-CAVEAT: TAMP driver currently log-only — `tamp` feature flag must flip to wipe before production |
| Rowhammer-on-bus equivalents | T3 | SRAM2/SRAM3 ECC option bytes (Stage-2 brownout hardening) | Pending option-byte flip on factory line |
| Random-delay glitch sentinel (`wait_random` style) | T3 | Planned — Trezor `random_delays.c:186-202` pattern with the double-invariant `i + j == wait` under volatile pair | Tracked in `docs/architecture/trezor-comparison.md §2.6` |

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
| Mid-transit swap of OPTIGA | T2 / T6 | Boot-time attestation: fresh nonce → OPTIGA ECDSA-signs with `0xE0F0`, cert chains to Infineon Trust M Root CA 2; per-die UID at OID `0xE0C2` compared against factory-pinned value (planned binding manifest, `docs/security/production-security.md §2.5`) | PRE-PROD-CAVEAT: per-device binding manifest not yet landed |
| Mid-transit swap of SE050 | T2 / T6 | Same shape with SE050 attestation via `Se05x_API_ReadObject_W_Attst`; chipId at IDENTIFY compared against factory-pinned; **variant constraint** — only SE050 C/E/F have factory attestation certs at OID `0xF0000013`; A/B/D do not. We use C-class. | PRE-PROD-CAVEAT: per-device binding manifest not yet landed |
| Mid-transit swap of STM32 (recap'd remarked chip) | T2 | Anti-counterfeit probes — CPUID/DBGMCU_IDCODE expected r0p4/`0x482`; UID register validated (lot ASCII range, wafer < 25, not all-0/all-FF); DHUK probe via SAES against factory-recorded fingerprint; ICACHE/DCACHE Stop-mode quirk fingerprints | Tracked in `docs/security/production-security.md §2.5`; specific bit positions need cross-check vs ES0499 |
| Clone with valid-looking attestation from a stolen factory HSM key | T6 | Per-device binding record stored 3× (STM32 flash wrapped, SE050 object 0x10000001, OPTIGA OID 0xF1D1); SHA-256 anchor written to OTP bytes 6-37; transparency-log Merkle anchor (planned) catches devices missing from log | Until transparency log lands, a single HSM compromise can produce valid devices. Plan = SLH-DSA-128s factory manifest under M-of-N HSM ceremony |
| Pre-first-boot intercept (flash a key-exfiltrating stub, boot once, restore real FW) | T6 | Defence stack: secure-boot chain + tamper-evident packaging + WebUSB box-opening ceremony at `verify.pqsigner.io` that re-verifies all three UIDs + manifest sig + firmware hash | Honest residual — the factory supplies only OTP-master-derived transport credentials, while final SE050 keys derive from the post-lock BHK and final OPTIGA PBS from post-lock DHUK plus fresh salt. **ADOPTED 2026-07-14 (work-todo #36):** devices ship at RDP-0 so anyone can SWD-verify flash/option-bytes/OTP before first power; secure-app early boot self-locks to RDP-2 before final rotation. Non-verifying users stay exposed to a transit reflash-and-self-lock — tamper-evident fulfillment + #22 are the mitigations |
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
| Steer a slot to on-chain exhaustion via `CMD_OFFCHAIN_SYNC` (sweep 2026-10-13 #2) | T0 + one user confirm | `aa::offchain_gate::sync_verdict`: a sync that would leave the slot 0 signatures is refused (no dialog, no write); a jump > 1,000 or < 1,000 left adds a `! CAREFUL` page; the dialog shows device count, app count and signatures left in plain language. An exhausted slot is recoverable by rotating to the next slot (protocol 0x0203 returns the new owner bytes, #353) | The device cannot see on-chain `slotUses`: on a restored device a confirmed sync can still exhaust a heavily used slot (warned unless < ~1,000 were left on-chain). Recovery costs one bootstrap use (S6) |
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
| **Companion DISTRIBUTION channel compromised** (not the companion's logic) | T0/T6 | Partly structural: the device decodes and renders from its own S-stack copy, so a poisoned companion cannot change what the screen says. The Ledger Connect Kit incident (Dec 2023) is the reference shape — a phished npm session token shipped three poisoned versions of a library embedded in hundreds of dApp front-ends for ~5 hours, and the poison persisted on CDN caches after the npm fix. The devices were never compromised; the channel between user and device was. | **PARTIAL — added 2026-07-31.** T0 already models a "supply-chain-compromised npm package on the dapp side" (§4), so the class is in-model; what is NOT covered is our own companion's release path: reproducible companion builds, release attestations, SRI/lockfile pinning, maintainer hardware-2FA and session-token hygiene. The residual is that a user cross-checks the device screen against what a poisoned companion told them to expect. |
| ZLP race / DWC2 TxFIFO atomicity (ES0499 §2.26.x) leaks stale FIFO data from a prior session | T0 (device side) | Driver enforces single-packet transfers (`DIEPTSIZ.XFRSIZ = DIEPCTL.MPSIZ`), no interleaving in ISR, flushes all FIFOs on USB reset (`GRSTCTL.RXFFLSH \| TXFFLSH` with TXFNUM=0x10) | Confirm against ES0499 Rev 11 — research-cited sub-section numbers partially verified |
| Stuck-NS via flood of OUT reports | T0 | **CORRECTED 2026-07-31 — the token bucket this row used to describe does not exist.** It was **DESCOPED-WITH-RATIONALE 2026-05-28** (a frame-level ~200 reports/s cap false-trips legitimate APDU-chained transfers: one 8 KB `FW_BEGIN` manifest fans out to ~33 chained `seq=0` frames in ~165 ms, i.e. right at the cap — see [`work-todo` archive](../archive/work-todo-retired-2026-07-19.md) "HID OUT rate limiter"). What actually covers this today: (1) **DWC2 RX-FIFO hardware NAK backpressure** — USB-level flow control the device cannot be overrun through; (2) the **F-17 sign-rate limiter** (`secure/src/sign_rate.rs`, 1 sig/s + 250/session) plus the PIN gate on the only expensive path; (3) malformed frames are dropped by the assembler in µs. | Battery / DoS only. **Note the IWDG is NOT a backstop for this case**: a live flood keeps the NS main loop *running*, so the heartbeat keeps being published and IWDG never fires — IWDG detects a **stalled** loop, not a **flooded** one. Re-open a bucket only if profiling shows a USB-level DoS that RX-FIFO backpressure does not absorb. |
| Buffer overflow in APDU reassembly | T0 | Bounded APDU reassembly: `4 ≤ declared_len ≤ 4096` at seq=0; 5 s timeout with buffer scrub; abort if seq=0 arrives mid-reassembly | Fuzz coverage is a tracked gap (`docs/architecture/trezor-comparison.md §2.4`) |
| EMFI on `min()` length-clamping (Colin O'Flynn WOOT 2019) | T3 | FI-resistant `fi_min` pattern (`if r > a \|\| r > b { return min }`); post-transfer assert `DIEPTSIZ.XFRSIZ` did not exceed declared length | Production hardness untested |
| Host-side keylogger captures PIN typing | T5 (effectively) | The PIN is **never** typed on the host. PIN entry is via on-device buttons through the trusted UI dialog (`secure/src/ui/pin_entry.rs`). The host never sees a PIN byte. | None — the host is never on the PIN path |
| BadUSB injects HID keystrokes simultaneously | T1 | Device buttons are S-owned GPIO — host cannot synthesize button presses. NS code reading buttons is irrelevant since the S-only confirm dialog reads them itself | None |
| Migration to OTG_HS (which has DMA) | — | Architectural ban — we use OTG_FS deliberately so all USB data is CPU-mediated and GTZC/TZ protections apply to every byte | Tracked invariant — do not migrate |

### 7.14 Quantum (CRQC)

| Attack | Tier | Mitigation | Residual |
|---|---|---|---|
| Shor against classical signature in the trust path | T7 | None exist. All signatures are SPHINCS+C10. | None |
| Shor against SE classical channel keys captured from historical traffic | T7 | Not applicable — both SE channels key from *pre-shared symmetric* roots (per-device PBS / SCP03 statics); no key agreement crosses the bus, so a capture contains no Shor target. The correct quantum attack is Grover key search on the AES-128 session key: ~2⁶⁴ serial ops per captured session (Cat 1), physical tap required, both tunnels needed (XOR split). | ACCEPTED §9.1 (owner, 2026-07-07); conditional on per-device key rotation (§9.2) — no forward secrecy in either KDF |
| Grover against 128-bit symmetric primitives | T7 | All symmetric primitives sized so Grover leaves ≥ 128-bit effective. AES-256, SHA-256, HMAC-SHA256 all qualify | None |
| Grover-on-hash against the SPHINCS+C10 preimage | T7 | C10 is sized as SHA-256-based at the post-Grover effective level | None |
| Quantum key search against the device's per-slot `slot_entropy` | T7 | `slot_entropy` is a 256-bit SHA-256 output — quantum search effective bit-strength = 128 bits | None |

### 7.15 Physical destructive (decap, microprobe, FIB)

| Attack | Tier | Mitigation | Residual |
|---|---|---|---|
| Decap STM32 to probe device roots / candidate OTP state | T4 | DHUK is SAES-only; the target BHK is DHUK-wrapped and becomes "must keep code running on this specific device." The factory OTP master is transport-only; its legacy field-auto-burn/final-root use is production-rejected. Candidate rollback/vendor OTP records are non-secret but integrity-critical. | Tier-4 lab is the residual for silicon roots; candidate OTP authority remains blocked pending its backend and ceremony. Cost is dominated by single-shot per-device destructive work. |
| Decap OPTIGA to extract `half_O` | T4 | EAL 6+ rated; without `half_E` extraction the seed is XOR-blind | Two-chip decap is the brute-force lower bound |
| Decap SE050 to extract `half_E` | T4 | EAL 6+ rated; same as above | Two-chip decap is the brute-force lower bound |
| FIB read of TAMP backup registers (BHK) | T4 | Post-Stage 2 — TAMP-BHK with `TAMP_SECCFGR.BHKLOCK` makes BHK SAES-only; FIB on TAMP backup registers is the residual surface | Tier-4, single-shot per device |

**What "EAL 6+ rated" above does and does not cover** (added 2026-07-17; see
[`docs/verification/hardware-assumption-boundary-2026-07-17.md`](../verification/hardware-assumption-boundary-2026-07-17.md)
§1(e) and `HW-ASSUME-SE-INTERNALS` / `HW-ASSUME-SE050-CERT-VERSION` in
[`HW_ASSUMPTIONS.json`](../../contracts/verification/docs/HW_ASSUMPTIONS.json)):

- **The decap rows are within scope.** Physical attack resistance of the die *is* what these
  certificates evaluate, which is why the citation belongs on exactly these two rows and nowhere
  else in this document.
- **OPTIGA — the boundary is sharp.** BSI-DSZ-CC-0961 (EAL6+/ALC_FLR.1) covers the **IC platform**:
  hardware, IC dedicated software, and the Infineon crypto libraries, on a 16-bit
  Intel-80251-compatible core. The Trust M **applet** — its object/OID model, access conditions,
  `LcsO` lifecycle, and the Shielded Connection — is IC *Embedded Software*, **above** the certified
  boundary; the report assigns application data handling to the environment (`OE.Resp-Appl`). So no
  row anywhere may read "discharged by EAL6+" for an OID/AC/LcsO/shielded property. Cite the current
  certificate version, not V4-2019, which **expired 2024-12-17**.
- **SE050 is genuinely stronger.** NSCIB-CC-180212-CR5's TOE includes the JCVM/JCRE/JCAPI — the layer
  that enforces our UserID PIN policy. It explicitly does **not** rate cryptographic protocol
  strength, so it does not cover SCP03-as-deployed. The part is the SE050E2 (`SE050E2HQ1/Z01Z3Z`, applet
  7.2.0, confirmed 2026-10-19), but whether its JCOP release is inside the certified TOE is
  unconfirmed (`HW-ASSUME-SE050-CERT-VERSION`).
- **A certificate is bounded expert effort, not a proof.** EUCLEAK is the standing refutation: a
  non-constant-time modular inversion in the Infineon cryptolib went unnoticed for *"14 years and
  about 80 highest-level Common Criteria certification evaluations"* (NinjaLab). Demonstrated on a
  YubiKey 5Ci (SLE78); NinjaLab reports the vulnerability "extends to" OPTIGA Trust M — suspected,
  not demonstrated, on our part. Not a live exposure for us regardless: invariant #5 means we never
  invoke OPTIGA's ECDSA (the driver has no asymmetric ops at all).

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
2. **Hardware PIN gating, three-way per-attempt consumption.** Defends Claim 3. Defeats software-side PIN-compare bugs; boot reconciliation remains the narrower directional page124/E120 check.
3. **E2E encrypted SE tunnels.** Defends §7.2 row 1. Defeats unaided I²C bus snoop and replay.
4. **All secrets only in TrustZone secure world.** Defends §7.5 and §7.3 row 2. Defeats every NS-side firmware compromise from being seed-extracting.
5. **One signature primitive: SPHINCS+C10.** Defends Claim 7 (no classical signature in the trust path) and Claim 4 (no second verifier to backdoor). Defeats Shor against the signing path.
6. **Bootstrap C10 keys immutable per-wallet.** Defends Claim 6 cross-chain address stability. Defeats a class of "rotate to a new key" social-engineering scams.
7. **Per-chain caps monotonic, unresettable.** Defends Claim 6 / §7.12. Defeats off-chain rollback / reset attacks.
8. **Stateless slot selection.** Defeats per-signature flash-state corruption attacks — the only per-signature flash state is the page-123 EIP-1271 counter; everything else is companion-supplied and re-derived in SRAM.
9. **Off-chain sig counter, combined cap.** Defeats EIP-1271 over-spending; defeats post-restore unregistered-slot signing.

**F3 residual — page-123 compaction crash-atomicity.** The page-123 off-chain
counter store is a log-structured journal compacted in place (erase-then-replay,
single page, no two-phase staging), so a physical power-loss / reset timed
*inside* the compaction window can tear it. Because "slot registered" is derived
from "≥1 journal entry exists", a tear could leave a slot registered with a
counter rolled back. This is **physical-fault-only** (not companion-reachable —
it needs a precisely-timed reset during compaction). The compaction now replays
the unbounded, no-on-chain-backstop `USEROP_SIGS` few-time tally **first** per
slot (`flash.rs::compact_page`), so the security-critical "registered but
few-time tally rolled back" state is unreachable: a tear before it leaves the
slot *unregistered* (invariant #9 forces a Type-1 re-registration), and a tear
after can only roll back the COUNT/USEROP counters, which are bounded by the
firmware gap ≤ `MAX_OFFCHAIN_GAP` and backstopped by the on-chain
`_setOffchainSigCount`/`slotUses` monotonicity. The remaining bounded
COUNT/USEROP roll-back, and full crash-atomicity via a two-page ping-pong /
commit marker, are tracked as a hardening follow-up. The **on-chain** caps
(invariant #7) are unaffected — they live in contract storage, not flash.

**SOL6 design note — cross-slot `removeOwnerAtIndex` authorization (owner
management).** *UPDATE 2026-10-20: resolved by deletion.* For the Trail of
Bits audit freeze the owner decided to delete `removeOwnerAtIndex` (#131,
#213). The device could never build that UserOp; the function let any slot
key remove any other slot, and remove + re-add reset a key's per-chain budget
(#131). The owner set is now append-only, a key can be installed only once,
and a slot-signed op carrying the old selector (`0x89625b57`) fails validation
(`test_removedRemoveOwnerSelectorFailsValidation`, Halmos
`check_removed_selector_does_not_dispatch`). The accepted residual is that
there is no on-chain revocation: a leaked slot key stays usable until its
per-chain cap is spent, and recovery means moving funds to a new account
index (`contracts/smart-wallet/AUDIT_REVIEW_GOALS.md` §4). The rest of this
note describes the removed design and is kept for history.
In `PQSmartWallet._validateSignature`, the H-3 ownerIndex-parity
check (calldata's first arg must equal the signed wrapper `ownerIndex`) is
**deliberately skipped for the `removeOwnerAtIndex` selector** — its first arg is
a *removal* index, not the signer's index. The consequence is that any active
slot key at index *i* ≥ 1 can sign `removeOwnerAtIndex(j, ownerBytes_j)` for any
*other* non-bootstrap slot *j* ≥ 1 (`ownerAtIndex(j)` is a public getter, so the
`ownerBytes_j` argument is not secret). This is an **intra-wallet availability**
property, **not fund theft**: a removed slot cannot move funds, the bootstrap
owner (index 0) is `removeOwnerAtIndex`-unremovable (`_removeOwnerAtIndex`
rejects index 0), and the bootstrap key can re-add any pruned slot, so recovery
holds. It is surfaced here for completeness — the code comment in
`_validateSignature` indicates it is intended, and the behavior is **pinned by
`test_sol6_crossSlotRemoveIsAcceptedByDesign`** so a future decision to bind
*i == j* for the remove selector is a deliberate change, not a silent
regression. Whether "any slot may prune any other slot" should be tightened to
"a slot may only remove itself" (binding *i == j*) is an **open design decision**
for the owner-management model; it does not affect `theft_free`
(no fund movement) and would require re-freezing the wallet codehash.

The hardening regressions that knowingly violate one or more of these are listed in §9.

---

## 9. Pre-Production Caveats (knowingly live regressions)

Each item here is a regression we accept *only* on the bring-up branch. CI gates production builds against them.

### 9.1 ML-KEM-1024 inner wrap — DESCOPED; residual ACCEPTED (owner decision 2026-07-07)
*Affects Claim 7 only on captured bus traffic.* No longer a pre-prod caveat to close: the owner accepted the bus-capture residual permanently. `half_O` and `half_E` cross I²C under the SE channels' AES-128 session encryption; since both channels are symmetric-rooted (no handshake on the wire), the strongest quantum attack on a capture is Grover-2⁶⁴ per session with a physical tap during a live unlock, twice over (XOR split) — Category 1, the system's uniform floor. The earlier wording here ("break the channel key agreement") overstated the exposure; with per-device statics there is no key agreement to break. **Load-bearing condition:** per-device SCP03/PBS rotation (§9.2) — neither KDF has forward secrecy, so leaked/fleet-default statics make a tapped session classically decryptable (one half only; contained by Claim 1). The prototype implementation (hybrid ML-KEM-1024 + HMAC(HUK) + AES-256-GCM, QEMU-validated) is retained behind off-by-default features with production fences — see `docs/security/ml-kem-inner-wrap.md` and work-todo #9 for the decision record.

### 9.2 Factory provisioning (per-device SCP03 + PBS) is not yet automated
*Affects Claim 2 against any device that has not been rotated.* The first-boot self-provisioning flow (work-todo #36 — devices ship at RDP-0 with factory-installed, OTP-master-derived *transport* credentials; secure-app early boot self-locks to RDP-2; SE050 rotates to unsalted BHK-rooted final SCP03/admin credentials; OPTIGA rotates to a final DHUK + page-127-salt PBS) is **device-side implemented 2026-07-14** behind feature `rdp2-self-lock` (host-tested; silicon-validation and protocol-closure pending — see `docs/provisioning/first-boot-provisioning.md`). Until it is approved, silicon-validated, and shipping, bench boards may use published/default or development credentials. **Pre-production only.** No shipping device passes QA without the factory transport-keyset install, and no device is user-ready until its first-boot rotation completes.

### 9.3 TZSC peripheral allowlist is regressed to all-NS
*Affects Invariant #4.* `secure/src/sau.rs` clears `GTZC1_TZSC_SECCFGR{1,2,3}` to 0 because USB OTG FS is on AHB2 (governed by GTZC2 — base address not yet confirmed; first guess bus-faulted). I²C1 / AES / HASH / PKA / SAES / RNG reachable from NS until restored. Fix: adopt Trezor's per-peripheral S-allowlist (`docs/architecture/trezor-comparison.md §1.1`).

### 9.4 Boot-time SE attestation is not yet landed
*Affects §7.11 — chip-swap defence is provisioning-time only today, not runtime-recurring.* The full binding manifest + boot-time triple-UID verification per `docs/security/production-security.md §2.5` is the production gate.

### 9.5 TAMP IRQ handler is log-only
*Affects FI residual in §7.9.* `secure/src/hw/tamp.rs` currently logs on tamper events rather than invoking `trigger_lockout_wipe()`. The Trezor `tamper.c:140-166` pattern (ITAMP1-3, ITAMP5-9, ITAMP11) needs to be ported and the IRQ handler must wipe before production.

### 9.6 Debug logging may ship in this branch
`debug-log` allowed on hardware in current bring-up; `secure_log!` in the wizard; NS pre-USB register dumps; DHCSR-gated semihosting prints in `hw::hash::init_clock`. CI must gate production on `debug-log` / `e2e-test` / `mock-se` / `otp-hardcoded-master-key` / `ui-capture` OFF. The `compile_error!` fences in `nsc/mod.rs` and the `saes-self-test` runner enforce most of this.

### 9.7 Domain-separation tags are sticky-but-renamable
The tag `"sphincs-c6-v1"` is historical (was a different parameter set when written; now C10). Do not rename mid-bring-up (re-provisions every bench board); coordinated cleanup pre-launch is fine. **PROD-INVARIANT after first shipment** — once a device exists with funds, the tag is frozen forever (Invariant #6 cross-chain address stability depends on it).

### 9.8 Vendor-pubkey OTP hash lock is not yet burned
A re-flashed FSBL today could substitute a different vendor key and the device would not refuse. Defence: `FLASH_OTP_BLOCK_VENDOR_PK_HASH` per `docs/architecture/trezor-comparison.md §1.2`. Production gate.

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
A device intercepted between factory and unboxing, with the case opened and a different firmware flashed, can try to consume the genuine first-field transition or install attacker-chosen post-lock state before the owner verifies it. The OTP transport master is already factory-burned, but the BHK first-write and OPTIGA salt generation occur on the device, so running an attacker image first remains the relevant risk. Defence stack: secure-boot chain + tamper-evident packaging + WebUSB box-opening ceremony at `verify.pqsigner.io` that re-verifies all three UIDs + manifest sig + firmware hash. The defence is *not* purely cryptographic; it includes a procedural + UX honesty layer.

### 10.5 Quantum-relevant break of SHA-256
Grover halves the effective bit strength of any preimage / hash search. We size all symmetric primitives to 256 bits so the post-Grover effective is 128 bits, which is the accepted PQ-symmetric baseline. A *novel* break of SHA-256 collision resistance or preimage resistance below √n is out of scope.

### 10.6 Cryptanalytic break of SPHINCS+C10
A novel attack on the SPHINCS+ family — beyond the well-understood single-fault grafting that we defend with double-compute — would be a research event. We track NIST PQC announcements; the C10 parameter set is the FIPS-205 round-3 finalist at our chosen security level. No known break below the parameter-set's design security.

### 10.7 MEV / front-running / on-chain ordering attacks
Out of scope of the wallet. The wallet signs what the user confirms on the trusted UI; chain-level ordering / sandwiching is a dapp / chain-level concern. Mitigation lives in dapp UX (slippage limits in calldata that the trusted UI displays correctly via §7.6), not in the wallet.

### 10.8 Privacy / deanonymisation (S7)
**User-facing disclosure: [`docs/companion/companion-privacy-disclosure.md`](../companion/companion-privacy-disclosure.md)** (added 2026-07-31) — what the companion can and cannot see, stated plainly, plus the account-index mitigation. A passive on-chain observer can correlate a wallet's deterministic CREATE2 address across chains. The same 24 words → same address on every chain is a *feature* (recovery UX); the privacy cost is acknowledged. Mitigation must come from off-device tooling (per-tx address rotation requires breaking Claim 6, which we explicitly do not do).

### 10.9 Stuck-in-display-pipeline bugs
If a future contract uses ABI patterns the typed-call parser doesn't handle, the user sees "⚠ BLIND SIGNING" and signs at their own risk. We do not ship a typed-call parser that decodes unfamiliar ABIs into friendly strings without a firmware-pinned descriptor / Merkle-verified binding (§7.6). This is a *feature* — refusing to invent a display is safer than inventing one wrongly.

### 10.10 Bugs in our dependencies
`sphincs-c10/` and `bip39/` are in-tree and reviewed line-by-line. Every external crate that touches secrets is pinned and reviewed. Despite that, "every shipped wallet vulnerability in history" is implementation bug. The honest residual is: an implementation bug in a code path we have not yet audited or that lands post-audit is the most likely failure mode. Mitigation = external audit before shipping + bug bounty + gradual rollout, per HARDENING §12.

---

## 11. Empirical Verification

These are tests that *back* threat-model claims, not just unit tests. Each is reproducible from the Makefile.

| Test | Falsifies | Status |
|---|---|---|
| `make e2e` | Gateway sign path under mock SEs in QEMU | Passing |
| `make e2e-hw` | Gateway sign path on real STM32U585 + dual-SE | Passing 2026-05-12 |
| `make pin-gate-hw-counter-e2e` | Claim 3 — three-way per-attempt consumption, in-run desynchronization recovery, and simulated cache resynchronization; no reboot/reconcile coverage | Passing for stated scope |
| Cold-reboot page124/E120 reconciliation on silicon (target not yet implemented) | Claim 3 boot edge — exact E120-leading state wipes before unlock/gateway exposure; exact MCU-leading state cold-boots without wiping and preserves the conservatively charged MCU debt | **OPEN — not implemented or run; requires a fresh owner-authorized sacrificial part** |
| `make pin-gate-wipe-e2e` | Claim 3 — 10-wrong factory wipe + page-124 erase | Passing |
| `make se050-admin-extract-attempt-e2e` | Claim 2 — admin can DELETE but not READ user-PIN-gated secrets on SE050 | Passing 2026-05-11 |
| `make saes-self-test-hw` | SAES driver + DHUK round-trip + 8-byte fingerprint cross-board consistency | Passing |
| `make optiga-hw-counter-e2e` | OPTIGA E120 LUC + F1D0 binding | Passing |
| `forge test -vv` (in `contracts/smart-wallet`) | Claims 4, 5, 6 on-chain | Passing |
| `cargo test -p sphincs-tz-secure --tests --release` | Pure-logic primitives, NIST PQC test vectors | Passing |
| `make test-key-speed` | DWT-timed signing bench; SCA-window characterisation | Passing |

Tests that *should* exist but don't yet:

- libFuzzer / cargo-fuzz harnesses against `parse_cmd_sign_userop_input(&[u8])` and the APDU parser (`docs/architecture/trezor-comparison.md §2.4`).
- An analogous `make optiga-admin-extract-attempt-e2e` mirroring the SE050 test for Claim 2's OPTIGA side.
- A scripted FI sweep — voltage glitch on the PIN-verify branch — even at home-equipment hardness, to characterise residual against §7.4 / §7.9.
- Zeroization-verification SRAM scan after every signing test (HARDENING §11).
- Screenshot-hash UI regression covering every confirm-dialog state, including blind-sign and the native clear-sign paths (`docs/architecture/trezor-comparison.md §2.3`).

---


### 11.4 Known-attack regression matrix (added 2026-07-31)

Every publicly documented hardware-wallet attack should exist here as a named
test, bench sweep, or design note — not as folklore. The citations below are
**not** re-derived: they are the ones already fact-checked, with hallucinations
adjudicated, in [`production-security.md`](production-security.md) §"research
round citation audit". Cite through that table, not through this one.

| Historical attack | Class | Our status | The specific missing piece |
|---|---|---|---|
| Rashid vs Ledger Nano S (2018) — MCU↔SE isolation bypass | Architecture | Dual-SE XOR split; no single chip holds the seed | **Do not state this as "keys never on the MCU"**: unlock reconstructs full entropy in Secure SRAM and caches slot secrets there for the signing window (`dual_se.rs`, `nsc/state.rs`). The split defeats single-chip extraction and at-rest compromise (single-chip extraction only since 2026-10-13: until #855 either chip also held the PIN — see Claim 1), *not* a compromised secure-world image — measured boot + RDP-2 + TrustZone are what answer that |
| wallet.fail vs Trezor (35C3, 2018) — FI during FW-update RAM staging | Fault + update flow | Sentinel FI gates in `fw_update`, measured boot, panic/reset zeroization | **No sweep injects during the staging window.** `tools/sca/` has 13 `fault_sweep_*.py` and none targets the CHUNK-accumulate → COMMIT-verify transition — filed as its own issue |
| Kraken Security Labs vs Trezor One / Model T (2020) — RDP-downgrade glitch, ~$75, 15 min | Fault + config | `rdp2-self-lock`, TAMP wipe, PIN-in-SE, no seed in MCU flash | Per-unit option-byte attestation (the bench unit is not unit #4,312); U585 glitch replication |
| Castelnovi/Genêt grafting trees vs SPHINCS signing (2018–2023) | Algorithmic fault | Double-compute + CT compare + verify-before-release + relock (`crypto.rs`), RFC 9814 §5 cited in §6.3 | Bench quantification of the *correlated*-fault residual (same fault in both passes) |
| Colin O'Flynn "MIN()imum Failure" (WOOT 2019) | FI on length clamps | `fi_min` pattern + post-transfer `DIEPTSIZ` assert (§7.13) | Production hardness untested on silicon |
| μ-Glitch (USENIX Sec 2023) — 4-fault TrustZone-M bypass | FI on TZ | SAU/GTZC config silicon-validated 2026-05-20 | Multi-fault model is not covered by the current single-injection sweeps |
| TROPIC01 laser FI bypass of signature verification (2026) | SE fault | The lesson *is* our design: the authorization decision sits behind a silicon boundary, and that chip's secret store survived full CPU compromise | Extend bench LFI/EMFI to our SE command paths, within disclosure norms |
| Ledger Connect Kit (Dec 2023) — poisoned library in dApp front-ends | Companion supply chain | Device renders from its own S-stack copy | Our companion's own release path — see the new §7.13 row |
| Radiant Capital (Oct 2024) — display-legit / sign-malicious + error-mimicry harvesting | Host + human | Trusted display defeats the substitution half | The harvesting half — see the new §7.6 row |
| TrapDoor (2026) — `build.rs` malware, `CLAUDE.md` persistence | Supply chain / AI | `cargo-deny` sources+bans, `cargo-vet`; **CODEOWNERS on AI-instruction files and an invisible-Unicode gate landed 2026-07-31** | Zero-day-malicious dependency detection (behavioural, not advisory-DB) |
| Address poisoning / homoglyph phishing (ongoing) | UX | Stronger than the usual answer: **all non-ASCII is refused** on trusted strings (`tx/src/wire.rs`, `pqsigner-erc7730/src/ir.rs`), so confusables cannot reach the display | Intra-ASCII lookalikes remain, and live in DB curation rather than rendering |

**Ownership rule:** a new public wallet attack becomes a row here within days,
with an explicit "missing piece" cell. A row whose missing piece is empty must
name the test that closes it.

### 11.5 Maintenance cadence (added 2026-07-31)

A threat model that ages silently is the most dangerous kind — this document
carried a defence in §7.13 for two months after it was descoped (the HID token
bucket; corrected 2026-07-31). To make that harder:

1. **Re-walk §7 on each minor firmware release**, and whenever an attack row in
   §11.4 changes status.
2. **Every mitigation cell must be falsifiable from the repo.** If a cell names
   a mechanism, `grep` must find it. The token-bucket row failed exactly this
   test and nobody ran it.
3. **An EMB3D property→threat crosswalk** (MITRE EMB3D v2.0.2) is a useful
   external cross-check and is worth producing once; TID-level numbers should be
   pinned to a stated EMB3D version, because they move between revisions.
4. **Feed post-launch detections back in**, upgrading theoretical leaves to
   evidenced ones rather than leaving them at "designed against".
5. **Weekly AI sweep (UPDATE 2026-10-13).** `make security-sweep`
   (`tools/security-sweep/`) runs attacker-goal hunters (seed, PIN, NS leak,
   sign-unseen, signing oracle, on-chain, state, persistent code, production
   config) with Claude (Kimi optional), has a fresh agent try to refute every
   finding, deduplicates it against the issue tracker, and writes issue drafts.
   It is organised by attacker goal rather than per claim, because the #855
   break (one dumped SE → PIN → seed) falsified Claim 1 *and* Claim 3 together
   and was missed by checks of each claim's wording. It is a lead generator,
   not evidence: an empty week means "nothing new found", not "claims hold".

## 12. Roadmap to Production Posture

In approximate phasing — the source of truth is the `EthereumPhone/PQ1` issue tracker (labels `source:work-todo` / `source:production-todo`), this is the threat-model lens on the same work.

1. **Phase 0 — Device root-key architecture (work-todo #24).** Closes the OPTIGA-PBS-firmware-hash brick (§7.7 / §9.5-related). Lands `hw/otp.rs` master + `hw/secret_keys.rs` HKDF subkeys + OPTIGA `setup_pbs_no_handshake` rewrite + `hw/huk.rs` re-root. **Landed** (Tier 1 SAES-CMAC(DHUK)).
2. **Phase 1 — Stage 2 brownout foundation (work-todo #21).** BOR/IWDG/ECC/PVD/TAMP/CSS at production defaults. Closes Masaryk-class glitch attacks (§7.9). Tracked.
3. **Phase 2 — SCA mandatory minimums (work-todo #18 P0).** OptRand + double-compute + FihInt + PIN-lockout fail-in. Closes §7.10 and §7.4. Largely landed; FihInt complement-storage pass in progress.
4. **Phase 3 — USB hardening (work-todo #19).** FI-resistant min + bounded reassembly + DWC2 errata workarounds. Closes §7.13.
5. **Phase 4 — Provisioning (work-todo #20 + #36).** Factory burns the per-device OTP transport master, installs SE-internal state on derived transport credentials, and ships at RDP-0 (user-verifiable before first power); on first field boot secure-app early boot self-locks to RDP-2, writes the BHK, rotates SE050 to BHK-rooted finals, and rotates OPTIGA to a DHUK + persisted-salt final PBS. Binding record via #22. Closes §7.11 + §9.2 only after the open protocol/silicon gates close.
6. **Phase 5 — Supply-chain attestation (work-todo #22).** SLH-DSA binding manifest + boot-time triple-UID + transparency log + WebUSB ceremony. Closes §9.4 + tightens §7.11.
7. **Phase 6 — ML-KEM-1024 inner wrap. DESCOPED 2026-07-07** (owner decision): §9.1 residual ACCEPTED instead of closed — Claim 7 stays conditional on the Grover-2⁶⁴/physical-tap bound and on per-device key rotation (Phase 4). Prototype retained feature-gated.
8. **Phase 7 — MPU privilege banking + vendor-pk-hash OTP lock + ITAMP9 → wipe + fuzz corpus.** Closes §9.5, §9.8, §9.9 and the listed empirical-test gaps.

Production-ship is gated on Phases 0–5 (Phase 6 descoped 2026-07-07; its acceptance leans on Phase 4's rotation ceremony). Phase 7 is a hardening pass that does not block first shipment but is required before public bug-bounty announcement.

---

## 13. Glossary and Cross-References

- **BHK** — Boot Hardware Key. 32 B of TRNG loaded into TAMP backup registers at boot, SAES-only after lock. STM32U585 hardware feature. "HDP-protected flash" storage is Trezor's pattern and a *deferred* PQSigner layer, not current: the ship profile sets `HDP1EN = HDP2EN = 0` and nothing in `secure/src` engages HDP, so the `bhk`-feature BHK sits in ordinary bank-1 flash page 126, DHUK-wrapped (tracked as the deferred HDP1 item, `EthereumPhone/PQ1` issue #39).
- **CMSE** — Cortex-M Security Extensions. ARMv8-M's secure-gateway / `cmse-nonsecure-entry` veneer mechanism.
- **DHUK** — Device Hardware Unique Key. Factory-fused 256-bit per-chip key in ST silicon. SAES-only access; at RDP0 is an ST-substituted constant shared across bench boards; per-die uniqueness only kicks in at RDP ≥ 1.
- **GTZC** — Global TrustZone Controller. Per-peripheral S/NS attribution on STM32U5.
- **HSM** — Hardware Security Module. Off-device vendor signing key custody.
- **LUC** — Lifetime Usage Counter. OPTIGA Trust M E120 silicon-monotonic counter, bound to F1D0 AuthRef's Execute access.
- **NSC** — Non-Secure Callable. The narrow gateway region between TrustZone-S and TrustZone-NS code.
- **PBS** — Platform Binding Secret for OPTIGA Shielded Connection. Current
  dev/legacy code derives a reproducible base value via SAES-CMAC(DHUK); the
  target product ships a factory transport PBS and performs a TRNG-salted final
  rotation after first-field RDP2. That flow and the E140 ordering remain OPEN.
- **RDP** — Readout Protection. STM32 levels 0/1/2 — 2 is irreversible and disables debug.
- **SAES** — Secure AES. STM32U585 AES peripheral with hardware-key selectors (`Software`, `DHUK`, `BHK`, `DHUK^BHK`); keys never appear as bus-visible bytes.
- **SAU** — Security Attribution Unit. ARMv8-M memory-attribution to S/NS/NSC at region granularity.
- **SCP03** — GlobalPlatform Secure Channel Protocol 03. AES-CMAC + AES-CBC channel used by SE050.
- **TAMP** — Tamper / Backup-domain Anti-tamper. STM32 peripheral with ITAMP1-13 internal sources + external pins; production must wire to `trigger_lockout_wipe()`.
- **TZSC** — TrustZone Security Controller. The GTZC sub-block governing per-peripheral attribution.

Cross-references:
- `CLAUDE.md` — non-negotiable invariants, lifecycle, wire formats, key derivation.
- `docs/security/HARDENING.md` — hardening requirements as a checklist.
- `docs/security/production-security.md` — research-round synthesis with citations.
- `docs/architecture/trezor-comparison.md` — pattern audit against Trezor firmware.
- `docs/secure-elements/optiga-brick-postmortem.md` — concrete worked example of a class-of-failure we redesigned around.
- `docs/firmware/firmware-update.md` — FW-update threat model deep-dive.
- `docs/secure-elements/se050-userid-pin-auth.md`, `docs/secure-elements/optiga-bringup-status.md` — SE-specific design notes.
- `EthereumPhone/PQ1` issues (label `source:work-todo`) — actionable tasks tracking the roadmap in §12.

---

## 14. One-line Summary

**No shipping claim is currently made: firmware rollback, OPTIGA shipping-state closure, and the named production gates remain open. Once those are closed, the intended composition requires an adversary to defeat both silicon PIN gates plus the immutable firmware-integrity chain before the three PIN-attempt mechanisms or the 120-second inactivity timeout erase the usable secret state, without triggering a visible measured-boot mismatch on the trusted NV3007 LCD.**

If any one of those three barriers holds, funds stay.

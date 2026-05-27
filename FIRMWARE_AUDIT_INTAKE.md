# Firmware Security Review — Pre-Meeting Intake

> Scope: **device firmware only.** The on-chain contracts (`contracts/`) are a
> **separate engagement** (see `contracts/smart-wallet/TOB_INTAKE.md`) and are
> **out of scope here.** This doc is the device-side counterpart.

## 1. What the software is

Firmware for **PQ1**, a $149 post-quantum self-custody hardware wallet. Target is **STM32U585 (Cortex-M33, ARM TrustZone-M) + OPTIGA Trust M V3 + NXP SE050**, written in **Rust `#![no_std]`, no heap, stack-only**. It is the device that produces the signatures the (separately-audited) ERC-4337 v0.6 smart account verifies on-chain.

The one and only signature primitive is **SPHINCS+C10** (hash-based, SLH-DSA-style; `h=18, d=2, a=11, k=13, w=8, l=43, target_sum=205` → 4008-byte sig). No classical signer (secp256k1/P-256/Ed25519) exists anywhere in the firmware, FSBL, or update path. SHA-256 is the only hash inside the PQ stack; Keccak-256 appears only for EVM-mandated hashes.

Runtime flow: BIP-39 entropy is **XOR-split across the two secure elements** (neither chip alone holds a seed bit); PIN is compared **in SE silicon, never in MCU code**, with a three-way lockstep counter (MCU flash page 124 + OPTIGA E120 LUC + SE050 UserID); on unlock the seed is reconstructed in TrustZone-secure SRAM only, used to derive per-`(account, chain, slot)` C10 keys, and zeroized on lock/tamper/timeout. A companion app (USB-HID) builds the UserOp and supplies non-secret routing metadata; **the device trusts the companion for nothing secret** and decodes/clear-signs every artifact on its own trusted OLED before the user confirms.

Pre-production: no devices shipped, no funds on-chain. Boots on real **B-U585I-IOT02A** and **QEMU mps2-an505**.

## 2. Scope boundary

**In scope (this engagement):** everything in the repo that runs on the device or feeds its supply chain — secure world, NSC gateway, SE drivers, HW drivers, the SPHINCS+C10 core, all pure-logic crates, the nonsecure/USB world, FSBL + FW-update, the ZK clear-sign verifier, and the host-side trust-DB / release-signing tools. Full-stack: **both software correctness and hardware/physical** (SCA, fault injection, TrustZone/GTZC, SE provisioning, OTP/DHUK).

**Out of scope:**
- **On-chain contracts** (`contracts/`) — separate engagement.
- **Companion app** — not in this repo; it is a *relied-upon but untrusted* peer (device trusts it only for non-secret metadata + displayed fields). Its compromise is *in* the threat model; its code is not under review here.
- **Well-vetted third-party crates** (RustCrypto et al., see §4) — relied upon, not re-audited; we want findings on *our use* of them, not their internals.

## 3. SLOC (in scope, full-stack)

Code SLOC = non-blank, non-comment-only lines. **Rust unit tests are inline (`#[cfg(test)]`) and counted here** (~7,200 test fns workspace-wide), and large data tables (BIP-39 wordlist, C10 KATs, BLS test vectors) inflate the figure — true production logic is materially smaller. A precise tests-excluded count (tokei) is available on request.

### On-device (runs on the STM32U585)

| Area | Path | Code SLOC |
|---|---|---:|
| Secure world (TrustZone-S) — total | `secure/src` | 53,311 |
| · NSC gateway (NS→S boundary) | `secure/src/nsc` | 5,929 |
| · tx decode + trusted display + EIP-712 | `secure/src/tx` | 8,867 |
| · SE drivers (OPTIGA + SE050) | `secure/src/{optiga,se050}` | 6,132 |
| · HW drivers (SAES/HASH/flash/OTP/TAMP/RNG/PKA/USB) | `secure/src/hw` | 4,622 |
| · ZK clear-sign verifier (Groth16/Poseidon) | `secure/src/zk` | 2,728 |
| · remainder (main, sau/GTZC, crypto, state, offchain, fw_update, dual_se, ui, …) | `secure/src/*` | ~25,033 |
| SPHINCS+C10 crypto core (written from scratch) | `sphincs-c10` | 1,168 |
| Pure-logic crates ¹ | proto, tx-core, aa, domain, tx, erc7730, bip39 ², hal, shared, fi | 8,428 |
| Nonsecure world — USB-HID / APDU v2 router | `nonsecure` | 3,551 |
| Immutable bootloader + FW-update manifest | `fsbl` + `fw-manifest` | 810 |
| BLS12-381 pairing (ZK path only; mostly-vendored fork) | `bls12_381_pka` | 11,949 |
| **On-device subtotal** | | **~79,200** |

¹ all `no_std`, no-heap, host-testable; the secure world re-exports them through thin shims.
² 2,048 of bip39's 2,466 lines are the BIP-39 English wordlist (data, not logic).

### Host-side supply-chain tooling

| Tool | Path | Code SLOC |
|---|---|---:|
| Release signer (vendor C10 key handling) | `fwsign` | 1,621 |
| Trust-DB / Merkle-root builder (ERC-20, ERC-7730, selectors) | `dbgen` | 4,924 |
| Groth16 host harness | `zk-test` | 768 |
| **Host subtotal** | | **7,313** |

**Total in scope ≈ 86,500 code SLOC** (inline tests + data tables included).

## 4. Third-party deps / forks

- **RustCrypto, vetted, relied-upon (not re-audited):** `sha2`, `sha3`, `aes`, `aes-gcm`, `cmac`, `hmac`, `subtle` (constant-time compares), `zeroize` / `zerocopy`. All `default-features = false`, `no_std`.
- **`bls12_381_pka`** — in-repo **fork of zkcrypto/bls12_381** adding a `pka` feature for STM32U585 PKA hardware acceleration. Vendored (path dep, ~12k SLOC, mostly upstream pairing math); the firmware-relevant delta is the PKA backend + the Groth16 usage. Linked only when the ZK clear-sign path is enabled.
- **`tropic01`** — the **only git-pinned external dependency** (`tropicsquare/libtropic-rs`, `rev = 0cacb5e…`), feature-gated (`tropic01-se`) and **not used in the shipping dual-SE config**. A `compile_error!` fence enforces the 40-char-hex pin.
- **Written from scratch (no upstream exists for this parameter set):** `sphincs-c10` (C10 SLH-DSA-style signer), `bip39` (`no_std` wordlist + derivation), plus the `proto / tx-core / aa / domain / tx / erc7730 / hal / fi` logic crates.
- **Ported / derived (provenance flag):** `secure/src/hw/tamp.rs` is a **port of Trezor** `core/embed/sec/tamper/stm32u5/tamper.c` (currently log-only — see §6); other hardening patterns (brownout, FI random-delay) are Trezor-informed. Per-slot key derivation parallels the Coinbase-Smart-Wallet port shared with the contracts. **Trezor-derived code may carry copyleft implications** — flag before open-sourcing.
- `proto/` is the single source of truth for every cross-boundary constant; the Solidity equivalents are **generated** from it (`xtask gen-solidity-constants`), so it is shared ground with the contracts engagement.

## 5. Open source?

Not yet public. We will grant the review team a private mirror before the engagement. License intent is **TBD** (no root `LICENSE` yet) — note the Trezor-derived TAMP port in §4 may constrain the choice; to be confirmed before publication.

## 6. Known pre-production caveats (tracked gates — *not* findings)

The bench branch knowingly ships some regressions/incomplete items. Please **flag these in the report as confirmed** rather than re-discovering them as findings; each is a tracked production gate. Full detail in `docs/threat-model.md §9` and `docs/production-security.md`.

1. **TAMP IRQ is log-only** (`hw/tamp.rs`) — must flip to `trigger_lockout_wipe()` before ship. (TAMP lives in GTZC2, the one remaining GTZC follow-up.)
2. **Factory provisioning not yet automated** — un-rotated bench boards use **NXP SE050 factory-default SCP03 keys (published in AN12436)** + a development OPTIGA PBS. Per-device rotation ceremony is a hard production gate.
3. **ML-KEM-1024 inner wrap on SE tunnels is planned, not present** — today the XOR halves cross I2C under classical channels (OPTIGA Shielded Connection CCM-8 / SE050 SCP03) only; a harvest-now/decrypt-later CRQC adversary is the residual.
4. **Boot-time SE attestation (chip-swap defence) not yet landed** — provisioning-time binding only.
5. **Vendor-pubkey OTP hash lock not yet burned** — a reflashed FSBL could currently substitute a different vendor key.
6. **MPU privilege-banking absent** — the secure world is a single privilege tier; any S-world code can reach `secret_keys::derive_into`.
7. **Debug instrumentation may be present on this branch** — `debug-log`, `secure_log!`, NS register dumps, semihosting prints. CI must gate production on `debug-log` / `e2e-test` / `mock-se` / `otp-hardcoded-master-key` / `ui-capture` **OFF** (`compile_error!` fences in `nsc/mod.rs` + the saes-self-test runner enforce most).
8. **Domain-separation tags are sticky-but-renamable pre-launch** — `"sphincs-c6-v1"` is historical (was a different parameter set; now C10). Frozen forever post-first-shipment for cross-chain address stability — **do not propose renaming.**
9. **NOTE — already fixed, ignore the stale doc text:** the TZSC/GTZC "regressed to all-NS" item in `docs/threat-model.md §9.3` is **out of date.** `secure/src/sau.rs` now wires a SECURE-allowlist (AES/HASH/RNG/PKA/SAES/I2C1/I2C2 secure; USB OTG FS stays NS) and `make gtzc-enforcement-hw` **passed on real silicon 2026-05-20** (commit `f3c7d20`). Please review the *current* `sau.rs`, not the §9.3 prose.

## 7. Greatest concerns / scenarios we're trying to avoid

Ordered roughly by blast radius.

1. **SPHINCS+C10 signer/verifier correctness.** `sphincs-c10/` (1,168 SLOC, from scratch, no upstream reference for C10) is the *only* signature primitive in the device. Any bug in WOTS+/FORS/hypertree/address-hashing is a silent forgery or key-recovery oracle. Differential-test against the on-chain Yul verifier; confirm no secret-dependent branches.
2. **Verify-before-release / fault-injection sig grafting.** Every Type 1/2 signature is double-computed on disjoint SRAM regions, constant-time compared, then verify-after-sign'd (`crypto::c10_sign_verified*`, `secure/src/fi.rs`). RFC 9814 §5 / Genêt TCHES 2023: verify-after-sign *alone* is insufficient — a single grafted fault yields a forgeable subtree. **Audit this for symmetry across *every* gateway handler**, not just the happy path.
3. **Deterministic-signing side-channel (OptRand).** Every signature must draw fresh TRNG randomness; OptRand = 0 enables horizontal-DPA `PRF(SK.seed)` recovery (Saarinen SLotH 2024). Confirm no signing path is deterministic; confirm OptRand sourcing is hardware-TRNG, never software PRNG.
4. **NSC gateway boundary (NS → S).** `secure/src/nsc/` is the entire untrusted-→-secure attack surface: `NsPtr<T>` range validation, copy-NS-buffer-to-S-stack-before-parse (TOCTOU), length confusion on bounded buffers. Any path that lets the nonsecure world read S-SRAM or skip a bound = full seed exfiltration. The two sign handlers (`cmd_sign_userop.rs`, `cmd_sign_userop_batch.rs`) are the hottest.
5. **Dual-SE XOR split + three-way PIN lockstep** (invariants #1/#2). No code path may store full entropy on one chip, transmit a half across, or compare the PIN in MCU software. The MCU/OPTIGA/SE050 counters must stay in lockstep so 10 wrong attempts deterministically wipes both SEs + page 124 — look for desync or a glitch that defeats the pre-commit (`nsc::gated_unlock`).
6. **Trusted-display clear-signing integrity.** The human-readable intent shown on the OLED and the hash actually signed must derive from the **same S-stack copy** — the companion never gets to substitute a digest. Covers the ERC-20 / Safe `SafeTx` / CowSwap `GPv2Order` / ERC-7730 decoders and the Groth16 ZK binding (`secure/src/{tx,zk}/`). A decode-vs-sign mismatch = user confirms X, signs Y.
7. **SE tunnels + factory provisioning.** No plaintext secret may touch I2C; channel keys come from a Tier-1 SAES-CMAC(DHUK) KDF (`hw/secret_keys.rs`). Note the published SE050 default SCP03 keys (§6.2) — confirm the rotation gate and that the shielded-connection/SCP03 state machines fail closed on MAC/desync.
8. **Firmware-update / boot integrity.** FSBL verifies a C10 sig over an **intentionally minimal 75-byte preimage** (`"PQFW_V1" ‖ version_be ‖ secure_hash ‖ nonsecure_hash`); A/B-slot selection + an OPTIGA monotonic counter block downgrade; COMMIT verify is FI-guarded. Audit `fsbl/`, `secure/src/fw_update/`, and host `fwsign/` for any preimage expansion, downgrade bypass, or a chunk written before its hash is checked. The install confirm is now a real trusted-display dialog at `CMD_FW_BEGIN`, *before* any destructive flash op (`fw_update::confirm_install`, `nsc/cmd_fw_begin.rs`); this path was hardened in May 2026 — timing-normalized `verify_manifest`, flash-backed verify-failure wipe, bounded image lengths, an anti-rollback HW test (`make fw-rollback-hw`) — see `docs/usb-fw-update-hardening.md`. Please confirm completeness rather than assuming it raw.
9. **Untrusted-input parsers (memory safety, `no_std`).** USB APDU reassembly (`nonsecure/src/usb/`), EIP-712 typed-data, the ERC-7730 binary-IR walker, the ABI typed-call parser, RLP/calldata decode. All bounded-buffer/no-heap; the worry is OOB / length-confusion / integer-truncation on attacker-shaped input. A cargo-fuzz scaffold now covers the FW-update manifest verify chain (`fw-manifest/fuzz/`, `make fuzz-manifest`); **harnesses against `parse_cmd_sign_userop_input` and the USB APDU reassembler remain a gap** — fuzzing-corpus generation is welcome.
10. **Off-chain counter + cap monotonicity** (invariants #7/#9). The flash-backed (page 123) per-slot `local_offchain_count` / `last_userop_count` store must be monotonic and unresettable: `MAX_OFFCHAIN_GAP = 100`, combined cap < 65,536, post-restore an unregistered slot must be refused. Audit the log-structured store + compaction (`offchain_state.rs`, `hw/flash.rs`) for a rollback/replay that mints free signatures, and the page-124 attempt counter for the same.

*Also please confirm hasn't regressed:* the GTZC SECURE-allowlist + readback self-check in `sau.rs` (§6.9), and the build-time production fences (§6.7).

## 8. How to build & exercise it (auditor quick-start)

Both worlds target `thumbv8m.main-none-eabi`. Pure-logic crates run on the host.

```bash
# QEMU (mps2-an505, mock SE) — no hardware needed
make run                 # non-interactive smoke
make e2e                 # automated unified-sign end-to-end
make play                # interactive arrow-key UI

# Real B-U585I-IOT02A via probe-rs
make test-key-speed      # DWT-timed signing bench, prints === PASS ===
make saes-self-test-hw   # SAES SW + DHUK round-trip
make gtzc-enforcement-hw # NS-access RAZ-fault check (invariant #4)
make pin-gate-hw-counter-e2e   # full three-way PIN lockstep
make pin-gate-wipe-e2e         # 10 wrong PINs → factory reset
make fw-rollback-hw            # FW anti-rollback on real silicon (reversible)

# Host-side logic + tooling
cargo test -p sphincs-tz-secure --tests --release
cargo test -p sphincs-c10 -p pqsigner-domain -p pqsigner-aa -p pqsigner-tx

# Fuzzing (nightly + cargo-fuzz)
make fuzz-manifest       # cargo-fuzz the FW-update manifest verify chain
```

**HW gotcha:** `probe-rs` doesn't implement semihosting `SYS_READC`, so any PIN-prompt path hangs on real silicon (`make e2e-hw`); use `make test-key-speed` or `make play-hw-display`. Feature-flag profiles: `mode-production` / `mode-bringup` / `mode-e2e` (`secure/Cargo.toml`, ~50 flags; `docs/feature-flags.md`).

## 9. Reference docs (full model — not duplicated here)

- `docs/threat-model.md` — assets (S0–S7), adversary tiers (T0–T7), trust boundaries, 16 attack surfaces.
- `docs/production-security.md` — top critical findings + factory/RDP flow.
- `docs/security-review-2026-05.md` — last internal review (open items H-/M-/L-).
- `docs/usb-fw-update-hardening.md` — over-USB FW-update audit + threat model + fuzz scaffold (2026-05).
- `docs/HARDENING.md`, `docs/brownout-hardening.md`, `docs/reproducible-builds.md`, `docs/firmware-update.md`.
- `README.md` / `CLAUDE.md` — architecture, invariants, file map.

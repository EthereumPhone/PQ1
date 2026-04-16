# JARDÍN-only cutover — phase-by-phase implementation notes

These files drive the refactor that collapses this hardware wallet down to a
single signing path: **pure-PQ JARDÍN FORS+C**, mirroring the architecture in
`/home/markus/Documents/SPHINCs-/` but without the ECDSA hybrid half.

- Master plan: `/home/markus/.claude/plans/happy-knitting-globe.md`
- Reference repo (signer + verifier): `/home/markus/Documents/SPHINCs-/`
- This repo (target): `/home/markus/Documents/sphincs_rust/`

Each phase file is **self-contained**: it lists the prerequisites, the exact
files to touch, the reference snippets to copy from, the frozen invariants, and
the verification steps. A fresh agent with no prior context should be able to
open one phase file and execute it end-to-end.

## Phase order

1. [Phase 1 — Flash persistence module](phase-01-flash-persistence.md) ✅ done
2. [Phase 2 — C11 key derivation](phase-02-c11-key-derivation.md)
3. [Phase 3 — Unified `cmd_sign_userop` state machine](phase-03-unified-sign-userop.md)
4. [Phase 4 — USB handler cleanup + webhid rewrite](phase-04-usb-and-webhid.md)
5. [Phase 5 — Solidity contract gut + C11 verifier port](phase-05-solidity-contracts.md)
6. [Phase 6 — Deletion pass](phase-06-deletion-pass.md)
7. [Phase 7 — Docs refresh](phase-07-docs.md)

## Global invariants (apply to every phase)

These must **never** change during this refactor — violating any of them
breaks the recovery contract (same 24 words must produce the same on-chain
wallet address across devices and across time):

- BIP-39 seed is split across OPTIGA Trust M (half_O) and SE050 (half_E) via
  XOR entropy split. Neither chip alone reveals any bit of the seed.
- PIN gating is hardware-enforced (OPTIGA auth-ref OID 0xF1D0, SE050 UserID
  0x7B06_0000). Firmware never compares PINs in software.
- TrustZone secure world owns all key material. Non-secure world only sees
  opaque commands (unlock, sign, status).
- C11 key derivation domain: `HMAC-SHA512("sphincs-c6-v1", bip39_seed)` →
  master → `keccak256("pk_seed" || master) & N_MASK` (pkSeed),
  `keccak256("sk_seed" || master)` (skSeed). The `"sphincs-c6-v1"` tag is a
  historical quirk from the SPHINCs- repo — keep it verbatim.
- JARDÍN slot entropy: `keccak256(master_entropy || "jardin_slot" || slot_index)`.
  Master entropy derivation tag: `"pqwallet-jardin-master"` (already in
  `secure/src/crypto.rs`, don't touch).
- JARDÍN constants (frozen by the on-chain verifier): N=16, K=26, A=5,
  Q_MAX=95, FORSC_BODY=2452, ADRS types {3=FORS_TREE, 4=FORS_ROOTS,
  6=UNBALANCED}. All live in `jardin-fosc/src/params.rs`.
- Signature wire formats (must match on-chain verifiers byte-for-byte):
  - **Type 1**: `[0x01 | r(32) | subPkSeed(16) | subPkRoot(16) | C11_sig(3976)]`
  - **Type 2**: `[0x02 | H(r)(32) | subPkSeed(16) | subPkRoot(16) | FORS+C_sig(2452+q·16)]`
  - No ECDSA signature prefix (unlike SPHINCs-).

## What NOT to do (applies to every phase)

- **Do not add a classical (secp256k1, P-256, Ed25519) transaction signer.**
  User explicitly rejected the hybrid ECDSA+PQ design. Pure PQ only.
- **Do not store secrets in non-secure world.** No PIN buffers, no entropy,
  no keys. Not even "temporarily".
- **Do not compare PINs in firmware.** The SE hardware does the comparison.
- **Do not transmit plaintext secrets over I2C/SPI.** Everything goes through
  the encrypted session (Shielded Connection or SCP03).
- **Do not change the key derivation domain tags.** These are part of the
  recovery contract.
- **Do not add heap allocation.** `#![no_std]`, no alloc, stack-only.
- **Do not add `debug-log` or `e2e-test` features to production builds.**

## Verification harness

Most phases include a "verification" section describing how to test. The
standard harness:

```bash
# QEMU end-to-end (mock SE)
make e2e

# Real hardware (STM32U585 + SE050 + OLED)
make flash-hw-se050-oled-standalone

# Foundry contract tests
cd contracts/smart-wallet && forge test -vv

# Firmware build check
cargo build --release --target thumbv8m.main-none-eabi \
  --target-dir target/secure -p sphincs-tz-secure \
  --no-default-features --features mock-se,debug-log,ui-semihosting
```

# Phase 7 — Docs refresh + CLAUDE.md invariants rewrite

**Status:** not started.
**Depends on:** phases 1–6 (can only write accurate docs once the code has
stabilized).
**Blocks:** nothing, but leaving stale docs around makes it impossible for
anyone (LLM or human) to orient in the repo — and there's a lot of
signer-architecture-specific prose in the existing docs that will lie.

## Why this phase exists

The current docs describe a multi-signer architecture (SLH-DSA main +
ML-DSA-44 bootstrap + ZK clear-signing + JARDÍN). After the cutover, the
architecture is single-signer JARDÍN with Type 1/Type 2 dispatch. The docs
must match.

Also: `CLAUDE.md` is loaded into every LLM session context. If it describes
a signer that no longer exists, every future LLM session will produce wrong
answers.

## Files to rewrite

| File | Scope of change |
|---|---|
| `CLAUDE.md` | Rewrite invariants section. New invariants: single JARDÍN signing path, flash-backed next_q, automatic rotation, pure PQ (no ECDSA). Delete references to SLH-DSA, ML-DSA-44, ZK clear-signing. Update architecture diagram. Update file map. |
| `README.md` | Update "Status", "Architecture at a Glance", "Quantum Threat Analysis" sections. Drop SLH-DSA / ZK / bootstrap mentions. |
| `docs/architecture.md` | Major rewrite (~1400 lines currently). JARDÍN-only flow, Type 1 / Type 2 dispatch, flash persistence. |
| `docs/usb-protocol-v2.md` | Strip deleted INS codes. Document new 0x30 unified payload + bundled response. Document 0x72 slot-info query. |
| `docs/companion-app-integration.md` | Rewrite signing flow: single device sign → possibly two on-chain UserOps (Type 1 + Type 2). Remove all ZK / bootstrap / SLH-DSA references. |
| `docs/pq-aa-wallet-design.md` | Rewrite around JARDÍN-only pure-PQ model. Cite the frozen constants and recovery contract. |
| `docs/work-todo.md` | Mark cutover items as complete. |
| `docs/jardin-fosc-firmware-completion.md` | **Likely obsolete** — the "completion" this doc tracks is exactly what phases 1–6 did. Either delete or repurpose as an implementation journal. |

## Files to delete

| File | Why |
|---|---|
| `docs/m4-cowswap-eip712.md` | CowSwap EIP-712 ZK clear-sign (no longer supported) |
| `docs/m4-cowswap-eip712-impl.md` | Same |
| Any other `docs/m4-*` | Post-M3 features that were planned but are now out of scope |
| `docs/research-bundles/*` if they cover ZK / SLH-DSA only | Audit each; keep if general-purpose research notes, delete if protocol-specific |
| `docs/se050-factory-reset.md` | **Audit**; keep if it covers generic factory reset, delete if it's specific to the old multi-signer layout |

## Files to keep unchanged

- `docs/HARDENING.md` — side-channel / fault-injection hardening is protocol-agnostic
- `docs/brownout-hardening.md` — same
- `docs/hardware_requirements.md` — BOM, unchanged
- `docs/dev-board-setup.md` — devkit setup, unchanged
- `docs/se050-userid-pin-auth.md` — SE050 integration, unchanged
- `docs/jardin-fosc-implementation-guide.md` — the JARDÍN reference, still valid
- `docs/oled-mirror.md` — UI plumbing, unchanged

## New CLAUDE.md structure (sketch)

```markdown
# PQSigner OS — LLM Context

Post-quantum ERC-4337 hardware wallet. Target: STM32U585 (Cortex-M33, TrustZone) +
Infineon OPTIGA Trust M V3 + NXP SE050. Seed phrase is the only long-term secret,
XOR-split across the two secure elements. Signing is **JARDÍN FORS+C only** —
pure post-quantum, no ECDSA, no classical fallback.

## Status
Single-signer JARDÍN cutover complete. Firmware boots on QEMU mps2-an505 and real
B-U585I-IOT02A. Both SEs (OPTIGA Trust M, SE050) drivers working. Dual-SE XOR
entropy split wired and tested.

## Non-Negotiable Invariants

1. **Dual-chip seed split.** BIP-39 entropy is XOR-split: half_O on OPTIGA Trust M,
   half_E on SE050. No code path may store the full entropy on a single chip.

2. **Hardware-level PIN gating.** PIN decision is made by secure element silicon,
   never by MCU firmware. OPTIGA: auth reference OID 0xF1D0. SE050: UserID
   0x7B06_0000.

3. **E2E encrypted tunnel to each SE.** OPTIGA Shielded Connection (AES-128-CCM-8).
   SE050 SCP03 (AES-CMAC + AES-CBC). No plaintext secret touches I2C.

4. **All secrets live ONLY in TrustZone secure world.** NS never sees a PIN digit,
   entropy byte, signing key, or derived secret. NSC gateway exposes opaque
   commands only.

5. **Post-quantum only for transaction signing.** JARDÍN FORS+C. No classical
   fallback, not even hybrid. C11 SPHINCS+ is used only for slot registration
   (Type 1), which is also purely hash-based post-quantum.

6. **next_q persistence before release.** Every FORS+C signature increments
   next_q in secure flash before the signature bytes leave the secure world.
   Rollback after sign would enable q reuse (security degrades 128→105 bits).

## Architecture at a Glance

```
  Seed on dual-SE (OPTIGA + SE050, XOR split, PIN-gated)
                         │
                         ▼ (unlock in S-world via trusted UI PIN entry)
       BIP-39 entropy reconstructed in S-SRAM
                         │
          ┌──────────────┴──────────────┐
          ▼                             ▼
   C11 master keypair          JARDÍN master entropy
   (HMAC-SHA512 derived        ↓ slot_entropy(slot_index)
    from BIP-39 seed)          ↓ JardinSlot::keygen (~20s first time)
                               ↓ slot state persisted to flash
                               ↓ JardinSlot::sign (q = next_q, 2452+q·16 B)
                         │
                         ▼
   CMD_SIGN_USEROP (the one sign command)
   returns: [type1_len | type1_bytes | type2_len | type2_bytes]
     first-sign / rotation: type1 is a C11 Type 1 payload for slot registration
     normal:                type1_len = 0; type2 is a FORS+C signature under
                            the current slot's sub-key
```

## Key files

| Path | Purpose |
|---|---|
| `secure/src/main.rs` | Boot, SAU/GTZC config, PIN entry, NSC gateway dispatch |
| `secure/src/crypto.rs` | BIP-39 reconstruction, JARDÍN master entropy, C11 keypair derivation |
| `secure/src/nsc/mod.rs` | NSC gateway (6 commands: status, unlock, lock, sign, slot-info) |
| `secure/src/nsc/cmd_sign_userop.rs` | Unified JARDÍN Type 1 / Type 2 state machine |
| `secure/src/nsc/jardin_flash.rs` | Slot-state persistence in secure flash (pages 123-124) |
| `secure/src/optiga/*` | OPTIGA Trust M driver + Shielded Connection |
| `secure/src/se050/*` | SE050 driver + SCP03 |
| `jardin-fosc/src/*` | FORS+C signing (Type 2) |
| `sphincs-c7/src/*` | SPHINCS+C11 signing (Type 1, matches SPHINCs- verifier) |
| `contracts/smart-wallet/src/PQJardinWallet.sol` | On-chain ERC-4337 account |
| `contracts/smart-wallet/src/verifiers/JardinForsCVerifier.sol` | Type 2 stateless FORS+C verifier |
| `contracts/smart-wallet/src/verifiers/SPHINCsC11Asm.sol` | Type 1 stateless C11 verifier |
| `tools/webhid_test.html` | Browser companion: sign via WebHID → submit to bundler |

## Frozen recovery contract (do not change)

- BIP-39 → seed: PBKDF2-HMAC-SHA512, 2048 iters, empty passphrase (standard)
- Seed → C11 master: `HMAC-SHA512("sphincs-c6-v1", bip39_seed)` → then
  `pkSeed = keccak256("pk_seed" || master[0..32]) & N_MASK`,
  `skSeed = keccak256("sk_seed" || master[0..32])`
- Seed → JARDÍN master entropy: `keccak256("pqwallet-jardin-master" || bip39_seed || ...)`
- Master → slot entropy: `keccak256(master || "jardin_slot" || slot_index)`
- Master → r for slot N: `keccak256(master || "jardin_r" || slot_index)` (check exact
  tag in `jardin-fosc/src/hash.rs`)
- CREATE2 wallet salt: `keccak256(masterPkSeed || masterPkRoot)` — same address
  on every chain

## What NOT to do

- Do not add a classical (secp256k1, P-256, Ed25519) signer path.
- Do not store secrets in NS world.
- Do not compare PINs in firmware.
- Do not transmit plaintext secrets over I2C/SPI.
- Do not store full entropy on a single chip.
- Do not add heap allocation. `#![no_std]`, stack-only.
- Do not use software PRNG; all randomness from hardware TRNG.
- Do not change KDF domain tags — changes the recovery contract.
- Do not skip the verify-before-release check on Type 1 or Type 2 sigs.
- Do not release Type 2 bytes to NS before flash-writing the incremented next_q.
```

## Doc drift checklist

After rewriting, grep the doc tree for stale references:

```bash
grep -rn "SLH-DSA\|slh_dsa\|ML-DSA\|ML_DSA\|bootstrap signer\|Groth16\|BLS12-381\|zk clear" docs/ CLAUDE.md README.md
```

Each hit is either a false positive (historical reference clearly marked) or
something to update / delete.

## What NOT to do

- **Don't** delete `docs/jardin-fosc-implementation-guide.md`. It's the
  authoritative reference for the JARDÍN scheme and still accurate.
- **Don't** let docs drift from the code. If you rewrite a doc and then
  change the code, bump the doc in the same commit.
- **Don't** write fluffy "why post-quantum matters" marketing prose —
  `CLAUDE.md` is an LLM context file and needs to be dense, invariant-first,
  scan-friendly.
- **Don't** leave placeholder TODOs in `CLAUDE.md`. If something isn't
  decided, omit it. TODOs in CLAUDE.md are worse than silence because LLMs
  sometimes treat them as confirmed facts.

## Verification

1. `grep -rn` checklist comes up clean for the stale-reference list above.
2. Read `CLAUDE.md` front-to-back cold — does it orient you in a fresh session?
3. A newcomer opening `docs/architecture.md` understands the system in one
   pass without needing to read the code.
4. `README.md` status section accurately reflects what works and what doesn't.

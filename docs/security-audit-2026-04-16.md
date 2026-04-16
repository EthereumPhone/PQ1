# Security Audit — PQSigner OS

**Audit window:** commits `634183c..f931c98` (post-JARDÍN cutover, OPTIGA Trust M bring-up, factory-reset target)
**Date:** 2026-04-16
**Scope:** Full security review of the JARDÍN-only architecture rewrite, with emphasis on the seven non-negotiable invariants from `CLAUDE.md`. Reviewer assumed the role of an attacker with all of: physical access to the device, NS-world code-execution, ability to MITM the I2C bus, ability to record and replay APDU sessions, and ability to dump secure flash.
**Methodology:** Seven parallel deep-dive sub-audits across the security-critical subsystems, followed by manual cross-verification against actual source for every CRITICAL/HIGH finding.

---

## Executive summary

**Verdict: DO NOT SHIP** in the current state.

The cryptography is sound. SPHINCS+C11 master signing, FORS+C JARDÍN sub-key signing, BIP-39 → C11 master key derivation, the on-chain Yul verifiers, and the wire formats are all internally consistent and match each other byte-for-byte. The seven recovery-contract domain tags are honored. The fault-injection guard around C11 signing is present.

However, the perimeter around that cryptography has serious problems. There are **9 CRITICAL** findings (any one of which enables fund loss, key extraction, or a recovery-contract-breaking divergence), **18 HIGH** findings (each violating at least one invariant from `CLAUDE.md` or breaking the trusted-display contract), and **20 MEDIUM** findings (defense-in-depth gaps and robustness issues that should be fixed before any production deployment).

The bugs cluster in three areas:

1. **Trusted-UI display lies about what's signed.** The user sees `nonce=0`, `gas=0`, `max fee = 0 gwei`, and the paymaster is invisible — but the signed `userOpHash` binds the real values from the wire payload. A hostile non-secure (NS) world signs gas-bombs and paymaster-drains while the trusted UI shows a clean transaction.
2. **The OPTIGA Trust M driver trusts the firmware where it should trust the chip silicon.** The PIN attempt counter is firmware-managed (not chip-enforced), the PIN KDF is a single SHA-256 (offline-brute-forceable), the Platform Binding Secret is in plaintext flash, and the PIN-auth challenge is sent in plaintext so a bus-snooper can pre-compute HMAC tables.
3. **The Cortex-M33 / TrustZone perimeter has a hole.** With the `usb` feature enabled (every shipping configuration), `TZSC_SECCFGR{1,2,3} = 0` makes every TZSC-controlled peripheral non-secure — including the TRNG, AES, PKA, HASH accelerators, and the I2C buses to both secure elements. This single line of code defeats CLAUDE.md invariant #4.

A fourth, more architectural issue is the multi-chain `next_q` overwrite (CRIT-1): the slot-state flash store keeps only one `SlotState` record at a time, so signing on chain B after chain A overwrites chain A's `next_q`. Returning to chain A triggers `Mode::FirstSign`, re-keygens the same deterministic sub-key with `next_q = 1`, and the device signs at `q=1` again. FORS+C security collapses sharply under q-reuse — the design promises 128-bit security at q=1, drops to ~105 bits at q=2 with random message choice, and degrades faster against an adversarial signer. Two distinct messages signed at the same `(slot, q)` reveals enough FORS leaves to forge subsequent signatures.

This document lists every finding by severity, with file:line citations, code excerpts, exploit narratives, and concrete fix recommendations. The closing section is a ship checklist ordered by priority.

---

## Table of contents

- [Methodology and what was audited](#methodology-and-what-was-audited)
- [The seven invariants from CLAUDE.md](#the-seven-invariants-from-claudemd)
- [CRITICAL findings](#critical-findings)
  - [CRIT-1 · Multi-chain `next_q` overwrite causes FORS+C key compromise](#crit-1--multi-chain-next_q-overwrite-causes-forsc-key-compromise)
  - [CRIT-2 · Trusted UI displays fake gas/nonce/fee values](#crit-2--trusted-ui-displays-fake-gasnoncefee-values)
  - [CRIT-3 · `paymaster_and_data_hash` is opaque NS input](#crit-3--paymaster_and_data_hash-is-opaque-ns-input)
  - [CRIT-4 · TZSC `SECCFGR1/2/3 = 0` exposes ALL peripherals to NS](#crit-4--tzsc-seccfgr123--0-exposes-all-peripherals-to-ns)
  - [CRIT-5 · `init_code_hash` hardcoded to `KECCAK_EMPTY`](#crit-5--init_code_hash-hardcoded-to-keccak_empty)
  - [CRIT-6 · OPTIGA PIN counter is firmware-managed, not chip-enforced](#crit-6--optiga-pin-counter-is-firmware-managed-not-chip-enforced)
  - [CRIT-7 · Single SHA-256 PIN KDF is brute-forceable](#crit-7--single-sha-256-pin-kdf-is-brute-forceable)
  - [CRIT-8 · OPTIGA `GetRandom` runs in plaintext](#crit-8--optiga-getrandom-runs-in-plaintext)
  - [CRIT-9 · Platform Binding Secret stored in plaintext flash](#crit-9--platform-binding-secret-stored-in-plaintext-flash)
- [HIGH findings](#high-findings)
- [MEDIUM findings](#medium-findings)
- [LOW findings](#low-findings)
- [Cryptographic correctness — what's CORRECT](#cryptographic-correctness--what-is-correct)
- [Recommended ship checklist](#recommended-ship-checklist)

---

## Methodology and what was audited

The audit covers commits `634183c43c..f931c98600` (~26K lines of diff) including:

- `e5e6cfb` — Phase 1: secure-flash JARDIN slot-state persistence
- `898ca12` — Phases 2–7: unified sign, C11 master keys, PQ-only contracts (the largest diff)
- `bc69448` — APDU chaining first-chunk fix
- `a6b307f` — Surface SECSR + addr on flash-write failure
- `a958328` — ICACHE invalidation after erase/program
- `5df8709` — Re-enable ERC-20 + ZK DB lookups
- `3784326` — OPTIGA Trust M real-silicon bring-up
- `f931c98` — `factory-reset` Make target

Files audited (read in full):
- `secure/src/nsc/cmd_sign_userop.rs` (~786 lines)
- `secure/src/nsc/jardin_flash.rs` (~711 lines)
- `secure/src/nsc/state.rs`, `ptr_validate.rs`, `mod.rs`, `cmd_request_unlock.rs`, `cmd_get_jardin_slot_info.rs`, `cmd_lock.rs`, `cmd_get_remaining.rs`, `cmd_is_unlocked.rs`
- `secure/src/crypto.rs`
- `secure/src/aa/userop.rs`, `aa/init_code.rs`
- `secure/src/sau.rs`, `secure/src/main.rs`, `secure/src/boot_ns.rs`, `secure/src/timeout.rs`
- `secure/src/optiga/mod.rs`, `apdu.rs`, `i2c.rs`, `ifx_i2c.rs`, `shield.rs`
- `secure/src/se050/*`
- `secure/src/dual_se.rs`
- `secure/src/hw/flash.rs`
- `secure/src/zk/mod.rs`, `secure/src/erc20/*`
- `secure/src/tx/display/*`, `secure/src/tx/eip1559.rs`
- `sphincs-c7/src/{lib,fors,wots,hypertree,merkle,address,hash,params}.rs`
- `jardin-fosc/src/{lib,hash,unbalanced}.rs`
- `bip39/src/lib.rs`
- `nonsecure/src/main.rs`, `usb/commands.rs`, `nsc_api.rs`
- `tools/webhid_test.html`
- `shared/src/lib.rs`
- `contracts/smart-wallet/src/PQJardinWallet.sol`, `PQJardinWalletFactory.sol`, `PQOwnable.sol`
- `contracts/smart-wallet/src/verifiers/SPHINCsC11Asm.sol`, `JardinForsCVerifier.sol`
- `contracts/smart-wallet/test/PQJardinWallet.t.sol`

The Solidity verifiers were cross-checked byte-for-byte against the Rust signers using `cast keccak`, `cast abi-encode`, and reading the actual EntryPoint v0.9 code from `lib/account-abstraction/`.

For every CRITICAL and HIGH finding I read the actual source to confirm — sub-audit findings were not taken on faith.

---

## The seven invariants from CLAUDE.md

For reference; these are the invariants any change to PQSigner OS must respect:

1. **Dual-chip seed split.** BIP-39 entropy is XOR-split: `half_O` on OPTIGA Trust M, `half_E` on SE050. Neither chip alone reveals any bit of the seed.
2. **Hardware-level PIN gating.** The PIN decision is made by the secure element silicon, never by MCU firmware.
3. **E2E encrypted tunnel between TrustZone secure world and each SE.** OPTIGA: Shielded Connection. SE050: SCP03. No plaintext secret over I2C.
4. **All secrets live ONLY in TrustZone secure world.** Non-secure world never sees a PIN digit, entropy byte, signing key, or derived secret.
5. **Post-quantum only for transaction signing.** JARDÍN FORS+C. No classical signer (secp256k1, P-256, Ed25519). Master identity is SPHINCS+C11. On-chain wallet contract has NO classical verifier path.
6. **`next_q` persistence before release.** Every FORS+C signature increments `next_q` in secure flash BEFORE the Type 2 bytes are released to NS.
7. **Master C11 keys are immutable.** The on-chain CREATE2 salt is `keccak256(masterPkSeed || masterPkRoot)`; rotating master keys would change the wallet address.

This audit found violations or near-violations of #2, #3, #4, and #6.

---

## CRITICAL findings

A CRITICAL finding is one that, exploited individually or in combination, enables fund theft, key extraction, complete PIN bypass, or a divergence between firmware and on-chain state that breaks recovery.

---

### CRIT-1 · Multi-chain `next_q` overwrite causes FORS+C key compromise

**Files:** `secure/src/nsc/cmd_sign_userop.rs:347-365`, `secure/src/nsc/jardin_flash.rs:512-555`
**Invariant violated:** #6 (next_q persistence)

The `jardin_flash` module persists exactly **one** `SlotStateRecord` at a time across the two flash pages (123 and 124). The `pick_newer` logic returns whichever has the higher `seq` number, and the writer alternates between pages. There is no provision for storing per-chain state.

The mode resolution in `cmd_sign_userop.rs:347-365`:

```rust
let existing = jardin_flash::read_latest();
let mode = match &existing {
    Some(s)
        if s.chain_id == chain_id
            && s.is_registered()
            && (s.next_q as usize) <= jardin_fosc::params::Q_MAX =>
    {
        Mode::Normal(s.clone())
    }
    Some(s)
        if s.chain_id == chain_id
            && s.is_registered()
            && (s.next_q as usize) > jardin_fosc::params::Q_MAX =>
    {
        Mode::Rotate { from: s.clone() }
    }
    _ => Mode::FirstSign,
};
```

When the persisted `chain_id` doesn't match the request, the fallthrough is `Mode::FirstSign`. `FirstSign` then triggers a full re-keygen with `slot.next_q = 1` (line 432-444).

The slot entropy is deterministic per (master, slot_index): `keccak256(master || "jardin_slot" || slot_index_be)`. Same master + same slot_index → same sub-key. So the "fresh" slot has the **identical** signing material as the previous chain-A session — but `next_q` has been reset to 1.

#### Reproduction

1. Unlock wallet. Chain A sign: 50 transactions. Flash now holds `{chain_id=A, slot_index=0, next_q=51, ...}`.
2. Chain B sign: 1 transaction. Flash now holds `{chain_id=B, slot_index=0, next_q=2, ...}` (chain-A record is overwritten by the writer's alternating-page logic, since A's record has lower `seq`).
3. Chain A sign again. `read_latest()` returns the chain-B record. Chain-A doesn't match → `Mode::FirstSign` → slot is re-keygen'd at slot_index=0 with `next_q = 1`. **Chain A signs at q=1 again.**

#### Why it's catastrophic

The chain-A on-chain wallet has the slot registered with `slots[keccak256(r)] = keccak256(subPkSeed||subPkRoot)`. The verifier checks the commitment and runs FORS+C verify — there is no on-chain `next_q` ratchet (intentional, per the design). So signatures at any `q ∈ [1..95]` against a registered slot are valid.

Two FORS+C signatures at the same `(slot, q)` against different messages reveal both messages' forced FORS leaf indices. With ~13 forced leaves per signature and 26 trees of 32 leaves each, two adversarially-chosen messages at q=1 reveal enough FORS secret leaves that subsequent signatures can be forged for arbitrary new messages whose forced indices fall within the revealed set. Standard FORS+C analysis: 128-bit security at q=1, ~105 bits at q=2 with random messages, drops faster against adversarial choice. With repeated q-reuse, the security parameter collapses.

#### Reachability

This is reachable for **every user who signs on more than one chain**. ERC-4337 wallets on multiple chains (Ethereum mainnet, Base, Arbitrum, Optimism, Polygon, …) with the same address — exactly the design promise of `salt = keccak256(masterPkSeed || masterPkRoot)` — will repeatedly trigger this bug.

#### Fix

Two options:

1. **Per-chain log-structured store.** Replace the single-record alternating-page design with an append-log of `(chain_id, slot_state)` records across the 16KB region. `read_latest` becomes `read_latest_for(chain_id)`. Add a compaction phase when the log fills.
2. **Bind chain_id into slot derivation.** Change `jardin_slot_entropy` and `jardin_slot_r` to include `chain_id`. This makes "slot 0 on chain A" and "slot 0 on chain B" cryptographically distinct sub-keys with disjoint q sequences. **However**, this is a recovery-contract change — domain tags are frozen per CLAUDE.md. Requires a coordinated companion + on-chain update.

Option 1 is preferable because it preserves the recovery contract.

---

### CRIT-2 · Trusted UI displays fake gas/nonce/fee values

**Files:** `secure/src/nsc/cmd_sign_userop.rs:210-221`, `secure/src/tx/display/value_transfer.rs:50-127`, `display/blind_sign.rs`, `display/erc20_known.rs`
**Invariant violated:** trusted-display contract (the user must see what they're signing)

The renderer is fed an `Eip1559Tx` shim built from the wire payload. The shim **lies about every gas/fee/nonce field**:

```rust
// secure/src/nsc/cmd_sign_userop.rs:210-221
let tx_for_display = Eip1559Tx {
    chain_id,
    nonce: 0,                                  // LIE — real nonce is in the wire
    max_priority_fee_per_gas: U256::zero(),    // LIE
    max_fee_per_gas: U256::zero(),             // LIE
    gas_limit: 0,                              // LIE
    to: Some(to_address),
    value: U256(value),
    data_len,
    access_list_count: 0,
    signing_hash: [0u8; 32],
};
```

The renderers then print the lying values straight to the OLED. From `secure/src/tx/display/value_transfer.rs`:

```rust
write_line(&mut pages.buf[3][0], "Max fee:");
write_gwei(&mut pages.buf[3][1], &tx.max_fee_per_gas);   // prints "0 gwei"
// ...
let n = tx.max_priority_fee_per_gas.format_decimal(9, 3, &mut tmp);  // prints "0.000 gwei"
// ...
let n = format_u64(tx.nonce, &mut tmp);   // prints "Nonce: 0"
```

The signed `userOpHash` (computed via `compute_user_op_hash_v09`) binds the **real** `nonce`, `account_gas_limits`, `pre_verification_gas`, `gas_fees`, and `paymaster_and_data_hash` from the wire (see `cmd_sign_userop.rs:487-497, 565-575`).

#### Exploit

A hostile NS submits a sign request with:
- `to_address` = a benign-looking address (e.g. user's own savings address)
- `value` = $0.01 USDC
- `pre_verification_gas` = `2^120` or similar
- `gas_fees` = `(maxFee=2^127, maxPrio=2^127)`

The user sees on the OLED:

```
To:    0x_savings_address
Value: 0.01 USDC
Max fee: 0 gwei
Tip:   0.000 gwei
(gas: 0)
Nonce: 0
```

The user confirms because everything looks fine. The wallet signs the userOpHash with the real values. The bundler submits to EntryPoint v0.9. EntryPoint pulls `verificationGasLimit * maxFeePerGas + callGasLimit * maxFeePerGas + preVerificationGas * maxFeePerGas` from the wallet's prefund — potentially the entire balance — and the bundler keeps the difference.

Same vector via paymaster (see CRIT-3): NS injects a hostile paymaster, user sees nothing about it, paymaster contract drains the wallet via post-op gas charge.

#### Why "show 0" is worse than "show nothing"

If the OLED simply omitted the gas rows, an experienced user might check the gas with a separate tool. Showing "0 gwei" actively reassures the user that the transaction is bounded.

#### Fix

Either render the real values:

```rust
let tx_for_display = Eip1559Tx {
    chain_id,
    nonce: u64::from_be_bytes(nonce[24..32].try_into().unwrap()),
    max_priority_fee_per_gas: U256::from_be_bytes(&gas_fees[16..32]),
    max_fee_per_gas: U256::from_be_bytes(&gas_fees[0..16]),
    gas_limit: u64::from_be_bytes(account_gas_limits[24..32].try_into().unwrap())
             + u64::from_be_bytes(account_gas_limits[8..16].try_into().unwrap())
             + (pre_verification_gas as u64),
    // ...
};
```

Or refuse the sign if any wrapper field exceeds a sane limit and display "Fees: see bundler" otherwise. The current design — rendering zeros — is the unsafe choice.

---

### CRIT-3 · `paymaster_and_data_hash` is opaque NS input

**Files:** `secure/src/nsc/cmd_sign_userop.rs:134-135, 496, 574`
**Invariant violated:** trusted-display contract; CLAUDE.md invariant #4 (TZ trust boundary)

The wire format passes `paymaster_and_data_hash` as 32 bytes from NS (offset 180-212 of the unified sign input). The firmware copies it directly into the userOpHash params:

```rust
// secure/src/nsc/cmd_sign_userop.rs:134-135
let mut paymaster_and_data_hash = [0u8; 32];
paymaster_and_data_hash.copy_from_slice(&snap[180..212]);
```

```rust
// secure/src/nsc/cmd_sign_userop.rs:496, 574
let t1_params = AaUserOpParamsV09 { ..., paymaster_and_data_hash, ... };
let t2_params = AaUserOpParamsV09 { ..., paymaster_and_data_hash, ... };
```

The trusted UI never sees the paymaster address — only the hash. There is no display path that can render "Paymaster: 0xABC...DEF" or even "Paymaster: yes / no".

#### Exploit

ERC-4337 paymasters can charge the wallet for gas via the EntryPoint's `postOp` callback. A malicious paymaster contract can charge arbitrary amounts (limited only by `paymasterPostOpGasLimit`, which is also NS-controlled). NS supplies a hostile `paymaster_and_data_hash`; user signs; paymaster drains the wallet on the next bundler submit.

#### Fix

Either:
1. Accept the raw `paymasterAndData` bytes (bounded, e.g. 256 bytes max), display the paymaster contract address on the trusted UI, and compute the hash inside the secure world.
2. Refuse to sign when `paymaster_and_data_hash != KECCAK_EMPTY`.

A non-displayable security parameter has no business being inside the signed bytes. This is a textbook "what the user sees ≠ what the user signs" violation.

---

### CRIT-4 · TZSC `SECCFGR1/2/3 = 0` exposes ALL peripherals to NS

**File:** `secure/src/sau.rs:115-121`
**Invariant violated:** #4 (all secrets in TrustZone secure world)

```rust
// secure/src/sau.rs:115-121
#[cfg(feature = "usb")]
{
    core::ptr::write_volatile(TZSC_SECCFGR1, 0x0000_0000);
    core::ptr::write_volatile(TZSC_SECCFGR2, 0x0000_0000);
    core::ptr::write_volatile(TZSC_SECCFGR3, 0x0000_0000);
    cortex_m::asm::dsb();
}
```

The comment immediately above acknowledges the issue:

```
// Mark all AHB2 and APB peripherals as NS for now. Production
// builds should restrict this to only the needed peripherals.
```

But there is **no compile-time guard**. The `usb` feature is enabled in every shipping configuration. This single line opens the entire TZSC-controlled peripheral region to non-secure access:

| Peripheral | What NS can do |
|------------|----------------|
| **RNG (TRNG)** | Read TRNG output. The secure world uses TRNG to generate entropy halves and to (eventually) randomize signing nonces. NS can either drain entropy or, worse, observe it and predict future secure-world reads. |
| **AES, PKA, HASH** | Read intermediate accelerator state during secure-world crypto. AES-GCM wrap of the entropy blob (see `crypto::wrap_entropy`) leaves intermediate cipher state in HW registers between API calls. |
| **I2C1, I2C2** | Issue I2C transactions to the OPTIGA Trust M and SE050 directly while the secure side is not looking. The Shielded Connection / SCP03 keys mitigate replay/eavesdrop but NS can flood the bus, induce timing variations, or interfere with secure-world transactions. |
| **GPIO** (beyond USB-needed pins) | Read button presses (the trusted-UI confirm signal!), drive the OLED to show fake confirmation pages while the secure world is doing something else. |
| **TIM** (timers) | Affect the inactivity timer if it ever migrates from SysTick to a TIM. |

#### Why this is the single biggest bug

CLAUDE.md invariant #4 says "All secrets live ONLY in TrustZone secure world." The intent is that even a fully-compromised NS world cannot reach the secrets. With this hole, NS has direct hardware access to the TRNG and crypto accelerators that the secure world uses to *create and protect* those secrets.

The "trusted UI" depends on GPIO buttons. If NS can read button state directly, NS knows when the user confirms — and could time other attacks to coincide with confirmation events.

#### Fix

Enumerate exactly which peripherals USB needs (USB OTG FS, GPIOA pins PA11/PA12, GPIOB pins PB6/PB7 for UCPD CC, UCPD1, possibly some GPIO for the OLED). Set TZSC bits to mark only those NS; everything else stays Secure. The STM32U585 reference manual (RM0456) §54 enumerates which TZSC bit gates which peripheral.

A useful short-term mitigation: add a `compile_error!` if `usb` is enabled together with `stm32u585` in a hardware release profile, until the per-peripheral allowlist is in place.

---

### CRIT-5 · `init_code_hash` hardcoded to `KECCAK_EMPTY`

**Files:** `secure/src/nsc/cmd_sign_userop.rs:492, 570`; `secure/src/aa/init_code.rs` (entire module is dead C7-era code)

The unified sign path always sets `init_code_hash: KECCAK_EMPTY` for both Type 1 and Type 2:

```rust
// cmd_sign_userop.rs:487-497 (Type 1)
let t1_params = AaUserOpParamsV09 {
    sender, entry_point, chain_id,
    nonce: U256(nonce),
    init_code_hash: KECCAK_EMPTY,         // always empty
    account_gas_limits,
    pre_verification_gas: U256(pre_verification_gas),
    gas_fees,
    paymaster_and_data_hash,
};
```

```rust
// cmd_sign_userop.rs:565-575 (Type 2)
let t2_params = AaUserOpParamsV09 {
    sender, entry_point, chain_id,
    nonce: U256(type2_nonce),
    init_code_hash: KECCAK_EMPTY,         // always empty
    // ...
};
```

#### Consequences

1. **First-deployment UserOps are unsignable.** When a wallet hasn't been deployed on a chain yet, the UserOp must include real `initCode` so the EntryPoint can call `SenderCreator.createSender(initCode)`. The on-chain EntryPoint will compute `userOpHash` with `keccak256(initCode) ≠ KECCAK_EMPTY`. The firmware-signed digest won't match. The C11 verifier fails. UserOp reverts. The wallet on this chain never gets deployed via this path.

2. **`aa/init_code.rs` is dead C7-era code referencing the wrong factory.** The module hard-codes `FACTORY_ADDRESS = [0u8; 20]` (per `shared/src/lib.rs:567`) and computes initCode for the **5-arg** `createAccount(bytes32,bytes32,bytes32,bytes32,bytes)` signature from the deleted `PQCoinbaseSmartWalletFactory`. The current `PQJardinWalletFactory.createAccount(bytes32,bytes32)` takes only 2 args. The selector `[0x19,0x64,0xc4,0xdd]` in `CREATE_ACCOUNT_SELECTOR` is keccak256 of the wrong signature.

3. **If anyone re-wires `init_code.rs` in the future**, NS could supply any `init_code_hash` while the trusted UI shows nothing about the deployment. The user sees "Send 0.01 ETH to Bob" but is also deploying a wallet with attacker-chosen constructor args (e.g. a wallet implementation pointing at a malicious EntryPoint).

#### Fix

Two options:
1. **Document the limitation:** the wallet must be deployed externally before any UserOp from this firmware is accepted on chain. Delete `aa/init_code.rs` to remove the misleading dead code.
2. **Build it correctly:** re-implement `init_code.rs` for the actual 2-arg `PQJardinWalletFactory.createAccount(bytes32,bytes32)`, populate `FACTORY_ADDRESS` with the deployed factory address, and feed the resulting `keccak256(initCode)` into both Type 1 and Type 2 hashes. This is the only way to support first-deploy UserOps without trusting NS to compute the hash correctly.

---

### CRIT-6 · OPTIGA PIN counter is firmware-managed, not chip-enforced

**Files:** `secure/src/optiga/mod.rs:419-470`, `secure/src/optiga/apdu.rs:601-615`
**Invariant violated:** #2 (hardware-level PIN gating)

The PIN attempt counter at `OID_COUNTER = 0xF1D5` has metadata installed at `apdu.rs:601-615`:

```rust
pub fn build_metadata_counter() -> (MetaBuf, usize) {
    let mut inner = [0u8; 64];
    let mut c = 0usize;
    push_ac_conf(&mut inner, &mut c, META_CHANGE);   // Change: Conf(0xE140) only
    push_ac_simple(&mut inner, &mut c, META_READ, AC_ALW);
    push_ac_simple(&mut inner, &mut c, META_EXECUTE, AC_NEV);
    wrap_meta(inner, c)
}
```

`Change=Conf(0xE140)` means the counter can be rewritten by anyone holding the Platform Binding Secret (anyone who can establish a Shielded Connection). It does **not** depend on a successful PIN verify.

Meanwhile `hmac_verify` (`apdu.rs:447-477`) is gated only by the chip's normal `DecryptSym` access controls. The chip does not consult `OID_COUNTER` when deciding whether to perform an HMAC verify. The counter is purely advisory — it's the firmware in `mod.rs:419-470` that:

1. Reads the counter,
2. Compares to `MAX_ATTEMPTS` in software,
3. Writes the bumped counter via `set_data_object` (over the Shielded Connection),
4. Calls `hmac_verify`.

Step 3 has no verify-readback. A glitch during step 3 that causes a nominal-success but actually-failed write leaves the counter unchanged. Step 4 still proceeds. Repeat indefinitely.

Even without faults: if any code path reaches `hmac_verify` without going through the bump-counter step (for example, a future refactor that adds a "test PIN" command, or a fault that skips the bump branch), the counter is bypassed entirely.

#### Why this defeats invariant #2

CLAUDE.md is explicit: "The PIN decision is made by the secure element silicon, never by MCU firmware." The current design makes the PIN decision in the chip silicon (good — `hmac_verify` is constant-time on-chip), but the **lockout decision** is made in firmware. A firmware bug, a glitch, or PBS leakage all bypass it.

#### Exploit

Combined with CRIT-7 and CRIT-9: an attacker with the PBS recovers the PIN offline in seconds. With the firmware-managed counter, even without offline brute force, an online brute force needs only to bypass step 3 once per attempt — which a glitch attack can achieve at MHz rates.

#### Fix

Use a chip-native monotonic counter. Either:
- A monotonic counter at OID `0xE120..0xE123` linked into the AC of `OID_AUTH_REF (0xF1D0)` so the chip refuses `DecryptSym` when the counter is exhausted.
- Set `OID_COUNTER` Change AC to `Conf(E140) AND Auto(F1D0)` so a wrong-PIN attempt cannot reset the counter.
- Add a verify-after-write read on the counter bump that asserts `read == attempts+1`; on mismatch, return `PinLocked` and zeroize state.

---

### CRIT-7 · Single SHA-256 PIN KDF is brute-forceable

**Files:** `secure/src/optiga/mod.rs:253-255`; same scheme used for SE050

```rust
pub fn derive_pin_secret(pin: &[u8; 8]) -> [u8; 32] {
    crypto::kdf(b"optiga-pin-auth-v1", pin, 0)  // single SHA-256 with 0 iterations
}
```

`crypto::kdf` is a single SHA-256 of `domain_tag || pin`. PIN is 8 ASCII digits → ~27 bits of entropy → 10^8 candidates. SHA-256 on a Cortex-M33 at 160 MHz takes microseconds; on commodity hardware, gigahash/sec.

#### Exploit chain

1. Attacker steals the device once. Reads flash via JTAG (or via CRIT-9 if PBS is in plaintext flash). Records a Shielded Connection PIN-auth APDU sequence.
2. Attacker decrypts the recorded session offline using PBS.
3. The decrypted plaintext contains `(challenge, HMAC(pin_secret, challenge))` where `pin_secret = SHA256("optiga-pin-auth-v1" || pin)`.
4. Attacker iterates over 10^8 PIN candidates, computes `HMAC(SHA256("optiga-pin-auth-v1" || candidate), challenge)`, compares to the recorded HMAC. Match in <1 second on a laptop.
5. Same PIN unlocks SE050 (per `dual_se.rs:104, 110`).
6. Attacker has both halves of the seed → full wallet compromise.

#### Fix

Use a memory-hard KDF. Argon2id with parameters tuned for ≥1 second on the STM32U585 (e.g. m=64MB, t=3, p=1 — though m must fit in SRAM, so practically m=128KB, t=10 to push to ~1s). Even with weakening for embedded constraints, this raises offline brute force from <1 second to centuries.

This is a single-function fix in `crypto::kdf` and is high-impact.

---

### CRIT-8 · OPTIGA `GetRandom` runs in plaintext

**Files:** `secure/src/optiga/apdu.rs:311-327`, `secure/src/optiga/mod.rs:444`

```rust
pub unsafe fn get_random(ifx: &mut IfxState, out: &mut [u8]) -> Result<usize, OptigaError> {
    // ...
    let n = ifx.transceive(apdu, &mut resp)?;   // raw I2C, no Shielded Connection
    // ...
}
```

`get_random` is the source of the HMAC challenge for PIN auth (`mod.rs:444`):

```rust
let mut challenge = [0u8; 32];
apdu::get_random(&mut self.ifx, &mut challenge)?;
let mac = hmac_sha256(pin_secret, &challenge);
apdu::hmac_verify(&mut self.ifx, &mut self.shield, OID_AUTH_REF, &challenge, &mac)?;
```

The `ifx.transceive` path skips the Shielded Connection entirely (verified: `send_command` checks `shield.active`, but `get_random` calls `ifx.transceive` directly).

#### Exploit

A MITM on the I2C bus replaces the chip's `get_random` response with a fixed challenge `c0`. The firmware then computes `HMAC(pin_secret, c0)` — over an attacker-chosen challenge.

This enables an offline pre-computation attack:
1. Attacker pre-computes a table of `(pin_i, HMAC(KDF(pin_i), c0))` for all 10^8 PIN candidates.
2. The MITM forces the firmware to use challenge `c0`. The HMAC is sent over the Shielded Connection (encrypted — but if PBS leaks per CRIT-9, recoverable).
3. Decrypted HMAC + table lookup → PIN.

Combined with CRIT-7, this is the primary realistic attack path.

#### Fix

Two fixes, either alone is sufficient, both together are best:
1. Route `get_random` through `send_command` so it goes over the Shielded Connection. The chip supports this; the API just doesn't use it.
2. XOR the chip-supplied random with host-side TRNG: `let mut challenge = chip_random; for i in 0..32 { challenge[i] ^= host_trng[i]; }`. Now even a MITM-controlled chip random is mixed with secure-world entropy.

---

### CRIT-9 · Platform Binding Secret stored in plaintext flash

**Files:** `secure/src/hw/flash.rs:50-51, 254-287`; `secure/src/optiga/apdu.rs:583-615, 640-670`

The PBS is the 32-byte symmetric key that anchors the OPTIGA Shielded Connection. Per `hw/flash.rs`:

```rust
pub const PBS_PAGE_ADDR: u32 = 0x0C0F_C000;
const PBS_PAGE_NUM: u32 = 126;
```

`write_pbs` (`flash.rs:275-287`) writes raw bytes. There is no SAES wrapping, no key encapsulation, no bind-to-HUK. STM32U585 has a hardware unique key (HUK) and SAES that supports key wrapping with AEAD; this is acknowledged as a TODO in `docs/OPTIGATRUSTM/shielded-connection.md:151` ("For STM32U585: SAES-wrapped in secure flash") but not implemented.

Anyone who can dump page 126 has the PBS. From there:

1. **Establish their own Shielded Connection** (`shield.rs:283`) — no PIN needed.
2. **Rewrite the auth-ref OID 0xF1D0** — its Change AC is `Conf(0xE140)` only (`apdu.rs:589-599`). Set the PIN HMAC secret to a known value, then "verify" with that.
3. **Trigger factory reset** — every user OID has Change=`Auto(F1D0) OR Conf(0xE140)` (`apdu.rs:553-579`). The Conf path doesn't need PIN.
4. **Read OID_ENTROPY** — its Read AC is `Auto(F1D0) AND Conf(0xE140)` for `require_shielded=true`, but step (2) gave us the auth-ref bypass.
5. **Reset the PIN counter** — Change AC is `Conf(E140)` only. Combined with (2), unlimited PIN guessing on a target that's not even in attacker's hands (if the PBS was extracted from a sibling device).

#### Why this is the single point of compromise

The dual-SE seed split (invariant #1) is supposed to mean "compromise of one chip leaks no seed bits". But the PBS protects access to the OPTIGA half. PBS in plaintext = PBS extracted = OPTIGA half extracted. Combined with the same PIN being used for SE050 (per `dual_se.rs:104, 110`) and CRIT-7's brute-forceable KDF, the SE050 half also falls.

The phrase "no longer erases PBS (chip remains reusable)" in the OPTIGA factory-reset commit message is also concerning: PBS persistence across factory resets means a stolen device that was previously sold to someone else still has the same PBS. If the original buyer ever extracted the PBS, all subsequent owners are compromised.

#### Fix

1. **SAES-wrap the PBS** with the STM32U585's HUK. `write_pbs` becomes "encrypt with SAES key derived from HUK, then write ciphertext+tag to flash". `load_pbs` becomes "read ciphertext+tag, decrypt with SAES". A flash dump alone yields ciphertext, useless without the per-die HUK.
2. **Bind PBS to measured boot.** Derive the SAES key from `HUK ⊕ measured_firmware_hash`. Now a swapped MCU OR a swapped firmware image yields a different decryption key; PBS becomes unrecoverable.
3. **Optional defense in depth:** require the user PIN to derive part of the wrap key. This breaks the "wipe-without-PIN" recovery path but materially raises the bar.

---

## HIGH findings

A HIGH finding violates a CLAUDE.md invariant or breaks the trusted-display contract, but exploitation requires either an additional precondition (e.g. fault injection capability, NS-world compromise, or a specific user behavior) or causes a more limited form of harm (e.g. session-only key exposure rather than seed extraction).

---

### HIGH-1 · `cmse-nonsecure-entry` pointer validation is software-only

**File:** `secure/src/nsc/ptr_validate.rs:25-65`

```rust
pub(super) fn validate_ns_write_ptr(ptr: u32, len: usize) -> bool {
    if ptr == 0 { return false; }
    let end = match ptr.checked_add(len as u32) { Some(e) => e, None => return false };
    if !(ptr >= NS_SRAM_BASE && end <= NS_SRAM_END) { return false; }
    if ptr < SHARED_MAILBOX_END && end > SHARED_MAILBOX_BASE { return false; }
    true
}
```

The validator only compares against compile-time constants. It never executes the ARMv8-M `TT`/`TTAT` instruction to ask the SAU/IDAU what security attribute the address actually has at runtime.

**Risk:** if anyone changes the SAU layout in `sau.rs`/`memory.x` without also updating `shared/src/lib.rs`, the validator silently accepts addresses that the SAU classifies as Secure. The secure world then accesses those addresses with secure attribution, bypassing the SAU's protection.

**Fix:** use the CMSE intrinsic `cmse_check_address_range(ptr, len, CMSE_NONSECURE | CMSE_MPU_READ)` (read) / `... | CMSE_MPU_READWRITE` (write). This is the ARM-recommended pattern for validating NS pointers from secure code. Keep the constant-window check as defense in depth.

---

### HIGH-2 · `e2e-test` feature exposes `set_e2e_unlocked` with no compile-error guard

**File:** `secure/src/nsc/mod.rs:108-113`, `secure/Cargo.toml:60-65`

```rust
#[cfg(feature = "e2e-test")]
pub fn set_e2e_unlocked(master: [u8; 32]) {
    state::with_state(|s| s.mark_unlocked(master));
}
```

If a CI invocation accidentally enables `e2e-test` together with `stm32u585` for a hardware release build, the resulting binary has a function that any caller can use to unlock the device with an arbitrary master key. `main.rs:600-631` provisions to a hardcoded 24-word abandon mnemonic in this configuration → known wallet.

**Fix:**
```rust
#[cfg(all(feature = "e2e-test", feature = "stm32u585", not(debug_assertions)))]
compile_error!("e2e-test must never be enabled in a hardware release build");
```

Same hardening should extend to `debug-log` and `ui-semihosting`.

---

### HIGH-3 · Verify-before-release is a single un-hardened branch

**File:** `secure/src/nsc/cmd_sign_userop.rs:605-614`

```rust
if !jardin_fosc::verify(
    &slot_ref.pk_seed,
    &slot_ref.pk_root,
    &t2_user_op_hash,
    &sig.data[..sig.len],
) {
    entropy.zeroize();
    ui::show_status("Sig verify", "FAIL");
    return NscStatus::CryptoError as u32;
}
```

A single fault-injected bit-flip on the `if !` instruction (or on the boolean register) skips the verify and releases an unverified Type 2 sig. The codebase commits to fault-injection hardening per `docs/HARDENING.md`.

**Fix:** double-evaluated boolean pattern:
```rust
let v1 = jardin_fosc::verify(...);
let v2 = jardin_fosc::verify(...);
if !v1 || !v2 {
    return NscStatus::CryptoError as u32;
}
```

Or use sentinel patterns: `let ok: u32 = if verify(...) { 0xa5a5_a5a5 } else { 0x5a5a_5a5a }; if ok != 0xa5a5_a5a5 { return CryptoError; }`. Two distinct fault-resistant comparisons increase the cost of fault attacks dramatically.

---

### HIGH-4 · ZK clear-sign attests only first 164 bytes of calldata

**File:** `secure/src/nsc/cmd_sign_userop.rs:289-298`

```rust
let calldata_prefix = &inner_data[..inner_data.len().min(ZK_MAX_CALLDATA)];
let attested_prefix = &calldata_bytes[..calldata_prefix.len()];
if calldata_prefix == attested_prefix
    && calldata_bytes[calldata_prefix.len()..]
        .iter()
        .all(|&b| b == 0)
```

If `inner_data.len() > ZK_MAX_CALLDATA = 164`, the cross-check passes for the first 164 bytes only. The trailing bytes of `inner_data` are not bound by the ZK proof but ARE included in the signed callData (they go into `t2_exec`).

**Exploit:** user sees ZK readable string "Approve 100 USDC for Aave"; firmware signs `approve(USDC, 100) || arbitrary_evil_bytes`. If the targeted contract's selector accepts the longer calldata, evil bytes are executed.

**Fix:** reject the ZK trailer if `inner_data.len() > ZK_MAX_CALLDATA`. Or extend the ZK circuit to attest variable-length calldata up to a higher cap.

---

### HIGH-5 · ZK clear-sign skips `verified_vk.chain_id`/`contract` cross-check

**Files:** `secure/src/nsc/cmd_sign_userop.rs:281-286`, `secure/src/zk/mod.rs:53-67`

The pre-cutover code (in the deleted `cmd_clear_sign.rs:171-174`) verified:
```rust
if verified.chain_id != parsed.tx.chain_id || verified.contract != target {
    ui::show_status("Bad clear-sign", "(vk!=target)");
    return NscStatus::CryptoError as u32;
}
```

Re-enabled ZK path in commit `5df8709` dropped this. The current `verify_clear_sign_proof` Merkle-verifies the VK bundle and runs Groth16 but never compares `verified_vk.chain_id` and `verified_vk.contract` against `tx.chain_id` and `tx.to`.

Per `db_format.rs:131-152`, multiple `(chain_id, contract)` rows can map to the same `vk_id`. An attacker can use a Merkle-verified VK from protocol A on chain A to validate a Type 2 for an unrelated `to_address`, provided they can construct calldata that passes Groth16 under the wrong VK.

**Fix:** restore the cross-check. Either inside `verify_clear_sign_proof` (which already returns the `VerifiedVk`) or at the call site immediately after `Ok(())`.

---

### HIGH-6 · Master keys live as `[u8; 32]` Copy locals on the secure stack

**Files:** `secure/src/nsc/cmd_sign_userop.rs:368, 389`; `secure/src/nsc/state.rs:117-122`; `cmd_request_unlock.rs:46-50`

```rust
// cmd_sign_userop.rs:368
let master_secret = super::state::peek_state(|s| s.master_secret);  // 32-byte copy

// cmd_sign_userop.rs:389
let jardin_master_entropy = crate::crypto::jardin_master_entropy_from_entropy(&entropy);  // never zeroized
```

```rust
// state.rs:117-122
pub(super) fn mark_unlocked(&mut self, master: [u8; 32]) {
    self.master_secret = master;   // overwrites previous via simple assignment, not zeroize
    // ...
}
```

```rust
// cmd_request_unlock.rs:46-50
match se.unlock(pin) {
    Ok(master) => {
        state::with_state(|s| s.mark_unlocked(master));  // master moved by value, not zeroized after
        // ...
    }
}
```

These `[u8; 32]` locals don't have `Drop` impls and don't auto-zeroize. They sit in stack SRAM until later frames overwrite them. A fault that dumps SRAM (cold-boot attack, JTAG, side-channel via subsequent stack reuse with shorter functions) exposes them.

**Fix:** wrap in `Zeroizing<[u8; 32]>` (the `zeroize` crate's newtype that runs zeroize on Drop):

```rust
let master_secret = Zeroizing::new(super::state::peek_state(|s| s.master_secret));
```

Same treatment for `jardin_master_entropy` and the unlock master. Also: in `mark_unlocked`, do `self.master_secret.zeroize()` before the assignment.

---

### HIGH-7 · SysTick re-entrancy can wipe state mid-handler

**Files:** `secure/src/main.rs:797-822`, `secure/src/nsc/state.rs:13-17`

`state.rs` claims "single-threaded and non-reentrant", but the SysTick handler runs while a long handler (PIN entry, slot keygen ~20s, FORS+C sign ~1s, C11 keygen ~3s) is in progress. From SysTick the firmware can call `nsc::zeroize_sensitive_state()` (line 805) when the inactivity timeout fires.

The handler thread holds a stack-local copy of `master_secret` (line 368). The SysTick wipe zeros `STATE.master_secret` but leaves the local copy intact. The handler then proceeds to decrypt entropy with a key the user just had wiped, signs a transaction for a session the user no longer is unlocked for, and only later returns.

Aliased mutable references to `STATE` between the SysTick path (`with_state`) and the main thread (also `with_state`) are undefined behavior in Rust.

**Fix:** either disable SysTick during long handlers, or have every blocking handler explicitly check `timeout::is_idle()` after each blocking step and exit cleanly with `IdleWipe` if true. The blocking PIN/confirm dialogs should drive their own idle checks rather than relying on SysTick to interrupt.

---

### HIGH-8 · PendSV-based re-unlock loop does multi-second blocking work in an exception handler

**File:** `secure/src/main.rs:829-884`

PendSV runs at the lowest exception priority. SysTick can preempt it. After idle-wipe, SysTick triggers PendSV, which runs an infinite `loop { enter_pin() }`. If SysTick re-pends PendSV during the loop, you re-enter the same exception handler — undefined on Cortex-M.

Additionally, while PendSV is blocking on PIN entry, NS cannot make any progress.

**Fix:** PendSV should run a finite amount of work (just queue a re-unlock request flag). The user-facing "press button, enter PIN" loop should run from a normal thread, not from a handler. Or convert to a state machine that runs one step per SysTick.

---

### HIGH-9 · `enc_seq` overflow in OPTIGA Shielded Connection

**File:** `secure/src/optiga/shield.rs:182-221`

```rust
self.enc_seq += 1;
```

No saturation, no wrap-detection. Per Infineon spec (`docs/OPTIGATRUSTM/shielded-connection.md:104`): "Renegotiation threshold: 0xFFFFFFF0 — when sequence number reaches this value, a new handshake is required." Not implemented.

CCM nonce = `enc_nonce_base(4) || enc_seq(4 BE)`. Wrap → nonce reuse → keystream recovery. 2^32 messages is far away in practice but the spec is explicit and this is a defense-in-depth gap.

**Fix:** force re-handshake at `enc_seq >= 0xFFFFFFF0`. Optionally also force re-handshake every N commands or every M minutes.

---

### HIGH-10 · `dec_seq` accepts whatever sequence number the chip sends

**File:** `secure/src/optiga/shield.rs:240-269`

```rust
let seq = ((input[1] as u32) << 24) | ...; // attacker-controlled if MITM
let nonce = Self::build_nonce(&self.dec_nonce_base, seq);
// ...
self.dec_seq = seq + 1;
```

The `dec_seq` is read from the chip-supplied frame. CCM auth still has to pass (so a MITM cannot forge a frame from scratch) but a MITM can **replay** an earlier valid response frame at any time.

**Concrete attack:** during `authenticate_and_read`, after the firmware sends `set_data_object(counter, attempts+1)` and waits for the success response, a MITM replays the success response from a *prior* counter-bump APDU. The chip never received the real command frame (the MITM dropped it). The firmware proceeds with the verify, but the on-chip counter never incremented. Attempt slot is reusable.

**Fix:** reject any received frame with `seq < expected_dec_seq`. Increment `dec_seq` strictly by 1 per response, validate the chip's `seq` matches the expected.

---

### HIGH-11 · `JardinSignature.data` and `type1_out` not zeroized on error paths

**Files:** `secure/src/nsc/cmd_sign_userop.rs:670-672` (and surrounding error branches)

`JardinSignature` is not `ZeroizeOnDrop`. After `slot_ref.sign()` succeeds, `sig.data[..sig.len]` contains the Type 2 bytes. If the subsequent flash write fails, the function returns without writing bytes to NS — but `sig` lives on the stack until the function unwinds. `type1_out` (a `[u8; JARDIN_TYPE1_LEN]`) similarly persists.

**Fix:** add `ZeroizeOnDrop` to `jardin_fosc::JardinSignature`. Ensure `type1_out` is wrapped in `Zeroizing`, or call `.zeroize()` explicitly on every error path.

---

### HIGH-12 · Flash unlock/program/lock sequences interruptible

**Files:** `secure/src/nsc/jardin_flash.rs:355-385`, `secure/src/hw/flash.rs:73-82`

The `unlock → program → lock` sequence in flash operations is not wrapped in `cortex_m::interrupt::free()`. SysTick or another IRQ can land between any two steps and leave SECCR in an inconsistent state (PG/PER set, lock not re-asserted). On STM32U5 this can also cause timing-dependent WRPERR/PGSERR.

`invalidate_icache` lacks DSB/ISB barriers between the FCR write and subsequent loads.

**Fix:** wrap the entire unlock-erase-lock and unlock-program-lock sequences in `cortex_m::interrupt::free(|_| { ... })`. Add `cortex_m::asm::dsb(); cortex_m::asm::isb();` after `invalidate_icache`.

---

### HIGH-13 · NS extends idle window indefinitely by spamming SIGN_USEROP

**Files:** `secure/src/ui/confirm.rs:52`, `cmd_sign_userop.rs`

`confirm()` calls `timeout::reset_activity()` on entry, regardless of whether the user pressed a button. NS-spammed sign requests reset the timer with no user input. Each attempt grants a fresh 2-minute unlocked window.

CLAUDE.md: "Do not let NS world control the inactivity timer. Timer runs on Secure-only TIM. NS pings do not reset it. Only real button presses on S-world confirm dialogs count as activity."

The current code violates this. NS can keep the wallet "armed" by spamming SIGN_USEROP attempts; if the user is away, the screen shows confirmation dialogs that nobody sees, but the timer never expires.

**Fix:** remove the `reset_activity()` call at `confirm.rs:52`. Only the actual button-press path should reset activity.

---

### HIGH-14 · ERC-7201 storage slot constant in `PQOwnable.sol` doesn't match the documented derivation

**File:** `contracts/smart-wallet/src/PQOwnable.sol:24-26`

```solidity
/// @dev keccak256(abi.encode(uint256(keccak256("pqsigner.storage.PQOwnable")) - 1)) & ~bytes32(uint256(0xff))
bytes32 private constant _PQ_OWNABLE_STORAGE_LOCATION =
    0xf3a1a4cdfe9d5bd1e7c1f3e3d6c8f7a3b2f6c9d1e2a4b6c8d0e2f4a6b8c0d200;
```

Verified via `cast`:
- `keccak256("pqsigner.storage.PQOwnable")` = `0xe46f3ef1...59`
- `keccak256(abi.encode(prev - 1)) & ~bytes32(uint256(0xff))` = `0xcb4cadeb7787e52e28ca307d180c484d592168b4843855f610dadfd7a22bd700`
- Hardcoded value: `0xf3a1a4cdfe9d5bd1e7c1f3e3d6c8f7a3b2f6c9d1e2a4b6c8d0e2f4a6b8c0d200`

These do not match. The hardcoded value is fabricated (note the suspicious "ascending nibbles" pattern). Today this is benign because nothing else uses the canonical derivation. Future contracts inheriting `PQOwnable` and adding their own ERC-7201 storage may collide.

**Fix:** replace with the correct constant `0xcb4cadeb7787e52e28ca307d180c484d592168b4843855f610dadfd7a22bd700` OR change the comment to say the slot is hand-picked rather than ERC-7201-derived.

---

### HIGH-15 · `validateUserOp` reverts on unknown sigType

**File:** `contracts/smart-wallet/src/PQJardinWallet.sol:228`

```solidity
revert InvalidSignatureType();
```

If `sig[0]` is anything other than `0x01` or `0x02`, the wallet reverts instead of returning `SIG_VALIDATION_FAILED`. The IAccount spec requires returning `SIG_VALIDATION_FAILED (1)` for failures, so bundlers can simulate without a valid signature.

For empty sig the code correctly returns `SIG_VALIDATION_FAILED` (line 161). For unknown sigType it reverts. Inconsistent.

**Fix:** `return SIG_VALIDATION_FAILED;` instead of revert. Add a unit test.

---

### HIGH-16 · Type 1 silently accepts `r == bytes32(0)` and skips slot registration

**File:** `contracts/smart-wallet/src/PQJardinWallet.sol:182-188`

```solidity
if (r != bytes32(0)) {
    bytes32 slotKey = keccak256(abi.encodePacked(r));
    bytes32 subVkHash = keccak256(abi.encodePacked(subSeed16, subRoot16));
    _registerJardinSlot(slotKey, subVkHash);
}
return SIG_VALIDATION_SUCCESS;
```

If `r == 0`, slot registration is silently skipped but validation succeeds (assuming the C11 sig is valid). The firmware never produces `r=0` in practice, but an attacker who acquires the master C11 key can call `validateUserOp` with `r=0` plus any sub-key commitments and execute arbitrary callData in a Type-1 UserOp without leaving a slot footprint. Forensic visibility lost.

**Fix:** `if (r == bytes32(0)) return SIG_VALIDATION_FAILED;` at line 182.

---

### HIGH-17 · Nonce-key carry on Type 1 + Type 2 nonce arithmetic

**File:** `secure/src/nsc/cmd_sign_userop.rs:738-751`

```rust
fn add_one_to_be_u256(buf: &mut [u8; 32]) {
    for i in (0..32).rev() {
        let (v, overflow) = buf[i].overflowing_add(1);
        buf[i] = v;
        if !overflow { return; }
    }
}
```

EntryPoint v0.9 nonces are 192-bit key + 64-bit sequence packed into 256 bits. `add_one_to_be_u256` adds 1 across the whole 256-bit number. If the user-supplied base nonce has key=K, seq=`0xFFFF…FFFF`, the carry propagates into the key field, silently changing the nonce key.

EntryPoint v0.9 enforces sequence ordering per key but not across keys. The Type 2 UserOp would still be accepted at fresh-key=K+1, seq=0, but the user's intent of "use key K" is silently violated.

**Fix:** explicitly handle the 192/64 split. Refuse the sign if `nonce[24..32] == 0xFF*8` and a Type 1 is required.

---

### HIGH-18 · OPTIGA `factory_reset_admin` is not crash-safe

**Files:** `secure/src/dual_se.rs:225-236`, `secure/src/optiga/mod.rs:654`

OPTIGA reset is sequential (`OID_ENTROPY → OID_AUTH_REF → OID_COUNTER`). A power cut between any two leaves the chip with entropy wiped but PIN auth still intact → the user can still "unlock" but reads zeros for entropy → undefined wallet behavior.

There is an `arm_wipe_flag` mechanism in `flash.rs:387-391` for SE050 only. OPTIGA has no equivalent boot-resume protection.

**Fix:** before starting the OPTIGA reset, write a wipe-in-progress flag to secure flash. On boot, if the flag is set and OPTIGA is in inconsistent state, complete the reset.

---

## MEDIUM findings

| ID | File | Issue |
|----|------|-------|
| M1 | `secure/src/nsc/cmd_sign_userop.rs:111-115` | `SNAP_BUF` static-mut never zeroized after sign; contains last-signed AA payload + inner tx |
| M2 | `secure/src/nsc/jardin_flash.rs:99-103` | 4-byte integrity tag is too narrow against fault injection; widen to 16 bytes |
| M3 | `secure/src/nsc/jardin_flash.rs:518-524` | `pick_newer` `>=` tie-break could pick stale record under glitched `seq` read |
| M4 | `secure/src/nsc/cmd_sign_userop.rs:413` | `slot_index_hint` is unvalidated NS input; bound to `0` for FirstSign |
| M5 | `secure/src/optiga/apdu.rs:606-615` | OPTIGA counter `Read=Always` leaks PIN-success timing to bus snoopers |
| M6 | `secure/src/optiga/apdu.rs:55-65` | `CMD_CLEAR_LAST_ERROR` flag silently wipes chip diagnostics; tamper events at 0xE0C5 invisible |
| M7 | `nonsecure/src/usb/commands.rs:83-94` | No APDU chain-timeout; stale chain state persists indefinitely |
| M8 | `nonsecure/src/usb/commands.rs:307-317` | NS can panic on malformed secure response (`overflow-checks=true`) |
| M9 | `nonsecure/src/usb/commands.rs:152-159` | `CHAIN_BUF` not zeroized on chain reset |
| M10 | `secure/src/aa/userop.rs:175-214` | Legacy v0.6 `compute_user_op_hash` still `pub`; risk of cross-version replay |
| M11 | `secure/src/erc20/bundle.rs:148, vk_bundle.rs:104` | `chain_id.to_le_bytes()` for canonical leaf vs `to_be_bytes` everywhere else |
| M12 | `contracts/PQJardinWalletFactory.sol:58-72` | "Same address on every chain" only holds if factory + verifiers deployed via singleton deployer; no script enforces |
| M13 | `contracts/test/PQJardinWallet.t.sol` | `executeBatch`, cross-chain replay, slot revocation, malformed sig — all untested |
| M14 | `contracts/test/mocks/Mock*.sol` | Mocks always return true; no guard against accidental production use |
| M15 | `secure/src/nsc/cmd_sign_userop.rs:664-672` | `EraseSR/ProgSR/VerifyFail` diagnostics on OLED leak SR bits + addr (acceptable in dev, gate from production) |
| M16 | `secure/src/optiga/shield.rs:240` | `unwrap_response` ignores SCTR; no record-type assertion |
| M17 | `secure/src/optiga/apdu.rs:297-327` | `OpenApplication` and `GetRandom` bypass shielded channel even when active (CRIT-8 covers GetRandom; OpenApplication is intentional) |
| M18 | `secure/src/nsc/jardin_flash.rs:332-346` | `invalidate_icache()` lacks DSB/ISB barriers; unbounded BUSYF wait |
| M19 | `secure/src/optiga/mod.rs:115-121` | Boot-time NOP-loop assumes 160 MHz clock; wakeup paths could overflow watchdog |
| M20 | `contracts/smart-wallet/src/PQJardinWallet.sol:191-225` | No on-chain slot revocation — leaked sub-key remains valid until `q` exhausted |

### M1 — `SNAP_BUF` not zeroized

```rust
static mut SNAP_BUF: [u8; SNAP_LEN] = [0u8; SNAP_LEN];
```

Lives in S SRAM, NS cannot read it directly, but a fault that dumps SRAM exposes the user's recent transaction details (chain, recipient, amount, ZK readable strings, VK bundle). Not a confidentiality leak across the boundary but an invariant-discipline issue.

### M5 — Counter Read=Always leaks unlock outcome

The PIN attempt counter is readable by anyone on the I2C bus (no PIN, no PBS). A passive observer can identify which PIN attempt succeeded (counter resets to 0 on success, increments on fail). Combined with bus traffic timing, narrows the search space if they later capture the device.

**Fix:** Change Read AC to `Conf(E140)` so only the firmware (which has PBS) can read it.

### M11 — Endianness inconsistency

```rust
// secure/src/erc20/bundle.rs:148
buf[0..8].copy_from_slice(&chain_id.to_le_bytes());

// secure/src/nsc/cmd_sign_userop.rs:118-120
let chain_id = u64::from_be_bytes(snap[0..8].try_into().unwrap());
```

The Merkle leaf encoding uses LE; everywhere else uses BE. The `dbgen` host tool must agree. Future maintainers will mismatch this. Document or unify.

### M14 — Test mocks

```solidity
contract MockJardinVerifier {
    bool public valid;
    function verifyForsCUnbalanced(...) external view returns (bool) {
        return valid;
    }
}
```

A typo in `deploy.s.sol` (e.g., the deployer accidentally addresses the mock instead of the real verifier) yields a wallet that accepts any signature. **Fix:** add a `MockOnly` modifier that reverts on `block.chainid != 31337`, or check `extcodehash(verifier) != mockHash` in factory constructor.

### M20 — No on-chain slot revocation

If a sub-key is exfiltrated (side channel, fault injection, compromised flash), the attacker can use any remaining `q` value until the slot is rotated. There is no on-chain "revoke this slot" function. **Fix:** add `revokeSlot(bytes32 slotKey)` gated by a Type-1 (master C11) signature.

---

## LOW findings

| ID | File | Issue |
|----|------|-------|
| L1 | `sphincs-c7/src/lib.rs:27,82,116`, `hypertree.rs:210`, `wots.rs`, `fors.rs:32` | Stale "C7" doc comments throughout; the crate implements C11 |
| L2 | `sphincs-c7/src/fors.rs:32` | Comment "Read up to 3 bytes to cover 16 bits" reflects C7 a=16; for C11 a=11 the math is correct but comment misleading |
| L3 | `secure/src/crypto.rs:597-622` | `derive_c11_master_keypair_from_entropy_with_progress` doesn't zeroize `pk_seed_16`, `sk_seed_arr`, `pk_seed_32`, `sk_seed_32` after move into `keygen` |
| L4 | `sphincs-c7/src/hash.rs:160-169` | `chain_hash` redundantly pad+truncate per iteration — minor optimization opportunity |
| L5 | `sphincs-c7/src/fors.rs:90`, `wots.rs:60` | Hardcoded `10_000_000` grind upper bound; not exploitable but a hardcoded fail-fast |
| L6 | `nonsecure/src/nsc_api.rs:180` | Dead `slot_index` parameter with stale comment |
| L7 | `secure/src/nsc/cmd_sign_userop.rs:740-751` | `add_one_to_be_u256` silently wraps to 0 on full 256-bit overflow (impossible in practice) |
| L8 | `contracts/smart-wallet/src/PQJardinWallet.sol:108-111` | `(ok)` discard pattern for refund call — standard ERC-4337 idiom but unusual |
| L9 | `contracts/smart-wallet/src/PQJardinWallet.sol:140` | `executeBatch` uses string require instead of custom error |
| L10 | `secure/src/nsc/mod.rs:20-29` | Stale documentation table lists deleted CMDs (3, 5, 6) |
| L11 | `secure/src/nsc/cmd_sign_userop.rs:777` | `copy_to_static` race on `STATIC_MSG` (microsecond stale window, non-secret) |
| L12 | `secure/src/optiga/mod.rs:282-290` | `is_provisioned` reads counter without shield — leaks state before unlock |
| L13 | `secure/src/optiga/mod.rs:253-255` | PIN length hardcoded to 8 bytes |
| L14 | `secure/src/optiga/mod.rs:77-104` | `OptigaTrustM` not Drop-zeroized (statics never drop, but inconsistent with `ShieldedConnection`) |
| L15 | `secure/src/boot_ns.rs` | NS image hash not verified before jump (by design — NS is untrusted) |

---

## Cryptographic correctness — what is correct

These were rigorously audited and confirmed correct:

### Recovery contract derivation
**File:** `secure/src/crypto.rs:523-561`

`derive_c11_master_from_bip39_seed` matches the Python reference byte-for-byte:
- HMAC-SHA512 with key `b"sphincs-c6-v1"` (13 ASCII bytes, historical C6 tag preserved per CLAUDE.md), bip39_seed as message.
- `masterPkSeed = keccak256("pk_seed" || master[0..32])` with bottom 16 bytes zeroed via N-mask.
- `masterSkSeed = keccak256("sk_seed" || master[0..32])`.
- Master, bip39_seed both zeroed after use.

7 host-side tests (`crypto.rs:822-900`) pin the derivation against external Python-generated reference vectors. Any silent change breaks the test suite.

### `extract_ht_index` C7→C11 fix
**File:** `sphincs-c7/src/fors.rs:53-72`

The fix in commit `898ca12` correctly replaces the C7-era `(digest >> 128) & 0xFFFFFF` (24 bits at bit 128) with C11-correct `(digest >> 143) & 0xFFFF` (16 bits at bit 143).

`K*A = 13*11 = 143` is the correct starting bit for `htIdx` in C11. The implementation reads `digest[12..15]` as a 24-bit window covering bit positions 136..159, which spans the needed 143..158. `(combined >> 7) & 0xFFFF` extracts exactly bits 143..158.

This matches the Solidity verifier `SPHINCsC11Asm.sol:38`: `let htIdx := and(shr(143, digest), 0xFFFF)`.

No other C7-parameter constants remain in executable code. All sized constants come from `params.rs` with compile-time `assert!`s (h=16, d=2, a=11, k=13, w=8, l=43, sig=3976).

### JARDIN unbalanced tree
**File:** `jardin-fosc/src/unbalanced.rs`

Symmetric build/verify; ADRS depth values `cp` walk from `q-1` to `0` in verify, mirroring build's bottom-up depth assignment. Boundary cases (q=1, q=Q_MAX=95) both reconstruct to the same `pk_root` produced by build.

### H_msg constructions
- **JARDIN H_msg (192 bytes)**: `pkSeed(32) || pkRoot(32) || R(32) || message(32) || counter_u256(32) || 0xFF×32`. Matches `JardinForsCVerifier.sol:41-52` byte-for-byte.
- **C11 H_msg (160 bytes)**: 5 fields (no counter). Matches `SPHINCsC11Asm.sol:30-35`.

### q encoding in FORS+C signature
`q = (sig.len() - 2452) / 16`, computed identically in Rust (`lib.rs:247-254`) and Solidity (`JardinForsCVerifier.sol:30-32`). Both reject invalid q values. q is unambiguous from signature length.

### Zeroization of crypto types
- `SigningKey` (`sphincs-c7/src/lib.rs:31`): `#[derive(Zeroize, ZeroizeOnDrop)]`. Zeroes `sk_seed`, `pk_seed`, `pk_root` on drop. Not Copy, not Clone.
- `JardinSlot` (`jardin-fosc/src/lib.rs:46`): `ZeroizeOnDrop`. `sk_seed` zeroed; `pk_seed`/`pk_root`/`fors_pks`/`spine`/`sentinel` skipped (public values).
- `derive_c11_master_from_bip39_seed` zeroes `master`. `derive_c11_master_from_entropy` zeroes `bip39_seed`.

### No `unsafe` in `sphincs-c7` / `jardin-fosc`
Both crates have `#![deny(unsafe_op_in_unsafe_fn)]` and zero `unsafe` blocks.

### Wire formats match firmware ↔ Solidity
- `JARDIN_TYPE1_LEN = 4041 = 1+32+16+16+3976` in `shared/src/lib.rs:486` and `TYPE_1_SIG_LEN` in `PQJardinWallet.sol:59`.
- 65-byte Type 2 header (1 marker + 32 slotKey + 16 subSeed + 16 subRoot) and FORS+C body match `cmd_sign_userop.rs:702-718` exactly.

### EIP-712 typehashes for v0.9
- `PACKED_USEROP_TYPEHASH = 0x29a0bca4af4be3421398da00295e58e6d7de38cb492214754cb6a47507dd6f8e` — verified via `cast keccak`, matches firmware constant.
- `EIP712Domain` typehash, `keccak256("ERC4337")`, `keccak256("1")` all match.

Known-vector test (`aa/userop.rs:766-802`) verifies `compute_user_op_hash_v09` against external Python reference.

### TOCTOU snapshot pattern
`cmd_sign_userop.rs:111-115` correctly snapshots the entire payload from NS into a static SRAM buffer before parsing. Single-threaded gateway means no NS-mid-call mutation race.

### APDU chaining INS-mismatch
`nonsecure/src/usb/commands.rs:147-155` correctly rejects chained chunks with mismatched INS. The `bc69448` fix is sound.

### Slot conflict guard
`PQOwnable.sol:53`: `require(prev == bytes32(0) || prev == subVkHash, "slot conflict");` — idempotent re-registration of the same key, mismatched re-registration reverts.

### Tear-resistant flash layout
`jardin_flash.rs`: integrity tag covers QW 0-6, valid_marker at byte 127 in QW 7 (programmed last). Torn writes during QW 7 leave valid_marker != 0x00 (rejected by `deserialize`). Torn writes earlier leave the integrity hash mismatched. Layout is structurally sound (though see M2 about widening the tag).

### Reentrancy (Solidity)
All sensitive functions on `PQJardinWallet` gated by `msg.sender == _entryPoint`. EntryPoint itself has `nonReentrant`. The target contract called via `execute`/`executeBatch` cannot re-enter `execute` or `validateUserOp` without being entryPoint.

### Forced-zero check (Solidity)
`JardinForsCVerifier.sol:56`: `if and(shr(125, digest), 0x1F) { revert(0, 0) }` — verifies tree 25 index is 0.

### EntryPoint trust boundary (Solidity)
`PQJardinWallet.sol:104, 121, 138`: `validateUserOp`, `execute`, `executeBatch` all check `msg.sender == address(_entryPoint)`. `_entryPoint` is `immutable`, set in constructor only.

### CREATE2 salt deterministic
`PQJardinWalletFactory.sol:74-76`: `salt = keccak256(masterPkSeed || masterPkRoot)`. Pure, deterministic, depends only on the master keys. Assuming the factory and verifier addresses are identical across chains (deployed via singleton deployer), the wallet address is the same on every chain.

### No upgradeability, no admin
Factory has no admin functions; wallet has no rotation function for master keys; constructor args (`masterPkSeed`, `masterPkRoot`) are `immutable`.

---

## Recommended ship checklist

In strict priority order. Items in **CANNOT SHIP** must be fixed before any wallet is provisioned for real funds; items in **MUST FIX BEFORE MAINNET** must be fixed before any production deployment; items in **DEFENSE IN DEPTH** are robustness improvements that should land before scale.

### Cannot ship

1. **CRIT-1 multi-chain q-reuse.** Restructure `jardin_flash` to a per-chain log-structured store. Each persisted record is keyed by `(chain_id, slot_index)`. `read_latest(chain_id)` returns the latest for that chain. Compaction when the 16KB region fills.
2. **CRIT-2 trusted-UI display.** Render the real `nonce`, `account_gas_limits` (separated into verGas/callGas), `pre_verification_gas`, `gas_fees` (separated into maxFee/maxPrio). Compute and display the maximum-fee (`maxFee × (verGas + callGas) + maxFee × preVerGas`). If any field exceeds a sane threshold (e.g. 10^9 wei × 10^7 gas = 10^16 wei = 0.01 ETH), require an additional confirmation page.
3. **CRIT-3 paymaster opacity.** Either (a) accept raw `paymasterAndData` bytes (bounded, ≤256B), display the paymaster contract address on the trusted UI, compute the hash inside the secure world; OR (b) refuse to sign when `paymaster_and_data_hash != KECCAK_EMPTY`.
4. **CRIT-4 TZSC peripheral exposure.** Enumerate USB-required peripherals (USB OTG FS, GPIOA PA11/PA12, GPIOB PB6/PB7 UCPD, UCPD1, OLED-driving GPIO). Set TZSC bits to mark only those NS; everything else stays Secure. Add a runtime assert that RNG, AES, PKA, HASH, both I2Cs are still Secure.
5. **CRIT-5 init_code_hash.** Either delete `aa/init_code.rs` and document that the wallet must pre-exist on chain, OR rebuild it for the actual 2-arg `PQJardinWalletFactory.createAccount` (with the deployed factory address) and feed real `keccak256(initCode)` into both Type 1 and Type 2 hashes.
6. **CRIT-6 OPTIGA counter.** Switch to chip-enforced lockout: monotonic counter at OID `0xE120..0xE123` linked into the AC of `OID_AUTH_REF (0xF1D0)`, OR change `OID_COUNTER` Change AC to `Conf(E140) AND Auto(F1D0)`. Add verify-after-write read.
7. **CRIT-7 PIN KDF.** Replace the single SHA-256 with Argon2id tuned for ~1 second on STM32U585. Single-function fix in `crypto::kdf`.
8. **CRIT-8 GetRandom.** Route `get_random` through `send_command` (over the Shielded Connection). XOR the chip-supplied random with host-side TRNG.
9. **CRIT-9 PBS protection.** SAES-wrap the PBS using STM32U585's HUK. `write_pbs` and `load_pbs` updated to encrypt/decrypt. Optionally bind the wrap key to measured-firmware-hash for additional defense.

### Must fix before mainnet

10. **HIGH-1.** Replace `validate_ns_*` with `cmse_check_address_range` (TT instruction).
11. **HIGH-2.** `compile_error!` for `e2e-test + stm32u585` combination. Same for `debug-log + stm32u585 + release`.
12. **HIGH-3.** Double-evaluate the verify-before-release branch on Type 2 sigs.
13. **HIGH-4 + HIGH-5.** Refuse ZK trailer if `inner_data.len() > 164`. Restore the `verified_vk.chain_id` and `verified_vk.contract` cross-check that pre-cutover code had.
14. **HIGH-6.** Wrap `master_secret`, `jardin_master_entropy`, and the unlock master in `Zeroizing<[u8; 32]>`. In `mark_unlocked`, zeroize the previous value before assignment.
15. **HIGH-7.** Disable SysTick wipe path during long handlers, OR have every blocking handler explicitly check `timeout::is_idle()` after each blocking step and exit cleanly.
16. **HIGH-8.** Refactor PendSV out of the blocking PIN entry. PendSV should set a flag; the user-facing PIN dialog should run from a thread.
17. **HIGH-9 + HIGH-10.** Implement Shielded Connection renegotiation threshold (`enc_seq >= 0xFFFFFFF0`). Reject decreasing `dec_seq`.
18. **HIGH-11.** Make `JardinSignature` `ZeroizeOnDrop`. Wrap `type1_out` in `Zeroizing`.
19. **HIGH-12.** `cortex_m::interrupt::free()` around all flash unlock/program/lock sequences. Add DSB/ISB after `invalidate_icache`.
20. **HIGH-13.** Remove `confirm()` entry-time `reset_activity()`. Only confirmed button presses count as activity.
21. **HIGH-14.** Fix the ERC-7201 constant in `PQOwnable.sol` (use `0xcb4cadeb...`) or remove the misleading derivation comment.
22. **HIGH-15 + HIGH-16.** `return SIG_VALIDATION_FAILED` for unknown sigType. Add `if (r == bytes32(0)) return SIG_VALIDATION_FAILED;` to Type 1 path.
23. **HIGH-17.** Explicit reject of nonce-key carry: if `nonce[24..32] == 0xFF*8` and Type 1 is required, refuse the sign.
24. **HIGH-18.** Crash-safe OPTIGA factory reset: write a wipe-in-progress flag to secure flash before starting; complete on boot if flag is set.

### Defense in depth

All MEDIUM items, particularly:
- **M2** — widen integrity tag from 4 bytes to 16 bytes (covers bytes [0..127), valid_marker at byte 127).
- **M4** — enforce `slot_index_hint == 0` on FirstSign.
- **M14** — add a deploy-script check or revert-on-mainnet guard in test mocks.
- **M20** — add `revokeSlot(bytes32 slotKey)` gated by Type-1 master signature.
- **M11** — unify endianness (BE everywhere).
- **M13** — fill test coverage gaps for `executeBatch`, cross-chain replay, slot-key collision attempts, malformed signatures.

### Process recommendations

- Add a `prod-check` Make target that fails if `e2e-test`, `debug-log`, `ui-semihosting`, or `mock-se` are enabled in a release build.
- Add a `cargo deny` config that enforces specific feature exclusions for hardware targets.
- Pin all submodule SHAs (account-abstraction, openzeppelin, solady).
- Add a Foundry deploy script that deploys via a singleton deployer (so factory + verifier addresses are deterministic across chains) and verify the script is the only code path that reaches `forge script`.
- Add a fuzz test for `compute_user_op_hash_v09` that compares output against a Solidity-side implementation deployed on a Foundry test chain.
- Add a Foundry invariant test that `PQJardinWallet` storage slots don't collide with `PQOwnable` storage slots even after upgrades to either contract.

---

## Closing notes

The post-cutover architecture is fundamentally sound: pure post-quantum signing, dual-SE seed split, hardware-rooted PIN, Merkle-anchored display metadata. The cryptography is correct. The on-chain contracts mirror the firmware byte-for-byte. The state machine for Type 1 / Type 2 / Rotate is the right shape.

The bugs are concentrated in three places where an attacker would naturally look first: (a) the boundary between what the user sees and what gets signed, (b) the OS-level isolation between secure and non-secure worlds, and (c) the OPTIGA driver's reliance on firmware to enforce decisions that should live in chip silicon. None of these are deep cryptographic flaws; all are addressable with focused engineering work.

The most important fixes are the trusted-UI display (CRIT-2), the TZSC peripheral closure (CRIT-4), and the OPTIGA hardening chain (CRIT-6 → CRIT-9). Those four fixes together collapse the attack surface dramatically.

The multi-chain q-reuse bug (CRIT-1) requires a more substantial flash-store refactor but is also achievable.

With the CRITICAL and HIGH items addressed, the wallet will be in a strong position. The cryptographic foundation is the hard part; everything else is engineering.

— end of audit

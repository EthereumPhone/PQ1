# JARDÍN FORS+C — Firmware Completion Guide

What's done, what's missing, and exact instructions for wiring up the E2E firmware path.

---

## 1. What Is Already Implemented

### 1.1 `jardin-fosc/` Rust Crate (COMPLETE)

A fully working `no_std`, no-alloc FORS+C library at `jardin-fosc/`.

| Module | Purpose | Status |
|--------|---------|--------|
| `src/params.rs` | k=26, a=5, Q_MAX=95, FORSC_BODY=2452, SIG_MAX=3972 | Done |
| `src/address.rs` | 32-byte ADRS packing (atype 3/4/6) | Done |
| `src/hash.rs` | keccak256 tweakable hashes, H_msg (192B), fors_secret, sentinel, key derivation | Done |
| `src/fors.rs` | FORS+C sign/verify, treehash, forced-zero grinding | Done |
| `src/unbalanced.rs` | left-spine Merkle tree (build, auth path, verify) | Done |
| `src/lib.rs` | `JardinSlot` (keygen/sign), `JardinSignature`, `verify()` | Done |

**Public API:**
```rust
pub struct JardinSlot {
    pub pk_seed: [u8; 32],    // N bytes left-aligned, right-zero-padded
    sk_seed: [u8; 32],        // ZeroizeOnDrop
    pub pk_root: [u8; 32],    // N bytes left-aligned
    pub fors_pks: [[u8; 32]; 95],
    spine: [[u8; 32]; 94],
    sentinel: [u8; 32],
    pub next_q: u32,          // 1-indexed, starts at 1
}  // ~3,125 bytes

impl JardinSlot {
    pub fn keygen(entropy: [u8; 32]) -> Self;     // ~235K hashes, ~3-4s on M33
    pub fn sign(&mut self, msg: &[u8; 32]) -> Result<JardinSignature, &'static str>;
    pub fn remaining(&self) -> u8;
    pub fn is_exhausted(&self) -> bool;
    pub fn sub_vk_hash(&self) -> [u8; 32];        // keccak256(pkSeed[..16] || pkRoot[..16])
}

pub fn verify(pk_seed: &[u8; 32], pk_root: &[u8; 32], msg: &[u8; 32], sig: &[u8]) -> bool;
```

**Key derivation chain** (in `hash.rs`):
```
master_entropy (32B, from BIP-39 via crypto.rs)
  → jardin_slot_entropy(master, slot_index) → slot_entropy (32B)
  → jardin_derive_keys(slot_entropy) → (pk_seed, sk_seed)
  → JardinSlot::keygen(slot_entropy) → full slot with fors_pks + spine + pk_root

  → jardin_slot_r(master, slot_index) → r (32B)
  → keccak256(r) → slot_key = H(r)  (on-chain identifier)
```

**11 tests pass**, including `test_sign_verify_all_q` which signs and verifies at every q=1..95.

### 1.2 Solidity Contracts (COMPLETE)

| File | Purpose | Status |
|------|---------|--------|
| `contracts/.../verifiers/JardinForsCVerifier.sol` | Yul-optimized FORS+C verifier | Done, 61K gas (q=1), 75K gas (q=50) |
| `contracts/.../verifiers/IJardinVerifier.sol` | Interface | Done |
| `contracts/.../PQOwnable.sol` | `jardinSlots` mapping, `_registerJardinSlot()`, event | Done |
| `contracts/.../PQCoinbaseSmartWallet.sol` | `SignerType.JARDIN`, `registerJardinSlot()`, validation branch, `slotKey` field in wrapper | Done |
| `test/JardinFoscVerifier.t.sol` | 10 cross-language tests, all pass | Done |
| `test/mocks/MockJardinVerifier.sol` | Test mock | Done |

**Cross-language verification confirmed:** Rust signs → Solidity verifies, tested at q=1, q=2, q=50.

### 1.3 Firmware Foundations (PARTIAL)

| File | Changes | Status |
|------|---------|--------|
| `shared/src/lib.rs` | CMD_SIGN_JARDIN=15, CMD_REGISTER_JARDIN_SLOT=16, CMD_GET_JARDIN_SLOT_INFO=17, SIGNER_JARDIN=0x02, JARDÍN size constants, NscStatus::SlotExhausted=8 | Done |
| `secure/Cargo.toml` | `jardin-fosc = { workspace = true }` dependency | Done |
| `secure/src/crypto.rs` | `jardin_master_entropy_from_bip39()`, `jardin_master_entropy_from_entropy()` | Done |
| `secure/src/nsc/state.rs` | JARDÍN fields in SecureState, static JARDIN_SLOT, zeroize integration | Done |
| `secure/src/nsc/sign_and_emit.rs` | `decrypt_and_sign_jardin()` — full signing pipeline | Done |
| Root `Cargo.toml` | Workspace member + profile overrides | Done |

---

## 2. What Is Missing for Full E2E

### 2.1 Three Gateway Command Handlers

These are the actual command entry points that the NS world calls. Each one follows the established pattern in the existing `cmd_*.rs` files.

| File to create | CMD ID | Purpose |
|----------------|--------|---------|
| `secure/src/nsc/cmd_sign_jardin.rs` | 15 | Compact JARDÍN sign |
| `secure/src/nsc/cmd_register_jardin_slot.rs` | 16 | Generate slot registration UserOp (C11-signed) |
| `secure/src/nsc/cmd_get_jardin_slot_info.rs` | 17 | Query current slot state |

### 2.2 Dispatcher Wiring in `nsc/mod.rs`

Three things to add:

1. **Module declarations** (after line 63):
```rust
mod cmd_sign_jardin;
mod cmd_register_jardin_slot;
mod cmd_get_jardin_slot_info;
```

2. **Import CMD constants** (line 70-75, add to the existing `use` block):
```rust
CMD_SIGN_JARDIN, CMD_REGISTER_JARDIN_SLOT, CMD_GET_JARDIN_SLOT_INFO,
```

3. **Match arms in `dispatch()`** (after line 201, before the `_ =>` catch-all):
```rust
CMD_SIGN_JARDIN => cmd_sign_jardin::run(args),
CMD_REGISTER_JARDIN_SLOT => cmd_register_jardin_slot::run(args),
CMD_GET_JARDIN_SLOT_INFO => cmd_get_jardin_slot_info::run(args),
```

4. **CMSE veneers** (after line 351, for STM32U585 hardware):
```rust
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_sign_jardin(
    payload_ptr: u32, sig_out_ptr: u32, total_len: u32,
) -> u32 {
    let args = GatewayArgs { arg0: payload_ptr, arg1: sig_out_ptr, arg2: total_len };
    unsafe { cmd_sign_jardin::run(&args) }
}

#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_register_jardin_slot(
    payload_ptr: u32, out_ptr: u32, total_len: u32,
) -> u32 {
    let args = GatewayArgs { arg0: payload_ptr, arg1: out_ptr, arg2: total_len };
    unsafe { cmd_register_jardin_slot::run(&args) }
}

#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_get_jardin_slot_info(
    payload_ptr: u32, out_ptr: u32, out_len: u32,
) -> u32 {
    let args = GatewayArgs { arg0: payload_ptr, arg1: out_ptr, arg2: out_len };
    unsafe { cmd_get_jardin_slot_info::run(&args) }
}
```

### 2.3 E2E Test Entries

Extend `nonsecure/src/e2e_test.rs` with JARDÍN test cases.

---

## 3. Exact Specifications for Each Missing Command

### 3.1 `cmd_sign_jardin.rs` (CMD 15)

**Purpose:** Sign a message hash with JARDÍN FORS+C using the compact signature scheme.

**Payload wire format:**
```
[0..8)     chain_id     u64 BE
[8..12)    slot_index   u32 BE
[12..44)   msg_hash     32 bytes
```
Total: 44 bytes (fixed).

**Response:** Written to `sig_out_ptr`, variable length:
```
[0]         signer_type   0x02 (SIGNER_JARDIN)
[1..33)     slot_key      H(r) — 32 bytes
[33..65)    subPkSeed     32 bytes (16 real + 16 zero-padding)
[65..97)    subPkRoot     32 bytes (16 real + 16 zero-padding)
[97..)      raw JARDÍN signature (2452 + q*16 bytes)
```
Total: 97 + 2452 + q*16 = 2549 (q=1) to 4069 (q=95).

**Handler structure** (follow `cmd_sign_message.rs` pattern):

```rust
//! CMD_SIGN_JARDIN — JARDÍN FORS+C compact signing.

use sphincs_tz_shared::{NscStatus, JARDIN_WRAPPER_MAX_LEN};
use super::ptr_validate::{validate_ns_read_ptr, validate_ns_write_ptr};
use super::GatewayArgs;

const PAYLOAD_LEN: usize = 8 + 4 + 32; // chain_id + slot_index + msg_hash = 44

pub(super) unsafe fn run(args: &GatewayArgs) -> u32 {
    crate::ui::show_status("JARDIN", "validating...");

    // 1. Check unlock
    if !super::state::peek_state(|s| s.pin_verified) {
        return NscStatus::NotInitialized as u32;
    }

    // 2. Parse args
    let payload_ptr = args.arg0 as *const u8;
    let sig_ptr = args.arg1 as *mut u8;
    let total_len = args.arg2 as usize;

    // 3. Length validation
    if total_len < PAYLOAD_LEN {
        return NscStatus::InvalidPointer as u32;
    }

    // 4. Pointer validation
    if !validate_ns_read_ptr(args.arg0, total_len) {
        return NscStatus::InvalidPointer as u32;
    }
    if !validate_ns_write_ptr(args.arg1, JARDIN_WRAPPER_MAX_LEN) {
        return NscStatus::InvalidPointer as u32;
    }

    // 5. TOCTOU snapshot (volatile read all payload bytes into secure stack)
    let mut buf = [0u8; PAYLOAD_LEN];
    for i in 0..PAYLOAD_LEN {
        buf[i] = core::ptr::read_volatile(payload_ptr.add(i));
    }

    // 6. Parse fields
    let chain_id = u64::from_be_bytes([
        buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
    ]);
    let slot_index = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
    let mut msg_hash = [0u8; 32];
    msg_hash.copy_from_slice(&buf[12..44]);

    // 7. UI confirmation (minimal — show "JARDÍN sign q=N")
    //    NOTE: For production, you'd want to show the decoded tx details.
    //    For initial E2E, a simple confirm is sufficient.
    //    The msg_hash is opaque here — the companion has already confirmed
    //    the tx details via the USB APDU protocol.
    //
    //    Alternatively, skip confirmation for JARDÍN if the companion
    //    protocol already confirmed at the USB layer (like CMD_SIGN_USEROP
    //    in mode ≥ 2 does for bootstrap sigs).

    // 8. Hand off to signing tail
    let (status, _total_written) = super::state::with_state(|s| {
        super::sign_and_emit::decrypt_and_sign_jardin(
            s,
            &msg_hash,
            sig_ptr,
            chain_id,
            slot_index,
            "Signed",
        )
    });

    status
}
```

**Key design notes:**

- Unlike `cmd_sign_userop`, this command receives a **pre-computed msg_hash** (the userOpHash or EIP-191 hash). The companion/NS world is responsible for computing the hash. The secure world just signs it.
- No OTS monotonicity check needed — JARDÍN's q counter is internal to the slot and advances automatically. The on-chain contract doesn't track q (it's implicit in the signature length). Double-signing the same q degrades security from 128→105 bits but doesn't break the protocol.
- `decrypt_and_sign_jardin` in `sign_and_emit.rs` handles slot initialization, keygen-on-first-use, and the signing tail. It returns `(status, total_bytes_written)`.
- The `total_bytes_written` return value tells the caller how many bytes were written to `sig_ptr`, since the signature is variable-length. The NS side needs this to know how much data to read back. You may want to write this as a prefix or pass it via a separate mechanism (e.g., write it to a known offset, or use `args.arg2` as a pointer to a u32 that receives the length).

**Open question — response length communication:**

The current `sign_and_emit::decrypt_and_sign_jardin` returns `(u32, usize)` where the second value is the total bytes written. But the NSC gateway only returns a single `u32` (the status code). Options:

1. **Write length prefix:** Write `total_len` as a 4-byte BE prefix at `sig_ptr[0..4]`, then the wrapper data at `sig_ptr[4..]`. NS reads the prefix first.
2. **Use arg2 as output pointer:** Pass `args.arg2` as a `*mut u32` where the handler writes the response length on success.
3. **Derive from q:** The NS side knows `slot_index` and can query `CMD_GET_JARDIN_SLOT_INFO` to learn the current `next_q`, then compute `97 + 2452 + q*16`. But this is fragile across races.

**Recommendation:** Option 1 (length prefix) is simplest and matches how the existing UserOp response format works (`init_code_len(4) + ...`). Change the response format to:
```
[0..4)      response_len   u32 BE (total bytes following this field)
[4..101)    JARDÍN wrapper header (97 bytes)
[101..)     raw JARDÍN signature (2452 + q*16 bytes)
```

### 3.2 `cmd_register_jardin_slot.rs` (CMD 16)

**Purpose:** Generate a C11-signed UserOp that calls `registerJardinSlot(slotKey, subVkHash)` on the wallet contract. The companion submits this UserOp to the EntryPoint.

**Payload wire format:**
```
[0..8)     chain_id     u64 BE
[8..12)    slot_index   u32 BE
[12..16)   key_index    u32 BE  (C11 main signer epoch for the outer sig)
[16..20)   ots_index    u32 BE  (C11 main signer OTS for the outer sig)
[20..52)   sender       20 bytes + 12 padding (wallet address for UserOp)
[52..72)   entry_point  20 bytes (EntryPoint address)
[72..104)  nonce        u256 BE
... (remaining AA fields same as CMD_SIGN_USEROP header)
```

This is the most complex command. It needs to:

1. Derive the JARDÍN slot for `(chain_id, slot_index)` to get `(pk_seed, pk_root)`
2. Compute `r = jardin_slot_r(master, slot_index)` and `slot_key = keccak256(r)`
3. Compute `sub_vk_hash = keccak256(pk_seed[..16] || pk_root[..16])`
4. Build the inner callData: `abi.encodeCall(registerJardinSlot, (slot_key, sub_vk_hash))`
   - Selector: `keccak256("registerJardinSlot(bytes32,bytes32)")[:4]`
   - ABI: `selector(4) + slot_key(32) + sub_vk_hash(32) = 68 bytes`
5. Build the outer `execute(self, 0, callData)` callData
6. Compute `userOpHash` from the AA parameters + `keccak256(executeCallData)`
7. Sign `userOpHash` with C11 main signer via `decrypt_and_sign_wrapped()`
8. Write the full UserOp response (same format as CMD_SIGN_USEROP mode 0)

**This is essentially a specialized version of CMD_SIGN_USEROP** where the inner tx is synthesized by firmware rather than parsed from NS. You can reuse `userop_tail.rs` machinery, or write a self-contained handler.

**Simplification for V1:** Instead of building the full UserOp, the firmware could just return the `(slot_key, sub_vk_hash, r, pk_seed, pk_root)` tuple and let the companion build the UserOp. The companion already knows how to construct UserOps — it just needs the slot parameters. This avoids duplicating the entire UserOp construction logic.

**Simplified response format:**
```
[0..32)     slot_key       H(r)
[32..64)    sub_vk_hash    keccak256(subPkSeed[..16] || subPkRoot[..16])
[64..80)    sub_pk_seed    16 bytes (raw, not padded)
[80..96)    sub_pk_root    16 bytes (raw, not padded)
[96..128)   r              32 bytes (the raw randomizer, for the companion to verify)
```
Total: 128 bytes.

The companion then constructs the UserOp with `execute(self, 0, registerJardinSlot(slot_key, sub_vk_hash))` and signs it via `CMD_SIGN_USEROP` or `CMD_SIGN_MESSAGE`.

### 3.3 `cmd_get_jardin_slot_info.rs` (CMD 17)

**Purpose:** Query the current JARDÍN slot state for a given chain.

**Payload wire format:**
```
[0..8)     chain_id     u64 BE
[8..12)    slot_index   u32 BE
```
Total: 12 bytes.

**Response format:**
```
[0..4)     slot_index     u32 BE
[4]        next_q         u8 (1-95, or 96 if exhausted)
[5]        remaining      u8 (0-95)
[6]        slot_active    u8 (1 if this slot is loaded in memory, 0 otherwise)
```
Total: 7 bytes.

**Handler structure** (follow `cmd_get_main_pubkey.rs` pattern):

```rust
use sphincs_tz_shared::NscStatus;
use super::ptr_validate::{validate_ns_read_ptr, validate_ns_write_ptr};
use super::GatewayArgs;

const PAYLOAD_LEN: usize = 12;
const RESPONSE_LEN: usize = 7;

pub(super) unsafe fn run(args: &GatewayArgs) -> u32 {
    let payload_ptr = args.arg0 as *const u8;
    let out_ptr = args.arg1 as *mut u8;
    let out_len = args.arg2 as usize;

    if out_len < RESPONSE_LEN {
        return NscStatus::InvalidPointer as u32;
    }
    if !validate_ns_read_ptr(args.arg0, PAYLOAD_LEN) {
        return NscStatus::InvalidPointer as u32;
    }
    if !validate_ns_write_ptr(args.arg1, RESPONSE_LEN) {
        return NscStatus::InvalidPointer as u32;
    }

    if !super::state::peek_state(|s| s.pin_verified) {
        return NscStatus::NotInitialized as u32;
    }

    // TOCTOU snapshot
    let mut buf = [0u8; PAYLOAD_LEN];
    for i in 0..PAYLOAD_LEN {
        buf[i] = core::ptr::read_volatile(payload_ptr.add(i));
    }

    let chain_id = u64::from_be_bytes([
        buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
    ]);
    let slot_index = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);

    // Read state
    let (next_q, remaining, active) = super::state::peek_state(|s| {
        if s.jardin_slot_active
            && s.jardin_chain_id == chain_id
            && s.jardin_slot_index == slot_index
        {
            // Read from the live slot
            let slot = &*core::ptr::addr_of!(super::state::JARDIN_SLOT);
            match slot {
                Some(s) => (s.next_q as u8, s.remaining(), 1u8),
                None => (1u8, 95u8, 0u8),
            }
        } else {
            (1u8, 95u8, 0u8) // not loaded
        }
    });

    // Write response
    let si_bytes = slot_index.to_be_bytes();
    for i in 0..4 {
        core::ptr::write_volatile(out_ptr.add(i), si_bytes[i]);
    }
    core::ptr::write_volatile(out_ptr.add(4), next_q);
    core::ptr::write_volatile(out_ptr.add(5), remaining);
    core::ptr::write_volatile(out_ptr.add(6), active);

    NscStatus::Ok as u32
}
```

---

## 4. Automatic Key Rotation — How It Works

### 4.1 Lifecycle

```
DEPLOY
  → register slot 0 (CMD_REGISTER_JARDIN_SLOT → companion submits Type 1 UserOp)
  → compact sign q=1..95 (CMD_SIGN_JARDIN)
  → slot exhausted (NscStatus::SlotExhausted returned at q=96)
  → register slot 1 (CMD_REGISTER_JARDIN_SLOT with slot_index=1)
  → compact sign q=1..95
  → repeat
```

### 4.2 Current State of Rotation Logic

**What's already wired:**

- `JardinSlot::is_exhausted()` returns true when `next_q > Q_MAX` — `sign_and_emit.rs:359`
- `NscStatus::SlotExhausted = 8` — returned when slot is full — `sign_and_emit.rs:360`
- Slot reinitialization on `(chain_id, slot_index)` change — `sign_and_emit.rs:330-348`
- Zeroize on lock/panic/idle — `state.rs:94-112`

**What's NOT wired:**

1. **Proactive precomputation** — When `slot.remaining() < 15`, the firmware should begin keygen for the next slot in the background. BUT: there is no background threading on bare-metal Cortex-M33. The realistic approach is:
   - On the first `CMD_SIGN_JARDIN` call where `remaining() < 15`, the response includes a "rotation soon" flag that the companion can read.
   - The companion calls `CMD_REGISTER_JARDIN_SLOT` to get the next slot's parameters before the current slot runs out.
   - No actual background work in firmware — the companion manages the lifecycle.

2. **Companion-side orchestration** — The companion app (USB host / mobile app) needs to:
   - Track the current `slot_index` per chain
   - Poll `CMD_GET_JARDIN_SLOT_INFO` or check the response from `CMD_SIGN_JARDIN`
   - When `remaining < 15`: call `CMD_REGISTER_JARDIN_SLOT`, build a Type 1 UserOp, submit to EntryPoint
   - When `remaining == 0`: switch to `slot_index + 1` for subsequent `CMD_SIGN_JARDIN` calls

3. **The USB APDU v2 protocol entries** — `INS_V2_SIGN_JARDIN`, `INS_V2_REGISTER_JARDIN_SLOT`, `INS_V2_GET_JARDIN_SLOT_INFO` in `shared/src/lib.rs` and the NS-side APDU handler.

### 4.3 Recovery After Power Loss

Session state (JARDÍN slot, q counter) is lost on power cycle. Recovery:

1. Companion queries on-chain `jardinSlots` mapping to find the latest registered slot index
2. Companion CANNOT determine current q from on-chain state (q is not tracked on-chain)
3. **Safe approach:** Register a fresh slot with `slot_index = latest + 1`, start from q=1
4. **Emergency fallback:** Use C11 `SIGNER_MAIN` directly (always works, no slot needed)

The key derivation is deterministic, so the same 24 words + slot_index always reproduce the same slot. If the companion knows the slot_index, it can re-derive `slot_key` and `sub_vk_hash` to verify which slots are registered on-chain.

---

## 5. Integration Points — Exact File Locations

### 5.1 Files to Create

| File | Lines (est.) | Complexity |
|------|-------------|------------|
| `secure/src/nsc/cmd_sign_jardin.rs` | ~60 | Low — thin wrapper around `decrypt_and_sign_jardin` |
| `secure/src/nsc/cmd_register_jardin_slot.rs` | ~80 | Medium — derives slot params, returns to companion |
| `secure/src/nsc/cmd_get_jardin_slot_info.rs` | ~50 | Low — pure query, reads state |

### 5.2 Files to Modify

| File | Change | Lines to touch |
|------|--------|----------------|
| `secure/src/nsc/mod.rs` | Add 3 `mod` declarations (after line 63), 3 CMD imports (line 70-75), 3 match arms (line 201), 3 CMSE veneers (after line 351) | ~25 lines |
| `nonsecure/src/e2e_test.rs` | Add JARDÍN E2E test entries | ~50 lines |

### 5.3 Files That Are Already Done (no more changes needed)

- `jardin-fosc/` — entire crate
- `shared/src/lib.rs` — all constants
- `secure/src/crypto.rs` — key derivation
- `secure/src/nsc/state.rs` — state fields + JARDIN_SLOT static
- `secure/src/nsc/sign_and_emit.rs` — `decrypt_and_sign_jardin()`
- `secure/Cargo.toml` — dependency
- Root `Cargo.toml` — workspace config
- All Solidity contracts and tests

---

## 6. Existing Patterns to Follow

### 6.1 Gateway Handler Pattern

Every `cmd_*.rs` follows this skeleton:

```rust
pub(super) unsafe fn run(args: &GatewayArgs) -> u32 {
    // 1. UI status
    crate::ui::show_status("CMD_NAME", "validating...");

    // 2. Check unlock
    if !super::state::peek_state(|s| s.pin_verified) {
        return NscStatus::NotInitialized as u32;
    }

    // 3. Parse args from GatewayArgs
    let payload_ptr = args.arg0 as *const u8;
    let out_ptr = args.arg1 as *mut u8;
    let total_len = args.arg2 as usize;

    // 4. Length + pointer validation
    if total_len < MIN { return NscStatus::InvalidPointer as u32; }
    if !validate_ns_read_ptr(args.arg0, total_len) { ... }
    if !validate_ns_write_ptr(args.arg1, out_size) { ... }

    // 5. TOCTOU snapshot (volatile read NS → secure stack)
    let mut buf = [0u8; MAX_PAYLOAD];
    for i in 0..total_len {
        buf[i] = core::ptr::read_volatile(payload_ptr.add(i));
    }

    // 6. Parse from snapshot
    let field = u64::from_be_bytes([buf[0], ..., buf[7]]);

    // 7. (Optional) UI confirmation
    let result = crate::ui::confirm(&pages);
    match result { Confirmed => {}, Cancelled => return UserRejected, IdleWipe => ... }

    // 8. Crypto operation (via sign_and_emit or direct)

    // 9. Write result (volatile writes to NS)
    for i in 0..result.len() {
        core::ptr::write_volatile(out_ptr.add(i), result[i]);
    }

    // 10. Return status
    NscStatus::Ok as u32
}
```

### 6.2 GatewayArgs

```rust
pub(super) struct GatewayArgs {
    pub(super) arg0: u32,  // typically: payload pointer (cast to *const u8)
    pub(super) arg1: u32,  // typically: output pointer (cast to *mut u8)
    pub(super) arg2: u32,  // typically: total_len or flags|len
}
```

### 6.3 State Access

```rust
// Read-only
super::state::peek_state(|s| s.pin_verified)
super::state::peek_state(|s| s.jardin_slot_active)

// Mutation
super::state::with_state(|s| {
    s.jardin_chain_id = chain_id;
    s.jardin_slot_index = slot_index;
})

// JARDIN_SLOT (separate static, not in SecureState)
unsafe {
    let slot = &mut *core::ptr::addr_of_mut!(super::state::JARDIN_SLOT);
    // slot is Option<jardin_fosc::JardinSlot>
}
```

### 6.4 Pointer Validation

```rust
use super::ptr_validate::{validate_ns_read_ptr, validate_ns_write_ptr};

// Returns false if: null, overflow, outside NS SRAM/flash, overlaps mailbox
validate_ns_read_ptr(ptr_u32, byte_count) -> bool
validate_ns_write_ptr(ptr_u32, byte_count) -> bool   // SRAM only for writes
```

### 6.5 Volatile I/O

```rust
// Read from NS (TOCTOU-safe)
buf[i] = core::ptr::read_volatile(ns_ptr.add(i));

// Write to NS
core::ptr::write_volatile(ns_ptr.add(i), byte);
```

---

## 7. Security Invariants

1. **No JARDÍN secret ever leaves secure world.** `sk_seed`, `master_entropy`, and `fors_secrets` live only in S-SRAM. Only public values (`pk_seed`, `pk_root`, `slot_key`, `sub_vk_hash`) and signatures cross to NS.

2. **Slot key `H(r)` is one-way.** The randomizer `r` is derived from master entropy and never sent to NS. Only `H(r) = keccak256(r)` is exposed (as the slot key). This prevents an attacker from computing the sub-key pair from the slot key.

3. **Zeroize on lock/panic/idle.** `state.rs:zeroize_sensitive()` clears `jardin_master_entropy`, drops `JARDIN_SLOT`, and resets all JARDÍN state flags. Called from the panic handler, idle-wipe timer, and lock command.

4. **No on-chain q counter.** JARDÍN's security is 128 bits per unique q. The protocol tolerates accidental double-signing of the same q (105 bits). This is intentional — it eliminates SSTORE gas on every compact signature.

5. **Domain separation.** All JARDÍN hash calls use distinct tags (`"jfors"`, `"jardin_sentinel"`, `"jardin_sub_v1"`, `"jardin_pk_seed"`, `"jardin_sk_seed"`, `"jardin_R"`, `"jardin_slot"`, `"jardin_r"`, `"pqwallet-jardin-master"`). None collide with C11 tags.

6. **Deterministic derivation.** Same 24 words + slot_index always produces the same slot. This is the recovery contract.

---

## 8. Testing Strategy for E2E

### 8.1 QEMU E2E Test Cases

Add to `nonsecure/src/e2e_test.rs`:

1. **Basic JARDÍN sign** — Unlock → CMD_SIGN_JARDIN(chain=1, slot=0, hash) → verify response has SIGNER_JARDIN header + valid-length sig
2. **Sequential signing** — Sign 3 times, verify q increments (sig lengths: 2468, 2484, 2500)
3. **Slot info query** — CMD_GET_JARDIN_SLOT_INFO → verify next_q, remaining, active
4. **Slot exhaustion** — Sign 95 times → verify 96th returns SlotExhausted
5. **Slot switch** — Sign with slot_index=0, then slot_index=1 → verify new keygen occurs
6. **Register slot params** — CMD_REGISTER_JARDIN_SLOT → verify slot_key and sub_vk_hash are deterministic
7. **Zeroize on lock** — Sign → lock → unlock → verify slot is gone (slot_active=false)

### 8.2 Cross-Compilation Check

```bash
# The secure crate requires thumbv8m.main-none-eabi
make run  # or make e2e for full E2E in QEMU
```

### 8.3 Stack Usage

JARDÍN keygen builds 95×26 FORS trees. Each tree uses `[[u8; 32]; 32]` = 1 KB stack for leaves + 192 bytes for treehash. The `build_fors_tree` function uses iterative treehash with O(A) = O(5) stack, so actual per-tree stack is ~256 bytes. The `keygen` function builds trees one at a time (not all simultaneously), so peak stack is dominated by one `sign_fors_tree` call (~1.2 KB for the nodes array) plus the `JardinSlot` itself (~3.1 KB, but that's in the static `JARDIN_SLOT`, not on the stack). Target: <8 KB total stack for the keygen path.

---

## 9. Signature Wire Format Summary

### On-chain PQSignatureWrapper (ABI-encoded, Solidity struct):

```solidity
struct PQSignatureWrapper {
    SignerType signerType;   // 0=MAIN, 1=BOOTSTRAP, 2=JARDIN
    uint32 keyIndex;         // C11 only (0 for JARDÍN)
    uint32 otsIndex;         // C11 only (0 for JARDÍN)
    bytes32 pkSeed;          // C11: main/boot pkSeed; JARDÍN: subPkSeed
    bytes32 pkRoot;          // C11: main/boot pkRoot; JARDÍN: subPkRoot
    bytes32 slotKey;         // JARDÍN only: H(r); zero for C11
    bytes signature;         // C11: 3976B; JARDÍN: 2468..3972B
}
```

### Firmware wrapper (binary, NOT ABI-encoded):

```
[0]         signer_type   u8
[1..33)     slot_key      32 bytes (JARDÍN) or key_index+ots_index+padding (C11)
[33..65)    subPkSeed     32 bytes
[65..97)    subPkRoot     32 bytes
[97..)      raw signature (variable length)
```

The companion must ABI-encode this into the Solidity struct format before submitting to the EntryPoint.

---

## 10. Gas Comparison

| Path | Sig size | Verify gas | Calldata gas (@16/byte) | Total per-tx |
|------|----------|-----------|------------------------|-------------|
| C11 MAIN (current) | 3,976 B | ~116K | ~64K | ~180K |
| JARDÍN q=1 | 2,468 B | ~62K | ~39K | ~101K + amortized slot reg |
| JARDÍN q=50 | 3,252 B | ~75K | ~52K | ~127K + amortized slot reg |
| JARDÍN q=95 | 3,972 B | ~89K (est.) | ~64K | ~153K + amortized slot reg |
| Slot registration | 3,976 B (C11) | ~116K | ~64K + ~45K SSTORE | ~225K (once per 95 txs) |

Amortized slot registration cost per tx: ~225K / 95 = ~2.4K gas.

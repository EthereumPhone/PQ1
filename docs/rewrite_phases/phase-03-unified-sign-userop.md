# Phase 3 — Unified `cmd_sign_userop.rs` (Type 1 / Type 2 state machine)

**Status:** not started.
**Depends on:** phase 1 (flash persistence), phase 2 (C11 derivation).
**Blocks:** phase 4 (USB + webhid need the new payload format).

This is the heart of the refactor. Everything else supports this.

## Why this phase exists

The master plan requires: user clicks "Sign", firmware transparently handles
slot registration (Type 1) when needed + signs the user's tx (Type 2), all in
one command. The user should never see "your slot is exhausted, register a
new one" — that's the firmware's job.

Today, `cmd_sign_userop.rs` signs UserOps with **SLH-DSA** (the old main
signer) and `cmd_sign_jardin.rs` / `cmd_register_jardin_slot.rs` exist as
separate commands. We're collapsing them into one unified command that
emits a bundled response the companion can submit to the bundler.

## Output contract (the companion will consume this)

```
[type1_len(4, BE)][type1_bytes...][type2_len(4, BE)][type2_bytes...]
```

- If `type1_len == 0`, no Type 1 needed (slot already registered, q within
  bounds).
- If `type1_len > 0`, the companion submits Type 1 first (slot
  registration), waits for confirmation, then submits Type 2.
- `type2_len` is always > 0 (every sign request produces a user-tx signature).

Type 1 payload (frozen, matches on-chain verifier):
```
[0x01][r(32)][subPkSeed(16)][subPkRoot(16)][C11_sig(3976)]
= 1 + 32 + 16 + 16 + 3976 = 4041 bytes
```

Type 2 payload (frozen, matches on-chain verifier):
```
[0x02][H(r)(32)][subPkSeed(16)][subPkRoot(16)][FORS+C_sig(2452 + q·16)]
= 1 + 32 + 16 + 16 + 2452 + q·16
q=1:  2517 bytes
q=95: 4037 bytes
```

Max response size: `4 + 4041 + 4 + 4037 = 8086 bytes`. Update
`MAX_JARDIN_RESPONSE_LEN` in `shared/src/lib.rs` accordingly.

## State machine

```
                  ┌─────────────────────────────┐
                  │ read slot state from flash  │ (nsc::jardin_flash::read_latest)
                  └─────────────┬───────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼                       ▼                       ▼
  no record yet          record exists,           record exists,
  OR                     registered,              registered,
  registered=false       next_q <= 95             next_q > 95
  OR                                              (rotation needed)
  chain_id mismatch
        │                       │                       │
        ▼                       ▼                       ▼
  (first sign)           (normal fast path)      (rotation)
  keygen slot_index=0    no keygen needed        keygen slot_index+1
  Type 1 + Type 2        Type 2 only             Type 1 + Type 2
  type1_len = 4041       type1_len = 0           type1_len = 4041
                         type2 uses cached       (new slot, q=1)
                         slot (rebuild from
                         master if not in RAM)
```

## Input payload format

The companion sends a UserOp bundle that will be used to compute userOpHash.
Design the payload to be minimal and reuse existing parsing where possible.

Proposal (matches SPHINCs-'s `PackedUserOperation` where feasible):

```
offset  size  field
---------------------------------------------------------
  0     8    chain_id (u64 BE)
  8     4    slot_index hint (u32 BE) — usually 0, firmware may override on rotation
 12    20    sender address (zeroed if undeployed, firmware computes from factory)
 32    32    nonce (u256 BE, EntryPoint nonce)
 64    32    call_gas_limit
 96    32    verification_gas_limit
128    32    pre_verification_gas
160    32    max_fee_per_gas
192    32    max_priority_fee_per_gas
224    32    paymaster_and_data_hash (keccak256 of paymasterAndData, or KECCAK_EMPTY)
256    20    to_address (inner tx recipient)
276    32    value (inner tx value, u256 BE)
308     2    data_len (u16 BE)
310     N    data (inner tx calldata)
...          (trailing padding to align if needed)
```

Firmware computes `userOpHash` internally by:
1. Reconstructing `execute(to, value, data)` callData (already have
   `crate::aa::userop::reconstruct_execute_calldata`).
2. Computing EntryPoint v0.6 (or v0.9 if matching SPHINCs-) userOpHash via
   `crate::aa::userop::compute_user_op_hash`.

**Important**: SPHINCs- uses EntryPoint v0.9; current `aa::userop` uses
v0.6. Verify which one the on-chain contract expects and align. SPHINCs-'s
`script/jardin_userop.py` has the reference.

## Files to modify

| File | Action |
|---|---|
| `secure/src/nsc/cmd_sign_userop.rs` | **Rewrite** (see implementation below) |
| `secure/src/nsc/mod.rs` | Remove all non-JARDÍN CMD arms (done in phase 6); for now, keep JARDÍN-relevant ones |
| `secure/src/nsc/state.rs` | Drop `last_chain_id/last_key_index/last_ots_index/has_signed`; `next_q` now lives in flash, not RAM |
| `secure/src/crypto.rs` | Expose `derive_c11_master_from_bip39_seed` (phase 2) + a helper `c11_sign(sk_seed, pk_seed, pk_root, msg) -> [u8; 3976]` via `sphincs-c7` |
| `secure/src/aa/userop.rs` | Verify EntryPoint version alignment; may need v0.9 variant |
| `shared/src/lib.rs` | Update `MAX_JARDIN_RESPONSE_LEN`, add Type 1 / Type 2 length constants |
| `nonsecure/src/e2e_test.rs` | Add JARDÍN test scenario: first sign (Type 1 + Type 2), second sign (Type 2 only), rotation at q=95 |

## Implementation sketch

```rust
//! cmd_sign_userop.rs — unified JARDÍN Type 1 + Type 2 dispatch.

use sphincs_tz_shared::{NscStatus, JARDIN_SIG_MIN, C11_SIG_LEN /* new */};
use crate::nsc::jardin_flash::{self, SlotState, FLAG_SLOT_REGISTERED};
use jardin_fosc::{JardinSlot, params::Q_MAX};

const TYPE1_PAYLOAD_LEN: usize = 1 + 32 + 16 + 16 + 3976; // 4041
const TYPE1_MARKER: u8 = 0x01;
const TYPE2_MARKER: u8 = 0x02;

pub(super) unsafe fn run(args: &GatewayArgs) -> u32 {
    // 1. Validate unlock, validate pointers, TOCTOU-snapshot input into SRAM.
    if !super::state::peek_state(|s| s.pin_verified) {
        ui::show_status("Sign", "not unlocked");
        return NscStatus::NotInitialized as u32;
    }
    // ... validate_ns_read_ptr, validate_ns_write_ptr, copy into SNAP_BUF ...

    // 2. Parse input: chain_id, slot_index_hint, AA fields, inner tx.
    let chain_id = u64::from_be_bytes(...);
    let slot_index_hint = u32::from_be_bytes(...);
    // ... parse rest ...

    // 3. Check flash for existing slot state.
    let existing = jardin_flash::read_latest();

    // 4. Decide mode.
    let mode = match &existing {
        Some(s) if s.chain_id == chain_id
            && s.is_registered()
            && s.next_q <= Q_MAX as u32 => Mode::Normal(s.clone()),
        Some(s) if s.chain_id == chain_id
            && s.is_registered()
            && s.next_q > Q_MAX as u32 => Mode::Rotate { from: s.clone() },
        _ => Mode::FirstSign,
    };

    // 5. Reconstruct entropy from SE (uses existing unlock_master flow).
    let entropy = reconstruct_entropy_from_dual_se(&master_secret)?;

    // 6. Derive JARDÍN master entropy (existing helper).
    let jardin_master = crypto::jardin_master_entropy_from_entropy(&entropy);

    // 7. Compute userOpHash over user's inner tx.
    let exec_calldata = aa::userop::reconstruct_execute_calldata(&parsed_tx, inner_data)?;
    let user_op_hash = aa::userop::compute_user_op_hash(&aa_params, &keccak256(&exec_calldata));

    // 8. Initialize slot + produce Type 1 if needed.
    let (slot, type1_bytes, type2_h_r, new_slot_index) = match mode {
        Mode::FirstSign | Mode::Rotate { .. } => {
            let new_slot_index = match &mode {
                Mode::FirstSign => 0,
                Mode::Rotate { from } => from.slot_index + 1,
                _ => unreachable!(),
            };
            ui::show_progress("Registering slot", 0);

            // Keygen new slot
            let slot_entropy = jardin_fosc::hash::jardin_slot_entropy(&jardin_master, new_slot_index);
            let slot = JardinSlot::keygen_with_progress(slot_entropy, keygen_progress);

            // r = deterministic, matches SPHINCs- (see jardin-fosc hash.rs::jardin_slot_r or similar)
            let r = jardin_fosc::hash::jardin_slot_r(&jardin_master, new_slot_index);
            let h_r = keccak256(&r);

            // Derive C11 master (phase 2).
            let (c11_pk_seed, c11_sk_seed) = crypto::derive_c11_master_from_bip39_seed(&bip39_seed);
            // C11 root (needs sphincs-c7 API call; may need new helper).
            let c11_pk_root = sphincs_c7::derive_root(&c11_pk_seed, &c11_sk_seed);

            // Registration userOpHash: this is SEPARATE from the user's userOpHash.
            // It's over a UserOp whose callData is `registerJardinSlot(h_r, sub_vk_hash)`.
            let sub_vk_hash = keccak256(&[slot.pk_seed[..16], slot.pk_root[..16]].concat());
            let reg_calldata = abi_encode_register_slot(h_r, sub_vk_hash);
            let reg_user_op_hash = compute_registration_user_op_hash(chain_id, &reg_calldata, ...);

            // C11 sign with master key over reg_user_op_hash.
            let c11_sig = crypto::c11_sign(&c11_sk_seed, &c11_pk_seed, &c11_pk_root, &reg_user_op_hash);

            // Assemble Type 1.
            let mut type1 = [0u8; TYPE1_PAYLOAD_LEN];
            type1[0] = TYPE1_MARKER;
            type1[1..33].copy_from_slice(&r);
            type1[33..49].copy_from_slice(&slot.pk_seed[..16]);
            type1[49..65].copy_from_slice(&slot.pk_root[..16]);
            type1[65..4041].copy_from_slice(&c11_sig);

            // Verify before release (fault-injection guard).
            // c11_verify(&c11_pk_seed, &c11_pk_root, &reg_user_op_hash, &c11_sig)?;

            (slot, Some(type1), h_r, new_slot_index)
        }
        Mode::Normal(s) => {
            // Slot is already registered. We still need to rebuild the slot
            // in memory to sign (keygen on unlock, cache in SecureState).
            let slot_entropy = jardin_fosc::hash::jardin_slot_entropy(&jardin_master, s.slot_index);
            let slot = JardinSlot::keygen_with_progress(slot_entropy, keygen_progress);
            // Fast-forward next_q to the flash-stored value.
            slot.next_q = s.next_q;
            (slot, None, s.h_r, s.slot_index)
        }
    };

    // 9. Sign user's userOpHash (Type 2).
    let q_used = slot.next_q;
    let fors_sig = slot.sign(&user_op_hash)?;
    // Verify-before-release.
    // jardin_fosc::verify(&slot.pk_seed, &slot.pk_root, &user_op_hash, &fors_sig.data[..fors_sig.len])?;

    // 10. Persist state BEFORE releasing Type 2 bytes to NS.
    let new_state = SlotState {
        seq: 0, // write() ignores
        chain_id,
        slot_index: new_slot_index,
        next_q: q_used + 1,
        flags: FLAG_SLOT_REGISTERED,
        h_r: type2_h_r,
        sub_pk_seed: slot.pk_seed[..16].try_into().unwrap(),
        sub_pk_root: slot.pk_root[..16].try_into().unwrap(),
    };
    jardin_flash::write(&new_state).map_err(|_| NscStatus::InternalError as u32)?;

    // 11. Assemble Type 2.
    let type2_len = 1 + 32 + 16 + 16 + fors_sig.len;
    let mut type2 = [0u8; JARDIN_SIG_MAX_WRAPPED];
    type2[0] = TYPE2_MARKER;
    type2[1..33].copy_from_slice(&type2_h_r);
    type2[33..49].copy_from_slice(&slot.pk_seed[..16]);
    type2[49..65].copy_from_slice(&slot.pk_root[..16]);
    type2[65..65 + fors_sig.len].copy_from_slice(&fors_sig.data[..fors_sig.len]);

    // 12. Write bundle to NS output.
    let mut out_offset = 0;
    write_u32_be(out_ptr, out_offset, type1_bytes.map_or(0, |_| TYPE1_PAYLOAD_LEN as u32));
    out_offset += 4;
    if let Some(t1) = type1_bytes {
        write_bytes(out_ptr, out_offset, &t1);
        out_offset += TYPE1_PAYLOAD_LEN;
    }
    write_u32_be(out_ptr, out_offset, type2_len as u32);
    out_offset += 4;
    write_bytes(out_ptr, out_offset, &type2[..type2_len]);
    out_offset += type2_len;

    // 13. Zeroize.
    entropy.zeroize();
    slot.zeroize();

    NscStatus::Ok as u32
}

enum Mode {
    FirstSign,
    Normal(SlotState),
    Rotate { from: SlotState },
}
```

## Frozen invariants

- `next_q` is persisted to flash **before** the Type 2 signature bytes are
  released to NS. Rollback attack defense: an attacker who power-cycles the
  device after seeing the signature but before flash write could otherwise
  cause q reuse.
- Verify every signature (both C11 Type 1 and FORS+C Type 2) locally before
  release. This is the standard fault-injection guard.
- Wipe entropy, slot secrets, intermediate buffers before return — use
  `zeroize` on every secret-bearing local.
- Type 1 is produced from a freshly keygen'd slot. **Never replay a
  previous Type 1** — the `r` value must be unique per slot_index, so it's
  derived from master_entropy + slot_index (deterministic, not random).
- Signing a message with q that's already been used on-chain is catastrophic
  for JARDÍN (security drops from 128 → ~105 bits at q=2, lower with more
  reuse). The flash-before-release ordering + the "strictly greater seq"
  check protects against this.

## EntryPoint version

Verify which EntryPoint version the ported contract targets. Look at:

```
grep -n "EntryPoint\|ENTRYPOINT\|0x4337" /home/markus/Documents/SPHINCs-/src/JardinAccount.sol
grep -n "EntryPoint\|ENTRYPOINT\|0x4337" /home/markus/Documents/SPHINCs-/script/jardin_userop.py
```

SPHINCs- appears to use EntryPoint v0.9 (address `0x4337...D009`); current
repo uses v0.6. Either port v0.9 hashing logic to `aa/userop.rs` or pin the
new contract to v0.6. Pick one and document it.

## Verification

1. Firmware builds clean on thumbv8m.
2. `make e2e` runs: verify the new test scenario passes (first sign → Type
   1+Type 2 bundle, second sign → Type 2 only, 95+ signs → rotation triggers
   automatically).
3. Host vectors: the Type 1 C11 sig for a fixed mnemonic + fixed registration
   hash should be byte-for-byte reproducible. Generate via SPHINCs-'s signer
   if possible and assert equality.
4. Cross-check with phase 5's on-chain `JardinWalletE2E.t.sol`: the firmware's
   Type 1 + Type 2 output should validate under the new `PQJardinWallet`
   contract in a Foundry simulation.

## What NOT to do

- **Don't skip flash persistence** "just for this sign" — every signature
  increments next_q and every increment must be persisted before release.
- **Don't derive the C11 keypair on every sign if it's only needed for
  Type 1.** Check `mode` first; Type 2-only signs skip C11 entirely. C11
  derivation involves HMAC-SHA512 + hypertree root computation (~3s on
  Cortex-M33) so skipping saves meaningful UX time.
- **Don't zeroize the `slot` before writing to flash** — you need
  `slot.next_q` after sign, and the pk_seed/pk_root for the flash record.
  Zeroize AFTER the flash write succeeds.
- **Don't expose a `CMD_REGISTER_JARDIN_SLOT`** as a separate command. The
  whole point of this phase is that registration is implicit, triggered by
  the unified sign command.

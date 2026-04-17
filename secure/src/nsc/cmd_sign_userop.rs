//! CMD_SIGN_USEROP — unified JARDÍN Type 1 / Type 2 sign command.
//!
//! Post-cutover every signing primitive in the wallet is SPHINCS+C10:
//!
//!   * **Type 1** (slot registration) — bootstrap C10 key signs a UserOp
//!     whose callData is a no-op `execute(sender, 0, "")`. The signature
//!     bundle carries the newly-derived slot C10 `(pk_seed, pk_root)` so
//!     `PQJardinWallet` can record `slots[sha256(r)] = sha256(pk_seed ||
//!     pk_root)` and bump `bootstrapUses`.
//!   * **Type 2** (user tx) — the slot C10 key signs the user's
//!     `execute(to, value, data)` UserOp. The on-chain wallet looks up
//!     the slot, verifies the C10 sig, and bumps `slotUses` against
//!     `MAX_SLOT_USES`.
//!
//! **Firmware is stateless** for slot selection. The non-secure companion
//! drives `(chain_id, slot_index, flags)` via the flags field:
//!
//!   * bit 31 (`FLAG_INCLUDE_INIT_CODE`) — first deploy, emit factory
//!     initCode so the first UserOp can bootstrap the wallet contract.
//!   * bit 30 (`FLAG_REGISTER_SLOT`) — emit a Type 1 ahead of Type 2,
//!     registering this `(chain_id, slot_index)` on-chain.
//!   * bits 29..0 (`SLOT_INDEX_MASK`) — authoritative slot index.
//!
//! There is no flash store, no `next_q`, no mode state machine. Slot keys
//! are derived deterministically from `(master_entropy, slot_index)` and
//! cached in SRAM across the unlock session; a cache miss on a different
//! `slot_index` triggers a fresh C10 keygen (~5-6 s on hardware).
//!
//! Every signature is verified locally before being written to NS
//! (fault-injection guard, double-evaluated).

use sha2::{Digest, Sha256};
use sphincs_tz_shared::{
    NscStatus, C10_SIG_LEN, FLAG_INCLUDE_INIT_CODE, FLAG_REGISTER_SLOT,
    JARDIN_CREATE_ACCOUNT_SELECTOR, JARDIN_INIT_CODE_LEN, JARDIN_TYPE1_LEN,
    JARDIN_TYPE1_MARKER, JARDIN_TYPE2_LEN, JARDIN_TYPE2_MARKER, MAX_JARDIN_RESPONSE_LEN,
    MAX_TX_LEN, PQ_JARDIN_WALLET_FACTORY, SIGN_USEROP_HEADER_LEN, SLOT_INDEX_MASK,
    ZK_CLEAR_SIGN_FIXED_LEN, ZK_MAX_CALLDATA, ZK_PROOF_LEN, ZK_STRING_LEN,
    ZK_VK_BUNDLE_MAX_LEN,
};
use zeroize::{Zeroize, Zeroizing};

#[inline]
fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

use super::ptr_validate::{validate_ns_read_ptr, validate_ns_write_ptr};
use super::state::CachedSlot;
use super::GatewayArgs;
use crate::aa::userop::{
    compute_user_op_hash_v09, reconstruct_execute_calldata, AaUserOpParamsV09, KECCAK_EMPTY,
};
use crate::erc20::bundle::{verify_erc20_bundle, Erc20Metadata, MAX_ERC20_BUNDLE_LEN};
use crate::erc20::calldata::{parse_erc20_calldata, Erc20Call};
use crate::tx::display::{
    render_blind_sign_pages, render_erc20_known_pages, render_erc20_unknown_pages, render_pages,
};
use crate::tx::eip1559::{Eip1559Tx, U256};
use crate::tx::hash::keccak256;
use crate::ui;

/// Reserve enough room to TOCTOU-snapshot the largest valid input the
/// gateway will accept.
const SNAP_LEN: usize = SIGN_USEROP_HEADER_LEN
    + MAX_TX_LEN
    + 2 + MAX_ERC20_BUNDLE_LEN
    + 2 + ZK_CLEAR_SIGN_FIXED_LEN + ZK_VK_BUNDLE_MAX_LEN;

pub(super) unsafe fn run(args: &GatewayArgs) -> u32 {
    use crate::ui::confirm::{confirm, ConfirmResult};

    // HIGH-7 fix: mark the handler as busy so SysTick's background
    // idle-wipe path cannot zero out `master_secret` while we still
    // hold a stack-local copy of it. Dropped on scope exit.
    let _busy = super::HandlerGuard::enter();

    ui::show_status("Sign", "validating...");

    // ── 1. Unlock check ─────────────────────────────────────────────
    if !super::state::peek_state(|s| s.pin_verified) {
        ui::show_status("Sign", "not unlocked");
        return NscStatus::NotInitialized as u32;
    }

    // ── 2. Pointer + length validation ───────────────────────────────
    let payload_ptr = args.arg0 as *const u8;
    let out_ptr = args.arg1 as *mut u8;
    let total_len = args.arg2 as usize;

    if total_len < SIGN_USEROP_HEADER_LEN || total_len > SNAP_LEN {
        ui::show_status("Sign", "bad length");
        return NscStatus::InvalidPointer as u32;
    }
    if !validate_ns_read_ptr(args.arg0, total_len) {
        ui::show_status("Sign", "bad ptr");
        return NscStatus::InvalidPointer as u32;
    }
    if !validate_ns_write_ptr(args.arg1, MAX_JARDIN_RESPONSE_LEN) {
        ui::show_status("Sign", "bad out");
        return NscStatus::InvalidPointer as u32;
    }

    // ── 3. TOCTOU snapshot ──────────────────────────────────────────
    //
    // M1 fix: wipe any leftover payload from the PREVIOUS sign before
    // we fill it with this request.
    static mut SNAP_BUF: [u8; SNAP_LEN] = [0u8; SNAP_LEN];
    {
        let buf = &mut *core::ptr::addr_of_mut!(SNAP_BUF);
        for b in buf.iter_mut() {
            *b = 0;
        }
    }
    let snap = &mut SNAP_BUF[..total_len];
    for i in 0..total_len {
        snap[i] = core::ptr::read_volatile(payload_ptr.add(i));
    }

    // ── 4. Parse header (big-endian, fixed offsets) ────────────────
    let chain_id = u64::from_be_bytes([
        snap[0], snap[1], snap[2], snap[3], snap[4], snap[5], snap[6], snap[7],
    ]);
    let flags = u32::from_be_bytes([snap[8], snap[9], snap[10], snap[11]]);
    let include_init_code = (flags & FLAG_INCLUDE_INIT_CODE) != 0;
    let register_slot = (flags & FLAG_REGISTER_SLOT) != 0;
    let slot_index = flags & SLOT_INDEX_MASK;
    let mut sender = [0u8; 20];
    sender.copy_from_slice(&snap[12..32]);
    let mut entry_point = [0u8; 20];
    entry_point.copy_from_slice(&snap[32..52]);
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&snap[52..84]);
    let mut account_gas_limits = [0u8; 32];
    account_gas_limits.copy_from_slice(&snap[84..116]);
    let mut pre_verification_gas = [0u8; 32];
    pre_verification_gas.copy_from_slice(&snap[116..148]);
    let mut gas_fees = [0u8; 32];
    gas_fees.copy_from_slice(&snap[148..180]);
    let mut paymaster_and_data_hash = [0u8; 32];
    paymaster_and_data_hash.copy_from_slice(&snap[180..212]);
    let mut to_address = [0u8; 20];
    to_address.copy_from_slice(&snap[212..232]);
    let mut value = [0u8; 32];
    value.copy_from_slice(&snap[232..264]);
    let data_len = u16::from_be_bytes([snap[264], snap[265]]) as usize;

    if data_len > MAX_TX_LEN || SIGN_USEROP_HEADER_LEN + data_len > total_len {
        ui::show_status("Sign", "bad data_len");
        return NscStatus::InvalidPointer as u32;
    }

    // initCode only rides a Type 1 frame; reject the inconsistent combo.
    if include_init_code && !register_slot {
        ui::show_status("Sign", "init_code w/o type1");
        return NscStatus::InvalidPointer as u32;
    }

    // CRIT-17: refuse nonce-seq overflow. v0.9 nonces are 192-bit key | 64-bit seq.
    // When Type 1 is present, Type 2 nonce = base + 1 — overflowing the seq
    // would carry into the key field and silently change the nonce key.
    if register_slot && nonce[24..32] == [0xFFu8; 8] {
        ui::show_status("Nonce seq", "overflow");
        return NscStatus::InvalidPointer as u32;
    }

    let inner_data: &[u8] =
        &snap[SIGN_USEROP_HEADER_LEN..SIGN_USEROP_HEADER_LEN + data_len];

    // ── 4b. Optional trailer: ERC-20 + ZK bundles ─────────────────────
    let mut cursor = SIGN_USEROP_HEADER_LEN + data_len;

    let erc20_bundle_len = if cursor + 2 <= total_len {
        let l = u16::from_be_bytes([snap[cursor], snap[cursor + 1]]) as usize;
        cursor += 2;
        l
    } else {
        0
    };
    if erc20_bundle_len > MAX_ERC20_BUNDLE_LEN || cursor + erc20_bundle_len > total_len {
        ui::show_status("Sign", "bad erc20 bundle");
        return NscStatus::InvalidPointer as u32;
    }
    let erc20_bundle_start = cursor;
    cursor += erc20_bundle_len;

    let zk_bundle_len = if cursor + 2 <= total_len {
        let l = u16::from_be_bytes([snap[cursor], snap[cursor + 1]]) as usize;
        cursor += 2;
        l
    } else {
        0
    };
    if zk_bundle_len > ZK_CLEAR_SIGN_FIXED_LEN + ZK_VK_BUNDLE_MAX_LEN
        || cursor + zk_bundle_len > total_len
    {
        ui::show_status("Sign", "bad zk bundle");
        return NscStatus::InvalidPointer as u32;
    }
    let zk_bundle_start = cursor;
    cursor += zk_bundle_len;

    if cursor != total_len {
        ui::show_status("Sign", "trailing bytes");
        return NscStatus::InvalidPointer as u32;
    }

    // ── 5. Build display-time Eip1559Tx shim ───────────────────────
    let display_nonce = u64::from_be_bytes([
        nonce[24], nonce[25], nonce[26], nonce[27],
        nonce[28], nonce[29], nonce[30], nonce[31],
    ]);
    let display_max_fee = {
        let mut v = [0u8; 32];
        v[16..32].copy_from_slice(&gas_fees[16..32]);
        U256(v)
    };
    let display_max_prio = {
        let mut v = [0u8; 32];
        v[16..32].copy_from_slice(&gas_fees[0..16]);
        U256(v)
    };
    let ver_gas_u128 = u128_from_be_16(&account_gas_limits[0..16]);
    let call_gas_u128 = u128_from_be_16(&account_gas_limits[16..32]);
    let pre_ver_u128 = u128_saturating_from_u256(&pre_verification_gas);
    let display_gas_limit: u64 = ver_gas_u128
        .saturating_add(call_gas_u128)
        .saturating_add(pre_ver_u128)
        .min(u64::MAX as u128) as u64;

    let tx_for_display = Eip1559Tx {
        chain_id,
        nonce: display_nonce,
        max_priority_fee_per_gas: display_max_prio,
        max_fee_per_gas: display_max_fee,
        gas_limit: display_gas_limit,
        to: Some(to_address),
        value: U256(value),
        data_len,
        access_list_count: 0,
        signing_hash: [0u8; 32],
    };

    // ── 6a. Verify optional ERC-20 bundle ──────────────────────────
    let verified_meta: Option<Erc20Metadata<'_>> = if erc20_bundle_len > 0 {
        let bundle_slice =
            &snap[erc20_bundle_start..erc20_bundle_start + erc20_bundle_len];
        match verify_erc20_bundle(bundle_slice) {
            Some(meta) => {
                let contract_match = match tx_for_display.to {
                    Some(addr) => addr == meta.contract,
                    None => false,
                };
                if meta.chain_id == chain_id && contract_match {
                    Some(meta)
                } else {
                    None
                }
            }
            None => None,
        }
    } else {
        None
    };

    // ── 6b. Verify optional ZK clear-sign bundle ───────────────────
    let zk_verified: Option<([u8; ZK_MAX_CALLDATA], [u8; ZK_STRING_LEN])> = if zk_bundle_len > 0
        && zk_bundle_len >= ZK_CLEAR_SIGN_FIXED_LEN
    {
        let zk_slice = &snap[zk_bundle_start..zk_bundle_start + zk_bundle_len];
        let proof_bytes: &[u8; ZK_PROOF_LEN] = zk_slice[..ZK_PROOF_LEN].try_into().unwrap();
        let calldata_bytes: &[u8; ZK_MAX_CALLDATA] = zk_slice
            [ZK_PROOF_LEN..ZK_PROOF_LEN + ZK_MAX_CALLDATA]
            .try_into()
            .unwrap();
        let readable_bytes: &[u8; ZK_STRING_LEN] = zk_slice
            [ZK_PROOF_LEN + ZK_MAX_CALLDATA..ZK_CLEAR_SIGN_FIXED_LEN]
            .try_into()
            .unwrap();
        let vk_bundle = &zk_slice[ZK_CLEAR_SIGN_FIXED_LEN..];

        if inner_data.len() > ZK_MAX_CALLDATA {
            None
        } else {
            match crate::zk::verify_clear_sign_proof(
                proof_bytes,
                calldata_bytes,
                readable_bytes,
                vk_bundle,
            ) {
                Ok(verified) => {
                    if verified.chain_id != chain_id || verified.contract != to_address {
                        None
                    } else {
                        let calldata_prefix =
                            &inner_data[..inner_data.len().min(ZK_MAX_CALLDATA)];
                        let attested_prefix = &calldata_bytes[..calldata_prefix.len()];
                        if calldata_prefix == attested_prefix
                            && calldata_bytes[calldata_prefix.len()..]
                                .iter()
                                .all(|&b| b == 0)
                        {
                            let mut cd = [0u8; ZK_MAX_CALLDATA];
                            cd.copy_from_slice(calldata_bytes);
                            let mut rd = [0u8; ZK_STRING_LEN];
                            rd.copy_from_slice(readable_bytes);
                            Some((cd, rd))
                        } else {
                            None
                        }
                    }
                }
                Err(_) => None,
            }
        }
    } else {
        None
    };

    // ── 6c. Pick the render flavour ────────────────────────────────
    let pages = if let Some((_, readable)) = zk_verified.as_ref() {
        crate::zk::render_clear_sign_pages(&tx_for_display, readable)
    } else if inner_data.is_empty() {
        render_pages(&tx_for_display)
    } else {
        match parse_erc20_calldata(inner_data) {
            Some(call) => {
                if let Some(meta) = verified_meta.as_ref() {
                    render_erc20_known_pages(&tx_for_display, &call, meta)
                } else {
                    render_erc20_unknown_pages(&tx_for_display, &call)
                }
            }
            None => render_blind_sign_pages(&tx_for_display, inner_data),
        }
    };
    let _erc20_type_marker: Option<Erc20Call> = None;
    match confirm(pages.as_slice()) {
        ConfirmResult::Confirmed => {}
        ConfirmResult::Cancelled => {
            ui::show_status("Cancelled", "");
            return NscStatus::UserRejected as u32;
        }
        ConfirmResult::IdleWipe => {
            super::zeroize_sensitive_state();
            ui::show_status("Locked", "(idle wipe)");
            return NscStatus::IdleWipe as u32;
        }
    }

    // ── 7. Reconstruct entropy + derive JARDÍN master ──────────────
    //
    // HIGH-6: wrap every stack-local secret in Zeroizing.
    let master_secret: Zeroizing<[u8; 32]> =
        Zeroizing::new(super::state::peek_state(|s| s.master_secret));
    let mut entropy_blob = Zeroizing::new([0u8; 64]);
    let entropy_blob_len = {
        use crate::secure_element::WalletStore;
        let se = &mut *core::ptr::addr_of_mut!(crate::SE);
        match se.read_entropy_blob(&mut *entropy_blob) {
            Ok(l) => l,
            Err(_) => return NscStatus::InternalError as u32,
        }
    };
    let mut entropy = Zeroizing::new(
        match crate::crypto::decrypt_entropy_blob(
            &entropy_blob[..entropy_blob_len],
            &*master_secret,
        ) {
            Ok(e) => e,
            Err(_) => return NscStatus::CryptoError as u32,
        },
    );
    let jardin_master_entropy: Zeroizing<[u8; 32]> =
        Zeroizing::new(crate::crypto::jardin_master_entropy_from_entropy(&*entropy));

    // ── 8. Build Type 2 callData: execute(to, value, data) ─────────
    let t2_exec = match reconstruct_execute_calldata(&tx_for_display, inner_data) {
        Ok(c) => c,
        Err(_) => {
            entropy.zeroize();
            return NscStatus::CryptoError as u32;
        }
    };

    // ── 9. Type 2 nonce ────────────────────────────────────────────
    // Type 1 (if present) consumes the supplied base nonce; Type 2 uses
    // base+1. In Type-2-only mode Type 2 uses base directly.
    let mut type2_nonce = nonce;
    if register_slot {
        add_one_to_be_u256(&mut type2_nonce);
    }

    // ── 10. Slot C10 keygen (cached by slot_index) ─────────────────
    //
    // Re-keygen iff the SRAM cache holds a different slot_index.
    let need_keygen = super::state::peek_state(|_| {
        // SAFETY: single-threaded gateway.
        let cached = unsafe { &*core::ptr::addr_of!(super::state::JARDIN_SLOT) };
        match cached {
            Some(c) => c.slot_index != slot_index,
            None => true,
        }
    });

    if need_keygen {
        ui::show_progress("Slot keygen", 0);
        let (slot_sk, _slot_pk_seed_32, _slot_pk_root_32) =
            crate::crypto::derive_c10_slot_keypair_with_progress(
                &*jardin_master_entropy,
                slot_index,
                |p| ui::show_progress("Slot keygen", p),
            );
        // SAFETY: single-threaded.
        unsafe {
            *core::ptr::addr_of_mut!(super::state::JARDIN_SLOT) = Some(CachedSlot {
                slot_index,
                key: slot_sk,
            });
        }
        super::state::with_state(|s| {
            s.jardin_master_entropy.zeroize();
            s.jardin_master_entropy = *jardin_master_entropy;
            s.jardin_master_derived = true;
        });
    }

    // Extract the 16-byte slot pubkey halves for the bundle header and the
    // slot SigningKey reference for signing.
    let (slot_pk_seed_16, slot_pk_root_16) = unsafe {
        match &*core::ptr::addr_of!(super::state::JARDIN_SLOT) {
            Some(c) => {
                let mut seed = [0u8; 16];
                let mut root = [0u8; 16];
                seed.copy_from_slice(&c.key.pk_seed()[..16]);
                root.copy_from_slice(&c.key.pk_root()[..16]);
                (seed, root)
            }
            None => {
                entropy.zeroize();
                return NscStatus::InternalError as u32;
            }
        }
    };

    // ── 11. Type 1 (optional) ──────────────────────────────────────
    let mut type1_out: Zeroizing<[u8; JARDIN_TYPE1_LEN]> =
        Zeroizing::new([0u8; JARDIN_TYPE1_LEN]);
    let mut init_code_out: Zeroizing<[u8; JARDIN_INIT_CODE_LEN]> =
        Zeroizing::new([0u8; JARDIN_INIT_CODE_LEN]);
    let mut emit_init_code = false;
    let h_r: [u8; 32];

    if register_slot {
        ui::show_status("Slot register", "building type 1");

        // Deterministic r per (master, slot_index). H(r) is the on-chain slotKey.
        let r = crate::crypto::jardin_slot_r(&*jardin_master_entropy, slot_index);
        h_r = sha256(&r);

        // Type 1 callData: execute(sender, 0, "")
        let t1_tx = Eip1559Tx {
            chain_id,
            nonce: 0,
            max_priority_fee_per_gas: U256::zero(),
            max_fee_per_gas: U256::zero(),
            gas_limit: 0,
            to: Some(sender),
            value: U256::zero(),
            data_len: 0,
            access_list_count: 0,
            signing_hash: [0u8; 32],
        };
        let t1_exec = match reconstruct_execute_calldata(&t1_tx, &[]) {
            Ok(c) => c,
            Err(_) => {
                entropy.zeroize();
                return NscStatus::CryptoError as u32;
            }
        };

        // C10 bootstrap keygen. Unavoidably expensive (~5-6 s on hardware)
        // but only needed on register-slot requests.
        ui::show_progress("C10 keygen", 0);
        let (c10_sk, c10_pk_seed_32, c10_pk_root_32) =
            crate::crypto::derive_c10_master_keypair_from_entropy_with_progress(
                &*entropy,
                |p| ui::show_progress("C10 keygen", p),
            );

        // Optional initCode:
        //   factory(20) || selector(4) || masterPkSeed(32) || masterPkRoot(32)
        let t1_init_code_hash = if include_init_code {
            let ic = &mut *init_code_out;
            ic[..20].copy_from_slice(&PQ_JARDIN_WALLET_FACTORY);
            ic[20..24].copy_from_slice(&JARDIN_CREATE_ACCOUNT_SELECTOR);
            ic[24..56].copy_from_slice(&c10_pk_seed_32);
            ic[56..88].copy_from_slice(&c10_pk_root_32);
            emit_init_code = true;
            keccak256(ic.as_slice())
        } else {
            KECCAK_EMPTY
        };

        // Type 1 userOpHash (EntryPoint v0.9).
        let t1_params = AaUserOpParamsV09 {
            sender,
            entry_point,
            chain_id,
            nonce: U256(nonce),
            init_code_hash: t1_init_code_hash,
            account_gas_limits,
            pre_verification_gas: U256(pre_verification_gas),
            gas_fees,
            paymaster_and_data_hash,
        };
        let t1_call_hash = keccak256(t1_exec.as_slice());
        let t1_user_op_hash = compute_user_op_hash_v09(&t1_params, &t1_call_hash);

        let c10_sig = match crate::crypto::c10_sign_verified_with_progress(
            &c10_sk,
            &t1_user_op_hash,
            c10_sign_progress_bootstrap,
        ) {
            Ok(s) => s,
            Err(_) => {
                entropy.zeroize();
                return NscStatus::CryptoError as u32;
            }
        };
        drop(c10_sk); // ZeroizeOnDrop.

        // Assemble Type 1 payload.
        type1_out[0] = JARDIN_TYPE1_MARKER;
        type1_out[1..33].copy_from_slice(&r);
        type1_out[33..49].copy_from_slice(&slot_pk_seed_16);
        type1_out[49..65].copy_from_slice(&slot_pk_root_16);
        type1_out[65..65 + C10_SIG_LEN].copy_from_slice(&c10_sig);
    } else {
        // Type-2-only mode: the companion already registered the slot, but
        // it still needs H(r) so the on-chain wallet can look up the slotKey.
        let r = crate::crypto::jardin_slot_r(&*jardin_master_entropy, slot_index);
        h_r = sha256(&r);
    }

    // ── 12. Type 2: slot C10 sign the user's userOpHash ────────────
    let t2_params = AaUserOpParamsV09 {
        sender,
        entry_point,
        chain_id,
        nonce: U256(type2_nonce),
        init_code_hash: KECCAK_EMPTY,
        account_gas_limits,
        pre_verification_gas: U256(pre_verification_gas),
        gas_fees,
        paymaster_and_data_hash,
    };
    let t2_call_hash = keccak256(t2_exec.as_slice());
    let t2_user_op_hash = compute_user_op_hash_v09(&t2_params, &t2_call_hash);

    ui::show_progress("Slot C10 sign", 0);
    let t2_sig = {
        // SAFETY: single-threaded; cache guaranteed populated above.
        let cached = unsafe { &*core::ptr::addr_of!(super::state::JARDIN_SLOT) };
        let slot_ref = match cached {
            Some(c) => &c.key,
            None => {
                entropy.zeroize();
                return NscStatus::InternalError as u32;
            }
        };
        match crate::crypto::c10_sign_verified_with_progress(
            slot_ref,
            &t2_user_op_hash,
            c10_sign_progress_slot,
        ) {
            Ok(s) => s,
            Err(_) => {
                entropy.zeroize();
                return NscStatus::CryptoError as u32;
            }
        }
    };

    // Verify-before-release, double-evaluated (HIGH-3).
    let (v1, v2) = {
        let cached = unsafe { &*core::ptr::addr_of!(super::state::JARDIN_SLOT) };
        let slot_ref = match cached {
            Some(c) => &c.key,
            None => {
                entropy.zeroize();
                return NscStatus::InternalError as u32;
            }
        };
        let v1 = sphincs_c10::verify(slot_ref.pk_seed(), slot_ref.pk_root(), &t2_user_op_hash, &t2_sig);
        let v2 = sphincs_c10::verify(slot_ref.pk_seed(), slot_ref.pk_root(), &t2_user_op_hash, &t2_sig);
        (v1, v2)
    };
    let ok_sentinel: u32 = if v1 && v2 { 0xA5A5_A5A5 } else { 0x5A5A_5A5A };
    if ok_sentinel != 0xA5A5_A5A5 || !v1 || !v2 {
        entropy.zeroize();
        ui::show_status("Sig verify", "FAIL");
        return NscStatus::CryptoError as u32;
    }

    // ── 13. Assemble output bundle ─────────────────────────────────
    //
    // Layout:
    //   [init_code_len(4 BE)][init_code(0 or 88)]
    //   [type1_len(4 BE)][type1(0 or 4073)]
    //   [type2_len(4 BE)][type2(4073)]
    let mut write_pos: usize = 0;
    let init_code_len = if emit_init_code { JARDIN_INIT_CODE_LEN } else { 0 };
    let ic_len_be = (init_code_len as u32).to_be_bytes();
    for i in 0..4 {
        core::ptr::write_volatile(out_ptr.add(write_pos + i), ic_len_be[i]);
    }
    write_pos += 4;
    if emit_init_code {
        for i in 0..JARDIN_INIT_CODE_LEN {
            core::ptr::write_volatile(out_ptr.add(write_pos + i), init_code_out[i]);
        }
        write_pos += JARDIN_INIT_CODE_LEN;
    }

    let type1_len = if register_slot { JARDIN_TYPE1_LEN } else { 0 };
    let t1_len_be = (type1_len as u32).to_be_bytes();
    for i in 0..4 {
        core::ptr::write_volatile(out_ptr.add(write_pos + i), t1_len_be[i]);
    }
    write_pos += 4;
    if register_slot {
        for i in 0..JARDIN_TYPE1_LEN {
            core::ptr::write_volatile(out_ptr.add(write_pos + i), type1_out[i]);
        }
        write_pos += JARDIN_TYPE1_LEN;
    }

    let t2_len_be = (JARDIN_TYPE2_LEN as u32).to_be_bytes();
    for i in 0..4 {
        core::ptr::write_volatile(out_ptr.add(write_pos + i), t2_len_be[i]);
    }
    write_pos += 4;

    core::ptr::write_volatile(out_ptr.add(write_pos), JARDIN_TYPE2_MARKER);
    write_pos += 1;
    for i in 0..32 {
        core::ptr::write_volatile(out_ptr.add(write_pos + i), h_r[i]);
    }
    write_pos += 32;
    for i in 0..16 {
        core::ptr::write_volatile(out_ptr.add(write_pos + i), slot_pk_seed_16[i]);
    }
    write_pos += 16;
    for i in 0..16 {
        core::ptr::write_volatile(out_ptr.add(write_pos + i), slot_pk_root_16[i]);
    }
    write_pos += 16;
    for i in 0..C10_SIG_LEN {
        core::ptr::write_volatile(out_ptr.add(write_pos + i), t2_sig[i]);
    }
    write_pos += C10_SIG_LEN;

    debug_assert!(write_pos <= MAX_JARDIN_RESPONSE_LEN);
    debug_assert_eq!(write_pos - (4 + init_code_len + 4 + type1_len + 4), JARDIN_TYPE2_LEN);
    let _ = write_pos;

    // ── 14. Zeroise transients ─────────────────────────────────────
    entropy.zeroize();
    type1_out.zeroize();
    init_code_out.zeroize();

    crate::timeout::reset_activity();
    ui::show_status("Signed", "");
    for _ in 0..3_000_000u32 {
        cortex_m::asm::nop();
    }
    ui::show_status("PQSigner OS", "Ready");

    NscStatus::Ok as u32
}

/// Increment the 64-bit sequence portion of an EntryPoint v0.9 nonce.
fn add_one_to_be_u256(v: &mut [u8; 32]) {
    for i in (24..32).rev() {
        let (sum, carry) = v[i].overflowing_add(1);
        v[i] = sum;
        if !carry {
            return;
        }
    }
    debug_assert!(false, "nonce seq overflow slipped past the step-4b guard");
}

fn c10_sign_progress_bootstrap(percent: u8) {
    crate::ui::show_progress("C10 sign", percent);
}

fn c10_sign_progress_slot(percent: u8) {
    crate::ui::show_progress("Slot C10 sign", percent);
}

/// Decode a 16-byte big-endian slice as `u128`.
fn u128_from_be_16(bytes: &[u8]) -> u128 {
    debug_assert_eq!(bytes.len(), 16);
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&bytes[..16]);
    u128::from_be_bytes(buf)
}

/// Decode a 32-byte BE u256 as `u128`, saturating at `u128::MAX`.
fn u128_saturating_from_u256(bytes: &[u8; 32]) -> u128 {
    for &b in &bytes[0..16] {
        if b != 0 {
            return u128::MAX;
        }
    }
    u128_from_be_16(&bytes[16..32])
}

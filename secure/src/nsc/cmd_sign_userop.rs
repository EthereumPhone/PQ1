//! CMD_SIGN_USEROP — Coinbase-Smart-Wallet-style sign command (all SHA-256).
//!
//! After the Coinbase Smart Wallet port, every signature on the wallet is a
//! SPHINCS+C10 sig over a purely-SHA-256 digest (no keccak on the sign path —
//! STM32U585 has HW SHA-256 but no keccak accelerator). The on-chain wallet
//! owns an array of 64-byte C10 owners: owner index 0 is the immutable
//! bootstrap key; owner index 1 is the per-chain slot-0 key (added by the
//! factory on deploy); higher indices are slot keys added by the bootstrap
//! when the previous slot hits its 65,536-sig cap.
//!
//! Three flows, selected by the companion-supplied flags field:
//!
//!   * **Deploy** (`FLAG_INCLUDE_INIT_CODE` only, slot_index = 0)
//!     The wallet doesn't yet exist on this chain. Firmware:
//!       1. Derives slot-0 for `(chain_id, 0)`.
//!       2. Signs `sha256("pqwallet-factory-add-slot" || chain_id ||
//!          slot0PkSeed || slot0PkRoot)` with the bootstrap key — this
//!          is the `factorySig` that unlocks `createAccount` on-chain.
//!       3. Assembles the factory-call `initCode` carrying `factorySig`.
//!       4. Signs the user's single UserOp (with `initCode` attached)
//!          using slot-0.
//!     Output: initCode + Type 2 sig wrapper (`ownerIndex = 1`).
//!
//!   * **Rotation** (`FLAG_REGISTER_SLOT` only, slot_index ≥ 1)
//!     slot N-1 is exhausted / compromised. Firmware:
//!       1. Derives slot-N for `(chain_id, slot_index)`.
//!       2. Builds an internal `addOwnerBytes(slot_N_owner_bytes)` UserOp,
//!          signs its SHA-256 sphincs digest with the bootstrap key.
//!       3. Builds the user's UserOp (nonce = base+1), signs with slot-N.
//!     Output: Type 1 sig wrapper (`ownerIndex = 0`) + Type 2 sig wrapper
//!     (`ownerIndex = slot_index + 1`).
//!
//!   * **Normal** (neither flag)
//!     Slot-N is already registered on-chain. Firmware:
//!       1. Derives (or reuses cached) slot-N.
//!       2. Signs the user's UserOp with slot-N.
//!     Output: Type 2 sig wrapper only.
//!
//! `FLAG_INCLUDE_INIT_CODE` and `FLAG_REGISTER_SLOT` are mutually exclusive
//! — first deploy cannot simultaneously be a rotation (slot-0 is set by the
//! factory atomically, no separate addOwner needed).
//!
//! Firmware is still stateless: slot keys are derived on demand from
//! `(master_entropy, chain_id, slot_index)` and cached in SRAM across the
//! unlock session. Bootstrap key regen happens only on rotation/deploy paths.
//!
//! Every signature is verified locally before being written to NS
//! (fault-injection guard, double-evaluated).

use sha2::{Digest, Sha256};
use sphincs_tz_shared::{
    NscStatus, ACCOUNT_INDEX_MASK, ACCOUNT_INDEX_SHIFT, C10_SIG_LEN, FLAG_INCLUDE_INIT_CODE,
    FLAG_REGISTER_SLOT, MAX_JARDIN_RESPONSE_LEN, MAX_TX_LEN, PQ_ADD_OWNER_BYTES_SELECTOR,
    PQ_CREATE_ACCOUNT_SELECTOR, PQ_INIT_CODE_LEN, PQ_SMART_WALLET_FACTORY,
    SIGN_USEROP_HEADER_LEN, SIG_WRAPPER_LEN, SLOT_INDEX_MASK, ZK_CLEAR_SIGN_FIXED_LEN,
    ZK_MAX_CALLDATA, ZK_PROOF_LEN, ZK_STRING_LEN, ZK_VK_BUNDLE_MAX_LEN,
};
use zeroize::{Zeroize, Zeroizing};

#[inline]
fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

/// Domain tag the firmware signs when authorising slot-0 on a new chain.
/// MUST match `PQSmartWalletFactory.FACTORY_ADD_SLOT_DOMAIN`.
const FACTORY_ADD_SLOT_DOMAIN: &[u8] = b"pqwallet-factory-add-slot";

use super::ptr_validate::{validate_ns_read_ptr, validate_ns_write_ptr};
use super::state::CachedSlot;
use super::GatewayArgs;
use crate::aa::userop::{
    compute_sphincs_digest_v09, reconstruct_execute_calldata, sha256_bytes,
    AaUserOpParamsV09Sha256, SHA256_EMPTY,
};
use crate::erc20::bundle::{verify_erc20_bundle, Erc20Metadata, MAX_ERC20_BUNDLE_LEN};
use crate::erc20::calldata::{parse_erc20_calldata, Erc20Call};
use crate::tx::display::{
    render_blind_sign_pages, render_erc20_known_pages, render_erc20_unknown_pages, render_pages,
};
use crate::tx::eip1559::{Eip1559Tx, U256};
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
    let account_index = (flags & ACCOUNT_INDEX_MASK) >> ACCOUNT_INDEX_SHIFT;
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

    // Flag-combination invariants (post-Coinbase-port):
    //   * INCLUDE_INIT_CODE and REGISTER_SLOT are mutually exclusive —
    //     first-deploy bundles its slot-0 registration into the factory
    //     call, so there is never a separate addOwner UserOp on deploy.
    //   * INCLUDE_INIT_CODE requires slot_index == 0 (the factory can
    //     only pre-register the canonical slot 0).
    //   * REGISTER_SLOT requires slot_index >= 1 (rotation only; slot-0
    //     is already added by the factory on deploy).
    if include_init_code && register_slot {
        ui::show_status("Sign", "incompatible flags");
        return NscStatus::InvalidPointer as u32;
    }
    if include_init_code && slot_index != 0 {
        ui::show_status("Sign", "init_code needs slot0");
        return NscStatus::InvalidPointer as u32;
    }
    if register_slot && slot_index == 0 {
        ui::show_status("Sign", "register needs slot>=1");
        return NscStatus::InvalidPointer as u32;
    }

    // CRIT-17: refuse nonce-seq overflow. v0.9 nonces are 192-bit key | 64-bit seq.
    // When REGISTER_SLOT is set, Type 2 nonce = base + 1 — overflowing the
    // seq would carry into the key field and silently change the nonce key.
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
    let jardin_master_entropy: Zeroizing<[u8; 32]> = Zeroizing::new(
        crate::crypto::jardin_master_entropy_from_entropy(&*entropy, account_index),
    );

    // ── 8. Build Type 2 callData: execute(to, value, data) ─────────
    let t2_exec = match reconstruct_execute_calldata(&tx_for_display, inner_data) {
        Ok(c) => c,
        Err(_) => {
            entropy.zeroize();
            return NscStatus::CryptoError as u32;
        }
    };

    // ── 9. Type 2 nonce ────────────────────────────────────────────
    // When REGISTER_SLOT is set, the Type 1 UserOp consumes the supplied
    // base nonce and Type 2 uses base+1. In the other two modes Type 2
    // uses the supplied base directly.
    let mut type2_nonce = nonce;
    if register_slot {
        add_one_to_be_u256(&mut type2_nonce);
    }

    // ── 10. Slot C10 keygen (cached by (account_index, chain_id, slot_index)) ──
    //
    // Post-Coinbase-port slot keys are chain-specific. With multi-
    // account derivation they're also account-specific (the master
    // entropy varies per `account_index`). A cache miss on any of the
    // three fields triggers a fresh ~5-6 s keygen.
    let need_keygen = super::state::peek_state(|_| {
        // SAFETY: single-threaded gateway.
        let cached = unsafe { &*core::ptr::addr_of!(super::state::JARDIN_SLOT) };
        match cached {
            Some(c) => {
                c.account_index != account_index
                    || c.chain_id != chain_id
                    || c.slot_index != slot_index
            }
            None => true,
        }
    });

    if need_keygen {
        ui::show_progress("Slot keygen", 0);
        let (slot_sk, _slot_pk_seed_32, _slot_pk_root_32) =
            crate::crypto::derive_c10_slot_keypair_with_progress(
                &*jardin_master_entropy,
                chain_id,
                slot_index,
                |p| ui::show_progress("Slot keygen", p),
            );
        // SAFETY: single-threaded.
        unsafe {
            *core::ptr::addr_of_mut!(super::state::JARDIN_SLOT) = Some(CachedSlot {
                account_index,
                chain_id,
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

    // Extract the 32-byte slot pubkey halves. Post-port the on-chain
    // verifier takes `bytes32` pkSeed + pkRoot directly from the 64-byte
    // owner bytes, so the old N-mask truncation to 16 bytes is gone.
    let (slot_pk_seed_32, slot_pk_root_32) = unsafe {
        match &*core::ptr::addr_of!(super::state::JARDIN_SLOT) {
            Some(c) => {
                let mut seed = [0u8; 32];
                let mut root = [0u8; 32];
                seed[..16].copy_from_slice(&c.key.pk_seed()[..16]);
                root[..16].copy_from_slice(&c.key.pk_root()[..16]);
                (seed, root)
            }
            None => {
                entropy.zeroize();
                return NscStatus::InternalError as u32;
            }
        }
    };

    // Slot-N's 64-byte owner bytes (pkSeed || pkRoot) — injected into the
    // Type 1 addOwnerBytes calldata.
    let mut slot_owner_bytes = [0u8; 64];
    slot_owner_bytes[..32].copy_from_slice(&slot_pk_seed_32);
    slot_owner_bytes[32..].copy_from_slice(&slot_pk_root_32);

    // ── 11. Build Type 1 (optional) + initCode (optional) ──────────
    //
    // We need the bootstrap C10 key in three cases:
    //   * FLAG_INCLUDE_INIT_CODE — to sign the factorySig for slot-0.
    //   * FLAG_REGISTER_SLOT — to sign the addOwnerBytes UserOp.
    // So regen the bootstrap key (~5-6 s) once and use as needed.
    //
    // Non-secret outputs:
    //   * `init_code_out` / `emit_init_code` — 4280-byte factory call.
    //   * `type1_wrapper_out` / `emit_type1` — 4128-byte SignatureWrapper.
    let mut init_code_out: Zeroizing<[u8; PQ_INIT_CODE_LEN]> =
        Zeroizing::new([0u8; PQ_INIT_CODE_LEN]);
    let mut type1_wrapper_out: Zeroizing<[u8; SIG_WRAPPER_LEN]> =
        Zeroizing::new([0u8; SIG_WRAPPER_LEN]);
    let mut emit_init_code = false;
    let mut emit_type1 = false;
    let mut t1_init_code_digest = SHA256_EMPTY;

    if include_init_code || register_slot {
        ui::show_progress("C10 keygen", 0);
        let (c10_sk, master_pk_seed_32, master_pk_root_32) =
            crate::crypto::derive_c10_master_keypair_from_entropy_with_progress(
                &*entropy,
                account_index,
                |p| ui::show_progress("C10 keygen", p),
            );

        // Refresh the bootstrap pubkey cache so the address-picker
        // doesn't have to re-keygen this account on the next look-up.
        super::state::with_state(|s| {
            s.bootstrap_cache_insert(account_index, master_pk_seed_32, master_pk_root_32);
        });

        // ── 11a. Deploy path: build initCode + factorySig ──────────
        if include_init_code {
            ui::show_status("Factory", "signing slot-0");

            // factorySig message: sha256(DOMAIN || chainId(8) ||
            //                             slot0PkSeed(32) || slot0PkRoot(32))
            let mut factory_msg = [0u8; 25 + 8 + 32 + 32];
            factory_msg[..25].copy_from_slice(FACTORY_ADD_SLOT_DOMAIN);
            factory_msg[25..33].copy_from_slice(&chain_id.to_be_bytes());
            factory_msg[33..65].copy_from_slice(&slot_pk_seed_32);
            factory_msg[65..97].copy_from_slice(&slot_pk_root_32);
            let factory_digest = sha256(&factory_msg);

            let factory_sig = match crate::crypto::c10_sign_verified_with_progress(
                &c10_sk,
                &factory_digest,
                c10_sign_progress_bootstrap,
            ) {
                Ok(s) => s,
                Err(_) => {
                    entropy.zeroize();
                    return NscStatus::CryptoError as u32;
                }
            };

            // Build the initCode blob. Layout:
            //
            //   factory(20)
            //   || selector(4)
            //   || masterPkSeed(32) || masterPkRoot(32)
            //   || slot0PkSeed(32) || slot0PkRoot(32)
            //   || chainId (left-padded to uint256, 32)
            //   || bytes-offset (0xE0 = 224, 32)
            //   || bytes-length (4008, 32)
            //   || factory_sig (4008 bytes, then padded to 4032)
            let ic = &mut *init_code_out;
            ic[..20].copy_from_slice(&PQ_SMART_WALLET_FACTORY);
            ic[20..24].copy_from_slice(&PQ_CREATE_ACCOUNT_SELECTOR);
            ic[24..56].copy_from_slice(&master_pk_seed_32);
            ic[56..88].copy_from_slice(&master_pk_root_32);
            ic[88..120].copy_from_slice(&slot_pk_seed_32);
            ic[120..152].copy_from_slice(&slot_pk_root_32);
            // chainId left-padded
            ic[152 + 24..184].copy_from_slice(&chain_id.to_be_bytes());
            // bytes-offset = 0xE0 (= head-args-len: 5 × 32 = 160; plus 32
            // for own offset slot gives 192 — wait, but offset is measured
            // from the start of the abi-encoded args, AFTER the selector.
            // Args start at ic+24. The 5 fixed slots take 5*32 = 160 bytes.
            // The bytes-offset slot itself is at 160..192. So offset value
            // = 192 (= 0xC0). Actually Solidity measures offset from the
            // *first byte of the abi-encoded args*, not from the offset
            // slot; and the offset points to the start of the length field.
            // For (bytes32,bytes32,bytes32,bytes32,uint64,bytes) the head
            // occupies 6×32 = 192 bytes (each head slot is 32), and the
            // length field starts at byte 192. So offset = 0xc0 = 192.
            let offset_field_start = 24 + 5 * 32;
            ic[offset_field_start + 24..offset_field_start + 32]
                .copy_from_slice(&(6 * 32u64).to_be_bytes());
            let length_field_start = offset_field_start + 32;
            ic[length_field_start + 24..length_field_start + 32]
                .copy_from_slice(&(C10_SIG_LEN as u64).to_be_bytes());
            let data_start = length_field_start + 32;
            ic[data_start..data_start + C10_SIG_LEN].copy_from_slice(&factory_sig);
            // Trailing 4032 - 4008 = 24 bytes of zero padding are already zero.

            debug_assert_eq!(data_start + 4032, PQ_INIT_CODE_LEN);
            emit_init_code = true;
            // initCode digest for the Type 2 sphincs sign.
            t1_init_code_digest = sha256_bytes(ic.as_slice());
        }

        // ── 11b. Rotation path: build addOwnerBytes UserOp + Type 1 sig ──
        if register_slot {
            ui::show_status("Slot register", "signing addOwner");

            // addOwnerBytes(bytes) calldata:
            //   selector(4) || offset(32 = 0x20) || length(32 = 0x40)
            //     || data(64 = slot_N_owner_bytes) — already 32-aligned
            let mut t1_call = [0u8; 4 + 32 + 32 + 64];
            t1_call[..4].copy_from_slice(&PQ_ADD_OWNER_BYTES_SELECTOR);
            t1_call[4 + 28..4 + 32].copy_from_slice(&0x20u32.to_be_bytes());
            t1_call[4 + 32 + 28..4 + 32 + 32].copy_from_slice(&64u32.to_be_bytes());
            t1_call[4 + 64..4 + 64 + 64].copy_from_slice(&slot_owner_bytes);
            let t1_call_digest = sha256_bytes(&t1_call);

            // Sphincs digest for the Type 1 UserOp.
            let t1_params = AaUserOpParamsV09Sha256 {
                sender,
                entry_point,
                chain_id,
                nonce: U256(nonce),
                init_code_digest: SHA256_EMPTY, // rotation never rides initCode
                account_gas_limits,
                pre_verification_gas: U256(pre_verification_gas),
                gas_fees,
                paymaster_and_data_digest: SHA256_EMPTY,
            };
            let t1_digest = compute_sphincs_digest_v09(&t1_params, &t1_call_digest);

            let bootstrap_sig = match crate::crypto::c10_sign_verified_with_progress(
                &c10_sk,
                &t1_digest,
                c10_sign_progress_bootstrap,
            ) {
                Ok(s) => s,
                Err(_) => {
                    entropy.zeroize();
                    return NscStatus::CryptoError as u32;
                }
            };

            encode_signature_wrapper(&mut *type1_wrapper_out, 0, &bootstrap_sig);
            emit_type1 = true;
        }

        drop(c10_sk); // ZeroizeOnDrop.
    }

    // ── 12. Type 2: slot C10 signs the user's UserOp sphincs digest ──
    let t2_call_digest = sha256_bytes(t2_exec.as_slice());
    let t2_init_code_digest = if include_init_code {
        t1_init_code_digest
    } else {
        SHA256_EMPTY
    };
    // The on-wire `paymaster_and_data_hash` is now the SHA-256 of the
    // paymasterAndData bytes (companion sends SHA256_EMPTY when absent).
    // Staying all-sha256 means zero keccak on the sign path.
    let t2_params = AaUserOpParamsV09Sha256 {
        sender,
        entry_point,
        chain_id,
        nonce: U256(type2_nonce),
        init_code_digest: t2_init_code_digest,
        account_gas_limits,
        pre_verification_gas: U256(pre_verification_gas),
        gas_fees,
        paymaster_and_data_digest: paymaster_and_data_hash,
    };
    let t2_digest = compute_sphincs_digest_v09(&t2_params, &t2_call_digest);

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
            &t2_digest,
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
        let v1 = sphincs_c10::verify(slot_ref.pk_seed(), slot_ref.pk_root(), &t2_digest, &t2_sig);
        let v2 = sphincs_c10::verify(slot_ref.pk_seed(), slot_ref.pk_root(), &t2_digest, &t2_sig);
        (v1, v2)
    };
    let ok_sentinel: u32 = if v1 && v2 { 0xA5A5_A5A5 } else { 0x5A5A_5A5A };
    if ok_sentinel != 0xA5A5_A5A5 || !v1 || !v2 {
        entropy.zeroize();
        ui::show_status("Sig verify", "FAIL");
        return NscStatus::CryptoError as u32;
    }

    // Wrap the Type 2 sig: ownerIndex = slot_index + 1 (bootstrap is at 0).
    let t2_owner_index = (slot_index as u64) + 1;
    let mut type2_wrapper_out: Zeroizing<[u8; SIG_WRAPPER_LEN]> =
        Zeroizing::new([0u8; SIG_WRAPPER_LEN]);
    encode_signature_wrapper(&mut *type2_wrapper_out, t2_owner_index, &t2_sig);

    // ── 13. Assemble output bundle ─────────────────────────────────
    //
    // Layout:
    //   [init_code_len(4 BE)][init_code(0 or 4280)]
    //   [type1_len(4 BE)][type1_wrapper(0 or 4128)]
    //   [type2_len(4 BE)][type2_wrapper(4128)]
    let mut write_pos: usize = 0;
    let init_code_len = if emit_init_code { PQ_INIT_CODE_LEN } else { 0 };
    write_be_u32(out_ptr, &mut write_pos, init_code_len as u32);
    if emit_init_code {
        for i in 0..PQ_INIT_CODE_LEN {
            core::ptr::write_volatile(out_ptr.add(write_pos + i), init_code_out[i]);
        }
        write_pos += PQ_INIT_CODE_LEN;
    }

    let type1_len = if emit_type1 { SIG_WRAPPER_LEN } else { 0 };
    write_be_u32(out_ptr, &mut write_pos, type1_len as u32);
    if emit_type1 {
        for i in 0..SIG_WRAPPER_LEN {
            core::ptr::write_volatile(out_ptr.add(write_pos + i), type1_wrapper_out[i]);
        }
        write_pos += SIG_WRAPPER_LEN;
    }

    write_be_u32(out_ptr, &mut write_pos, SIG_WRAPPER_LEN as u32);
    for i in 0..SIG_WRAPPER_LEN {
        core::ptr::write_volatile(out_ptr.add(write_pos + i), type2_wrapper_out[i]);
    }
    write_pos += SIG_WRAPPER_LEN;

    debug_assert!(write_pos <= MAX_JARDIN_RESPONSE_LEN);
    debug_assert_eq!(write_pos - (4 + init_code_len + 4 + type1_len + 4), SIG_WRAPPER_LEN);
    let _ = write_pos;

    // ── 14. Zeroise transients ─────────────────────────────────────
    entropy.zeroize();
    type1_wrapper_out.zeroize();
    type2_wrapper_out.zeroize();
    init_code_out.zeroize();

    crate::timeout::reset_activity();
    ui::show_status("Signed", "");
    for _ in 0..3_000_000u32 {
        cortex_m::asm::nop();
    }
    ui::show_status("PQSigner OS", "Ready");

    NscStatus::Ok as u32
}

/// Encode a SignatureWrapper `(uint256 ownerIndex, bytes innerSig)` into
/// `out` in place. Layout:
///
///   [0..32)      ownerIndex (uint256 BE)
///   [32..64)     offset to bytes = 0x40 (uint256 BE)
///   [64..96)     length = C10_SIG_LEN (uint256 BE)
///   [96..4128)   inner C10 sig, right-padded with zeros to a 32-byte boundary
fn encode_signature_wrapper(out: &mut [u8; SIG_WRAPPER_LEN], owner_index: u64, inner_sig: &[u8]) {
    debug_assert_eq!(inner_sig.len(), C10_SIG_LEN);
    // ownerIndex left-padded to 32 bytes
    out[24..32].copy_from_slice(&owner_index.to_be_bytes());
    // offset = 0x40
    out[32 + 31] = 0x40;
    // length = 4008 = 0x0fa8
    out[64 + 24..64 + 32].copy_from_slice(&(C10_SIG_LEN as u64).to_be_bytes());
    // inner sig
    out[96..96 + C10_SIG_LEN].copy_from_slice(inner_sig);
    // trailing padding is already zero from the Zeroizing init.
}

/// Volatile write of a big-endian u32 to `out_ptr + *write_pos`, advancing the cursor.
unsafe fn write_be_u32(out_ptr: *mut u8, write_pos: &mut usize, v: u32) {
    let be = v.to_be_bytes();
    for i in 0..4 {
        core::ptr::write_volatile(out_ptr.add(*write_pos + i), be[i]);
    }
    *write_pos += 4;
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

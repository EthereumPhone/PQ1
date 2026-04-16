//! CMD_SIGN_USEROP — unified JARDÍN Type 1 / Type 2 sign state machine.
//!
//! The one and only signing command in the post-cutover wallet. Given an
//! inner transaction (to, value, data) plus the AA wrapper parameters,
//! the firmware transparently handles slot registration (Type 1) when
//! needed and always produces a Type 2 FORS+C signature for the user's
//! actual tx.
//!
//! The companion submits up to two EntryPoint v0.9 PackedUserOperations:
//!
//!   1. Type 1 — slot registration UserOp. `callData = execute(sender, 0, "")`
//!      (a no-op call to self). Signature wraps a full SPHINCS+C11 sig
//!      against the C11 master key, plus the raw randomiser `r` and the
//!      N-truncated sub-key `(subPkSeed, subPkRoot)`. The wallet
//!      contract validates the C11 sig and, as a side effect, records
//!      `slots[keccak256(r)] = keccak256(subPkSeed || subPkRoot)`.
//!
//!   2. Type 2 — user tx UserOp. `callData = execute(to, value, data)`.
//!      Signature wraps a FORS+C sig against the registered sub-key.
//!
//! The state machine:
//!
//! ```text
//!   read SlotState from flash
//!   ├── none / not-registered / chain-mismatch    → FirstSign (slot_index = hint)
//!   │                                                emit Type 1 + Type 2
//!   ├── registered & next_q <= Q_MAX               → Normal
//!   │                                                emit Type 2 only
//!   └── registered & next_q > Q_MAX                → Rotate (slot_index + 1)
//!                                                    emit Type 1 + Type 2
//! ```
//!
//! `next_q` is persisted to flash **before** the Type 2 bytes are
//! released to NS. A power-cycle after sign-but-before-flash would
//! otherwise allow q reuse and FORS+C security collapses under reuse
//! (128 → 105 bits at q=2, lower with more).
//!
//! Every signature is verified locally before being written to NS
//! (fault-injection guard).
//!
//! See `sphincs_tz_shared::SIGN_USEROP_HEADER_LEN` for the input
//! wire format.

use sphincs_tz_shared::{
    NscStatus, C11_SIG_LEN, JARDIN_FORSC_BODY, JARDIN_TYPE1_LEN, JARDIN_TYPE1_MARKER,
    JARDIN_TYPE2_HEADER_LEN, JARDIN_TYPE2_MARKER, MAX_JARDIN_RESPONSE_LEN, MAX_TX_LEN,
    SIGN_USEROP_HEADER_LEN, ZK_CLEAR_SIGN_FIXED_LEN, ZK_MAX_CALLDATA, ZK_PROOF_LEN,
    ZK_STRING_LEN, ZK_VK_BUNDLE_MAX_LEN,
};
use zeroize::{Zeroize, Zeroizing};

use super::jardin_flash::{self, SlotState, FLAG_SLOT_REGISTERED};
use super::ptr_validate::{validate_ns_read_ptr, validate_ns_write_ptr};
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

/// Mode the state machine dispatches on.
enum Mode {
    FirstSign,
    Normal(SlotState),
    Rotate { from: SlotState },
}

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
    // we fill it with this request. Otherwise a fault that dumps
    // secure SRAM between signs could expose the user's last-signed
    // transaction to an attacker.
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
    let slot_index_hint = u32::from_be_bytes([snap[8], snap[9], snap[10], snap[11]]);
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

    // ── 4. CRIT-17: refuse nonce-key overflow ─────────────────────
    //
    // EntryPoint v0.9 nonces are 192-bit key | 64-bit seq. Our Type 2
    // nonce = base + 1 when Type 1 is present. If the bottom 64 bits
    // are all 0xFF, the +1 carries into the key field and silently
    // changes the nonce key — a user intent violation. Refuse outright;
    // the companion can submit a fresh base nonce.
    if nonce[24..32] == [0xFFu8; 8] {
        ui::show_status("Nonce seq", "overflow");
        return NscStatus::InvalidPointer as u32;
    }

    // Copy the variable-length sections into owned buffers so we can
    // release the SNAP_BUF lifetime after parsing. `inner_data` stays a
    // borrow into the snapshot because the sign path copies it into the
    // execute() calldata anyway.
    let inner_data: &[u8] =
        &snap[SIGN_USEROP_HEADER_LEN..SIGN_USEROP_HEADER_LEN + data_len];

    // ── 4b. Optional trailer: ERC-20 bundle + ZK clear-sign bundle ──
    //
    // Layout (appended after inner_data):
    //   erc20_bundle_len u16 BE
    //   erc20_bundle     [u8; erc20_bundle_len]
    //   zk_bundle_len    u16 BE
    //   zk_bundle        [u8; zk_bundle_len]
    //
    // Both length fields default to zero when absent. Older companions
    // that don't know about the trailer simply set total_len to
    // SIGN_USEROP_HEADER_LEN + data_len and the firmware treats the
    // missing fields as zero.
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

    // ── 5. Build a display-time Eip1559Tx shim ──────────────────────
    //
    // CRIT-2 fix: the shim previously fed zeros for nonce / gas / fees
    // to the renderer while the signed userOpHash bound the real
    // numbers, so a hostile NS could present "Max fee: 0 gwei" to the
    // user while actually signing a gas-bomb. We now decode the real
    // values from the EntryPoint v0.9 packed fields and feed them to
    // the display.
    //
    // EntryPoint v0.9 packing:
    //   nonce              = u256 BE (top 192 bits = key, bottom 64 = seq)
    //   accountGasLimits   = bytes32, (verificationGasLimit << 128) | callGasLimit
    //   gasFees            = bytes32, (maxPriorityFeePerGas << 128) | maxFeePerGas
    //   preVerificationGas = u256 BE
    let display_nonce = u64::from_be_bytes([
        nonce[24], nonce[25], nonce[26], nonce[27],
        nonce[28], nonce[29], nonce[30], nonce[31],
    ]);
    let display_max_fee = {
        // maxFeePerGas lives in the low 128 bits of gas_fees; zero-
        // extend to U256 for the renderer.
        let mut v = [0u8; 32];
        v[16..32].copy_from_slice(&gas_fees[16..32]);
        U256(v)
    };
    let display_max_prio = {
        let mut v = [0u8; 32];
        v[16..32].copy_from_slice(&gas_fees[0..16]);
        U256(v)
    };
    // gas_limit displayed = verGas + callGas + preVerificationGas,
    // saturating at u64::MAX so the format helper can't overflow.
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

    // ── 6a. Verify the optional ERC-20 metadata bundle ──────────────
    //
    // A verified bundle upgrades an ERC-20 transfer from the
    // `Erc20Unknown` trust level ("structurally decoded, amount shown
    // as raw uint256") to `Erc20Known` ("trusted symbol + decimals
    // from the firmware-embedded Merkle-rooted DB"). The cross-checks
    // against `tx.chain_id` and `tx.to` live here, NOT inside
    // `verify_erc20_bundle`.
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
                    // Bundle is structurally valid but doesn't match the
                    // tx being signed. Fall back to Erc20Unknown rather
                    // than reject the sign — the bundle is just a
                    // display hint.
                    None
                }
            }
            None => None,
        }
    } else {
        None
    };

    // ── 6b. Verify the optional ZK clear-sign bundle ────────────────
    //
    // When present, the NS world is attesting that `readable` is a
    // human-sensible interpretation of `calldata`, and the secure
    // world must display `readable` instead of dumping the raw
    // calldata hex. The Groth16 proof binds Poseidon(calldata) and
    // Poseidon(readable) to a circuit-specific VK that was committed
    // to in the firmware's Merkle-rooted VK DB.
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

        // HIGH-4 fix: reject outright if the inner calldata exceeds
        // the ZK circuit's attestation window. A longer calldata is
        // partially bound (first 164 bytes) and the trailing bytes
        // slip through into the signed tx unattested.
        if inner_data.len() > ZK_MAX_CALLDATA {
            None
        } else {
            // Verify the VK bundle against the firmware-embedded Merkle
            // root, compute Poseidon public signals, and run Groth16.
            match crate::zk::verify_clear_sign_proof(
                proof_bytes,
                calldata_bytes,
                readable_bytes,
                vk_bundle,
            ) {
                Ok(verified) => {
                    // HIGH-5 fix: cross-check that the VK's claimed
                    // (chain_id, contract) matches the tx being signed.
                    // Without this a VK for protocol A on chain A could
                    // validate calldata routed at protocol B on chain B.
                    if verified.chain_id != chain_id || verified.contract != to_address {
                        None
                    } else {
                        // The bound calldata MUST match what the user
                        // actually wants to sign, otherwise a malicious
                        // NS could attest to a different readable
                        // string and have the secure world sign an
                        // unrelated tx.
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
        // ZK clear-sign: the NS-attested readable string is on screen
        // instead of the raw calldata.
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
    let _erc20_type_marker: Option<Erc20Call> = None; // suppress unused import when cfg trims
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

    // ── 7. Read slot state from flash for this chain, decide mode ──
    //
    // CRIT-1 fix: read per-chain. The log-structured store keeps one
    // latest record per chain_id, so signing on chain B cannot overwrite
    // chain A's next_q the way the v1 single-record store did.
    let existing = jardin_flash::read_latest_for(chain_id);
    let mode = match &existing {
        Some(s)
            if s.is_registered()
                && (s.next_q as usize) <= jardin_fosc::params::Q_MAX =>
        {
            Mode::Normal(s.clone())
        }
        Some(s)
            if s.is_registered()
                && (s.next_q as usize) > jardin_fosc::params::Q_MAX =>
        {
            Mode::Rotate { from: s.clone() }
        }
        _ => Mode::FirstSign,
    };

    // ── 8. Reconstruct entropy + derive JARDIN master ──────────────
    //
    // HIGH-6 fix: every stack-local copy of a secret is wrapped in
    // Zeroizing so a panic or early return can't leave bytes on the
    // stack for a subsequent shorter-frame to expose.
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
            Err(_) => {
                return NscStatus::CryptoError as u32;
            }
        },
    );
    // `entropy_blob` and `master_secret` drop on scope exit; no manual
    // zeroize needed.
    let jardin_master_entropy: Zeroizing<[u8; 32]> =
        Zeroizing::new(crate::crypto::jardin_master_entropy_from_entropy(&*entropy));

    // ── 9. Build Type 2 callData: execute(to, value, data) ──────────
    let t2_exec = match reconstruct_execute_calldata(&tx_for_display, inner_data) {
        Ok(c) => c,
        Err(_) => {
            entropy.zeroize();
            return NscStatus::CryptoError as u32;
        }
    };

    // ── 10. Nonces per UserOp ──────────────────────────────────────
    //
    // Companion supplies the base nonce. When Type 1 is present it
    // runs FIRST at the supplied nonce; Type 2 then goes at nonce+1.
    // In Normal mode Type 2 goes at the supplied nonce directly.
    let needs_type1 = !matches!(mode, Mode::Normal(_));
    let mut type2_nonce = nonce;
    if needs_type1 {
        add_one_to_be_u256(&mut type2_nonce);
    }

    // ── 11. Determine the slot_index and initialise the slot ────────
    //
    // M4 fix: the NS-supplied `slot_index_hint` is unvalidated
    // attacker input. On FirstSign we bind it to 0 — there is no
    // legitimate reason for a fresh chain to skip straight to a
    // non-zero slot, and an attacker could otherwise pick a slot
    // index that collides with one they later want to rotate into.
    let new_slot_index = match &mode {
        Mode::FirstSign => {
            let _ = slot_index_hint;
            0
        }
        Mode::Rotate { from } => from.slot_index + 1,
        Mode::Normal(s) => s.slot_index,
    };

    let need_keygen = match &mode {
        Mode::FirstSign | Mode::Rotate { .. } => true,
        Mode::Normal(stored) => unsafe {
            match &*core::ptr::addr_of!(super::state::JARDIN_SLOT) {
                Some(cur) => {
                    cur.pk_seed[..16] != stored.sub_pk_seed
                        || cur.pk_root[..16] != stored.sub_pk_root
                        || cur.next_q != stored.next_q
                }
                None => true,
            }
        },
    };

    if need_keygen {
        ui::show_progress("Slot keygen", 0);
        let slot_entropy =
            jardin_fosc::hash::jardin_slot_entropy(&*jardin_master_entropy, new_slot_index);
        let mut slot = jardin_fosc::JardinSlot::keygen_with_progress(slot_entropy, |p| {
            ui::show_progress("Slot keygen", p);
        });
        if let Mode::Normal(stored) = &mode {
            slot.next_q = stored.next_q;
        }
        unsafe {
            *core::ptr::addr_of_mut!(super::state::JARDIN_SLOT) = Some(slot);
        }
        super::state::with_state(|s| {
            s.jardin_master_entropy.zeroize();
            s.jardin_master_entropy = *jardin_master_entropy;
            s.jardin_master_derived = true;
            s.jardin_chain_id = chain_id;
            s.jardin_slot_index = new_slot_index;
            s.jardin_slot_active = true;
        });
    }

    // ── 12. Type 1 (if needed) ─────────────────────────────────────
    //
    // HIGH-11 fix: wrap in Zeroizing so any error-path early return
    // (or panic before we hand the bytes to NS) wipes the in-flight
    // signature rather than leaving it on the stack.
    let mut type1_out: Zeroizing<[u8; JARDIN_TYPE1_LEN]> =
        Zeroizing::new([0u8; JARDIN_TYPE1_LEN]);
    let mut h_r = [0u8; 32];

    if needs_type1 {
        ui::show_status("Slot register", "building type 1");

        // Deterministic r per (master, slot_index). H(r) is the on-chain slotKey.
        let r = jardin_fosc::hash::jardin_slot_r(&*jardin_master_entropy, new_slot_index);
        h_r = jardin_fosc::hash::keccak256(&r);

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

        // Type 1 userOpHash (EntryPoint v0.9).
        let t1_params = AaUserOpParamsV09 {
            sender,
            entry_point,
            chain_id,
            nonce: U256(nonce),
            init_code_hash: KECCAK_EMPTY,
            account_gas_limits,
            pre_verification_gas: U256(pre_verification_gas),
            gas_fees,
            paymaster_and_data_hash,
        };
        let t1_call_hash = keccak256(t1_exec.as_slice());
        let t1_user_op_hash = compute_user_op_hash_v09(&t1_params, &t1_call_hash);

        // C11 keygen + sign.
        ui::show_progress("C11 keygen", 0);
        let (c11_sk, _c11_pk_seed_32, _c11_pk_root_32) =
            crate::crypto::derive_c11_master_keypair_from_entropy_with_progress(
                &*entropy,
                |p| ui::show_progress("C11 keygen", p),
            );
        let c11_sig = match crate::crypto::c11_sign_verified_with_progress(
            &c11_sk,
            &t1_user_op_hash,
            c11_sign_progress,
        ) {
            Ok(s) => s,
            Err(_) => {
                entropy.zeroize();
                return NscStatus::CryptoError as u32;
            }
        };
        drop(c11_sk); // Zeroise on drop.

        // Extract the newly-built sub-key commitments from the slot.
        let (sub_pk_seed, sub_pk_root) = unsafe {
            match &*core::ptr::addr_of!(super::state::JARDIN_SLOT) {
                Some(s) => {
                    let mut seed = [0u8; 16];
                    let mut root = [0u8; 16];
                    seed.copy_from_slice(&s.pk_seed[..16]);
                    root.copy_from_slice(&s.pk_root[..16]);
                    (seed, root)
                }
                None => {
                    entropy.zeroize();
                    return NscStatus::InternalError as u32;
                }
            }
        };

        // Assemble Type 1 payload.
        type1_out[0] = JARDIN_TYPE1_MARKER;
        type1_out[1..33].copy_from_slice(&r);
        type1_out[33..49].copy_from_slice(&sub_pk_seed);
        type1_out[49..65].copy_from_slice(&sub_pk_root);
        type1_out[65..65 + C11_SIG_LEN].copy_from_slice(&c11_sig);
    } else if let Mode::Normal(stored) = &mode {
        h_r = stored.h_r;
    }

    // ── 13. Type 2 sign the user's userOpHash ──────────────────────
    let (sub_pk_seed_16, sub_pk_root_16) = unsafe {
        match &*core::ptr::addr_of!(super::state::JARDIN_SLOT) {
            Some(s) => {
                let mut seed = [0u8; 16];
                let mut root = [0u8; 16];
                seed.copy_from_slice(&s.pk_seed[..16]);
                root.copy_from_slice(&s.pk_root[..16]);
                (seed, root)
            }
            None => {
                entropy.zeroize();
                return NscStatus::InternalError as u32;
            }
        }
    };

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

    ui::show_progress("FORS+C sign", 0);
    let slot_ref = unsafe {
        match &mut *core::ptr::addr_of_mut!(super::state::JARDIN_SLOT) {
            Some(s) => s,
            None => {
                entropy.zeroize();
                return NscStatus::InternalError as u32;
            }
        }
    };

    if slot_ref.is_exhausted() {
        entropy.zeroize();
        ui::show_status("Slot exhausted", "rotate");
        return NscStatus::SlotExhausted as u32;
    }

    let q_used = slot_ref.next_q;
    let sig = match slot_ref.sign(&t2_user_op_hash) {
        Ok(s) => s,
        Err(_) => {
            entropy.zeroize();
            return NscStatus::CryptoError as u32;
        }
    };
    // Verify-before-release. HIGH-3 fix: double-evaluate so a single
    // fault-injected bit-flip on the `if !` instruction or its
    // predicate register can't skip the gate and release an unverified
    // sig. Two independent evaluations plus a sentinel check raise the
    // cost of the attack from "one glitch" to "two perfectly-placed
    // glitches on the same instruction boundary".
    let v1 = jardin_fosc::verify(
        &slot_ref.pk_seed,
        &slot_ref.pk_root,
        &t2_user_op_hash,
        &sig.data[..sig.len],
    );
    let v2 = jardin_fosc::verify(
        &slot_ref.pk_seed,
        &slot_ref.pk_root,
        &t2_user_op_hash,
        &sig.data[..sig.len],
    );
    let ok_sentinel: u32 = if v1 && v2 { 0xA5A5_A5A5 } else { 0x5A5A_5A5A };
    if ok_sentinel != 0xA5A5_A5A5 || !v1 || !v2 {
        entropy.zeroize();
        ui::show_status("Sig verify", "FAIL");
        return NscStatus::CryptoError as u32;
    }

    // ── 14. Persist next_q BEFORE releasing bytes ──────────────────
    let mut new_state = SlotState {
        seq: 0,
        chain_id,
        slot_index: new_slot_index,
        next_q: q_used + 1,
        flags: FLAG_SLOT_REGISTERED,
        h_r,
        sub_pk_seed: sub_pk_seed_16,
        sub_pk_root: sub_pk_root_16,
    };
    if let Err(e) = jardin_flash::write(&new_state) {
        entropy.zeroize();
        new_state.zeroize();
        // Emit a SECSR diagnostic onto the OLED so we can tell WRPERR
        // (0x10) from PGSERR (0x80) from VerifyFailed without hooking
        // up a debugger. `hex_line` lives in the ui module.
        let (kind, detail) = match e {
            jardin_flash::FlashError::EraseHardware { sr, page } => {
                let mut buf = [0u8; 14];
                let _ = u32_hex(&mut buf, sr);
                buf[8] = b' ';
                buf[9] = b'P';
                buf[10] = b':';
                let p = (page & 0xFF) as u8;
                buf[11] = hex_nib(p >> 4);
                buf[12] = hex_nib(p & 0x0F);
                buf[13] = 0;
                ("Erase SR:", copy_to_static(&buf))
            }
            jardin_flash::FlashError::ProgramHardware { sr, addr } => {
                let mut buf = [0u8; 14];
                let _ = u32_hex(&mut buf, sr);
                buf[8] = b' ';
                buf[9] = b'@';
                buf[10] = hex_nib(((addr >> 12) & 0xF) as u8);
                buf[11] = hex_nib(((addr >> 8) & 0xF) as u8);
                buf[12] = hex_nib(((addr >> 4) & 0xF) as u8);
                buf[13] = hex_nib((addr & 0xF) as u8);
                ("Prog SR:", copy_to_static(&buf))
            }
            jardin_flash::FlashError::VerifyFailed { addr, byte_idx, .. } => {
                let mut buf = [0u8; 14];
                buf[0] = b'@';
                buf[1] = hex_nib(((addr >> 12) & 0xF) as u8);
                buf[2] = hex_nib(((addr >> 8) & 0xF) as u8);
                buf[3] = hex_nib(((addr >> 4) & 0xF) as u8);
                buf[4] = hex_nib((addr & 0xF) as u8);
                buf[5] = b'+';
                buf[6] = hex_nib(((byte_idx >> 4) & 0xF) as u8);
                buf[7] = hex_nib((byte_idx & 0xF) as u8);
                buf[8] = 0;
                ("VerifyFail:", copy_to_static(&buf))
            }
        };
        ui::show_status(kind, detail);
        return NscStatus::InternalError as u32;
    }
    new_state.zeroize();

    // ── 15. Assemble output bundle ─────────────────────────────────
    let mut write_pos: usize = 0;
    let type1_len = if needs_type1 { JARDIN_TYPE1_LEN } else { 0 };
    let t1_len_be = (type1_len as u32).to_be_bytes();
    for i in 0..4 {
        core::ptr::write_volatile(out_ptr.add(write_pos + i), t1_len_be[i]);
    }
    write_pos += 4;
    if needs_type1 {
        for i in 0..JARDIN_TYPE1_LEN {
            core::ptr::write_volatile(out_ptr.add(write_pos + i), type1_out[i]);
        }
        write_pos += JARDIN_TYPE1_LEN;
    }

    let type2_total = JARDIN_TYPE2_HEADER_LEN + sig.len;
    debug_assert_eq!(
        type2_total,
        JARDIN_TYPE2_HEADER_LEN + JARDIN_FORSC_BODY + q_used as usize * 16
    );
    let t2_len_be = (type2_total as u32).to_be_bytes();
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
        core::ptr::write_volatile(out_ptr.add(write_pos + i), sub_pk_seed_16[i]);
    }
    write_pos += 16;
    for i in 0..16 {
        core::ptr::write_volatile(out_ptr.add(write_pos + i), sub_pk_root_16[i]);
    }
    write_pos += 16;
    for i in 0..sig.len {
        core::ptr::write_volatile(out_ptr.add(write_pos + i), sig.data[i]);
    }
    write_pos += sig.len;

    debug_assert!(write_pos <= MAX_JARDIN_RESPONSE_LEN);
    let _ = write_pos;

    // ── 16. Zeroise transients ─────────────────────────────────────
    entropy.zeroize();
    type1_out.zeroize();

    crate::timeout::reset_activity();
    ui::show_status("Signed", "");
    for _ in 0..3_000_000u32 {
        cortex_m::asm::nop();
    }
    ui::show_status("PQSigner OS", "Ready");

    NscStatus::Ok as u32
}

/// Increment the 64-bit sequence portion of an EntryPoint v0.9 nonce.
///
/// v0.9 nonces are `(key: 192) | (seq: 64)`. Incrementing across the
/// full 256-bit word would carry into the key field on overflow, which
/// silently changes the nonce key — a user-intent violation. We add 1
/// to the bottom 8 bytes ONLY, and the caller rejects the input when
/// `seq == 0xFF..FF` so overflow is impossible here (HIGH-17 fix).
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

fn c11_sign_progress(percent: u8) {
    crate::ui::show_progress("C11 sign", percent);
}

/// Hex-format a u32 as 8 ASCII chars into `out[..8]`.
fn u32_hex(out: &mut [u8; 14], v: u32) -> usize {
    for i in 0..8 {
        let nib = ((v >> ((7 - i) * 4)) & 0xF) as u8;
        out[i] = hex_nib(nib);
    }
    8
}

fn hex_nib(n: u8) -> u8 {
    match n & 0x0F {
        0..=9 => b'0' + n,
        _ => b'a' + (n - 10),
    }
}

/// Copy a nul-terminated ASCII buffer into a static and return it as a
/// `&'static str`. The underlying buffer is shared across calls but the
/// OLED renders immediately, so the stale-data window is a few
/// microseconds — acceptable for a diagnostic-only path.
fn copy_to_static(buf: &[u8; 14]) -> &'static str {
    static mut STATIC_MSG: [u8; 14] = [0u8; 14];
    unsafe {
        let dst = &mut *core::ptr::addr_of_mut!(STATIC_MSG);
        *dst = *buf;
        let end = dst.iter().position(|&b| b == 0).unwrap_or(dst.len());
        core::str::from_utf8_unchecked(&dst[..end])
    }
}

/// Decode a 16-byte big-endian slice as `u128`.
fn u128_from_be_16(bytes: &[u8]) -> u128 {
    debug_assert_eq!(bytes.len(), 16);
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&bytes[..16]);
    u128::from_be_bytes(buf)
}

/// Decode a 32-byte big-endian u256 as `u128`, saturating at `u128::MAX`.
/// Used for display only — the signed digest still carries the full
/// u256 value.
fn u128_saturating_from_u256(bytes: &[u8; 32]) -> u128 {
    for &b in &bytes[0..16] {
        if b != 0 {
            return u128::MAX;
        }
    }
    u128_from_be_16(&bytes[16..32])
}

//! Safe multisig (`approveHash`) EIP-712 typed-data clear-signing.
//!
//! Targets Safe contracts v1.3.0 and later — the dominant deployments on
//! Ethereum mainnet and L2s today. Older Safes (v1.1.x) used a domain
//! separator without `chainId`, which produces a different `safeTxHash`
//! and therefore self-rejects via the calldata cross-check below.
//!
//! ## How it differs from the CowSwap v3 path
//!
//! Both protocols are EIP-712 typed-data approvals signed by the
//! wallet, but the bind story is structurally different:
//!
//!   * **CowSwap setPreSignature**: the calldata carries an opaque
//!     `orderUid` (a 32-byte EIP-712 digest + 20-byte owner + 4-byte
//!     validTo). The order's actual *fields* are nowhere in the
//!     calldata, so the firmware needs a Groth16 proof to bring them
//!     on-device with cryptographic guarantee, then it cross-checks
//!     by re-deriving the orderUid from the proven canonical.
//!   * **Safe approveHash**: the calldata carries the EIP-712
//!     `safeTxHash` *itself*. The trailer brings the canonical SafeTx
//!     fields plus the raw inner-call data. The firmware natively
//!     keccaks (raw_data → data_hash, then canonical → safeTxHash)
//!     and byte-compares the result against `inner_data[4..36]`. No
//!     Groth16 needed because the bind is just keccak chains and
//!     keccak is already a native primitive.
//!
//! This module exposes:
//!
//!   * [`SafeTx`] — typed accessor over a verified canonical buffer.
//!   * [`decode_canonical`] — parse + range-check the 281-byte canonical.
//!   * [`compute_safe_tx_hash`] — natively recompute the Safe v1.3.0+
//!     EIP-712 digest from a canonical buffer.
//!   * [`verify`] — top-level trailer verification that
//!     `cmd_sign_userop` invokes (gated off host tests like CoW v3).

use super::{keccak, Eip712Error};
use sphincs_tz_shared::{
    SAFE_DOMAIN_TYPEHASH, SAFE_OFF_BASE_GAS, SAFE_OFF_CHAIN_ID, SAFE_OFF_DATA_HASH,
    SAFE_OFF_GAS_PRICE, SAFE_OFF_GAS_TOKEN, SAFE_OFF_NONCE, SAFE_OFF_OPERATION,
    SAFE_OFF_REFUND_RECEIVER, SAFE_OFF_SAFE_ADDRESS, SAFE_OFF_SAFE_TX_GAS, SAFE_OFF_TO,
    SAFE_OFF_VALUE, SAFE_TX_TYPEHASH, SAFE_V1_CANONICAL_LEN,
};

// Unlike the CoW v3 path (which calls into `crate::zk` and so is
// `#[cfg(not(test))]`-gated), the Safe verifier only depends on
// keccak and our own decode + digest helpers — all available on host
// — so it compiles for both firmware and unit tests.
pub mod verify;
pub use verify::{verify_and_bind_trailer, VerifiedSafeV1};

#[cfg(test)]
mod test_vectors;

#[cfg(test)]
mod extra_tests;

// ---------------------------------------------------------------------------
// Decoded SafeTx
// ---------------------------------------------------------------------------

/// Decoded SafeTx fields. Borrows nothing — every field is owned and
/// the returned struct is `Copy`. Mirrors Safe's Solidity struct order
/// for the EIP-712 typehash, with byte arrays preserved at their
/// natural width (addresses 20 B, uint256 32 B BE).
#[derive(Clone, Copy, Debug)]
pub struct SafeTx {
    pub chain_id: u64,
    pub safe_address: [u8; 20],
    pub to: [u8; 20],
    pub value: [u8; 32],
    pub data_hash: [u8; 32],
    /// Operation byte: `0` = Call, `1` = DelegateCall. Other values
    /// are rejected by [`decode_canonical`].
    pub operation: u8,
    pub safe_tx_gas: [u8; 32],
    pub base_gas: [u8; 32],
    pub gas_price: [u8; 32],
    pub gas_token: [u8; 20],
    pub refund_receiver: [u8; 20],
    pub nonce: [u8; 32],
}

/// Parse the 281-byte canonical packed SafeTx into structured fields.
///
/// The only range check today is on `operation`: Safe's Solidity
/// definition uses an `Enum.Operation` whose only legal values are 0
/// (`Call`) and 1 (`DelegateCall`). Anything else is rejected here so
/// `compute_safe_tx_hash` and the rendering path never see an invalid
/// canonical.
pub fn decode_canonical(canonical: &[u8; SAFE_V1_CANONICAL_LEN]) -> Result<SafeTx, Eip712Error> {
    let chain_id = u64::from_be_bytes([
        canonical[SAFE_OFF_CHAIN_ID],
        canonical[SAFE_OFF_CHAIN_ID + 1],
        canonical[SAFE_OFF_CHAIN_ID + 2],
        canonical[SAFE_OFF_CHAIN_ID + 3],
        canonical[SAFE_OFF_CHAIN_ID + 4],
        canonical[SAFE_OFF_CHAIN_ID + 5],
        canonical[SAFE_OFF_CHAIN_ID + 6],
        canonical[SAFE_OFF_CHAIN_ID + 7],
    ]);
    let mut safe_address = [0u8; 20];
    safe_address.copy_from_slice(&canonical[SAFE_OFF_SAFE_ADDRESS..SAFE_OFF_SAFE_ADDRESS + 20]);
    let mut to = [0u8; 20];
    to.copy_from_slice(&canonical[SAFE_OFF_TO..SAFE_OFF_TO + 20]);
    let mut value = [0u8; 32];
    value.copy_from_slice(&canonical[SAFE_OFF_VALUE..SAFE_OFF_VALUE + 32]);
    let mut data_hash = [0u8; 32];
    data_hash.copy_from_slice(&canonical[SAFE_OFF_DATA_HASH..SAFE_OFF_DATA_HASH + 32]);
    let operation = canonical[SAFE_OFF_OPERATION];
    if operation > 1 {
        return Err(Eip712Error::EnumOutOfRange);
    }
    let mut safe_tx_gas = [0u8; 32];
    safe_tx_gas.copy_from_slice(&canonical[SAFE_OFF_SAFE_TX_GAS..SAFE_OFF_SAFE_TX_GAS + 32]);
    let mut base_gas = [0u8; 32];
    base_gas.copy_from_slice(&canonical[SAFE_OFF_BASE_GAS..SAFE_OFF_BASE_GAS + 32]);
    let mut gas_price = [0u8; 32];
    gas_price.copy_from_slice(&canonical[SAFE_OFF_GAS_PRICE..SAFE_OFF_GAS_PRICE + 32]);
    let mut gas_token = [0u8; 20];
    gas_token.copy_from_slice(&canonical[SAFE_OFF_GAS_TOKEN..SAFE_OFF_GAS_TOKEN + 20]);
    let mut refund_receiver = [0u8; 20];
    refund_receiver
        .copy_from_slice(&canonical[SAFE_OFF_REFUND_RECEIVER..SAFE_OFF_REFUND_RECEIVER + 20]);
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&canonical[SAFE_OFF_NONCE..SAFE_OFF_NONCE + 32]);

    Ok(SafeTx {
        chain_id,
        safe_address,
        to,
        value,
        data_hash,
        operation,
        safe_tx_gas,
        base_gas,
        gas_price,
        gas_token,
        refund_receiver,
        nonce,
    })
}

// ---------------------------------------------------------------------------
// EIP-712 struct hash
// ---------------------------------------------------------------------------

/// Compute the SafeTx EIP-712 struct hash from a decoded order.
///
/// Layout follows Safe's Solidity `encodeTransactionData`:
///
/// ```text
///   keccak256(
///     SAFE_TX_TYPEHASH ||
///     to                                  (left-padded to 32) ||
///     value                               (uint256) ||
///     data_hash                           (keccak256(data), bytes32) ||
///     operation                           (left-padded to 32) ||
///     safe_tx_gas                         (uint256) ||
///     base_gas                            (uint256) ||
///     gas_price                           (uint256) ||
///     gas_token                           (left-padded to 32) ||
///     refund_receiver                     (left-padded to 32) ||
///     nonce                               (uint256)
///   )
/// ```
///
/// 11 × 32 = 352 bytes total preimage.
pub fn struct_hash(tx: &SafeTx) -> [u8; 32] {
    let mut buf = [0u8; 32 * 11];
    buf[0..32].copy_from_slice(&SAFE_TX_TYPEHASH);
    // [1] to (left-padded address)
    buf[32 + 12..32 + 32].copy_from_slice(&tx.to);
    // [2] value (uint256)
    buf[64..96].copy_from_slice(&tx.value);
    // [3] data_hash (bytes32)
    buf[96..128].copy_from_slice(&tx.data_hash);
    // [4] operation (uint8 left-padded)
    buf[128 + 31] = tx.operation;
    // [5] safe_tx_gas (uint256)
    buf[160..192].copy_from_slice(&tx.safe_tx_gas);
    // [6] base_gas (uint256)
    buf[192..224].copy_from_slice(&tx.base_gas);
    // [7] gas_price (uint256)
    buf[224..256].copy_from_slice(&tx.gas_price);
    // [8] gas_token (left-padded address)
    buf[256 + 12..256 + 32].copy_from_slice(&tx.gas_token);
    // [9] refund_receiver (left-padded address)
    buf[288 + 12..288 + 32].copy_from_slice(&tx.refund_receiver);
    // [10] nonce (uint256)
    buf[320..352].copy_from_slice(&tx.nonce);

    keccak(&buf)
}

// ---------------------------------------------------------------------------
// EIP-712 domain separator (Safe v1.3.0+)
// ---------------------------------------------------------------------------

/// `keccak256(abi.encode(SAFE_DOMAIN_TYPEHASH, chain_id, verifying_contract))`.
///
/// Safe v1.3.0+ uses a slimmer domain than CoW (no `name` / `version`
/// — just `chainId` + `verifyingContract`), so it gets its own helper
/// rather than reusing the protocol-agnostic
/// `eip712_domain_separator` in the parent module.
pub fn domain_separator(chain_id: u64, verifying_contract: &[u8; 20]) -> [u8; 32] {
    let mut buf = [0u8; 32 * 3];
    buf[0..32].copy_from_slice(&SAFE_DOMAIN_TYPEHASH);
    // chainId as uint256: 24 zero bytes, then 8 BE bytes.
    buf[32 + 24..32 + 32].copy_from_slice(&chain_id.to_be_bytes());
    // verifyingContract as address (left-padded to 32 bytes).
    buf[64 + 12..64 + 32].copy_from_slice(verifying_contract);
    keccak(&buf)
}

// ---------------------------------------------------------------------------
// Top-level digest entry point
// ---------------------------------------------------------------------------

/// Compute the EIP-712 `safeTxHash` from a 281-byte canonical SafeTx.
///
/// Returns the 32-byte digest the on-chain Safe will check
/// `approvedHashes[msg.sender][safeTxHash]` against. The firmware
/// byte-compares this against `inner_data[4..36]` (the bytes32 argument
/// to `approveHash`) — a successful match means the canonical we just
/// rendered to the OLED is exactly the SafeTx that on-chain `approveHash`
/// will record.
pub fn compute_safe_tx_hash(
    canonical: &[u8; SAFE_V1_CANONICAL_LEN],
) -> Result<[u8; 32], Eip712Error> {
    let tx = decode_canonical(canonical)?;
    let dom = domain_separator(tx.chain_id, &tx.safe_address);
    let sh = struct_hash(&tx);
    Ok(super::final_digest(&dom, &sh))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod typehash_tests {
    //! Sanity-check that the hardcoded typehash byte arrays match the
    //! preimages they claim. Catches typos in the `[u8; 32]` literals
    //! before they propagate into a fixture mismatch.

    use super::*;

    const SAFE_DOMAIN_TYPEHASH_PREIMAGE: &[u8] =
        b"EIP712Domain(uint256 chainId,address verifyingContract)";

    const SAFE_TX_TYPEHASH_PREIMAGE: &[u8] = b"SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)";

    #[test]
    fn safe_domain_typehash_matches_preimage() {
        assert_eq!(keccak(SAFE_DOMAIN_TYPEHASH_PREIMAGE), SAFE_DOMAIN_TYPEHASH);
    }

    #[test]
    fn safe_tx_typehash_matches_preimage() {
        assert_eq!(keccak(SAFE_TX_TYPEHASH_PREIMAGE), SAFE_TX_TYPEHASH);
    }
}

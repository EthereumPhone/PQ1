//! Context-binding cross-checks. After `bundle::verify_erc7730_bundle`
//! succeeds we know the IR is one of the descriptors the firmware was
//! built to trust. We do NOT yet know it applies to *this* sign request.
//!
//! ERC-7730 §1 ("Binding Constraints") makes that the wallet's
//! responsibility:
//!
//! > Wallets MUST verify that the ABI is applicable to the contract
//! > being called.
//! >
//! > Wallets MUST verify that the target chain and contract address of
//! > the containing transaction MUST match one of these deployment
//! > options.
//! >
//! > [For EIP-712:] Wallets MUST verify that each key-value pair in
//! > this domain binding matches.
//!
//! These two functions are the only place those checks live, so they
//! can be FI-hardened (sentinel double-check) and code-reviewed in
//! isolation. The caller passes in the IR view from
//! `VerifiedDescriptor` plus the bytes from the parsed transaction or
//! EIP-712 payload.

use crate::ir::{ContextKind, Erc7730Ir};

/// All the ways a descriptor can fail to apply. Each variant maps to a
/// distinct on-device status line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindingError {
    /// Descriptor declares EIP-712 context but caller is signing
    /// contract calldata (or vice versa).
    WrongContextKind,
    /// `ir.chain_id` does not match `tx.chain_id` /
    /// `domain.chainId`.
    ChainIdMismatch,
    /// `ir.contract` does not match `tx.to` /
    /// `domain.verifyingContract`.
    ContractMismatch,
    /// `ir.domain_separator` does not match the
    /// caller-computed value (EIP-712 only).
    DomainSeparatorMismatch,
}

/// Check that the descriptor's contract-context binding matches the
/// transaction the user is about to sign.
///
/// Caller passes the parsed `chain_id` and `to` from the inner
/// EIP-1559 envelope (NOT from any companion-supplied trailer). This
/// is the load-bearing check that prevents a hostile companion from
/// shipping a USDC descriptor while signing a transfer to an
/// attacker-controlled contract.
pub fn cross_check_contract(
    ir: &Erc7730Ir<'_>,
    tx_chain_id: u64,
    tx_to: &[u8; 20],
) -> Result<(), BindingError> {
    if !matches!(ir.context_kind, ContextKind::Contract) {
        return Err(BindingError::WrongContextKind);
    }
    if ir.chain_id != tx_chain_id {
        return Err(BindingError::ChainIdMismatch);
    }
    if &ir.contract != tx_to {
        return Err(BindingError::ContractMismatch);
    }
    Ok(())
}

/// Check that the descriptor's EIP-712 context binding matches the
/// typed-data payload the user is about to sign.
///
/// The `domain_separator` argument MUST be the value computed by the
/// secure-world EIP-712 verifier from the inbound payload — NOT a
/// value supplied by the companion. Same load-bearing guarantee as
/// `cross_check_contract`.
pub fn cross_check_eip712(
    ir: &Erc7730Ir<'_>,
    domain_chain_id: u64,
    domain_verifying_contract: &[u8; 20],
    domain_separator: &[u8; 32],
) -> Result<(), BindingError> {
    if !matches!(ir.context_kind, ContextKind::Eip712) {
        return Err(BindingError::WrongContextKind);
    }
    if ir.chain_id != domain_chain_id {
        return Err(BindingError::ChainIdMismatch);
    }
    if &ir.contract != domain_verifying_contract {
        return Err(BindingError::ContractMismatch);
    }
    if &ir.domain_separator != domain_separator {
        return Err(BindingError::DomainSeparatorMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{Erc7730Ir, CTX_CONTRACT, CTX_EIP712, HEADER_LEN, SCHEMA_VER};

    fn ir_bytes(ctx_kind: u8, chain_id: u64, contract: [u8; 20], domain_sep: [u8; 32]) -> std::vec::Vec<u8> {
        let mut buf = std::vec![0u8; HEADER_LEN];
        buf[0] = SCHEMA_VER;
        buf[1] = ctx_kind;
        buf[2..10].copy_from_slice(&chain_id.to_be_bytes());
        buf[10..30].copy_from_slice(&contract);
        buf[62..94].copy_from_slice(&domain_sep);
        let pool_off = HEADER_LEN as u16;
        buf[126..128].copy_from_slice(&pool_off.to_be_bytes());
        buf[128..130].copy_from_slice(&pool_off.to_be_bytes());
        buf[132..134].copy_from_slice(&1u16.to_be_bytes());
        buf.push(0u8);
        buf
    }

    #[test]
    fn contract_happy_path() {
        let addr = [0x11u8; 20];
        let bytes = ir_bytes(CTX_CONTRACT, 1, addr, [0u8; 32]);
        let ir = Erc7730Ir::parse(&bytes).unwrap();
        assert_eq!(cross_check_contract(&ir, 1, &addr), Ok(()));
    }

    #[test]
    fn contract_chain_mismatch() {
        let addr = [0x11u8; 20];
        let bytes = ir_bytes(CTX_CONTRACT, 1, addr, [0u8; 32]);
        let ir = Erc7730Ir::parse(&bytes).unwrap();
        assert_eq!(
            cross_check_contract(&ir, 137, &addr),
            Err(BindingError::ChainIdMismatch)
        );
    }

    #[test]
    fn contract_address_mismatch() {
        let addr = [0x11u8; 20];
        let other = [0x22u8; 20];
        let bytes = ir_bytes(CTX_CONTRACT, 1, addr, [0u8; 32]);
        let ir = Erc7730Ir::parse(&bytes).unwrap();
        assert_eq!(
            cross_check_contract(&ir, 1, &other),
            Err(BindingError::ContractMismatch)
        );
    }

    #[test]
    fn contract_rejects_eip712_descriptor() {
        let addr = [0x11u8; 20];
        let domain_sep = [0x55u8; 32];
        let bytes = ir_bytes(CTX_EIP712, 1, addr, domain_sep);
        let ir = Erc7730Ir::parse(&bytes).unwrap();
        assert_eq!(
            cross_check_contract(&ir, 1, &addr),
            Err(BindingError::WrongContextKind)
        );
    }

    #[test]
    fn eip712_happy_path() {
        let addr = [0x33u8; 20];
        let domain_sep = [0x55u8; 32];
        let bytes = ir_bytes(CTX_EIP712, 1, addr, domain_sep);
        let ir = Erc7730Ir::parse(&bytes).unwrap();
        assert_eq!(
            cross_check_eip712(&ir, 1, &addr, &domain_sep),
            Ok(())
        );
    }

    #[test]
    fn eip712_domain_sep_mismatch() {
        let addr = [0x33u8; 20];
        let domain_sep = [0x55u8; 32];
        let bytes = ir_bytes(CTX_EIP712, 1, addr, domain_sep);
        let ir = Erc7730Ir::parse(&bytes).unwrap();
        let wrong = [0x66u8; 32];
        assert_eq!(
            cross_check_eip712(&ir, 1, &addr, &wrong),
            Err(BindingError::DomainSeparatorMismatch)
        );
    }

    #[test]
    fn eip712_rejects_contract_descriptor() {
        let addr = [0x11u8; 20];
        let bytes = ir_bytes(CTX_CONTRACT, 1, addr, [0u8; 32]);
        let ir = Erc7730Ir::parse(&bytes).unwrap();
        assert_eq!(
            cross_check_eip712(&ir, 1, &addr, &[0u8; 32]),
            Err(BindingError::WrongContextKind)
        );
    }
}

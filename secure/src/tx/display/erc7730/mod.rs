//! ERC-7730 clear-signing renderer — UI-bound half.
//!
//! Pure-logic pieces (TLV parameter parser, visibility evaluator,
//! `RenderErr`) live at `crate::tx::erc7730_render::*` so host-test
//! builds (which gate out `crate::tx::display`) can still exercise
//! them. This module owns the [`Pages`]-using formatter dispatcher,
//! intent renderer, and nested-calldata recursor.
//!
//! Entry points:
//!
//! - [`render_erc7730_pages`] — contract context (EIP-1559 UserOp
//!   execution against a known smart contract).
//! - [`render_erc7730_eip712_pages`] — EIP-712 typed-data offchain
//!   signs driven by `OFFCHAIN_KIND_EIP712_TYPED = 2` (Step 7).
//!
//! Both consume a [`VerifiedDescriptor`] minted by Phase 3's bundle
//! verifier and produce a [`Pages`] object the existing
//! [`crate::ui::confirm::confirm`] loop drives.
//!
//! Returning [`RenderErr`] from the entry points is how the renderer
//! tells [`super::pick_sign_pages`] "I don't have a clean rendering
//! for this transaction — please fall through to the next ladder
//! rung." See the per-variant docs on
//! [`crate::tx::erc7730_render::RenderErr`].

mod calldata_nested;
mod formatters;
mod intent;

use crate::erc20::bundle::Erc20Metadata;
use crate::names::NameResolver;
use crate::tx::display::primitives::{
    chain_name, write_chain, write_fee_budget_row, write_gas, write_gwei, write_line,
    write_nonce_row, write_tip_row,
};
use crate::tx::eip1559::Eip1559Tx;
use crate::tx::erc7730::VerifiedDescriptor;
use crate::tx::erc7730_render::params::parse as parse_params;
use crate::tx::erc7730_render::visibility::{should_render, Action};
use crate::tx::erc7730_render::RenderErr;

use super::Pages;

/// Entry point for contract-context renders. Phase 4 wires this into
/// [`super::pick_sign_pages`] between the Safe-V1 rung and the
/// plain-ETH check.
pub fn render_erc7730_pages<'ir>(
    tx: &Eip1559Tx,
    inner_data: &[u8],
    descriptor: &'ir VerifiedDescriptor<'ir>,
    erc20: Option<&Erc20Metadata<'_>>,
    resolver: &NameResolver<'_>,
) -> Result<Pages, RenderErr> {
    // 1. Locate the format by 4-byte calldata selector.
    if inner_data.len() < 4 {
        return Err(RenderErr::NoFormat);
    }
    let selector: [u8; 4] = inner_data[..4].try_into().unwrap();
    let format = descriptor
        .ir
        .find_format_by_selector(&selector)
        .map_err(|_| RenderErr::Reject("7730 bad formats"))?
        .ok_or(RenderErr::NoFormat)?;
    let body = &inner_data[4..];

    // 2. Allocate the page buffer (grows via push_blank).
    let mut pages = Pages::with_len(0);

    // 3. Banner — page 0.
    intent::render_intent_banner(&mut pages, &descriptor.ir, &format)?;

    // 4. Iterate fields.
    render_fields(&mut pages, &descriptor.ir, &format, body, tx, erc20, resolver)?;

    // 5. Envelope pages (chain / fee / nonce). Mirrors the tail of the
    //    erc20_known renderer so the user always sees gas + chain
    //    information regardless of which descriptor lit up.
    append_envelope_pages(&mut pages, tx)?;

    // 6. Final confirm-button page.
    append_confirm_page(&mut pages)?;

    Ok(pages)
}

/// Entry point for EIP-712 typed-data renders driven by the
/// `OFFCHAIN_KIND_EIP712_TYPED = 2` sign path. Caller passes the
/// companion-supplied `primary_type_hash` + `encoded_data` so the
/// renderer can locate the right
/// [`pqsigner_erc7730::ir::FormatHeader`] and walk the typed-data
/// fields.
pub fn render_erc7730_eip712_pages<'ir>(
    chain_id: u64,
    verifying_contract: &[u8; 20],
    primary_type_hash: &[u8; 32],
    encoded_data: &[u8],
    descriptor: &'ir VerifiedDescriptor<'ir>,
    erc20: Option<&Erc20Metadata<'_>>,
    resolver: &NameResolver<'_>,
) -> Result<Pages, RenderErr> {
    // 1. Locate the format by primaryTypeHash[..4].
    let key: [u8; 4] = primary_type_hash[..4].try_into().unwrap();
    let format = descriptor
        .ir
        .find_format_by_selector(&key)
        .map_err(|_| RenderErr::Reject("7730 bad formats"))?
        .ok_or(RenderErr::NoFormat)?;

    // 2. Build a synthetic envelope tx so the formatters can render
    //    `@.chainId` / `@.to` / `@.value` against the EIP-712 domain.
    //    `value` defaults to zero (no on-chain transfer for typed-data
    //    signing); `to` is the verifying contract.
    let synth_tx = Eip1559Tx {
        chain_id,
        nonce: 0,
        max_priority_fee_per_gas: crate::tx::eip1559::U256::zero(),
        max_fee_per_gas: crate::tx::eip1559::U256::zero(),
        gas_limit: 0,
        to: Some(*verifying_contract),
        value: crate::tx::eip1559::U256::zero(),
        data_len: 0,
        access_list_count: 0,
        signing_hash: [0u8; 32],
    };

    let mut pages = Pages::with_len(0);
    intent::render_intent_banner(&mut pages, &descriptor.ir, &format)?;
    render_fields(
        &mut pages,
        &descriptor.ir,
        &format,
        encoded_data,
        &synth_tx,
        erc20,
        resolver,
    )?;
    append_eip712_chain_page(&mut pages, chain_id)?;
    append_confirm_page(&mut pages)?;
    Ok(pages)
}

fn render_fields(
    pages: &mut Pages,
    ir: &crate::tx::erc7730::Erc7730Ir<'_>,
    format: &crate::tx::erc7730::FormatHeader<'_>,
    body: &[u8],
    tx: &Eip1559Tx,
    erc20: Option<&Erc20Metadata<'_>>,
    resolver: &NameResolver<'_>,
) -> Result<(), RenderErr> {
    for field_result in format.fields() {
        let field = field_result.map_err(|_| RenderErr::Reject("7730 bad field"))?;
        let params = parse_params(ir, field.param_off)?;
        match should_render(&params, None) {
            Action::Render => formatters::dispatch(
                &field, pages, ir, body, tx, erc20, resolver, &params,
            )?,
            Action::Skip => continue,
            Action::Reject(msg) => return Err(RenderErr::Reject(msg)),
        }
    }
    Ok(())
}

fn append_envelope_pages(pages: &mut Pages, tx: &Eip1559Tx) -> Result<(), RenderErr> {
    // Chain.
    let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    write_line(pages.row_mut(p, 0), "Chain:");
    write_chain(pages.row_mut(p, 1), tx.chain_id);
    write_line(pages.row_mut(p, 2), chain_name(tx.chain_id));
    write_line(pages.row_mut(p, 3), "> next");

    // Fees.
    let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    write_line(pages.row_mut(p, 0), "Max fee:");
    let _ = write_gwei(pages.row_mut(p, 1), &tx.max_fee_per_gas);
    write_tip_row(pages.row_mut(p, 2), &tx.max_priority_fee_per_gas);
    write_line(pages.row_mut(p, 3), "> next");

    // Worst-case fee budget + gas.
    let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    write_line(pages.row_mut(p, 0), "Worst-case:");
    write_fee_budget_row(pages.row_mut(p, 1), &tx.max_fee_per_gas, tx.gas_limit);
    write_gas(pages.row_mut(p, 2), tx.gas_limit);
    write_line(pages.row_mut(p, 3), "> next");

    // Nonce.
    let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    write_nonce_row(pages.row_mut(p, 0), tx.nonce);
    write_line(pages.row_mut(p, 3), "> next");

    Ok(())
}

fn append_eip712_chain_page(pages: &mut Pages, chain_id: u64) -> Result<(), RenderErr> {
    let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    write_line(pages.row_mut(p, 0), "Chain:");
    write_chain(pages.row_mut(p, 1), chain_id);
    write_line(pages.row_mut(p, 2), chain_name(chain_id));
    write_line(pages.row_mut(p, 3), "> next");
    Ok(())
}

fn append_confirm_page(pages: &mut Pages) -> Result<(), RenderErr> {
    let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    write_line(pages.row_mut(p, 2), "L=Cancel");
    write_line(pages.row_mut(p, 3), "R=Confirm");
    Ok(())
}

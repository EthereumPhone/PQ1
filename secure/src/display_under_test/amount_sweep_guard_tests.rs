//! Guards against the 2026-11-14 bug class: a value the device can show as
//! an exact friendly decimal reaching the user as an integer (`... base
//! AAVE`, `... wei`), as an overflow banner, or not at all (a refusal
//! because a row was too narrow).
//!
//! * [`realistic_values_reach_the_user_as_exact_decimals`] drives realistic
//!   native sends, ERC-20 transfers/approvals and network fees through the
//!   real dispatcher AND the pixel emitter.
//! * [`pixel_lays_out_every_amount_its_page_shows`] pins that the pixel
//!   screen has room for every amount form its page painter picks, per row
//!   capacity, so no page/pixel pair can disagree into a refusal.
//!
//! The painters' own policy is pinned in
//! `pqsigner_erc7730::display::primitives::amount_form_policy_tests`.

extern crate std;

use std::{format, string::String, vec::Vec};

use super::dispatch::{pick_sign_pages, DispatchPageProofs};
use super::primitives::{native_amount_form, token_amount_form, AmountRows};
use super::px_lift::{self, Body, ContentInputs};
use super::safe_screens_render_pure_tests::screen_text;
use super::screen_kit::{native_amount, token_amount_as_page};
use super::trailer_screens::TrailerSet;
use super::userop_screens::UserOpInputs;
use super::userop_screens_render_pure_tests::{append_handler_trailers, tx, Facts, BASE, RECIPIENT};
use crate::erc20::bundle::Erc20Metadata;
use crate::names::NameResolver;
use crate::tx::eip1559::{Eip1559Tx, U256};
use pqsigner_ui_px::fit::{layout_amount_or_wrap, Region};
use pqsigner_ui_px::Screens;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    /// Uniform in `lo..=hi`.
    fn range(&mut self, lo: u128, hi: u128) -> u128 {
        let wide = (u128::from(self.next()) << 64) | u128::from(self.next());
        lo + wide % (hi - lo + 1)
    }

    /// Log-uniform in `1..10^exp`: every magnitude equally likely.
    fn magnitude(&mut self, exp: u32) -> u128 {
        let e = u32::try_from(self.range(1, u128::from(exp.max(1)))).unwrap();
        self.range(1, 10u128.pow(e.min(38)))
    }
}

fn u256(v: u128) -> U256 {
    let mut b = [0u8; 32];
    b[16..].copy_from_slice(&v.to_be_bytes());
    U256(b)
}

fn erc20_call(selector: [u8; 4], who: [u8; 20], amount: u128) -> [u8; 68] {
    let mut d = [0u8; 68];
    d[..4].copy_from_slice(&selector);
    d[16..36].copy_from_slice(&who);
    d[52..68].copy_from_slice(&amount.to_be_bytes());
    d
}

/// Dispatch, then emit the pixel screens; the screens' text, or why not.
fn sign_screens(t: &Eip1559Tx, data: &[u8], erc20: Option<&Erc20Metadata<'_>>) -> Result<String, &'static str> {
    let resolver = NameResolver::new();
    let facts = Facts::new(t.chain_id, t.to.expect("call"), data, false, false, false);
    let mut proofs = DispatchPageProofs::new();
    proofs.fail_initialize();
    let mut pages = pick_sign_pages(t, data, &facts.sender, None, None, None, None, erc20, None, &resolver, &mut proofs)
        .map_err(|_| "the dispatcher refused")?;
    let trailer = facts.trailer(t, TrailerSet::Sign);
    append_handler_trailers(&mut pages, &trailer);
    let body = UserOpInputs { tx: t, inner_data: data, erc20, selector: None, resolver: &resolver };
    let inputs = ContentInputs { body: Body::UserOp(body), trailers: &trailer };
    let mut screens = Screens::blank();
    px_lift::emit_content(&mut screens, &inputs).map_err(|_| "the pixel emitter refused")?;
    Ok(screen_text(&screens))
}

/// A line that shows an integer, a banner or a cut where a decimal fits.
fn unfriendly(text: &str) -> Option<&'static str> {
    text.lines().map(str::trim).find_map(|l| {
        if l == "wei" || l.ends_with(" wei") {
            Some("wei shown")
        } else if l.contains("base ") {
            Some("base units shown")
        } else if l.contains("OVF") || l.contains("OVERFLOW") || l.contains("too big") {
            Some("overflow shown")
        } else {
            None
        }
    })
}

#[test]
fn realistic_values_reach_the_user_as_exact_decimals() {
    let mut rng = Rng(0x1234_5678_9abc_def1);
    let tokens: [(u8, &[u8]); 5] = [(18, b"AAVE"), (6, b"USDC"), (18, b"TOSHI"), (8, b"cbBTC"), (18, b"stETH")];
    let mut failures: Vec<String> = Vec::new();
    let mut check = |what: String, result: Result<String, &'static str>| match result {
        Err(why) => failures.push(format!("{what}: {why}")),
        Ok(text) => {
            if let Some(why) = unfriendly(&text) {
                failures.push(format!("{what}: {why}\n{text}"));
            }
        }
    };
    for chain in [BASE, 1u64] {
        for i in 0..1500u32 {
            // Network fees as wallets set them: any wei precision, tip up to
            // the max, gas from a plain send to a big batch.
            let (max_fee, gas) = if chain == BASE {
                (rng.range(1_000_000, 60_000_000), rng.range(21_000, 3_000_000))
            } else {
                (rng.range(100_000_000, 300_000_000_000), rng.range(21_000, 3_000_000))
            };
            let tip = rng.range(0, max_fee);
            let mut t = tx(chain, RECIPIENT, rng.magnitude(18), 0);
            t.max_fee_per_gas = u256(max_fee);
            t.max_priority_fee_per_gas = u256(tip);
            t.gas_limit = u64::try_from(gas).unwrap();
            check(format!("chain {chain} fee {max_fee}/{tip} wei x {gas} gas"), sign_screens(&t, &[], None));

            // Amounts at full precision, dust to a billion tokens (fee kept
            // at the fixture default so only the amount varies).
            let (decimals, symbol) = tokens[(i as usize) % tokens.len()];
            let amount = rng.magnitude(u32::from(decimals) + 9);
            let meta = Erc20Metadata { chain_id: chain, contract: [0x77; 20], decimals, name: b"Token", symbol };
            let (selector, kind) = if i % 2 == 0 {
                ([0xa9, 0x05, 0x9c, 0xbb], "transfer")
            } else {
                ([0x09, 0x5e, 0xa7, 0xb3], "approve")
            };
            let data = erc20_call(selector, RECIPIENT, amount);
            let t = tx(chain, [0x77; 20], 0, data.len());
            let sym = core::str::from_utf8(symbol).unwrap();
            check(format!("chain {chain} {kind} {amount} {sym} @{decimals}"), sign_screens(&t, &data, Some(&meta)));

            let value = rng.magnitude(18 + 9);
            let t = tx(chain, RECIPIENT, value, 0);
            check(format!("chain {chain} send {value} wei"), sign_screens(&t, &[], None));
        }
    }
    assert!(failures.is_empty(), "{} of 9000 values not shown as exact decimals:\n{}", failures.len(), failures.join("\n"));
}

#[test]
fn pixel_lays_out_every_amount_its_page_shows() {
    let mut rng = Rng(0x0bad_cafe_f00d_d00d);
    let units: [&[u8]; 6] = [b"ETH", b"AAVE", b"USDC", b"stETH", b"ABCDEFGHIJ", b"ABCDEFGHIJKLM"];
    let mut checked = 0usize;
    for _ in 0..4000 {
        let mut word = [0u8; 32];
        let bytes = usize::try_from(rng.range(1, 32)).unwrap();
        for b in &mut word[32 - bytes..] {
            *b = rng.next() as u8;
        }
        let value = U256(word);
        for decimals in [0u8, 6, 8, 18, 24] {
            for symbol in units {
                let meta = Erc20Metadata { chain_id: 1, contract: [0x11; 20], decimals, name: b"T", symbol };
                for rows in [AmountRows::Two, AmountRows::Three] {
                    if token_amount_form(&value, &meta, rows).is_none() {
                        continue;
                    }
                    let amt = token_amount_as_page(&value, &meta, rows).expect("page form has a pixel amount");
                    assert!(
                        layout_amount_or_wrap(amt.digits(), amt.unit(), Region::Docked).is_ok(),
                        "page shows {:?} {:?} ({rows:?}) but the pixel screen has no layout",
                        core::str::from_utf8(amt.digits()),
                        core::str::from_utf8(amt.unit()),
                    );
                    checked += 1;
                }
            }
        }
        for chain_id in [1u64, 8453, 4_242_424_242] {
            for rows in [AmountRows::Two, AmountRows::Three] {
                if native_amount_form(&value, chain_id, rows).is_none() {
                    continue;
                }
                let amt = native_amount(&value, chain_id, rows).expect("page form has a pixel amount");
                assert!(
                    layout_amount_or_wrap(amt.digits(), amt.unit(), Region::Docked).is_ok(),
                    "page shows {:?} {:?} ({rows:?}) but the pixel screen has no layout",
                    core::str::from_utf8(amt.digits()),
                    core::str::from_utf8(amt.unit()),
                );
                checked += 1;
            }
        }
    }
    assert!(checked > 50_000, "too few renderable amounts: {checked}");
}

//! Source pins for the structured off-chain kinds (`SIGN_OFFCHAIN` 4 =
//! SafeTx, 5 = CoW order): `nsc/cmd_sign_offchain_structured.rs` and its
//! wiring into `nsc/cmd_sign_offchain.rs`. Like the other `nsc_*_pure_tests`
//! these read source text because the handlers do not link on the host; the
//! signed value itself is tested behaviourally in
//! `tx::eip712::offchain_structured` (equal to RAW32 over the ethers-checked
//! digest).

const STRUCTURED_SRC: &str = include_str!("nsc/cmd_sign_offchain_structured.rs");
const OFFCHAIN_SRC: &str = include_str!("nsc/cmd_sign_offchain.rs");

fn code(src: &str) -> String {
    src.lines()
        .map(|l| l.split("//").next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n")
}

fn pos(hay: &str, needle: &str) -> usize {
    hay.find(needle).unwrap_or_else(|| panic!("missing `{needle}`"))
}

#[test]
fn signed_value_is_only_the_replay_safe_nesting_of_the_recomputed_digest() {
    let c = code(STRUCTURED_SRC);
    // Every assignment of the signed value is RAW32's nesting.
    let assigns: Vec<&str> = c.lines().filter(|l| l.contains("let hash_to_sign =")).collect();
    assert_eq!(assigns.len(), 2, "{assigns:?}");
    for a in assigns {
        assert!(a.contains("crate::aa::eip1271::replay_safe_hash(chain_id, &wallet_addr,"), "{a}");
    }
    // The nested digest is the device's own: from the verifiers, never from
    // the payload bytes directly.
    assert!(c.contains("replay_safe_hash(chain_id, &wallet_addr, &safe_tx_hash)"));
    assert!(c.contains("replay_safe_hash(chain_id, &wallet_addr, &digest)"));
    // Structured kinds never route through RAW32.
    assert!(!c.contains("OFFCHAIN_KIND_RAW32"));
}

#[test]
fn both_kinds_verify_twice_with_a_randomized_gap() {
    let c = code(STRUCTURED_SRC);
    for verifier in ["verify_offchain_safe_tx(", "verify_offchain_cow_order("] {
        assert_eq!(c.matches(verifier).count(), 2, "{verifier} must run exactly twice");
        let first = pos(&c, verifier);
        let second = first + 1 + pos(&c[first + 1..], verifier);
        assert!(c[first..second].contains("crate::fi::wait_random()"), "{verifier}: no gap");
    }
    assert!(c.contains("safe_pair_equal(&a, &b)") && c.contains("cow_pair_equal(&a, &b)"));
}

#[test]
fn suffix_proofs_precede_the_confirm_and_the_receipt_follows_the_re_derivation() {
    let c = code(STRUCTURED_SRC);
    for (fp, render) in [
        ("FpKind::SafeTxHash(safe_tx_hash)", "render_safe_offchain_pages("),
        ("FpKind::Eip712Final(digest)", "render_cowswap_offchain_pages("),
    ] {
        let r = pos(&c, render);
        let f = r + pos(&c[r..], fp);
        let s = f + pos(&c[f..], "append_suffix(");
        let p = s + pos(&c[s..], "suffix_final_proofs(");
        let k = p + pos(&c[p..], "run_confirm(px, &pages)");
        let fin = k + pos(&c[k..], "finish(receipt,");
        assert!(r < f && f < s && s < p && p < k && k < fin, "{render}: order");
    }
    // finish(): the independent second derivation, then the one receipt.
    let f = pos(&c, "fn finish(");
    let d = f + pos(&c[f..], "structured_signed_value(");
    let g = d + pos(&c[d..], "if !gate(same)");
    let r = g + pos(&c[g..], "receipt.record_confirmed(ctx)");
    assert!(f < d && d < g && g < r);
}

#[test]
fn safe_wrapped_presign_requires_its_order_and_nothing_else_carries_one() {
    let c = code(STRUCTURED_SRC);
    assert!(c.contains("if bind.via_safe {"));
    assert!(c.contains("\"v3 required\""));
    assert!(c.contains("\"cow unexpected\""));
    assert!(c.contains("multisend_sign_gate(Some(&verified), None, cow.as_ref(), reserved)"));
}

#[test]
fn undeployed_wallets_are_refused_before_any_flash_write() {
    let c = code(OFFCHAIN_SRC);
    let gate = pos(&c, "OFFCHAIN_KIND_SAFE_TX | OFFCHAIN_KIND_COW_ORDER => {");
    let refusal = gate + pos(&c[gate..], "\"struct needs deploy\"");
    let probe = pos(&c, "offchain_count_is_registered(");
    let promote = pos(&c, "offchain_count_promote_to(");
    assert!(refusal < probe && refusal < promote);
    // The module re-checks (belt).
    assert!(code(STRUCTURED_SRC).contains("\"struct needs deploy\""));
    // Unknown kinds are still refused.
    assert!(c.contains("\"bad kind\""));
}

#[test]
fn structured_kinds_join_the_common_signing_gate() {
    let c = code(OFFCHAIN_SRC);
    let hook = pos(&c, "cmd_sign_offchain_structured::confirm(");
    let init = pos(&c, "offchain_confirm_receipt.fail_initialize();");
    let gate = pos(&c, "offchain_confirm_receipt.completion_proof(&signing_context_a)");
    assert!(init < hook && hook < gate);
    // The §4 length/deploy gate and the §8 "already confirmed" arm; nothing
    // falls to the `_` refusals.
    assert_eq!(c.matches("OFFCHAIN_KIND_SAFE_TX | OFFCHAIN_KIND_COW_ORDER =>").count(), 2);
}

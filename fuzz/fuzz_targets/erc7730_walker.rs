//! libFuzzer harness for the ERC-7730 path-bytecode walker.
//! `resolve_program` consumes opcode bytes from a caller-supplied
//! buffer and walks a caller-supplied AbiNode tree. Any panic or
//! over-read on adversarial input would be a denial-of-service vector
//! at sign time (the bytes come from a Merkle-verified IR pool, but
//! the parser still has to be panic-free against arbitrary
//! adversarial pool contents).
//!
//! The harness feeds arbitrary bytes as a program against a small
//! fixed tree (struct of one leaf + one nested array) so the walker
//! sees both struct and array descents.

#![no_main]
use libfuzzer_sys::fuzz_target;
use pqsigner_erc7730::abi::{AbiField, AbiNode, AbiView, ContainerView};
use pqsigner_erc7730::walker::{resolve_program, WalkerCtx};

fuzz_target!(|data: &[u8]| {
    let be32 = [0u8; 32];
    let elems = [AbiNode::Uint { bits: 256, be32: &be32 }];
    let inner_fields = [AbiField {
        idx: 0,
        node: AbiNode::Bool(true),
    }];
    let fields = [
        AbiField { idx: 0, node: AbiNode::Uint { bits: 256, be32: &be32 } },
        AbiField { idx: 1, node: AbiNode::Array(&elems) },
        AbiField { idx: 2, node: AbiNode::Struct(&inner_fields) },
    ];
    let view = AbiView::new(AbiNode::Struct(&fields));
    let container = ContainerView::new(AbiNode::Struct(&fields));
    let ctx = WalkerCtx::new(view, container);
    let _ = resolve_program(data, &ctx);
});

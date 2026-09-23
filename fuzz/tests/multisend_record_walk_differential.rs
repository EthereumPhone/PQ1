//! Differential test — host-extracted Safe `MultiSendCallOnly` inner
//! record walk (`pqsigner_tx::multisend::MsRecordIter`) vs the REAL
//! deployed MultiSendCallOnly v1.3.0 bytecode executed in `revm`.
//!
//! ## Why this exists (move 3 of the firmware bounded-verification plan)
//!
//! The outer ABI framing of `multiSend(bytes)` is closed by the Kani
//! canonical-acceptance proof on `decode_multisend`
//! (`pqsigner_tx::multisend::verification`). That proof structurally
//! CANNOT reach the **inner** layer — the packed-record walk — because
//! the packed encoding (`op(1) ‖ to(20) ‖ value(32) ‖ dataLen(32) ‖
//! data`, concatenated, no padding) mirrors MultiSendCallOnly's
//! hand-rolled assembly loop, not standard ABI. So we diff the extracted
//! Rust walk against an INDEPENDENT EVM ground-truth oracle: revm running
//! the actual on-chain bytecode, with a CALL-tracing inspector that
//! recovers the exact `(to, value, data)` sequence the EVM dispatches.
//!
//! ## Oracle: real bytecode (NOT a reference decoder)
//!
//! `MS_RUNTIME_HEX` is the runtime bytecode deployed at the canonical
//! MultiSendCallOnly v1.3.0 address `0x40A2…130D` (the first entry in
//! `MULTISEND_CALL_ONLY_ADDRESSES`, fetched live via `cast code` on
//! 2026-06-30). It is the firmware's allowlisted DELEGATECALL target, so
//! its loop IS the on-chain semantics the WYSIWYS render must agree with.
//! The oracle is independent of the code under test in every sense:
//! different language (EVM), different author (Safe / Gnosis), executed
//! by a third-party interpreter (revm).
//!
//! ## The property: SOUNDNESS direction (strict-Rust vs lenient-EVM)
//!
//! `MsRecordIter` is a STRICT parser — the cursor must land exactly on
//! the slice end, every record fully framed. The MultiSendCallOnly
//! assembly (`i := 0x20; for {} lt(i, length) {}`) is LENIENT: it
//! silently ignores up to 32 trailing bytes, zero-extends an over-long
//! `dataLength` past memory, processes an unbounded record count, and
//! does nothing for an empty payload. These are real, *fail-closed*
//! divergences (the firmware refuses inputs the chain would accept) — NOT
//! bugs, and NOT security holes (refusing to sign something the chain
//! accepts cannot forge anything).
//!
//! So we assert the dangerous direction only — the one a real WYSIWYS
//! hole would live in:
//!
//! > **Rust-accept ⟹ revm succeeds AND the EVM's dispatched CALL
//! > sequence is byte-identical to the Rust record sequence.**
//!
//! A counterexample (Rust accepts, but the chain dispatches a different
//! `(to, value, data)` set, or reverts) is a genuine decoder bug and
//! HARD-PANICS this test with the offending payload. The fail-closed
//! divergences are catalogued and reported, never asserted as agreement.
//!
//! ## Comparison target = `MsRecordIter` + `op==0` + record-count bound
//!
//! Bare `MsRecordIter` reports `operation` verbatim (the `op==0`
//! enforcement and the `1..=MULTISEND_MAX_RECORDS` bound live in
//! `summarize`). The EVM reverts on any `op != 0`. To diff like-for-like
//! we wrap the iterator with exactly the `summarize` loop body MINUS the
//! `cow_binding` presign counting (kept pure — no hashing, no
//! classification). `rust_decode_records` IS that wrapper.
//!
//! ## Execution-semantics constraints (documented, deliberate)
//!
//! The diff targets the record WALK (framing / op / order), not
//! value-transfer execution. So the corpus keeps every record's `value`
//! fundable (top 24 bytes zero) and every `to` code-less + non-precompile
//! (first byte `0xd0`, ≠ the MultiSend address, ≠ the caller) so each
//! sub-CALL trivially succeeds and the EVM never reverts for a reason
//! OTHER than a framing/op decision. `value` is still compared exactly,
//! 32 bytes, per record.

use pqsigner_tx::multisend::{MsError, MsRecordIter};
use sphincs_tz_shared::MULTISEND_MAX_RECORDS;

use revm::{
    context::{Context, TxEnv},
    context_interface::ContextTr,
    database::InMemoryDB,
    inspector::{InspectEvm, Inspector},
    interpreter::{CallInputs, CallOutcome},
    primitives::{hardfork::SpecId, Address, Bytes, TxKind, U256},
    state::{AccountInfo, Bytecode},
    MainBuilder, MainContext,
};

// ---------------------------------------------------------------------------
// EVM ground-truth oracle
// ---------------------------------------------------------------------------

/// Real deployed MultiSendCallOnly v1.3.0 runtime bytecode
/// (`0x40A2aCCbd92BCA938b02010E17A5b8929b49130D` on mainnet — the first
/// entry of `MULTISEND_CALL_ONLY_ADDRESSES`; fetched via `cast code`
/// 2026-06-30). The `multiSend(bytes)` selector is `0x8d80ff0a`.
const MS_RUNTIME_HEX: &str = "60806040526004361061001e5760003560e01c80638d80ff0a14610023575b600080fd5b6100dc6004803603602081101561003957600080fd5b810190808035906020019064010000000081111561005657600080fd5b82018360208201111561006857600080fd5b8035906020019184600183028401116401000000008311171561008a57600080fd5b91908080601f016020809104026020016040519081016040528093929190818152602001838380828437600081840152601f19601f8201169050808301925050505050505091929192905050506100de565b005b805160205b8181101561015f578083015160f81c6001820184015160601c60158301850151603584018601516055850187016000856000811461012857600181146101385761013d565b6000808585888a5af1915061013d565b600080fd5b50600081141561014c57600080fd5b82605501870196505050505050506100e3565b50505056fea264697066735822122035246402746c96964495cae5b36461fd44dfb89f8e6cf6f6b8d60c0aa89f414864736f6c63430007060033";

const MS_ADDR: Address = Address::new([
    0x40, 0xA2, 0xaC, 0xCb, 0xd9, 0x2b, 0xCa, 0x93, 0x8b, 0x02, 0x01, 0x0E, 0x17, 0xA5, 0xb8, 0x92,
    0x9b, 0x49, 0x13, 0x0D,
]);

/// Real deployed MultiSendCallOnly v1.5.0 runtime bytecode
/// (`0xA83c336B20401Af773B6219BA5027174338D1836` — entry `[3]` of
/// `MULTISEND_CALL_ONLY_ADDRESSES`; fetched via `cast code` on Base
/// 2026-09-23, keccak = safe-deployments codeHash `0xcdbdcec3…6663`).
/// Its record loop differs from v1.3.0: `to := or(to, mul(iszero(to),
/// address()))` and revert-data bubbling. See the provenance note at
/// the bottom of this file.
const MS150_RUNTIME_HEX: &str = "60806040526004361061001e5760003560e01c80638d80ff0a14610023575b600080fd5b6100dc6004803603602081101561003957600080fd5b810190808035906020019064010000000081111561005657600080fd5b82018360208201111561006857600080fd5b8035906020019184600183028401116401000000008311171561008a57600080fd5b91908080601f016020809104026020016040519081016040528093929190818152602001838380828437600081840152601f19601f8201169050808301925050505050505091929192905050506100de565b005b805160205b8181101561016a578083015160f81c6001820184015160601c3081150281179050601583018501516035840186015160558501870160008560008114610130576001811461014057610145565b6000808585888a5af19150610145565b600080fd5b5080610157576040513d6000823e3d81fd5b82605501870196505050505050506100e3565b50505056fea26469706673582212201ad552da02f0e66afd7f2ad29a305f1d4c737610d3b9e7ce8c994444949e57d664736f6c63430007060033";

const MS150_ADDR: Address = Address::new([
    0xA8, 0x3c, 0x33, 0x6B, 0x20, 0x40, 0x1A, 0xf7, 0x73, 0xB6, 0x21, 0x9B, 0xA5, 0x02, 0x71, 0x74,
    0x33, 0x8D, 0x18, 0x36,
]);

/// Every bytecode oracle the corpus is diffed against: `(label, runtime hex, address)`.
const ORACLES: [(&str, &str, Address); 2] = [
    ("v1.3.0", MS_RUNTIME_HEX, MS_ADDR),
    ("v1.5.0", MS150_RUNTIME_HEX, MS150_ADDR),
];
const CALLER: Address = Address::new([0x11; 20]);

/// A single CALL the EVM dispatched from inside `multiSend` — the
/// ground-truth record the on-chain code acts on.
#[derive(Clone, Debug, PartialEq, Eq)]
struct EvmCall {
    to: [u8; 20],
    value: [u8; 32],
    data: Vec<u8>,
}

/// Captures the depth-1 CALLs (the records). The top-level tx call into
/// MS_ADDR is depth 0 and skipped; a record's sub-CALL into a code-less
/// account makes no further calls, so depth never exceeds 2.
struct CallTracer {
    depth: usize,
    calls: Vec<EvmCall>,
}

impl<CTX: ContextTr> Inspector<CTX> for CallTracer {
    fn call(&mut self, context: &mut CTX, inputs: &mut CallInputs) -> Option<CallOutcome> {
        if self.depth >= 1 {
            let data = inputs.input.bytes(context).to_vec();
            let mut value = [0u8; 32];
            value.copy_from_slice(&inputs.value.get().to_be_bytes::<32>());
            self.calls.push(EvmCall {
                to: inputs.target_address.into_array(),
                value,
                data,
            });
        }
        self.depth += 1;
        None
    }

    fn call_end(&mut self, _context: &mut CTX, _inputs: &CallInputs, _outcome: &mut CallOutcome) {
        self.depth -= 1;
    }
}

/// Wrap a packed-records slice in canonical `multiSend(bytes)` calldata.
/// The packed bytes are passed THROUGH unchanged — both sides see the
/// identical payload; this is purely the EVM call transport.
fn encode_multisend(packed: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&[0x8d, 0x80, 0xff, 0x0a]);
    let mut off = [0u8; 32];
    off[31] = 0x20;
    out.extend_from_slice(&off);
    let mut len = [0u8; 32];
    len[28..32].copy_from_slice(&(packed.len() as u32).to_be_bytes());
    out.extend_from_slice(&len);
    out.extend_from_slice(packed);
    let pad = (32 - packed.len() % 32) % 32;
    out.extend_from_slice(&vec![0u8; pad]);
    out
}

/// Run the real MultiSendCallOnly bytecode over `packed` and recover the
/// dispatched record sequence. Returns `(tx_succeeded, calls)`.
fn run_evm(packed: &[u8]) -> (bool, Vec<EvmCall>) {
    run_evm_with(MS_RUNTIME_HEX, MS_ADDR, packed)
}

/// [`run_evm`] against an explicit oracle bytecode deployed at `ms_addr`.
fn run_evm_with(runtime_hex: &str, ms_addr: Address, packed: &[u8]) -> (bool, Vec<EvmCall>) {
    let code = Bytecode::new_raw(Bytes::from(hex::decode(runtime_hex).unwrap()));
    let big = U256::from(10u64).pow(U256::from(30u64)); // ≈ 2^99 ≫ any fundable record value
    let mut db = InMemoryDB::default();
    db.insert_account_info(
        ms_addr,
        AccountInfo {
            balance: big,
            nonce: 1,
            code: Some(code),
            ..Default::default()
        },
    );
    db.insert_account_info(
        CALLER,
        AccountInfo {
            balance: big,
            nonce: 0,
            ..Default::default()
        },
    );

    let calldata = encode_multisend(packed);
    let tracer = CallTracer {
        depth: 0,
        calls: Vec::new(),
    };
    let mut evm = Context::mainnet()
        .with_db(db)
        .modify_cfg_chained(|c| c.spec = SpecId::CANCUN)
        .build_mainnet_with_inspector(tracer);

    let tx = TxEnv {
        caller: CALLER,
        gas_limit: 30_000_000,
        gas_price: 0,
        kind: TxKind::Call(ms_addr),
        value: U256::ZERO,
        data: Bytes::from(calldata),
        nonce: 0,
        chain_id: Some(1),
        ..Default::default()
    };

    let res = evm.inspect_tx(tx).unwrap();
    let success = res.result.is_success();
    let calls = evm.inspector.calls.clone();
    (success, calls)
}

// ---------------------------------------------------------------------------
// Rust decoder under test (the extracted record walk + summarize gates)
// ---------------------------------------------------------------------------

/// The accepted decode of one record — `op` is always 0 on accept.
#[derive(Clone, Debug, PartialEq, Eq)]
struct RecordView {
    to: [u8; 20],
    value: [u8; 32],
    data: Vec<u8>,
}

/// `MsRecordIter` + the `summarize` hard rules (op==0, to!=0, 1..=MAX records),
/// MINUS the `cow_binding` presign counting (kept pure). This is exactly
/// the firmware's record-walk acceptance predicate.
fn rust_decode_records(packed: &[u8]) -> Result<Vec<RecordView>, MsError> {
    let mut out: Vec<RecordView> = Vec::new();
    for rec in MsRecordIter::new(packed) {
        let rec = rec?;
        if rec.operation != 0 {
            return Err(MsError::RecordOpNotCall);
        }
        if rec.to == [0u8; 20] {
            return Err(MsError::RecordToZero);
        }
        if out.len() == MULTISEND_MAX_RECORDS {
            return Err(MsError::BadRecordCount);
        }
        out.push(RecordView {
            to: rec.to,
            value: rec.value,
            data: rec.data.to_vec(),
        });
    }
    if out.is_empty() {
        return Err(MsError::BadRecordCount);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Corpus builders
// ---------------------------------------------------------------------------

/// Pack one record header + data: `op ‖ to ‖ value(32) ‖ dataLen(32) ‖ data`.
fn pack_record(op: u8, to: &[u8; 20], value: &[u8; 32], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(op);
    out.extend_from_slice(to);
    out.extend_from_slice(value);
    let mut len_word = [0u8; 32];
    len_word[28..32].copy_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(&len_word);
    out.extend_from_slice(data);
    out
}

/// Pack a record with a hand-chosen raw 32-byte `dataLen` word (for
/// overrun / high-bit adversarial framing — decoupled from `data.len()`).
fn pack_record_raw_len(op: u8, to: &[u8; 20], value: &[u8; 32], len_word: [u8; 32], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(op);
    out.extend_from_slice(to);
    out.extend_from_slice(value);
    out.extend_from_slice(&len_word);
    out.extend_from_slice(data);
    out
}

/// A safe, code-less, non-precompile, non-MultiSend, non-caller target.
fn safe_to(tag: u8) -> [u8; 20] {
    let mut a = [0u8; 20];
    a[0] = 0xd0;
    a[19] = tag;
    a[10] = tag ^ 0x5a;
    a
}

/// A fundable value (top 24 bytes zero) carrying an arbitrary low-8-byte pattern.
fn fundable_value(low: u64) -> [u8; 32] {
    let mut v = [0u8; 32];
    v[24..32].copy_from_slice(&low.to_be_bytes());
    v
}

/// Hand-crafted, labelled corpus covering every bullet in the spec:
/// 0 records, 1, many up to MAX (and over), empty data, max data,
/// op != 0, truncated header, dataLen overrun, off-by-one framing,
/// dataLen high bits, trailing bytes.
fn handcrafted_corpus() -> Vec<(&'static str, Vec<u8>)> {
    let mut c: Vec<(&'static str, Vec<u8>)> = Vec::new();
    let v0 = [0u8; 32];

    // 0 records (empty payload).
    c.push(("zero_records", Vec::new()));

    // 1 record, empty data.
    c.push(("one_record_empty_data", pack_record(0, &safe_to(1), &v0, &[])));

    // 1 record, non-zero (fundable) value.
    c.push((
        "one_record_value",
        pack_record(0, &safe_to(2), &fundable_value(0xdead_beef), &[0x01, 0x02]),
    ));

    // 1 record, "max-ish" data (256 bytes).
    c.push(("one_record_max_data", pack_record(0, &safe_to(3), &v0, &[0xab; 256])));

    // Exactly MULTISEND_MAX_RECORDS records (boundary, must accept).
    {
        let mut p = Vec::new();
        for i in 0..MULTISEND_MAX_RECORDS {
            p.extend_from_slice(&pack_record(0, &safe_to(0x40 + i as u8), &v0, &[i as u8; 4]));
        }
        c.push(("exactly_max_records", p));
    }

    // MAX + 1 records (over the cap → Rust BadRecordCount; EVM accepts all).
    {
        let mut p = Vec::new();
        for i in 0..=MULTISEND_MAX_RECORDS {
            p.extend_from_slice(&pack_record(0, &safe_to(0x50 + i as u8), &v0, &[]));
        }
        c.push(("over_max_records", p));
    }

    // The Safe-UI CoW shape: [approve-ish 68B, presign-ish 164B], both op 0.
    {
        let mut p = pack_record(0, &safe_to(0x70), &v0, &[0xaa; 68]);
        p.extend_from_slice(&pack_record(0, &safe_to(0x71), &v0, &[0xbb; 164]));
        c.push(("cow_shape_two_records", p));
    }

    // op = 1 (nested DELEGATECALL) — MultiSendCallOnly reverts.
    // to == 0: v1.5.0 rewrites it to address(this); firmware refuses it everywhere.
    c.push(("record_to_zero", pack_record(0, &[0u8; 20], &v0, &[])));
    {
        let mut p = pack_record(0, &safe_to(14), &v0, &[0x22; 4]);
        p.extend_from_slice(&pack_record(0, &[0u8; 20], &v0, &[]));
        c.push(("second_record_to_zero", p));
    }
    c.push(("record_op1", pack_record(1, &safe_to(4), &v0, &[0xaa; 4])));
    // op = 2 (undefined) and op = 255 — also revert.
    c.push(("record_op2", pack_record(2, &safe_to(5), &v0, &[])));
    c.push(("record_op255", pack_record(255, &safe_to(6), &v0, &[])));
    // first record fine, second op=1.
    {
        let mut p = pack_record(0, &safe_to(7), &v0, &[0x11; 8]);
        p.extend_from_slice(&pack_record(1, &safe_to(8), &v0, &[]));
        c.push(("second_record_op1", p));
    }

    // Truncated record header (< 85 bytes).
    c.push(("truncated_header_50", vec![0u8; 50]));
    c.push(("truncated_header_84", vec![0u8; 84]));

    // dataLen overrun: declare 100, supply 4 (moderate → EVM zero-extends).
    {
        let mut w = [0u8; 32];
        w[31] = 100;
        c.push((
            "datalen_overrun_moderate",
            pack_record_raw_len(0, &safe_to(9), &v0, w, &[0xaa; 4]),
        ));
    }
    // Off-by-one framing: declare dataLen = actual + 1.
    {
        let data = [0xcd; 16];
        let mut w = [0u8; 32];
        w[28..32].copy_from_slice(&((data.len() as u32) + 1).to_be_bytes());
        c.push((
            "datalen_off_by_plus_one",
            pack_record_raw_len(0, &safe_to(10), &v0, w, &data),
        ));
    }
    // Off-by-one framing: declare dataLen = actual - 1 (leaves 1 trailing byte
    // that starts a second, truncated record).
    {
        let data = [0xcd; 16];
        let mut w = [0u8; 32];
        w[28..32].copy_from_slice(&((data.len() as u32) - 1).to_be_bytes());
        c.push((
            "datalen_off_by_minus_one",
            pack_record_raw_len(0, &safe_to(11), &v0, w, &data),
        ));
    }
    // dataLen high bits (above u32) → Rust BadRecordDataLen; EVM OOG-reverts.
    {
        let mut w = [0u8; 32];
        w[6] = 0x01; // ≈ 2^200
        c.push((
            "datalen_high_bits",
            pack_record_raw_len(0, &safe_to(12), &v0, w, &[]),
        ));
    }

    // Trailing bytes after one complete record.
    for n in [1usize, 16, 32, 33, 84] {
        let mut p = pack_record(0, &safe_to(13), &v0, &[]);
        p.extend_from_slice(&vec![0xee; n]);
        c.push((Box::leak(format!("trailing_{n}_bytes").into_boxed_str()), p));
    }

    c
}

/// Tiny deterministic xorshift64* PRNG — no `rand` dep, reproducible.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// Randomized, structure-aware sweep: builds `n ∈ 0..=8` exact records
/// (so some land as valid 1..=MAX accepts, some over-cap), each with a
/// mostly-zero op (occasionally non-zero), code-less `to`, fundable
/// `value`, and a data length from a representative set — then with some
/// probability mutates the tail (trailing bytes / dataLen corruption /
/// truncation) to exercise the adversarial framing space.
fn random_corpus(count: usize, seed: u64) -> Vec<(&'static str, Vec<u8>)> {
    let mut rng = Rng(seed);
    let mut out = Vec::with_capacity(count);
    let data_lens = [0usize, 1, 4, 16, 31, 32, 33, 68, 96];
    for _ in 0..count {
        let n = rng.below(9); // 0..=8
        let mut packed = Vec::new();
        for _ in 0..n {
            let op = if rng.below(100) < 12 {
                (rng.below(254) + 1) as u8 // 1..=254 (non-CALL → revert)
            } else {
                0
            };
            let to = safe_to((rng.next() & 0xff) as u8);
            let value = if rng.below(100) < 30 {
                fundable_value(rng.next())
            } else {
                [0u8; 32]
            };
            let dl = data_lens[(rng.below(data_lens.len() as u64)) as usize];
            let mut data = vec![0u8; dl];
            for b in data.iter_mut() {
                *b = (rng.next() & 0xff) as u8;
            }
            packed.extend_from_slice(&pack_record(op, &to, &value, &data));
        }
        // Tail mutation (off-by-one / truncated framing space).
        match rng.below(5) {
            0 => {
                // append 1..=40 trailing bytes (sub-header garbage)
                let t = (rng.below(40) + 1) as usize;
                packed.extend_from_slice(&vec![(rng.next() & 0xff) as u8; t]);
            }
            1 => {
                // append a partial record-header fragment (1..=84 bytes)
                packed.extend_from_slice(&vec![(rng.next() & 0xff) as u8; (rng.below(84) + 1) as usize]);
            }
            2 if !packed.is_empty() => {
                // truncate a few bytes off the end
                let cut = (rng.below(40) + 1) as usize;
                packed.truncate(packed.len().saturating_sub(cut));
            }
            _ => {}
        }
        out.push(("random", packed));
    }
    out
}

// ---------------------------------------------------------------------------
// Differential driver
// ---------------------------------------------------------------------------

/// SOUNDNESS predicate: the EVM dispatched exactly the Rust-decoded
/// record sequence (same count, same `(to, value, data)` in order). The
/// explicit length guard avoids the `zip` truncation footgun. Pure +
/// independently testable so its failure path is demonstrated (see
/// `negative_control_soundness_check_has_teeth`) rather than only ever
/// observed `true`.
fn sequences_agree(evm_calls: &[EvmCall], rust: &[RecordView]) -> bool {
    evm_calls.len() == rust.len()
        && evm_calls
            .iter()
            .zip(rust.iter())
            .all(|(e, r)| e.to == r.to && e.value == r.value && e.data == r.data)
}

#[derive(Default)]
struct Tally {
    total: usize,
    accept_match: usize,
    both_reject: usize,
    fail_closed: usize, // Rust rejects, EVM lenient-accepts (safe; Rust stricter)
    dangerous: usize,   // Rust accepts, EVM disagrees → real bug
    accept_examples: Vec<String>,
    both_reject_examples: Vec<String>,
    fail_closed_examples: Vec<String>,
}

fn classify(label: &str, packed: &[u8], t: &mut Tally) {
    for (oracle, runtime_hex, ms_addr) in ORACLES {
        classify_with(oracle, runtime_hex, ms_addr, label, packed, t);
    }
}

fn classify_with(oracle: &str, runtime_hex: &str, ms_addr: Address, label: &str, packed: &[u8], t: &mut Tally) {
    t.total += 1;
    let rust = rust_decode_records(packed);
    let (evm_ok, evm_calls) = run_evm_with(runtime_hex, ms_addr, packed);

    match &rust {
        Ok(records) => {
            // SOUNDNESS direction — the only hard correctness assertion.
            let matches = evm_ok && sequences_agree(&evm_calls, records);
            if matches {
                t.accept_match += 1;
                if t.accept_examples.len() < 4 {
                    t.accept_examples.push(format!(
                        "[{oracle}] {label}: ACCEPT {} record(s) → EVM dispatched identical sequence (e.g. rec0 to=0x{:02x}.., data_len={})",
                        records.len(),
                        records[0].to[0],
                        records[0].data.len(),
                    ));
                }
            } else {
                t.dangerous += 1;
                panic!(
                    "DANGEROUS Rust-accept / EVM-disagree (POTENTIAL DECODER BUG)\n  \
                     oracle  = {oracle}\n  \
                     label   = {label}\n  \
                     packed  = 0x{}\n  \
                     rust    = Ok({} records)\n  \
                     evm_ok  = {evm_ok}\n  \
                     evm_calls = {} call(s)\n  \
                     rust_recs = {:?}\n  \
                     evm_recs  = {:?}",
                    hex::encode(packed),
                    records.len(),
                    evm_calls.len(),
                    records
                        .iter()
                        .map(|r| (hex::encode(&r.to[..4]), r.data.len()))
                        .collect::<Vec<_>>(),
                    evm_calls
                        .iter()
                        .map(|e| (hex::encode(&e.to[..4]), e.data.len()))
                        .collect::<Vec<_>>(),
                );
            }
        }
        Err(e) => {
            if !evm_ok {
                t.both_reject += 1;
                if t.both_reject_examples.len() < 4 {
                    t.both_reject_examples
                        .push(format!("[{oracle}] {label}: BOTH REJECT (Rust {e:?}, EVM revert)"));
                }
            } else {
                // Rust stricter than the lenient EVM assembly — fail-closed,
                // catalogued, NOT asserted as agreement.
                t.fail_closed += 1;
                if t.fail_closed_examples.len() < 8 {
                    t.fail_closed_examples.push(format!(
                        "[{oracle}] {label}: FAIL-CLOSED (Rust {e:?} ⟂ EVM accepts {} call(s))",
                        evm_calls.len()
                    ));
                }
            }
        }
    }
}

#[test]
fn multisend_record_walk_differential() {
    let mut t = Tally::default();

    // 1. Hand-crafted, labelled adversarial + valid frames.
    for (label, packed) in handcrafted_corpus() {
        classify(label, &packed, &mut t);
    }

    // 2. Structure-aware randomized sweep (deterministic, reproducible).
    for (label, packed) in random_corpus(1500, 0x9E37_79B9_7F4A_7C15) {
        classify(label, &packed, &mut t);
    }

    // ---- Report -------------------------------------------------------
    println!("\n=== multiSend record-walk differential (revm v1.3.0 + v1.5.0 bytecode oracles) ===");
    println!("cases total          : {}", t.total);
    println!("ACCEPT + same sequence: {}", t.accept_match);
    println!("BOTH reject          : {}", t.both_reject);
    println!("fail-closed (Rust stricter, safe): {}", t.fail_closed);
    println!("DANGEROUS (Rust-accept/EVM-disagree): {}", t.dangerous);
    println!("\n-- ACCEPT examples (non-vacuity, oracle accepts valid frames) --");
    for e in &t.accept_examples {
        println!("  {e}");
    }
    println!("-- BOTH-REJECT examples (non-vacuity, adversarial rejected by both) --");
    for e in &t.both_reject_examples {
        println!("  {e}");
    }
    println!("-- FAIL-CLOSED examples (Rust strict ⟂ EVM lenient — reported, expected) --");
    for e in &t.fail_closed_examples {
        println!("  {e}");
    }

    // ---- Assertions ---------------------------------------------------
    // The dangerous direction must be empty (any case would have panicked
    // above; this is belt-and-braces).
    assert_eq!(t.dangerous, 0, "a Rust-accept/EVM-disagree case slipped through");
    // Non-vacuity: the oracle genuinely ACCEPTS valid frames with matching
    // sequences (not a reject-everything oracle)…
    assert!(
        t.accept_match >= 5,
        "oracle vacuous: expected several accepted+matched frames, got {}",
        t.accept_match
    );
    // …and genuinely REJECTS adversarial frames on both sides.
    assert!(
        t.both_reject >= 3,
        "expected several both-reject adversarial frames, got {}",
        t.both_reject
    );
}

/// Negative control — proves the soundness check actually has TEETH.
///
/// The main differential only ever observes `sequences_agree == true`
/// (0 dangerous over 1500+ cases), so the failure path of the headline
/// assertion is never exercised by the corpus alone. Here we drive a real
/// EVM-recovered sequence for a valid 2-record frame, confirm it agrees,
/// then perturb it three ways and assert each perturbation is CAUGHT as a
/// disagreement. Without this, a silently-always-true comparison would
/// make the whole differential vacuous.
#[test]
fn negative_control_soundness_check_has_teeth() {
    let v0 = [0u8; 32];
    let mut packed = pack_record(0, &safe_to(0xa1), &v0, &[0xaa; 32]);
    packed.extend_from_slice(&pack_record(0, &safe_to(0xb2), &fundable_value(7), &[0xbb; 64]));

    let (ok, evm_calls) = run_evm(&packed);
    let records = rust_decode_records(&packed).expect("valid 2-record frame must decode");
    assert!(ok && records.len() == 2 && evm_calls.len() == 2);

    // Truth: identical sequences agree.
    assert!(
        sequences_agree(&evm_calls, &records),
        "real EVM sequence must agree with the Rust decode"
    );

    // Perturbation A — swap record order: must be caught.
    let mut swapped = evm_calls.clone();
    swapped.swap(0, 1);
    assert!(
        !sequences_agree(&swapped, &records),
        "reordered record sequence MUST be flagged as disagreement"
    );

    // Perturbation B — flip a `to` byte: must be caught.
    let mut flipped = evm_calls.clone();
    flipped[0].to[0] ^= 0xff;
    assert!(
        !sequences_agree(&flipped, &records),
        "altered `to` MUST be flagged as disagreement"
    );

    // Perturbation C — drop a record (length mismatch): must be caught
    // (this is the `zip`-truncation footgun the length guard defends).
    let dropped = vec![evm_calls[0].clone()];
    assert!(
        !sequences_agree(&dropped, &records),
        "a dropped record MUST be flagged (length guard)"
    );

    // Perturbation D — alter one data byte: must be caught.
    let mut data_mut = evm_calls.clone();
    data_mut[1].data[0] ^= 0x01;
    assert!(
        !sequences_agree(&data_mut, &records),
        "altered record data MUST be flagged as disagreement"
    );
}

/// Pins the reason for the firmware's `to == 0` refusal: v1.5.0 dispatches a
/// zero-`to` record to `address(this)` (under the SafeTx DELEGATECALL: the
/// Safe itself), v1.3.0 dispatches it to `0x0`. Same bytes, different
/// callee — so the firmware must refuse rather than render either.
#[test]
fn v150_rewrites_zero_to_self_and_firmware_refuses() {
    let packed = pack_record(0, &[0u8; 20], &[0u8; 32], &[]);
    let (_, calls130) = run_evm_with(MS_RUNTIME_HEX, MS_ADDR, &packed);
    let (_, calls150) = run_evm_with(MS150_RUNTIME_HEX, MS150_ADDR, &packed);
    assert_eq!(calls130.first().map(|c| c.to), Some([0u8; 20]));
    assert_eq!(calls150.first().map(|c| c.to), Some(MS150_ADDR.into_array()));
    assert_eq!(rust_decode_records(&packed), Err(MsError::RecordToZero));
    assert_eq!(
        pqsigner_tx::multisend::summarize_packed(&packed).map(|_| ()),
        Err(MsError::RecordToZero)
    );
}

// ---------------------------------------------------------------------------
// Oracle provenance / cross-variant fidelity (verified 2026-06-30)
// ---------------------------------------------------------------------------
//
// `MS_RUNTIME_HEX` is the v1.3.0-canonical deployment. The firmware
// allowlists three MultiSendCallOnly variants (`MULTISEND_CALL_ONLY_
// ADDRESSES`): v1.3.0-canonical (0x40A2…130D), v1.3.0-eip155
// (0xA1da…102B), and v1.4.1 (0x9641…02e2). All three were fetched via
// `cast code` and the record-walk loop body
//
//   805160205b8181101561015f57…8260550187019650505050505050
//   (DUP1 MLOAD; PUSH1 0x20; for{}lt(i,length){}: op=shr(0xf8,…),
//    to=shr(0x60,…), value@0x15, dataLen@0x35, data@0x55; switch op
//    case 0 -> call; else revert; i += 0x55 + dataLen)
//
// is BYTE-IDENTICAL across all three (only the surrounding ABI prologue /
// solc metadata trailer differ). So this single embedded blob is a
// faithful oracle for every allowlisted target — the differential's
// conclusion carries to all three.
//
// UPDATE 2026-09-23 — v1.5.0 (0xA83c…1836) added to the allowlist. Its
// loop body is NOT byte-identical: after `to := shr(0x60, …)` it inserts
// `30 81 15 02 81 17` = `to := or(to, mul(iszero(to), address()))`, and a
// failed sub-call bubbles its revert data (`returndatacopy`/`revert`)
// instead of `revert(0, 0)`. The op-0-only switch is unchanged. v1.5.0 is
// therefore embedded as its own oracle (`MS150_RUNTIME_HEX`) and every
// case runs against both; the zero-`to` rewrite is neutralised by
// `summarize_packed`'s `RecordToZero` refusal (pinned by
// `v150_rewrites_zero_to_self_and_firmware_refuses`). Revert bubbling
// changes only the failure payload, not which calls are dispatched.

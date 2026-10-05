# Handoff — Aeneas extraction of `domain::{de,}serialize_pin_state` (next §33 rank)

**Status (2026-06-26): REJECTION RANK LANDED.** The `Chunks` iterator-adapter
model + the malformed-length rejection theorem are in
`contracts/verification/extracted/Extracted/PinState/` (commit — see Completion
Log): `deserialize_pin_state_rejects_bad_len` proves every `len=0 ∨ len>481`
blob is rejected with `Err` (no panic, no array population), kernel-clean
`{propext, Classical.choice, Quot.sound}`, wired into `AxiomCheck.lean`,
`make verify-extracted` green. The `Chunks`/`Enumerate.next` externals are
content-axiom-free DEFs (`FunsExternal.lean`/`TypesExternal.lean`). **Remaining:
the deeper ROUND-TRIP rank** (`deserialize (serialize …) = Ok …`, the
chunks/enumerate fold-invariant proof) is still open — see "Proof targets"
below. The recipe/findings below are retained for that follow-on.

_(Original status 2026-06-16: pipeline VALIDATED end-to-end; rank
EXTRACTION-READY; the `Chunks` infra step — now DONE.)_

## Why this rank

`deserialize_pin_state` (`domain/src/lib.rs:855`) is the PIN-state blob parser
used by the mock-SE MACD path. It is the highest-value *uncovered* pure-logic
function in `domain` and exactly the shape that caught a real bug at rank 8
(`decode_item`'s 32-bit `checked_shl` wrap): a length-validated, `Result`-typed
byte parser. Proving it **rejects every malformed-length blob** (never proceeds
to populate the fixed `[[u8;48];10]` array) is a genuine anti-malformed-input
property. The inverse `serialize_pin_state` (`:833`) gives the round-trip.
_(UPDATE 2026-10-05: line citations re-resolved against current master; they
read `:739`/`:717`, correct when written in June, before code was added above
both functions.)_

## What was validated (this session)

The Charon→Aeneas pipeline extends cleanly to the `domain` crate. Both functions
extract to clean Lean (no `unsafe`, no panics beyond the documented bounds):

```bash
cd /home/nicola/repos/PQSigner_OS/domain
RUSTFLAGS="--cfg lean_extract" \
  ~/.local/share/pqsigner-lean/charon cargo --preset=aeneas \
  --opaque sha2 --opaque aes_gcm --opaque zeroize --opaque hmac \
  --opaque sphincs_c10 --opaque sphincs_tz_bip39 \
  --start-from 'pqsigner_domain::serialize_pin_state' \
  --start-from 'pqsigner_domain::deserialize_pin_state' \
  --dest-file /tmp/pqsigner-extract/pinstate.llbc
~/.local/share/pqsigner-lean/aeneas -backend lean -dest /tmp/pqsigner-extract/pout \
  -split-files /tmp/pqsigner-extract/pinstate.llbc
# → Funs.lean (195 lines), Types.lean (PinState struct), FunsExternal_Template.lean
```

### Extraction-coverage boundary discovered

A reusable finding for picking future ranks:

- **Hash-builder functions do NOT extract cleanly.** `slot_entropy` and the other
  `domain` KDF helpers use the incremental `Sha256::new().chain_update()…finalize()`
  *builder* (the `Digest` trait). Charon faithfully but uselessly explodes this
  into a `typenum`/`generic-array`/`CtVariableCoreWrapper` type-level soup — not
  provable. The `sphincs-c10` hash functions extract cleanly only because they
  call a single-shot `sha256_bytes` helper (opaqued as one function).
  **Lesson:** to extract a hashing function, it must funnel through a single-shot
  `sha256(&[u8]) -> [u8;32]` (opaque), not the builder.
- **Parsers / counter-loops extract cleanly** (this rank, and the existing 12).

## The one remaining infra step: model the `Chunks` iterator adapter

`deserialize_pin_state` iterates `rest.chunks(48).enumerate()`. Aeneas renders the
loop with these externals (`FunsExternal_Template.lean`), which must be given
**defs** (the project keeps proof closures content-axiom-free — see
`Extracted/Rlp/FunsExternal.lean`'s `into_iter` def and the comment in
`Extracted/Decode/FunsExternal.lean`):

| External | How to model | Source template |
|---|---|---|
| `core.num.Usize.is_multiple_of` | `fun a b => ok (decide (b.val = 0 → a.val = 0 ∧ b.val ≠ 0 → a.val % b.val = 0))` — match Rust `is_multiple_of` (m=0 ⇒ self==0) | — |
| `…into_iter` (slice) | `fun s => ok ⟨s, 0⟩` | **already defined** in `Extracted/Rlp/FunsExternal.lean:28` |
| `core.slice.Slice.chunks` | construct a `Chunks` from `(slice, chunk_size)` | mirror `List.toChunksExact` (`Aeneas/Std/SliceIter.lean:148`) |
| `Chunks.next` / `Chunks.enumerate` | pop-head / wrap-in-Enumerate | mirror `IteratorChunksExact.{next,enumerate}` (`Aeneas/Std/SliceIter.lean:108-129`) |
| `Enumerate.next` (over Chunks) | `match inner.next with none → (none,self) | some x → (some (count,x), ⟨inner', count+1⟩)` | `Enumerate` struct at `Aeneas/Std/Core/Iter.lean:37` |
| `pqsigner_proto.MAX_ATTEMPTS` | `ok 10#u8` | — (it is `10`) |
| `AES_GCM_TAG_LEN` (global in Funs) | `16` ⇒ `PER_SLOT_CT_LEN = 48`, `PIN_STATE_MAX_LEN = 481` | — |

Aeneas Std models `ChunksExact` (not `Chunks`); the only genuinely-new piece is a
`Chunks` struct + its `next` (the last chunk may be short — irrelevant here since
`is_multiple_of 48` guarantees exact chunks, but model it faithfully anyway). The
`Enumerate` struct already exists in Aeneas Std. Budget: ~60 LoC of defs.

## Proof targets (once the infra is in place)

**Rank-baseline (tractable, no loop invariant) — the malformed-input rejection.**
All four reject paths return `Err` *before* the loop, so this proves from the
straight-line guards by `simp`/unfold (the loop externals need only exist):

```lean
-- (totality + rejection) the parser never panics and rejects every malformed length
theorem deserialize_pin_state_rejects_bad_len
    (blob : Slice Std.U8) (blob_len : Std.Usize)
    (h : blob_len.val = 0 ∨ blob_len.val > 481) :
    deserialize_pin_state blob blob_len = ok (.Err ()) := by
  unfold deserialize_pin_state ; ... -- case on the two length guards
-- and: on success, num_slots ≤ MAX_ATTEMPTS (the explicit belt-and-braces check)
```

**Deeper (loop invariant) — the round-trip.** `deserialize (serialize n secrets) =
Ok ⟨n, secrets.length, secrets-padded⟩`, via a `chunks`/`enumerate` fold invariant
(the harder, decode_item-grade proof). This is the follow-on once the baseline +
infra land.

## Recommendation

Land the `Chunks` infra + the rejection theorem as the next clean rank (it also
unblocks any future `chunks`/`enumerate`-using extraction). The round-trip is a
separate, deeper rank. Both are additions-only, kernel-clean, and do not touch
`theft_free`.

# ERC-7730 bounded multi-tail ABI design

> **UPDATE 2026-08-05 — implemented.** The bounded M1–M3 design landed on
> `master` at `ee8699105939f5ffa8bc45ab89018ccd8af3e508` (tree
> `f86271111e1cb0166ce28b78bc1dcc01bd0c065d`) and #347 is closed. Current
> source accepts authenticated exact partitions of two to four top-level
> `Blob` or one-word primitive-array tails; the current generated catalogue has
> six deployment-format rows carrying the topology marker. The source below
> remains the frozen design record and its non-goals remain unchanged.

Status: Phase-B design freeze for GitHub issue #347. This document authorizes
only the bounded, reversible Phase-C implementation described below. It does
not authorize blind-sign fallback, deployment, flashing, or shipment.

## Objective and baseline

PQ1 will clear-sign contract calldata with two to four top-level dynamic ABI
objects only when authenticated IR describes the complete topology and one
runtime proof establishes an exact canonical partition of every signed tail
byte. Static calldata and the existing sole-tail path remain byte-identical.

The baseline is remote `master` commit
`27208ce05d17470ed653672b9ea91c96d9efe7fa`, tree
`7982ff60004bd7790974ec00a1b2e9a6dc356eaf`, on isolated branch
`erc7730/multi-tail-347-20260722`. The primary checkout is outside this work
surface and must not be cleaned or moved.

Owner inputs are issue #347, `CLAUDE.md`, `docs/STATUS.md`, companion guide
section 12.5, the current resolver, and the 2026-07 clear-signing findings.
They agree on the load-bearing rule: multi-tail support requires authenticated
topology, canonical order, no alias/overlap/gap/trailing bytes, bounded work,
and no second permissive decoder.

## Selected authority and invariants

A new versioned `PARAM_DYNAMIC_TAIL_TOPOLOGY` TLV is emitted only on field zero
of a contract format with two to four supported dynamic top-level arguments.
The Merkle-rooted payload is:

```text
version=1 | count:u8 | count * (head_slot:u16 BE | kind:u8)
```

Kinds are initially `Blob` (`bytes` or `string`) and `StaticWordArray`
(`T[]`, where `T` is one static ABI word). Dbgen derives the complete record
list directly from the canonical function signature in argument order. It
does not infer topology from visible fields. Runtime deep validation requires
one marker on field zero, a canonical count, strictly increasing unique head
slots inside the authenticated static head, known kinds, and exact payload
consumption.

The tag is a compatible authenticated-IR extension, not a USB/proof-set wire
change. Existing firmware rejects the unknown TLV. Existing static and sole-
tail leaves carry no marker and retain their current interpretation. A global
schema-v7 header field was rejected because it rotates and enlarges every
format without adding authority beyond the versioned, placement-pinned TLV.

One allocation-free partition kernel starts at
`static_head_words * 32`. For each authenticated record it reads the exact
head-slot offset and requires it to equal the running cursor. Blob length,
data, zero right-padding, and padded end are checked with the existing hardened
reader; static-word arrays use checked `count * 32`. Every cursor and body end
is 32-byte aligned. The final cursor must equal `body.len()`. Therefore every
accepted interval is ordered, disjoint, gap-free, non-aliased, in bounds, and
the set consumes all signed bytes after the head.

The partition is capped at four tails and a `MAX_TX_LEN - 4`-byte body, the
`MAX_TX_LEN - selector` input envelope (UPDATE 2026-10-22: 8,188 B since
`MAX_TX_LEN` went to 8192; it was a 4,092 literal, which would have
hard-refused every verified multi-tail descriptor on a 4–8 KB call). Per-field render limits remain
stricter: strings remain exact printable values of at most 32 bytes and
`ArrayAll` remains at most eight elements. The whole format refuses if either
the topology proof or a field-local semantic check fails.

Every dynamic field and token path must consume one matching topology record,
and every record must be referenced before the intent page is buffered.
Dynamic strings, render-all primitive arrays, token identity extraction, and
an enrolled nested-calldata field obtain their interval from this same proof.
The deployment-enrolled Router02 parser remains a separate exact exception;
generic dynamic tuples do not borrow multi-tail authority.

## Scope and non-goals

Phase C has three reversible slices:

1. **M1 — authenticated topology and partition:** TLV grammar/deep validation,
   compiler derivation, exact fixed-capacity runtime partition, unit/Kani
   invariants, and legacy parity.
2. **M2 — renderer consumption:** replace sole-tail assumptions only when the
   authenticated marker is present; reconcile all fields before publication;
   keep nested-child interval binding and hard-refusal routing intact.
3. **M3 — catalogue and integration:** admit the clean real formats, add one
   honest synthetic E2E fixture, regenerate artifacts, and collect focused
   host/fuzz/formal/QEMU/resource evidence.

Explicit non-goals are dynamic tuples or tuple-local offsets; `bytes[]`,
arrays of tuples, nested arrays, or fixed arrays containing dynamic values;
displayed value slices or single array indexes; arbitrary opaque-bytes
semantics; recursive calldata; a new fallback; a capability bit; or a second
ABI walker. Unsupported shapes continue to hard-refuse for known calls.

The expected production effect is five newly admitted source formats across
Sei, Avvatar, and Kiln, with the production leaf count and known-call Bloom
unchanged. Exact generated counts and hashes are evidence, not assumptions,
and will be recorded only after regeneration.

## Validation and stopping rules

Mandatory Phase-C evidence is:

- parser/compiler round trips for two, three, and four tails; max-plus-one,
  unsupported-kind, missing/duplicate/extra/unsorted/out-of-head records;
- exact partition positives for blob/blob and blob/two-array shapes, including
  adjacent empty tails, plus alias, overlap, reordering, gap, unaligned offset,
  dirty high words, dirty padding, truncation, trailing bytes, arithmetic, and
  total-work failures;
- pre-publication hidden-tail refusal and complete record reconciliation;
  valid rendering, page-budget boundaries, signed-byte flips, and legacy
  sole/static page parity;
- focused Kani partition tiling/binding plus non-vacuity and mutation controls;
  one 100,000-run topology-aware render fuzz campaign;
- dbgen and renderer suites, descriptor drift, secure host tests, one rooted
  synthetic QEMU positive, and final Thumb link/size receipts.

Phase C stops and returns to Phase B if work requires a dynamic tuple, a new
host-controlled fact, fallback/signing authority, persistent state, a USB or
proof-set migration, an irreversible action, or a failed resource envelope.
Unrelated findings are banked as GitHub issues.

The next review boundary is one frozen combined Phase D after M1-M3. Its
closed checklist is: target identity; the mandatory evidence above; the one
simultaneous three-reviewer source wave; blocker-only remediation and the
workflow-required re-review rule; fast-forward landing; issue/status receipt.
The combined deferred playbook assurance remains owner-triggered in #78/#403
and is not part of this merge phase.

Rollback is a revert of the #347 commits and regenerated artifacts. Because
the existing static/sole-tail path is retained and no external state changes,
rollback restores the previous hard-refusal behavior without migration.

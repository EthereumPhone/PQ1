# TLA+/TLC models (FV-surface expansion)

## Running them

```sh
make -C contracts/verification verify-tla       # all three suites
TLA2TOOLS=/path/to/tla2tools.jar make -C contracts/verification verify-tla
```

The target needs `tla2tools.jar` (not vendored: 4.3 MB of third-party binary).
It looks at `$TLA2TOOLS`, then `$HOME/tla2tools.jar`, and **fails loudly** if
absent — it never silently skips. Fetch from
<https://github.com/tlaplus/tlaplus/releases>.

The committed results were obtained with a TLA+ Tools **nightly**
(`Build-TimeStamp 2026-07-15T13:43:31Z`, sha256
`58d44845a37a8d776deaf8cf3a623213b59d311bc0ec287bcdfbe148dd11bb3d`). The target
prints the hash of whatever jar it used and warns when it differs: a different
TLC is a different tool, so a green under another build is not attributable to
these results. The hash is *not* a hard gate precisely because the validated
build is a nightly — pinning it against "download latest" would fail for
everyone. Attribution over false precision.

Each `run_*.sh` is **self-checking**: it asserts an expected verdict per config,
including the deliberately `VIOLATED` ones that are the negative controls (a
wrong-order compaction must break; a symmetric PIN model must false-wipe). A
green means *all expected outcomes matched* — not *no violations found*. 17
expected outcomes across the three models (6 + 3 + 8) as of 2026-08-20.

Every `.cfg` is additionally **sha256-pinned** in `cfg_pins.sha256` (#668,
2026-08-20): the run scripts verify the pins *before* invoking TLC and fail
closed on any drift, a missing cfg, or an un-pinned new cfg — a `Slots`/
`MaxCount` shrink or an `INVARIANT` deletion used to stay green because only
TLC's stdout was classified. Re-pin after a *deliberate* cfg change:

```sh
(cd contracts/verification/tla && sha256sum *.cfg > cfg_pins.sha256)
```

Before this target existed (work-todo C5) there was no way to re-run any of
this: the only jar on the box lived in a scratch directory belonging to a
session that no longer exists, while three model-checking results were cited in
docs as evidence. A pilot result that cannot be re-run is a verification claim
with no executable evidence.


First pilot of the formal-verification-surface expansion program
(`docs/verification/fv-surface-expansion-inventory-2026-07-16.md`).

## `Page123Compaction.tla` — page-123 compaction crash-atomicity

Bounded TLA+/TLC model of the STM32U585 page-123 log-structured off-chain
signing-counter store (`secure/src/hw/flash.rs`). Tests the flash.rs F3
crash-atomicity claim that replaying `USEROP_SIGS` first per slot keeps a
torn compaction from rolling back a registered slot's few-time-key tally.

**Read the full report + scope caveats first:**
`docs/verification/fv-pilot-page123-crash-atomicity-2026-07-16.md`.
This is a **bounded model** of the algorithm under stated assumptions —
`model ≠ implementation ≠ hardware`, not a universal proof.

### Run

```sh
# fetch the checker once (single jar), then:
TLA2TOOLS=/path/to/tla2tools.jar ./run.sh
# (or drop tla2tools.jar in $HOME). https://github.com/tlaplus/tlaplus/releases
```

`run.sh` is a self-checking harness: it asserts each of the 6 pinned configs
produces its expected PASS/VIOLATED outcome and exits non-zero on any mismatch
(the same anti-vacuity discipline as the repo's other FV gates). The wrong
replay order (`sigslast_skip.cfg`) MUST reproduce the rollback, or the model is
vacuous.

| cfg | replay | torn model | invariant | expect |
|---|---|---|---|---|
| `sigsfirst_skip` | SigsFirst | Skip | `INV_SIGS_COMPACTION_LOCAL` | PASS — F3 claim confirmed |
| `sigslast_skip` | SigsLast | Skip | `INV_SIGS_COMPACTION_LOCAL` | VIOLATED — negative control |
| `sigsfirst_mayvalid` | SigsFirst | MayValid | `INV_SIGS_COMPACTION_LOCAL` | VIOLATED — no per-entry integrity tag (Finding 1) |
| `endtoend_sigsfirst_skip` | SigsFirst | Skip | `INV_SIGS_NO_ROLLBACK` | VIOLATED — local reset, backstopped by inv#9+on-chain (Finding 2) |
| `partial_erase_sigsfirst` | SigsFirst | Skip (+ partial erase) | `INV_SIGS_COMPACTION_LOCAL` | VIOLATED — a torn partial erase rolls a slot back even under SigsFirst (erase-atomicity is load-bearing) |
| `cnt_sigsfirst_skip` | SigsFirst | Skip | `INV_CNT_NO_ROLLBACK` | VIOLATED — documented residual |

Not CI-gated (needs a JVM + tla2tools.jar; TLA+ is a new, local tool for the
project). Treat like `verify-easycrypt` / `verify-kontrol`: a local gate.

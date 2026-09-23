# PQ-UI → firmware: the port

**Rewritten 2026-09-23** (the earlier five-phase version grew too much
process; this one is only the porting work). Starting point:
`docs/ui/pixel-ui-pilot.md` (Safe family native on `ui-px-evt`, ran on
EVT #1 2026-09-22). Design source: `EthereumPhone/PQ-UI` (Elie Munsi).

## Goal

Every screen the device shows is drawn by the PQ-UI pixel engine instead
of the 16×4 text pages.

## The one rule

The existing page painters (`*_display.rs`) keep deciding *what* is shown.
Each family gets a `*_screens.rs` emitter next to its painter that draws the
same facts in the PQ-UI look. A host test per family checks that every fact
on the pages (addresses, amounts, symbols, nonces, hashes, chain) appears
in the screens. Nothing else changes: no verifier, decoder, or gate is
touched.

## How to port a family

1. Look up the flow in the vendored `tools/pq-ui/flows/<family>/`.
2. Write `<family>_screens.rs` from the facts the page painter already
   produces. Copy `safe_screens.rs` as the template.
3. Add the route to `px_route_confirm`.
4. Add the fact test (pages ⊆ screens) and one QEMU `make e2e-px` scenario.
5. Regenerate frames: `tools/ui_screens_export.py --px`, eyeball them,
   bless goldens (`make ui-px-goldens-bless`).
6. Bake any new mark/icon with `make ui-px-assets`.

That is the whole loop. Do not add proofs, harnesses, fences, or reviews
while porting; see "Not in this plan".

## Steps

### 1. Safe — DONE

Native on `ui-px-evt` (`644474e5`, `e56d533e`, `9998b45a`, plus the
goldens/catalogue commit): hero/details, trailers (`trailer_screens.rs`),
signing film, fact tests (`assert_facts_carry_over`, every Safe fixture),
frame goldens for 11 Safe transcripts (`pqsigner-ui-px/tests/fixtures/safe/`,
`make ui-px-goldens-bless`), 89-frame catalogue `docs/ui-screens/px/`
(regenerates byte-identical from a `make e2e-px` log). Re-verified
2026-09-23: `make e2e-px` 40/40 scenarios + the three ui-px assertions
(4 pixel transcripts, 0 Legacy records, well-formed records); secure host
tests 2596/0; `pq-ui-check`, `ui-px-assets-check`, `pq-ui-port-diff`
(24 MATCH, 1 recorded DEVIATION) green. Only an EVT walk-through of the Safe
flows is still pending (human).

### 2. Single-UserOp families

One emitter each, in this order:

| firmware route | upstream flow |
|---|---|
| `value_transfer` | `send` |
| `erc20_known` | `send_token`, `send_token_named`, `transfer_token`, `approve_token` |
| `erc20_unknown` | `transfer_unknown_token` (gradient from the token address) |
| `blind_sign`, `forced_blind` | `blind/bare_call`, `call_with_value`, `unknown_call` |
| `typed_call` | `blind/typed_call/sign_with_args` |
| `slot_rotation` | `rotate_slot` |
| `deployment` | deploy banner + initCode |
| `contract_call` | `contract_call` |

Assets: ETH, USDC, DAI, USDT marks + blind / rotate icons.

Done when: `pick_sign_pages` routes every single-UserOp shape to px and
each family has one e2e scenario and blessed frames.

### 3. Structured flows

- **CoW direct** (`cowswap/swap`, `address_mode`): the Safe-wrapped path
  already emits screens from `append_order_body_pages`; make the direct
  route call the same emitter.
- **ERC-7730** (`erc7730/swap`): add a `Screens` sink to the existing
  FormatOp render in `pqsigner-erc7730::display::render`, so one walk
  produces both pages and screens. Biggest item; start it early.
- **EIP-1271 / off-chain**: PERSONAL_SIGN text, EIP712_TYPED via the
  ERC-7730 sink, counterfactual banner, `! BLIND RAW32` + full hash.
  `cmd_sign_offchain` gets the same px route as `cmd_sign_userop`.
- **Batch** (`batch/transfers`, `transfers_declined`, `unlock_batch`):
  hero-pager band, `SIGNED i OF N` between segments. Re-derive screens per
  segment (the batch signs in place over `SIGN_SNAP_BUF`). One owner
  decision: N asks or one ask.

Done when: every upstream flow family in `flows/MANIFEST.md` has a
firmware twin with frames.

### 4. Everything outside the sign dialog

- **PIN entry** (`pin/unlock`, `pin_entering`, `pin_differ`): pin-row +
  entry-dial on the two buttons. Only the painting changes; `pin_entry.rs`
  logic stays.
- **Verdicts** (`screens/verdict/*`): one registry in
  `pqsigner-ui-px::scene` with the procedural icons; `wipe` gets the
  explosion film.
- **Boot**: 8-word fingerprint on `words-grid` + `firmware_verified`. The
  FSBL window is NOT ported (it stays text).
- **Seed wizard**: words-grid display + entry-dial confirm.
- **Firmware update**: progress status screen → `firmware_verified` /
  verdict.
- **Idle** screens + the 120 s lock → `padlock`.

Done when: cold boot → wizard → unlock → sign → lock → wipe on EVT shows no
text frame.

### 5. Switch over

- Text `Ui` backends become the px presenter; drop the on-device text
  painter. Keep the page painters as host-only fact producers (they are
  what the fact tests compare against).
- Rebase onto `feat/pq1-board-target`, one PR per step above, `make e2e`
  + `make e2e-px` green.

## Flash

Bench/EVT images are monolithic and fit. The A/B-slot ship shape is ~9 KB
over with Safe alone (`make size-report-px BOARD=pq1`); each family adds
code. Port on the monolithic image and re-measure after step 2. The
lever (spare bank-1 pages, feature trim, or code diet) is an owner
decision and is not part of this plan.

## Not in this plan

Deliberately deferred to a separate hardening pass after the port is
visually complete: Kani harnesses, FI twins / transcript proofs, the
design-rule checker gate, production `compile_error!` fences, resource
(stack/BSS/frame-time) proofs, external-model reviews, GPDMA SPI
streaming, upstream PR to PQ-UI. Do not start any of these while porting.

## Owner decisions

1. Batch: N asks or one ask (step 3).
2. Flash lever (after step 2 numbers).

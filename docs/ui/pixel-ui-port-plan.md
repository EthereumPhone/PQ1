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

### 2. Single-UserOp families — DONE (2026-09-23)

| firmware route | upstream flow | emitter |
|---|---|---|
| `value_transfer` | `send`, `contract_call` | `value_transfer_screens.rs` |
| `erc20_known` | `send_token`, `send_token_named`, `transfer_token`, `approve_token` | `erc20_screens.rs` |
| `erc20_unknown` | `transfer_unknown_token` (ramp from the token address) | `erc20_screens.rs` |
| `blind_sign` | `blind/bare_call`, `call_with_value`, `unknown_call` | `blind_sign_screens.rs` |
| `typed_call` | `blind/typed_call/sign_with_args` | `typed_call/screens.rs` |
| `slot_rotation` | `rotate_slot` | `slot_rotation_screens.rs` |
| `deployment` | deploy banner | the `! DEPLOY` trailer twin (`trailer_screens.rs`, step 1) |

How it is wired: `userop_screens.rs` re-walks the tail of the dispatcher
ladder (below Safe / CoW / ERC-7730 / known-call) and hands the route to its
emitter; the shared pieces (`Emit`, amount policies, wrap, caption fit, token
looks) moved from `safe_screens.rs` to `screen_kit.rs` (Safe output
byte-identical). `px_lift` takes a `Body` (Safe / UserOp / Rotation); a
single-UserOp body is bound by re-running its page painter and comparing the
proven body pages byte-for-byte, the rotation body by its one page. Trailers
wear the family's disc (`Look`) and a `TrailerSet::Rotation` covers the
rotation consent (signer, nonce lane, gas lane). `px_route_confirm` sends
every non-Safe route that is not a direct CoW order or an authenticated
ERC-7730 descriptor to the pixel dialog; the rotation consent has its own
route. Where a page cut a value (the function signature at 32 characters,
the calldata hash to 16 of 32 bytes) the screens show all of it; a typed-call
integer the page could only show as `!OVERFLOW` refuses on the pixel path.

Engine: disc icons ETH, USDC, USDT, DAI, blind, rotate (baked marks; the
atlas is 74,204 B of its 77,824 B NS window — every mark but `safe` is
trimmed to fit), the placeholder-ramp tint (`colors.PLACEHOLDER_GRADIENTS`,
hashed like `placeholder_index`), unbranded endings (black disc, green /
red stroke) with per-family captions via `lcd::set_film_look`.

Evidence: `userop_screens_render_pure_tests` (12 scenarios through the real
dispatcher + trailer painters: route, lift proof, fact differential over body
AND trailers, design-rule checker, record goldens, fixtures under
`pqsigner-ui-px/tests/fixtures/<family>/` with blessed frame goldens); secure
host tests 2608/0; `pqsigner-ui-px` tests green with the Safe goldens
unchanged; `make e2e-px` all assertions passed (24 pixel transcripts; a pixel hero per family — APPROVE, EXECUTE, SEND, CALL, TRANSFER, UNKNOWN, BLIND, ROTATE; the `DEPLOY` trailer twin; zero Legacy records); catalogue `docs/ui-screens/px/` regenerated (362 frames, 19 scenarios; the four Safe scenarios byte-identical). The suite gained Scenario 4a (zero-value
contract call), 4b (unknown-token transfer) and 4c (first deploy with
initCode).

Not ported, on purpose:

- `forced_blind` (default-off `erc7730-forced-blind`): its consent is
  `confirm_forced_checked` (two phases, deadlines, request-bound receipts),
  not the page dialog. Porting it needs a pixel twin of that ceremony, not
  an emitter; it stays on the page dialog until then.
- Token logos are drawn as the white part of the art on the token-colour disc
  (the atlas carries 4-bit masks, not colour art), and the USDC / USDT / DAI
  marks are third-party brand assets with no production sign-off gate like
  `safe_logo_approved` yet.
- The firmware trail darkens toward the disc; upstream `trail_chain` paints
  the brightest follower next to it. Fixing it re-blesses every golden
  (Safe included) — one line, left for a deliberate re-bless.

Flash after step 2 (`make size-report-px BOARD=pq1`): the ship-shaped A/B
image overflows the secure slot by 25,408 B (Safe alone: 9.2 KB). The
monolithic EVT dev image (`FEAT_S=dual-se,dev-testkey,ui-lcd,ui-px,dev-dfu,stm32u585,usb,board-pq1
tools/evt-dev-flash.sh --build-only`) links: 494,816 B secure, 97,808 B
non-secure. The flash lever stays an owner decision (see § Flash).

### 3. Structured flows — DONE (2026-09-23)

| firmware route | upstream flow | emitter |
|---|---|---|
| direct CoW order | `cowswap/swap`, `cowswap/address_mode` | `cowswap_screens.rs` (the order body is shared with the Safe-wrapped presign) |
| ERC-7730 contract call | `erc7730/swap` | `erc7730_screens.rs` (`Surface::Contract`) |
| off-chain `personal_sign` | `eip1271/personal_counterfactual` | `offchain_screens.rs` |
| off-chain RAW32 | `eip1271/personal_counterfactual_hash` | `offchain_screens.rs` (`! BLIND RAW32`, full hash) |
| off-chain EIP-712 typed | — (ERC-7730 typed) | `erc7730_screens.rs` (`Surface::Typed`) |
| batch member / final ask | `batch/transfers`, `transfers_declined` | `batch_screens.rs` + the member's own route |
| erc8213 fingerprints | `fingerprint/*` | the `FP8213` / `DIGEST` trailer twins (step 1) |

How it is wired: `px_lift::Body` gained `Cow`, `Erc7730 { pages, start,
body_len }`, `Offchain`, `BatchMember { index, total, inner }` and
`BatchSummary`; the body is bound to the proven pages at an offset
(`body_bound(body, pages, start, len)`), so a batch member binds its banner
page and then its inner route one page in. `px_route_confirm` now sends every
sign route to the pixel dialog; `cmd_sign_offchain` (typed, personal, RAW32)
and `cmd_sign_userop_batch` (rotation consent, each member, the final ask)
route the same way and play the signing film. `TrailerFacts` gained the sets
`Offchain` (fingerprint, RAW32's replay-safe fingerprint, the three
signer / wallet / mode context pages), `BatchMember` and `BatchFinal`.

Decisions and deviations from the plan text above:

- **ERC-7730 is a page lift, not a renderer sink.** The screens are laid out
  from the proven, two-pass-checked 7730 page range itself (row 0 = field
  label, rows 1-3 = value; split addresses re-joined, `1/2`/`2/2` word pages
  and the hex nonce merged into two-page screens, navigation rows dropped).
  A sink inside the 13k-line audited renderer would have touched every
  `FormatOp` painter, which "the one rule" forbids; the lift carries every
  fact by construction and the fact test checks it.
- **Batch (owner decision 2026-09-23): N asks + the final ask**, i.e. today's
  gating unchanged. Each member dialog is its own route body with a `BATCH`
  screen (`BATCH SIGN` / `Tx i of N`) after the hero; between members the
  device shows `TX i OF N CONFIRMED`, never `SIGNED` (nothing is signed
  before the final `SIGN N TXS?`). The batch snapshot can fill the whole
  shared buffer, so the pixel transcript uses the tail past the request: a
  batch request over 29,291 B is refused on the pixel route (`px scratch`).
- **CoW decoded legs now show the token** (verified name over the full
  contract address) on the Safe-wrapped route too — step 1 dropped the page's
  anti-spoof token page for decoded legs; no Safe golden covered it.
- `forced_blind` stays on its own ceremony (unchanged from step 2).

Engine: `Icon::Cowswap` (the navy cow head baked from `cowswap.png`, branded
`#65D9FF` disc and brand trail; signed ending fills the disc with a navy
check), `Screens::insert_after_hero` (the batch position screen, disc
alternation kept). Atlas 74,816 B of the 77,824 B NS window.

Evidence: `structured_screens_render_pure_tests` (11 scenarios: direct CoW
decoded + address mode, ERC-7730 Uniswap with and without UserOp fields,
personal_sign counterfactual, RAW32, EIP-712 typed, batch member and final
ask, plus binding refusals for a different order and the wrong batch
position — route, lift proof, fact differential, design-rule checker, record
+ frame goldens under `pqsigner-ui-px/tests/fixtures/{cowswap,erc7730,
eip1271,batch}/`); step-1/2 goldens unchanged; secure host tests
2619/0; e2e Scenarios 5q-direct, 5p-personal, 5p-raw32 added;
`make e2e` and `make e2e-px` ALL ASSERTIONS PASSED (47 pixel transcripts, the
5e-rt-erc20 row check has a pixel twin); catalogue `docs/ui-screens/px/`
regenerated (721 frames, 30 scenarios; every step-1/2 frame byte-identical, 5m-nested gained its ERC-7730 dialog).

Flash after step 3: the ship-shaped A/B image (`make size-report-px BOARD=pq1`)
overflows the secure slot by 39,520 B (25,408 B after step 2). The monolithic
EVT dev image links: 508,928 B secure, 97,808 B non-secure. The flash lever
stays an owner decision (see § Flash).

Done: every upstream sign-flow family in `flows/MANIFEST.md` has a firmware
twin with frames. `firmware/update`, `pin/unlock` and `unlock_batch` (PIN →
batch idle → padlock) are screens outside the sign dialog — step 4.

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

1. ~~Batch: N asks or one ask (step 3).~~ Decided 2026-09-23: N asks + the
   final ask (today's gating), `CONFIRMED` between members.
2. Flash lever (after step 2 numbers).

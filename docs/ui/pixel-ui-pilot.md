# Pixel trusted UI (`ui-px`) — the PQ-UI port, Safe-flow pilot

**Status (2026-09-22):** engine + Safe sign flow implemented on
`feat/ui-px-safe-pilot` (off `feat/pq1-board-target`). QEMU e2e passes with
`ui-px` (all 24 scenarios; the Safe scenarios print `[UI-PX]` screens); the
EVT image builds; **ran on glass 2026-09-22** (EVT #1, branch `ui-px-evt` = this branch + `pq1-evt-dfu`, flashed over ROM DFU with `FEAT_S=dual-se,dev-testkey,ui-lcd,ui-px,dev-dfu,stm32u585,usb,board-pq1 tools/evt-dev-flash.sh`; `tools/hid_sign_safe.py` sent the Scenario-5 Safe `approveHash` UserOp on Base and the device clear-signed it end to end — SW 0x9000, well-formed Type-2 wrapper, ownerIndex 1 — after the human walked the pixel flow and held right; fps / orientation notes pending); **does not fit the release A/B
slot** (see Budgets). Owner decisions that shaped it are in
`CLAUDE.md` Pre-Production Caveats and `docs/security/HARDENING.md` §2.4.

Design source: `EthereumPhone/PQ-UI` (Elie Munsi), vendored subset in
`tools/pq-ui/` (pinned in `tools/pq-ui/UPSTREAM.txt`); the spec is
`tools/pq-ui/pq1/DESIGN.md`. Device firmware implements § Input natively.

## Architecture — one classification, two painters

```
verified Safe inputs ──► safe_display::classify()  (FI gates, refund / inner-ETH / safeTxGas decisions, InnerKind)
        ├──► safe_display.rs  paints 16×4 Pages  ─► every existing enforce_* / *_proof (unchanged, always)
        └──► safe_screens.rs  emits Screens      ─► px_lift: Legacy-wrap the trailer pages, returning hero,
                                                    Confirm? at index 5, transcript_proof (FI sentinel)
                                                        ─► ui::px::confirm_px  (FlowDriver grammar, FihBool arming)
                                                              ├─ text presenter   (QEMU: [UI-PX]/[UI-PXR] + [UI-FP])
                                                              └─ px::lcd          (NV3007: strips, springs, SysTick edges)
```

* **`pqsigner-ui-px`** (pure, `no_std`, no heap, `#![forbid(unsafe_code)]`):
  `screen` (256-byte printable-ASCII records; `Screens` overlays a byte
  scratch region), `fit` (tier table + baked advance widths; never
  truncates), `driver` (hub / page-first / commit arming), `input` (tap ≤ 250,
  hold 2000, snap-back 200, chord 150, debounce 30 ms), `motion` (Q16 springs,
  curves, cycles), `raster` (428×N RGB565 strips, AA disc/ring/chord/chevron/
  marks, 4-bit glyph blit), `font` (atlas reader), `scene` (DESIGN.md grid +
  the animation runtime), `metrics_gen` (generated advance tables).
* **Secure world:** `tx/display/safe_screens.rs` (emitter),
  `tx/display/px_lift.rs` (wrap + proof, double emit with SHA-256 receipt),
  `nsc::px_confirm_safe` (overlay on the `SIGN_SNAP_BUF` tail — zero extra
  BSS), `ui/px/{confirm_px,text,lcd,assets}.rs`.
* **Trailers** (fees, signer, target, gas lane, ERC-8213, paymaster, nonce
  lane, deploy) are shown as `Legacy` screens (the proven page bytes,
  Aileron 22 px) in the pilot; native twins are the next step.

## Screens (Safe)

Hero `APPROVE SAFE TX?` / `EXECUTE SAFE TX?` → `NETWORK` (chain mark) →
`SAFE ACCT` → `TX INFO` (nonce, op) → refund block (3) → `SAFE VALUE` →
`SAFETX GAS` → inner call (ERC-20 `SEND/APPROVE/PULL` + `TOKEN` + `TO`/`SPENDER`
+ `CONTRACT`; blind: `BLIND SIGN` + `TO` + `CALL DATA` + full `DATA HASH`;
Safe-mgmt ops; CoW order: `COW ORDER`, `SELL`/`BUY`, `RECEIVER`, `EXPIRES`,
`FEE (SELL)`, `SOURCES`, `APP DATA` (2 pages); multiSend: `RECORD i/N` +
`REC VALUE` + per-record screens) → Legacy trailers → `Confirm?` (auto, when ≥ 7
details) → returning hero. Addresses: EIP-55, 2 × 21 chars at 22 px, or 3 × 14
when the uppercase-heavy string exceeds 276 px. Endings: `SIGNED SAFE TX`
(branded disc + check), `SAFE TX DECLINED` (red disc + X).

Host goldens: `secure/src/display_under_test/safe_screens_render_pure_tests.rs`
(per-scenario record hashes + the legacy→screens fact differential) and
`pqsigner-ui-px/tests/golden.rs` (frame hashes; `UI_PX_PNG=1` writes PNGs to
`target/ui-px-golden/`).

## Build, run, test

```bash
make ui-px-assets            # re-bake fonts/marks + metrics_gen.rs (Pillow)
make ui-px-assets-check      # reproducibility gate
cargo test -p pqsigner-ui-px # 55 unit tests + 4 frame goldens
cargo test -p sphincs-tz-secure --tests --release   # 2592 host tests (incl. 13 screen/lift tests)
make e2e-px                  # QEMU e2e with ui-px (every scenario + the ui-px transcript assertions)
make play-hw-px BOARD=pq1    # EVT: flash + physical buttons (probe-rs path)
make play-hw-px BOARD=pq1 PX_EXTRA_FEATURES=,ui-px-spi40   # 40 MHz SPI variant
```

Feature axis: `ui-px` is additive over the backend (`ui-lcd` → pixel
presenter; `ui-semihosting` → text presenter). Fences: `ui-px` ×
`ui-oled-bench` refused; `mode-production` + `ui-px` requires `ui-lcd`;
`build.rs` validates the assets against `manifest.json` and refuses the Safe
brand mark in a production image without `safe_logo_approved`.

## Budgets (measured 2026-09-22)

| image | text | data | bss |
|---|---|---|---|
| dual-SE LCD standalone (`build-hw-dual-se-lcd-standalone`, pq1) | 417,289 | 10,536 | 42,648 |
| + `ui-px` (code, transcript overlay, no assets yet in that config) | 443,305 | 10,536 | 42,648 |
| dev pq1 image `mock-se,debug-log,ui-lcd,ui-px` (engine + assets) | 530,872 | 9,984 | 61,024 |

Assets: `fonts.bin` 68,867 B (4-bit, eight tiers, trimmed charsets) +
three marks 5,070 B. Engine code ≈ 17 KB, screen emitter/lift/driver ≈ 26 KB.
**UPDATE 2026-09-23:** the atlas no longer lives in the secure image (owner
decision, port plan § Flash: `nonsecure/assets/ui-px/atlas.pq1a`
at a fixed NS-slot offset, root-pinned and re-proved by the secure world
around every dialog). Measured with `make size-report-px` on the nearest
buildable ship shape: 432,448 B without `ui-px`, **476,160 B with it** —
still 9.2 KB over the 466,944 B v6 secure slot; the ≥ 40 KB headroom gate is
not met and the remaining lever (geometry / feature set / deeper diet) is an
open owner decision.

**UPDATE 2026-10-05 — the 9.2 KB above was Safe-only; all nine families are
78.5 KB over, and a profile change recovered 82% of it.** Re-measured with
`make size-report-px BOARD=pq1`, physical span cross-checked against
`readelf -l` LOAD:

| build | span | vs the 466,944 B slot |
|---|---:|---:|
| no `ui-px` | 431,680 B | fits, 35,264 B spare |
| + `ui-px`, `opt-level = "s"` | 545,504 B | **78,560 B OVER** |
| + `ui-px`, secure `opt-level = "z"` | 481,376 B | 14,432 B over |
| + `ui-px`, everything `"z"` | 475,648 B | **8,704 B over** (current) |

At `"s"` the image did not merely exceed the gate, it would not LINK:
`region FLASH overflowed by 70368 bytes`. Moving `[profile.release]` to `z`
recovered 64,128 B with no code deleted and no family
dropped. Crypto stays at opt-level 3 (signing throughput unaffected) and
`pqsigner-ui-px` stays at `"s"`; the further 5,728 B that `"z"` buys there needs
an on-panel `ui-px-frametime` run first.

**Frame time is not fenced off by that override, and is unmeasured at `z`.**
The per-frame work is split across two crates and the slower half is in
`sphincs-tz-secure`, which moved to `z`: `ui::px::lcd::present_frame_ex` and
`blit_strip` are the presenter and the SPI push, measured at 24 ms for nine
strips (~13 ms with unchanged strips skipped) against a 24 ms frame period —
the bottleneck. The raster and glyph compositing left at `"s"` are only
8-11 ms. So `z` put the dominant frame cost at `z`. An on-panel
`ui-px-frametime` run gates shipping it; if the hero sweep regresses, give the
presenter its own profile override rather than reverting the parent profile,
which is what makes the image linkable at all.

**UPDATE 2026-10-05b — `pqsigner-ui-px` also moved to `z` (owner request), and
the security properties were re-verified at that profile.**

Image: **475,648 B**, 8,704 B over the slot. Frame time is UNMEASURED: both
halves of the per-frame path are now at `z`, `ui-px-frametime` requires
`ui-lcd` and a real panel (no host or QEMU path), and no device was attached by
any channel when this landed — not probe-rs, not DFU. Run it on the EVT unit
comparing s/s, z/s and z/z on the same hero sweep; a lone z/z number against
the 2026-09-22 baseline is confounded by two weeks of code change. If the hero
sweep regresses, revert the `pqsigner-ui-px` override to `"s"` (5,728 B) before
touching the parent profile.

What WAS verified at `z`:

- **Constant time.** `make checkct` (binsec relational proof, thumbv8m):
  `driver_kdf`, `driver_fors`, `driver_th`, `driver_saes`, `driver_ct_eq` all
  report `secure`, 2,326 control-flow and 11,132 memory-access checks passing.
  The by-design-insecure `fisher_yates` control still reports `insecure`, so
  the proof is not vacuous. NOTE: `make checkct` therefore always exits
  non-zero — read the per-driver verdicts, not the exit code.
- **The CT harness had to move with the root.** `tools/sca/checkct/Cargo.toml`
  is a separate workspace whose `opt-level` is a hand-written MIRROR of the
  root's, precisely "so the CT proof exercises the codegen the device actually
  ships". The root's move to `z` left it at `s`, which would have certified
  codegen the device does not ship. Both are now `z`, and
  `make check-checkct-profile` binds them (negative control: it fails when
  they differ).
- **FI double-compute intact.** `c10_sign_verified_with_progress_inner` still
  contains 2 `sign_with_shuffle` calls and 2 FI verified-checks, identical to
  `s`. `ct_eq` and `CfiCounter` symbol counts unchanged.
- **Pinned crypto byte-identical.** `sphincs_c10::{verify, sign_with_shuffle,
  wots::keygen_pk, merkle::verify_auth_path}` and `sha2::{compress256,
  compress512}` are the same size at s and z, so per-package `opt-level = 3`
  survives fat LTO and signing throughput is unaffected.
- **A metric that does NOT work at `z`.** Static FI call-site counts fall
  247 -> 203, which looks like 44 lost FI checks. It is not: `z` enables LLVM's
  MachineOutliner, which factors identical FI call sequences into
  `OUTLINED_FUNCTION_*` helpers — 5 helpers hold 1 FI call each and are invoked
  39 times. Per-function FI attribution is likewise invalid (it reported
  `multisend_sign_gate` 4 -> 0 while the calls had moved into outlined
  helpers). Do not use static counts to argue FI health at `z`.

Still OPEN: the repo's own gate for this question, `make check-fi-ir` ("the FI
recompute guard must survive -O"), is DEAD — `scripts/check_fi_ir.sh` is not
tracked in git, the target fails with Error 127, and it runs in no CI job.

The FSBL is pinned back to `"s"`, but the pin is PARTIAL: span went 28,704 B
(all-s) -> 19,708 B (all-z) -> 20,464 B (z + pin), so only ~756 B of 8,996 B
reverted, because a per-package override does not reach dependencies
(sphincs-tz-bip39, fw-manifest, pqsigner-geometry, cortex-m*). The trust root's
18/18 on-silicon boot proof and the 10,372-B stack bound of invariant #10 were
both taken at all-`s` and have NOT been re-taken.

Where the 113,824 B went, at `"s"`: **.text +103,584 / .rodata +9,472 /
.data +776 — 91% is code.** Pre-existing functions grew only 8,742 B, and the
shared `tx::display` decode/classify modules SHRANK 1,482 B: the decode logic
is genuinely shared and is not the cost. The cost is a second *presentation*
stack. Largest single items: `scene::Anim::build` 12,090 B (the whole scene
builder inlines into it), `userop_screens::emit` 7,732, `ui::px::lcd::
present_frame_ex` 4,310, `px_lift::emit_body` 2,234. For erc7730, userop, cow,
offchain and the trailers the pixel emitter *adapts* the 16×4 painter's
`Pages` rather than drawing natively (see the header of
`tx/display/erc7730_screens.rs`: the planned in-renderer `Screens` sink was
dropped so the audited renderer stays untouched), `safe_screens` and
`batch_screens` are native, and `px_lift` is a third layer proving the two
agree.

Bank occupancy, for the geometry lever: bank 1 has **zero** spare pages — the
frozen registry owns all 128, and the port plan's "spare bank-1 pages" do not
exist. The bank-2 NS slot has **275,100 B free** (149,436 B NS image +
75,176 B atlas, of `NS_SLOT_SPAN` 499,712 B). Bank 2 is likewise fully owned by the
registry — that 275,100 B is slack INSIDE the two NS slots, not unowned pages —
so every option below re-lays both banks and needs a bank-2 secure watermark
(RM0456 allows one per bank), the FSBL reading through the secure alias with
SAU (the trap that silently hashed 7,488 zero bytes on 2026-09-16), and a
re-review of the frozen Draft 1.1 registry digest.

At `opt-level = "z"` the image needs 59 pages, not the 67 it needed at `"s"`,
which changes the shape of the ask: two 59-page secure slots DO fit in bank 1
(5 FSBL + 2 manifest + 59 + 1 journal + 59 + 1 journal = 127 of 128) if the
five per-device state pages 123-127 move to bank 2. But 59 pages is 483,328 B
against a 481,376 B image — about 1.9 KB spare, which is LESS than the "few KB"
the Makefile itself budgets for `rdp2-self-lock`. So that layout is not
"fits"; it is arithmetically possible and operationally too tight. Report it
as a direction, not a solution.

Carve-out: the FSBL draws the boot fingerprint with its own `nv3007` +
`draw_text` (`fsbl/src/render.rs`) in a separate image capped at
`FSBL_MAX_LOAD_SPAN` 38,912 B and WRP-frozen at RDP-2. The 37.6 KB pixel
engine cannot live there, and invariant #10 wants that window visually
distinctive. "No 16×4 text UI anywhere" excludes the FSBL boot window.
Strip buffer: 13,696 B BSS on `ui-lcd` builds; the transcript costs no BSS
(overlay). QEMU e2e stack/BSS: unchanged vs baseline.

Frame time, **measured on EVT #1 (2026-09-22, `ui-px-frametime` overlay,
DWT cycles)** after the renderer / presenter fixes of that day: on the
sweeping hero at 40 MHz SPI (`ui-px-spi40`, clean on the production panel)
render ≈ 8–11 ms, blit 24 ms for all nine strips and ≈ 13 ms once unchanged
strips are skipped (per-strip 64-bit digests), frame period ≈ 24 ms
(≈ 40 fps; the 16 ms cap never binds). Before the fixes the same hero was
> 100 ms per frame: the disc / ring / trail evaluated a 64-bit-divide Newton
square root for every pixel of each circle's bounding box.

**Input on hardware.** Taps are debounced in the SysTick ISR (30 ms lockout
per side, first edge exact), replayed with their timestamps, and the frame
clock is read after the replay. `TAP_MAX_MS` is **500 ms on the device**
(the PQ-UI reference said 250 when this was written, and ADOPTED 500 in
198bbcb9 — it is no longer a deviation): deliberate presses on the pq1 switches run
250–400 ms and were being demoted to aborted holds ("only a double-click
advances", EVT #1 2026-09-22). **The sign gesture on the device is the
two-button chord click** (both down together, fires on release; owner
decision 2026-09-22 for parity with the legacy dialog) — hold-right is a
no-op, hold-left declines; the disc floods while the chord is held. See
`docs/security/HARDENING.md` § 2.4.

## Known gaps / next steps

The port of every remaining screen (single-UserOp families, structured flows,
PIN/verdicts/boot, switch-over) is `docs/ui/pixel-ui-port-plan.md`
(rewritten 2026-09-23); this pilot is its step 1. **UPDATE 2026-09-23:**
step 2 is done — every single-UserOp route (value / contract call, ERC-20
known and unknown, typed call, blind sign) and the slot-rotation consent go
through the same lift (`px_lift::Body`), with the new disc icons, the
placeholder-ramp tint and unbranded endings; see the plan's step 2 for the
evidence and what stayed on the page dialog (`forced_blind`). **UPDATE 2026-09-23
(later):** step 3 is done — direct CoW, ERC-7730 (a lift of the proven 7730
pages), the off-chain kinds and the batch (N member asks + the final ask)
confirm through the pixel UI too; see the plan's step 3.

1. ~~Run on the EVT~~ — done 2026-09-22 over the cable-free DFU loop
   (`FEAT_S=... tools/evt-dev-flash.sh`, `tools/hid_sign_safe.py`): strip
   orientation correct, `ui-px-spi40` clean, ≈ 40 fps on the sweep, taps and
   the chord sign verified after the fixes above. Next lever if more is wanted:
   GPDMA for the SPI stream so render and blit overlap (≈ 13 ms frames).
2. ~~**Endings during the sign**~~ — done 2026-09-23 (port plan step 1): the qubit loading film (`pqsigner_ui_px::loading`,
   `ui::px::lcd::film_*`) plays around the sign, paced by the signer's
   progress hook, and lands with the design's `RESULT_HOLD_MS`.
3. ~~**Native trailer screens**~~ — done 2026-09-23 (`tx/display/
   trailer_screens.rs`, eleven slots with per-slot + set proofs; the
   `Legacy` kind is unused on every pixel route, which since step 2 includes
   the single-UserOp routes and the rotation consent, and since step 3
   every sign route). Still open: the families outside the sign dialog
   (boot, PIN, wizard, verdicts — step 4).
4. ~~`tools/ui_screens_export.py --px`~~ — done: `docs/ui-screens/px/`.
5. ~~Kani~~ — installed (`kani-verifier 0.67.0`); `cargo kani -p
   pqsigner-ui-px` runs the `fit`, `driver` and `check` harnesses.
6. **Flash (owner decision still open):** the atlas moved to the NS slot
   (see the port plan § Flash), yet the ship-shaped image with `ui-px`
   is 476,160 B vs the 466,944 B v6 secure slot — 9.2 KB over.
7. Two branch fixes rode along: `hw/sca_trigger.rs` referenced `crate::board`
   on QEMU builds (gated on `sca-trigger`), and the QEMU mailbox transport
   lacked `get_pin_attempt_log_call`.


## UPDATE 2026-09-30 — re-synced to PQ-UI 198bbcb9 (the Sep-27 re-audit)

The vendored design system moved from `0b3ca495` (Sep 22) to `198bbcb9`
(Sep 28) and the port was brought into conformance with it. What changed
here:

* **`placeholder_ramp` hashes over 13 ramps, not 14** (`MONO_RAMP`). The
  reference's own fix, audit COL-01: a hashed key reaching the mono ramp
  drew a disc byte-identical to ether's, and the address form of that key
  is chosen by whoever deploys the contract. See the commit for the scope.
* `DEBOUNCE_MS` 25 -> 30 and `PRESS_FEEDBACK_MS` 120 -> 145 (the
  two-panel-frame floor). The debounce is **not re-validated on glass**.
* Placeholder ramps 0 and 12 retuned; marks re-centred on their ink, so
  the atlas is 75,176 B of its 77,824 B NS window.
* **Left no longer leads on from the ask** (RULES.md § A): a left tap on
  either ask is inert, right enters. Hold-left still declines everywhere.
* `pq-ui-port-diff` now checks the palette and the hash rule as well as
  the timings — 26 timing rows + 96 colour rows.

`spec/colors.json` and `spec/icons.json` reached the handoff only in this
upstream revision; before it nothing bound the palette at all.

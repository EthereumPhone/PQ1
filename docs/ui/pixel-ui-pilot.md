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
  hold 2000, snap-back 200, chord 150, debounce 25 ms), `motion` (Q16 springs,
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

**Input on hardware.** Taps are debounced in the SysTick ISR (25 ms lockout
per side, first edge exact), replayed with their timestamps, and the frame
clock is read after the replay. `TAP_MAX_MS` is **500 ms on the device**
(the PQ-UI reference says 250): deliberate presses on the pq1 switches run
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
evidence and what stayed on the page dialog (`forced_blind`).

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
   the single-UserOp routes and the rotation consent). Still open: direct
   CoW, ERC-7730, batch and off-chain routes; the remaining families (boot,
   PIN, wizard, verdicts).
4. ~~`tools/ui_screens_export.py --px`~~ — done: `docs/ui-screens/px/`.
5. ~~Kani~~ — installed (`kani-verifier 0.67.0`); `cargo kani -p
   pqsigner-ui-px` runs the `fit`, `driver` and `check` harnesses.
6. **Flash (owner decision still open):** the atlas moved to the NS slot
   (see the port plan § Flash), yet the ship-shaped image with `ui-px`
   is 476,160 B vs the 466,944 B v6 secure slot — 9.2 KB over.
7. Two branch fixes rode along: `hw/sca_trigger.rs` referenced `crate::board`
   on QEMU builds (gated on `sca-trigger`), and the QEMU mailbox transport
   lacked `get_pin_attempt_log_call`.

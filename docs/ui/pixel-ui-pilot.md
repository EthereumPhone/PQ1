# Pixel trusted UI (`ui-px`) — the PQ-UI port, Safe-flow pilot

**Status (2026-09-22):** engine + Safe sign flow implemented on
`feat/ui-px-safe-pilot` (off `feat/pq1-board-target`). QEMU e2e passes with
`ui-px` (all 24 scenarios; the Safe scenarios print `[UI-PX]` screens); the
EVT image builds; **not yet run on glass**; **does not fit the release A/B
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
make e2e-px                  # QEMU e2e with ui-px (24/24)
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
**The 464 KB A/B release slot cannot hold the dual-SE image plus the atlas**
(≈ 428 KB + 74 KB). Levers, in order: code diet in `safe_screens.rs` /
`confirm_px`, 2-bit alpha on the 36/32/28 tiers (−18 KB), drop SB22
(−7 KB), fewer tiers, or a different flash geometry. Owner decision pending.
Strip buffer: 13,696 B BSS on `ui-lcd` builds; the transcript costs no BSS
(overlay). QEMU e2e stack/BSS: unchanged vs baseline.

Frame time (estimated, to be measured on the EVT): render ≈ 3–8 ms, blit
48.6 ms @ 20 MHz SPI (≈ 17 fps), 24.3 ms @ 40 MHz (`ui-px-spi40`).

## Known gaps / next steps

1. **Run on the EVT** (`play-hw-px BOARD=pq1`): measure fps, verify the
   strip orientation on glass, tune `ui-px-spi40`, check the SysTick edge
   sampler against the physical buttons.
2. **Endings during the sign:** the design's qubit loading film is not
   implemented; signing shows the legacy progress text painted through the
   engine, then the branded resolve plays (`px::lcd::show_ending`).
3. **Native trailer screens** (fees, signer, target, gas lane, DATA HASH,
   paymaster, nonce lane, deploy) with `*_screen_proof` twins; batch and
   off-chain routes; the remaining families (boot, PIN, wizard, verdicts).
4. `tools/ui_screens_export.py --px` (the screens catalogue on this branch
   does not exist yet; master has `docs/ui-screens/`).
5. `cargo kani -p pqsigner-ui-px` harnesses exist (`fit`, `driver`) but
   Kani is not installed on this box.
6. Two branch fixes rode along: `hw/sca_trigger.rs` referenced `crate::board`
   on QEMU builds (gated on `sca-trigger`), and the QEMU mailbox transport
   lacked `get_pin_attempt_log_call`.

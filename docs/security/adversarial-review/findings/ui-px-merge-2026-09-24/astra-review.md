**I would block this merge.** I reviewed incoming tip `5c27782e` against `77a0fe10`. Line numbers below refer to that tip. No files modified. Reproductions used in-memory data; I did not run hardware attacks.

1. **CONFIRMED — HIGH: atlas verification does not protect the pixels rendered between checks.**

   `secure/src/ui/px/assets.rs:55` creates a live slice into NS flash. `verify_atlas()` hashes it, then returns borrowed views (`:109`). `pqsigner-ui-px/src/font.rs:77` subsequently reads glyph records and bitmaps through those views. Nothing copies the verified atlas into secure SRAM.

   Your boot-only suspicion is **partly incorrect**: signing checks immediately before and after the dialog (`secure/src/nsc/mod.rs:1108,1122`). Status/progress rendering uses a cached verdict (`assets.rs:133`). **Neither prevents swap–render–restore.**

   The atlas starts at `0x08101000` (`nonsecure/memory-stm32u585-px.x:22`). SAU leaves that bank and the NS peripheral window non-secure (`secure/src/sau.rs:760,784`); there is no atlas write protection. NS can unlock/program its flash controller. `PRIS` prioritizes secure interrupts; it does not prevent an NS interrupt from preempting Secure thread-mode execution. See [STM32 RM0456, §7.9](https://www.st.com/resource/en/reference_manual/rm0456-stm32u5-series-armbased-32bit-mcus-stmicroelectronics.pdf) and [Arm’s security guide, §8.3.1](https://documentation-service.arm.com/static/67936b5127eda361ad4e5c0d?token=).

   **Exploit:** compromised NS runs a flash writer from NS SRAM, substitutes digit glyphs after verification, lets Secure render a false amount, then restores the original pages before confirmation returns. Both hashes pass; the signed amount remains unchanged. Using the actual atlas blob, I demonstrated that replacing the `9` glyph records with `1` records changes their rendering while restoring the blob restores the pinned hash.

   **Minimal fix:** keep signing glyphs in secure flash, or copy the atlas into secure SRAM, authenticate **that copy**, and render exclusively from it. More endpoint rehashes do not fix this.

2. **CONFIRMED — HIGH: confirmation can succeed before the request’s first frame is displayed.**

   In `secure/src/ui/px/lcd.rs`, sampling starts at `:734`, signing arms at `:758`, and queued gestures are processed at `:769`. A `ChordClick` can produce `Signed` at `:797`; the loop exits at `:821`. The first `build_and_present()` is later, at `:839`.

   **Exploit:** after sampling starts, compromised NS delays the secure thread while secure SysTick records a physical chord. On resumption, the loop accepts that queued chord while the panel still contains the previous screen. The affirmative sentinel proves acceptance of an input event, not presentation of this request.

   This is separate from intentionally permitting approval on the opening screen: **the opening screen need not have appeared.**

   **Minimal fix:** finish presenting the current approval screen before arming; discard earlier gestures and require a fresh press/release sequence after presentation.

3. **CONFIRMED — HIGH: the ERC-7730 pixel adapter silently removes signed field content.**

   `secure/src/tx/display/erc7730_screens.rs:87` classifies every row beginning with `"> "` as navigation. The field loop drops those rows at `:333`. Its `trimmed()` function also removes meaningful leading spaces (`:73`).

   This is reachable through the admitted Celo `setName(string)` descriptor in `secure/data/erc7730/curations/files/registry/celo/calldata-celo_accounts.json:303`. The original formatter preserves printable string bytes (`pqsigner-erc7730/src/display/render/formatters.rs:2618`).

   **Exploit/reproduction:** `"> Alice"` and `"> Carol"` produce different original pages but identical pixel field content: `NAME` and `7 bytes`, with the name omitted. Likewise, `"Alice "` and `" Alice"` become identical displayed content, including the same length. A malicious companion can substitute these signed operands without a corresponding visible change.

   The pointer/range check in `secure/src/tx/display/px_lift.rs:262` does not detect this lossy transformation.

   **Minimal fix:** identify navigation structurally, not from arbitrary text. Preserve field bytes and spacing. As an immediate containment, refuse affected strings on the pixel route.

The remaining requested checks:

- **#2 — C10: no confirmed cryptographic-chain regression.** I read `secure/src/crypto.rs` and `sphincs-c10/src/{hypertree,merkle,wots,near_miss}.rs`, plus the actual display callbacks. Both computations remain (`crypto.rs:317,324`), followed by constant-time comparison (`:339`), verification (`:374`), and final CFI validation (`:398`). Independent shuffle seeds remain.

  Reports are **not exclusively fixed leaf counters**: Merkle reports every 16 leaves; WOTS grinding reports every 4,096 attempts (`wots.rs:80`). That count is message-dependent but published in the signature. I found no new secret-dependent callback argument. Concrete callbacks execute secure UI code; NS does not supply the function pointer. However, `fn(u8)` is not an isolation boundary: callbacks mutate display state and perform MMIO.

  **SUSPECTED, unproven:** the additional display activity provides power/fault synchronization landmarks in both redundant computations. The passes remain distinguishable; matching percentages do not make them indistinguishable. This is not demonstrated key leakage or a double-compute bypass. Removing the new hot-path display calls contains that concern pending measurements.

- **#3 — handlers: no additional release/accounting bypass found beyond finding 2.** Read `secure/src/nsc/{cmd_sign_userop,cmd_sign_userop_batch,cmd_sign_offchain,mod}.rs`. Confirmation/sentinel gates remain. Type-2 tally commits precede signature output: single `:2634` before `:2696`; batch `:2727` before `:2775`. Off-chain counter commit remains before release (`cmd_sign_offchain.rs:1347`). NS input snapshots and output-pointer checks remain. Compile-error fences: **44 → 46; none removed**. Pixel auto-confirm is `#[cfg(feature = "e2e-test")]`; its production incompatibility survives at `nsc/mod.rs:502`.

- **#4 — Safe: no additional classification/refusal regression found.** Read `safe_display.rs`, `safe_screens.rs`, `dispatch.rs`, `px_lift.rs`, Safe verification/exec/MultiSend/CoW-binding code, `tx/src/multisend.rs`, and the pinned constants. The three-address DELEGATECALL allowlist, every-record `operation == 0`, six-record cap, per-record metadata/value handling, and overflow refusals survive. Key gates remain at `safe_display.rs:1132,1237`; pixel record-count checks remain at `safe_screens.rs:405`. Findings 1–2 still compromise the resulting consent.

- **#5 — dev DFU: Makefile protection works; the compile fence is missing.** Read `dev_dfu.rs`, its module/call sites, `secure/Cargo.toml`, and the Makefile gate. `PROD_FORBIDDEN` includes `dev-dfu` (`Makefile:2653`) and checks the correct **secure crate** (`:2721`). But the code is gated only by `dev-dfu`/`stm32u585`; direct Cargo builds lack a dedicated production incompatibility. It runs before normal boot protections (`main.rs:1143`). Add that compile fence. I did **not** establish a canonical-release bypass or an RDP2 firmware-replacement path; other production quarantines also remain.

- **#6 — firmware verification: no weakening found.** Read `secure/src/fw_update/{verify,mod}.rs` and `ui/px/status_map.rs`. `verify.rs` merely exposes `hash_flash()` internally for atlas verification (`:120`); image comparisons and FI checks remain. `mod.rs` adds pixel presentations for verifier authorization and installation consent. Those dialogs inherit the UI issues above.

**Where your read is too optimistic:** authenticated source bytes and repeated transcript generation do not establish faithful pixels or fresh consent. Also, `confirm_px.rs:36` explicitly disables scroll-to-end. The branch documents this as an owner decision in `docs/security/HARDENING.md:53`; amounts, recipients, and warnings can therefore remain unseen even after fixing finding 2. That is a material consent-policy change to assess explicitly, separate from the implementation bugs.
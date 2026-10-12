TITLE: Seed letters and the live PIN digit are drawn through the public (address-keyed) font path on the shipping 16x4 UI, and the letter dial always starts at "a"
LABELS: finding,priority:medium,surface:trusted-ui,surface:sca-fi,source:frontier-research-2026-10
---
## Summary

The mnemonic pages and the candidate list are drawn through a constant-time glyph path so that the font lookup does not depend on the secret. Two neighbouring screens on the same shipping backend are not:

1. The **letter row** of seed entry and the **active PIN digit** go through the ordinary flush, which indexes the font table by character.
2. The **letter dial starts at a fixed `a`** and the candidate cursor at the start of its range, so the number of presses reveals each letter. PIN entry already randomises its start digit for exactly this reason; letters have no equivalent.

## Evidence

Line numbers at master `0feea78a` (2026-10-11). The research ran at `c75b0d9c`, an ancestor of master; the cited files were diffed against master before filing.

- `secure/src/ui/seed_wizard.rs:952-983` (`render_letter_screen`): letters at `:964-967`, then `d.flush()` at `:983`.
- `secure/src/ui/lcd.rs:153-170`: `Display::flush` calls `public_glyph_cols(ch)` at `:166`. `secure/src/ui/secret_text.rs:84-94` documents that function as "NEVER call this for secret rows; use `secret_glyph_cols`".
- `secure/src/ui/pin_entry.rs:188-221`: the active digit (`b'0' + d`, `:203-205`) is flushed the same way at `:221`.
- By contrast the mnemonic pages and candidate list use `flush_with_secret_rows` (`secure/src/ui/lcd.rs:180`).
- Fixed start: `secure/src/ui/seed_wizard.rs:851` `let mut buf = [b'a'; MAX_LETTERS];`, `:931` `buf[len] = b'a';`, `:997` `let mut cur = start;`. Random start for the PIN: `secure/src/ui/pin_entry.rs:79-88`.

## Reach

- Restore: all 24 words' prefixes go through this row (`enter_mnemonic`, `:781-807`), and every intermediate dial value is drawn.
- New wallet: the three check words (`verify_mnemonic`, `:658`, `:689`). The observer learns three words but not their positions.

## What this does and does not fix

An observer who can count button presses, with button identity, gets each letter exactly. That is the channel the random start closes. The glyph-address channel has only an emulated trace behind it. Neither fix hides anything from a tap on the display bus itself, where the letter's pixels are visible regardless.

## Severity and evidence level

- Letter and digit on the public path: **low-medium** (merger), **low** (skeptic, final value).
- Fixed start letter: **low-medium**.
- Evidence: code read; re-checked independently (both confirmed). No seed-wizard or PIN screen has run on pq1 silicon with a panel (#700).

## Fix directions

- [ ] Route row 1 of `render_letter_screen` and of the PIN screen through `flush_with_secret_rows`.
- [ ] Random start letter per position and a random candidate cursor. Without these the first fix is close to cosmetic.
- [ ] Widen #784 (the pixel-UI twin) so both paths are fixed and tested together.

## Related

#784, #700, #786.

---
<sub>**Provenance.** Security frontier research, 2026-10-11 (report item M03, defect row A25 and A26). Re-checked before filing by an independent read at `c75b0d9c` (both confirmed). The full report is `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`; it was not committed when this issue was filed, so this body is written to stand alone.</sub>

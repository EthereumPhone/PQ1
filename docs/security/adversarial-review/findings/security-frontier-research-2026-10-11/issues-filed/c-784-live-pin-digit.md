COMMENT_ON: 784
---
**One addition from the 2026-10-11 security frontier research (defect B6), after an independent re-check.** This issue contrasts the letter row with `pin_row`, "which masks with `b'*'`". That is true only for digits already entered. The **live** digit is put in the record in clear (`secure/src/ui/px/status_map.rs:288` at master `0feea78a`: `glyphs[i] = b'0' + pin[i] % 10;`) and `pin_entry` calls `show()`, which is `show_with(s, &[])`, so the frame is not forced. The digit is drawn by `Item::Text` through `Font::blit_run` (a table index keyed on the character), not by `blit_secret_run`, and a strip digest of those pixels is kept in the static. So the pixel-UI PIN row has the same defect as the letter row.

The research also claimed that secret frames are re-streamed repeatedly while the entry animation runs. That was **refuted** on re-check at the research commit: a host replication of the loop gave one forced frame per call for the seed, candidate, PIN and letter screens. Master has a reworked presenter that was not re-probed.

`ui-px` only, so not in the shipping feature set today. The legacy 16x4 twin of this defect, which is in the shipping set, is filed as {{17}}.

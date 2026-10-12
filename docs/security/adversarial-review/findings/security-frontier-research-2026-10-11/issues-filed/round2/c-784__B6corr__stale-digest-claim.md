COMMENT_ON: 784
---
**Correction to my comment of 2026-10-12 above.** Two of its statements were already out of date at the commit it cited (`0feea78a`). Lines below are at master `c2fab970`.

- "the frame is not forced": the force flag no longer decides anything. `present_frame_ex` ignores it (`secure/src/ui/px/lcd.rs:468`, the parameter is `_force`) and every frame is streamed in full under one window.
- "a strip digest of those pixels is kept in the static": the per-band digest and its table were deleted by `ea95a1fe` (2026-10-07, the tear fix for #780). The comment that records the deletion is at `secure/src/ui/px/lcd.rs:117`. No digest of letter or digit pixels outlives a frame now.

What still stands from that comment: the live PIN digit is written into the record in clear (`secure/src/ui/px/status_map.rs:288`) and is drawn as an ordinary text item through `Font::blit_run` (`pqsigner-ui-px/src/raster.rs:497`), a table lookup keyed on the character, and not through the constant-time `blit_secret_run` that secret items use (`pqsigner-ui-px/src/raster.rs:503`). So the routing half of this issue applies to the PIN row as well as the letter row. The frame-skipping half of the original body is superseded for both.

Found while re-reading the display items of the same research against master. Code reading only; nothing was run.

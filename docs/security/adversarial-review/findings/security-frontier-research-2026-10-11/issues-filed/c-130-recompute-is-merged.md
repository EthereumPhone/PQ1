COMMENT_ON: 130
---
**Note on the pending fix (2026-10-11 security frontier research, defect D6).** The uncommitted `black_box` change keeps the guard's two compares alive, but the recompute is still merged into the first `umin`, on host and on thumbv8m: a tripped guard returns the same first-computed value. The fix therefore does not defend the single-glitch case. IR and details are in my comment on #777. The 2026-08-20 note here ("guard + recompute now survive -O") holds for the guard only.

COMMENT_ON: 777
---
**A warning before the uncommitted `fi_min` fix and its gate are landed (2026-10-11 security frontier research, defect D6, after an independent re-check).**

The pending fix adds `black_box` so that the guard's two compares survive optimisation, and `scripts/check_fi_ir.sh` counts compares. On re-check, **the compares do survive, on host and on thumbv8m, but the recompute does not.** With the fix applied (thumbv8m, opt-level `s` and `z`, LTO, `#[inline(never)]` probe):

```
  %a.b.i = tail call i32 @llvm.umin.i32(i32 %a, i32 %b)
  %_5.i = icmp ugt i32 %_0.i.i, %a
  %_6.i = icmp ugt i32 %_0.i.i, %b
  %r.sroa.0.0.i = select i1 %or.cond.i, i32 %a.b.i, i32 %_0.i.i
```

When the guard trips, the function returns the first `umin` again (`movhi r1, r2`, where `r2` is the first min). The "opposite-inequality recompute" has been merged into the first computation. A single skip of the `movlo` in the min trips the guard and still returns the wrong, larger value. So the fix does nothing against the single-glitch case it exists for, and a gate that counts compares passes it.

This is not specific to thumbv8m (the research report said it was; that was wrong). A host-only script could catch it, if it checked that the fallback value is computed independently and not that two compares exist.

Suggested direction: recompute from `black_box(a)` and `black_box(b)` separately, and make the gate assert that the value returned on the tripped path does not alias the first result. #130's comment of 2026-08-20 ("guard + recompute now survive -O") is right about the guard and wrong about the recompute.

Caveat: the probe is a standalone call site, not `fi_min` inlined into the USB and APDU call sites of a release image, which cannot be built today.

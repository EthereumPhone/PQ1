## What it is

One timeline shared by every screen that states a fact. The canvas is black, an icon arrives, it does whatever it has to do, the caption lands, the screen rests. Four phases, in this order, always:

**hold → icon in → beat → caption**, then the [result hold](result-hold.md).

`pq1.verdict.VerdictAnim` ({{loc:pq1.verdict.VerdictAnim.draw}}) is the one implementation. A concrete verdict supplies `draw_icon(cv, t, u)` and, if it needs one, longer phase lengths; it never re-implements the timeline.

The icon arrives on the circle grid — its resting optical centre on x {{val:pq1.layout.CENTER_X}}, y {{val:pq1.layout.CIRCLE_CY}}, where the token disc sat — and the caption lands on the shared baseline y {{val:pq1.layout.BASELINE_Y}}. A **detail verdict** (SIG ERROR) puts its art on the detail grid instead and keeps the same phases. The art is procedural (`pq1/procedural/`, the check / X / exclamation marks in `marks.py`); its colour comes from the screen's `state` or an explicit `color`, never a local hex.

## The law

{{motion-head}}
{{row:black hold | pq1.verdict.VerdictAnim.T_HOLD | hold | nothing of the screen draws. With `handoff` the flow's token washes out here — see [handoff crossfade](handoff.md)}}
{{row:the icon arrives | pq1.verdict.VerdictAnim.T_IN | ease_out + arrive | `draw_icon` is called with the raw progress `u` through this window, and only once `u` is past zero}}
{{row:the beat — the mechanism's window | pq1.verdict.VerdictAnim.T_WAIT | — | the icon stands, or performs: a shake, a tumble, a spin-down. Each verdict fills this itself. `draw_icon` keeps being called for the rest of the screen with `u` clamped at 1, so a mechanism reads the screen clock `t`, never `u`}}
{{row:the caption fades in | pq1.verdict.VerdictAnim.T_TEXT | ease_out | one line of 18 px caps on the y {{val:pq1.layout.BASELINE_Y}} baseline}}
{{row:resolved | pq1.verdict.VerdictAnim.T_HOLD + pq1.verdict.VerdictAnim.T_IN + pq1.verdict.VerdictAnim.T_WAIT + pq1.verdict.VerdictAnim.T_TEXT | — | `t_resolve` is the sum of the four, nothing else}}
{{row:the screen rests | pq1.status.RESULT_HOLD_MS | hold | the same for every resolving screen}}
{{row:whole screen | pq1.verdict.VerdictAnim.T_HOLD + pq1.verdict.VerdictAnim.T_IN + pq1.verdict.VerdictAnim.T_WAIT + pq1.verdict.VerdictAnim.T_TEXT + pq1.status.RESULT_HOLD_MS | — | `duration` = `t_resolve` + the result hold}}

## The entrance law

Inside `T_IN`, from the same linear progress `u`, `VerdictAnim.entrance` ({{loc:pq1.verdict.VerdictAnim.entrance}}) returns two channels and nothing else:

- **alpha** = `ease_out(u)` — a plain fade in.
- **scale** = `motion.arrive(u)` ({{loc:pq1.motion.arrive}}) — {{tok:pq1.motion.ARRIVE_FROM}} rising to 1, also on `ease_out`.

A rise of three percent, **never an overshoot**, and never longer than {{tok:pq1.motion.ARRIVE_MS}}. `pop` and `back_out` exist for celebrations; they are not entrances. There is one source for these two lines: a verdict calls `self.entrance(u)`, it does not re-derive them.

A mechanism plays on the **arrived** icon. Its own window may be as long as the screen needs; the fade and the rise inside it may not.

## What a screen may change, and what it may not

| phase | may a screen change it? |
|---|---|
| `T_HOLD` | yes — {{val:anim:verdict/pin_mismatch:T_HOLD}} to {{val:anim:verdict/padlock:T_HOLD}} across the library. It is also the [handoff](handoff.md) span, so a longer hold means a slower token crossfade |
| `T_IN` | **no.** It is {{tok:pq1.motion.ARRIVE_MS}}, the law's maximum. A mechanism belongs in `T_WAIT` |
| `T_WAIT` | yes, freely — this is where mechanisms live. Zero is legal |
| `T_TEXT` | no screen changes it; it is the caption fade |
| `t_resolve`, `duration` | never by hand. Both are derived |

The conformance checker enforces exactly this: `V-TIN` (an error when `T_IN` exceeds `ARRIVE_MS`), `V-SUM` (`t_resolve` is the sum), `V-HOLD` (the rest is `RESULT_HOLD_MS`), `V-ENTRANCE` (no second copy of the two entrance lines), and `V-PHASEVAR`, which simply records the screens with a non-default `T_HOLD` / `T_WAIT`.

One screen breaks the phase bookkeeping on purpose and is baselined: the **padlock** puts its whole mechanism inside `T_IN` and then recomputes the entrance inline against `ARRIVE_MS`. What you see obeys the law; the phase table does not. Port the padlock's mechanism as a `T_WAIT`, not as a long `T_IN`.

## Every verdict in the library

Phase lengths per instance, in ms; the machine-readable copy is `spec/anims.json` → `phases`.

| verdict | `T_HOLD` | `T_IN` | `T_WAIT` | resolves | ends | what fills `T_WAIT` |
|---|---:|---:|---:|---:|---:|---|
| [firmware verified](../library/verdict-firmware-verified.md) | {{val:anim:verdict/firmware_verified:T_HOLD}} | {{val:anim:verdict/firmware_verified:T_IN}} | {{val:anim:verdict/firmware_verified:T_WAIT}} | {{val:anim:verdict/firmware_verified:t_resolve}} | {{val:anim:verdict/firmware_verified:duration}} | nothing — the law untouched |
| [headshake](../library/verdict-headshake.md) | {{val:anim:verdict/headshake:T_HOLD}} | {{val:anim:verdict/headshake:T_IN}} | {{val:anim:verdict/headshake:T_WAIT}} | {{val:anim:verdict/headshake:t_resolve}} | {{val:anim:verdict/headshake:duration}} | one decaying head shake, then a beat |
| [shield](../library/verdict-shield.md) — `backup_ok` | {{val:anim:verdict/shield@backup_ok:T_HOLD}} | {{val:anim:verdict/shield@backup_ok:T_IN}} | {{val:anim:verdict/shield@backup_ok:T_WAIT}} | {{val:anim:verdict/shield@backup_ok:t_resolve}} | {{val:anim:verdict/shield@backup_ok:duration}} | the nod, then a beat |
| shield — `no_match` | {{val:anim:verdict/shield@no_match:T_HOLD}} | {{val:anim:verdict/shield@no_match:T_IN}} | {{val:anim:verdict/shield@no_match:T_WAIT}} | {{val:anim:verdict/shield@no_match:t_resolve}} | {{val:anim:verdict/shield@no_match:duration}} | the wiggle, then a beat |
| [padlock](../library/verdict-padlock.md) — `lock` | {{val:anim:verdict/padlock@lock:T_HOLD}} | {{val:anim:verdict/padlock@lock:T_IN}} | {{val:anim:verdict/padlock@lock:T_WAIT}} | {{val:anim:verdict/padlock@lock:t_resolve}} | {{val:anim:verdict/padlock@lock:duration}} | turn-in, drop, click — inside `T_IN`, see above |
| padlock — `unlock` | {{val:anim:verdict/padlock@unlock:T_HOLD}} | {{val:anim:verdict/padlock@unlock:T_IN}} | {{val:anim:verdict/padlock@unlock:T_WAIT}} | {{val:anim:verdict/padlock@unlock:t_resolve}} | {{val:anim:verdict/padlock@unlock:duration}} | snap, body kick, pause, swing out — likewise |
| [pin mismatch](../library/verdict-pin-mismatch.md) | {{val:anim:verdict/pin_mismatch:T_HOLD}} | {{val:anim:verdict/pin_mismatch:T_IN}} | {{val:anim:verdict/pin_mismatch:T_WAIT}} | {{val:anim:verdict/pin_mismatch:t_resolve}} | {{val:anim:verdict/pin_mismatch:duration}} | the row fills, holds, turns red, is shaken off, beat |
| [last attempt](../library/verdict-last-attempt.md) | {{val:anim:verdict/last_attempt:T_HOLD}} | {{val:anim:verdict/last_attempt:T_IN}} | {{val:anim:verdict/last_attempt:T_WAIT}} | {{val:anim:verdict/last_attempt:t_resolve}} | {{val:anim:verdict/last_attempt:duration}} | rest, the reel down to 1, a wobble, the heart's pumps |
| [rng failed](../library/verdict-rng-failed.md) | {{val:anim:verdict/rng_failed:T_HOLD}} | {{val:anim:verdict/rng_failed:T_IN}} | {{val:anim:verdict/rng_failed:T_WAIT}} | {{val:anim:verdict/rng_failed:t_resolve}} | {{val:anim:verdict/rng_failed:duration}} | the die rests, tumbles on three axes, lands, beat |
| [sig error](../library/verdict-sig-error.md) | {{val:anim:verdict/sig_error:T_HOLD}} | {{val:anim:verdict/sig_error:T_IN}} | {{val:anim:verdict/sig_error:T_WAIT}} | {{val:anim:verdict/sig_error:t_resolve}} | {{val:anim:verdict/sig_error:duration}} | two decaying attention pulses (on the detail grid) |
| [tamper](../library/verdict-tamper.md) | {{val:anim:verdict/tamper:T_HOLD}} | {{val:anim:verdict/tamper:T_IN}} | {{val:anim:verdict/tamper:T_WAIT}} | {{val:anim:verdict/tamper:t_resolve}} | {{val:anim:verdict/tamper:duration}} | the same two pulses, centred |
| [wipe](../library/verdict-wipe.md) — `wallet_wiped` | {{val:anim:verdict/wipe@wallet_wiped:T_HOLD}} | {{val:anim:verdict/wipe@wallet_wiped:T_IN}} | {{val:anim:verdict/wipe@wallet_wiped:T_WAIT}} | {{val:anim:verdict/wipe@wallet_wiped:t_resolve}} | {{val:anim:verdict/wipe@wallet_wiped:duration}} | the brush mark, then the pulse treatment |
| wipe — `wallet_wiped_anim` | {{val:anim:verdict/wipe@wallet_wiped_anim:T_HOLD}} | {{val:anim:verdict/wipe@wallet_wiped_anim:T_IN}} | {{val:anim:verdict/wipe@wallet_wiped_anim:T_WAIT}} | {{val:anim:verdict/wipe@wallet_wiped_anim:t_resolve}} | {{val:anim:verdict/wipe@wallet_wiped_anim:duration}} | the brush mark, then the sweep treatment |
| wipe — `wallet_wiped_explosion` | {{val:anim:verdict/wipe@wallet_wiped_explosion:T_HOLD}} | {{val:anim:verdict/wipe@wallet_wiped_explosion:T_IN}} | {{val:anim:verdict/wipe@wallet_wiped_explosion:T_WAIT}} | {{val:anim:verdict/wipe@wallet_wiped_explosion:t_resolve}} | {{val:anim:verdict/wipe@wallet_wiped_explosion:duration}} | the same verdict, after a [lead film](lead-film.md) — the phases are unchanged, the clock starts later |
| [duress differ](../library/verdict-duress-differ.md) | {{val:anim:verdict/duress_differ:T_HOLD}} | {{val:anim:verdict/duress_differ:T_IN}} | {{val:anim:verdict/duress_differ:T_WAIT}} | {{val:anim:verdict/duress_differ:t_resolve}} | {{val:anim:verdict/duress_differ:duration}} | the row holds, the scanline crosses and returns, the shake, beat |
| [factory signing](../library/verdict-factory-signing.md) | {{val:anim:verdict/factory_signing:T_HOLD}} | {{val:anim:verdict/factory_signing:T_IN}} | {{val:anim:verdict/factory_signing:T_WAIT}} | {{val:anim:verdict/factory_signing:t_resolve}} | {{val:anim:verdict/factory_signing:duration}} | the gear coasts to a stop — it is already turning as it arrives — then a beat |

## Who else obeys it

[arrive](../screen-types/status-arrive.md) — an ending with no film of its own — uses the same four phases and the same entrance for the resting look instead of an icon. It types the numbers out again rather than inheriting them; they are the same numbers and should be one table in a port.

Not under the law: the [qubit film](../screen-types/status-qubit.md), the [resolve](../screen-types/status-resolve.md), the [explosion](../library/fx-explosion.md) and the hold demo — those are films, with timelines of their own. Note that `pin/pin_differ` is a verdict-shaped screen that is **not** a `VerdictAnim`: it fades its pill in with `ease` over its own hold, with no rise and no handoff. Its twin `verdict/duress_differ` is the one to copy.

## Input

None, for the whole screen ([unbound gestures](../actions/unbound-gestures.md)). The flow draws no corner chevrons on a verdict — `chev` is None on a status screen. (The one status screen with chevrons is the [PIN row](../components/pin-row.md), which draws its own because it takes input.)

## Preview

{{preview}}

## Do / Don't

- **Do** derive `t_resolve` from the phases and `duration` from `t_resolve`. Nothing in a flow's dwell should be typed twice.
- **Do** put a mechanism in `T_WAIT` and let it start on the arrived icon.
- **Do** give any one-shot accent at least {{tok:pq1.motion.VERDICT_ACCENT_MIN_MS}} — under two panel frames it may never be sampled.
- **Don't** overshoot the entrance, and don't stretch it past {{tok:pq1.motion.ARRIVE_MS}}, whatever the icon.
- **Don't** fade the caption in with the icon. The beat between them is what makes a verdict read as a statement rather than a label.

{{partial:port-notes}}

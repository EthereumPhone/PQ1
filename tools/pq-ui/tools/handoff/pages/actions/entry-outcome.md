## What it is

What happens after the row: the device answers, and the driver decides where to go. An entry has exactly three outcomes ({{loc:screens.pin.pin_entering.PinEntering.outcome}}):

| outcome | how it is reached | what the user sees |
|---|---|---|
| `match` | the eighth ENTER, digits equal to the device's PIN | the `match` verdict — UNLOCKED (the padlock springs open) |
| `miss` | the eighth ENTER, digits not equal | the `miss` verdict of *that try* — WRONG PIN, LAST ATTEMPT, LOCKED |
| `cancel` | the left hold completes — see [cancel](entry-cancel.md) | nothing: the row fades out |

The verdict plays **in the same screen**. One try is one screen: the entry, then the answer its digits earned. A port must not model this as "entry screen" followed by "verdict screen" — the flow never advances between them, and the caller never sees a screen change.

## The submit timeline

{{motion-head}}
{{row:the row holds, entered and checked | screens.pin.pin_entering.T_CHECK | hold | eight white rings; the device compares here}}
{{row:the whole picture fades to black | screens.pin.pin_entering.T_OUT | ease_out | one alpha over rings, digits and caption: the entry **ends empty**}}
{{row:the verdict starts, on the empty canvas | - | — | from `t_exit` = submit + {{tok:screens.pin.pin_entering.T_CHECK}} + {{tok:screens.pin.pin_entering.T_OUT}}; its own hold phase is the black beat before its sign — see [the verdict law](../transitions/verdict-law.md)}}
{{row:a submit with no verdict attached rests on black | screens.pin.pin_entering.T_BLACK | hold | the PIN-gate case (`match=None`): nothing plays, the screen just holds black, then the flow moves on}}

The verdict is built with its handoff crossfade switched off ({{loc:screens.pin.pin_entering.PinEntering._settle_tail}}): there is no token to hand over, because the entry left nothing on the canvas.

A **cancel** has no check beat. The row fades over {{tok:screens.pin.pin_entering.T_OUT}} from the moment the hold fires, and no verdict follows.

## Where the driver goes next

Once the verdict has rested ({{loc:pq1.driver.FlowDriver._after_entry}}):

| outcome | next screen | if there is none |
|---|---|---|
| `miss` | the following screen **if it is another entry** — the next attempt | rest on the verdict (LOCKED is terminal) |
| `match` | the first following screen that is **not** an entry | rest on the verdict (UNLOCKED ends the flow) |
| `cancel` | the nearest **non-status** screen behind the entry — the ask that led into it | no such screen: a fresh, empty row opens in place |

`flows/pin` builds the ladder out of these: `attempt(wrong_pin())`, `attempt(last_attempt(2))`, `attempt(locked())` — three tries, each one screen, each with its own answer. A PIN gate inside another flow is the same `attempt(...)` with `match=None`, so a match falls through to the screen after it.

## While the verdict plays

The screen takes no input. The driver's state goes from `navigating` to `resolving` the moment the outcome exists — that is at the submit itself, so the check beat and the fade already ignore both buttons — and the armed set stays empty until the entry is finished. The same rule as any other status screen.

## Arriving and leaving

- **Every visit starts empty.** The driver drops the entry's event log on **arrival**, never on leaving, so the transit still fades the frame the row rested on.
- **Leaving an entry is a token-less transit.** The resting frame fades to black on the outgoing alpha spring; no token disc rides the transit, and the next screen's handoff crossfade is dropped so nothing pops in — see [token-less transit](../transitions/tokenless-fade.md).

## Do / Don't

- **Do** keep the answer inside the try. The next attempt is a new screen only because the flow lists three attempts.
- **Do** let a terminal verdict rest. LOCKED has nowhere to go; the frame freezes.
- **Don't** port the render-time `state` (`"done"` / `"failed"`) on an attempt: it only sorts the demo GIF into `success/` or `cancel/`.
- **Don't** port the demo's PIN or its `typed` digits. `PIN` and `WRONG` in `flows/pin` are samples; the device's PIN is the user's.

{{partial:port-notes}}

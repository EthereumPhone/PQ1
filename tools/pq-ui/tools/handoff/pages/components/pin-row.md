## What it is

The device's keypad, reduced to two buttons: {{val:screens.pin.pin_entering.DIGITS}} rings on one row, one per digit. Exactly one ring is **active** — it carries the dial the buttons turn; the rings before it hold entered digits; the rings after it are empty, except one that was dialed and left behind (it keeps its digit in a grey ring). There is **no token disc** at rest on this screen. The row is the whole picture (`rests_on_token` is False), so it is also what the cancel hold fills, and leaving it fades to black — see [token-less transit](../transitions/tokenless-fade.md).

Two files own it: `pq1/procedural/pin_slots.py` draws a row from one dict per slot and knows nothing about time ({{loc:pq1.procedural.pin_slots.draw}}); `screens/pin/pin_entering.py` holds the state and hands it the dicts. The state is an **event log** — `[(t, kind, arg)]` replayed by `entry_state` ({{loc:screens.pin.pin_entering.entry_state}}) — so every frame of an entry is a pure function of time, exactly like every other screen here.

## When it appears

Wherever the device asks for the PIN: the `pin/unlock` flow (one try per screen, three tries), and as a gate inside another flow (`flows/pin` `attempt(...)` ahead of the ending). It is the only screen kind that takes input while being a `status` screen — see the library page, [pin / pin_entering](../library/pin-pin-entering.md).

## Spec

{{fields:kind,anim,id,state}}

The entry's own keys ride along on the same dict (`screens.spec("pin_entering", …)`):

| key | form | meaning |
|---|---|---|
| `busy` | `"ENTER PIN"` | the caption under the row while a slot is active |
| `bottom` | `"PIN ENTERED"` | the caption the row swaps to once all eight are in. DEMO ONLY: a device submit never shows it |
| `pin` | `"00000000"` | the digits the device accepts. Per-device data — never a constant in a flow |
| `typed` | `"00000001"` | DEMO ONLY: what the scripted demo dials. The driver ignores it (`live`) |
| `exit` | `"rest"` \| `"submit"` | DEMO ONLY: rest on PIN ENTERED, or submit on the 8th digit |
| `miss` | a screen dict | the verdict a wrong PIN earns, played in this same screen |
| `match` | a screen dict \| `None` | the verdict a right PIN earns; `None` falls through to the next screen |
| `labels` | `(("−","+"), ("ENTER (BOTH)",), …)` | the rotating hints; a 1-tuple is centred between the chevrons |
| `done_labels` | a pair \| `()` | a hint after the row is full. Empty on the device: the 8th ENTER checks at once |

## Geometry

| part | value |
|---|---|
| row | {{val:screens.pin.pin_entering.DIGITS}} rings, radius 21, pitch 50, centred on x {{val:pq1.layout.CENTER_X}}, y {{val:pq1.layout.CIRCLE_CY}} |
| ring centres | x 39 to 389, step 50 |
| stroke | 2 px idle and entered, 2.5 px fully active |
| digit | {{val:pq1.typography.SIZE_BODY}} px {{val:pq1.procedural.pin_slots.DIGIT_WEIGHT}}, centred in the ring and nudged 1.5 px down (optical centring, not a baseline) |
| caption | ENTER PIN on the shared baseline y {{val:pq1.layout.BASELINE_Y}} |
| hint labels | {{val:screens.pin.pin_entering.LBL_SIZE}} px caps at 80 % white on the chevron line (the corner slots, {{loc:pq1.layout.CHEV_LEFT}}), each label's edge facing its chevron at x {{val:screens.pin.pin_entering.LBL_L}} (left) / {{val:screens.pin.pin_entering.LBL_R}} (right), ink-box centred on the line |
| − / + marks | `procedural.marks.minus` / `plus`, bar span 0.6 × {{val:screens.pin.pin_entering.SIGN_R}} px, stroke {{val:screens.pin.pin_entering.SIGN_STROKE}} × that radius (lighter than the x mark's), {{val:screens.pin.pin_entering.SIGN_GAP}} px from the chevron edge |

The signs are **marks, not text**: typed − and + are too thin to read on this glass.

## The five looks of one ring

| state | ring | digit |
|---|---|---|
| empty, ahead of the cursor | 70 % white, 2 px | none |
| active (the dial) | YELLOW, 2.5 px, lifted 3 px | the dialed digit |
| dialed but not entered (the cursor moved away) | 70 % white | the digit stays visible |
| entered | white, 2 px | the digit |
| filling (the cancel hold) | opaque white liquid rising over the stroke | the part under the surface turns black |

The liquid is **not** the token's see-through film: in the rings it is opaque white and it covers the stroke, because there is no disc to darken. Same curve, different dress — see [hold flood](hold-flood.md).

## Motion

{{motion-head}}
{{row:the rings fade in | screens.pin.pin_entering.T_FADE | ease | the round's own clock: a restart replays this in place}}
{{row:the token handed over fades to black under them | screens.pin.pin_entering.T_FADE | ease_out | only when the screen before rests on a token (a hero): the resting disc is drawn and blackened as the rings come up ({{loc:screens.pin.pin_entering.PinEntering.draw_handoff}}). After another token-less screen the handoff is dropped and the row opens on black}}
{{row:captions and hints follow the rings | screens.pin.pin_entering.T_TEXT | ease_out | released at {{tok:screens.pin.pin_entering.T_UI}}, once the rings have settled}}
{{row:the chevrons trail the hints | screens.pin.pin_entering.CHEV_STAGGER | ease_out | the same fade, started this much later}}
{{row:the first ring becomes active | screens.pin.pin_entering.ACT_MS | ease | colour 70 % white to YELLOW, stroke 2 to 2.5 px, lift 0 to 3 px, on one curve. This ramp runs ONCE, from {{tok:screens.pin.pin_entering.T_UI}} on the round's clock — it is not per slot}}
{{row:every later cursor move | - | cut | the leaving ring is white and the arriving ring fully yellow in the same frame; only the bounce softens it}}
{{row:micro-bounce on every dial, enter and move | screens.pin.pin_entering.BOUNCE_MS | sine | the ACTIVE ring only — a half sine: up 2.5 px at the midpoint, back to the lift}}
{{row:one hint: fade in, hold, fade out | screens.pin.pin_entering.L_FADE * 2 + screens.pin.pin_entering.L_SHOW | ease_out | {{tok:screens.pin.pin_entering.L_FADE}} in, {{tok:screens.pin.pin_entering.L_SHOW}} lit, {{tok:screens.pin.pin_entering.L_FADE}} out}}
{{row:then nothing, before the next hint | screens.pin.pin_entering.L_GAP | hold | one hint slot is {{tok:screens.pin.pin_entering.L_SLOT}}; three slots make the cycle}}
{{row:a caption or hint swap | screens.pin.pin_entering.SWAP_MS * 2 | ease_out | sequential: the old fades fully out, then the new fades in ({{loc:screens.pin.pin_entering.swap}})}}
{{row:the row leaves | screens.pin.pin_entering.T_OUT | ease_out | rings, digits, captions, liquid — one alpha, one piece}}

## Input

The row is navigable: taps dial, the chord enters, a double press moves, the left hold cancels. Each gesture has its own page — [dial](../actions/entry-dial.md), [ENTER](../actions/entry-enter.md), [BACK / NEXT](../actions/entry-move.md), [cancel](../actions/entry-cancel.md), [what follows](../actions/entry-outcome.md).

## Do / Don't

- **Do** keep the row a replay of an event log. Every visit starts empty; the driver drops the log on arrival, never on leaving, so the transit still fades the frame the row rested on.
- **Do** draw the dial in the ring it belongs to. Moving the cursor never takes a digit away: a dialed-but-not-entered digit stays visible in its grey ring.
- **Don't** port the dial pace — {{tok:screens.pin.pin_entering.T_SETTLE}} before the typing starts, then {{tok:screens.pin.pin_entering.STEP_TICK}} ms per tick, {{tok:screens.pin.pin_entering.STEP_SETTLE}} ms on the digit, {{tok:screens.pin.pin_entering.STEP_ADV}} ms to advance — or {{tok:screens.pin.pin_entering.REST_MS}}: that is the scripted demo dialing itself for the GIF ({{loc:screens.pin.pin_entering.script}}). On the device only a button moves the row.
- **Don't** show PIN ENTERED on a device submit. The caption only swaps in the `exit="rest"` preview, which never submits.

{{partial:port-notes}}

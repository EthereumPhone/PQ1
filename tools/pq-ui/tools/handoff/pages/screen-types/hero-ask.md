## What it is

The one question a flow exists to ask — `SEND 12,500 TOSHI?`, `SIGN SAFE TX?`. The token disc sits centred with the question on the bottom band. It is the **hub** of the flow: every walk through the details starts here and comes back here, and it is one of only two places a signature can be given (the other is [Confirm?](confirm.md)).

## When it appears

First screen of almost every flow (after an [intro](hero-intro.md) when the family has one), and again as the return point after the last detail. {{used-in}}

## Spec

{{fields:kind,bottom,icon,token,hint,commit,sweep,chev}}

{{example}}

`commit` defaults to true on a hero: the right hold is armed. `chev` defaults to `"lr"`: taps navigate.

## Geometry

{{geometry}}

The circle never resizes ({{tok:pq1.layout.CIRCLE_R}}, centre y {{val:pq1.layout.CIRCLE_CY}}). The caption sits on the shared baseline y {{val:pq1.layout.BASELINE_Y}}. Corner chevrons: {{loc:pq1.layout.CHEV_LEFT}}.

## Motion

{{motion-head}}
{{row:arrive from the previous screen | - | spring NAV | circle x / y / r + glyph mix + text alpha on one spring set — see [spring morph](../transitions/spring-morph.md)}}
{{row:caption fades in after the circle starts | pq1.motion.TEXT_IN_DELAY_MS | spring NAV | the disc leads, the words follow}}
{{row:rest before the idle sweep starts | pq1.motion.SWEEP_DELAY_MS | — | }}
{{row:idle sweep, one full side-to-side cycle | pq1.motion.SWEEP_PERIOD_MS | sine + tau_chase | amplitude {{val:pq1.motion.SWEEP_AMP}} px, smoothed with tau {{val:pq1.motion.OSC_TAU}}; stays inside x {{val:pq1.layout.SWEEP_X_MIN}}–{{val:pq1.layout.SWEEP_X_MAX}}}}
{{row:chevron hint cycle (only when `hint` is set) | pq1.motion.CHEV_HINT_PERIOD_MS | ease | the chevrons turn up and bob — see [chevrons](../components/chevrons.md)}}
{{row:trail follows the sweeping disc | pq1.motion.CHAIN_TAU_IDLE | tau_chase | slower chase than in a transit ({{val:pq1.motion.CHAIN_TAU}})}}

A press recentres a sweeping disc: while a hold is live the sweep target is zero, so the disc glides home and the fill rises in a disc that stands still.

## Input

{{gestures:hero — the ask}}

Either tap enters the details — the ask never regresses to an intro. `hold right` signs; `hold left` declines. See [tap on the ask](../actions/tap-hub.md), [hold right — sign](../actions/hold-right-sign.md).

## Preview

{{preview}}

## Do / Don't

- **Do** keep the question text as data: the amount and symbol are per-transaction values, never constants.
- **Do** run the sweep and the hint only while the screen is at rest; both stop the instant a transit or a hold begins.
- **Don't** port the dwell timer ({{tok:pq1.motion.HERO_DWELL}}): it advances the demo loop only. On the device nothing moves without a press.

{{partial:port-notes}}

## What it is

A hero that announces instead of asking. It looks like the [ask](hero-ask.md) — the disc centred, a caption on the bottom band — with three differences:

- the caption carries one right-pointing chevron after the text (the [band chevron](../components/band-chevron.md));
- the two corner chevrons are hidden (`chev` defaults to `None` when `band_chev` is set);
- nothing is signed here: the flow sets `commit` to false, so the right hold is unbound.

The disc wears the family's identity mark, not the token: the dev mark on a black disc over the gold trail (ERC-7730), the fingerprint mark on the white disc (firmware).

## When it appears

{{used-in}}

- **ERC-7730** — the first screen of the flow, ahead of the ask. Built by `flows.erc7730.intro()` ({{loc:flows.erc7730.intro}}).
- **Firmware update** — the second screen: after the opening ask, ahead of the [words grid](value-words.md). Built by `flows.firmware.fingerprint_intro()` ({{loc:flows.firmware.fingerprint_intro}}).

A batch's announce screen is the same idiom plus a pager — see [hero — batch position](hero-pager.md).

## Spec

{{fields:kind,bottom,band_chev,commit,chev,icon,token,sweep}}

{{example}}

**`band_chev` does not switch `commit` off.** `normalize_screens` arms every hero by default ({{loc:pq1.layout.normalize_screens}}); only `chev` follows `band_chev`. An intro must carry `commit: False` itself — both family helpers do. An intro left armed would sign on a right hold.

**`chev: None` hides the chevrons; it does not disable input.** The schema note above reads "None = no input", but the reference driver never looks at `chev` ({{loc:pq1.driver.FlowDriver.armed}}): an intro takes both taps and the left hold with no corner chevrons on the panel. What is armed follows `kind` and `commit`.

## Geometry

{{geometry}}

The layout reports the caption at x {{val:pq1.layout.CENTER_X}}, but the drawing shifts a band-chevron caption: the text is centred on x {{val:pq1.components.VIEW_MORE_CX}}, so text plus chevron read centred (`draw_text`, {{loc:pq1.components.draw_text}}). The chevron's centre sits {{val:pq1.components.VIEW_MORE_CHEV_GAP}} px past the right edge of the text, at y {{val:pq1.components.VIEW_MORE_CHEV_CY}}, pointing right. The text width counts the letter spacing ({{val:pq1.typography.LS_QUESTION}} px per gap, size {{val:pq1.typography.SIZE_QUESTION}}). It is the same unit the [Confirm? band](../components/confirm-band.md) draws for OR VIEW MORE: `_band_unit`, {{loc:pq1.components._band_unit}}.

The chevron position depends on the caption's width, so measure the text on the device; never fix the x.

## Motion

{{motion-head}}
{{row:arrive from the previous screen | - | spring NAV | the same spring set as every screen change — see [spring morph](../transitions/spring-morph.md)}}
{{row:caption and band chevron fade in, after the disc starts | pq1.motion.TEXT_IN_DELAY_MS | spring NAV | the chevron is drawn with the caption's alpha; it never moves on its own}}
{{row:corner chevrons fade out on the way in, back in on the way out | - | spring NAV | their alpha follows the glyph mix spring between a screen that shows them and the intro}}
{{row:the disc body and the trail colours change | - | cut | they switch in one step when the mix spring passes one half; only the glyph crossfades (dev mark to ether mark)}}
{{row:rest before the idle sweep starts | pq1.motion.SWEEP_DELAY_MS | — | an intro sweeps like any hero unless `sweep` is false}}
{{row:idle sweep, one full side-to-side cycle | pq1.motion.SWEEP_PERIOD_MS | sine + tau_chase | see [idle sweep](../components/idle-sweep.md); the caption and its chevron stay still}}

The band chevron has no hint bob. `motion.chevron_hint` moves the corner pair only, and an intro sets no `hint`.

## Input

{{gestures:hero — an intro}}

- **Either tap leads on.** The rule is `_hub_target` ({{loc:pq1.driver.FlowDriver._hub_target}}): when the next screen is a hero, a tap goes to it; otherwise it goes to the section's first screen — the segment's first detail, value or Confirm?. So the ERC-7730 intro leads to the ask, and the firmware intro leads to the words, which are a value screen.
- **Hold right is unbound.** No fill is drawn, nothing fires. The `snapback` on the early-release row is only the driver's return value: there is no fill to drain.
- **Hold left declines**, as on every navigable screen. The [fill](../components/hold-flood.md) rises in the intro's own disc: the white film inside the black ERC-7730 disc, the black film over the white firmware disc.
- The chord and the double press are not bound here. The bench sends them as two presses, and each one counts as a tap — that is why those rows travel two screens. Do not port that as a shortcut.

Coming back: in ERC-7730 the walk never returns to the intro. A left tap on the first detail goes to the ask before it, and the ask's taps go into the details. In the firmware flow the intro sits between the opening ask and the words, so a left tap on the words **does** return to the intro; the opening ask is the screen that is never seen again.

## Preview

The clip is the demo walk: dwell timers advance it, at the KIOSK pace. On the device each step waits for a tap and moves on the NAV spring.

{{preview}}

## Do / Don't

- **Do** keep the caption a family constant. The two live captions are `INTRO_CAPTION` and `FINGERPRINT_CAPTION`; they are not per-transaction data.
- **Do** keep the corner chevrons hidden while the band chevron shows. One screen never shows both.
- **Don't** arm the right hold on an intro.
- **Don't** port the dwell timer ({{tok:pq1.motion.HERO_DWELL}}) or the demo loop's wrap from the ending back to the intro. On the device the intro waits for a tap.

{{partial:port-notes}}

## What it is

The one asymmetry in a [spring morph](spring-morph.md). Outgoing text starts fading the instant the leg starts; the incoming screen's text is held dark for {{tok:pq1.motion.TEXT_IN_DELAY_MS}} and only then released onto its own alpha spring. The leg starts when the navigation fires — on a tap that is the *release* edge, not the press-down ([tap left / right](../actions/tap-navigate.md)) — and the delay runs from there. The disc visibly leads and the words land just behind it, instead of both arriving together and reading as a slide.

It is a *release*, not a curve: after the delay the incoming alpha is an ordinary spring on the same profile as the circle ([spring morph](spring-morph.md)), so the fade-in still ends with the travel rather than at a fixed time.

## When it appears

On every screen-to-screen leg of a flow, in both directions, whatever the two screens are — a hero, a detail, a value, the Confirm?, an ending. It is not a property of a screen type; it belongs to the leg. A [token-less transit](tokenless-fade.md) is no exception: the outgoing frame fades to black and the incoming caption still waits out the delay, there is simply no disc leading it.

## How it is held

One scalar on the Sim — `text_in_at`, an absolute ms deadline. `go_to` sets it to `now + TEXT_IN_DELAY_MS` and retargets every *other* screen's alpha to 0 straight away ({{loc:pq1.flow.Sim.go_to}}). Each `draw` compares the clock against it and, once past, retargets the **current** screen's alpha to 1 and clears the deadline ({{loc:pq1.flow.Sim.draw}}).

Three consequences a port must reproduce:

- There is only ever **one** pending release. A second press before the deadline overwrites it, so the release lands on whatever screen is current when it finally fires — which is what makes a [reversal](reversal.md) behave: you get the text of where you ended up, not of where you were going.
- A run of presses closer together than the delay keeps pushing it out. On `send_token`, four taps two panel frames apart never release anything: the caption they left fades out over the first few frames and then the panel shows the travelling disc and **no text at all** until the taps stop.
- A leg is not settled while a release is pending: `text_in_at is None` is the first clause of the settle test ({{loc:pq1.flow.Sim._all_settled}}). Firing it early would end the leg early.

The first screen of a flow is exempt: the snap entry writes its alpha straight to 1 and clears the deadline ({{loc:pq1.flow.Sim.cur}}), so a flow opens with its caption already up.

## Motion

{{motion-head}}
{{row:outgoing text starts fading | - | spring NAV | when the leg starts, with no delay — every screen but the destination}}
{{row:incoming text held dark | pq1.motion.TEXT_IN_DELAY_MS | hold | measured from the leg's start, not from the frame that follows it}}
{{row:incoming text fades in | - | spring NAV | an ordinary alpha spring, same profile as the circle}}

The deadline is only checked once per frame, so on the panel the real delay is the token value rounded up to the next frame boundary — up to a whole panel frame late. Measured on a hero → detail leg at the NAV pace: the release fires about half a frame late and the incoming alpha is already 0.31 on the frame it first appears, while the outgoing caption is down to 0.15. They are on the glass together for three frames (the outgoing at 0.15, then 0.06, then 0.02) and never cross at full strength.

## Do / Don't

- **Do** keep it as a single deadline that any new leg overwrites. Per-screen timers would let a stale release fire onto a screen you have left.
- **Do** measure it from the instant the leg starts. Do not restart it when the springs happen to slow down.
- **Don't** apply it to the outgoing text — the asymmetry is the whole effect.
- **Don't** hold the incoming text for a fixed *total* time and then snap it on. After the delay it is a spring, so it lands with the disc.
- **Don't** lengthen it to "make the disc read". The delay is short on purpose: long enough to see the disc set off, short enough that the caption is up before the disc stops.

Draw order is text first, disc second: the travelling token paints over any caption it crosses, which is another reason the words are not up yet while it is moving ({{loc:pq1.flow.Sim.draw}}).

{{partial:port-notes}}

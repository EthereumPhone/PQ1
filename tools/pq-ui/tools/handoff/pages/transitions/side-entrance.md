## What it is

The [explosion](../library/fx-explosion.md) normally opens with its token already in the middle of the panel. `enter` opens it with the token — or with both qubits — **travelling in from off the panel** first. It is the film's own prologue, not a flow transition: a pure function of the film's clock, seekable like the rest of it.

Four values, `burst.ENTERS` ({{loc:pq1.procedural.burst.ENTERS}}): none, `"left"`, `"right"`, `"sides"`. Anything else raises with the valid names.

## When it appears

`"sides"` on WALLET WIPED (the `wallet_wiped_explosion` preset — red qubits flying in from both edges), and as an option on any spliced explosion. The firmware endings use no entrance: their film opens on the flow's own disc, already centred.

## left / right — one disc slides in

One full-size body at the token's visible radius (the layout radius {{val:qubit:r_big}} less the {{val:pq1.components.TOKEN_INSET}} px stroke inset — the radius the seed opens at, so the edge never steps) starts off-panel and travels to the film's centre; the follower stream samples the same pose, so its trail rides in with it. The entrance IS the travel, so no flow circle is handed over: once it lands the film seeds in place, exactly as in the [qubit film](../screen-types/status-qubit.md) — when the screen names an `icon`, the token's glyph and its edge stroke ride the sliding body and leave over the seed — so a flow's disc appears to walk in, become a qubit and split ([entering a film](film-entrance.md)).

| part | value |
|---|---|
| start x, `"left"` | {{val:pq1.layout.VALUE_PARK_X}} — the value screen's park spot, the disc fully off-panel |
| start x, `"right"` | mirrored across the panel: its width, {{val:pq1.layout.W}}, minus the park spot |
| travel | to the film's own centre, `QubitCfg.gc` — x {{val:pq1.layout.CENTER_X}}, y {{val:pq1.layout.CIRCLE_CY}}, the grid's circle centre — the same 274 px either way |
| curve | `motion.spring_travel` ({{loc:pq1.motion.spring_travel}}) — a critically damped spring released from rest, in closed form |

The whole film after it is simply **shifted** by the entrance's length (`burst.t_shift`, {{loc:pq1.procedural.burst.t_shift}}): seed, split, orbit, spiral, clump and boom all happen that much later.

## sides — two qubits fly onto the orbit

No rest, no split, no token body: the pair arrives already apart. Each qubit (r {{val:qubit:r_q}}) is laid out on a polar spiral from {{val:pq1.procedural.burst.SIDES_R0}} px out — both fully off the panel — down to the orbit radius over {{val:pq1.procedural.burst.SIDES_TURN}} rad, one full turn, its vertical reach squashed toward {{val:pq1.procedural.burst.SIDES_Y_MAX}} px by a `tanh` so the path matches the qubit join's ellipse. The twin is the same path turned by π.

The qubits travel that path **by arc length**, at a speed that only falls: {{val:pq1.procedural.burst.SIDES_V0}} × the orbit speed at the edge, easing onto *exactly* the orbit speed at the join. The orbit is then entered at the arrival angle, so speed and heading are continuous — the motion never stops and restarts.

This entrance **replaces** the film's seed, split and join, so `t_shift` is negative: a `"sides"` film resolves *earlier* than the stock one. Do not assume an entrance always makes a film longer.

## Motion

{{motion-head}}
{{row:left / right — the disc travels in | pq1.motion.ENTER_MS | spring KIOSK | by here the 274 px trip has settled to about a third of a pixel; the film then switches to the loading pose}}
{{row:left / right — everything after, shifted whole | pq1.motion.ENTER_MS | — | `burst.t_shift`}}
{{row:no entrance — the pair reaches the orbit | qubit:t2 + qubit:T_SPLIT + qubit:T_JOIN | — | `burst.t_arrive`: the seed, the split and the sweep onto the circle}}
{{row:left / right — the same moment | pq1.motion.ENTER_MS + qubit:t2 + qubit:T_SPLIT + qubit:T_JOIN | — | the busy caption opens here, never over the split ([busy caption](../components/busy-caption.md))}}
{{row:sides — the approach, edge to orbit | - | linear + ease_out | no token: its length is geometry — the spiral's arc length divided by the speed schedule, a steady term plus a falling one shaped like `ease_out`}}
{{row:sides — the orbit takes over | - | — | at the first orbit angle that matches the arrival, so nothing jumps}}
{{row:the trail follows the entering body | - | — | five links sampled from the same pose, one every 0.22 rad of orbit}}

## Input

None: the film is part of an ending ([unbound gestures](../actions/unbound-gestures.md)).

## Preview

{{preview}}

## Do / Don't

- **Do** port the `KIOSK` response for this one trip. It is the film's own choreography, baked into a pure function of ms, not a navigation spring — the one place the demo pace is device-visible on purpose. Everything the *flow* springs stays on `NAV` ([spring morph](spring-morph.md)).
- **Do** keep the `"sides"` speed monotonically falling onto the orbit speed. A port that eases position instead of arc length will stall at the join.
- **Do** hold the busy caption until the pair is on the orbit — on the way in a qubit crosses the caption band.
- **Don't** expect a glyph handoff on `"sides"`: there is no single body to carry the mark, and the code draws none.
- **Don't** hard-code a length for `"sides"`. It falls out of the geometry; if you change the spiral, recompute it.

{{partial:port-notes}}

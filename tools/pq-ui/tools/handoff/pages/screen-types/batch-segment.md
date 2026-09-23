## What it is

A batch is several transactions signed in one session. The flow is a run of **segments**, one per transaction. A segment is every screen up to and including a status screen: the status closes it (`layout._segments`, {{loc:pq1.layout._segments}}). An ordinary flow is one segment; a batch has one per transaction, and each segment has its own hub, its own commit points and its own ending.

This is not a new screen kind. It is a rule about how heroes, details and endings are strung together, and about what the buttons reach.

## When it appears

{{used-in}}

`batch/transfers` signs three transfers. `batch/transfers_declined` is its render twin: it shows a decline on transaction 2 ending the whole batch. The twin exists for the GIF only — do not port it as a second flow.

## Spec

One segment of `batch/transfers` — screens 1–9 are built by `transaction()` in `flows/batch/transfers.py`, the closing status by `signed()`:

| # | screen | kind | notes |
|---|---|---|---|
| 1 | `BATCH SIGN TX n OF m` ▸ | [hero, pager](hero-pager.md), announce form | the last transaction opens on the ask form instead |
| 2 | `SEND 1,250 TOSHI?` | [hero — the ask](hero-ask.md) | the transaction's own ask: no pager, `commit` true |
| 3–8 | TO, CHAIN, AMOUNT, MAX FEE, WORST CASE, DETAILS | [detail](detail.md) | per-transaction values |
| 9 | `BATCH SIGN TX n OF m TX?` | hero, pager, ask form | the return point; `commit` true |
| 10 | `SIGNED n OF m` | [status, qubit film](status-qubit.md) | closes the segment; the last one is `BATCH SIGNED m OF m` |

The ask form that closes a segment:

{{example}}

- Mid-batch endings come from `signed()` ({{loc:flows.batch.signed}}); the two terminal endings from `ends()` ({{loc:flows.batch.ends}}). There is **one** decline ending for the whole batch, `BATCH DECLINED`: its caption names the batch, never the transaction it was reached from.
- [Confirm?](confirm.md) is counted **per segment**: a segment with {{val:pq1.layout.CONFIRM_MIN_DETAILS}} or more details gets it at index {{val:pq1.layout.CONFIRM_INDEX}} of the segment, never on the batch total ({{loc:pq1.layout.insert_confirm}}). The BATCH screen and the inner ask both take a slot, so in a batch segment Confirm? lands after the third detail. No live batch is that long; the rule was checked on a synthetic one.
- Every number, address and amount is per-transaction data. So are n and m.

## Motion

Inside a segment nothing is new: [spring morph](../transitions/spring-morph.md) between screens, the [hold](../actions/hold-right-sign.md) on an ask. What is specific to a batch is the seam between two segments:

{{motion-head}}
{{row:the hold on an ask fires, measured from press-down | pq1.motion.HOLD_COMMIT_MS | — | then the full fill fades with the leg into the segment's own ending — see [hold right](../actions/hold-right-sign.md)}}
{{row:the mid-batch ending, `SIGNED n OF m`, start to end | anim:core/qubit:duration | — | the full [qubit film](status-qubit.md), counted from the moment the leg into it has settled; input-dead for all of it}}
{{row:of which: the result rests | pq1.status.RESULT_HOLD_MS | hold | the same [result hold](../transitions/result-hold.md) as every ending}}
{{row:the resting look is replaced by the next token | - | cut | the first step of the leg already draws the next hero's disc; the check, the green ring and the old caption do not crossfade}}
{{row:the next segment's BATCH screen settles | - | spring NAV | the disc is already centred, so only the glyph mix and the text alpha move}}
{{row:its caption and pager fade in | pq1.motion.TEXT_IN_DELAY_MS | spring NAV | }}
{{row:a decline from anywhere: `BATCH DECLINED`, start to end | anim:core/resolve:duration | — | the [cancel resolve](status-resolve.md), no film; then the batch is over}}

**The mid-batch ending moves on by itself.** When `SIGNED n OF m` has rested, the next segment's first screen opens with no press. This is part of the grammar (`DESIGN.md` § Input: the mid-batch ending plays through into the next segment), and the reference driver does it in `frame()` ({{loc:pq1.driver.FlowDriver.frame}}). No press is needed and none is accepted: the ending is input-dead. After the **last** ending, and after `BATCH DECLINED`, the driver freezes on the resting frame.

## Input

Verified on the reference driver with flow `batch/transfers`. Every segment is its own little flow:

| on | either tap | left tap | right tap | hold right | hold left |
|---|---|---|---|---|---|
| BATCH n, announce | to the inner ask | | | unbound | `BATCH DECLINED` |
| BATCH m, ask form, opening the last transaction | to the inner ask | | | signs the last transaction: `BATCH SIGNED` | `BATCH DECLINED` |
| the inner ask `SEND …?` | to the first detail | | | signs this transaction | `BATCH DECLINED` |
| first detail | | back to the inner ask | next detail | unbound | `BATCH DECLINED` |
| last detail | | previous detail | to the returning BATCH ask | unbound | `BATCH DECLINED` |
| BATCH n, ask form, returning | to the first detail | | | signs this transaction | `BATCH DECLINED` |
| `SIGNED n OF m` | input-dead | | | | |

- **Hold right signs the current segment's ending**, not the flow's last one: the driver looks up the segment that holds the current screen (`_segment`, {{loc:pq1.driver.FlowDriver._segment}}) and goes to its closing status (`_hold`, {{loc:pq1.driver.FlowDriver._hold}}).
- **Up to three screens can sign** in a segment: the inner ask and the returning BATCH ask always, and — on the last transaction only — the opening BATCH ask as well. A right hold there signs the last transaction before its details are seen. That is by design: every ask signs.
- **Taps never cross a segment.** The hub target, the section start and the last navigable screen are all read from the current segment, so a signed transaction cannot be revisited. One gap in the reference driver: the back tap is guarded by `i > 0`, not by the segment's first screen (`_tap`, {{loc:pq1.driver.FlowDriver._tap}}). It never shows, because every live segment opens on a BATCH hero and a tap on a hero goes to the hub — but on the device clamp the back tap at the segment's first screen.
- **Hold left is armed on every navigable screen of every segment** and always reaches the same `BATCH DECLINED`. The UI rule stops there: a decline anywhere ends the whole batch. What happens to signatures already given is not defined in this repo.

## Preview

See the clip on [hero — batch position](hero-pager.md). The full render is `python3 -m flows batch/transfers --end all`.

## Do / Don't

- **Do** give every transaction its own ending that names its place (`SIGNED 2 OF 3`), and the batch one shared decline ending.
- **Do** keep the pager and the captions in step with the segment: n changes only at the seam.
- **Don't** port the demo's walk: the dwell timers, the hold the demo performs on each returning ask, the KIOSK spring pace. The device uses the NAV profile and waits for presses — except at the seam above.
- **Don't** port `--end`: it swaps only the **last** status screen, for renders. On the device the ending is chosen by the hold.
- **Don't** drive `batch/transfers_declined` as a device flow. In the driver its transaction 2 closes on `BATCH DECLINED`, so a right hold there lands on the decline ending.

{{partial:port-notes}}

"""SEND flow — screen content only (grid/type/motion come from pq1).

  SEND 5.25 ETH? (idle sweep) -> TO -> on BASE -> MAX FEE -> WORST CASE
  -> DETAILS -> SEND 5.25 ETH? -> status (CONFIRMED by default)

Endings (--end on the CLI): CONFIRMED is the qubit film resolving to a
green check; DECLINED plays no film (the cancel resolve,
status.default_anim) — the token resolves in place, red ring stroke and
red X on the unfilled black disc; FAILED is the work dispatched and lost:
the same film (anim="qubit") colliding into the red X — the one ending a
host's "no" latches (`--ready MS`, the bench's `n`).
Render with `python -m flows send`.

ETH is a RECOGNIZED token: every screen takes the mono treatment (black
body, white ring, white logo, grey trail) via DEFAULTS — the gradient disc
is reserved for tokens the device cannot identify.
"""
from pq1 import gradients

DEFAULTS = dict(token=dict(palette=gradients.MONO_RAMP))

BODY = [
    dict(id="SEND", kind="hero", icon="eth", bottom="SEND 5.25 ETH?", chev="lr", hint=True),
    dict(id="TO", kind="detail", side="left", icon="eth", label="TO",
         lines=["0x78D8526282Ac09f1885", "D0F39B8875a0180Fc081e"], size=22, chev="lr"),
    dict(id="CHAIN", kind="detail", side="right", chain=8453, label=None, chev="lr"),
    dict(id="MAX FEE", kind="detail", side="left", icon="eth", label="MAX FEE",
         lines=["45.5 gwei", "Tip: 2 gwei"], size=28, chev="lr"),
    dict(id="WORST CASE", kind="detail", side="right", icon="eth", label="WORST CASE",
         lines=["Max: 0.0036 ETH", "Gas: 80000"], size=28, chev="lr"),
    dict(id="DETAILS", kind="detail", side="left", icon="eth", label="DETAILS",
         lines=["Nonce: 42", "Data:  0B"], size=28, chev="lr"),
    dict(id="SEND", kind="hero", icon="eth", bottom="SEND 5.25 ETH?", chev="lr", hint=True),
]

ENDS = {
    "confirmed": dict(id="CONFIRMED", kind="status", icon="eth",
                      bottom="TRANSACTION CONFIRMED", chev=None),
    "declined": dict(id="DECLINED", kind="status", icon="eth",
                     result="x", state="failed", bottom="DECLINED", chev=None),
    # the one X ending that plays the film: the work was dispatched and
    # FAILED — the same loading, colliding into the X (anim named, so the
    # host's "no" latches it; a decline stays the film-less resolve)
    "failed": dict(id="FAILED", kind="status", icon="eth", anim="qubit",
                   result="x", state="failed",
                   bottom="TRANSACTION FAILED", chev=None),
}

DEFAULT_END = "confirmed"
SCREENS = BODY + [ENDS[DEFAULT_END]]

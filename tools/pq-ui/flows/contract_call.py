"""CONTRACT CALL flow — screen content only (grid/type/motion come from pq1).

  CONFIRM CONTRACT CALL? (idle sweep) -> NETWORK -> VALUE -> TO -> MAX FEE
  -> WORST CASE -> DETAIL -> back on the idle hero (every detail seen, the
  ask again) -> status (CONFIRMED by default) — the full walkthrough.

Endings (--end on the CLI): CONFIRMED is the qubit film resolving to a
green check; DECLINED plays no film (the cancel resolve,
status.default_anim) — the token resolves in place, red ring stroke and
red X on the unfilled black disc. Six detail screens: below the 7-detail
threshold there is no mid-flow Confirm? and no --early variant
(DESIGN.md § Flow shape) — the call is signed on an ask only, the
opening or the returning one.

A generic contract call: the chain context, the value carried by the
call, the contract address, the fee cap, the worst-case cost and the
transaction detail. Every label and value line is variable content —
"0 ETH", the address, the gwei figures, the nonce and the calldata size
are representative samples filled per transaction on device.
The chain screen follows the hero, so the id stays NETWORK: canonical id
CHAIN must directly follow TO or AMOUNT.
Render with `python -m flows contract_call --end all`.

The contract has no logo asset: every screen takes the placeholder
treatment (DESIGN.md § Color, Placeholder palettes) — a SOLID disc, never
the gradient, in the fill of the six-stop ramp hashed from the contract
ADDRESS (token "palette" -> components.token_ramp, crc32, never fixed),
its trail the same ramp darkening away from the token — so this contract
always wears the same colour. CONTRACT is one constant: the TO screen
shows it and the token derives its ramp from it. The endings keep the
unbranded resting look — black disc, the state colour on the ring stroke
and the glyph — and the hold fill rises as a black film over the solid
disc.
"""
# the contract address — variable content, filled per transaction on device
CONTRACT = "0x78D8526282Ac09f1885D0F39B8875a0180Fc081e"

DEFAULTS = dict(token=dict(palette=CONTRACT))   # solid fill + trail from the address

BODY = [
    dict(id="CONTRACT CALL", kind="hero", icon="eth",
         bottom="CONFIRM CONTRACT CALL?", chev="lr", hint=True),
    dict(id="NETWORK", kind="detail", side="right", chain=8453, label=None, chev="lr"),
    dict(id="VALUE", kind="detail", side="left", icon="eth", label="VALUE",
         lines=["0 ETH"], size=36, chev="lr"),
    dict(id="TO", kind="detail", side="right", icon="eth", label="TO",
         lines=[CONTRACT[:21], CONTRACT[21:]], size=22, chev="lr"),
    dict(id="MAX FEE", kind="detail", side="left", icon="eth", label="MAX FEE",
         lines=["45.5 gwei", "Tip: 2 gwei"], size=28, chev="lr"),
    dict(id="WORST CASE", kind="detail", side="right", icon="eth", label="WORST CASE",
         lines=["Max: 0.0036 ETH", "Gas: 80000"], size=28, chev="lr"),
    dict(id="DETAIL", kind="detail", side="left", icon="eth", label="DETAIL",
         lines=["Nonce: 42", "Data:  0B"], size=28, chev="lr"),
]

ENDS = {
    "confirmed": dict(id="CONFIRMED", kind="status", icon="eth",
                      bottom="CONTRACT CALL CONFIRMED", chev=None),
    "declined": dict(id="DECLINED", kind="status", icon="eth",
                     result="x", state="failed", bottom="CONTRACT CALL DECLINED", chev=None),
}

DEFAULT_END = "confirmed"
# the full walkthrough: every detail, back on the idle ask, then the
# ending plays — loading resolving to success (or cancellation via --end)
SCREENS = BODY + [dict(BODY[0]), ENDS[DEFAULT_END]]

"""SEND TOKEN flow — a token send, screen content only (grid/type/motion
come from pq1).

  SEND 12,500 TOSHI? (idle sweep) -> NETWORK -> TO -> VALUE -> MAX FEE
  -> WORST CASE -> DETAIL -> back on the idle hero (every detail seen, the
  ask again) -> status (SUCCESSFUL by default) — the full walkthrough.

Endings (--end on the CLI): SUCCESSFUL is the qubit film resolving to a
green check; DECLINED plays no film (the cancel resolve,
status.default_anim) — the token resolves in place, red ring stroke and
red X on the unfilled black disc. Six detail screens: below the 7-detail
threshold there is no mid-flow Confirm? and no --early variant
(DESIGN.md § Flow shape) — the send is signed on an ask only, the
opening or the returning one.

The token's balance and symbol are VARIABLE content — filled per
transaction on the device, for ANY token; "12,500 TOSHI" is one
placeholder sample shared by the ask and the VALUE screen (BALANCE +
SYMBOL below), sitting exactly on the 36-tier budget (12 chars). The
sample is a LONG-TAIL token on purpose — never a popular one with a logo
asset (USDC, USDT, DAI, ETH) — so this module shows the placeholder look.
components.token_defaults(SYMBOL) resolves the treatment from the symbol:
here a SOLID disc, never the gradient, in the fill of the six-stop ramp
hashed from the symbol (token "palette" -> components.token_ramp, crc32,
never fixed), its trail the same ramp darkening away from the token — so
this token always wears the same colour. On device the same switch puts a
popular token's logo art in the disc (set SYMBOL to USDC / USDT / DAI to
render that look); flows/send_token_named.py is the twin whose TO screen
resolves to a name. The address, the gwei figures, the worst case in the
chain's gas token (ETH: fee cap x gas limit), the nonce and the calldata
size (transfer(to, amount) is 68 bytes) are representative samples too.
The chain screen follows the hero, so the id stays NETWORK:
canonical id CHAIN must directly follow TO or AMOUNT.
Render with `python -m flows send_token --end all`.

The endings keep the unbranded resting look — black disc, the state
colour on the ring stroke and the glyph — and the hold fill rises as a
black film over the solid disc.
"""
from pq1 import components

# the token balance + symbol — variable content, filled per transaction on
# device; the sample is a long-tail token so the placeholder look shows
BALANCE = "12,500"
SYMBOL = "TOSHI"
AMOUNT = f"{BALANCE} {SYMBOL}"

DEFAULTS = components.token_defaults(SYMBOL)   # solid fill + trail hashed from the symbol

BODY = [
    dict(id="SEND", kind="hero", bottom=f"SEND {AMOUNT}?", chev="lr", hint=True),
    dict(id="NETWORK", kind="detail", side="right", chain=8453, label=None, chev="lr"),
    dict(id="TO", kind="detail", side="left", label="TO",
         lines=["0x78D8526282Ac09f1885", "D0F39B8875a0180Fc081e"], size=22, chev="lr"),
    dict(id="VALUE", kind="detail", side="right", label="VALUE",
         lines=[AMOUNT], size=36, chev="lr"),
    dict(id="MAX FEE", kind="detail", side="left", label="MAX FEE",
         lines=["45.5 gwei", "Tip: 2 gwei"], size=28, chev="lr"),
    dict(id="WORST CASE", kind="detail", side="right", label="WORST CASE",
         lines=["Max: 0.0036 ETH", "Gas: 80000"], size=28, chev="lr"),
    dict(id="DETAIL", kind="detail", side="left", label="DETAIL",
         lines=["Nonce: 42", "Data: 68B"], size=28, chev="lr"),
]

ENDS = {
    "successful": dict(id="SUCCESSFUL", kind="status",
                       bottom="TRANSACTION SUCCESSFUL", chev=None),
    "declined": dict(id="DECLINED", kind="status",
                     result="x", state="failed", bottom="TRANSACTION DECLINED", chev=None),
}

DEFAULT_END = "successful"
# the full walkthrough: every detail, back on the idle ask, then the
# ending plays — loading resolving to success (or cancellation via --end)
SCREENS = BODY + [dict(BODY[0]), ENDS[DEFAULT_END]]

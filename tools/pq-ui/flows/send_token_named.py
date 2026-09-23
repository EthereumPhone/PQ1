"""SEND TOKEN (NAMED RECIPIENT) flow — the send_token twin whose TO screen
resolves to a name, screen content only (grid/type/motion come from pq1).

  SEND 12,500 TOSHI? (idle sweep) -> NETWORK -> TO -> VALUE -> MAX FEE
  -> WORST CASE -> DETAIL -> back on the idle hero (every detail seen, the
  ask again) -> status (SUCCESSFUL by default) — the full walkthrough.

Identical to send_token screen for screen except TO: the recipient is
known to the device (address book / ENS), so the name carries the first
row — SemiBold, the face a name inside a value takes (DESIGN.md § Text
rules, Names: the name identifies, the address confirms) — and a
SHORTENED address — the address's first 8 and last 8 characters around a
single ellipsis — sits under it in Regular as the confirming second row.
Both rows share the screen's one tier: the 17-character
shortened address is past the 28-tier's 16-character budget, so TO is 22
(DESIGN.md § Typography).

DEPARTURE, deliberate and scoped to this screen: DESIGN.md § Text rules
says addresses break mid-string over <=21-character lines with NO
ellipsis, "the full value must be verifiable on screen" — the shortened
form here cannot be fully verified. It is the point of the flow: the name
is the recipient's identity and the shortened address is its fingerprint.
Use send_token when the full address must be read on screen.

Both rows are VARIABLE content — the name and the address are filled per
transaction on the device; "Hardware Wallet" and the shortened address
below are placeholder samples that exercise the 22 tier. The balance and
symbol are variable too ("12,500 TOSHI" is one sample shared by the ask
and the VALUE screen, the same long-tail sample as send_token), as are
the gwei figures, the worst case in the chain's gas token (ETH: fee cap
x gas limit), the nonce and the calldata size (transfer(to, amount) is
68 bytes). The chain screen follows the hero, so the id stays NETWORK:
canonical id CHAIN must directly follow TO or AMOUNT.

Endings (--end on the CLI): SUCCESSFUL is the qubit film resolving to a
green check; DECLINED plays no film (the cancel resolve,
status.default_anim) — the token resolves in place, red ring stroke and
red X on the unfilled black disc. Six detail screens: below the 7-detail
threshold there is no mid-flow Confirm? and no --early variant
(DESIGN.md § Flow shape) — the send is signed on an ask only, the
opening or the returning one.
Render with `python -m flows send_token_named --end all`.

The token treatment is send_token's: components.token_defaults(SYMBOL)
is the switch — the long-tail sample takes the placeholder look, a SOLID
disc, never the gradient, in the fill of the six-stop ramp hashed from
the symbol (token "palette" -> components.token_ramp, crc32, never
fixed), its trail the same ramp darkening away from the token — so this
token always wears the same colour as it does in send_token; on device
a popular symbol (components.TOKEN_LOGOS: USDC, USDT, DAI) puts its logo
art in the disc instead, ETH its white mark on the mono body. The
endings keep the unbranded resting look — black disc, the state colour
on the ring stroke and the glyph — and the hold fill rises as a black
film over the solid disc (over the art on a logo token).
"""
from pq1 import components

# the token balance + symbol — variable content, filled per transaction on
# device; the sample is a long-tail token so the placeholder look shows
BALANCE = "12,500"
SYMBOL = "TOSHI"
AMOUNT = f"{BALANCE} {SYMBOL}"

# the resolved recipient — variable content: the device's name for the
# address, and that address's first 8 / last 8 characters as its fingerprint
NAME = "Hardware Wallet"
ADDRESS_SHORT = "0x78D852…80Fc081e"

DEFAULTS = components.token_defaults(SYMBOL)   # solid fill + trail hashed from the symbol

BODY = [
    dict(id="SEND", kind="hero", bottom=f"SEND {AMOUNT}?", chev="lr", hint=True),
    dict(id="NETWORK", kind="detail", side="right", chain=8453, label=None, chev="lr"),
    dict(id="TO", kind="detail", side="left", label="TO",
         lines=[dict(str=NAME, weight="semibold"), ADDRESS_SHORT], size=22, chev="lr"),
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

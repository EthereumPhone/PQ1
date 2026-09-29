"""TRANSFER UNKNOWN TOKEN flow — an ERC-20 transfer of a token the device
does not recognize, screen content only (grid/type/motion come from pq1).

  TRANSFER UNKNOWN TOKEN? (idle sweep) -> NETWORK -> CONTRACT -> AMOUNT
  -> TO -> Confirm? (auto-inserted as screen 6, the early exit) -> MAX FEE
  -> WORST CASE -> DETAILS -> back on the idle hero (every detail seen,
  the ask again) -> status (SUCCESSFUL by default) — the full walkthrough.

Seven detail screens: the design system inserts the mid-flow Confirm? as
screen 6 (DESIGN.md § Flow shape) and `--early` commits there, skipping
the fee screens. The transfer is signed on an ask only — the opening
hero, Confirm?, or the returning hero — never on a detail.

Endings (--end on the CLI): SUCCESSFUL is the qubit film resolving to a
green check; DECLINED plays no film (the cancel resolve,
status.default_anim) — the token resolves in place, red ring stroke and
red X on the unfilled black disc. Captions "TRANSFER SUCCESSFUL" /
"TRANSFER DECLINED".

The token is UNRESOLVED — the device has no symbol, no name, no decimals —
so every screen shows what the transaction itself carries: CONTRACT the
token contract address alone (the address treatment, two <= 21-char
halves at 22, no name line); AMOUNT the raw uint256 transfer amount,
undivided by decimals, flagged "(RAW)" over the integer (22: the integer
is 20 chars); TO the recipient address alone. EVERY value line is
VARIABLE content — the addresses, the raw amount, the gwei figures, the
worst case in the chain's gas token (fee cap x gas limit: 45.5 gwei x
65000), the nonce and the calldata size (transfer(to, amount) is 68
bytes) are representative samples filled per transaction on device.
The chain screen follows the hero, so the id stays NETWORK: canonical id
CHAIN must directly follow TO or AMOUNT.
Render with `python -m flows transfer_unknown_token --end all` and
`python -m flows transfer_unknown_token --early --end all`.

No logo asset and no symbol: the token takes the placeholder treatment
(DESIGN.md § Color, Placeholder palettes) — a SOLID disc, never the
gradient, in the fill of the six-stop ramp hashed from the contract
ADDRESS (token "palette" -> components.token_ramp, crc32, never fixed),
its trail the same ramp darkening away from the token. CONTRACT is one
constant: the CONTRACT screen shows it and the token derives its ramp
from it. The endings keep the unbranded resting look — black disc, the
state colour on the ring stroke and the glyph — and the hold fill rises
as a black film over the solid disc.
"""
# the token contract, the raw amount and the recipient — variable content,
# filled per transaction on device
CONTRACT = "0x3cA9e5F1b72D04E8a6c1D9B3f57E28a0C4d6B1e9"
RAW_AMOUNT = "12345678901234567890"
RECIPIENT = "0x78D8526282Ac09f1885D0F39B8875a0180Fc081e"

DEFAULTS = dict(token=dict(palette=CONTRACT))   # solid fill + trail from the address

BODY = [
    dict(id="TRANSFER", kind="hero", icon="eth",
         bottom="TRANSFER UNKNOWN TOKEN?", chev="lr", hint=True),
    dict(id="NETWORK", kind="detail", side="right", chain=8453, label=None, chev="lr"),
    dict(id="CONTRACT", kind="detail", side="left", icon="eth", label="CONTRACT",
         lines=[CONTRACT[:21], CONTRACT[21:]], size=22, chev="lr"),
    dict(id="AMOUNT", kind="detail", side="right", icon="eth", label="AMOUNT",
         lines=["(RAW)", RAW_AMOUNT], size=22, chev="lr"),
    dict(id="TO", kind="detail", side="left", icon="eth", label="TO",
         lines=[RECIPIENT[:21], RECIPIENT[21:]], size=22, chev="lr"),
    # Confirm? lands here — screen 6, placed by layout.insert_confirm
    dict(id="MAX FEE", kind="detail", side="right", icon="eth", label="MAX FEE",
         lines=["45.5 gwei", "Tip: 2 gwei"], size=28, chev="lr"),
    dict(id="WORST CASE", kind="detail", side="left", icon="eth", label="WORST CASE",
         lines=["Max: 0.0030 ETH", "Gas: 65000"], size=28, chev="lr"),
    dict(id="DETAILS", kind="detail", side="right", icon="eth", label="DETAILS",
         lines=["Nonce: 42", "Data: 68B"], size=28, chev="lr"),
]

ENDS = {
    "successful": dict(id="SUCCESSFUL", kind="status", icon="eth",
                       bottom="TRANSFER SUCCESSFUL", chev=None),
    "declined": dict(id="DECLINED", kind="status", icon="eth",
                     result="x", state="failed", bottom="TRANSFER DECLINED", chev=None),
}

DEFAULT_END = "successful"
# the full walkthrough: every detail, back on the idle ask, then the
# ending plays — loading resolving to success (or cancellation via --end)
SCREENS = BODY + [dict(BODY[0]), ENDS[DEFAULT_END]]

"""APPROVE TOKEN flow — an ERC-20 approve, screen content only (grid/type/
motion come from pq1).

  APPROVE USDC? (idle sweep) -> NETWORK -> SPENDER -> AMOUNT -> CONTRACT
  -> Confirm? (auto-inserted as screen 6, the early exit) -> MAX FEE
  -> WORST CASE -> DETAILS -> back on the idle hero (every detail seen,
  the ask again) -> status (APPROVED by default) — the full walkthrough.

Seven detail screens: the design system inserts the mid-flow Confirm? as
screen 6 (DESIGN.md § Flow shape) and `--early` commits there, skipping
the fee screens. The approval is signed on an ask only — the opening
hero, Confirm?, or the returning hero — never on a detail.

Endings (--end on the CLI): APPROVED is the qubit film resolving to a
green check; REJECTED plays no film (the cancel resolve,
status.default_anim) — the token resolves in place, red ring stroke and
red X on the unfilled black disc. Both captions carry the token symbol:
"USDC APPROVED" / "USDC REJECTED".

THE EXAMPLES CYCLE THE POPULAR TOKENS. SAMPLES lists four example tokens
— USDC, DAI, USDT and WETH (ether's ERC-20 wrapper: ether itself has no
approve) — and build(**sample) is the flow for one of them. The renders
take one sample per variant slot (flows.sample_slot: full/approved USDC,
full/rejected DAI, early/approved USDT, early/rejected WETH;
`--sample DAI` or `--sample all` picks by hand), so the example set shows
every logo on its own coloured trail: components.token_defaults(symbol)
dresses a listed token in its logo art (components.TOKEN_LOGOS) on the
trail in the logo's own colour (colors.TOKEN_GRADIENTS, pinned by symbol),
WETH in the white ether mark on the mono body, and any other symbol in
the solid placeholder disc hashed from it. Production is untouched: on
device every value is filled per transaction and the same switch serves
every token.

EVERY value line is VARIABLE content — the flow fixes the screens, their
order, labels and sides, and the tier rule, never a value. The samples:
the symbol in the ask and the captions; SPENDER the spender address alone
(the address treatment, two <= 21-char halves at 22); AMOUNT the
allowance — "Unlimited" here, a capped allowance reads as an amount +
symbol pair ("1,000 USDC"); CONTRACT the token contract the approve is
sent to (the Base deployments) — its NAME rides SemiBold on line 1
(DESIGN.md § Text rules, Names: the name identifies, the address
confirms) over the Regular address halves; MAX FEE the fee cap per gas +
the priority tip; WORST CASE the max cost in the chain's gas token (fee
cap x gas limit) + the gas limit (an approve burns ~46-60k gas); DETAILS
the nonce + the calldata size (approve(spender, amount) is 68 bytes).
The chain screen follows the hero, so the id stays NETWORK: canonical id
CHAIN must directly follow TO or AMOUNT.
Render with `python -m flows approve_token --end all` and
`python -m flows approve_token --early --end all`.

The endings keep the unbranded resting look — black disc, the state
colour on the ring stroke and the glyph — and the hold fill rises as a
black film over the logo art (white inside WETH's black body).
"""
from pq1 import components

# the example tokens — the renders cycle through them (one per variant
# slot); on device the token is whatever the transaction approves
SAMPLES = [
    dict(symbol="USDC", name="USD Coin",
         contract="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"),
    dict(symbol="DAI", name="Dai Stablecoin",
         contract="0x50c5725949A6F0c72E6C4a641F24049A917DB0Cb"),
    dict(symbol="USDT", name="Tether USD",
         contract="0xfde4C96c8593536E31F229EA8f37b2ADa2699bb2"),
    dict(symbol="WETH", name="Wrapped Ether",
         contract="0x4200000000000000000000000000000000000006"),
]
# the spender and the allowance — variable content too
SPENDER = "0x000000000022D473030F116dDEE9F6B43aC78BA3"
ALLOWANCE = "Unlimited"
DEFAULT_END = "approved"


def build(symbol, name, contract):
    """the flow for one token sample -> dict(DEFAULTS, ENDS, SCREENS)"""
    body = [
        dict(id="APPROVE", kind="hero", bottom=f"APPROVE {symbol}?", chev="lr", hint=True),
        dict(id="NETWORK", kind="detail", side="right", chain=8453, label=None, chev="lr"),
        dict(id="SPENDER", kind="detail", side="left", label="SPENDER",
             lines=[SPENDER[:21], SPENDER[21:]], size=22, chev="lr"),
        dict(id="AMOUNT", kind="detail", side="right", label="AMOUNT",
             lines=[ALLOWANCE], size=36, chev="lr"),
        dict(id="CONTRACT", kind="detail", side="left", label="CONTRACT",
             lines=[dict(str=name, weight="semibold"), contract[:21], contract[21:]],
             size=22, chev="lr"),
        # Confirm? lands here — screen 6, placed by layout.insert_confirm
        dict(id="MAX FEE", kind="detail", side="right", label="MAX FEE",
             lines=["45.5 gwei", "Tip: 2 gwei"], size=28, chev="lr"),
        dict(id="WORST CASE", kind="detail", side="left", label="WORST CASE",
             lines=["Max: 0.00273 ETH", "Gas: 60000"], size=28, chev="lr"),
        dict(id="DETAILS", kind="detail", side="right", label="DETAILS",
             lines=["Nonce: 42", "Data: 68B"], size=28, chev="lr"),
    ]
    ends = {
        "approved": dict(id="APPROVED", kind="status",
                         bottom=f"{symbol} APPROVED", chev=None),
        "rejected": dict(id="REJECTED", kind="status", result="x", state="failed",
                         bottom=f"{symbol} REJECTED", chev=None),
    }
    # the full walkthrough: every detail, back on the idle ask, then the
    # ending plays — loading resolving to approval (or rejection via --end)
    return dict(DEFAULTS=components.token_defaults(symbol), ENDS=ends,
                SCREENS=body + [dict(body[0]), ends[DEFAULT_END]])


# the module's own flow is the first sample — what `python -m flows
# approve_token` plays, what the manifest tables, what the bench player drives
_first = build(**SAMPLES[0])
DEFAULTS, ENDS, SCREENS = _first["DEFAULTS"], _first["ENDS"], _first["SCREENS"]

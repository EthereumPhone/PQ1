"""TRANSFER TOKEN flow — an ERC-20 transfer of a recognized token, screen
content only (grid/type/motion come from pq1).

  SEND 1,250.00 USDC? (idle sweep) -> NETWORK -> TO -> CONTRACT -> MAX FEE
  -> WORST CASE -> DETAIL -> back on the idle hero (every detail seen, the
  ask again) -> status (SUCCESSFUL by default) — the full walkthrough.

Six detail screens: below the 7-detail threshold there is no mid-flow
Confirm? and no --early variant (DESIGN.md § Flow shape) — the transfer
is signed on an ask only, the opening or the returning one. The balance
lives in the ask alone: there is no separate amount screen.

Endings (--end on the CLI): SUCCESSFUL is the qubit film resolving to a
green check; DECLINED plays no film (the cancel resolve,
status.default_anim) — the token resolves in place, red ring stroke and
red X on the unfilled black disc. Captions "TRANSACTION SUCCESSFUL" /
"TRANSACTION DECLINED".

THE EXAMPLES CYCLE THE POPULAR TOKENS. SAMPLES lists four example tokens
— USDC, DAI, USDT and WETH — and build(**sample) is the flow for one of
them. The renders take one sample per variant slot (flows.sample_slot:
full/declined USDC, full/successful DAI; `--sample USDC` or
`--sample all` picks by hand), so the example set shows the logos on
their own coloured trails: components.token_defaults(symbol) dresses a
listed token in its logo art (components.TOKEN_LOGOS) on the trail in
the logo's own colour (colors.TOKEN_GRADIENTS, pinned by symbol), WETH in
the white ether mark on the mono body, and any other symbol in the solid
placeholder disc hashed from it. Production is untouched: on device
every value is filled per transaction and the same switch serves every
token — flows/send_token.py is the same transfer on a long-tail sample.

EVERY value line is VARIABLE content — the flow fixes the screens, their
order, labels and sides, and the tier rule, never a value. The samples:
the balance and symbol in the ask; TO the recipient address alone (the
address treatment, two <= 21-char halves at 22); CONTRACT the token
contract the transfer is sent to (the Base deployments) — its NAME rides
SemiBold on line 1 (DESIGN.md § Text rules, Names: the name identifies,
the address confirms) over the Regular address halves; MAX FEE the fee
cap per gas + the priority tip; WORST CASE the max cost in the chain's
gas token (fee cap x gas limit: 45.5 gwei x 65000) + the gas limit;
DETAIL the nonce + the calldata size (transfer(to, amount) is 68 bytes).
The chain screen follows the hero, so the id stays NETWORK: canonical id
CHAIN must directly follow TO or AMOUNT.
Render with `python -m flows transfer_token --end all`.

The endings keep the unbranded resting look — black disc, the state
colour on the ring stroke and the glyph — and the hold fill rises as a
black film over the logo art (white inside WETH's black body).
"""
from pq1 import components

# the example tokens — the renders cycle through them (one per variant
# slot); on device the token is whatever the transaction sends
SAMPLES = [
    dict(symbol="USDC", balance="1,250.00", name="USD Coin",
         contract="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"),
    dict(symbol="DAI", balance="1,250.00", name="Dai Stablecoin",
         contract="0x50c5725949A6F0c72E6C4a641F24049A917DB0Cb"),
    dict(symbol="USDT", balance="1,250.00", name="Tether USD",
         contract="0xfde4C96c8593536E31F229EA8f37b2ADa2699bb2"),
    dict(symbol="WETH", balance="0.5", name="Wrapped Ether",
         contract="0x4200000000000000000000000000000000000006"),
]
# the recipient — variable content too
RECIPIENT = "0x78D8526282Ac09f1885D0F39B8875a0180Fc081e"
DEFAULT_END = "successful"


def build(symbol, balance, name, contract):
    """the flow for one token sample -> dict(DEFAULTS, ENDS, SCREENS)"""
    body = [
        dict(id="SEND", kind="hero", bottom=f"SEND {balance} {symbol}?", chev="lr", hint=True),
        dict(id="NETWORK", kind="detail", side="right", chain=8453, label=None, chev="lr"),
        dict(id="TO", kind="detail", side="left", label="TO",
             lines=[RECIPIENT[:21], RECIPIENT[21:]], size=22, chev="lr"),
        dict(id="CONTRACT", kind="detail", side="right", label="CONTRACT",
             lines=[dict(str=name, weight="semibold"), contract[:21], contract[21:]],
             size=22, chev="lr"),
        dict(id="MAX FEE", kind="detail", side="left", label="MAX FEE",
             lines=["45.5 gwei", "Tip: 2 gwei"], size=28, chev="lr"),
        dict(id="WORST CASE", kind="detail", side="right", label="WORST CASE",
             lines=["Max: 0.0030 ETH", "Gas: 65000"], size=28, chev="lr"),
        dict(id="DETAIL", kind="detail", side="left", label="DETAIL",
             lines=["Nonce: 42", "Data: 68B"], size=28, chev="lr"),
    ]
    ends = {
        "successful": dict(id="SUCCESSFUL", kind="status",
                           bottom="TRANSACTION SUCCESSFUL", chev=None),
        "declined": dict(id="DECLINED", kind="status", result="x", state="failed",
                         bottom="TRANSACTION DECLINED", chev=None),
    }
    # the full walkthrough: every detail, back on the idle ask, then the
    # ending plays — loading resolving to success (or cancellation via --end)
    return dict(DEFAULTS=components.token_defaults(symbol), ENDS=ends,
                SCREENS=body + [dict(body[0]), ends[DEFAULT_END]])


# the module's own flow is the first sample — what `python -m flows
# transfer_token` plays, what the manifest tables, what the bench player drives
_first = build(**SAMPLES[0])
DEFAULTS, ENDS, SCREENS = _first["DEFAULTS"], _first["ENDS"], _first["SCREENS"]

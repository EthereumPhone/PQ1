"""ERC7730 SWAP flow — a call clear-signed from its ERC-7730 descriptor,
screen content only (grid/type/motion come from pq1).

  ERC-7730 CLEAR SIGNING ▸ (the intro: dev mark, gold trail) -> SIGN SWAP
  COINBASE UNISWAP V3? (idle sweep) -> NETWORK -> AMOUNT -> FUNCTION
  -> MAX FEE -> WORST CASE -> DETAIL -> back on the idle hero (every
  detail seen, the ask again) -> status (SIGNED by default) — the full
  walkthrough.

Six detail screens: below the 7-detail threshold there is no mid-flow
Confirm? and no `--early` variant (DESIGN.md § Flow shape). The swap is
signed on an ask only — the opening ask or the returning one — never on
the intro or a detail.

Endings (--end on the CLI): SIGNED is the qubit film resolving to a
green check; DECLINED plays no film (the cancel resolve,
status.default_anim) — the token resolves in place, red ring stroke and
red X on the unfilled black disc. Captions "SWAP SIGNED" / "SWAP
DECLINED".

EVERY value line is VARIABLE content — the descriptor's intent and the
transaction's figures, filled per transaction on device; the flow fixes
the screens, their order, labels and sides, never a value. The samples:
the ask the descriptor's short intent; NETWORK the chain; AMOUNT the
value the call carries ("0 ETH" at 36); FUNCTION the call in words
("Approve unlimited USDC" — 22 characters, broken once between words at
28); MAX FEE the fee cap per gas + the priority tip; WORST CASE the max
cost in the chain's gas token (fee cap x gas limit) + the gas limit;
DETAIL the account nonce alone at 36. The chain screen follows the ask,
so the id stays NETWORK: canonical id CHAIN must directly follow TO or
AMOUNT.
Render with `python -m flows erc7730/swap --end all`.
"""
from flows.erc7730 import defaults, ends, intro

# the contract the call goes to (Uniswap V3 SwapRouter02 on Base) —
# variable content; the disc takes its colour from this address
CONTRACT = "0x2626664c2603336E57B271c5C0b26F421741e481"

DEFAULTS = defaults(CONTRACT)

BODY = [
    intro(),
    dict(id="SIGN", kind="hero", bottom="SIGN SWAP COINBASE UNISWAP V3?", chev="lr", hint=True),
    dict(id="NETWORK", kind="detail", side="right", chain=8453, label=None, chev="lr"),
    dict(id="AMOUNT", kind="detail", side="left", label="AMOUNT",
         lines=["0 ETH"], size=36, chev="lr"),
    dict(id="FUNCTION", kind="detail", side="right", label="FUNCTION",
         lines=["Approve", "unlimited USDC"], size=28, chev="lr"),
    dict(id="MAX FEE", kind="detail", side="left", label="MAX FEE",
         lines=["45.5 gwei", "Tip: 2 gwei"], size=28, chev="lr"),
    dict(id="WORST CASE", kind="detail", side="right", label="WORST CASE",
         lines=["Max: 0.00273 ETH", "Gas: 60000"], size=28, chev="lr"),
    dict(id="DETAIL", kind="detail", side="left", label="DETAIL",
         lines=["Nonce: 42"], size=36, chev="lr"),
]

ENDS = ends("SWAP")
DEFAULT_END = "signed"
# the full walkthrough: every detail, back on the ask (BODY[1] — never the
# intro), then the ending plays
SCREENS = BODY + [dict(BODY[1]), ENDS[DEFAULT_END]]

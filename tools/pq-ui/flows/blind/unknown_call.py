"""UNKNOWN CALL flow — a blind-signed contract call, screen content only
(grid/type/motion come from pq1).

  CONFIRM UNKNOWN CALL? (idle sweep) -> NETWORK -> FUNCTION -> TO -> AMOUNT
  -> Confirm? (auto-inserted as screen 6, the early exit) -> DATA HASH
  -> MAX FEE -> WORST CASE -> CALL DATA -> DETAILS -> back on the idle
  hero (every detail seen, the ask again) -> status (CONFIRMED by default)
  — the full walkthrough.

Nine detail screens: the design system inserts the mid-flow Confirm? as
screen 6 (DESIGN.md § Flow shape) and `--early` commits there, skipping
the hash, the fee screens and the calldata. The call is signed on an ask
only — the opening hero, Confirm?, or the returning hero — never on a
detail.

Endings (--end on the CLI, flows.blind.ends): CONFIRMED is the qubit film
resolving to a green check; DECLINED plays no film (the cancel resolve) —
the token resolves in place, red ring stroke and red X on the unfilled
black disc. Captions "UNKNOWN CALL CONFIRMED" / "UNKNOWN CALL DECLINED".

The device cannot decode this call, so the token wears the family's
blind mark (flows.blind: pq1/assets/blind_icon.svg as procedural art) on
the solid placeholder disc hashed from the contract address — TO shows
the address and the token derives its colour from it, one constant.

EVERY value line is VARIABLE content — the flow fixes the screens, their
order, labels and sides, and the tier rule, never a value. The samples
describe one plausible call — a Uniswap V2 router swap on Base:
FUNCTION the human reading of the selector the device could name
("Swap exact tokens for tokens", broken once between its words at 28);
TO the router address alone (the address treatment, two <= 21-char
halves at 22); AMOUNT the ether the call carries ("0 ETH" — a token
swap sends none); DATA HASH the calldata hash SHORTENED to its first 12
and last 12 characters around a single "…" (a real Aileron glyph) —
the ONE sanctioned departure from DESIGN.md § Text rules "no ellipsis":
the hash is a fingerprint to match against the dapp, not a value to
read in full, and the full 66-char hash would need four 22 px lines;
MAX FEE the fee cap per gas + the priority tip; WORST CASE the max
cost in the chain's gas token (fee cap x gas limit: 45.5 gwei x 150000
= 0.0068 ETH) + the gas limit; CALL DATA the 4-byte selector + the
calldata size (swapExactTokensForTokens with a two-token path is 260
bytes); DETAILS the account nonce.
The chain screen follows the hero, so the id stays NETWORK: canonical id
CHAIN must directly follow TO or AMOUNT.
Render with `python -m flows blind/unknown_call --end all` and
`python -m flows blind/unknown_call --early --end all`.
"""
from flows.blind import defaults, ends

# the contract address — variable content, filled per transaction on device
CONTRACT = "0x4752ba5DBc23f44D87826276BF6Fd6b1C372aD24"
# the calldata hash — variable content; the screen shows 12 + 12 characters
DATA_HASH = "0x8c3e1f5a29d7b6c04e5f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f"

DEFAULTS = defaults(CONTRACT)   # the blind mark on the address-hashed solid disc

BODY = [
    dict(id="UNKNOWN CALL", kind="hero", bottom="CONFIRM UNKNOWN CALL?",
         chev="lr", hint=True),
    dict(id="NETWORK", kind="detail", side="right", chain=8453, label=None, chev="lr"),
    dict(id="FUNCTION", kind="detail", side="left", label="FUNCTION",
         lines=["Swap exact tokens", "for tokens"], size=28, chev="lr"),
    dict(id="TO", kind="detail", side="right", label="TO",
         lines=[CONTRACT[:21], CONTRACT[21:]], size=22, chev="lr"),
    dict(id="AMOUNT", kind="detail", side="left", label="AMOUNT",
         lines=["0 ETH"], size=36, chev="lr"),
    # Confirm? lands here — screen 6, placed by layout.insert_confirm
    dict(id="DATA HASH", kind="detail", side="right", label="DATA HASH",
         lines=[DATA_HASH[:12], "…" + DATA_HASH[-12:]], size=28, chev="lr"),
    dict(id="MAX FEE", kind="detail", side="left", label="MAX FEE",
         lines=["45.5 gwei", "Tip: 2 gwei"], size=28, chev="lr"),
    dict(id="WORST CASE", kind="detail", side="right", label="WORST CASE",
         lines=["Max: 0.0068 ETH", "Gas: 150000"], size=28, chev="lr"),
    dict(id="CALL DATA", kind="detail", side="left", label="CALL DATA",
         lines=["Selector: 0x38ed1739", "Data: 260B"], size=22, chev="lr"),
    dict(id="DETAILS", kind="detail", side="right", label="DETAILS",
         lines=["Nonce: 42"], size=36, chev="lr"),
]

ENDS = ends("UNKNOWN CALL")
DEFAULT_END = "confirmed"      # what --early commits to when no --end is given
# the full walkthrough: every detail, back on the idle ask, then the
# ending plays — loading resolving to success (or cancellation via --end)
SCREENS = BODY + [dict(BODY[0]), ENDS[DEFAULT_END]]

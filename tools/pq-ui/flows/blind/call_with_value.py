"""CALL WITH VALUE flow — a blind-signed contract call carrying ether,
screen content only (grid/type/motion come from pq1).

  CONFIRM UNKNOWN CALL? (idle sweep) -> NETWORK -> TO -> AMOUNT -> DATA HASH
  -> Confirm? (auto-inserted as screen 6, the early exit) -> MAX FEE
  -> WORST CASE -> CALL DATA -> DETAILS -> back on the idle hero (every
  detail seen, the ask again) -> status (CONFIRMED by default) — the full
  walkthrough.

The unknown_call flow without its FUNCTION screen: the device cannot
name the selector, so nothing stands between the chain and the address.
What sets this flow apart is the AMOUNT screen — the call CARRIES ETHER
(a payable call: a swap paying in from the account, a deposit), so the
value is the figure the signer must read, not "0 ETH". Eight detail
screens: the design system inserts the mid-flow Confirm? as screen 6
(DESIGN.md § Flow shape), right after the hash, and `--early` commits
there, skipping the fee screens and the calldata. The call is signed on
an ask only — the opening hero, Confirm?, or the returning hero — never
on a detail.

Endings (--end on the CLI, flows.blind.ends): CONFIRMED is the qubit film
resolving to a green check; DECLINED plays no film (the cancel resolve) —
the token resolves in place, red ring stroke and red X on the unfilled
black disc. Captions "UNKNOWN CALL CONFIRMED" / "UNKNOWN CALL DECLINED".

The token wears the family's blind mark (flows.blind) on the solid
placeholder disc hashed from the contract address — TO shows the address
and the token derives its colour from it, one constant.

EVERY value line is VARIABLE content — the flow fixes the screens, their
order, labels and sides, and the tier rule, never a value. The samples
describe one plausible call — a payable router multicall on Base:
TO the router address alone (the address treatment, two <= 21-char
halves at 22); AMOUNT the ether the call carries ("0.25 ETH" — an
amount + symbol pair at 36); DATA HASH the calldata hash shortened to its
first 12 and last 12 characters around a single "…" (the fingerprint
departure from DESIGN.md § Text rules "no ellipsis", as on
unknown_call); MAX FEE the fee cap per gas + the priority tip; WORST CASE
the max cost in the chain's gas token (fee cap x gas limit: 45.5 gwei x
180000 = 0.0082 ETH — the gas only; the value rides on AMOUNT) + the gas
limit; CALL DATA the 4-byte selector + the calldata size; DETAILS the
account nonce.
The chain screen follows the hero, so the id stays NETWORK: canonical id
CHAIN must directly follow TO or AMOUNT.
Render with `python -m flows blind/call_with_value --end all` and
`python -m flows blind/call_with_value --early --end all`.
"""
from flows.blind import defaults, ends

# the contract address — variable content, filled per transaction on device
CONTRACT = "0x2626664c2603336E57B271c5C0b26F421741e481"
# the calldata hash — variable content; the screen shows 12 + 12 characters
DATA_HASH = "0xd41c7b3e9a08f26c5e1b7f4a2d93c6e8b05a1f7c3d9e2b4a6c8f0e1d3b5a7c9e"

DEFAULTS = defaults(CONTRACT)   # the blind mark on the address-hashed solid disc

BODY = [
    dict(id="UNKNOWN CALL", kind="hero", bottom="CONFIRM UNKNOWN CALL?",
         chev="lr", hint=True),
    dict(id="NETWORK", kind="detail", side="right", chain=8453, label=None, chev="lr"),
    dict(id="TO", kind="detail", side="left", label="TO",
         lines=[CONTRACT[:21], CONTRACT[21:]], size=22, chev="lr"),
    dict(id="AMOUNT", kind="detail", side="right", label="AMOUNT",
         lines=["0.25 ETH"], size=36, chev="lr"),
    dict(id="DATA HASH", kind="detail", side="left", label="DATA HASH",
         lines=[DATA_HASH[:12], "…" + DATA_HASH[-12:]], size=28, chev="lr"),
    # Confirm? lands here — screen 6, placed by layout.insert_confirm
    dict(id="MAX FEE", kind="detail", side="right", label="MAX FEE",
         lines=["45.5 gwei", "Tip: 2 gwei"], size=28, chev="lr"),
    dict(id="WORST CASE", kind="detail", side="left", label="WORST CASE",
         lines=["Max: 0.0082 ETH", "Gas: 180000"], size=28, chev="lr"),
    dict(id="CALL DATA", kind="detail", side="right", label="CALL DATA",
         lines=["Selector: 0x5ae401dc", "Data: 452B"], size=22, chev="lr"),
    dict(id="DETAILS", kind="detail", side="left", label="DETAILS",
         lines=["Nonce: 42"], size=36, chev="lr"),
]

ENDS = ends("UNKNOWN CALL")
DEFAULT_END = "confirmed"      # what --early commits to when no --end is given
# the full walkthrough: every detail, back on the idle ask, then the
# ending plays — loading resolving to success (or cancellation via --end)
SCREENS = BODY + [dict(BODY[0]), ENDS[DEFAULT_END]]

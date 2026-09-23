"""BARE CALL flow — the plainest blind-signed contract call, screen
content only (grid/type/motion come from pq1).

  CONFIRM UNKNOWN CALL? (idle sweep) -> NETWORK -> TO -> AMOUNT -> DATA HASH
  -> Confirm? (auto-inserted as screen 6, the early exit) -> MAX FEE
  -> WORST CASE -> CALL DATA -> DETAILS -> back on the idle hero (every
  detail seen, the ask again) -> status (CONFIRMED by default) — the full
  walkthrough.

The unknown_call flow without its FUNCTION screen and without a value:
the device has nothing but the raw calldata — no selector it can name,
no ether carried ("0 ETH") — so the signer reads the address, the hash
and the calldata figures and nothing else. Eight detail screens: the
design system inserts the mid-flow Confirm? as screen 6 (DESIGN.md
§ Flow shape), right after the hash, and `--early` commits there,
skipping the fee screens and the calldata. The call is signed on an ask
only — the opening hero, Confirm?, or the returning hero — never on a
detail. call_with_value is this flow's twin for a call that carries
ether.

Endings (--end on the CLI, flows.blind.ends): CONFIRMED is the qubit film
resolving to a green check; DECLINED plays no film (the cancel resolve) —
the token resolves in place, red ring stroke and red X on the unfilled
black disc. Captions "UNKNOWN CALL CONFIRMED" / "UNKNOWN CALL DECLINED".

The token wears the family's blind mark (flows.blind) on the solid
placeholder disc hashed from the contract address — TO shows the address
and the token derives its colour from it, one constant.

EVERY value line is VARIABLE content — the flow fixes the screens, their
order, labels and sides, and the tier rule, never a value. The samples:
TO the contract address alone (the address treatment, two <= 21-char
halves at 22); AMOUNT "0 ETH"; DATA HASH the calldata hash shortened to
its first 12 and last 12 characters around a single "…" (the fingerprint
departure from DESIGN.md § Text rules "no ellipsis", as on
unknown_call); MAX FEE the fee cap per gas + the priority tip; WORST CASE
the max cost in the chain's gas token (fee cap x gas limit: 45.5 gwei x
120000 = 0.0055 ETH) + the gas limit; CALL DATA the 4-byte selector the
device could not name + the calldata size (a selector and three words:
100 bytes); DETAILS the account nonce.
The chain screen follows the hero, so the id stays NETWORK: canonical id
CHAIN must directly follow TO or AMOUNT.
Render with `python -m flows blind/bare_call --end all` and
`python -m flows blind/bare_call --early --end all`.
"""
from flows.blind import defaults, ends

# the contract address — variable content, filled per transaction on device
CONTRACT = "0x9E3b5c0f7A1d24e86C3F0b7d5a2E4c6F8b1D3a7c"
# the calldata hash — variable content; the screen shows 12 + 12 characters
DATA_HASH = "0x6a2f9c1e8b4d07f3a5c2e9d1b8f4a6c3e0d7b2f9a1c5e8d3b6f0a4c7e2d9b1f5"

DEFAULTS = defaults(CONTRACT)   # the blind mark on the address-hashed solid disc

BODY = [
    dict(id="UNKNOWN CALL", kind="hero", bottom="CONFIRM UNKNOWN CALL?",
         chev="lr", hint=True),
    dict(id="NETWORK", kind="detail", side="right", chain=8453, label=None, chev="lr"),
    dict(id="TO", kind="detail", side="left", label="TO",
         lines=[CONTRACT[:21], CONTRACT[21:]], size=22, chev="lr"),
    dict(id="AMOUNT", kind="detail", side="right", label="AMOUNT",
         lines=["0 ETH"], size=36, chev="lr"),
    dict(id="DATA HASH", kind="detail", side="left", label="DATA HASH",
         lines=[DATA_HASH[:12], "…" + DATA_HASH[-12:]], size=28, chev="lr"),
    # Confirm? lands here — screen 6, placed by layout.insert_confirm
    dict(id="MAX FEE", kind="detail", side="right", label="MAX FEE",
         lines=["45.5 gwei", "Tip: 2 gwei"], size=28, chev="lr"),
    dict(id="WORST CASE", kind="detail", side="left", label="WORST CASE",
         lines=["Max: 0.0055 ETH", "Gas: 120000"], size=28, chev="lr"),
    dict(id="CALL DATA", kind="detail", side="right", label="CALL DATA",
         lines=["Selector: 0x9b7f6d1c", "Data: 100B"], size=22, chev="lr"),
    dict(id="DETAILS", kind="detail", side="left", label="DETAILS",
         lines=["Nonce: 42"], size=36, chev="lr"),
]

ENDS = ends("UNKNOWN CALL")
DEFAULT_END = "confirmed"      # what --early commits to when no --end is given
# the full walkthrough: every detail, back on the idle ask, then the
# ending plays — loading resolving to success (or cancellation via --end)
SCREENS = BODY + [dict(BODY[0]), ENDS[DEFAULT_END]]

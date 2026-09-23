"""SIGN WITH ARGS flow — a blind-signed call whose decoded ARGUMENTS the
device can show one by one, screen content only (grid/type/motion come
from pq1).

  CONFIRM BLIND SIGN? (idle sweep) -> NETWORK -> TO -> MAX FEE -> WORST CASE
  -> Confirm? (auto-inserted as screen 6, the early exit) -> DETAILS
  -> ARG 0 -> ARG 1 -> ARG 2 -> ARG 3 -> ARG 4 -> ARG 5 -> back on the
  idle hero (every detail seen, the ask again) -> status (CONFIRMED by
  default) — the full walkthrough.

The device cannot name the function, but it can split the calldata into
its ABI arguments: after the address and the fee screens, one screen per
argument, labelled ARG <n> counting from 0 (the ABI's own index). Eleven
detail screens: the design system inserts the mid-flow Confirm? as
screen 6 (DESIGN.md § Flow shape), right after WORST CASE, and `--early`
commits there, skipping the transaction detail and every argument. The
call is signed on an ask only — the opening hero, Confirm?, or the
returning hero — never on a detail.

Endings (--end on the CLI, flows.blind.ends): CONFIRMED is the qubit film
resolving to a green check; DECLINED plays no film (the cancel resolve) —
the token resolves in place, red ring stroke and red X on the unfilled
black disc. Captions "BLIND SIGN CONFIRMED" / "BLIND SIGN DECLINED".

The token wears the family's blind mark (flows.blind) on the solid
placeholder disc hashed from the contract address — TO shows the address
and the token derives its colour from it, one constant.

EVERY value line is VARIABLE content — the flow fixes the screens, their
order, labels and sides, and the tier rule, never a value. The samples:
TO the contract address alone (the address treatment, two <= 21-char
halves at 22); MAX FEE the fee cap per gas + the priority tip; WORST CASE
the max cost in the chain's gas token (fee cap x gas limit: 45.5 gwei x
200000 = 0.0091 ETH) + the gas limit; DETAILS the account nonce + the
calldata size (six words of head, a 21-byte bytes tail, a 16-byte string
tail and a three-item array tail: 452 bytes). The arguments show one
presentation each — the value as the device decodes it, the tier fit on
its longest line: ARG 0 a raw hash read in full (42 hex characters,
two 21-char lines at 22 — a 32-byte value would take the `pages`
treatment, DESIGN.md § Text rules, Pages); ARG 1 a typed integer, the
type on line 1 and the full number on line 2 ("uint256:" /
"1000000000000000000", 19 characters, 22); ARG 2 a boolean on one line
("Boolean = true", 14 characters, 32); ARG 3 a bytes32 SHORTENED around a
single "…" (a real Aileron glyph) under its type — the fingerprint form,
as dictated ("bytes32:" / "0xaabbceff…8aabbccdd", 22); ARG 4 a string as
sent ("Hello, ethereum!", 16 characters, 28); ARG 5 an array summarised
on three lines — the type, the item count, the first item ("uint256[]" /
"[3 items]" / "first: 42", three lines so 22).
The chain screen follows the hero, so the id stays NETWORK: canonical id
CHAIN must directly follow TO or AMOUNT.
Render with `python -m flows blind/typed_call/sign_with_args --end all` and
`python -m flows blind/typed_call/sign_with_args --early --end all`.
"""
from flows.blind import defaults, ends

# the contract address — variable content, filled per transaction on device
CONTRACT = "0xB7c4E1f92a6D3058Fe7b21C9a4d0E6f83B5c9A17"
# ARG 0 — a raw hash argument, read in full (42 hex characters here)
HASH_ARG = "34d32ee39f15ba31f012b34814a0934d32ee39f15b"
assert len(HASH_ARG) == 42

DEFAULTS = defaults(CONTRACT)   # the blind mark on the address-hashed solid disc

BODY = [
    dict(id="BLIND SIGN", kind="hero", bottom="CONFIRM BLIND SIGN?",
         chev="lr", hint=True),
    dict(id="NETWORK", kind="detail", side="right", chain=8453, label=None, chev="lr"),
    dict(id="TO", kind="detail", side="left", label="TO",
         lines=[CONTRACT[:21], CONTRACT[21:]], size=22, chev="lr"),
    dict(id="MAX FEE", kind="detail", side="right", label="MAX FEE",
         lines=["45.5 gwei", "Tip: 2 gwei"], size=28, chev="lr"),
    dict(id="WORST CASE", kind="detail", side="left", label="WORST CASE",
         lines=["Max: 0.0091 ETH", "Gas: 200000"], size=28, chev="lr"),
    # Confirm? lands here — screen 6, placed by layout.insert_confirm
    dict(id="DETAILS", kind="detail", side="right", label="DETAILS",
         lines=["Nonce: 42", "Data: 452B"], size=28, chev="lr"),
    # the decoded arguments, ABI index order from 0
    dict(id="ARG 0", kind="detail", side="left", label="ARG 0",
         lines=[HASH_ARG[:21], HASH_ARG[21:]], size=22, chev="lr"),
    dict(id="ARG 1", kind="detail", side="right", label="ARG 1",
         lines=["uint256:", "1000000000000000000"], size=22, chev="lr"),
    dict(id="ARG 2", kind="detail", side="left", label="ARG 2",
         lines=["Boolean = true"], size=32, chev="lr"),
    dict(id="ARG 3", kind="detail", side="right", label="ARG 3",
         lines=["bytes32:", "0xaabbceff…8aabbccdd"], size=22, chev="lr"),
    dict(id="ARG 4", kind="detail", side="left", label="ARG 4",
         lines=["Hello, ethereum!"], size=28, chev="lr"),
    dict(id="ARG 5", kind="detail", side="right", label="ARG 5",
         lines=["uint256[]", "[3 items]", "first: 42"], size=22, chev="lr"),
]

ENDS = ends("BLIND SIGN")
DEFAULT_END = "confirmed"      # what --early commits to when no --end is given
# the full walkthrough: every detail, back on the idle ask, then the
# ending plays — loading resolving to success (or cancellation via --end)
SCREENS = BODY + [dict(BODY[0]), ENDS[DEFAULT_END]]

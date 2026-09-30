"""SAFE sign flow, decoded call data — clear signing, screen content only.

  SEND 25,000 USDC? (idle sweep) -> NETWORK -> SAFE ACCT -> TO -> SEND
  -> Confirm? (auto-inserted 6th — this flow has 7 detail screens,
  DESIGN.md § Flow shape: hold-right commits from there, the band
  alternates OR VIEW MORE / TO GO BACK) -> TX INFO -> CALL DATA
  -> TX HASH (two pages) -> back on the idle hero (every detail seen)
  -> loading -> SIGNED (success) — the full walkthrough. `--end
  declined` swaps the cancellation ending; `--early [--end …]` renders
  the commit path: Confirm? jumps straight to the ending, the rest
  never visited.

The device CAN decode this call data — the clear-signing counterpart of
safe/can_not_decode: the decoded send (25,000 USDC on Mainnet, from the
Safe account, to the recipient) is shown in full, so there is no BLIND
SIGN warning and nothing pulses. Labels and value lines are variable
content — the device fills them per transaction; these are
representative samples. The chain screen follows the hero, so the id
is NETWORK: canonical id CHAIN must directly follow TO or AMOUNT.

TX HASH is the safeTxHash, the EIP-712 digest the owner signs and a
co-signer matches against the Safe UI — read IN FULL. Its 66 characters
overflow the three 22 px lines one screen holds, and a hash is ONE
value, so the screen turns PAGES rather than splitting into two screens
or shortening (DESIGN.md § Text rules, Pages): two pages of two
byte-aligned lines at 22 (page 1 "0x" + 8 bytes / 8 bytes, page 2
8 bytes / 8 bytes), the pager "1/2" / "2/2" top centre signalling the
second page. On the bench (pq1.driver) a right tap turns the page
before it advances, a left tap turns it back.
Render with `python -m flows safe/clear_sign --end all` (and
`--early --end all` for the commit paths).
"""
from flows.safe import DEFAULTS, ends  # noqa: F401  (DEFAULTS read by flows.screens)

# the Safe transaction hash — variable content, the EIP-712 digest the
# owner signs; shown IN FULL over two pages, never shortened
HASH = "0xb79b7df60161f21a70ba06cad4839a1845ee2d6787c5272e8a09960f18dd3120"
assert len(HASH) == 66

BODY = [
    dict(id="SEND", kind="hero", bottom="SEND 25,000 USDC?", hint=True),
    dict(id="NETWORK", kind="detail", side="right", chain=1, label=None),
    dict(id="SAFE ACCT", kind="detail", side="left", label="SAFE ACCT",
         lines=["0x1111111111222222222", "3333333333444444444aa"], size=22),
    dict(id="TO", kind="detail", side="right", label="TO",
         lines=["0x123456789abcdef1234", "56789abcdef123456789"], size=22),
    dict(id="AMOUNT", kind="detail", side="left", label="SEND",
         lines=["25,000 USDC"], size=36),
    dict(id="TX INFO", kind="detail", side="right", label="TX INFO",
         lines=["Nonce: 8", "Standard call"], size=28),
    dict(id="CALL DATA", kind="detail", side="left", label="CALL DATA",
         lines=["Function: 0x12345678", "Data: 64 B"], size=22),
    dict(id="TX HASH", kind="detail", side="right", label="TX HASH",
         pages=[[HASH[:18], HASH[18:34]],        # "0x" + 8 bytes / 8 bytes
                [HASH[34:50], HASH[50:66]]],     # 8 bytes / 8 bytes
         size=22),
]

ENDS = ends()
ENDS["signed"]["bottom"] = "SIGNED SAFE TRANSACTION"   # spelled out for this flow
DEFAULT_END = "signed"      # what --early commits to when no --end is given
# the full walkthrough: every detail, back on the idle ask, then the
# ending plays — loading resolving to success (or cancellation via --end)
SCREENS = BODY + [dict(BODY[0]), ENDS[DEFAULT_END]]

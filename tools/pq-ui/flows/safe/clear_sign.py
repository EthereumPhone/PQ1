"""SAFE sign flow, decoded call data — clear signing, screen content only.

  SEND 25,000 USDC? (idle sweep) -> SEND -> CHAIN -> SAFE ACCT -> TO
  -> Confirm? (auto-inserted 6th — this flow has 7 detail screens,
  DESIGN.md § Flow shape: hold-right commits from there, the band
  alternates OR VIEW MORE / TO GO BACK) -> TX INFO -> CALL DATA
  -> TX HASH -> back on the idle hero (every detail seen) -> loading ->
  SIGNED (success) — the full walkthrough. `--end declined` swaps the
  cancellation ending; `--early [--end …]` renders the commit path:
  Confirm? jumps straight to the ending, the rest never visited.

The device CAN decode this call data — the clear-signing counterpart of
safe/can_not_decode: the decoded send (25,000 USDC on Mainnet, from the
Safe account, to the recipient) is shown in full, so there is no BLIND
SIGN warning and nothing pulses. Labels and value lines are variable
content — the device fills them per transaction; these are
representative samples.
Render with `python -m flows safe/clear_sign --end all` (and
`--early --end all` for the commit paths).
"""
from flows.safe import DEFAULTS, ends  # noqa: F401  (DEFAULTS read by flows.screens)

BODY = [
    dict(id="SEND", kind="hero", bottom="SEND 25,000 USDC?", hint=True),
    dict(id="AMOUNT", kind="detail", side="left", label="SEND",
         lines=["25,000 USDC"], size=36),
    dict(id="CHAIN", kind="detail", side="right", chain=1, label=None),
    dict(id="SAFE ACCT", kind="detail", side="left", label="SAFE ACCT",
         lines=["0x1111111111222222222", "3333333333444444444aa"], size=22),
    dict(id="TO", kind="detail", side="right", label="TO",
         lines=["0x123456789abcdef1234", "56789abcdef123456789"], size=22),
    dict(id="TX INFO", kind="detail", side="left", label="TX INFO",
         lines=["Nonce: 8", "Standard call"], size=28),
    dict(id="CALL DATA", kind="detail", side="right", label="CALL DATA",
         lines=["Function: 0x12345678", "Data: 64 B"], size=22),
    dict(id="TX HASH", kind="detail", side="left", label="TX HASH",
         lines=["0x9f86d081884c7d", "...6c15b0f00a08"], size=22),
]

ENDS = ends()
ENDS["signed"]["bottom"] = "SIGNED SAFE TRANSACTION"   # spelled out for this flow
DEFAULT_END = "signed"      # what --early commits to when no --end is given
# the full walkthrough: every detail, back on the idle ask, then the
# ending plays — loading resolving to success (or cancellation via --end)
SCREENS = BODY + [dict(BODY[0]), ENDS[DEFAULT_END]]

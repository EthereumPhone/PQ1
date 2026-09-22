"""SAFE ERC-20 transfer flow — token send from the Safe, screen content only.

  SEND 250 USDC? (idle sweep) -> NETWORK -> SAFE ACCT -> SEND -> TO
  -> Confirm? (auto-inserted 6th — this flow has 7 detail screens,
  DESIGN.md § Flow shape: hold-right commits from there, the band
  alternates OR VIEW MORE / TO GO BACK) -> TOKEN -> CONTRACT -> TX INFO
  -> back on the idle hero (every detail seen, the ask again) -> loading
  -> SIGNED (success) — the full walkthrough. `--end declined` swaps the
  cancellation ending; `--early [--end …]` renders the commit path:
  Confirm? jumps straight to the ending, the rest never visited.

Transfers an ERC-20 token out of the Safe: the chain context, the Safe
account, the amount at full decimal precision, the recipient, the token's
full name, its contract address and the transaction nonce. Every label
and value line is variable content — "250 USDC" / "USD Coin" and the
addresses are representative samples filled per transaction on device.
The chain screen follows the hero, so the id stays NETWORK: canonical id
CHAIN must directly follow TO or AMOUNT.
Render with `python -m flows safe/erc20_transfer --end all`.
"""
from flows.safe import DEFAULTS, ends  # noqa: F401  (DEFAULTS read by flows.screens)

BODY = [
    dict(id="TRANSFER", kind="hero", bottom="SEND 250 USDC?", hint=True),
    dict(id="NETWORK", kind="detail", side="right", icon="mainnet", label=None,
         lines=["on Mainnet"], size=32, text_x=175, circle_x=291),
    dict(id="SAFE ACCT", kind="detail", side="left", label="SAFE ACCT",
         lines=["0x1111111111222222222", "3333333333444444444aa"], size=22),
    dict(id="SEND", kind="detail", side="right", label="SEND",
         lines=["250.000000 USDC"], size=28),
    dict(id="TO", kind="detail", side="left", label="TO",
         lines=["0x78D8526282Ac09f1885", "D0F39B8875a0180Fc081e"], size=22),
    dict(id="TOKEN", kind="detail", side="right", label="TOKEN",
         lines=["USD Coin"], size=36),
    dict(id="CONTRACT", kind="detail", side="left", label="CONTRACT",
         lines=["0xA0b86991c6218b36c1d", "19D4a2e9Eb0cE3606eB48"], size=22),
    dict(id="TX INFO", kind="detail", side="right", label="TX INFO",
         lines=["Nonce: 5"], size=36),
]

ENDS = ends()
DEFAULT_END = "signed"      # what --early commits to when no --end is given
# the full walkthrough: every detail, back on the idle ask, then the
# ending plays — loading resolving to success (or cancellation via --end)
SCREENS = BODY + [dict(BODY[0]), ENDS[DEFAULT_END]]

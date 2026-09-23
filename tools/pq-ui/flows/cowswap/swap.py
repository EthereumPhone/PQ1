"""CoW Swap order sign flow — screen content only.

  SIGN COWSWAP? (idle sweep) -> NETWORK -> SELL -> BUY -> TO -> Confirm?
  (auto-inserted 6th — this flow has 7 detail screens, DESIGN.md § Flow
  shape: hold-right commits from there, the band alternates OR VIEW MORE
  / TO GO BACK) -> EXPIRES -> FEE -> DETAILS -> back on the idle hero
  (every detail seen, the ask again) -> loading -> COWSWAP SIGNED
  (success) — the full walkthrough. `--end declined` swaps the
  cancellation ending; `--early [--end …]` renders the commit path:
  Confirm? jumps straight to the ending, the rest never visited. Ending
  renders land in success/ and cancel/ folders (see flows/__main__).

Signs a CoW Swap order: the chain context, what is sold, the minimum
received (the buy amount is a floor — the solver may do better), the
receiver, the order's validity window, the fee note and the fill-or-kill
terms. The big detail text is VARIABLE — filled per transaction on the
device; the numbers and symbols below are placeholder samples chosen to
exercise the tier rule, never fixed content. SELL / BUY carry an amount
+ symbol pair: one line while
the pair fits a one-line tier ("0.5 WETH", 36); when it grows past the
32 budget it breaks once, after the number — the amount on line 1, the
symbol on line 2 ("min. 1,842.31" / "USDC", 28) — never inside the
number (DESIGN.md § Text rules). The chain screen is id NETWORK: the
canonical id CHAIN must directly follow TO or AMOUNT, and here the chain
opens the walkthrough.
Render with `python -m flows cowswap/swap --end all`.
"""
from flows.cowswap import DEFAULTS, ends  # noqa: F401  (DEFAULTS read by flows.screens)

BODY = [
    dict(id="SIGN", kind="hero", bottom="SIGN COWSWAP?", hint=True),
    dict(id="NETWORK", kind="detail", side="right", chain=1, label=None),
    dict(id="SELL", kind="detail", side="left", label="SELL",
         lines=["0.5 WETH"], size=36),
    dict(id="BUY", kind="detail", side="right", label="BUY",
         lines=["min. 1,842.31", "USDC"], size=28),
    dict(id="TO", kind="detail", side="left", label="TO",
         lines=["0x78D8526282Ac09f1885", "D0F39B8875a0180Fc081e"], size=22),
    dict(id="EXPIRES", kind="detail", side="right", label="EXPIRES",
         lines=["Tx expires in", "~20 min"], size=28),
    dict(id="FEE", kind="detail", side="left", label="FEE",
         lines=["No extra fee"], size=36),
    dict(id="DETAILS", kind="detail", side="right", label="DETAILS",
         lines=["Fills in one go.", "If not, the", "trade's cancelled."], size=22),
]

ENDS = ends()
DEFAULT_END = "signed"      # what --early commits to when no --end is given
# the full walkthrough: every detail, back on the idle ask, then the
# ending plays — loading resolving to success (or cancellation via --end)
SCREENS = BODY + [dict(BODY[0]), ENDS[DEFAULT_END]]

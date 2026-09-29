"""CoW Swap order sign flow, address mode — screen content only.

  SIGN COWSWAP? (idle sweep) -> NETWORK -> SELL -> BUY -> TO -> Confirm?
  (auto-inserted 6th — 7 detail screens, DESIGN.md § Flow shape)
  -> EXPIRES -> FEE -> DETAILS -> back on the idle hero (every detail
  seen, the ask again) -> loading -> COWSWAP SIGNED (success) — the
  full walkthrough. `--end declined` swaps the cancellation ending;
  `--early [--end …]` renders the commit path. Ending renders land in
  success/ and cancel/ folders (see flows/__main__).

The swap flow (flows/cowswap/swap.py) for tokens the device cannot
resolve to a symbol: SELL and BUY show the token's CONTRACT ADDRESS —
the address alone, the full value split mid-string into two ≤ 21-char
centred lines at 22 (the address treatment, DESIGN.md § Text rules),
never an ellipsis, so the contract is verifiable on screen. No amount
rides with it: the big detail text is variable per transaction and a
flow fixes only the screen's structure, not a number. Everything else
is the swap flow's content — representative samples of variable
content. The chain screen is id NETWORK: the
canonical id CHAIN must directly follow TO or AMOUNT, and here the chain
opens the walkthrough.
Render with `python -m flows cowswap/address_mode --end all`.
"""
from flows.cowswap import DEFAULTS, ends  # noqa: F401  (DEFAULTS read by flows.screens)

BODY = [
    dict(id="SIGN", kind="hero", bottom="SIGN COWSWAP?", hint=True),
    dict(id="NETWORK", kind="detail", side="right", chain=1, label=None),
    dict(id="SELL", kind="detail", side="left", label="SELL",
         lines=["0xC02aaA39b223FE8D0A0", "e5C4F27eAD9083C756Cc2"], size=22),
    dict(id="BUY", kind="detail", side="right", label="BUY",
         lines=["0xA0b86991c6218b36c1d", "19D4a2e9Eb0cE3606eB48"], size=22),
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

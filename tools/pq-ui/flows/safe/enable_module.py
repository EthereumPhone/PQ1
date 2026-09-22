"""SAFE enable-module flow — module management on the Safe, screen content only.

  APPROVE ENABLE MODULE? (idle sweep) -> NETWORK -> SAFE ACCT -> ENABLE
  -> MODULE -> TX INFO -> back on the idle hero (every detail seen, the
  ask again — 5 detail screens, so no mid-flow Confirm? and no --early
  variants, DESIGN.md § Flow shape: accept/cancel never exists while
  viewing details) -> loading -> SIGNED "ENABLE MODULE APPROVED"
  (success) — the full walkthrough. `--end declined` swaps the
  "ENABLE MODULE DECLINED" cancellation ending.

Enables a module on the Safe: the chain context, the Safe account, what
enabling means (execution authority granted to the module address), the
module address itself and the transaction nonce. The chain screen is
variable content like every label and value line — "on Mainnet" +
icon="mainnet" is a representative sample. The id stays NETWORK:
canonical id CHAIN must directly follow TO or AMOUNT, and this flow has
neither.
Render with `python -m flows safe/enable_module --end all`.
"""
from flows.safe import DEFAULTS, ends  # noqa: F401  (DEFAULTS read by flows.screens)

BODY = [
    dict(id="ENABLE MODULE", kind="hero", bottom="APPROVE ENABLE MODULE?", hint=True),
    dict(id="NETWORK", kind="detail", side="right", icon="mainnet", label=None,
         lines=["on Mainnet"], size=32, text_x=175, circle_x=291),
    dict(id="SAFE ACCT", kind="detail", side="left", label="SAFE ACCT",
         lines=["0x1111111111222222222", "3333333333444444444aa"], size=22),
    dict(id="ENABLE", kind="detail", side="right", label="ENABLE",
         lines=["Grants exec auth", "to module address"], size=22),
    dict(id="MODULE", kind="detail", side="left", label="MODULE",
         lines=["0x9999999999999999999", "999999999999999999999"], size=22),
    dict(id="TX INFO", kind="detail", side="right", label="TX INFO",
         lines=["Nonce: 7"], size=36),
]

ENDS = ends()
ENDS["signed"]["bottom"] = "ENABLE MODULE APPROVED"
ENDS["declined"]["bottom"] = "ENABLE MODULE DECLINED"
DEFAULT_END = "signed"      # what the walkthrough resolves to when no --end is given
# the full walkthrough: every detail, back on the idle ask, then the
# ending plays — loading resolving to success (or cancellation via --end)
SCREENS = BODY + [dict(BODY[0]), ENDS[DEFAULT_END]]

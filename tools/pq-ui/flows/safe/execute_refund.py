"""SAFE execute-with-refund flow — a transfer executed from the Safe, the
Safe refunding the executor's gas, screen content only.

  EXECUTE SAFE TX? (idle sweep) -> NETWORK -> SAFE ACCT -> SEND -> TO
  -> GAS -> CONTRACT -> back on the idle hero (every detail seen, the
  ask again — 6 detail screens, so no mid-flow Confirm? and no --early
  variants, DESIGN.md § Flow shape: accept/cancel never exists while
  viewing details) -> loading -> SIGNED "SAFE TX EXECUTED" (success) —
  the full walkthrough. `--end declined` swaps the
  "SAFE TX EXECUTION DECLINED" cancellation ending.

Executes a transfer out of the Safe with a gas refund: the chain
context, the Safe account, the amount, the recipient, who pays for
execution (the Safe pays it) and the contract the call
goes through. Every label and value line is variable content — "0.1
ETH" and the addresses are representative samples filled per
transaction on device. The chain screen follows the hero, so the id
stays NETWORK: canonical id CHAIN must directly follow TO or AMOUNT.
Render with `python -m flows safe/execute_refund --end all`.
"""
from flows.safe import DEFAULTS, ends  # noqa: F401  (DEFAULTS read by flows.screens)

BODY = [
    dict(id="EXECUTE", kind="hero", bottom="EXECUTE SAFE TX?", hint=True),
    dict(id="NETWORK", kind="detail", side="right", chain=1, label=None),
    dict(id="SAFE ACCT", kind="detail", side="left", label="SAFE ACCT",
         lines=["0x1111111111222222222", "3333333333444444444aa"], size=22),
    dict(id="SEND", kind="detail", side="right", label="SEND",
         lines=["0.1 ETH"], size=36),
    dict(id="TO", kind="detail", side="left", label="TO",
         lines=["0x78D8526282Ac09f1885", "D0F39B8875a0180Fc081e"], size=22),
    dict(id="GAS", kind="detail", side="right", label="GAS",
         lines=["Safe pays", "the execution"], size=28),
    dict(id="CONTRACT", kind="detail", side="left", label="CONTRACT",
         lines=["0x41675C099F32341bf84", "BFc5382aF534df5C7461a"], size=22),
]

ENDS = ends()
ENDS["signed"]["bottom"] = "SAFE TX EXECUTED"
ENDS["declined"]["bottom"] = "SAFE TX EXECUTION DECLINED"
DEFAULT_END = "signed"      # what the walkthrough resolves to when no --end is given
# the full walkthrough: every detail, back on the idle ask, then the
# ending plays — loading resolving to success (or cancellation via --end)
SCREENS = BODY + [dict(BODY[0]), ENDS[DEFAULT_END]]

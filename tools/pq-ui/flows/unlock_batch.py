"""Worked example: composing a flow from the screens/ library.

PIN entry -> batch-sign idle -> padlock verdict, every screen spliced via
screens.spec() (kind="status" + a registered animation); Sim dwells each
for its animation's duration, fades the PIN row out and the idle token in
between them (the row owns its canvas — no token to morph), and morphs
the idle token into the padlock's black hold.
"""
import screens  # registers the library's anims into pq1.status.ANIMS

SCREENS = [
    screens.spec("pin_entering", pin="24031958"),
    screens.spec("batch_sign", tx=1, total=5),
    screens.spec("padlock", preset="unlock"),      # green, "UNLOCKED"
]

ENDS = {"locked": screens.spec("padlock", preset="lock")}

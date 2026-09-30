"""Duress PIN differ — the pin-category name for the duress_differ film.

The same animation as screens/verdict/duress_differ.py, frame for frame
(user, 2026-09-26: the two told one rule with two different pill
animations). It used to run its own timeline — a flat pill fade, a
separate dot fill, a 1.5-cycle sweep and no verdict beat — which made
the same refusal look like two different events. Now it IS the verdict
twin under its pin-category name: black hold, pill and dots arriving
together on the entrance law, the scanline across and back, the shake,
the beat, the caption. Retune the pace in duress_differ only.

    python3 -m screens pin_differ
"""
from pq1 import status
from screens.verdict.duress_differ import SPEC as _SPEC, DuressDiffer

ANIM = "pin_differ"
SPEC = dict(_SPEC)


class PinDiffer(DuressDiffer):
    """duress_differ, registered under the pin-category name"""


status.register(ANIM, PinDiffer)

"""PQ1 design system — screen-agnostic layout, color, type, motion and
components for the NV3007 wallet UI.

One module per design aspect:

    layout      the 428x142 grid, layout_of(), the screen-dict schema
    colors      solid palette + semantic states; placeholder ramps (the
                per-token unknown gradients + placeholder palettes)
    typography  Aileron loader + the PQ1 type scale
    motion      easing, timing constants, follower chain
    canvas      the 3x supersampled drawing surface
    components  token, glyphs/circle image, chevrons, caption, trails,
                pulse, pills/badges
    loading     the qubit status film (pose math + drawing)
    status      status-screen engine — one resting look, pluggable
                animations ("qubit" for done endings, the film-less
                "resolve" for cancels + registered screens),
                per-screen fields
    verdict     VerdictAnim — icon-verdict screens (screens/verdict/ registers)
    flow        Sim — drives any list of screens with the PQ1 motion
    gradients   gradient/ramp import surface + ramp helpers
    procedural  generative icon art, one module per image (lazy package)
    render      standalone-screen frame loop + CLI harness

Screens are plain dicts (see pq1.layout docstring for the schema); every
current and future screen renders through these modules so the UI stays
consistent by construction.
"""
from . import (canvas, colors, components, flow, gradients,  # noqa: F401
               layout, loading, motion, procedural, render, status,
               typography, verdict)
from .canvas import Canvas  # noqa: F401
from .colors import (BLACK, GREEN, MONO_RAMP, NEUTRAL_RAMP,  # noqa: F401
                     ORANGE, PLACEHOLDER_GRADIENTS, PLACEHOLDER_PALETTES,
                     RED, STATE, WHITE, YELLOW, grad_color,
                     placeholder_palette)
from .flow import Sim, render_flow, save_gif  # noqa: F401
from .layout import H, SUP, W, layout_of, normalize_screens  # noqa: F401

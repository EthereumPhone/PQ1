"""PQ1 procedural imagery — generative icon art, one module per image.

Import submodules directly (`from pq1.procedural import padlock`); this
package namespace stays lazy on purpose so pq1.components can depend on
marks without dragging the whole art library (or pq1.loading, via burst)
into every import.

Modules
    geometry  rounded_polygon, quad_bezier, bezier, svg_subpaths — shared path math
    marks     check, x (cancel), exclamation — the result/notice marks;
              plus, minus — the entry signs beside the corner chevrons
    blind     the blind-signing mark (assets/blind_icon.svg traced)
    dev       the ERC-7730 intro mark (assets/dev_icon.svg traced)
    rotate    the slot-rotation mark (assets/rotate_icon.svg traced)
    download  the firmware-update mark (assets/download_icon.svg traced)
    shield    encrypted-backup shield outline
    warning_triangle  rounded warning triangle
    brush     wipe brush (rigged: swivel/bend)
    padlock   padlock (rigged: spin/lift/recoil)
    gear      8-tooth factory gear
    heart     bezier heart
    die3d     3-axis rotating die (rigged: rot; sweep = the tumble's shutter blur)
    digit_reel  masked slot-machine digit reel
    pin_slots   8-slot PIN entry ring row
    pin_pill    4-dot PIN pill + its check scanline (the pin errors)
    burst     explosion choreography (on pq1.loading; import from screens/)

API convention: draw(cv, cx, cy, *, <size>, color, alpha=1.0, **pose) in UI
pixels; static images also provide glyph(**frozen_pose) returning the
components glyph signature fn(cv, cx, cy, r, alpha=1.0, color=None, rot=0.0).
"""

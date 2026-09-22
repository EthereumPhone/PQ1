"""PQ1 color system.

Solid colors are the primary language: tokens are solid fills with a white
ring, and the semantic state colors below carry meaning across every screen.

A gradient disc is NOT a general decoration — it is the treatment for a
token the device does not recognize (an unknown token). The disc's hue is
one of the placeholder ramps below, chosen deterministically from the
token's identity (components.token_ramp), so the same unknown token always
wears the same gradient. Do not confuse it with blind signing; it only
says "this asset is not known".

Ramp material (placeholder ramps, sampling helpers) is defined here and
surfaced for screen code through pq1.gradients.
"""
import zlib

from .motion import clamp01, lerp

BLACK = (0, 0, 0)
WHITE = (255, 255, 255)
YELLOW = (220, 196, 25)     # awaiting input
GREEN = (46, 229, 106)      # done / success
RED = (255, 66, 61)         # failed / canceled  (#FF423D)
ORANGE = (245, 160, 51)     # warning

# semantic aliases — prefer these in screen code so intent stays readable
STATE = {"awaiting": YELLOW, "done": GREEN, "failed": RED, "warning": ORANGE}

# factory screens only — provisioning/manufacturing UI. Never a state colour,
# never on user-facing wallet screens (DESIGN.md § Color).
FACTORY_BLUE = (74, 159, 240)

def grad_color(u, stops):
    """sample a stop list [(pos, (r, g, b)), ...] at u in [0, 1]"""
    u = clamp01(u)
    for i in range(len(stops) - 1):
        p0, c0 = stops[i]
        p1, c1 = stops[i + 1]
        if u <= p1:
            k = 0 if p1 == p0 else (u - p0) / (p1 - p0)
            return tuple(int(round(lerp(c0[j], c1[j], k))) for j in range(3))
    return stops[-1][1]


def scale(color, k):
    """color faded toward black — the flow's alpha idiom on the pure-black bg"""
    return tuple(int(round(c * k)) for c in color)


def luma(color):
    """relative brightness 0..1 (Rec. 709 weights) — is this body dark or light?"""
    r, g, b = color[:3]
    return (0.2126 * r + 0.7152 * g + 0.0722 * b) / 255


# ------------------------------------------- placeholder token palettes -----
# For a KNOWN token that has no image/logo: the token stays solid, and it and
# its five follower circles are coloured from one of these six-stop ramps.
#
# Reading each ramp top -> bottom, the LAST stop is the token circle itself,
# the 5th stop is the first follower (nearest the token), the 4th the second
# follower ... the 1st stop is the farthest follower:
#
#     stop 6 -> token fill        stop 3 -> trail[2]
#     stop 5 -> trail[0]          stop 2 -> trail[3]
#     stop 4 -> trail[1]          stop 1 -> trail[4]
#
# i.e. fill = ramp[-1], trail = ramp[-2::-1]. Use placeholder_palette().
PLACEHOLDER_GRADIENTS = [
    (
        "#413D2E",
        "#4B452E",
        "#655A26",
        "#867200",
        "#967900",
        "#AD9300",
    ),

    (
        "#641220",
        "#85182A",
        "#A71E34",
        "#B21E35",
        "#C71F37",
        "#E01E37",
    ),

    (
        "#051923",
        "#00304D",
        "#005680",
        "#006EAD",
        "#008BD3",
        "#009EDE",
    ),

    (
        "#38160D",
        "#4C261B",
        "#562F21",
        "#603728",
        "#6A3F2F",
        "#7E503C",
    ),

    (
        "#310055",
        "#3C0663",
        "#4A0A77",
        "#5A108F",
        "#6818A5",
        "#8B2FC9",
    ),

    (
        "#5C2E0C",
        "#753B11",
        "#8F4916",
        "#AA581B",
        "#C66720",
        "#E37626",
    ),

    (
        "#031911",
        "#062A1D",
        "#083324",
        "#0E4530",
        "#12563D",
        "#176849",
    ),

    (
        "#03312E",
        "#005656",
        "#007067",
        "#007E76",
        "#00918D",
        "#00A5A2",
    ),

    (
        "#640E30",
        "#78183C",
        "#8D2249",
        "#A22D56",
        "#B9375E",
        "#E05780",
    ),

    (
        "#7C050A",
        "#8D1917",
        "#9E2824",
        "#AF3630",
        "#C1443B",
        "#D35148",
    ),

    (
        "#26262C",
        "#2F3037",
        "#393A41",
        "#4B4C52",
        "#5B5C62",
        "#6A6B70",
    ),

    (
        "#11001C",
        "#220732",
        "#37174C",
        "#5C317E",
        "#6F4097",
        "#8C57BC",
    ),

    (
        "#07238B",
        "#1639A1",
        "#274EB8",
        "#3964D0",
        "#4B79E7",
        "#5E8EFF",
    ),

    # 13 — MONO: the recognized-logo treatment (black body, white ring, grey
    # trail — see the palette override below); as an unknown-token disc it
    # renders as this greyscale ramp
    (
        "#050505",
        "#2E2E2E",
        "#5C5C5C",
        "#8F8F8F",
        "#C4C4C4",
        "#F4F4F4",
    ),
]


def hex_to_rgb(h):
    """'#RRGGBB' -> (r, g, b)"""
    h = h.lstrip("#")
    return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))


def _ramp_to_palette(ramp):
    """six-stop ramp -> (token fill, five follower colours nearest-first)"""
    rgb = [hex_to_rgb(h) for h in ramp]
    return rgb[-1], rgb[-2::-1]


# (fill, trail) per ramp, same order as PLACEHOLDER_GRADIENTS
PLACEHOLDER_PALETTES = [_ramp_to_palette(g) for g in PLACEHOLDER_GRADIENTS]

# named ramp indices
MONO_RAMP = len(PLACEHOLDER_GRADIENTS) - 1   # 13 — recognized-logo treatment
NEUTRAL_RAMP = 10                            # grey — keyless-unknown fallback

# the mono entry fills BLACK (a token with a logo keeps the black body +
# white ring); its trail keeps the generic grey derivation
PLACEHOLDER_PALETTES[MONO_RAMP] = (BLACK, PLACEHOLDER_PALETTES[MONO_RAMP][1])

# each ramp as evenly spaced gradient stops for grad_color / the unknown disc
RAMP_STOPS = [tuple((i / (len(g) - 1), hex_to_rgb(h)) for i, h in enumerate(g))
              for g in PLACEHOLDER_GRADIENTS]


def placeholder_index(key):
    """stable ramp index for a key: an int wraps, a string (token symbol /
    name) hashes deterministically so the same token always gets the same
    palette across runs (Python's str hash is salted per process)"""
    if isinstance(key, int):
        return key % len(PLACEHOLDER_PALETTES)
    return zlib.crc32(str(key).upper().encode()) % len(PLACEHOLDER_PALETTES)


def placeholder_palette(key):
    """(fill, trail) for a token without an image; key = ramp index or symbol"""
    return PLACEHOLDER_PALETTES[placeholder_index(key)]


# -------------------------------------------------------------- brand ramps --
# Dedicated six-stop ramps for a specific signing context, keyed by name.
# Same stop layout as the placeholder ramps (fill = ramp[-1], trail =
# ramp[-2::-1]) but NOT placeholder material: placeholder_index only ever
# hashes into PLACEHOLDER_PALETTES, so no unknown token can wear a brand
# ramp. A brand ramp renders only when a flow pins it by name (token
# "palette": "SAFE") — the SAFE gradient shows exactly when a SAFE
# transaction is on screen.
SAFE_GRADIENT = (
    "#354E40",
    "#3F6852",
    "#3F9265",
    "#34C275",
    "#20DD77",
    "#13FF7F",   # the Safe token disc
)
# CoW Swap — the official blue primary palette (swap.cow.fi brand assets:
# the #65D9FF disc wearing the #012F7A cow head), darkening away from the
# token like every ramp
COWSWAP_GRADIENT = (
    "#021E34",
    "#012F7A",
    "#005EB7",
    "#00A1FF",
    "#3FC4FF",
    "#65D9FF",   # the CoW Swap token disc
)
COWSWAP_DARK = (1, 47, 122)   # #012F7A — the cow head: the family's mark
                              # colour (edge stroke, chain mark, check / X)
# Slot rotation — the device's own key-slot operation, not a token: the
# rotate mark white on a BLACK body (the palette override below, the
# MONO_RAMP idiom) over a gold trail darkening away. Stop 6 never paints
# the disc — it is the status film's body colour (token_style_from_spec
# "film"), kept bright so the qubits never render black on black.
ROTATE_GRADIENT = (
    "#413D2E",
    "#514B33",
    "#7A6E3B",
    "#AF992E",
    "#DDC019",   # the nearest follower
    "#DDC019",   # the film colour (the disc itself is BLACK)
)
# ERC-7730 clear signing — the intro the descriptor-driven flows open on
# wears the dev mark white on the same BLACK body over the same gold
# trail: the device's default gold ramp, pinned under its own name so a
# flow says which identity it shows (flows/erc7730)
ERC7730_GRADIENT = ROTATE_GRADIENT
# Fingerprint — the device showing a cryptographic digest (ERC-8213) for
# the user to match: the fingerprint mark BLACK on a WHITE disc under a
# black edge stroke (the family's explicit ring) — the
# mono look inverted, a firmware action rather than a token — over the
# default grey trail (the MONO ramp's followers), pinned under its own
# name so a flow says which identity it shows (flows/fingerprint). Stop 6
# stays the film colour (the palette override below fills the disc).
FINGERPRINT_GRADIENT = PLACEHOLDER_GRADIENTS[MONO_RAMP]
# Firmware — the device acting on its own firmware (an update to a new
# version): the download mark BLACK on the same WHITE disc under the black
# edge stroke — the firmware-action look the fingerprint family set — over
# the default grey trail, pinned under its own name so a flow says which
# identity it shows (flows/firmware). Stop 6 stays the film colour.
FIRMWARE_GRADIENT = FINGERPRINT_GRADIENT

# ----------------------------------------------------------- token ramps --
# A popular token's logo art rides on a trail in the token's OWN colour —
# the dominant colour of its logo asset (pq1/assets/<stem>.png: USDC
# #2775CA, USDT #50AF95, DAI #F5AC37 — sampled from the art, never
# guessed), the five followers darkening away from the token like every
# ramp. Keyed by SYMBOL, pinned by components.token_defaults; the same
# named-ramp registry as the brands, so token_ramp resolves them by name
# and no unknown token can hash onto one. ETH is not here: its identity is
# the white mark on the mono body (MONO_RAMP).
RAMP_STEPS = (0.15, 0.30, 0.50, 0.70, 0.86, 1.0)   # far follower -> the token


def ramp_from(hex_color, steps=RAMP_STEPS):
    """a six-stop ramp darkening away from one colour: stop 6 = the colour,
    stops 5..1 the colour scaled toward black by `steps` (the trail)"""
    r, g, b = hex_to_rgb(hex_color)
    return tuple("#%02X%02X%02X" % tuple(int(round(c * k)) for c in (r, g, b))
                 for k in steps)


TOKEN_COLORS = {"USDC": "#2775CA", "USDT": "#50AF95", "DAI": "#F5AC37"}
TOKEN_GRADIENTS = {sym: ramp_from(h) for sym, h in TOKEN_COLORS.items()}

# every named ramp — brands, popular tokens, device operations — pinned by
# name, outside the placeholder hash space
BRAND_GRADIENTS = {"SAFE": SAFE_GRADIENT, "COWSWAP": COWSWAP_GRADIENT,
                   "ROTATE": ROTATE_GRADIENT, "ERC7730": ERC7730_GRADIENT,
                   "FINGERPRINT": FINGERPRINT_GRADIENT, "FIRMWARE": FIRMWARE_GRADIENT,
                   **TOKEN_GRADIENTS}
BRAND_PALETTES = {k: _ramp_to_palette(g) for k, g in BRAND_GRADIENTS.items()}
# the rotation and ERC-7730 discs fill BLACK (white mark + white ring),
# their trails gold
for _k in ("ROTATE", "ERC7730"):
    BRAND_PALETTES[_k] = (BLACK, BRAND_PALETTES[_k][1])
# the firmware-action discs (fingerprint, firmware update) fill WHITE
# (black mark), their trails the mono grey
for _k in ("FINGERPRINT", "FIRMWARE"):
    BRAND_PALETTES[_k] = (WHITE, BRAND_PALETTES[_k][1])
BRAND_RAMP_STOPS = {
    k: tuple((i / (len(g) - 1), hex_to_rgb(h)) for i, h in enumerate(g))
    for k, g in BRAND_GRADIENTS.items()}


# A resolved ramp key (components.token_ramp) is a placeholder index (int)
# or a brand name (str) — these accessors read either.
def ramp_gradient(key):
    """hex ramp for a resolved ramp key"""
    return BRAND_GRADIENTS[key] if isinstance(key, str) else PLACEHOLDER_GRADIENTS[key]


def ramp_palette(key):
    """(fill, trail) for a resolved ramp key"""
    return BRAND_PALETTES[key] if isinstance(key, str) else PLACEHOLDER_PALETTES[key]


def ramp_stops(key):
    """grad_color stop list for a resolved ramp key"""
    return BRAND_RAMP_STOPS[key] if isinstance(key, str) else RAMP_STOPS[key]

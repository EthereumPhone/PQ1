#!/usr/bin/env python3
"""Bake the pixel trusted-UI assets (Aileron glyph atlases + disc marks).

Reads the vendored PQ-UI design system (`tools/pq-ui/`, pinned in
`tools/pq-ui/UPSTREAM.txt`) and writes, deterministically:

  secure/assets/ui-px/fonts.bin        glyph atlases, one tier per (size, weight)
  secure/assets/ui-px/<name>.a4        4-bit alpha disc marks (safe, mainnet, base,
                                       eth, blind, rotate, usdc, usdt, dai,
                                       cowswap)
  secure/assets/ui-px/manifest.json    sha256 of every output + inputs, versions
  nonsecure/assets/ui-px/atlas.pq1a    the SHIPPED form: fonts + marks in one
                                       container, linked into the NON-SECURE
                                       image at a fixed slot offset (owner
                                       decision 2026-09-23: the atlas lives in
                                       the FSBL-measured NS slot, not the
                                       secure A/B slot)
  secure/src/ui/px/atlas_root.rs       ATLAS_ROOT = sha256(atlas.pq1a) and
                                       ATLAS_LEN, pinned into the secure image
                                       (the secure world verifies the NS blob
                                       against them before AND after every
                                       pixel dialog)
  pqsigner-ui-px/src/metrics_gen.rs    advance-width tables for the host fitter

Glyphs are rasterised exactly like the design reference (`pq1/canvas.py`:
draw at 3x, downsample) and quantised to 4-bit alpha (owner decision
2026-09-22; `--alpha2` is the fallback-ladder switch). Every output is a pure
function of the inputs, so `make ui-px-assets-check` can re-bake into a temp
dir and diff the manifest.

Binary formats (little-endian):

  fonts.bin
    FileHeader  magic b"PQ1F" | version u16 | n_tiers u16 | total_len u32      (12 B)
    Tier[n]     size_px u8 | weight u8 (0 regular, 1 semibold) | first_code u8 |
                n_glyphs u8 | ascent_q6 i16 | descent_q6 i16 |
                glyph_tab_off u32 | bitmap_off u32                            (16 B)
    Glyph[n]    w u8 | h u8 | bearing_x i8 | bearing_top i8 | advance_q6 u16 |
                bmp_off u16 (relative to the tier's bitmap_off)               (8 B)
    Bitmap      rows of (w+1)//2 bytes, high nibble first (alpha4 in 0..15;
                alpha2 mode stores 0/5/10/15 so the reader is unchanged)
  <name>.a4
    magic b"PQ1M" | w u8 | h u8 | reserved u16 | rows as above (centre = w/2, h/2) (8 B header)
  atlas.pq1a  (the container the firmware reads; parsed by pqsigner_ui_px::pq1a)
    Header      magic b"PQ1A" | version u16 | n_entries u16 | total_len u32 |
                reserved[20] (zero)                                           (32 B)
    Entry[n]    name[8] (ASCII, NUL-padded) | off u32 | len u32               (16 B)
    Payload     each entry's bytes at `off` from the container start, 4-aligned;
                entries: "fonts" (fonts.bin), "safe", "mainnet", "base",
                "eth", "blind", "rotate", "usdc", "usdt", "dai", "cowswap" (.a4)

Missing glyphs have w = h = advance = 0 (the fitter treats advance 0 as
"not renderable at this tier"); code 0x7F stands in for U+2026 (ellipsis) in
the caption tiers.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import sys

from PIL import Image, ImageDraw, ImageFont
import PIL

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PQ_UI = os.path.join(HERE, "pq-ui")
ASSETS = os.path.join(PQ_UI, "pq1", "assets")
OUT_DIR_DEFAULT = os.path.join(ROOT, "secure", "assets", "ui-px")
NS_OUT_DIR_DEFAULT = os.path.join(ROOT, "nonsecure", "assets", "ui-px")
METRICS_DEFAULT = os.path.join(ROOT, "pqsigner-ui-px", "src", "metrics_gen.rs")
ROOT_RS_DEFAULT = os.path.join(ROOT, "secure", "src", "ui", "px", "atlas_root.rs")

ATLAS_MAGIC = b"PQ1A"
ATLAS_VERSION = 1
ATLAS_ENTRY_ORDER = ("fonts", "safe", "mainnet", "base", "eth", "blind", "rotate", "usdc", "usdt", "dai", "cowswap", "fprint")
# Procedural pq1 glyphs baked as marks (pq1/components.GLYPHS names).
PROCEDURAL_MARKS = ("mainnet", "base", "eth", "blind", "rotate", "fingerprint")
# Glyph name -> container / file name where the glyph's name is too long.
MARK_KEYS = {"fingerprint": "fprint"}
# Popular-token logo art (components.TOKEN_LOGOS) -> (asset, the token colour
# the art is painted in, colors.TOKEN_COLORS). The disc is drawn in that
# colour on-device; the mark is the WHITE part of the art.
TOKEN_ART = {
    "usdc": ("usdc.png", (0x27, 0x75, 0xCA)),
    "usdt": ("tether.png", (0x50, 0xAF, 0x95)),
    "dai": ("dai.png", (0xF5, 0xAC, 0x37)),
}

FORMAT_VERSION = 1
SUP = 3  # supersample factor, same as pq1/layout.py SUP

FONTS = {
    0: os.path.join(ASSETS, "Aileron-Regular.otf"),
    1: os.path.join(ASSETS, "Aileron-SemiBold.otf"),
}

FULL = [chr(c) for c in range(0x20, 0x7F)]
TRIM_OUT = set('~^\\`|{}[]<>@#$*_=;"')
TRIM = [c for c in FULL if c not in TRIM_OUT]
CAPS = [" "] + [chr(c) for c in range(ord("A"), ord("Z") + 1)] + \
       [chr(c) for c in range(ord("0"), ord("9") + 1)] + list("?.,:/-'&%+!()") + ["…"]
PAGER = list("0123456789/")

# (size_px, weight, charset) — the tiers the pilot renders.
TIERS = [
    (36, 0, TRIM),
    (32, 0, TRIM),
    (28, 0, TRIM),
    (22, 0, FULL),
    (22, 1, FULL),
    (18, 0, CAPS),
    (16, 1, CAPS),
    (16, 0, PAGER),
]
assert len(TRIM) == 76 and len(FULL) == 95 and len(CAPS) == 51 and len(PAGER) == 11

MARK_DIAMETER = 58  # 2 * (r 30 - TOKEN_INSET 1.2) rounded: the visible disc


def code_of(ch: str) -> int:
    return 0x7F if ch == "…" else ord(ch)


def sha256_file(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def align_down(v: int, m: int) -> int:
    return v - (v % m)


def align_up(v: int, m: int) -> int:
    return -align_down(-v, m)


def quantise(img: Image.Image, levels4: bool) -> bytes:
    """L image -> packed nibbles, high nibble first, rows padded."""
    w, h = img.size
    px = img.load()
    out = bytearray()
    for y in range(h):
        row = bytearray((w + 1) // 2)
        for x in range(w):
            v = px[x, y]
            a = (v * 15 + 127) // 255
            if not levels4:
                a = (a // 5) * 5  # 0,5,10,15
            if x % 2 == 0:
                row[x // 2] |= a << 4
            else:
                row[x // 2] |= a
        out += row
    return bytes(out)


def render_glyph(font: ImageFont.FreeTypeFont, ch: str):
    """Rasterise one glyph at 3x, box-downsample to 1x, return
    (w, h, bearing_x, bearing_top, advance_q6, L image)."""
    adv3 = font.getlength(ch)
    bbox = font.getbbox(ch, anchor="ls")  # relative to the baseline-left origin
    if bbox is None or bbox[2] <= bbox[0] or bbox[3] <= bbox[1]:
        return 0, 0, 0, 0, int(round(adv3 / SUP * 64)), None
    x0, y0, x1, y1 = bbox
    x0, y0 = align_down(x0, SUP), align_down(y0, SUP)
    x1, y1 = align_up(x1, SUP), align_up(y1, SUP)
    canvas = Image.new("L", (x1 - x0, y1 - y0), 0)
    ImageDraw.Draw(canvas).text((-x0, -y0), ch, font=font, fill=255, anchor="ls")
    small = canvas.reduce(SUP)  # box filter, the same downsample family as Canvas.out()
    # Trim rows/columns that quantise to zero coverage so the atlas stores only ink.
    bbox1 = small.point(lambda v: 255 if (v * 15 + 127) // 255 else 0).getbbox()
    if bbox1 is None:
        return 0, 0, 0, 0, int(round(adv3 / SUP * 64)), None
    small = small.crop(bbox1)
    w, h = small.size
    return w, h, x0 // SUP + bbox1[0], -y0 // SUP - bbox1[1], int(round(adv3 / SUP * 64)), small


def bake_fonts(levels4: bool):
    """Returns (fonts_bin bytes, metrics list)."""
    tier_blobs = []
    metrics = []
    for size, weight, charset in TIERS:
        font = ImageFont.truetype(FONTS[weight], size * SUP)
        asc3, desc3 = font.getmetrics()
        first = min(code_of(c) for c in charset)
        last = max(code_of(c) for c in charset)
        n = last - first + 1
        table = bytearray()
        bitmap = bytearray()
        adv_table = [0] * 96  # indexed by code - 0x20
        present = {code_of(c): c for c in charset}
        max_w = max_h = 0
        for code in range(first, last + 1):
            ch = present.get(code)
            if ch is None:
                table += struct.pack("<BBbbHH", 0, 0, 0, 0, 0, 0)
                continue
            w, h, bx, top, adv_q6, img = render_glyph(font, ch)
            if img is None:
                table += struct.pack("<BBbbHH", 0, 0, 0, 0, adv_q6, 0)
            else:
                assert w < 256 and h < 256 and -128 <= bx < 128 and -128 <= top < 128
                assert len(bitmap) < 65536, "tier bitmap exceeds u16 offsets"
                table += struct.pack("<BBbbHH", w, h, bx, top, adv_q6, len(bitmap))
                bitmap += quantise(img, levels4)
                max_w, max_h = max(max_w, w), max(max_h, h)
            adv_table[code - 0x20] = adv_q6
        tier_blobs.append((size, weight, first, n, int(round(asc3 / SUP * 64)),
                           int(round(desc3 / SUP * 64)), bytes(table), bytes(bitmap)))
        metrics.append(dict(px=size, weight=weight, ascent_q6=int(round(asc3 / SUP * 64)),
                            descent_q6=int(round(desc3 / SUP * 64)), advance_q6=adv_table,
                            glyphs=len(charset), table_bytes=len(table), bitmap_bytes=len(bitmap),
                            max_w=max_w, max_h=max_h))
    header_len = 12 + 16 * len(tier_blobs)
    body = bytearray()
    tier_hdrs = bytearray()
    for size, weight, first, n, asc, desc, table, bitmap in tier_blobs:
        tab_off = header_len + len(body)
        body += table
        bmp_off = header_len + len(body)
        body += bitmap
        tier_hdrs += struct.pack("<BBBBhhII", size, weight, first, n, asc, desc, tab_off, bmp_off)
    total = header_len + len(body)
    out = struct.pack("<4sHHI", b"PQ1F", FORMAT_VERSION, len(tier_blobs), total) + tier_hdrs + body
    assert len(out) == total
    return bytes(out), metrics


def crop_centred(mask: Image.Image) -> Image.Image:
    """Trim empty borders SYMMETRICALLY (the same amount off opposite sides),
    so the centre stays at (w/2, h/2) and a 1:1 blit lands on the same pixels
    as the uncropped mask. Only the bytes shrink — the NS atlas window
    (0x13000) is the budget."""
    w, h = mask.size
    q = quantise(mask, True)
    stride = (w + 1) // 2

    def a(x, y):
        b = q[y * stride + x // 2]
        return (b >> 4) if x % 2 == 0 else (b & 15)

    xs = [x for y in range(h) for x in range(w) if a(x, y)]
    ys = [y for y in range(h) for x in range(w) if a(x, y)]
    if not xs:
        return mask
    kx = min(min(xs), w - 1 - max(xs))
    ky = min(min(ys), h - 1 - max(ys))
    return mask.crop((kx, ky, w - kx, h - ky))


def mark_from_mask(mask: Image.Image, name: str, crop: bool = True) -> bytes:
    """Masks are baked centred, so the optical centre is (w/2, h/2). Every
    mark but `safe` is cropped (`crop_centred`); the Safe mark keeps its full
    square because the film blits it scaled, where a crop would move the
    sampling grid and change the Safe goldens."""
    if crop:
        mask = crop_centred(mask)
    w, h = mask.size
    assert w < 256 and h < 256
    return struct.pack("<4sBBH", b"PQ1M", w, h, 0) + quantise(mask, True)


def bake_safe_mark() -> bytes:
    """The Safe logo art is two-colour (#13FF7F disc, #121212 mark). The disc is
    drawn procedurally on-device, so the asset is only the dark mark as an
    alpha mask at the visible disc diameter."""
    im = Image.open(os.path.join(ASSETS, "safe.png")).convert("RGBA")
    big = im.resize((MARK_DIAMETER * SUP, MARK_DIAMETER * SUP), Image.LANCZOS)
    mask = Image.new("L", big.size, 0)
    src = big.load()
    dst = mask.load()
    for y in range(big.size[1]):
        for x in range(big.size[0]):
            r, g, b, a = src[x, y]
            dark = max(0.0, 1.0 - g / 255.0) / (1.0 - 18 / 255.0)
            dst[x, y] = int(round(min(1.0, dark) * a))
    return mark_from_mask(mask.reduce(SUP), "safe", crop=False)


# CoW Swap brand art (cowswap.png): the navy cow head (colors.COWSWAP_DARK)
# on the #65D9FF disc. Like the Safe mark, the device draws the disc and the
# asset is the dark part of the art as an alpha mask.
COWSWAP_DISC = (0x65, 0xD9, 0xFF)
COWSWAP_NAVY = (0x01, 0x2F, 0x7A)


def bake_cowswap_mark() -> bytes:
    """Per pixel, how far the colour sits from the disc toward the navy head
    (projection onto the disc -> navy segment), times alpha."""
    im = Image.open(os.path.join(ASSETS, "cowswap.png")).convert("RGBA")
    big = im.resize((MARK_DIAMETER * SUP, MARK_DIAMETER * SUP), Image.LANCZOS)
    mask = Image.new("L", big.size, 0)
    src = big.load()
    dst = mask.load()
    d = [n - c for n, c in zip(COWSWAP_NAVY, COWSWAP_DISC)]
    dd = sum(v * v for v in d)
    for y in range(big.size[1]):
        for x in range(big.size[0]):
            r, g, b, a = src[x, y]
            t = sum((p - c) * v for p, c, v in zip((r, g, b), COWSWAP_DISC, d)) / dd
            dst[x, y] = int(round(max(0.0, min(1.0, t)) * a))
    return mark_from_mask(mask.reduce(SUP), "cowswap")


def bake_token_mark(name: str) -> bytes:
    """A popular token's full-bleed logo art (e.g. white USDC glyph on the
    #2775CA disc): the device paints the disc in the token colour, so the
    asset is the art's WHITE part as an alpha mask — per pixel, how far the
    colour sits from the token colour toward white — at the visible disc
    diameter."""
    file, tok = TOKEN_ART[name]
    im = Image.open(os.path.join(ASSETS, file)).convert("RGBA")
    big = im.resize((MARK_DIAMETER * SUP, MARK_DIAMETER * SUP), Image.LANCZOS)
    mask = Image.new("L", big.size, 0)
    src = big.load()
    dst = mask.load()
    for y in range(big.size[1]):
        for x in range(big.size[0]):
            r, g, b, a = src[x, y]
            t = min((r - tok[0]) / (255 - tok[0]), (g - tok[1]) / (255 - tok[1]), (b - tok[2]) / (255 - tok[2]))
            dst[x, y] = int(round(max(0.0, min(1.0, t)) * a))
    return mark_from_mask(mask.reduce(SUP), name)


def bake_procedural_mark(name: str) -> bytes:
    """Render a pq1 procedural glyph (white on black, 3x) and take its
    luminance as the alpha mask, at the visible disc diameter."""
    sys.path.insert(0, PQ_UI)
    from pq1 import canvas as pq_canvas, components  # noqa: WPS433 (vendored)

    cv = pq_canvas.Canvas(MARK_DIAMETER, MARK_DIAMETER, (0, 0, 0))
    r = MARK_DIAMETER / 2
    components.glyph(cv, name, r, r, r, alpha=1.0, color=(255, 255, 255))
    mask = cv.img.convert("L").reduce(SUP)
    return mark_from_mask(mask, name)


def write_metrics_rs(path: str, metrics: list, fonts_sha: str) -> None:
    lines = [
        "//! GENERATED by `tools/ui_px_assets.py` — do not edit.",
        "//!",
        "//! Advance widths (Q6, 1/64 px) and vertical metrics for every baked",
        "//! tier, so the host-side tier fitter measures real Aileron widths without",
        "//! parsing the atlas. Indexed by `code - 0x20`; 0 means the glyph is not",
        "//! baked at that tier (the fitter treats it as unrenderable).",
        f"//! fonts.bin sha256 = {fonts_sha}",
        "",
        "/// One baked (size, weight) tier.",
        "#[derive(Clone, Copy, Debug)]",
        "pub struct TierMetrics {",
        "    pub px: u8,",
        "    pub semibold: bool,",
        "    pub ascent_q6: i16,",
        "    pub descent_q6: i16,",
        "    pub advance_q6: [u16; 96],",
        "}",
        "",
        "/// Every baked tier, in atlas order.",
        f"pub const TIERS: [TierMetrics; {len(metrics)}] = [",
    ]
    for m in metrics:
        adv = ", ".join(str(v) for v in m["advance_q6"])
        lines += [
            "    TierMetrics {",
            f"        px: {m['px']},",
            f"        semibold: {'true' if m['weight'] else 'false'},",
            f"        ascent_q6: {m['ascent_q6']},",
            f"        descent_q6: {m['descent_q6']},",
            f"        advance_q6: [{adv}],",
            "    },",
        ]
    lines += ["];", ""]
    with open(path, "w") as f:
        f.write("\n".join(lines))


def build_atlas_container(entries: dict) -> bytes:
    """Pack the named blobs into one PQ1A container (fixed entry order, every
    payload 4-aligned, header + table first)."""
    names = [n for n in ATLAS_ENTRY_ORDER if n in entries]
    hdr_len = 32 + 16 * len(names)
    off = (hdr_len + 3) & ~3
    table = b""
    payload = b""
    for n in names:
        blob = entries[n]
        pad = (-(off + len(payload))) & 3
        payload += b"\0" * pad
        start = off + len(payload)
        table += struct.pack("<8sII", n.encode("ascii"), start, len(blob))
        payload += blob
    total = off + len(payload)
    header = struct.pack("<4sHHI20s", ATLAS_MAGIC, ATLAS_VERSION, len(names), total, b"\0" * 20)
    out = header + table
    out += b"\0" * (off - len(out))
    out += payload
    assert len(out) == total
    return out


def write_atlas_root_rs(path: str, container: bytes) -> None:
    sha = hashlib.sha256(container).digest()
    words = ", ".join(f"0x{b:02x}" for b in sha)
    lines = [
        "//! GENERATED by `tools/ui_px_assets.py` — do not edit.",
        "//!",
        "//! The pixel-UI atlas (`nonsecure/assets/ui-px/atlas.pq1a`: glyph tiers +",
        "//! disc marks) is linked into the NON-SECURE image at a fixed slot offset",
        "//! and is therefore part of what the FSBL measures at boot (invariant #10).",
        "//! The secure world never trusts those bytes on address alone: it re-hashes",
        "//! the window and compares against this pinned root before AND after every",
        "//! pixel dialog (`crate::ui::px::assets`). A stale bake fails",
        "//! `secure/build.rs` (root != sha256 of the committed container).",
        "",
        "/// SHA-256 of the whole `atlas.pq1a` container.",
        f"pub const ATLAS_ROOT: [u8; 32] = [{words}];",
        "/// Exact container length in bytes.",
        f"pub const ATLAS_LEN: usize = {len(container)};",
        "",
    ]
    with open(path, "w") as f:
        f.write("\n".join(lines))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=OUT_DIR_DEFAULT)
    ap.add_argument("--metrics", default=METRICS_DEFAULT)
    ap.add_argument("--ns-out", default=NS_OUT_DIR_DEFAULT, help="where atlas.pq1a (the shipped container) goes")
    ap.add_argument("--root-rs", default=ROOT_RS_DEFAULT, help="generated secure-side ATLAS_ROOT / ATLAS_LEN")
    ap.add_argument("--alpha2", action="store_true", help="fallback ladder: 4-level alpha for the 36/32/28 tiers")
    ap.add_argument("--no-marks", action="store_true")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    os.makedirs(args.ns_out, exist_ok=True)

    fonts_bin, metrics = bake_fonts(levels4=not args.alpha2)
    with open(os.path.join(args.out, "fonts.bin"), "wb") as f:
        f.write(fonts_bin)
    fonts_sha = hashlib.sha256(fonts_bin).hexdigest()
    write_metrics_rs(args.metrics, metrics, fonts_sha)

    marks = {}
    if not args.no_marks:
        marks["safe"] = bake_safe_mark()
        for name in PROCEDURAL_MARKS:
            try:
                # Container names are at most 8 bytes (pq1a NAME_*).
                marks[MARK_KEYS.get(name, name)] = bake_procedural_mark(name)
            except Exception as e:  # noqa: BLE001 — report and continue; the manifest shows what shipped
                print(f"warning: mark {name!r} not baked: {e}", file=sys.stderr)
        for name in TOKEN_ART:
            marks[name] = bake_token_mark(name)
        marks["cowswap"] = bake_cowswap_mark()
        for name, blob in marks.items():
            with open(os.path.join(args.out, f"{name}.a4"), "wb") as f:
                f.write(blob)

    container = build_atlas_container({"fonts": fonts_bin} | marks)
    with open(os.path.join(args.ns_out, "atlas.pq1a"), "wb") as f:
        f.write(container)
    write_atlas_root_rs(args.root_rs, container)

    manifest = {
        "format_version": FORMAT_VERSION,
        "alpha_levels": 4 if args.alpha2 else 16,
        "pillow": PIL.__version__,
        "inputs": {os.path.relpath(p, ROOT): sha256_file(p) for p in FONTS.values()}
        | {os.path.relpath(os.path.join(ASSETS, f), ROOT): sha256_file(os.path.join(ASSETS, f))
           for f in ["safe.png", "cowswap.png"] + [a for a, _ in TOKEN_ART.values()]},
        "outputs": {"fonts.bin": {"sha256": fonts_sha, "bytes": len(fonts_bin)}}
        | {f"{n}.a4": {"sha256": hashlib.sha256(b).hexdigest(), "bytes": len(b)} for n, b in marks.items()}
        | {"atlas.pq1a": {"sha256": hashlib.sha256(container).hexdigest(), "bytes": len(container)}},
        "tiers": [{k: v for k, v in m.items() if k != "advance_q6"} for m in metrics],
        # The Safe logo is a third-party brand asset. `secure/build.rs` refuses
        # to embed safe.a4 into a `mode-production` image while this is false.
        "safe_logo_approved": False,
    }
    with open(os.path.join(args.out, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
        f.write("\n")

    total = len(fonts_bin) + sum(len(b) for b in marks.values())
    print(f"fonts.bin {len(fonts_bin)} B  marks {sum(len(b) for b in marks.values())} B  total {total} B  atlas.pq1a {len(container)} B (NS slot)")
    for m in metrics:
        print(f"  {'sb' if m['weight'] else 'r '}{m['px']:2d}: {m['glyphs']:3d} glyphs  table {m['table_bytes']:5d}  bitmap {m['bitmap_bytes']:6d}  max {m['max_w']}x{m['max_h']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

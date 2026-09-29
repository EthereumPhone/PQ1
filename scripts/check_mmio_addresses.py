#!/usr/bin/env python3
"""verify-mmio-addresses — every hand-transcribed MMIO base address in
`secure/src/hw/*` and `secure/src/sau.rs` must match ST's own CMSIS header.

WHY (work-todo C2). Peripheral base addresses are typed into this repo by hand
from RM0456. A single wrong nibble is silent: the driver writes into whatever
lives at the wrong address and the failure surfaces, if at all, as an
unrelatable bug a long way away. This project has already been bitten — the TAMP
driver sat at the wrong base for an unknown period precisely because nothing
compared it to anything, and `hw/tzic.rs`'s own history carries the same shape.
An external artifact that can DISAGREE is the cheapest possible defence, and it
is the only one available: there is no proof to be had here, just a diff.

SOURCE OF TRUTH. ST's CMSIS device header for this exact part —
`STM32CubeU5/Drivers/CMSIS/Device/ST/STM32U5xx/Include/stm32u585xx.h`, i.e. the
vendor's own machine-readable definition, which is a stronger reference than a
third-party SVD (work-todo C2 originally proposed the stm32-rs patched SVD; ST's
header is upstream of it). Point the gate elsewhere with STM32U5_CMSIS_HEADER=.

SCOPE — read this before trusting a green:
  * It checks BASE/peripheral addresses that have a CMSIS counterpart. It does
    NOT check register OFFSETS, bit positions, or field semantics.
  * The header defines addresses symbolically (`AHB2PERIPH_BASE_S + 0xA0400UL`),
    so this resolves the arithmetic. That resolver is itself code that can be
    wrong; it is unit-tested by --self-test against known-good values.
  * Addresses with NO CMSIS counterpart (flash page addresses we chose, SAU
    window bounds, QEMU MPC bases) are listed as UNMAPPED and skipped, not
    silently passed. Growing that list is how this gate rots — a new UNMAPPED
    entry should be justified in review.
  * A green means "these constants agree with ST's header", never "the drivers
    address the right peripheral for the right reason".
"""

import os
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
HEADER = Path(os.environ.get(
    "STM32U5_CMSIS_HEADER",
    Path.home() / "repos/STM32CubeU5/Drivers/CMSIS/Device/ST/STM32U5xx/Include/stm32u585xx.h",
))

# Rust const name -> CMSIS symbol it must equal. Secure aliases (_S) where the
# secure world is the owner; that IS the property we want pinned (a driver that
# quietly moved to the NS alias would defeat invariant #4).
EXPECTED = {
    "secure/src/hw/hash.rs":   {"HASH_BASE": "HASH_BASE_S"},
    "secure/src/hw/saes.rs":   {"SAES_BASE": "SAES_BASE_S"},
    "secure/src/hw/rng.rs":    {"RNG": "RNG_BASE_S"},
    # GTZC1's CMSIS names are GTZC_TZSC1_/GTZC_TZIC1_ (instance number on the
    # BLOCK, not the controller) — the obvious-looking GTZC1_TZSC_BASE_S does
    # not exist. Exactly the kind of near-miss that makes hand transcription
    # worth diffing.
    "secure/src/hw/tzic.rs":   {"TZIC_BASE": "GTZC_TZIC1_BASE_S"},
    "secure/src/hw/tamp.rs": {
        "TAMP": "TAMP_BASE_S",
        "RCC": "RCC_BASE_S",
        "PWR": "PWR_BASE_S",
    },
    "secure/src/sau.rs": {
        "TZSC_BASE": "GTZC_TZSC1_BASE_S",
        "MPCBB1_BASE": "GTZC_MPCBB1_BASE_S",
        "MPCBB2_BASE": "GTZC_MPCBB2_BASE_S",
    },
    "secure/src/hw/spi_hw.rs": {"SPI_BASE": "SPI1_BASE_S"},
    # The per-board pin maps (`BOARD=iota2|pq1`). These are the single point of
    # truth for every peripheral a driver reaches through `crate::board`, so
    # they are exactly the constants worth diffing against ST. Note both USARTs
    # and both I2Cs appear here: a board swap chooses BETWEEN them, so a wrong
    # nibble in the unused one stays invisible until someone flips BOARD.
    "secure/src/board/mod.rs": {
        "RCC_S": "RCC_BASE_S",
        "GPIOA_S": "GPIOA_BASE_S",
        "GPIOB_S": "GPIOB_BASE_S",
        "GPIOC_S": "GPIOC_BASE_S",
        "GPIOD_S": "GPIOD_BASE_S",
        "GPIOE_S": "GPIOE_BASE_S",
        "USART1_S": "USART1_BASE_S",
        "USART2_S": "USART2_BASE_S",
        "I2C1_S": "I2C1_BASE_S",
        "I2C4_S": "I2C4_BASE_S",
        "SPI1_S": "SPI1_BASE_S",
        "SPI2_S": "SPI2_BASE_S",
    },
    # A4a's die-identity probe. DBGMCU has no _S/_NS split — one base.
    "secure/src/hw/dbgmcu.rs": {"DBGMCU_BASE": "DBGMCU_BASE"},
}

# Constants that are a peripheral base PLUS a register offset. Checked as
# base + offset so the gate covers them without pretending they are bases.
EXPECTED_OFFSET = {
    "secure/src/sau.rs": {
        # RCC_AHB1ENR at offset 0x88 — ST's header struct RCC_TypeDef says
        # "AHB1ENR ... Address offset: 0x88". sau.rs writes it as
        # `0x5602_0C00 + 0x88`, which is why the extractor must evaluate sums.
        "RCC_AHB1ENR_ADDR": ("RCC_BASE_S", 0x88),
    },
}

# Constants with no CMSIS counterpart. Each needs a REASON — this list is where
# the gate rots if it is grown carelessly.
UNMAPPED = {
    "SAU_NS_FLASH_BASE": "our SAU window choice, not a peripheral",
    "SAU_NS_FLASH_END": "our SAU window choice",
    "SAU_NS_SRAM_BASE": "our SAU window choice",
    "SAU_NS_SRAM_END": "our SAU window choice",
    "SAU_CTRL_ADDR": "ARMv8-M core register (ARM DDI0553), not an ST peripheral",
    "SAU_RNR_ADDR": "ARMv8-M core register",
    "SAU_RBAR_ADDR": "ARMv8-M core register",
    "SAU_RLAR_ADDR": "ARMv8-M core register",
    "SCB_AIRCR_ADDR": "ARMv8-M core register",
    "MPC0_BASE": "QEMU mps2-an505 SSE-200, not STM32",
    "MPC1_BASE": "QEMU mps2-an505 SSE-200, not STM32",
    "BHK_PAGE_ADDR": "flash page WE allocate (page 126), not a peripheral",
    "OTP_BASE": "flash-region base; CMSIS has no OTP_BASE symbol",
}

# Captures the WHOLE initialiser, not just the first hex literal. An earlier
# version stopped at the first `0x...` and so read
# `const RCC_AHB1ENR_ADDR: u32 = 0x5602_0C00 + 0x88;` as 0x5602_0C00 — then
# reported the (correct) code as a mismatch. A gate that misreads the source
# produces false positives, which is how gates get disabled.
CONST_RE = re.compile(r"const\s+([A-Z][A-Z0-9_]*)\s*:\s*u32\s*=\s*([0-9A-Fa-fx_\s+*|-]+?);")
DEFINE_RE = re.compile(r"^#define\s+(\w+)\s+(.+?)(?:/\*.*)?$")


def parse_header(path):
    """Resolve the header's #define arithmetic into concrete addresses."""
    raw = {}
    for line in path.read_text(errors="ignore").splitlines():
        m = DEFINE_RE.match(line.strip())
        if m and "(" not in m.group(1):  # skip function-like macros
            raw[m.group(1)] = m.group(2).strip()

    resolved, resolving = {}, set()

    def resolve(name, depth=0):
        if name in resolved:
            return resolved[name]
        if name not in raw or depth > 12 or name in resolving:
            return None
        resolving.add(name)
        expr = raw[name]
        # Strip comments/UL suffixes, keep only symbol/number arithmetic.
        expr = re.sub(r"/\*.*?\*/", "", expr)
        expr = re.sub(r"\b(\d+|0[xX][0-9A-Fa-f]+)[UuLl]+", r"\1", expr)
        if not re.fullmatch(r"[\s\w()+\-*x0-9A-Fa-f]+", expr):
            resolving.discard(name)
            return None
        py = expr
        # Identifiers only — NOT the `x50000000` that `[A-Za-z_]\w*` happily
        # finds inside `0x50000000`. That bug made the resolver return None for
        # every symbol, which the --self-test caught immediately: without an
        # independently-known expected value, a resolver that resolves nothing
        # reports "CMSIS symbol not resolvable" for all of them and reads like a
        # header problem rather than a gate problem.
        syms = set(re.findall(r"(?<![0-9A-Za-z_])[A-Za-z_]\w*", expr))
        for sym in sorted(syms, key=len, reverse=True):
            v = resolve(sym, depth + 1)
            if v is None:
                resolving.discard(name)
                return None
            py = re.sub(rf"(?<![0-9A-Za-z_]){re.escape(sym)}\b", str(v), py)
        try:
            val = eval(py, {"__builtins__": {}}, {})  # noqa: S307 - arithmetic only, filtered above
        except Exception:
            val = None
        resolving.discard(name)
        if isinstance(val, int):
            resolved[name] = val
            return val
        return None

    for k in raw:
        resolve(k)
    return resolved


def _eval_rust_int(expr):
    """Evaluate a simple `0xA + 0xB`-style Rust const initialiser."""
    e = expr.replace("_", "").strip()
    if not re.fullmatch(r"[0-9A-Fa-fx\s+*|-]+", e):
        return None
    try:
        return eval(e, {"__builtins__": {}}, {})  # noqa: S307 - arithmetic only, filtered above
    except Exception:
        return None


def rust_consts(rel):
    """name -> set of values. A SET because several of these are cfg-duplicated
    (spi_hw.rs defines SPI_BASE twice: SPI1 under `spi1-arduino`, SPI2
    otherwise). Taking only the first silently checked one arm and reported the
    other as a mismatch."""
    p = REPO / rel
    if not p.exists():
        return {}
    out = {}
    for m in CONST_RE.finditer(p.read_text(errors="ignore")):
        v = _eval_rust_int(m.group(2))
        if v is not None:
            out.setdefault(m.group(1), set()).add(v)
    return out


def check(cmsis):
    errs, checked, unmapped_seen = [], 0, []
    for rel, mapping in EXPECTED.items():
        consts = rust_consts(rel)
        if not consts:
            errs.append(f"{rel}: no u32 hex consts found — did the file move? (a gate that "
                        f"silently checks nothing is worse than no gate)")
            continue
        for rust_name, cmsis_name in mapping.items():
            if rust_name not in consts:
                errs.append(f"{rel}: expected const `{rust_name}` not found — re-point this gate "
                            f"rather than dropping the check")
                continue
            want = cmsis.get(cmsis_name)
            if want is None:
                errs.append(f"{rel}: CMSIS symbol `{cmsis_name}` not resolvable in the header "
                            f"— wrong header, or the resolver broke")
                continue
            got = consts[rust_name]
            if want not in got:
                shown = " / ".join(f"0x{g:08X}" for g in sorted(got))
                errs.append(f"{rel}: {rust_name} = {shown} but ST's {cmsis_name} = 0x{want:08X} "
                            f"— a wrong base is SILENT at runtime")
            checked += 1

    # base + documented register offset
    for rel, mapping in EXPECTED_OFFSET.items():
        consts = rust_consts(rel)
        for rust_name, (cmsis_name, off) in mapping.items():
            if rust_name not in consts:
                errs.append(f"{rel}: expected const `{rust_name}` not found")
                continue
            base = cmsis.get(cmsis_name)
            if base is None:
                errs.append(f"{rel}: CMSIS symbol `{cmsis_name}` not resolvable")
                continue
            want = base + off
            got = consts[rust_name]
            if want not in got:
                shown = " / ".join(f"0x{g:08X}" for g in sorted(got))
                errs.append(f"{rel}: {rust_name} = {shown} but ST's {cmsis_name}+0x{off:02X} "
                            f"= 0x{want:08X} — a wrong register address is SILENT at runtime")
            checked += 1

    # Report, don't hide, the constants we are not checking.
    for rel in EXPECTED:
        for name in rust_consts(rel):
            if name in UNMAPPED:
                unmapped_seen.append((rel, name, UNMAPPED[name]))
    return errs, checked, unmapped_seen


def self_test(cmsis):
    """The resolver is code; prove it against values independently known."""
    known = {
        "PERIPH_BASE_S": 0x50000000,
        "AHB2PERIPH_BASE_S": 0x52020000,
        "HASH_BASE_S": 0x520C0400,
        "SAES_BASE_S": 0x520C0C00,
        "UID_BASE": 0x0BFA0700,
    }
    rc = 0
    for sym, want in known.items():
        got = cmsis.get(sym)
        if got == want:
            print(f"  [ok  ] resolver: {sym:22s} = 0x{got:08X}")
        else:
            g = f"0x{got:08X}" if isinstance(got, int) else repr(got)
            print(f"  [FAIL] resolver: {sym:22s} = {g}, expected 0x{want:08X}")
            rc = 1
    # And prove the gate BITES: a deliberately wrong expectation must fail.
    bad = dict(cmsis)
    bad["HASH_BASE_S"] = 0xDEADBEEF
    errs, _, _ = check(bad)
    if any("HASH_BASE" in e for e in errs):
        print("  [ok  ] mutation: perturbed CMSIS value -> caught")
    else:
        print("  [FAIL] mutation: perturbed CMSIS value SURVIVED (gate is vacuous)")
        rc = 1
    return rc


def main():
    if not HEADER.exists():
        print(f"verify-mmio-addresses: SKIP — ST CMSIS header not found at {HEADER}")
        print("  This gate needs STM32CubeU5. Set STM32U5_CMSIS_HEADER=/path/to/stm32u585xx.h")
        print("  Fetch: https://github.com/STMicroelectronics/STM32CubeU5")
        return 0  # absent vendor SDK is a setup gap, not a code defect

    cmsis = parse_header(HEADER)

    if "--self-test" in sys.argv:
        print("=== verify-mmio-addresses self-test ===")
        rc = self_test(cmsis)
        print("=== self-test PASS ===" if rc == 0 else "=== self-test FAIL ===")
        return rc

    errs, checked, unmapped = check(cmsis)
    if errs:
        print(f"verify-mmio-addresses: {len(errs)} MISMATCH(es) vs ST's {HEADER.name}:")
        for e in errs:
            print("  -", e)
        return 1
    print(f"verify-mmio-addresses: OK — {checked} hand-transcribed base addresses "
          f"match ST's {HEADER.name}.")
    if unmapped:
        print(f"  not checked ({len(unmapped)} — no CMSIS counterpart):")
        for rel, name, why in unmapped:
            print(f"    {name:20s} {why}")
    print("  NOTE: bases only. Register offsets, bit positions and field semantics are NOT checked.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

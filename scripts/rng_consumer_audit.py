#!/usr/bin/env python3
"""Fail if a new direct platform-RNG consumer bypasses the reviewed allowlist."""

from __future__ import annotations

import re
import sys
from collections import Counter, defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SECURE = ROOT / "secure" / "src"

EXCLUDED_FILES = {"rng.rs", "rng_strong.rs", "host_rng.rs"}
# `try_byte_nonsecret` was added in #835 and this pattern did not cover it, so
# the FI delay path — a direct platform-RNG consumer, and the single highest
# call-rate one in the firmware — went INVISIBLE to this gate the moment the
# old `byte_nonsecret` call was removed. A new accessor must not be able to
# walk around the allowlist; matching the `byte` prefix family keeps any
# future `byte_*` helper in scope by default.
CALL = re.compile(r"\b(?:crate::)?rng::(?:fill|byte|byte_nonsecret|try_byte_nonsecret)\s*\(")
SOFTWARE_RNG = re.compile(
    r"\b(?:StdRng|SmallRng|ChaCha(?:8|12|20)?Rng|thread_rng|fastrand|"
    r"yasmarang|xorshift(?:32|64)?|Lcg|seed_from_u64)\b|\brand::(?:rngs|thread_rng)"
)

# These two PRNGs drive observable, non-secret visuals only. Neither output can
# reach a key, nonce, seed, challenge, or the strong-RNG facade.
NONSECRET_SOFTWARE_RNG_FILES = {
    "secure/src/hw/consumption_mask.rs",
    "secure/src/ui/splash_test.rs",
}

# Direct platform-RNG calls are permitted only for bootstrap/public transcript,
# non-secret SCA/UI jitter, explicitly nonshipping code, or an RDP-excluded
# bench wrapper. Counts are deliberate: a second call under the same local
# variable name is still a new bypass and fails this gate.
EXPECTED = {
    # #835: the substituting `byte_nonsecret(FI_DELAY_LAST_GOOD)` call is GONE.
    # A delay that cannot be given a fresh length no longer reuses one; it
    # poisons the operation, which then refuses at its own boundary. What
    # remains is the NON-substituting accessor, which can say no.
    "secure/src/fi.rs": Counter(
        {"if let Some(b) = crate::rng::try_byte_nonsecret() {": 1}
    ),
    # Bench-only measurement probes (`ui-px-bench`, and the fault probe also
    # needs `rng-fault-probe`, which is in PROD_FORBIDDEN and fenced in
    # nsc/mod.rs). None of these bytes reaches a key, nonce, seed or
    # signature: two are a poison-boundary self-test whose buffer is zeroed
    # immediately, and one is the #832 fan-out length sweep.
    "secure/src/ui/px/bench.rs": Counter(
        {
            "let _ = crate::rng::fill(&mut buf[..len]);": 1,
            "if crate::rng::fill(&mut scratch).is_err() {": 1,
            "if crate::rng::fill(&mut scratch).is_ok() {": 1,
        }
    ),
    "secure/src/bench_masked_sha.rs": Counter(
        {"let _ = crate::rng::fill(&mut b);": 1}
    ),
    "secure/src/se050/scp03.rs": Counter(
        {
            "crate::rng::fill(&mut host_challenge).map_err(|_| Se050Error::Scp03)?;": 1,
        }
    ),
    "secure/src/pq_wrap.rs": Counter(
        {"crate::rng::fill(&mut m).map_err(|()| WrapError)?;": 1}
    ),
    "secure/src/ui/seed_wizard.rs": Counter(
        {"let candidate = rng::byte_nonsecret(count as u8) % (WORD_COUNT as u8);": 1}
    ),
    "secure/src/optiga/mod.rs": Counter(
        {
            "crate::rng::fill(&mut p).map_err(|_| OptigaError::Transport)?;": 1,
            "crate::rng::fill(&mut host_nonce).map_err(|_| OptigaError::Transport)?;": 3,
            "crate::rng::fill(&mut host_tag).map_err(|_| OptigaError::Transport)?;": 3,
        }
    ),
    "secure/src/hw/bhk.rs": Counter(
        {"if crate::rng::fill(&mut bhk).is_err() {": 1}
    ),
    "secure/src/hw/consumption_mask.rs": Counter(
        {
            "crate::rng::fill(&mut seed_bytes)?;": 1,
            "if crate::rng::fill(&mut sb).is_ok() {": 1,
        }
    ),
    "secure/src/nsc/prodtest.rs": Counter(
        {"if crate::rng::fill(&mut sample[..n]).is_err() {": 1}
    ),
    # `se-lcd-diag` only: the LCD-only secure-element diagnostic reads the
    # raw platform TRNG once and shows OK / E:all-zero / E:fill on the panel
    # ("1. platform TRNG"). It is a liveness probe of the TRNG ITSELF, so
    # routing it through `rng_strong` would defeat its purpose -- the point
    # is to see the bare peripheral answer. The bytes are displayed as a
    # verdict and never derive a key. `se-lcd-diag` is in PROD_FORBIDDEN and
    # carries a mode-production compile fence, so it cannot reach a shipping
    # image. Reviewed 2026-09-24 on the ui-px-evt merge.
    "secure/src/main.rs": Counter({"let r = rng::fill(&mut b);": 1}),
}

REQUIRED_THREE_SOURCE = {
    "secure/src/main.rs": ["rng_strong::fill(&mut entropy)"],
    "secure/src/crypto.rs": [
        "rng_strong::fill(&mut opt_rand_buf)",
        "rng_strong::fill(&mut shuffle_seed_a)",
        "rng_strong::fill(&mut shuffle_seed_b)",
        "rng_strong::fill_with_store(out, store)",
    ],
    "secure/src/dual_se.rs": [
        "rng_strong::fill_with_store(&mut half_o, self)",
        "rng_strong::fill_with_store(&mut *transient_secret, self)",
    ],
    "secure/src/hw/otp.rs": ["rng_strong::fill(&mut key)"],
    "secure/src/first_boot/mod.rs": [
        "rng_strong::fill_with_source_draw(&mut bhk",
        "rng_strong::fill_with_store(&mut salt, self.se)",
    ],
    "secure/src/ui/seed_wizard.rs": ["rng_strong::fill(&mut decoy_entropy[i])"],
}


def code_before_line_comment(line: str) -> str:
    return line.split("//", 1)[0].strip()


def scan_direct_calls() -> dict[str, Counter[str]]:
    found: dict[str, Counter[str]] = defaultdict(Counter)
    for path in sorted(SECURE.rglob("*.rs")):
        rel = path.relative_to(ROOT).as_posix()
        is_test_fixture = path.name != "prodtest.rs" and (
            "test" in path.name or any("under_test" in part for part in path.parts)
        )
        if path.name in EXCLUDED_FILES or is_test_fixture:
            continue
        for raw_line in path.read_text(encoding="utf-8").splitlines():
            code = code_before_line_comment(raw_line)
            if code and CALL.search(code):
                found[rel][re.sub(r"\s+", " ", code)] += 1
    return dict(found)


def require_snippets(errors: list[str]) -> None:
    for rel, snippets in REQUIRED_THREE_SOURCE.items():
        source = (ROOT / rel).read_text(encoding="utf-8")
        for snippet in snippets:
            if snippet not in source:
                errors.append(f"missing mandatory three-source route: {rel}: {snippet}")

    fences = {
        "secure/src/hw/bhk.rs": [
            '#[cfg(not(feature = "rdp2-self-lock"))]\npub unsafe fn provision()',
        ],
        "secure/src/optiga/mod.rs": [
            '#[cfg(all(feature = "optiga-hw-counter", not(feature = "optiga-lock-operational")))]\n    unsafe fn reset_e120_via_transient_auth',
        ],
        "secure/src/nsc/mod.rs": [
            "PRODUCTION_ENTROPY_BACKENDS_REQUIRED",
            'not(feature = "stm32u585")',
            'not(feature = "dual-se")',
            'not(feature = "optiga-trust-m")',
            'not(feature = "se050")',
            "mode-production and mlkem-inner-wrap are mutually exclusive",
        ],
        "secure/src/main.rs": [
            "BHK missing after first-boot ALL_DONE; refusing reprovision",
        ],
    }
    for rel, snippets in fences.items():
        source = (ROOT / rel).read_text(encoding="utf-8")
        for snippet in snippets:
            if snippet not in source:
                errors.append(f"missing raw-RNG scope fence: {rel}: {snippet}")


def reject_software_rng(errors: list[str]) -> None:
    """Reject software PRNGs outside the explicit non-secret visual allowlist."""
    for path in sorted(SECURE.rglob("*.rs")):
        rel = path.relative_to(ROOT).as_posix()
        is_test_fixture = (
            "test" in path.name or any("under_test" in part for part in path.parts)
        )
        if is_test_fixture or rel in NONSECRET_SOFTWARE_RNG_FILES:
            continue
        for line_no, raw_line in enumerate(
            path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            code = code_before_line_comment(raw_line)
            match = SOFTWARE_RNG.search(code)
            if match:
                errors.append(
                    f"software PRNG forbidden in production source: "
                    f"{rel}:{line_no}: {match.group(0)}"
                )


def main() -> int:
    errors: list[str] = []
    found = scan_direct_calls()
    if found != EXPECTED:
        all_paths = sorted(set(found) | set(EXPECTED))
        for rel in all_paths:
            if found.get(rel, Counter()) != EXPECTED.get(rel, Counter()):
                errors.append(
                    f"raw RNG allowlist drift in {rel}:\n"
                    f"  expected={dict(EXPECTED.get(rel, Counter()))}\n"
                    f"  found={dict(found.get(rel, Counter()))}"
                )

    require_snippets(errors)
    reject_software_rng(errors)

    if errors:
        print("rng-consumer-audit: FAIL", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    call_count = sum(sum(counter.values()) for counter in found.values())
    print(
        "rng-consumer-audit: PASS — "
        f"{call_count} direct platform-RNG calls are bounded to reviewed "
        "bootstrap/public/nonsecret/nonshipping contexts; critical outputs "
        "retain mandatory three-source routes; no unapproved software-PRNG "
        "identifiers found"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

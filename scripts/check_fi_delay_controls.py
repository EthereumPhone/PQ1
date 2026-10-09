#!/usr/bin/env python3
"""Mutation controls for the FI delay-length path (#802, #832, #833, #835).

WHY THIS LIVES IN THE REPO
--------------------------
These controls have caught four real defects that the host tests passed
straight through, and they were twice lost to a cleaned scratchpad -- the same
way `build-evt-image.sh` was lost before it became a repo tool. A control that
is not durable is not a control.

WHAT A CONTROL IS FOR
---------------------
A green test suite proves nothing on its own: a test can assert something the
code does not do, or slice a window that no longer reaches its own assertions,
or name a constant that merely appears in a log line. Each mutation below
breaks ONE mechanism and demands that EXACTLY the named test(s) go red. A
mutation that changes nothing means the test is vacuous; a mutation that reds
something unexpected means an expectation is wrong.

Run: python3 scripts/check_fi_delay_controls.py   (or `make fi-delay-controls`)
"""
import os
import re
import shutil
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Firmware RUSTFLAGS break host build scripts; that run would be void.
ENV = {k: v for k, v in os.environ.items() if k != "RUSTFLAGS"}

FILES = {
    "fi": "secure/src/fi.rs",
    "pool": "secure/src/fi_delay_pool.rs",
    "rng": "secure/src/hw/rng.rs",
    "crypto": "secure/src/crypto.rs",
}
SRC = {k: os.path.join(REPO, v) for k, v in FILES.items()}
BAK = {k: v + ".ctlbak" for k, v in SRC.items()}

P = "fi_delay_pool::tests::"
Z = P + "positive_a_zero_byte_is_drawn_past_rather_than_failing_the_operation"
ZL = P + "negative_take_never_returns_a_zero_length_delay"
FRESH = P + "positive_every_byte_a_full_fan_out_needs_is_served_fresh_and_distinct_slots"
UNARMED = P + "positive_an_unarmed_pool_defers_to_the_ordinary_path_without_counting_a_miss"
REFUSE = P + "negative_a_refusing_trng_leaves_the_pool_unarmed_so_behaviour_is_unchanged"
EMPTY = P + "negative_an_armed_but_empty_pool_counts_a_miss_and_defers"
SHORTFALL = P + "positive_a_shortfall_is_topped_up_in_place_rather_than_escalated"
WIPE = P + "negative_disarm_wipes_the_pool_so_no_length_outlives_its_guard"
TOPUP = P + "positive_replenish_tops_up_only_once_the_pool_has_run_low"

F = "secure_fi_pin_rng_pure_tests::fi_source_text::"
NOREUSE = F + "negative_rng_byte_never_substitutes_a_reused_delay_length"
DELEG = F + "negative_wait_random_delegates_to_shared_crate_on_prod"
STRONG = F + "negative_rng_byte_does_not_route_through_rng_strong"
RELOCK = "secure_crypto_glue_under_test::pure_tests::positive_crypto_relocks_on_confirmed_fault_only"

# (file, description, exact-anchor, replacement, tests that MUST go red)
MUTATIONS = [
    # ---- the pool (#832, #835 C2) ----
    ("pool", "take ignores ARMED",
     "if !ARMED.load(Relaxed) {\n        return None;\n    }",
     "if false {\n        return None;\n    }",
     {UNARMED, REFUSE}),
    ("pool", "take serves one constant byte (the #832 defect itself)",
     "let b = POOL[n - 1].swap(0, Relaxed);",
     "let b = { let _ = n; 0x5Au8 };",
     # The zero-byte test reds too, and correctly: a constant 0x5A means no
     # zero ever appears, so its ZERO_SKIPS expectation fails. The first
     # version of this expectation named only FRESH and was under-specified.
     {FRESH, Z}),
    # THE bug the EVT unit found and nine host tests did not.
    ("pool", "a zero byte fails the draw again (the silicon-found bug)",
     "ZERO_SKIPS.fetch_add(1, Relaxed);\n                continue;",
     "return None;",
     {Z}),
    ("pool", "a zero byte is handed out as a zero-length delay",
     "if b == 0 {\n                // A legitimate 1/256 TRNG zero",
     "if false {\n                // A legitimate 1/256 TRNG zero",
     {Z, ZL}),
    ("pool", "exhaustion is silent",
     "MISSES.fetch_add(1, Relaxed);\n                if refilled || !refill_in_place() {",
     "if refilled || !refill_in_place() {",
     {EMPTY, SHORTFALL}),
    ("pool", "a refusing TRNG still arms",
     "if n > 0 {\n            ARMED.store(true, Relaxed);\n        }",
     "ARMED.store(true, Relaxed);",
     {REFUSE}),
    ("pool", "in-place top-up removed (a shortfall would fail the operation)",
     "if refilled || !refill_in_place() {", "if true {",
     {SHORTFALL}),
    ("pool", "disarm leaves the bytes behind",
     "for slot in &POOL {\n            slot.store(0, Relaxed);\n        }", "",
     {WIPE}),
    ("pool", "replenish re-draws even when full",
     "if ARMED.load(Relaxed) && AVAIL.load(Relaxed) >= REFILL_BELOW {\n        return;\n    }", "",
     {TOPUP}),
    # ---- the no-reuse policy and its sink (#833, #835) ----
    ("fi", "the no-length arm halts again (the pre-#835 sink)",
     "None => poison_delay_source(),", "None => loop { core::hint::spin_loop() },",
     {DELEG}),
    ("fi", "the no-length arm reuses a byte (the pre-#802 defect)",
     "poison_delay_source();\n        None", "return Some(FI_DELAY_BOOTSTRAP);",
     {NOREUSE}),
    ("fi", "wait_random stops delegating to the shared loop",
     "Some(b) => pqsigner_fi::wait_random_loop(|| b),", "Some(_b) => {},",
     {DELEG}),
    ("fi", "widen the conditioning-window exemption to always-on",
     "if crate::rng::fixed_delay_permitted() {", "if true {",
     {NOREUSE}),
    ("fi", "drop the retry bound (refuse on the first error)",
     "while attempt < FRESH_DELAY_ATTEMPTS {", "while attempt < 0 {",
     {NOREUSE}),
    ("fi", "swap the non-substituting draw for the substituting one",
     "if let Some(b) = crate::rng::try_byte_nonsecret() {",
     "if let Some(b) = Some(crate::rng::byte_nonsecret(0)) {",
     {NOREUSE, STRONG}),
    # ---- the fi-2 DoS exclusion ----
    ("crypto", "the poison refusal relocks (violating the fi-2 DoS exclusion)",
     "    if crate::fi::delay_source_failed() {\n        opt_rand_buf.zeroize();",
     "    if crate::fi::delay_source_failed() {\n        #[cfg(not(test))]\n"
     "        crate::nsc::zeroize_sensitive_state();\n        opt_rand_buf.zeroize();",
     {RELOCK}),
]


def run():
    p = subprocess.run(
        ["cargo", "test", "-p", "sphincs-tz-secure", "--tests",
         "--features", "mock-se", "--no-fail-fast", "--quiet"],
        cwd=REPO, env=ENV, capture_output=True, text=True, timeout=2400)
    out = p.stdout + p.stderr
    return ("test result:" in out), set(re.findall(r"^(\S+) --- FAILED", out, re.M)), out


def restore():
    for k in SRC:
        shutil.copyfile(BAK[k], SRC[k])
        # mtime FORWARD, or cargo keeps serving the mutant.
        os.utime(SRC[k], None)


def main():
    for k in SRC:
        shutil.copyfile(SRC[k], BAK[k])
    log, bad = [], False
    try:
        built, failed, out = run()
        if not built or failed:
            print("BASELINE NOT GREEN:", sorted(failed))
            print(out[-3000:])
            return 1
        log.append(f"baseline: GREEN")

        for tgt, name, old, new, expect in MUTATIONS:
            src = open(BAK[tgt]).read()
            if src.count(old) != 1:
                log.append(f"SKIP [{name}] -> anchor matches {src.count(old)}x, not 1")
                bad = True
                continue
            open(SRC[tgt], "w").write(src.replace(old, new, 1))
            os.utime(SRC[tgt], None)
            built, failed, out = run()
            if not built:
                log.append(f"VOID [{name}] -> did not compile; no test was exercised")
                bad = True
            elif failed == expect:
                log.append(f"ok   [{name}]")
            else:
                log.append(f"BAD  [{name}] -> expected {sorted(expect)}, got {sorted(failed)}")
                bad = True
            restore()
            built, failed, out = run()
            if failed:
                log.append(f"RESTORE FAILED after [{name}]: {sorted(failed)}")
                bad = True
                break
    finally:
        restore()
        built, failed, out = run()
        ok = built and not failed
        log.append("final restore: " + ("GREEN" if ok else "NOT GREEN"))
        bad = bad or not ok
        for k in SRC:
            if os.path.exists(BAK[k]):
                os.remove(BAK[k])

    print("\n".join(log))
    print(f"\n{len(MUTATIONS)} mutations; " + ("REVIEW" if bad else "ALL_OK"))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())

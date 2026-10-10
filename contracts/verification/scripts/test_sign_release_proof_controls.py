#!/usr/bin/env python3
"""Reuse the independent, typed fixture runner for release caller refinements."""
import test_sign_whole_proof_controls as runner

runner.FAMILIES = {
    "release-exit": (["SignReleaseLoop"], "releaseLoopExit", [
        ("discard-signature", "| .done (sig,_,_) => .done sig",
         "| .done (sig,_,_) => .done (Array.repeat 4008#usize 0#u8)"),
    ]),
    "release-caller": (["SignReleaseSpec"], "releaseCallerComposition", [
        ("wrong-message", "fors.grind_r sk seed root msg opt", "fors.grind_r sk seed root sk opt"),
        ("discard-optrand", "fors.grind_r sk seed root msg opt", "fors.grind_r sk seed root msg none"),
    ]),
    "release-suffix": (["SignReleaseSpec"], "releaseAfterForest", [
        ("skip-layer-zero", "{start := 0#u32,", "{start := 1#u32,"),
        ("skip-layer-one", "UScalar.cast .U32 params.D", "UScalar.cast .U32 1#usize"),
    ]),
    "release-composition": (["SignReleaseSpec"], "pureWholeSignNodes", [
        ("wrong-root-input", "pureGrindR sk msg seed root opt", "pureGrindR sk msg seed seed opt"),
        ("wrong-forest-secret", "forsSignerSecrets s sk ht indices", "forsSignerSecrets s s ht indices"),
        ("wrong-layer-index", "(Array.to_slice (forsSignerRoots s sk ht))) ht",
         "(Array.to_slice (forsSignerRoots s sk ht))) 0#u32"),
    ]),
}

if __name__ == "__main__":
    runner.main()

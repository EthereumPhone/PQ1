# Integration review reconciliation — first wave

Target b143b10f06799f56608acc97802cd2bedaf2b1f7, tree 2c9399a504efa5ac178e818ae670e814ab95cbeb; base ab9e9049a5a8c8d088966d02b7ff9a5714ae678a.

SOL FIX: absent heavy mutation target CONFIRMED by `make -n verify-kani-mutation-heavy` (exit 2, no rule). Missing nightly protocol self-test CONFIRMED by the workflow and Makefile invocation chain, contrary to the checker's documented CI contract. Both corrected in 6bc23f22; regressions exercise the real Make entrypoints and reject removal of the pinned CI self-test.

Opus GO: no findings. Its receipt acknowledges diff-stat-only coverage of older proof-project changes and a disregarded archive search match. Earlier identical-project proof receipts and fresh Verity/TLC/protocol/proof-mutation checker controls supply the explicitly recorded coordinator evidence; this was not full independent proof replay of all FV systems.

Kimi GO with a medium robustness finding: optimized Python removes helper verdict assertions. CONFIRMED with a disposable always-success EasyCrypt stub: optimization disabled exits 1, enabled exits 0 and prints the success marker. The pinned Docker image environment has no PYTHONOPTIMIZE and the wrapper does not forward host values, so this does not reproduce a bypass of the current container gate. Nevertheless corrected in the same user-authorized findings batch; new regressions require rejection under optimization levels 0, 1 and 2. Compiler subprocesses did still execute before the correction; the removed checks, not execution itself, caused the false green.

Issue #687 tracks this correction. All original reports are retained unchanged. Main wave launched together; SOL's first attempt had only nested-namespace startup failures and was terminated for its one allowed same-model retry. Completed reports were within 900 seconds and 800 words, identical prompt SHA, and the target remained clean. No provider refusal was retried. The new source/gate identity requires its own fresh review and full replay; the interrupted first replay is not accepted proof evidence.

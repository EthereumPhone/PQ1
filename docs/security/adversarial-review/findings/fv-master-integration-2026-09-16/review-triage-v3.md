# Corrected-source review reconciliation (eb18115e)

The simultaneous Astra / Opus / Kimi wave completed inside 900 seconds and 800 words per leg, with identical prompts and unchanged target identity. Raw reports are retained; Astra and Kimi returned GO contingent on the separately running proof replay. Opus returned FIX.

Both Opus findings are addressed in `557d7216f4e711ee95daba779bdc1a835951f14c`:

- HIGH: coordinator reproduction of the quoted-restriction/comment decoy returned no old source-gate failures while Tamarin 1.12.0 parsed the live pinned lemma as the tautology. The correction rejects comment delimiters in every quoted token, including unpinned restrictions, and adds the exact decoy plus delimiter controls.
- MEDIUM: the three Python assertions in the protocol self-test were confirmed and replaced by explicit HarnessError conditions. Nine targeted controls demonstrate that wrong counts, no-op edits and wrong failure reasons raise the required errors under optimization modes 0, 1 and 2. Normal self-tests also pass under all three modes.

All three current Tamarin source formula inventories still match their unchanged baselines; the fresh live Tamarin replay passes all eight lemmas in three models. The v4 change touches only `scripts/check_protocol_models.py`. EasyCrypt inputs, wrapper and gate callers are byte-identical to eb18115e, so its ongoing full replay of identity `623ad0710d73000a1c693049b8933813` continues and may be reused for those exact inputs. It must finish green before publication.

Material protocol-checker corrections require fresh review of 557d7216. The owner-selected Astra replacement persists; Opus and Kimi remain the other two reviewers. No risk acceptance, master push, numerical security claim or research-theorem promotion is inferred. #509 stays deferred.

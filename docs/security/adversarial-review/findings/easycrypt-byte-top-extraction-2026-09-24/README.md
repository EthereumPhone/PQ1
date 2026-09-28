# Top-layer extraction in the actual C10 byte game

Source-merge receipt for `0feb5137262318961c57b96fc5773cbc72ae0885`, tree `cf8db39d9c31f53af7ec514196aeeb5514e62cb5`, based on
`ef9102f8e5c21c14558035306d8dc839420b786c`. The later receipt commit changes no proof or gate input.

Arbitrary successful complete byte-game verification now yields a top WOTS reference opening from the earlier actual key-generation history, outside the already charged public-node collision and zero-node events. The reference may be selected after adaptive calls. The result binds the recorded message hash, supplied top signature, original public seed/root and final new-message guard. The same initialized-game hop retains its successful-forgery residual. The lower-tree value is existential; lower-layer/FORS extraction and new probability charges remain open, and this bridge alone supplies no smaller numerical bound.

## Validation

- [Full cold replay](full-gate.log): `393` direct targets,
  `393` default-CLI targets and `304` controls pass.
  Pinned r2026.02 image, network disabled, read-only source and disposable
  cold proof copy; no budget change. Exit 0 in 9587.3 seconds.
- Started 2026-09-24T13:23:33.470140+00:00; finished 2026-09-24T16:03:20.771375+00:00.
  Input identity `dfffe3f932c98a5ae98c9ae0075d2868` stayed unchanged across the run.
- `2796` pins, `2438` statements, `147` roots,
  `2107` census rows and `357` manual source bindings.
  No new project axiom, admit or unrealized clone assumption.
- All `18` repository-only focused proof-driver checks and
  `19` new controls match the enrolled sources and expected reasons.
  Eleven checker regression groups, static contract and source binding pass.
- [Opus](opus-report.txt) returned GO. [Astra](astra-report.txt) reported GAP
  solely because the required cold replay was still pending; both reported no
  source-level findings. The [coordinator record](review-summary.json) resolves
  that exact evidence gap with this unchanged-source replay and preserves both
  raw verdicts and runtime/model evidence. Standing owner instructions replace
  SOL with Astra and omit Kimi. No source change or additional reviewer turn
  was required.
- The [hosted CI record](hosted-ci-triage.json) separately identifies any
  unchanged baseline failures. A local proof-gate result is not an overall
  green-CI claim.

These are classical manual-model statements. Rust/model fixture agreement
is tested correspondence, not extraction. No concrete SHA-256 theorem, QROM,
96-bit deployed security or hardware/production authority is claimed.
Adaptive opening coverage and component forgery reduction remain under
#100/#295; #509 stays an owner-triggered deferred combined playbook pass.

## Control and identity evidence

The 19 new controls comprise six positives, five scope probes and eight
rejected exact theorem applications. Rejection establishes only the declared
diagnostic. Removing the root premise leaves an unclosed proof obligation;
its expected diagnostic was corrected and the unchanged control rerun. The
[diagnostic record](control-diagnostic-correction.json) preserves that distinction.
No rejection proves falsity, necessity or tightness. The concrete positive
examples cover leaf indices 0/511, the excluded index 512, and maximum-index
two-layer geometry; they are not complete-game nonvacuity evidence.

The preflight command rejected the old input identity after deliberate
enrollment. Its checker, source-binding and static stages passed. The identity
was explicitly updated in the candidate; the separate identity check and
full frozen cold replay pass at the new value.

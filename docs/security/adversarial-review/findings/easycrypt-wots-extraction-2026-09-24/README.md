# Actual WOTS and Merkle-layer opening extraction

Source-merge receipt for `444c1d4aca22d7b676a0b64b4be1fc13881c813d`, tree `2cbbf5202001e3c0c8fff788b84d4414c594263e`, based on
`faa06863f908adf14c3f96150dc0fb5e16c6c290`. The later receipt commit changes no proof or gate input.

Actual WOTS recovery matching a retained key yields its reference-chain opening, outside the already charged public-node collision and zero-node events. The verifier predicate uses the full u32 counter domain and has a forward replay theorem. Actual Merkle-layer recovery composes this result; actual key-generation leaf and Merkle-builder harnesses supply references, with probability-one termination. The complete adaptive byte-game forgery residual remains open.

## Validation

- [Full cold replay](full-gate.log): `384` direct targets,
  `384` default-CLI targets and `285` controls pass.
  Pinned r2026.02 image, network disabled, read-only source and disposable
  cold proof copy; no budget change. Exit 0 in 9345.35 seconds.
- Started 2026-09-24T10:15:11.978114+00:00; finished 2026-09-24T12:50:57.325925+00:00.
  Input identity `6df326d66261b1b266bbc2688b2ec799` stayed unchanged across the run.
- `2772` pins, `2417` statements, `142` roots,
  `2104` census rows and `348` manual source bindings.
  No new project axiom, admit or unrealized clone assumption.
- All `26` repository-only focused proof-driver checks and
  `22` new controls match the enrolled sources and expected reasons.
  Eleven checker regression groups, static contract and source binding pass.
- [Astra](astra-report.txt) and [Opus](opus-report.txt) returned GO without
  findings in one simultaneous bounded wave. The [coordinator record](review-summary.json)
  retains exact runtime/model evidence. Standing owner instructions replace
  SOL with Astra and omit Kimi. The cold-replay requirement is now resolved.
- The [hosted CI record](hosted-ci-triage.json) separately identifies any
  unchanged baseline failures. A local proof-gate result is not an overall
  green-CI claim.

These are classical manual-model statements. Rust/model fixture agreement
is tested correspondence, not extraction. No concrete SHA-256 theorem, QROM,
96-bit deployed security or hardware/production authority is claimed.
Adaptive opening coverage and component forgery reduction remain under
#100/#295; #509 stays an owner-triggered deferred combined playbook pass.

## Interrupted replay

The first cold replay was interrupted by a host crash and has no passing
receipt. Its interruption and archive location are retained in
[interrupted-gate.json](interrupted-gate.json). Both bounded reviewers had
already finished; their report, prompt and raw-runtime hashes were checked
after reboot. This receipt uses the fresh complete cold replay only.

## Control and identity evidence

The 22 new controls comprise five positive checks, eight scope probes and
nine exact-statement mismatches. Rejection does not establish logical falsity
or necessity. The positive examples cover unequal retained inputs with equal
outputs, unequal rows with equal flattenings and a wire counter outside the
signing-search range; each proves only its stated property.

The preflight command first rejected the old committed input identity after
the deliberate enrollment change. Its checker, source-binding and static
checks passed. The identity was explicitly updated in the candidate; the
separate identity check and full frozen cold replay pass at the new value.

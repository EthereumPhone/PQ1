# Bounded WOTS game probability bridge — 2026-09-22

Source-merge review and the mandatory full gate pass for
`2c9be6fc596f498946d2789f126f13190422baa9` / tree `c21fc1fd7d5612bcc12152d2a2f6317794170a36`, compared with
`d947c04780a156853160bef32882b158518c90b7`. Input identity: `082bc8c6b54bd13642f7cb526e80d429`.
The candidate is published in [PR #718](https://github.com/EthereumPhone/PQ1/pull/718).
This receipt establishes source/proof evidence, not production or shipment authority.

`C10BoundedGame.bounded_win_le_total` relates the guarded bounded and existing
total WOTS games for the same admissible, terminating adversary, including
adaptive queries. Failure is absorbing and contributes no bounded-game win.
The comparison assumes neither IID sampling nor universal search success.
`C10BoundedReduction.bounded_interactive_D1` composes the existing conditional
WOTS reduction, retaining N2 and its original collection-tweak well-formedness
premise. Those premises, member-aware hypertree composition, real shared-hash
probability, and numerical resource bounds remain open under #100/#295.

Validation on the exact source:

- Both drivers check all 68 files directly; all 56 roots and their local dependencies are included.
- All 67 registered controls pass, including rejection of the two new invalid variants: erasing the failure guard and clearing failure after a query.
- The source-bound Rust transcript and digit tests pass. Rust and Lean source inputs are unchanged from the September 21 correspondence batch; no fresh extraction or cross-assistant theorem is claimed.
- The gate checks 1,339 declaration pins, 1,208 statements and the unchanged 1,730-row assumption/module census. No new project axiom or admit is added. The broader legacy FORS admit and its containment boundary are unchanged.
- Image `ghcr.io/easycrypt/ec-test-box@sha256:bf1a13e73d7fe18fccdcc91d1532c1a5a17cfc3a6a2a34619248c4f2710d0bb3` runs with no network, a read-only source mount and a disposable copy; caches are purged. The [full raw gate](full-gate.log) and [execution times](full-gate-result.json) identify the completed run. Host static gate regressions also pass.

Astra and Opus returned **GO**, with no findings. The initial simultaneous
launch and the single permitted Astra mechanical retry completed in
412.543 seconds total, below the 900-second cap; reports
are 23 and 582 words, below 800 each. The prompt bytes were identical.
Astra was requested as `gpt-6-astra` / `ultra`; Opus as `opus` / `xhigh`, with
runtime model `claude-opus-5` (the CLI also records auxiliary Haiku usage).
Astra substitutes SOL and Kimi is omitted under standing owner decisions.
The initial Astra commands could not create a nested Bubblewrap namespace;
they read no source. Its one retry used legacy Landlock inside the unchanged
outer read-only candidate/Git mounts. This was a mechanical failure, not a
provider policy refusal. The raw reports and launcher manifests are retained.
Both manifests report a clean, unchanged target. They enforce candidate/Git
immutability; they do not claim complete host isolation or OS-enforced mutual
blindness. Neither reviewer independently ran the full prover.

The [interrupted first run](full-gate-interrupted.log) is **not green**: it had
68 successful compilations and 31 successful CLI replays before Docker
terminated it with exit 143. Docker restarted at 2026-09-22 10:04:59 UTC.
The fresh completed run supplies the mandatory full receipt; results are not
spliced across the interruption. Claude authentication was restored before
the review wave began.

Broad PR CI still has the known baseline failures on unchanged inputs:
[#660](https://github.com/EthereumPhone/PQ1/issues/660) (TRNG ledger anchor),
[#711](https://github.com/EthereumPhone/PQ1/issues/711) (curation/proto receipt
and fuzz lockfile), and [#717](https://github.com/EthereumPhone/PQ1/issues/717)
(Foundry installer executing a binary through bash). Their job logs were read;
[CI disposition](ci-disposition.json) records paths and decisive lines.
G1 gate enforcement, Lean FV, secure host tests, firmware linking, QEMU, Miri
and cargo-vet pass. This receipt does not label all repository CI green.

Only receipt/status links are added after the reviewed proof commit. All 68
proof-file hashes are bound in [evidence.json](evidence.json); the certification
input identity remains unchanged. #509 stays the deferred owner-triggered
combined playbook pass. PR #718 records landing under standing authorization
and the final branch status; #100/#295 retain the research handoff.

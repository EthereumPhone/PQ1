# Final correction review — Astra / Opus / Kimi

The owner instructed “Use astra instead of sol” for the unavailable SOL leg.
Astra's replacement review found two concrete checker defects, reproduced in
`astra-reproductions.json`: a commented/attributed Tamarin formula decoy and an
EasyCrypt declaration-name alias. The alias correction binds canonical names
and unique parsed declaration identities. It changes the split input identity
to `623ad0710d73000a1c693049b8933813` without changing proof sources or assumptions.

Subsequent required reviews found additional Tamarin lexical discrepancies.
The final correction removes that general-purpose lexical scanner and checks
SHA-256 of each complete, fixed model source before formula extraction or prover
invocation. It retains independent formula and verdict inventories. Any source
edit, including comments or preprocessing, now requires explicit review and
re-baselining. This is a fixed-source boundary, not a general Tamarin parser.
The reproduced variants remain negative controls; optimized Python runs retain
explicit failure checks.

Final source: `816db25c4d161544d2ba74b988efd50942167d0d`.
Tree: `050cafedbcb138388636551687710f67c69a9368`.
Base: `ab9e9049a5a8c8d088966d02b7ff9a5714ae678a`.

| Reviewer | Requested model / effort | Seconds | Words | Verdict |
|---|---|---:|---:|---|
| Astra | gpt-6-astra / ultra | 594.792 | 29 | GO |
| Opus | opus / xhigh | 186.947 | 555 | GO |
| Kimi | kimi-code/k3 / max | 298.528 | 345 | GO |

All three fresh reviews used identical prompt bytes, a 900-second CLOCK_BOOTTIME
bound (includes suspend), and an 800-word cap. Launch skew was 0.001131 seconds.
No drift occurred. Report, prompt, runtime and stderr hashes were independently
verified against the raw artifacts. The raw compact reports and manifests are
preserved; larger runtime streams and provider stderr remain in the recorded local scratch
paths. Provider diagnostics are not copied into the publication; their hashes
remain in the manifests.
The source and common Git metadata were mounted read-only. This supplies local
candidate immutability and procedural non-disclosure, not strict same-UID host
isolation or remote model attestation. Opus runtime also reports auxiliary Haiku
usage; no extra coordinator reviewer was launched. The explicitly preflighted
CLI version boundary and legacy Landlock setting remain in the manifests.

No final reviewer reported a finding; the coordinator has no reproduced blocker.
All reviewers identified the declared executable runs as pending at prompt time.
The frozen final Tamarin replay subsequently passed all three models/eight
lemmas. Full EasyCrypt replay completion is recorded separately in the final
completion receipt; a GO report alone does not discharge that gate.

Earlier FIX reports are superseded only by the corrected and re-reviewed source,
not by majority vote. Earlier timeout receipts remain historical. No missing-leg
risk acceptance is inferred. #688 retains the optional notes, #509 retains the
owner-triggered broader assurance pass, and #100 retains the research frontier.

# Accepted-history C10 milestone — September 23, 2026

Source-merge receipt for `e45e977a76867b2e72bf5e2e143be6baba04d537`, tree `af7f51132c5459b8480782dcfbadb75409e4872f`, based on
`d3e6dd0303888010ef1425355031b1e4c06fd058`. The later receipt commit changes no
proof or gate input. The independent dirty board worktree was not used here.

The bounded nonadaptive hypertree now has a checked four-term challenge bound
without N2 or a grind-failure summand. Actual cube construction, recorded leaf
queries, transcript shape and event-preserving game hops establish that accepted
public histories exclude grind failure. Original theorem contracts remain
compatibility corollaries. The observer is private; target-cap, address/member/
encoder separation and termination requirements remain explicit.

The shared raw-input model preserves cached answers and final history. The
secret-keyed R/H_msg loop uses the deployed layouts and truncation, retains
repeated inputs and makes at most 20 million raw calls. Exact FORS acceptance
mass applies only to a fresh query. These are classical ideal-oracle foundations.

## Evidence

- Full cold `make -C contracts/verification verify-easycrypt-split`: pinned
  r2026.02 image, disposable copy, network disabled, source read-only, caches
  purged; 90 files pass direct compilation and CLI iteration; 98 controls pass.
- Run: 2026-09-23T08:09:46.297261+00:00 to 2026-09-23T10:23:48.087171+00:00;
  8041.79 seconds, exit 0. [Raw replay](full-gate.log).
- Input identity `d1d88a7319995db0b21c47869c79fa8d`; 1,561 unique pins, 1,374 statements,
  78 roots, 1,813 raw census rows and 47 manual source-bound inputs.
  No new project axiom, admit or clone assumption. The broader cone's legacy
  admit remains outside the headline environments.
- [Focused receipts](focused-receipts.json) bind both drivers for all 13 changed
  proof files to source SHA-256 and raw local log hashes. Four Rust transcript
  checks pass in the complete replay; this is manual correspondence, not extraction.
- Eight new semantic controls exercise the exact headline, observer privacy,
  accepted-history requirement, fresh versus cached mass, replay draw count,
  retained successful history and headline scope.

## Review and remaining work

[Opus](opus-report.txt) returned GO with no findings.
[Astra](astra-report.txt) returned GAP solely because the cold replay was still
pending; its source review found no concrete blocker. The unchanged-source
successful replay resolves that gate. The raw GAP verdict is preserved.
The [initial cold run](initial-cold-failure.log) passed all 90 direct targets,
89 CLI targets and 98 controls but rejected `C10CubeConstruction.nodes_input`
under the gate-default CLI budget. Focused runs had used a larger solver budget.
The correction proves the index bound before using it, with unchanged theorem
statements and gate limits; the corrected snapshot received a fresh review and
this full cold replay. [Initial result](initial-cold-failure-result.json).
Opus checked the source, including the explicit index-bound correction, but
did not rerun the proof toolchain itself. [Coordinator disposition](review-summary.json).

Astra ultra replaces SOL and Kimi is omitted under standing owner instructions.
The initial Astra runtime could not execute source-read commands because nested
Bubblewrap failed. Its sole mechanical retry used legacy Landlock under the same
outer read-only mounts, unchanged prompt and original 15-minute deadline. Runtime
manifests preserve versions, times and report hashes; neither review was extended.

The full shared-oracle scheme/reduction simulation and meaningful quantitative
ITSR/EUF-CMA bounds remain open under #100/#295. The legacy uncosted ITSR game
admits a probability-one countermodel. Later external secret-prefix research is
not covered by this receipt. #509 remains the deferred combined playbook pass.
No QROM, SHA-256 independence, hardware, firmware or shipment claim is made.

[Evidence identity](evidence.json) and [SHA256SUMS](SHA256SUMS) bind this receipt.

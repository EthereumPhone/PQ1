# PQSigner — STATUS (start here)

**Kani/EasyCrypt evidence correction (2026-09-16):** current gate scope and
research limits are owned by the [FV surface map](../contracts/verification/docs/FV_SURFACE_MAP.md),
rows 4 and 9. Historical draft receipts below do not certify the vendored split.
Implementation/review evidence: [remediation record](security/adversarial-review/findings/fv-evidence-remediation-2026-09-16.md).

**EasyCrypt research update (2026-09-23):** accepted public histories now
remove the grind-failure charge from the bounded nonadaptive hypertree theorem.
A persistent raw-input oracle now covers the complete adaptive byte-session
model and its costs. The
[quantitative foundations](../contracts/verification/easycrypt/c10-port/QUANTITATIVE-FOUNDATIONS.md)
add exact-coordinate replay accounting and accepted-output bounds for the
memoized grinder and complete signer. The
[complete-session history results](../contracts/verification/easycrypt/c10-port/COMPLETE-SESSION-HISTORY.md)
establish new-message freshness and account for repeated signing contexts.
The [raw authentication-path results](../contracts/verification/easycrypt/c10-port/RAW-PATH-CORRESPONDENCE.md)
connect actual Merkle/FORS recovery to recorded reference paths and explicit
node-collision events. The
[actual construction results](../contracts/verification/easycrypt/c10-port/RAW-BUILDER-PATHS.md)
supply the reference witnesses and actual FORS secret provenance, and prove
signing/recovery equality to the tree root computed during signing.
The [WOTS component](../contracts/verification/easycrypt/c10-port/RAW-WOTS-CORRECTNESS.md)
and [complete FORS forest](../contracts/verification/easycrypt/c10-port/RAW-FOREST-CORRECTNESS.md)
now have actual sign/recover correctness proofs, with bounded WOTS failure
and the special last FORS tree explicit. The
[full honest-correctness result](../contracts/verification/easycrypt/c10-port/RAW-BYTE-SIGNER-CORRECTNESS.md)
now connects actual key generation, complete signing, the exact byte codec
and verification against the earlier root, with bounded signing failure explicit.
The [shared-oracle correctness transfer](../contracts/verification/easycrypt/c10-port/RAW-PHYSICAL-HONEST-CORRECTNESS.md)
now bounds honest byte-error probability. The
[public-node collision and zero-node charges](../contracts/verification/easycrypt/c10-port/RAW-ZERO-NODE-CHARGE.md)
apply to the actual byte game while retaining its remaining forgery event.
The [reverse WOTS recovery result](../contracts/verification/easycrypt/c10-port/RAW-WOTS-EXTRACTION.md)
now derives reference chain openings from matching WOTS/layer recovery,
including actual key-generation and Merkle-builder comparison harnesses.
The [byte-game top-layer bridge](../contracts/verification/easycrypt/c10-port/RAW-BYTE-TOP-EXTRACTION.md)
now derives a top reference opening from arbitrary successful complete
verification after adaptive calls, using the earlier key-generation history.
The [subtree bridge](../contracts/verification/easycrypt/c10-port/RAW-SUBTREE-EXTRACTION.md)
now links both actual verifier layers and separates unrecorded top messages
from paired WOTS openings, without assigning either case a numerical charge.
Adaptive accumulated opening coverage, the complete byte-game component
reduction and numerical end-to-end forgery bounds remain open.
See the
[current artifact boundary](../contracts/verification/easycrypt/c10-port/README.md)
and [research obligations](verification/easycrypt-euf-cma-port-feasibility-2026-07.md#2026-09-23-accepted-history-composition-and-persistent-raw-oracle).
The [merge receipt](security/adversarial-review/findings/easycrypt-accepted-history-2026-09-23/README.md)
binds the corrected cold replay and bounded Astra/Opus review to the source.

> **The front door.** Read this first. It's a **router, not an encyclopedia**: §0 maps *where the truth
> lives* (one owner per concern — everyone else links); §A–§D are the **security/verification frontier**,
> the one slice this file owns directly. Detail lives in the linked docs, not here.
>
> **Freshness.** §A–§D are a snapshot **reconciled against the repo on 2026-06-17** (`security-frontier-reconcile`
> workflow). They are only trustworthy if re-reconciled — a stale STATUS is worse than none. Re-run that
> workflow over a slice before relying on its rows, and trust the **evidence pointer, not the prose**.
>
> **Work-tracking migration (2026-07-19).** `docs/work-todo.md` and
> `docs/production-todo.md` are **retired**: every open item moved to GitHub
> Issues (`EthereumPhone/PQ1`) under the `source:work-todo` /
> `source:production-todo` labels (plus `priority:*`, `surface:*`,
> `ship-blocker`). Both files survive as redirect stubs and in full at
> `docs/archive/work-todo-retired-2026-07-19.md` and
> `docs/archive/production-todo-retired-2026-07-19.md`. Every
> `work-todo`/`production-todo` citation in the dated rows below is
> historical and resolves through those archives; the live action list is
> the tracker, not any file in this repo.
>
> **Scoped rollback/process/SE update (2026-07-14).** This correction
> reconciled §0's planning/rollback owners, the full AT-A-GLANCE summary, §A
> `FW-RB`, `S-1..S-7`, `S-4`, `HIGH-1`, `MED-2`, and Claim 3, plus their
> affected §B/§D mirrors. Rollback evidence is Draft 1.1 commit `93da7567`,
> SHA-256 `743bc156…3d7ad`, its bounded deletion receipt, and the planning-
> workflow review; `MED-2` was checked against commit `f8effd45`. No other
> §A–§D row was refreshed, and this does not supersede the 2026-06-17 full-
> frontier snapshot.

> **FV correction — 2026-07-15.** The current full-stack adversarial review is
> [`fv-full-stack-2026-07-15-coordinator.md`](security/adversarial-review/findings/fv-full-stack-2026-07-15-coordinator.md),
> with the nine-surface inventory in
> [`FV_SURFACE_MAP.md`](../contracts/verification/docs/FV_SURFACE_MAP.md) and the
> sourced expansion roadmap in
> [`formal-verification-assurance-expansion-2026-07-15.md`](verification/formal-verification-assurance-expansion-2026-07-15.md).
> Individual Lean results remain scoped and kernel-valid, but current
> end-to-end assurance promotion is blocked by extraction freshness, the actual
> signed-digest bridge, extracted closure policy, protocol-driver semantics,
> and EasyCrypt gate/parameter correspondence. EasyCrypt reproduced 10/21
> compiled with 11 skips and success; its imported WOTS theorem excludes C10's
> `log2_w=3`. UPDATE 2026-07-19: the EasyCrypt reproducibility defect is closed — the container gate (`make -C contracts/verification verify-easycrypt-docker`) compiled the full 21-file closure as targets with zero skips and three fired mutation controls on 2026-07-17 (receipt `contracts/verification/easycrypt/docker/GATE-RECEIPT-2026-07-17.log`); the C10-parameter (log2_w=3) and conditional-capstone residuals remain research, tracked in the c10-eufcma-port feasibility doc. **UPDATE 2026-07-25: the C10-parameter item is NOT a closable "residual" — it is a hard boundary.** Adjudicated at source with machine-checked receipts + two external reviewers: `log2_w=3`, the `len > len1` width, and `two_encodings` are **one coupled obstruction**, and the axiom is **unsatisfiable** at deployed `(w=8, len=43)` geometry, so relaxing the parameter enumeration is provably insufficient. Every EasyCrypt EUF-CMA claim in this file therefore holds **at MM45-admissible WOTS parameters (`w ∈ {4,16,256}`) only**; nothing is proven at deployed C10. This is not a defect in C10 (its non-injectivity is by design, paid for by S-TCR(Th+C)). See [`verification/easycrypt-euf-cma-port-feasibility-2026-07.md`](verification/easycrypt-euf-cma-port-feasibility-2026-07.md) UPDATE 2026-07-25d. UPDATE 2026-07-23: the source-derived Kani census is 173 harnesses / 27 files; mutation-enrolled files contain 162 / 21, with 11 / six outside and three of 43 groups full-only.
> No fresh full Kani campaign was run. V1 is legacy evidence; V4 versus V6
> remains an owner conflict, not a selected implementation target.

> **FV deep review + CI evidence gap — 2026-07-19.** A full executing adversarial review of the FV stack landed: [`security/adversarial-review/findings/fv-deep-review-2026-07-19-coordinator.md`](security/adversarial-review/findings/fv-deep-review-2026-07-19-coordinator.md) (13 findings) with the SOTA follow-up [`verification/fv-sota-newly-possible-2026-07-19.md`](verification/fv-sota-newly-possible-2026-07-19.md). Two rows matter for every reader of this file: (1) **all GitHub CI has been dead on an account billing outage since ~2026-07-16 (nightly since ~2026-06-30)** — every "CI-gated"/"nightly" claim in §B/§C is an evidence-suspended local-run claim until the first green run after restoration, and merges in that window proceeded without executed gates (use the local gate checklist in the findings doc F1); (2) `make verify-extraction-freshness`-equivalent (`check_extraction_freshness.py`) was red on master from 2026-07-18 (aa-userop drift), so extracted-Rust evidence newer than the 2026-07-16 re-pin is provisional. The 2026-07-16→17 FV expansion pilots (TLA+ page-123/combined-budget/PIN, Verus flash journal, crux-mir NS-ptr, TrustZone memory-map, signed-digest correspondence, 4 Lean quantitative/TCB refinements, HW-assumption ledger) are real and landed, but were not yet ingested into this file's rows — see the findings doc's positive-controls list. **UPDATE 2026-07-31 — row (1) is superseded, and the replacement is a different problem with a different fix.** The billing outage is over: `gh run list` shows the first post-outage success on **2026-07-29** (every run from 2026-07-10 through 2026-07-27 concluded `failure`; 2026-07-28 shows `action_required`), with runs executing on 2026-07-29/30/31. CI is therefore **no longer dark — it is RED**: of the 8 root workflows, `CI`, `Nightly (heavy gates)`, `ClusterFuzzLite (batch)` and `Lean FV (extracted §33 Aeneas)` are failing on master, while `Lean FV (SphincsCVerify)` and `A3.1 transcription lint` are green (`cflite-pr` and `security-review` are PR-only and have not been exercised). The distinction matters for how this file is read: a *dark* CI honestly reads as "evidence suspended", whereas a *red* CI still reads as "CI-wired" to anyone skimming §B/§C — so those rows stay **evidence-suspended**, now because the gates run and fail rather than because they never start. Known root causes so far: the `Host unit tests` job fails on a stale `Cargo.lock` input-hash pin in the ERC-7730 curation manifest (the same test passes locally, so CI is mutating `Cargo.lock` before the check — an argument for `--locked` on every CI cargo invocation), and `Invariant gates` aborts with "the live ledger is already failing". Tracked on issue #456 with the run-list receipt; the four-workflow breakdown is the remediation scope, not "restore billing".

> **Scoped PQ1 clear-signing correction — 2026-07-16.** The normative hard
> refusal remains unchanged. The first forced-blind architecture identity and
> the first current-refusal implementation identity both completed as
> **NO-GO**. The owner then selected exactly one attempt per successful PIN
> unlock, a 300-second forced-flow deadline, and the fail-closed host-denial
> residual on 2026-07-22.
> Earlier waves replaced Bloom authority and identified the full authenticated
> inventory, gas-proof ordering, state-codeword, and SysTick-bound precision.
> A subsequent frozen identity returned GPT-5.6 SOL **FIX** and Opus 4.8
> **GO**; Kimi K3 reached the 15-minute hard limit without a report, recorded as
> an honest gap rather than retried. The coordinator reproduced GPT's two
> hardware-boundary traces: non-secure IWDG reload could defeat a frozen tick,
> and a non-secure DMA master can observe output writes before a post-write
> scrub. The current correction limits eligibility to the derived refused-known
> set `F = K \ C` (3,214 tuples / 546 groups / 32,528 bytes), preserves hard
> refusal for all 1,366 clear-capable tuples on metadata omission, requires
> Secure-only IWDG ownership under [#79](https://github.com/EthereumPhone/PQ1/issues/79),
> and makes the `<299,000` pre-write check the irreversible release point backed
> by a mandatory measured sub-1,000 ms fixed 4,148-byte publication. It also pins
> PIN-only arming, rate/combined-cap/page-123 preflight, every 29-page grid, and
> tick/deadline behavior. The exact corrected architecture identity
> `6bda0fae` / tree `2135ad34` then received **GO with no blockers from GPT-5.6
> SOL, Opus 4.8, and Kimi K3**. The 2026-07-22 owner/maintainer decision
> authorizes its bounded Phase-C implementation only; P73K and the forced flow
> remain unimplemented, current hard refusal still controls, and no merge,
> production, shipment, flashing, or irreversible authority follows. The next
> boundary is the combined Phase-D implementation review. The materially
> remediated current tree is host, codegen and QEMU green; optimized
> development inspection is favorable but is
> not executable FI, a production profile, or a hardware stack/high-water
> bound. The remediated current-refusal phase completed its exact three-reviewer
> wave and landed; this does not authorize the separate forced-blind design.
> Follow the live campaign in GitHub issue
> [`#329`](https://github.com/EthereumPhone/PQ1/issues/329),
> the architecture record in
> [`clear-signing-pq1-forced-blind-architecture-2026-07-16.md`](security/adversarial-review/findings/clear-signing-pq1-forced-blind-architecture-2026-07-16.md),
> and the implementation assessment in
> [`erc7730-implementation-review-2026-07.md`](erc7730-implementation-review-2026-07.md).
> ERC-8176 provenance remains an independent production ship blocker; its
> advisory checker cannot authorize a production flip.

> **Scoped ERC-8176 code-half update — 2026-07-22.** `dbgen` now has a
> bounded, network-free verifier for the pinned open-draft EAS-v2 snapshot
> format. It authenticates the checkpoint, EAS account/code, EOA signer and
> revocation proofs, then applies the distinct-attester threshold to the exact
> resolved-JCS descriptor hash after known-call inventory. This is plumbing,
> not production authority: the canonical policy has no approved snapshot or
> real auditor population, remains `dev-unattested`, and the production gate
> must still fail. [#377](https://github.com/EthereumPhone/PQ1/issues/377)
> remains open for that external half; authenticated companion/root pairing is
> separately [#379](https://github.com/EthereumPhone/PQ1/issues/379).

> **Scoped ERC-7730 companion/release binding update — 2026-07-22.** `dbgen`
> now emits a canonical 256-byte `P73S` receipt for the exact catalogue root,
> blob/Bloom identities, schemas/counts, provenance, policy/curation inputs and
> compiler version. The selected receipt is retained in an allocated read-only
> final-secure-image section; `fwsign` extracts it from the ELF, proves it lies
> in the flattened image covered by the signed manifest, packages an exact
> sidecar, and rejects missing/malformed/ambiguous/mismatched identities before
> compatibility use. The companion reference authenticates the release and
> exact/minimum firmware version, then rebuilds the complete P730 Merkle tree
> and byte-compares every proof and the independently hash-bound known-call
> Bloom before enabling clear signing. Its report is compatibility-only:
> `erc8176_attestation=false`, `production_authority=false`. With no
> authenticated running-device query, automatic readiness is limited to a
> signed release the companion installed/recorded; unknown or externally
> changed identity fails closed. [#379](https://github.com/EthereumPhone/PQ1/issues/379)
> remains open for the production release/rollback/installed-identity boundary,
> independently of [#377](https://github.com/EthereumPhone/PQ1/issues/377).

> **Scoped PQ1 ERC-7730 implementation update — 2026-07-17; corrected
> 2026-07-18.** Bounded
> `nativeCurrencyAddress` lists, injective `nftName` collection identity, and
> constrained scalar `interpolatedIntent` are complete. Tag `0x42`
> authenticates one or two exact native-token sentinels while preserving the
> legacy scalar encoding. Dedicated tags `0x44` and `0x45` bind each NFT field
> to exactly one literal collection or static address path; the device always
> shows the exact token ID and complete collection address. A friendly name is
> optional and requires descriptor or exact-chain metadata authority; wildcard
> names never qualify. Authenticated TLV `0x46` enrolls only a terminal,
> always-visible static `amount`/`tokenAmount` placeholder and substitutes the
> exact value the trusted formatter successfully painted, including its bound
> unit/ticker; all ordinary field and identity pages remain. The compiler
> evaluates the 11 reviewed source/selector templates independently for every
> deployment. Of 78 candidate deployment formats, six have a static token
> identity covered by the exact device-verifiable ERC-20 metadata capability
> set (or a firmware-pinned native identity); the other 72 retain their static
> intent and emit no interpolation program. At completion of those Phase-C
> slices, the catalogue was 428 leaves / 340,215 bytes / root
> `c785f90c…b054d4`; the 4,542 known-call set and its receipt were unchanged,
> and omissions remained 281.
> Evidence is recorded in the
> [`work-todo` archive](archive/work-todo-retired-2026-07-19.md#pq1-erc-7730-productization-campaign--owner-direction-2026-07-16)
> row (work tracking moved to the
> [`source:work-todo`](https://github.com/EthereumPhone/PQ1/issues?q=label%3Asource%3Awork-todo)
> issues on 2026-07-19). Host suites, descriptor drift, and standalone plus canonical dual-SE
> STM32U585 `thumbv8m` checks are green. This is bounded implementation evidence,
> not the batched Phase-D adversarial review or production/ship authority;
> forced blind signing remains disabled under the 2026-07-16 decision above.

> **Scoped ERC-7730 V5 review / V9 completion receipt — 2026-07-18.** Frozen
> ref `review/erc7730-phase-d-20260718-v5` at
> `c70f6ffff34e739cbde78ecfec8cfc7f7253772b` completed the combined
> source-first Phase-D review and returned **DO NOT MERGE**. Blocking findings
> covered typed off-chain context and bool-gated confirmation authority; native
> `amount`/`tokenAmount` rounding collisions; non-injective enum labels;
> schema/compiler/runtime policy drift; empty visible labels, recursive
> validation, and formatter-aware `tokenPath` coverage; stale census/digest and
> non-atomic ERC-20/ERC-7730 drift checks; and incomplete batch tuple
> commitment.
>
> V6 remediates those findings without enabling blind signing. Its structured
> typed kinds render exact account/slot/wallet/deployment/budget context, while
> `personal_sign` retains its complete signer context. The frozen V6 RAW32
> transcript did not show the full wallet, exact response mode, or nested hash
> actually passed to C10; the bounded Phase-D remediation candidate adds those
> pages and proofs, but has no inherited merge recommendation. All four kinds
> carry one fail-initialized, domain-separated `OffchainConfirmReceipt` through
> two common gates before signing. IR schema v4 requires shared exhaustive
> `TerminalKind × FormatOp × params` validation in compiler and device,
> rejects schema v3, empty visible labels and over-depth nested structures, and
> applies formatter-aware identity coverage. Known-native dispatcher values and
> ordinary ERC-7730 `amount`/native `tokenAmount` values refuse before page or
> CFI publication when their signed value is not exactly representable. Batch
> authorization commits and independently reparses every ordered
> `(index,target,value,calldata)` tuple.
>
> V9 frozen generated identity: 428 leaves / 345,546 bytes / root
> `668a7964b4241ec0c2348d117adaa5e29e9b34d97286ef5d1c722cdda43d700a`;
> production blob SHA-256
> `45e57e54dd3d2ea33efd5819d95ac611a06a61e8e036bc2a13a170577a9f9eac`;
> E2E root
> `f8256e1bf1f41391eb337bf2ee3f85e59f738d0f6ed60c16eaa916e99842e4cf`;
> review artifact 1,389,653 bytes, SHA-256
> `6a8abeec1f228a58c60557d54a975086a033742db28f6542539d07129f5839b7`.
> Census: 162 harnesses / 26 files; 154 / 20 mutation-enrolled; eight / six
> outside; 40 groups (10 quick / 27 default / 3 full), 38 distinct enrolled
> harnesses.
>
> Final V9 evidence is green: the combined host package suites pass; secure
> mock-SE suites pass 2245/0 under both no-default and
> `erc7730-dev-unattested`, with one diagnostic test ignored; descriptor drift,
> census, the scoped Kani harness and exact enrolled mutation pass; and the
> strict linked Thumb profile remains within FLASH/static-RAM/stack margins.
> Commit `870cb113800235b47ca8a22e6c5a853e143516b8`, tree
> `3e5492d1c34d623820899bf16d1563a6d8a90ad2`, is retained at
> `review/erc7730-phase-d-20260718-v9`; the simultaneous GPT-5.6 SOL, Opus 4.8,
> and Kimi K3 fast review returned three **GO** verdicts with no findings, after
> which that identity landed on `master` and was pushed. The exhaustive
> combined playbook lock-in is explicitly deferred to the future
> owner-triggered item (`source:work-todo` issues); session restart does not activate
> it. This grants no production, shipment, or forced-blind authority.

> **Scoped ERC-7730 upstream-conformance review receipt — 2026-07-18.** The
> bounded slice is test-only: it adds exact format-level inventory,
> strict signed-Type-2 and legacy EIP-155 fixture adapters, and the first real
> upstream EIP-712 semantic transcript. The pinned corpus contains 502 unique
> fixture-targeted formats against 818 accepted PQ1 formats; 289 intersect, 529
> accepted formats lack a fixture, and 213 fixture targets are not accepted.
> Four Merkle-verified semantic transcripts now cover unsigned and signed
> Type-2, legacy EIP-155, and flat-static EIP-712; all exact case-owned waivers
> must be consumed, while the malformed trailing-byte WETH fixture still
> refuses. Evidence is focused lane 10/0, full dbgen 276/0,
> `pqsigner-erc7730` 242/0, xtask 60/0, and clean descriptor/codegen drift.
> This candidate changes no production descriptor, root, known-call Bloom,
> firmware signing behavior, or legacy
> transaction authority. Broader semantic enrollment and corpus-derived
> adversarial mutations remain open in the `source:work-todo` issues; forced blind signing
> remains disabled and out of scope. Frozen commit
> `8b32c3a925bbf1f1d34d53caf5ca76b2a6d2245b`, tree
> `036a209950f20bfe629570a78d4bdbeccd0d4f76`, received simultaneous GPT-5.6
> SOL, Opus 4.8, and Kimi K3 **GO** verdicts with no stage-blocking finding.
> Three non-blocking test-hardening observations are banked in the owner TODO;
> they do not expand the reviewed phase or confer production authority.

> **Scoped ERC-7730 Aave V3 basic-lending completion receipt — 2026-07-18.** This
> bounded production-catalogue curation admits only Aave V3 `borrow`, `deposit`,
> and `supply` by changing their existing `referralCode` field from hidden to an
> always-visible complete raw word. Across all 15 unique Pool deployments, the
> 45 deployment-format instances render the bound amount and token identity,
> complete debtor or collateral-recipient address, and exact referral word;
> `borrow` also retains its authenticated interest-rate enum. Permit variants
> and `multicall` remain omitted and hard-refused. The regenerated catalogue is
> 428 leaves / 349,671 bytes / root
> `0074f39ed119ae4ed07a5d520b080f211033417bc66577a4fe7e82196df9c1ec`;
> omissions fall from 281 to 278. The 4,542 known-call tuples, tuple-set hash,
> production/E2E Bloom bytes, and E2E catalogue are unchanged. Full dbgen,
> `pqsigner-erc7730`, xtask, the secure ERC-7730 renderer lane, and descriptor
> drift gates are green. Frozen target
> `0dc3275c354324d4287e1b42a0b26ab0fcd24206`, tree
> `8468e60ac2042b23c2808624d315dbc5cab04610`, is retained at
> `review/erc7730-aave-v3-basic-lending-20260718-v1`. Kimi K3 and Opus 4.8
> returned **GO**; Opus identified one non-material stale historical label,
> corrected in the receipt-only follow-up. GPT-5.6 SOL inspected the frozen
> source and artifacts but reached the mandatory eight-minute cap without a
> final verdict, so no third GO is claimed and no retry or substitute was
> launched. No reviewer produced a stage-blocking source finding. This is merge
> evidence only; it adds no formatter, fallback, generic signing, legacy
> transaction, production/ship, ERC-8176 provenance, or forced-blind authority.

## §0 — Where the truth lives (doc map)

One concern → one **owner** doc. If a fact lives in two docs it *will* drift (it did: S-1/S-2/S-3 status was
in four places). The rule: **owners hold the fact; everything else links.**

| Concern | Owner (source of truth) | Notes |
|---------|------------------------|-------|
| Non-negotiable invariants · code conventions · key-file map · KDF tags | **`CLAUDE.md`** | the LLM operating contract; the "do / never" rules |
| Engineering planning · scope/requirements change control · convergence · fast three-model adversarial review | **`docs/planning-and-review-workflow.md`** | `AGENTS.md` is the mandatory agent router; this owner doc holds the process |
| Security-review playbook routing · additive lenses · finding-record lifecycle | **`docs/security/adversarial-review/README.md`** | full sweeps are future owner-triggered assurance unless a stricter gate activates them; the planning workflow owns fast-review cadence and convergence |
| External architecture · per-device shipping checklist | **`README.md`** | auditor/integrator altitude |
| Reversible dev backlog · the dated Completion Log | **GitHub Issues** (`label:source:work-todo`) | retired 2026-07-19; full archive `docs/archive/work-todo-retired-2026-07-19.md` |
| **Irreversible** factory/silicon burn ceremony (OPTIGA LcsO, OTP/WRP/RDP, SCP03 PUT-KEY) | **GitHub Issues** (`label:source:production-todo`, `label:ship-blocker`) | retired 2026-07-19; full archive `docs/archive/production-todo-retired-2026-07-19.md` |
| Security + verification frontier (done/left/why) | **this file (§A–§D)** | reconciled pointer index |
| Tools & systems an agent can use (+ gaps) | **`docs/tooling-and-systems.md`** | the capability manifest |
| Adversary tiers · trust boundaries · falsifiable Claims | **`docs/security/threat-model.md`** | |
| Ship-blocker provenance (`C-n → S-n`) | **`docs/security/security-review-2026-05.md`** | the audit that named S-1..S-7 |
| Hardening requirements ("what must hold") | **`docs/security/HARDENING.md`** | |
| EVT bench-attack pass/fail bars | **`docs/security/red-teaming.md`** | the on-copper test matrix |
| Empirical on-silicon SE050 status | **`docs/secure-elements/se050-silicon-findings.md`** | |
| Provisioning ceremony (untrusted-CM) | **`docs/provisioning/provisioning-reference.md`** | |
| A/B rollback architecture candidate and physical/resource gates | **`docs/security/a-b-firmware-rollback-architecture.md`** | Draft 1.1 is pending exact-digest dual review + owner approval; its frozen technical text is preserved as a research candidate only, while any embedded reviewer-runtime/choreography text is superseded by `docs/planning-and-review-workflow.md`. Bounded deletion receipt: `docs/security/fw-rollback-draft11-deletion-gate-2026-07.md`. Draft 0.9 is historical at tag `rollback-architecture-v0.9`; receipts: `docs/security/a-b-firmware-rollback-review-receipt-2026-07.md` and `docs/security/fw-rollback-draft09-host-model-receipt-2026-07.md` |
| Companion integration · clear-signing | `docs/companion/companion-app-integration.md` + the `companion-*` deltas | firmware side: `docs/companion/erc7730-integration.md` |
| FV strategy / what full proof requires | **`docs/verification/how_to_math_proof_secureness.md`** | live proof state: `contracts/verification/` (`THE_CLAIM.md`) |
| FV target ranking · security-tooling adoption | `docs/verification/verification-targets-2026-06.md` · `docs/verification/security-tooling-sota-2026-06.md` (= §34) | |
| C10 ↔ FIPS-205 deviations | **`docs/verification/c10-fips205-delta-audit.md`** | keeps public claims accurate |
| SCA/FI tooling & harnesses | `docs/tooling-and-systems.md` + `tools/sca/DONJON-RUST-TOOLING.md` | |
| Quarantined historical docs (stale / superseded / completed handoffs) | **`docs/archive/`** (+ its `README.md` index) | NOT current guidance; each README row names the live successor. Don't merge archived content forward (several state a superseded signing primitive) |

**Ownership rule of thumb for any edit:** before writing a status/fact into a doc, ask *"is this doc the
owner of this concern?"* If not, link to the owner instead of restating — that's what keeps this tree from
re-drifting.

> **Two rules that make it trustworthy** (this repo's checkboxes have lied in both directions repeatedly):
> 1. **Every `DONE` row carries a spot-checkable evidence pointer** — a commit, a `file:line`, a `make`
>    target, or a test name you can run. Trust nothing; verify the pointer.
> 2. **Every open row carries a `blocked-on` tag** so "what can I actually do from the keyboard right now"
>    is answerable at a glance:
>    `code` = keyboard-doable now · `compute` = doable but heavy CPU/time · `bench` = needs the physical
>    STM32U585 / glitch rig · `factory` = needs HSM key-custody or a release pipeline · `research` =
>    long-horizon or a separate project.
>
> **Verification depth.** Where a reconciler *ran* the tool, the row says so (ProVerif/Tamarin, cargo-fuzz
> corpus, git archaeology). Where it confirmed *existence* of harness + commit but did not re-execute a heavy
> toolchain (Kani/CBMC, cargo-checkct/binsec, Kontrol/KEVM), the row notes "asserted by commit, not re-run."

---

## AT A GLANCE

- **The real ship gate is NOT a tooling track** — it includes **firmware
  rollback Foundation A** (legacy OTP/A-B path is production-fenced; Draft 1.1
  exact-digest approval, implementation, separate physical FLASH and
  static-RAM/worst-case-stack fit, and physical
  journal/ECC/OTP receipts remain open), **OPTIGA silicon (S-1/S-3 LcsO ratchet) + S-2 closure of the real type-`0x11` pool and device-certificate retype boundary under a selected factory policy**, the **first-boot final SE pairing/rotation closure
  (HIGH-1; a journaled candidate exists, but its authenticated factory handoff,
  old/new/KVN recovery proof, E140 order, and silicon receipts remain open)**,
  and the **S-5 bus capture**.
- **Keyboard-doable security work right now (`blocked-on: code`):** HIGH-1's
  candidate handoff/recovery review and crash-safe durable-state validation,
  `make checkct` CI enrollment, S-4's remaining
  documentation/code items, the optional Lean credits corollary, mutation
  testing, and the Draft-1.1 review/model work named by `FW-RB`. The detailed
  §B table—not this summary—is authoritative; previously listed hevm, KAT,
  ClusterFuzzLite, security-review Action, prod-config, and most ToB-pilot work
  are already closed or deliberately deprioritized there.
- **The big compute item:** the full ~40h FI fault-sweep campaign (harnesses built, only smoke-run).
- **Stale-doc flag found during reconcile:** `docs/secure-elements/se050-silicon-findings.md` still says lockout SW `0x6982`; the
  live post-revert code maps `0x6986` (`ef3d00da`). Worth a 2-minute sync.

---

## A. SHIP GATE — must close before any unit leaves the bench

The [`label:ship-blocker`](https://github.com/EthereumPhone/PQ1/issues?q=label%3Aship-blocker) issues own the OPTIGA
bench/factory spec (retired `docs/production-todo.md` → see the migration note above; full pre-migration text at
`docs/archive/production-todo-retired-2026-07-19.md`); `docs/security/security-review-2026-05.md` owns the
`C-n → S-n` finding provenance; `docs/security/red-teaming.md` owns the bench pass/fail bars.

| ID | Item | Status | Blocked-on | Evidence (spot-check) | What remains |
|----|------|--------|-----------|------------------------|--------------|
| **FW-RB** | A/B rollback + anti-rollback root | Draft 1.1 research candidate; implementation **NO-GO** | **code + bench + factory** | Draft 1.1 commit `93da7567`, SHA `743bc156…3d7ad`; bounded host deletion receipt; exact-digest Opus/GPT reviews and owner approval remain pending; build.rs + Rust compile gates cover production secure/FSBL, factory/rehearsal, and explicit bench opt-in; `prod-check-ship` is an expected-failure CI gate | Obtain both exact Draft-1.1 architecture reviews + owner approval; implement and adversarially review the selected contract. The physical FSBL FLASH LOAD span must meet the candidate's proposed 38,912-B target (40,960-B hard ceiling), and separately `OPEN-RAM-1` must close the static-RAM + worst-case-stack envelope. Close `OPEN-PIN-HW-1`, `OPEN-JRN-HW-1`, `OPEN-JRN-DUR-1`, `OPEN-FLASH-HW-1`, `OPEN-ECC-1`, `OPEN-RAM-1`, `OPEN-OTP-1..3`, `OPEN-REL-1`, and `OPEN-C10-1`; then obtain separately authorized Section-13 silicon/factory receipts. Legacy 1,024-bit tally and current try-once claims are rejected. |
| **S-1** | F1D0 `Change=ALW` → desolder PIN brute-force | partial | **bench** | `secure/src/nsc/mod.rs` feature fence `optiga-lock-operational`; `secure/src/optiga/apdu.rs::build_metadata_auth_ref_luc`; `secure/src/optiga/mod.rs::OptigaTrustM::verify_and_lock` (commit `832a369d`) | Irreversible **LcsO=Op ratchet** + sacrificial-part validation on fresh silicon. During the rollback quarantine, a non-production STM32 image can compile only with explicit `legacy-fw-rollback-unsafe`, while production and factory shapes are blocked; this is bench capability, not a shippable escape. |
| **S-2** | Empty/unratcheted type-`0x11` trust-anchor slots can authorize attacker-signed Protected Updates | partial | **factory** | `secure/src/optiga/reset.rs::{TRUST_ANCHOR_OID,TRUST_ANCHOR_CERT}` documents the retired, mis-targeted `0xE0E3` sample-key helper; `secure/src/nsc/mod.rs` fences `OPTIGA_RESET_OIDS_RETIRED` and `OPTIGA_S2_PRODUCTION_BLOCKED`; fail-closed candidate `secure/src/optiga/mod.rs::OptigaTrustM::lockdown_ta_pool` names `{0xE0E8,0xE0E9,0xE0EF}` | Pin the SKU/revision inventory; select a reviewed HSM-anchor or irreversible-neutralization policy for the real type-`0x11` pool; close every unused surface; and ratchet `0xE0E1..=0xE0E3` as device-cert objects without retyping them. The observed `0xE0E3` is a full type-`0x12` device cert, so the old helper is a no-op; that correction does not close the real pool. |
| **S-3** | Default build has no silicon-enforced PIN lockout | partial; weak-profile production fence closed | **bench + factory** | `secure/src/nsc/mod.rs` fence string ``Production OPTIGA builds require `optiga-hw-counter```; `secure/src/optiga/apdu.rs::{build_metadata_auth_ref_luc,OID_PIN_CTR}`; `make optiga-hw-counter-e2e` PASSED 2026-04-22 | Freeze and authorize the final F1D0/E120 metadata and lifecycle profile, then validate the LcsO ratchet, reset/power-cut behavior, and limit boundary on named sacrificial parts. Under `optiga-hw-counter`, F1E1 remains a provisioning/reset sentinel and is not lockout authority. |
| **S-5** | SCP03 response unprotected (`half_E` plaintext on I²C) | **done** (code+func-silicon) | bench | `secure/src/se050/scp03.rs::{establish,unwrap_response}`; `secure/src/se050/apdu.rs::send_apdu`; tests `secure/src/se050_under_test/pure_tests.rs::{positive_scp03_external_authenticate_p1_is_0x33,positive_scp03_unwrap_response_exists}`; B-U585I functional round-trip recorded in the SE050 stress evidence | Only the dedicated **logic-analyzer bus capture** confirming no plaintext on the wire (`docs/security/red-teaming.md` §5.1). |
| **S-6** | Admin-delete on USERID → seed theft | **done** | none | `secure/src/se050/mod.rs::Se050::store_objects` calls `write_userid(..., None)`; tests `secure/src/se050_under_test/pure_tests.rs::{negative_admin_userid_provisioning_uses_no_admin_ref,negative_user_userid_has_no_admin_ref_post_s6}` and stress `userid_no_admin_delete` | — |
| **S-7a/b/c** | max_attempts=0 footgun; `0x6986`→Ok mis-map; extended-Lc 2-byte Le | **done** | none | `secure/src/se050/apdu.rs::{write_userid,delete_object,send_apdu}`; stress `pin_unlimited_no_lockout` | — |
| **S-7d** | Empirical UserID-lockout SW mapping | **done** (on silicon) | none | commit `ef3d00da` (Runs 3-4, B-U585I); `secure/src/se050/apdu.rs::create_session` maps `0x6986` to `AuthMethodBlocked`; stress `userid_silicon_lockout` and `pin_counter_persists_across_reinit` | ⚠ **was marked open** — actually run. `0x6982` was a reverted red herring. **`docs/secure-elements/se050-silicon-findings.md` is stale (says 0x6982) — sync it.** |
| **S-4** | OPTIGA lower-sev cleanups (5 sub-items) | partial | bench + code | `secure/src/optiga/apdu.rs::{build_metadata_protected,build_metadata_counter,OID_COUNTER}`; current authority names E120 as lockout and F1E1 as the provisioning/reset sentinel | The remaining sentinel lifecycle/replacement choice needs design + bench evidence; irreversible items need the board. |
| **HIGH-1** | SCP03 default-keyed with PUBLISHED AN12436 factory keys (dev) → bus attacker extracts `half_E` | partial; journaled first-boot candidate exists, production closure OPEN | **code + factory + bench** | `secure/src/nsc/mod.rs` fence string ``Candidate SE050 profile is incomplete without non-public SCP03 transport keys``; `secure/src/first_boot/`; `secure/src/se050/mod.rs::{rotate_scp03_transport_to_final,rekey_admin_transport_to_final}`; `secure/src/scp03_logic.rs::keys_are_factory_default` | The published-key fallback is compile-fenced and the candidate implements BHK-rooted SE050 rotation plus persisted-salt OPTIGA rotation. It is not a reviewed ceremony: close the authenticated per-unit transport handoff/receipt, authenticate-before-rotate rule, old/new/KVN recovery proof, E140 order, and silicon validation. No production authority until those gates close. |
| **MED-2** | `e2e-test`/`dev-testkey` escape hatches ship fixed secrets; no prod-check CI gate | **done 2026-06-18** | none | `secure/src/nsc/mod.rs` `mode-production` incompatibility fence strings; `make prod-check`; per-push `prod-config-gate` CI job (`f8effd45`) | — |
| — | **Claim 3 (PIN gate) is PROVISIONAL** | — | bench | `docs/security/threat-model.md` Claim 3 | After S-1 closes, re-establish the on-board three-way per-attempt leg with `pin-gate-hw-counter-e2e` on a ratcheted sacrificial part. The directional boot branches remain open pending a separate cold-reboot silicon receipt. |

---

## B. ACTIVE FRONTIER — open / partial assurance work, grouped by what unblocks it

### `blocked-on: code` — doable from the keyboard now

| Area | Item | Status | Evidence / where | Source |
|------|------|--------|------------------|--------|
| CI | Prod-config gate rejecting `e2e-test`/`dev-testkey` fixed secrets (MED-2) | **DONE 2026-06-18, CI-green** | `mode-production`+`e2e-test`/`+dev-testkey` `compile_error!` fences (`nsc/mod.rs`) + `make prod-check` (cargo-tree feature resolution; catches transitive `dev-testkey→otp-hardcoded-master-key`) wired into `release` + the per-push `prod-config-gate` CI job (green on master `f8effd45`) | audits/tz-tamper |
| cargo-checkct | a CI gate (driver coverage now complete) | partial | **`driver_saes` DONE 2026-06-18** (proves SECURE on binsec — the Tier-1 SAES-CMAC(DHUK) framing incl. `double_l`'s secret-MSB reduction is branchless on thumbv8m); 4 SECURE drivers (kdf/fors/th/saes); `make checkct` EXISTS (`Makefile:3620`). Remaining = a CI job (binsec needs a local opam switch, so kept host-local for now) | sota §1 |
| on-chain Yul | **hevm equivalence** of `SPHINCsC10Asm` vs a reference Solidity verifier | **deprioritized — redundant 2026-06-18** | Marginal value ≈ 0 over the existing stack: A3.1 proves `execC10Asm = Spec.verify` **∀-input in-kernel** (Yul-model = the SPEC — a STRONGER reference than "= another Solidity impl"; §A3.1 row), Kontrol/KEVM discharges the **deployed-bytecode** level 33/33 (same level hevm targets, same KEVM-class engine), the transcription lint guards source↔model, the clean-room signer (row below) adds cross-impl differential. hevm would only prove "Yul ≡ a reference verifier" (a new impl that itself needs trust) and would NOT close the residual bytecode↔model SHA-256 axiom (the shared A1 ceiling). Cost = a from-scratch ~hundreds-of-line reference verifier (days) + hevm install for ~0 net assurance. Revisit only if a 2nd independent bytecode-equivalence engine is specifically wanted. halmos side done (42 receipted / 42 wired, incl. the EIP-1271 G8 harness — receipt `contracts/verification/halmos/sessions/halmos-session-2026-07-19.txt`; count reconciliation per fv-deep-review-2026-07-19 F9). | sota §2 |
| on-chain Yul | KAT oracle — independent-source leg | **DONE 2026-06-18** | A clean-room SHA-256-C10 signer landed: `contracts/verification/scripts/independent_c10_signer.py` — written from the deployed `SPHINCsC10Asm.sol` + the documented PRF preimages (`sphincs-c10/src/hash.rs`/`fors.rs`), NOT a transliteration of the Rust signer (and NOT signer.py's `c10` config, whose FORS ADRS is the pre-fix shared-forest layout, not PQSigner's `htIdx`-bound one). VALIDATED: reproduces the Rust `pk_root` + ALL 4 valid KAT vectors BYTE-FOR-BYTE + round-trips fresh messages; and `sphincs-c10/tests/independent_signer_xcheck.rs` confirms the EXISTING Rust verifier accepts FRESH independent-signer output. `make -C contracts/verification verify-independent-signer` (+ CI host-tests step). Honest scope: implementation diversity over the SHARED C10 spec (no second spec exists), not a second spec. | sota §2 |
| CI / fuzz | ClusterFuzzLite over the 12 fuzz targets | **done (build CI-validated)** | `.clusterfuzzlite/{project.yaml,Dockerfile,build.sh}` + `cflite-pr.yml` (code-change, hard gate) + `cflite-batch.yml` (scheduled). **Build proven green 2026-06-18** (batch run `27770338025`, `Build fuzzers`=success after wiring `github-token` for the private-repo clone); `cflite-pr` promoted off `continue-on-error`. First real PR will exercise the code-change run_fuzzers path | trezor-comp |
| CI | `claude-code-security-review` GitHub Action (ext-contributor-gated) | **done 2026-06-18** | `.github/workflows/security-review.yml` — SHA-pinned (`@0c6a49f1`), fork-guarded (`head.repo==repository`), `pull_request` NOT `_target`, no-ops without `ANTHROPIC_API_KEY`; advisory-only (never a merge gate) | sota §8 |
| ToB skills | Pilot tail: mutation/property/differential/variant/entry-point/supply-chain/agentic-actions/seatbelt/fp-check | **mostly covered 2026-06-18 (methodology substitute)** | the plugins aren't `/plugin install`ed, but the METHODOLOGY ran as a fan-out workflow (`tob-methodology-security-audit`, **14 findings / 0 FP** → the supply-chain fixes in `5b295e52` + `eb416ccf`). Covered: supply-chain-risk / agentic-actions / entry-point / variant / fp-check(=the Verify phase). seatbelt-sandboxer = macOS-N/A (Linux analog `tools/sca/run-isolated.sh` landed). Genuinely OPEN: **mutation-testing** (no gambit/vertigo mutant runner on the contracts) | sota §11 |
| OPTIGA | S-4 items 2 (plaintext VK-read confirm) / 3 (duress-PBS caveat in threat-model) / 5 (F1D5↔F1E1 naming) | open | doc/code | work-todo S-4 |
| Lean FV | Optional global credits-native aggregate corollary (`#executes ≤ #validates`) | open (low-pri) | not written; skeleton `Theorems.lean:696-706` | faithfulness P2 |

### `blocked-on: compute` — doable but heavy

| Area | Item | Status | Evidence | Source |
|------|------|--------|----------|--------|
| FI/SCA | **Full FI fault-sweep campaign** (14 rainbow harnesses × full width × all fault models, ~40h+) | partial — harnesses built, **only smoke-run** | `tools/sca/fault_sweep_*.py` (14); `make -C tools/sca c10-sign`; commits `8d8b9af7`(smoke)/`3891237b` are NOT full coverage | sota §0; README §C10-sign |

### `blocked-on: bench` — needs the physical board / glitch rig

| Area | Item | Status | Evidence | Source |
|------|------|--------|----------|--------|
| SCA | dudect DWT Welch t-test on real U585 (`verify()`/KDF) | open | no make target / artifact | sota §1 |
| SCA | lascar/scared CPA — **on-silicon** SHA-2 PRF DPA sufficiency (emulated half done: F-9 found+fixed) | partial | `make kdf`/`f9-*`; emulated = software-AES stand-in | work-todo §18b(b) |
| FI/SCA | Hardware bench: ChipWhisperer-Husky + ChipSHOUTER-PicoEMP | open | listed adopt-now, nothing acquired | sota §SCA-rigs |
| OPTIGA | S-1 / S-3 LcsO=Op ratchet + sacrificial-part validation | open | `label:ship-blocker` issues | sec-review |
| SE050 | S-5 logic-analyzer bus capture | open | `red-teaming §5.1` | — |

> **Resolved sub-question:** "no public STM32U5 RDP/TZ glitch result exists" has **flipped** — the
> Masaryk/Šimoník thesis demonstrates ~76% PIN-glitch bypass on STM32U5 silicon (`work-todo:1050`),
> invalidating Donjon's prior statement. The *our-board* bench campaign is still open; the literature question is answered.

### `blocked-on: factory` — needs a factory policy/ceremony, key custody, or a release pipeline

| Area | Item | Status | Source |
|------|------|--------|--------|
| OPTIGA | S-2 real type-`0x11` pool + device-certificate retype closure; select HSM-anchor or irreversible neutralization policy | open | production-todo S-2 |
| supply-chain | cargo-vet audit set + SLSA provenance / cosign→Rekor on release | open | sota §8 |
| provisioning | Factory provisioning automation (per-device SCP03 + PBS) | open | threat-model §9.2 |

### `blocked-on: research` — long-horizon / separate project

| Area | Item | Status | Evidence / note | Source |
|------|------|--------|-----------------|--------|
| Lean FV | **A3.1** deductive interpreter-refinement closure (the verifier ∀-theorem) | **model-side ∀ CLOSED 2026-06-18** (was "partial") | `execC10Asm = nMaskedB pkSeed && nMaskedB pkRoot && verifyYulModel` proven **∀-input, kernel-clean** (`execC10Asm_eq`, commit `940d43e8`) ⇒ `execC10Asm = Spec.verify` on N-masked keys; adversarially reviewed (`contracts/verification/docs/findings/A3_1_ADVERSARIAL_REVIEW_2026-06-18.md`) + positional transcription lint (`make verify-transcription`, `064357d5`/`229e1b3d`). RESIDUAL is NOT open proof work — two documented trust boundaries: the bytecode↔model axiom `solidityVerifier_compiles_correctly` (`discharged-bytecode-partial`: Halmos input-gates + 396-vector KAT/mutant differential; full ∀-body symbolic = the **A1 uninterpreted-SHA-256 ceiling**) and the `c10Program`↔`.sol` transcription (now lint-guarded + corpus). Interpreter is in `lean/SphincsCVerify/Interpreter/` (the `contracts/verity/` scaffold from old subtasks was superseded). | verity / how_to_math_proof |
| Lean FV | Real-valued / probability-monad quantitative bound (deeper half of E) | open | log-domain floor done (`Crypto/Quantitative.lean`); `Pr[forge]≤ε` half absent | FV-frontier(b) |
| Lean FV | `deserialize_pin_state` as a proven Aeneas rank | open | source `domain/src/lib.rs:739`; not extracted (Kani already proves panic-freedom) | handoff-pinstate |
| Lean FV | Extend Aeneas into `domain` derivation (`slot_entropy`/`derive_c10_slot_seeds`) | open | needs `sha256_bytes` refactor first | FV-frontier |
| Firmware FV | LeanLoop roadmap (goal-splitting / prover ensembling / lean-lsp MCP tier) | open | separate repo | sota §3 |
| Crypto | ML-KEM-1024 inner wrap (Claim 7 / CRQC bus-capture residual) | descoped — residual ACCEPTED (owner, 2026-07-07) | Grover-2⁶⁴/Cat-1 bound accepted; per-device SCP03/PBS rotation (work-todo #11 / §9.2) now load-bearing for the static-leak residual; prototype retained feature-gated | threat-model §9.1, work-todo #9 |
| Platform | Boot-time SE attestation; MPU privilege-banking | open | HARDENING §3.4 / threat-model §9.4, §9.9 | — |

---

## C. DONE — verified, with evidence

Compact ledger of security/verification items confirmed complete against the repo. Spot-check the pointer.

| Area | Item | Evidence | Depth |
|------|------|----------|-------|
| Supply-chain | cargo-deny `advisories+bans+sources` in CI + `make invariant-gates`; exact host-only ERC-8176 `dbgen -> k256 -> ecdsa` boundary | `deny.toml`; `scripts/check_classical_crypto_boundary.py`; `ci.yml` invariant job; `Makefile` `classical-crypto-boundary` | live gates pass 2026-07-22 |
| Fuzzing | cargo-fuzz campaign, 12 targets, 0 artifacts, `make fuzz-all` | `fuzz/fuzz_targets/` (12); four tracked selector-gate seeds plus ignored local/generated corpora; `fuzz/README.md` | fail-closed campaign re-run 2026-07-13 |
| Supply-chain | `make sbom` (CycloneDX sidecar) | `Makefile:3528-3532`; cargo-cyclonedx installed | target exists |
| Firmware FV | Kani (173 harnesses — exhaustive decoder-DECISION fence over the extracted clear-sign + FW-update crates) + Miri (0-UB incl. secure-crate NS-ptr + tree-borrows) + `revm`/MultiSendCallOnly bytecode differential | `make kani`/`make miri`; `#[kani::proof]` across `pqsigner-tx`(multiSend/CoW/typed-call/SafeTx/Safe-mgmt/erc20), `pqsigner-erc7730`, `sphincs-tz-shared`(NS-ptr), `fw-manifest`(rollback+preimage), `pqsigner-domain`/`aa`/`tx-core`; exact source-derived identities in `scripts/kani_census.lock.json` | **CI-wired, evidence suspended**: Miri per-push (`ci.yml` `miri` job), Kani nightly (`nightly.yml`), but GitHub billing has prevented fresh CI evidence. Current closure evidence is local and must be read with the bounded-harness scope in `contracts/verification/docs/FV_SURFACE_MAP.md`. |
| CI / UI | ui-capture golden-screenshot regression gate | `make ui-golden` (`Makefile`); producer `ui/capture.rs`, comparator `tools/ui_fixture.py`, fixtures `tests/ui_fixtures.json` | **target added 2026-06-18** — LOCAL/manual gate, **wired but not yet run to completion** (the regen run was killed mid-QEMU at 11 min; full-e2e capture is too slow over QEMU semihosting → not CI-gated; a dedicated short-capture scenario is the CI-viable follow-up) |
| CI / repro | Reproducible-build byte-diff gate | `make verify-repro` (`Makefile:1912`); `nightly.yml` `verify-repro` job | **wired 2026-06-18** — was capability-only (Makefile comment falsely claimed per-PR); now nightly-gated |
| Protocol | ProVerif (33 pinned queries / 6 models) + Tamarin (**8 lemmas**) | `make proverif`/`make tamarin`; `4beebec7`,`118665bf`,`86291fd7`,`3f82f560`; **+`fw_update_authenticity.pv`** (FW-update no-forgery + domain-separation PROVEN under a cross-protocol-reuse adversary, 2026-06-26) **+`seed_split_xor.spthy`** (dual-SE XOR seed-split secrecy info-theoretic via `builtins: xor` — single-SE compromise leaks nothing; positive control both-compromise leaks; 2026-06-26) | **both provers re-run end-to-end** |
| SCA | cargo-checkct: 4 SECURE CT proofs (kdf/fors/th/**saes**) | `checkct/driver_{kdf,fors,th,saes}`; `driver_saes` proves SECURE on binsec 2026-06-18 (Tier-1 SAES-CMAC framing) | binsec re-run for driver_saes; kdf/fors/th from `b0944ecf` |
| SCA | Muscat pilot — full-10M TVLA reproduces lascar, CPA flat | `muscat/pqsigner_tvla_cpa.rs` (`23e72bd4`) | cross-check on emulated traces (not silicon) |
| ToB skills | zeroize-audit (clean); ct_analyzer → CT-1 found+fixed; semgrep rules hand-authored | `8184d4b5`; fix `shuffle.rs:181` (`0d432f8f`); `.semgrep/pqsigner-invariants.yml` | commits + live fix |
| Lean FV (A5) | EUF-CMA restated consistently; `theft_free` re-derived; sha256→collision-resistance; 3 shapes→opaque | `Crypto/EUFCMA.lean:123`, `Assumptions.lean:101-170` (`4ba5be10`,`83776287`); `make verify-audit` = 11 axioms, 0 sorryAx | gate asserted |
| EasyCrypt (A5, WOTS+C leg) | **WOTS+C multi-instance EU-naCMA MACHINE-CHECKED and now UNCONDITIONAL** against MM45's *real* WOTS-TW theorem: `Pr[M_EUF_NACMA_WOTSC_L] ≤ Pr[S_TCR_C] + Pr[M_EUF_GCMA_WOTSTWESNPRF]` — real games, **no free reals, 0 admit, no embedding hypothesis**. Matches the paper's Thm C.2 exactly. FLAG-2 (`emb_disj_wgpidxs`) **discharged 2026-07-09** by re-basing the stack onto the concrete `FSSLXMTWES.WTWES` instance and defining `emb_tw`. | `~/repos/c10-eufcma-port` (out-of-tree) `c5fa41a`: `WOTS_C_Real.ec::emb_disj_concrete` + `WOTS_C_Bridge.ec::emb_disj_wgpidxs_holds`; `WOTS_C_EmbDischarge.ec:173 D1_MEUFNACMA_WOTSC_MM45_embthfc` (premises 3→2, conclusion byte-identical) | **done (leg) AT MM45-ADMISSIBLE WOTS PARAMETERS ONLY (`w ∈ {4,16,256}`)** — ⚠ **UPDATE 2026-07-25: this row is NOT a statement about the deployed signer.** There is **no instantiation of any part of that development at deployed C10** (`W=8, LOG_W=3, L=43, TARGET_SUM=205`), and none can exist under MM45's unconditional `two_encodings`: it forces an **injective antichain** encoding, so 2^128 messages must fit the max antichain of `{0..7}^43` = 2^123.76 — **unsatisfiable at deployed geometry** (`len >= 45` needed at `w=8`). This is **not** a defect in C10 — its encoding is deliberately non-injective, paid for by the S-TCR(Th+C) term. Do **not** claim the FORS leg is proven at deployed FORS geometry either (`val_log2w` is ambient via `SPHINCS_PLUS`, incl. `GprocFORSC10.ec:53`). Full CAN/CANNOT boundary + DO-NOT list: [`verification/easycrypt-euf-cma-port-feasibility-2026-07.md`](verification/easycrypt-euf-cma-port-feasibility-2026-07.md) UPDATE 2026-07-25d. — Other residual side-conditions are `c <= p_tgts` (parameter) and the definitional encode-compat. Anti-vacuity: RHS→`0%r` fails; `nonvac_guard` + `emb_off_range` proven; `thfc`/`predC` stay abstract. A5-EUFCMA stays `cited-tcb` (composition `hfx` + FORS+C leg still open). Gate: compile EVERY `.ec` as a target |
| EasyCrypt (A5, FORS+C leg) | **A5-ITSR RESTATED 2026-07-10 → `ITSRC10`, a NAMED NONSTANDARD assumption** (standard ITSR + conditioning of the message key). It was cited to Barbosa et al. §6 Thm 2 = *plain* ITSR for *standard* SPHINCS+ — a different scheme. The published SPHINCS+C paper has **no FORS+C theorem** (§IV: *"we can use the previous ITSR analysis"*; §V: *"straightforward"*), and **MM45 never bounds ITSR either** — its top theorem carries `Pr[MCO_ITSR.ITSR(…)]` as an *unreduced term*. So the honest closure was never a reduction. **Now backed by more than the paper or MM45 offer:** the assumption is mechanized as a game (`FORS_C10.ec`, C10-faithful, 0 admit), its combinatorial core is machine-checked (`DarkSide.ec`, 0 admit: `cover_pr` proves `DS_γ` *is* the coverage probability; `forsc_le_fors` proves the paper's central claim `DS^(k-1)·(1/t) ≤ DS^k`), and a black-box reduction to the standard assumption costs **~102 bits** — so the nonstandard form is necessary. | `AXIOM_STATUS.json` A5-ITSR (+`mechanized-assumption` artifact); `Crypto/Assumptions.lean` `axiom ITSR_F` docstring; c10-eufcma-port `0eae219`; `make -C contracts/verification verify-forsc-margin` (WORK FACTOR 130.6 bits FORS+C vs 128.5 plain — hash queries needed, **not** an advantage; at q_h = 2^128 the advantage is 2^-2.6) | **restated, still `cited-tcb`** — the citation now names an assumption we defined, mechanized and concretely analysed, instead of a theorem about a different scheme. Residual: like plain ITSR it is unbounded inside EasyCrypt (no stdlib concentration inequalities); k-fold product / binomial mixture / (q_h+1) union bound not mechanized |
| EasyCrypt (A5, blast radius) | FORS+C **never weaker than plain FORS at C10's params**: `ratio = p_FORS+C/p_FORS = 1/(t_last·DS_γ) ≤ 1` since `DS_γ ≥ 1/t`; C10 has `t_last = t = 2^11` (equality boundary) → identical at γ=1 (`2^-143`), better by `~log2 γ` beyond. Forced-zero enforced by **both** verifiers. | `make -C contracts/verification verify-forsc-margin` (wired-in negative control: FAILS if `t_last < t`); `hypertree.rs:374`, `SPHINCsC10Asm.sol:86`; test `negative_forced_zero_fors_index_is_enforced_in_emitted_sig` | **gate added 2026-07-09** — a **computed margin, NOT a reduction**; bounds the blast radius of the row above. Does not discharge A5-ITSR |
| Lean FV (faithfulness) | cap-bootstrap survivor; Gap-3 domain sep; Gap-2 per-step credits; Gap-4 upgrade-unreachable; A4 content; Gap-1 lint | `Invariants.lean:580`, `OffchainBinding.lean:87`, `Theorems.lean:726`, `UpgradeSafety.lean:96` (2026-06-14) | files exist |
| Lean FV (faithfulness) | Scope-honesty headline write-up | `THE_CLAIM.md:149-153` | ⚠ **was marked open** — actually done (checkbox lag) |
| Lean FV (Pass-2) | lean4checker gate; FV-invariant lints; 2 KAT near-miss vectors | `make verify-lean4checker`/`verify-fv-lints`; `KatVectors.lean:59-63` | targets exist |
| Lean FV (Pass-2) | Kontrol/KEVM discharge A3.2/A3.3/A3.4 (33/33) on deployed bytecode | `7042de2d`,`b8cf51a8`,`2f675244`,`451a3ce2`,`df1c08e9`; backend installed | commit chain; re-run = compute |
| Lean FV (Pass-2) | Quantitative log-domain floor (96-bit @ 2^16 cap, cap load-bearing) | `Crypto/Quantitative.lean` (axiom-free) | partial item — real-valued half open (§B). ⚠ the "96-bit" figure is an **advantage bound** (`(q+q²)·2⁻¹²⁸ ≤ 2⁻⁹⁵` at `q=2¹⁶`), **not** a work factor — do not compare it against the `2¹²⁸`/`2⁶⁴` work-factor numbers (units mismatch; an external reviewer read it as a contradiction on 2026-07-25) |
| Crypto (C10 params) | **MONITOR — global bootstrap-key signature budget.** Deployed-parameter margin triaged 2026-07-25 against IACR CiC 2/1/13 (ePrint 2025/055) Parameter Requirements. **CiC verdict: NO-ACTION** (no attack; NIST's own SLH-DSA-SHA2-128s misses the same requirements by more on every comparable axis; the "~105-bit grind-randomness gap" is not a meaningful comparison — the WOTS count is a deterministic *public* index with ≈0 bits of entropy, transmitted and re-checked). **What IS monitored:** the bootstrap/master key is chain-**independent** (`domain/src/lib.rs:537,556-566`) while `bootstrapUses` is per-**chain** (`PQMultiOwnable.sol:22`), so the FORS+C few-time term crosses 128 bits at `q ≈ 99,376` (~1.5 chains) → **126.16 bits at 2 chains, 121.02 at 4**. Slot keys are chain-bound and unaffected (130.57 bits at their 2¹⁶ cap). | `docs/verification/easycrypt-euf-cma-port-feasibility-2026-07.md` UPDATE 2026-07-25h (full triage + both external reviews); numbers from `contracts/verification/scripts/forsc_grinding_margin.py` (its plain-FORS column reproduces the upstream Fluhrer-Dang sweep exactly) | **Not a new finding and not a re-raise** — same residual class as the owner-ACCEPTED WON'T-FIX `docs/VULN-getinitcode-bootstrap-fewtime-oracle.md` (2026-06-30). Recorded because the previously-stated premise "≤2¹⁶ sigs/key enforced on-chain" is **false** and the corrected number belongs in the record. No parameter change warranted (invariant #6). Monitor conditions (a)-(e) in the triage section |
| Audits | 2026-06-09 firmware-signing audit (12 findings) + 4 parallel paper-audits (2026-06-11) | `docs/security/security-audit-2026-06-firmware-signing.md` (all resolved); `docs/security/audits/*` | as-resolved record (except HIGH-1/MED-2 in §A) |

---

## D. RESEARCH-CORPUS MAP — research/design docs → live work they justify

So "fill the gaps from the deep researches" is a lookup, not archaeology. Each doc's **source-of-truth** column
says what it authoritatively owns (don't duplicate it — link it).

| Doc | Covers | Live items it owns / spawned | Source-of-truth for |
|-----|--------|------------------------------|----------------------|
| `docs/verification/security-tooling-sota-2026-06.md` | 2026-06 3-pass SOTA sweep (~250 systems) | Owns **§34**; spawned the whole adopt-now shortlist + FI/SCA/protocol items | The adopt/pilot/skip decision matrix; "FI countermeasure already closed"; Binsec/Rel NO-GO |
| `docs/verification/verification-targets-2026-06.md` | 12 ranked pure-logic FV targets (R1–R12) | Feeds `goals.leanloop.toml` one at a time (the FV frontier) | The FV-target ranking + KAT-anchor map driving §33/A3.1 |
| `docs/security/threat-model.md` | STRIDE; T0–T7 tiers; S0–S7 assets; Claims 1–7; §9 live caveats | §9.1 ML-KEM (ACCEPTED residual 2026-07-07, no longer open), §9.2 provisioning, §9.4 boot-attest, §9.9 MPU; **Claim 3 provisional until S-1** | Adversary taxonomy + falsifiable security-claim contract |
| `docs/security/security-review-2026-05.md` | 2026-05 firmware code-review | **Originated S-1..S-7** (`C-4→S-1`, `C-5→S-2`, … `C-9→S-7`) + H-5/H-6/M-2/M-3 carry-overs | The `C-n → S-n` ship-blocker derivation |
| `docs/archive/production-todo-retired-2026-07-19.md` (retired 2026-07-19; live items on the tracker) | Factory irreversible-burn TODO | The **bench/factory closure of S-1/S-2/S-3** + E140/F1D1-4/global-LcsO ratchets — now issues under `label:source:production-todo` | **OPTIGA LcsO bench spec + factory burn ceremony** (the metadata bytes) |
| `docs/provisioning/provisioning-reference.md` | Hardened provisioning research (untrusted-CM) | Corrects S-1/S-2 defaults: F1D0's candidate locked shape uses `LcsO<op>` rather than ALW; observed `0xE0E3` is a full type-`0x12` device cert; candidate type-`0x11` pool is `{0xE0E8,0xE0E9,0xE0EF}`; production `0xE0E0` is device identity, not a wallet trust anchor | Provisioning research inputs + corrected OPTIGA object inventory; not an executable ceremony |
| `docs/security/red-teaming.md` | EVT bench-attack matrix | Bench tasks: §5.1 S-5 bus capture, §5.4 S-1/2/3 lockdown, §5.5 S-7d, §6.3 TAMP | The physical pass/fail bars + required instruments |
| `docs/security/audits/*-20260611-*.md` | 4 parallel adversarial paper-audits | se-tunnels HIGH-1 (SCP03 factory keys) — published-key fallback is **code-fenced since the audit** (`secure/src/nsc/mod.rs`, fence string ``Candidate SE050 profile is incomplete without non-public SCP03 transport keys``); a journaled first-boot candidate now exists, while handoff/recovery/E140/silicon production closure remains open; tz-tamper MED-2 (prod-config gate, closed by `f8effd45`); rest resolved-in-commit | The 2026-06-11 four-domain audit record (as-found — verify against current code) |
| `docs/security/security-audit-2026-06-firmware-signing.md` | WYSIWYS signing/display audit | None open — 12 findings resolved 2026-06-10 (C-1 native-ETH-value page) | The to/value/data→digest binding soundness proof |
| `docs/secure-elements/se050-silicon-findings.md` | First on-silicon SE050 stress run (2026-05-28) | S-5 round-trip evidence; S-7d mapping ⚠ **stale: says 0x6982, code now 0x6986** | Empirical on-silicon SE050 status |
| `docs/verification/c10-fips205-delta-audit.md` | FIPS-205 ↔ C10 deviation map | Scopes A3.1 (Lean spec ↔ Yul byte-layout); Rust↔Yul agree byte-for-byte | C10↔FIPS-205 deviation ledger |
| `archive/handoff-verity-c10-verifier.md` + `archive/verity-v0.1.0-primitive-map.md` | Verity Yul-verifier port — **archived 2026-06-18: the Verity-EDSL re-authoring approach was superseded by the live Aeneas→Lean extraction track** | The (now-secondary) multi-quarter Phase 0–7 plan to prove Yul refines the Lean reference | Historical: the EDSL-port route, kept for provenance (the active route is §FV / `docs/verification/verification-targets-2026-06.md`) |
| `docs/verification/how_to_math_proof_secureness.md` | What full FV of the wallet requires | The 3-piece decomposition (Lean ref + Yul-refines + 4337 scaffolding) | The overarching FV strategy + TCB boundaries |
| `docs/verification/lean-verification-research-2026-06.md` | AI-aided-Lean tooling research | Decision: stay on Aeneas; Lean-Squad orchestration; refuted-claims list | The extraction-tool decision + realistic close-rates |
| `docs/verification/spec-assurance-research-2026-06.md` | Spec-assurance + mutation-testing research | `leanloop mutate`/`kat`/`vet` design; spec-review checklist (⚠ `vet` RED/`NEGATION PROVED` not yet citable as assurance — F10) | The spec-strength tooling design rationale |
| `docs/security/production-security.md` | Bundles A–E → actionable plan | tracker issues (formerly work-todo #18–22 + #24: FI/key-mgmt/SCA/USB/supply-chain/root-key) | Bundle→backlog mapping + root-key tiering decisions |
| `docs/security/HARDENING.md` | Consolidated "what we do" requirements | §3.4 boot-attest, §3.5 provisioning gaps (= threat-model §9.4 / archived work-todo #8/#22, now tracker issues) | The normative hardening-requirements checklist |
| `docs/security/brownout-hardening.md` | Brownout/glitch design + rollout | Staged rollout; FI double-compute (#18) | The power-interruption recovery taxonomy |
| `research-bundles/A–F` | 6 deep-research prompt bundles | A→#18 FI, B→#20 key-mgmt, C→#18 SCA, D→#19 USB, E→#22 supply-chain, F→Trezor | The reproducible research-question + code-snapshot bundles |

---

## How this was built / how to extend

Reconciled by a fan-out workflow (`security-frontier-reconcile`, run `wf_718a4bc1-be4`, 2026-06-17): 7 agents
each verified one cluster against the repo + 1 mapped the corpus. To extend to another slice (companion / UI /
hardware), re-run the same shape over that slice's tracker issues (formerly work-todo sections). **Re-verify before trusting any row
older than the last commit it cites** — the whole point of this file is that the pointer, not the prose, is the truth.

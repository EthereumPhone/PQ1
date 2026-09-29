# Rollback architecture freeze receipt — 2026-07-26

**Scope:** composite freeze identity for the Draft 1.1 + Draft 1.2 rollback
and lock architecture gate. A file cannot embed its own digest, so the pair
is recorded here.

## Frozen pair

> **GATE STATE: REOPENED (2026-08-06) — REVIEW ATTRIBUTION. Milestone 0
> RE-CLOSED 2026-09-16 by owner de-minimis acceptance.** The digests below
> are the CURRENT freeze identity. They are **not** the digests the dual
> APPROVE was granted over — see "Re-freeze 2026-08-06" immediately after
> this table. No reviewer has run against Draft 1.2 `51be51b7…ebb8`, so this
> marker stays and `APPROVED_PAIR` in `check_rollback_freeze_pin.py` still
> names the reviewed pair: both track *review* attribution, not closure.
> Milestone-0 closure at the current bytes rests on "Amendment 2026-09-16"
> below, route 2 of this receipt's own re-closure rules. Do not cite this
> receipt as an *approval* of the current bytes; cite it as owner-accepted
> at specification stage.

| document | path | SHA-256 |
|---|---|---|
| Draft 1.1 (post-errata-4, unchanged) | `docs/security/a-b-firmware-rollback-architecture.md` | `abc058b1667d76cecf73f563340d24da17af4a35af61312e7abe61ee86da6284` |
| Draft 1.2 (post-BLOCKER-1, post-`fb66a1e5`) | `docs/security/fw-rollback-draft12-candidate-2026-07-21.md` | `51be51b78053097a8ad24b0a6c6a793335f66de9a4e6435d3ee65073a686ebb8` |

Superseded pair (GPT-5.6 SOL run-7 APPROVE, 2026-07-26): Draft 1.1
`57b7e359…8293` + Draft 1.2 `eb856dd4…700b` — superseded by the
BLOCKER-1 remediation recorded below; that APPROVE is historical and does
not carry to the new pair.

**Approved-but-superseded pair (dual APPROVE + owner ratification,
2026-07-26):** Draft 1.1 `abc058b1…6284` + Draft 1.2 `6173fe59…64ee`. That
approval is recorded in full below and remains the historical record of what
was reviewed; per ratification condition 3 it does **not** carry to the pair
in the table above.

## Re-freeze 2026-08-06 — mechanical re-pin, gate reopened

**What happened.** The 2026-07-26 ratification states: *"Any byte change to
either draft document reopens the gate."* On 2026-07-31, commit `fb66a1e5`
(*"fix(fv): rename HW-CONFIRM-\* ledger ids to HW-ASSUME-\* — the gate could not
see them"*) changed Draft 1.2. Draft 1.1 was untouched and still matches its
approved digest.

**The exact delta** — one token, line 375, inside non-normative Reconciliation
prose:

```diff
-   pin, `HW-CONFIRM-PUTKEY-KCV-RESP`, DEK-liveness bench. This draft's
+   pin, `HW-ASSUME-PUTKEY-KCV-RESP`, DEK-liveness bench. This draft's
```

Provenance verified by reproduction:
`git show fb66a1e5^:docs/security/fw-rollback-draft12-candidate-2026-07-21.md |
sha256sum` = `6173fe59…64ee`, i.e. the pre-`fb66a1e5` bytes are exactly the
approved ones, and the edit above is the entire difference.

**Why the bytes were NOT reverted.** `HW-ASSUME-PUTKEY-KCV-RESP` is the
canonical identifier in `contracts/verification/docs/HW_ASSUMPTIONS.json:116`,
enforced by `contracts/verification/scripts/check_hw_assumptions.py` in CI.
Restoring `HW-CONFIRM-*` would reintroduce an orphan id that the assumption
gate cannot see — trading a governance break for a verification break. The
rename stands; the freeze identity is re-pinned to it.

**What this re-pin does and does not do.**

- **Does:** record the current freeze identity, so drift is detectable from here
  on, and give the new CI gate (below) a single source of truth.
- **Does NOT:** re-grant the dual APPROVE, and does not re-close Milestone 0.
  No reviewer has run against `51be51b7…ebb8`. Ratification condition 2
  (honest recording) forbids describing the gate as closed at these bytes.

**To re-close Milestone 0, one of:**

1. Re-run both exact-digest legs (GPT-5.6 SOL + Claude Opus 5 second leg)
   against the pair in the table above, plus owner ratification; **or**
2. A **de-minimis owner acceptance** naming this specific delta — that the
   `HW-CONFIRM-*` → `HW-ASSUME-*` rename in non-normative prose does not
   disturb any reviewed row — recorded here as an amendment. This is the cheap
   path and the diff above is the entire scope it must cover.

Either way a re-freeze is now owed, so the "adopting it reopens the freeze"
objection to any *substantive* amendment (e.g. the recovery-key row, the §6.3
step-11 zeroization row, or the fingerprint-input-scope row discussed in
`vendor-signing-key-compromise.md`) charges a cost that is already sunk. If
substantive rows are wanted, batch them with this repair rather than paying two
review cycles.

**Root cause and the fix that landed with this re-pin.** Nothing pinned these
digests anywhere in `Makefile`, `.github/`, `xtask/`, `scripts/`, `tools/` or
`contracts/verification/`, so a single-token edit in an unrelated workstream
silently reopened a ratified gate and went unnoticed for six days. The gate
`contracts/verification/scripts/check_rollback_freeze_pin.py` (run by
`make -C contracts/verification verify-rollback-freeze-pin`, and in CI) now
recomputes both digests against **this table** and fails the build on any drift.
Re-pinning is therefore a deliberate, reviewable edit to this file rather than
an invisible side effect of editing a draft.

## Amendment 2026-09-16 — owner de-minimis acceptance (Milestone 0 re-closed)

**Owner acceptance (2026-09-16):** "I accept the one-word rename, record the
de-minimis acceptance." Recorded under route 2 of "To re-close Milestone 0"
above, which fixes this acceptance's scope as exactly the `fb66a1e5` delta.

**Scope — the entire delta accepted.** One line of non-normative
Reconciliation prose in Draft 1.2 (hunk `@@ -372,7 +372,7 @@`):

```diff
-   pin, `HW-CONFIRM-PUTKEY-KCV-RESP`, DEK-liveness bench. This draft's
+   pin, `HW-ASSUME-PUTKEY-KCV-RESP`, DEK-liveness bench. This draft's
```

The token is a hardware-assumption ledger id. `HW-ASSUME-PUTKEY-KCV-RESP` is
the canonical spelling in `contracts/verification/docs/HW_ASSUMPTIONS.json`,
enforced by `contracts/verification/scripts/check_hw_assumptions.py`; the old
`HW-CONFIRM-*` spelling was an orphan the assumption gate could not see. It
appears in a list of other people's open gates, disturbs no reviewed row, and
carries no normative force (Draft 1.2's Reconciliation section is descriptive).

**Reproduction before recording (2026-09-16).**

- `sha256sum` of both drafts equals the pinned table above, and
  `make -C contracts/verification verify-rollback-freeze-pin` passes
  (self-test: 1 good + 38 parser mutations + 11 attribution controls ok).
- `git show fb66a1e5^:docs/security/fw-rollback-draft12-candidate-2026-07-21.md
  | sha256sum` = `6173fe598d43ec7ac597f7ab843142bebe3456d63a63653cebc0ed369ad964ee`
  — the pre-rename bytes are exactly the dual-approved ones.
- `git show fb66a1e5 --stat` on that path: 1 file changed, 1 insertion,
  1 deletion. The diff quoted above is the whole change.
- Draft 1.1 is untouched and still matches its approved digest
  `abc058b1667d76cecf73f563340d24da17af4a35af61312e7abe61ee86da6284`.

**What this acceptance does.** Restores Milestone-0 closure at the current
frozen pair (Draft 1.1 `abc058b1…6284` + Draft 1.2 `51be51b7…ebb8`).
Specification-stage authority only, per Draft 1.1 §14's own bounds.

**What it does NOT do.**

- It is **not a review**. The dual APPROVE stays recorded over
  `6173fe59…64ee` only; the `GATE STATE: REOPENED` marker and the script's
  `APPROVED_PAIR` constant are deliberately left naming the reviewed pair, so
  a green gate keeps telling readers no reviewer ran against these bytes.
- Ratification condition 1 (precedent cap) is untouched: this authorizes no
  irreversible or hardware act — not physical-backend selection,
  `OPEN-OTP-1..3` closure, OTP programming, OPTIGA LcsO ratchets, nor the §13
  named-board sacrificial campaign. Each still needs its own owner acceptance.
- It covers **only** the delta quoted above. The substantive amendments parked
  in `docs/security/vendor-signing-key-compromise.md` (FSBL fingerprint input
  scope, the §6.3 step-11 zeroization row, the recovery-key row) are NOT
  accepted here; adopting any of them changes the bytes again and owes a fresh
  gate run.

## Gate history (all GPT-5.6 SOL `ultra`, exact-digest)

- **Run 1 (2026-07-26):** NO-GO — 10 findings (A14/A16/A18/A28/A35
  availability-constructor staleness, A38/B4 factory-genesis contradiction,
  B3 burn-window matrix gap, C1 digest drift, C2 heal ambiguity, C3
  invariant overscope). Coordinator reproduced the two load-bearing claims;
  the C1 "drift" was the `589fb771` reviewer-lineup change only.
- **Owner decision (2026-07-26):** `RecoverySameEpoch` and
  `FloorBoundAccepted` DECLINED (availability, not safety; service/RMA
  accepted). Executed as bounded in-text errata.
- **Run 2 (2026-07-26):** NO-GO — all 10 remediated; 2 remaining blockers
  (B3 carried; A38-new mutation-owner gap). Remediated: §11 burn-window
  rows + R2.6 carve-out; `FirstBootLockWriter` owner entry.
- **Run 3 (2026-07-26):** NO-GO — both blockers remediated; §18 at 28
  RESOLVED / 12 GAP (all OPEN-register production gates). Sole finding D1:
  superseded digests named as the base. Remediated by this receipt.
- **Run 4 (2026-07-26):** NO-GO — D1 remediated; sole finding R4-1:
  Draft 1.2 §3 rows 1–2 + OPEN-LOCK-1 still carried heal semantics,
  contradicting the adopted verify-never-heal. Remediated (rows now
  hard-fail; OPEN-LOCK-1 re-scoped to burn-path one-shotness +
  Phase-B crash-consistency).
- **Run 5 (2026-07-26):** NO-GO — R4-1 edits remediated; findings R5-1
  ("factory-escape corrector" / "heal-then-lock" wording) and R5-2
  (burn-window re-enter vs tz-1 hard-fail contradiction). Remediated:
  wording fixes + phase-appropriate profiles on both sides (re-attempt
  only on exactly the pre-ceremony staged profile; else halt/RMA).
- **Run 6 (2026-07-26):** NO-GO — R5-1/R5-2 remediated; sole finding R6-1:
  Draft 1.2's Base pin still named the pre-R5 Draft-1.1 digest
  (`ee982785…`) while this receipt bound `57b7e359…`. Remediated: Base
  re-pinned; Draft 1.1 digest unchanged since. (Run 6 also recorded a
  pre-freeze evidence GAP: BENCH-4/A3/A4 completion evidence is owed
  before the Option-B/A freeze review — tracked as #401/#387/#388, not a
  blocker for this architecture freeze.)
- **Run 7 (2026-07-26):** **APPROVE** — no stage-blocking defect found.
  §18: 28 RESOLVED / 12 GAP (the 12 are Draft 1.1's declared later-stage
  production/silicon gates — OPEN-JRN-HW-1, JRN-DUR-1, ECC-1, FLASH-HW-1,
  RAM-1, OTP-1..3, REL-1, C10-1, §12.3 capacity/EOL, VBAT retention,
  ES0499 envelope). BENCH-4/A3/A4 completion (#401/#387/#388) recorded
  as a pre-FSBL-freeze evidence gap, non-blocking for this architecture
  freeze. (Tracker correction 2026-07-26: BENCH-4 is issue #401; #398 is
  BENCH-1. Draft 1.2's frozen text carries the harmless "#398" mislabel
  in its BENCH-4 row and receipt — corrected here, not in the frozen
  text.) Model-identity honesty: runs 1–4 invoked and self-attested
  `gpt-5.6-sol` at `ultra`; runs 5–7 invoked identically but the runtime
  exposed only "Codex, GPT-5 family" — recorded as GAP, not hidden.
- **Second-leg run 1 (2026-07-26, Claude Opus 5 — runtime
  `claude-opus-5`; effort attestation gap: the runtime exposes numeric
  effort `60`, not the policy's `xhigh` label — recorded, not claimed):**
  NO-GO on one stage-blocker. **BLOCKER-1**: Draft 1.2's mandatory
  Phase-B provisioning journal had no page owner in Draft 1.1 §5 (bank-1
  page 127 still assigned to the Tropic01-key reservation retired with
  that backend on 2026-07-14) and no writer owner in §6.3
  (`FirstBootLockWriter` performs no flash write; `RuntimeStateWriter`
  allowlists stop at page 126) — while
  `docs/provisioning/first-boot-requirements.md` R3.x/R4.x and
  `secure/src/first_boot/journal.rs` already own page 127. The
  unremediated sibling of A38-new. Coordinator reproduced every
  load-bearing claim (§5 registry row + prose, §6.3 writer maps,
  FROZEN-FLASH-MUT-1 enumeration, first-boot spec R3.x, journal.rs)
  before remediation. Remediated in Draft 1.1's text: §5 page-127
  reassignment + prose; §6.3 `FirstBootJournalWriter` (page-127
  commit-LAST appends + journal-gated page-126 erase-and-reprogram,
  `FirstBootLockWriter`-equivalent fencing); FROZEN-FLASH-MUT-1
  enumeration gains both operations; §12.6 item 4 names the tz-1
  tripwire. In Draft 1.2: §3 row-6 attribution corrected to "executed by
  this row" (the leg's §6-Q4 traceability finding). Verification:
  `cargo test --locked -p pqsigner-fsbl-tests --test
  draft11_deletion_experiments` → 7/7. The leg's §18 tally: 23 RESOLVED,
  5 RESOLVED-rule/GAP-evidence, 1 advisory, 10 declared-OPEN GAPs, 1 new
  GAP (= BLOCKER-1). §6 Q1–Q4 answered: Q1 no missed binding signal; Q2
  yes, conditionally; Q3 burn window fully covered, Phase-B rows are
  declared OPEN-LOCK-1; Q4 the row-6 attribution defect, no frozen-row
  contradiction.
- **Run 8 (2026-07-26, GPT-5.6 SOL — invoked as `gpt-5.6-sol`/`ultra`;
  the runtime attested only "Codex, GPT-5 family", no model/effort
  labels — recorded, not claimed):** **APPROVE** over the frozen pair.
  BLOCKER-1 remediation confirmed consistent across §5 registry/prose,
  §6.3, FROZEN-FLASH-MUT-1, §12.6 item 4; the run-7 basis is not
  reopened; no new stage-blocker. §18 answers changed by the delta:
  Q15/Q37/Q39 now YES at the rule level (physical fit stays with the
  declared evidence gates).
- **Second-leg run 2 (2026-07-26, Claude Opus 5 — runtime
  `claude-opus-5`; the `xhigh` label is not exposed by the runtime —
  recorded, not claimed):** **APPROVE** over the same frozen pair.
  BLOCKER-1 remediation confirmed to the letter of its specified minimal
  repair; no-new-defects sweep clean; the §6-Q4 attribution repair
  verified against §7.4's text. Three banked notes added below.
- **Adversarial ratification calls (2026-07-26, owner-requested, mutually
  blind):** each leg was asked to steelman the case that the recorded
  attestation gaps block ratification, then render a call. GPT-5.6 SOL:
  **RATIFY-WITH-CONDITIONS** — (1) the owner receipt names both digests
  and explicitly accepts the unverified serving side; (2) no claim of
  serving-side attestation, only correctly invoked dual approval with
  recorded gaps; (3) the exception is confined to Milestone 0 and cannot
  satisfy any later implementation/production/hardware/release/
  irreversible-action gate without authoritative serving-side evidence
  or a fresh owner risk acceptance for that gate. Claude Opus 5:
  **RATIFY-WITH-CONDITIONS** — (1) cap the precedent at Milestone 0, no
  carry-forward to irreversible-action gates; (2) harvest the Opus
  transcript evidence and narrow the receipt's attestation sentence;
  (3) state the GPT residual precisely, with where it was looked for.
  Both steelman attacks failed on the same two rocks: runs 5–7 produced
  real, coordinator-reproduced findings from inside the unattested
  window, and Milestone 0's authority is reversible/nonshipping by
  construction. Conditions adopted in the ratification section below.

**DUAL APPROVAL over one digest pair, 2026-07-26:** Draft 1.1
`abc058b1667d76cecf73f563340d24da17af4a35af61312e7abe61ee86da6284` +
Draft 1.2 `6173fe598d43ec7ac597f7ab843142bebe3456d63a63653cebc0ed369ad964ee`.

This meets the dual exact-digest review requirement of Draft 1.1 §14
Milestone 0; owner ratification (below) completed Milestone 0 the same
day. Specification-stage approval only — no implementation, production,
hardware, or irreversible-action authority.

The 12 run-3 GAPs are Draft 1.1's own declared production gates
(OPEN-JRN-HW-1, OPEN-JRN-DUR-1, OPEN-ECC-1, OPEN-FLASH-HW-1, OPEN-RAM-1,
OPEN-OTP-1..3, OPEN-REL-1, OPEN-C10-1, §12.3 capacity/EOL, VBAT retention,
master-list completeness, ES0499 envelope) — they gate implementation and
silicon, not this architecture freeze, per Draft 1.1 §14's own milestone
structure.

## Attestation evidence (harvested 2026-07-26)

The reviewers' recorded attestation gaps describe what each could see
about ITSELF in context. The contemporaneous local transcript layer is
stronger, and was harvested 2026-07-26 (coordinator verification):

- **Opus leg:** Claude session transcripts
  `c9a232e0-22f4-49df-9d90-fa2a9a1eb24a` and
  `c9eea95e-36ad-4970-ae95-65e79b4fed7c` (both 2026-07-26): 41 and 38
  assistant records, every record `model:"claude-opus-5"` +
  `effort:"xhigh"`, bound to server-issued requestIds. The policy's
  exact tier label is durably recorded at the transcript layer.
- **GPT leg:** all 14 codex rollout files dated 2026-07-26 under the
  PQSigner_OS cwd record `model:"gpt-5.6-sol"` +
  `reasoning_effort:"ultra"` on every turn; the run-7-era rollout
  `019f9ebe-fbd0-7503-aa26-ac982f3e7514` (2026-07-26) carries the
  then-approved pair's digests (`57b7e359…`/`eb856dd4…`), tying run to
  record. (The "irreducible — verified negatively" assessment in the
  Opus leg's ratification call inspected `session_meta` only, which does
  lack both fields; the per-turn records carry them. Coordinator
  verification falsified that one claim. The same call's self-reported
  near-miss — almost citing the `pq-fv-wave*` trail, a concurrent FV
  wave, as corroboration — stands as its own recorded retraction.)
- **Honest residual (unchanged in kind):** both transcript layers are
  written by the local runtime on the request/response path; neither is
  a server-signed serving attestation. A silent API-side fallback would
  remain invisible. In-context self-report remains unavailable — that
  is what the reviewers could see about themselves, and what the
  original gap sentences in the gate history above record.

## Owner ratification (2026-07-26)

The owner ratified Milestone 0 as complete on 2026-07-26, adopting both
reviewers' convergent RATIFY-WITH-CONDITIONS calls:

1. **Precedent cap.** This acceptance is confined to Milestone 0. It
   does not satisfy, and must not be cited to satisfy, any later gate
   that authorizes an irreversible or hardware act — Foundation A
   physical-backend selection, `OPEN-OTP-1..3` closure, OTP programming,
   OPTIGA LcsO ratchets, or the §13 named-board sacrificial campaign.
   Each such gate requires either a runtime with authoritative
   serving-side attestation or a fresh explicit owner acceptance naming
   that gate.
2. **Honest recording.** Neither this receipt nor any status claim may
   describe the gate as serving-side-attested. The correct statement is:
   correctly invoked dual approval over one exact digest pair, with both
   legs' policy model+effort contemporaneously recorded at the local
   transcript layer; server-side serving not independently attested.
3. **Sequencing.** This ratification is recorded and pushed in the same
   commit as the re-frozen trio; the approved pair's digests
   (`abc058b1…6284` / `6173fe59…64ee`) were re-verified unchanged at
   commit time. Any byte change to either draft document reopens the
   gate.

Milestone 0 of Draft 1.1 §14 is therefore CLOSED: dual exact-digest
APPROVE over one digest pair + owner ratification, both recorded here.
Specification-stage authority only, per §14's own bounds.

*Superseded 2026-08-06: that closure covered digests `abc058b1…6284` /
`6173fe59…64ee` only. Draft 1.2's bytes have since changed (see "Re-freeze
2026-08-06"). Milestone-0 closure at the current bytes rests on "Amendment
2026-09-16 — owner de-minimis acceptance", not on this paragraph, and the
dual APPROVE still covers only the pair named here — do not quote this
paragraph as current closure.*

## Banked non-blocking observations (Opus-5 leg run 1)

- **OPTSTRT whole-shadow constraint:** on STM32U5 the option-byte program
  commits the entire option-byte shadow set, not a single field, so
  §6.3's "programs no option byte other than RDP" is a net-effect
  requirement — the writer must snapshot every non-RDP word into the
  shadows and re-verify them across the program. The pair already fails
  closed (RDP `0xCC` paired with any wrong staged word ⇒ halt/RMA).
  Implementation constraint; belongs to the first-boot spec's writer
  section.
- **OPEN-LOCK-2 OTP range:** the published "canonical comparison ranges"
  should explicitly enumerate the 32-QW OTP bank alongside flash and
  option bytes — catches the interdiction OTP-poisoning case (OTP is
  one-way even at RDP-0; Draft 1.1's orphan rule makes poisoning a
  detectable brick, and the user's external SWD check should see it).
- **Q16 advisory:** `SurvivingInstallGeneration` simplification —
  deferred to implementation planning, not this gate.
- **§5 warning build** must be re-run with tz-1 linked in before
  Foundation A selects a family — now structural via §12.6 item 4.
- **Row-2 compare set** (OPTR/WRP/SECWM/TZEN/BOOT_LOCK/RDP) confirmed as
  the correct superset: on U585, BOOT_LOCK lives in SECBOOTADD0R, not
  OPTR.
- **ALL_DONE window phrasing (Opus run 2):** §6.3's "before `ALL_DONE`"
  bounds the ceremony window's end, not its start — the composite
  prohibition on pre-confirm journal writes holds via the first-boot
  spec's R2.2 blank-check and R2.4 ("touch no journal state"), with R3.x
  Phase-B by construction. No text change needed; implementation note.
- **§3 line anchors (Opus run 2):** Draft 1.2 §3's Draft-1.1 line
  anchors are stale against the frozen digest (e.g., row 6 cites
  2813–2827; §7.4 sits earlier post-errata); resolvable by section
  number + quoted text, and Draft 1.2 declares the staleness itself.
  Cosmetic.
- **FROZEN-FLASH-MUT-1 pre-existing gap (Opus run 2):** the bank-1-busy
  enumeration does not name ordinary runtime page-123/124/125 writes;
  pre-existing, out-of-delta, narrowed rather than widened by the
  remediation. Examine during Foundation A mutation-boundary work.

## Review-policy note

Reviewer lineup per on-master policy commit `589fb771`: Claude Opus 5
(`opus`) at `xhigh` effort and GPT-5.6 SOL at `ultra` effort, each over the
same frozen digest, neither seeing the other's report first. Both legs were
invoked exactly per policy and both have now APPROVED the same frozen pair
(GPT run 8 and Opus run 2, 2026-07-26). The originally recorded attestation
gaps are narrowed by the harvested transcript evidence above: both legs'
exact policy model+effort are contemporaneously recorded at the local
transcript layer; only server-side serving attestation remains unheld, and
the ratification records that residual honestly. A follow-up (not a
ratification gate): amend the `589fb771` procedure so future legs capture
attestation at run time rather than reconstructing it afterward, and so the
Milestone-0 precedent-cap is codified for irreversible-action gates.

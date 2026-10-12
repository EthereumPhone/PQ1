# Brief: turn untracked research recommendations into issue drafts

You are helping file GitHub issues on `EthereumPhone/PQ1` (a public repo) for a hardware wallet called pq1 / PQSigner OS. A research report produced 70 recommendation items. Its **defects** were already filed yesterday as issues #846 to #867. The owner now asked: "file whatever has not been filed as an issue yet, that we can actually do with this version of the board". Your job is to decide, for each item in your manifest, what (if anything) still needs an issue, and to draft it. **You do not file anything. You do not run `gh issue create`, `gh issue comment` or any other write to GitHub. You write draft files only.** I review every draft and file them myself.

The two ways this goes wrong, in order of cost:

1. **A duplicate.** The tracker has 606 open issues. Many recommendations are already asked for by an existing issue, in whole or in part. A new issue that repeats one is noise the owner has to close. Read issue **bodies**, not titles, before saying something is untracked. An earlier pass of this same research said "untracked" for things #106 and #835 already covered.
2. **A stale or wrong premise.** The report was written at commit `c75b0d9c`. Master is now 159 commits later. Several things the report says are missing may have landed. Every "today the code does X" sentence in a draft must be re-read at master by you.

## Where things are

- **Master source tree (read this for every code claim):** `/home/nicola/.local/state/pqsigner-research/security-frontier-2026-10/landing` at commit `c2fab9704b54a4b67b807f8b7bb79badf5bf6bec`. **Read-only for you: do not edit, build, test or run git write commands there.** Do not read code from `/home/nicola/repos/PQSigner_OS` for citations; that checkout is the old commit with uncommitted changes. (Use it only if you need to see what a report line number pointed at.)
- **The report:** `<master tree>/docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`. Your manifest gives line ranges. Each surface section has "Recommendations" (the item text), "Considered and rejected" and "Open questions and unmeasured claims". Lines 226-290 are a dated correction note; read it once, because it corrects some rows the item text relies on. The report's own line numbers for code are at `c75b0d9c` and are NOT valid on master.
- **Raw data per item:** `<master tree>/docs/security/adversarial-review/findings/security-frontier-research-2026-10-11/` plus the "Data file" path in your manifest. Cluster files hold the merged recommendation (`merge`) and an independent review (`skeptic`). Where they disagree, the skeptic's corrected value wins.
- **Every existing issue, with body, as of today:** `/home/nicola/.claude/projects/-home-nicola-repos-PQSigner-OS/7844318a-f4f1-49a2-b794-31ae48f548cc/research/issues2/all_issues.json`. Two helpers in the same folder:
  - `python3 <folder>/iss.py 846 131` prints full bodies. `-t` prints title, state and labels only.
  - `python3 <folder>/isearch.py 'regex' [-o] [-n 40]` searches all titles and bodies. `-o` = open only.
  - Comments are not in the dump. `gh issue view N -R EthereumPhone/PQ1 --comments` is allowed (read-only) when a body is ambiguous.
- **The issues filed yesterday** (#846 to #867) and the 14 comments: bodies are in the dump, and the drafts are in `<data folder>/issues-filed/`. Read the ones on your surface first. Much of your manifest overlaps them.
- **Format and tone example:** `<data folder>/issues-filed/08-halt-on-glitch-no-zeroize.md`.
- **Project rules:** `<master tree>/CLAUDE.md`.

## What "this version of the board" means

Board: AL_A66_MB_V10. STM32U585CIU6, 48-pin UFQFPN, TrustZone. OPTIGA Trust M and SE050 secure elements. NV3007 SPI display with **no read-back line** (no MISO). Two buttons on PA0 and PA1. **No battery.** Free pads PA10, PB4 and PC13 are not routed anywhere. PA6 is not connected on the board (it carries a timer output with no load). Enclosed EVT units can only be flashed over USB DFU and have no debug port; the open bench board has a debug port but **no display panel fitted**.

Classify each piece of work:

- **DOABLE**: firmware, bootloader (FSBL), option bytes, host tools, CI and process, documentation, companion-app guidance. No hardware change.
- **DOABLE-FACTORY**: a factory or assembly process step that needs no change to the PCB, the parts list or the enclosure tooling.
- **DOABLE-BENCH**: a measurement or test campaign on existing units. Say exactly what it needs (a unit with a panel, a debug port, an oscilloscope, a fault-injection rig, sacrificial units, a hand-modified unit).
- **NEEDS-NEW-BOARD**: needs a layout, parts-list, package or enclosure change, or needs PA6, PA10, PB4 or PC13 wired to something. **Do not draft these.** List them in your dispositions with one line on what change they need.

Mixed items: draft only the doable part, and say in the body which part waits for a new board.

## Never draft

- Anything that reopens an owner decision: no ML-KEM wrap on the secure-element tunnels; stay on SHA-2 (no SHAKE); no battery; no TROPIC01; no classical signer anywhere; no OLED; no EntryPoint v0.7/v0.8 migration; OPTIGA ship-blockers S-1/S-2/S-3 are deferred by design; `CMD_GET_INIT_CODE` returning a bootstrap signature without a prompt is WON'T-FIX; the pixel-UI scroll-to-end rule; the glyph atlas living in the non-secure slot; keep BHK as the SE050 key axis; no heap. Also anything `CLAUDE.md` marks "do not re-raise".
- The three rejected items (SCA-09, M01, CS-06) and anything in a "Considered and rejected" list.
- Wallet-contract changes (tracked as the owner decision #867).
- For items whose status is "redesign needed": draft only the narrower surviving form the report describes, never the refuted original.

## What to do for each item in your manifest

1. Read the item's text in the report and its data file. List its concrete sub-actions.
2. For each sub-action find who already asks for it. Start with the related issues in the manifest, then search the dump with your own keywords (function names, register names, the idea in plain words). Open and read every candidate body. Note open or closed. Decide: COVERED (name the issue and quote the line that asks for it), PARTLY, or UNTRACKED.
3. Re-read the premise at master. If the thing is already implemented, say DONE-ON-MASTER with the file and line. If a closed issue claims it is fixed, check the fix is really there.
4. Classify board feasibility as above.
5. Pick one outcome for the item:
   - `NEW-ISSUE`: an untracked, doable remainder exists. Draft one issue for the item (not one per sub-bullet), covering only the remainder. Group by the change that would land it.
   - `COMMENT`: the remainder is small and belongs on an existing open issue. Draft a comment for that issue.
   - `COVERED`: nothing to file. Say which issues cover which parts.
   - `DONE-ON-MASTER`, `NEEDS-NEW-BOARD`, `OWNER-DECISION-ONLY` (nothing can be built until the owner decides; describe the decision in one line), or `SKIP` with a reason.
   An item can produce a `NEW-ISSUE` plus one or two `COMMENT`s if that is the honest shape. Prefer fewer, better drafts. If you are unsure whether something is covered, say so in the disposition and do not draft; I will decide.
6. Also read your sections' "Open questions and unmeasured claims" lists. For each one that a measurement on existing hardware could settle and that no issue tracks, add an entry to `measurements` in your dispositions file (do not draft issues for them; I will combine them).

If, while reading master, you find a **new defect** that the report did not record, do not draft it. Put it under `new_defects` in your dispositions with file, line, a quoted line and two sentences.

## Draft format

Write each new-issue draft to `<folder>/drafts/<your group>/<ITEM-ID>-<short-slug>.md`:

```
TITLE: <one line, plain, says the change and the reason; under 160 characters>
LABELS: enhancement,priority:<high|medium|low>,surface:<...>[,surface:<...>],source:frontier-research-2026-10
---
## Summary
<3 to 6 sentences. What to change, what it protects against, and why it is not already tracked.>

## What the code does today
<bullets with `path:line` at master and what the line does. Only lines you opened at master.>

## What is already tracked elsewhere
<bullets: #N covers X. So this issue is only about Y.>

## Proposed work
- [ ] <concrete, checkable steps>

## What it needs
<Firmware only / a factory step / a bench unit with ... . One or two lines. If it must land before the first unit is locked (bootloader or option bytes), say so in bold.>

## Limits
<what this does not protect against; what is unmeasured; the reviewer's objections that survive>

## Related
<#N list, public sources with links>

---
<sub>**Provenance.** Security frontier research, 2026-10-11 (report item <ID>, section <N>). Report priority <P0..P3> is a research rating, not an owner decision. Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading and public sources; nothing was run on silicon. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`.</sub>
```

Comment drafts go to `<folder>/drafts/<your group>/c-<issue number>-<ITEM-ID>-<slug>.md`:

```
COMMENT_ON: <issue number>
---
<the comment: what the research adds to this issue, with master `path:line` evidence, and a short checkbox list if it adds work. End with the same Provenance line.>
```

Rules for the text:

- Labels: priority from the report's table priority (P0 or P1 = `priority:high`, P2 = `priority:medium`, P3 = `priority:low`). Do not use `bug`, `finding`, `ship-blocker` or `priority:critical`. Use `documentation` instead of `enhancement` for a pure docs change. Surface labels that exist: `surface:secure-element`, `surface:clear-signing`, `surface:sca-fi`, `surface:trusted-ui`, `surface:lifecycle`, `surface:hardware`, `surface:release`, `surface:docs`, `surface:trustzone`, `surface:runtime`, `surface:lockdown`, `surface:prodtest`, `surface:fw-update`, `surface:entropy`, `surface:onchain`, `surface:offchain`, `surface:contracts`, `surface:usb`, `surface:companion`, `surface:fv`.
- Plain, direct English for a reader who has not seen the report. Expand an acronym the first time. No em-dashes or en-dashes; use commas, colons or full stops. No filler and no praise.
- Write "invariant 10", never "invariant #10": on GitHub `#10` links to issue 10. Use `#N` only for a real issue number you looked up.
- Say what was not checked. Never write "verified" for something you only read. Nothing was run on silicon.
- Do not copy the report's code line numbers. Cite master lines you opened.
- Do not state an attack works unless the report has a proof of concept (it has none).
- The body must stand alone: the report is not on master yet, so a reader cannot open it.

## Dispositions file

Write `<folder>/drafts/<your group>/dispositions.json`:

```json
{
 "items": [
  {"id": "M05", "outcome": "NEW-ISSUE|COMMENT|COVERED|DONE-ON-MASTER|NEEDS-NEW-BOARD|OWNER-DECISION-ONLY|SKIP",
   "board": "DOABLE|DOABLE-FACTORY|DOABLE-BENCH|NEEDS-NEW-BOARD|MIXED",
   "drafts": ["M05-....md", "c-130-M05-....md"],
   "sub_actions": [{"what": "...", "status": "COVERED|PARTLY|UNTRACKED|DONE-ON-MASTER|NEEDS-NEW-BOARD|OWNER", "by": "#847", "evidence": "quoted line from the issue body, or master path:line"}],
   "issues_read": [847, 854, 130],
   "one_line": "plain sentence I can paste into a summary for the owner",
   "unsure": "anything you could not settle"}
 ],
 "citations": [{"draft": "M05-....md", "path": "fsbl/src/main.rs", "line": 123, "snippet": "an exact substring of that line at master"}],
 "measurements": [{"surface": "fi", "what": "...", "needs": "...", "tracked_by": "none or #N"}],
 "new_defects": []
}
```

`citations` must hold **every** `path:line` that appears in your drafts, with a snippet that is an exact substring of that line in the master tree. I check them mechanically; a citation that does not match is treated as an unverified claim and the draft is sent back.

Your final message to me: a table of item, outcome, draft file names, and one line each; then anything you were unsure about. Keep it under 500 words. The drafts and the JSON are the deliverable.

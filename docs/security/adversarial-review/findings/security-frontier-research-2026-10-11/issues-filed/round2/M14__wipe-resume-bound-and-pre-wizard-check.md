TITLE: Lockout wipe: bound the boot-time resume, add a terminal "wipe incomplete" state, and check both secure elements for survivors before the setup wizard
LABELS: enhancement,priority:high,surface:secure-element,surface:lifecycle,source:frontier-research-2026-10
---
## Summary

The wipe that follows ten wrong PINs (and the tamper wipe, and the boot-time counter cross-check wipe) is a multi-step operation across two secure elements (SE) and two flash pages. #106 and #123 track making its result honest: stop treating "unknown" as "wiped", and only clear the resume flag, reset the attempt counter and show "WALLET WIPED" after a verified result. Two things that fix needs are not asked for by any issue. First, once a failed wipe keeps the flag armed and the counter charged, a persistent SE fault makes every boot retry the wipe for the life of the device, so the resume needs a bound and a designed end state. Second, after a failed resume the boot carries on into the setup wizard or the PIN prompt, and nothing looks for surviving objects before the wizard runs. A third point, that one SE leg alone clears the resume flag, is noted as a symptom in the #106 comment; this issue gives the fix a place (the layer that sees both legs). Together these make the wipe a resumable transaction with a defined end. It does not make a wiped device usable again; that is #168.

## What the code does today

- `secure/src/main.rs:1949`: at boot, a wipe is resumed when the page-125 flag is armed or the page-124 attempt counter is at its maximum.
- `secure/src/main.rs:1957`: the result of `factory_reset_admin()` is discarded. `secure/src/main.rs:1962` then resets page 124 and `secure/src/main.rs:1963` shows "WALLET WIPED" / "restore from seed", whatever happened. There is no retry count and no halt: the boot continues past this block.
- `secure/src/main.rs:3982`: the setup wizard runs when `is_provisioned` is false. `secure/src/dual_se.rs:142`: that is the AND of the two SE checks. The OPTIGA check reads one sentinel object (`secure/src/optiga/mod.rs:976`), and writing that sentinel is the first write of the OPTIGA wipe (`secure/src/optiga/mod.rs:2829`). So the wizard is reachable as soon as that one write has landed. Nothing between the wipe block and the wizard looks for surviving SE050 objects.
- `secure/src/se050/mod.rs:3222`: the page-125 flag is erased by the SE050 leg when `admin_exists()` is false, and `secure/src/se050/mod.rs:679` makes that false when the SE050 cannot be reached. The dual-SE wrapper runs both legs (`secure/src/dual_se.rs:632`, `secure/src/dual_se.rs:633`) and has no say over the flag.
- `secure/src/hw/flash.rs:626`: page 125 holds the wipe flag at offset 16. `secure/src/hw/flash.rs:710`: the same page holds the duress wipe-mode word at offset 32. A resume counter would be a third field on this page, and erasing the page clears all of them.
- `secure/src/hw/tzic.rs:246`: the tamper path arms the same flag, so whatever bound is chosen also governs tamper-triggered wipes.
- `secure/src/se050/mod.rs:2428`: a code comment records the SE050 as "single-use post-lockout", while the wipe screens (`secure/src/main.rs:1963`, `secure/src/nsc/cmd_request_unlock.rs:209`) tell the user to restore from seed.

## What is already tracked elsewhere

- #106 and its comment of 2026-10-12 cover the SE050 side: three-state existence probes, the admin object deleting itself after failed data deletes, the `Ok(())` return when the admin PIN cannot be derived, the three unconditional page-124 resets, and gating the flag erase and the screen on a verified wipe. The comment also notes that the SE050 leg discards the flag the OPTIGA leg armed; it does not say where the clear should live.
- #123 covers the OPTIGA side: verification, write order, the swallowed flag arming, and the stale OPTIGA counter that re-triggers a wipe.
- #107 and #129 cover objects missing from the wipe lists.
- #168 and its comment cover the fact that a wiped device cannot be set up again on the locked profile.
- #865 (item 4) covers moving the wipe decision logic into a workspace crate so its tests run, adding a cold reboot to `pin-gate-wipe-e2e`, and the lockout-wipe fault suite that is not in the tree.
- #853 covers which unlock entry point triggers the wipe. #200 covers the cold-reboot receipt for the boot-time counter cross-check.

So this issue is only about the resume bound and end state, the check before the wizard, and moving the flag clear to the layer that sees both legs.

## Proposed work

- [ ] Write the end states of a wipe as a small explicit state machine (verified; incomplete and retryable; incomplete and given up) in the workspace crate that #865 asks for, with host tests. Inputs: a verdict per SE leg (wiped, not wiped, unknown), the flag, and the resume count.
- [ ] After an unverified wipe, on the first attempt or on a resume, do not continue the boot into the wizard or the PIN prompt. Show one fixed screen (for example "WIPE INCOMPLETE" / "power cycle"). Decide whether the device halts there or still brings up USB with a "wipe incomplete" status that a companion and a test can read.
- [ ] Bound the resume, and record which form was chosen. Option A: a small resume counter on page 125 beside the flag. That is new durable state, written once per failed resume and never per signature; it needs a reviewed encoding and a rule for who may erase the page. Option B: no new state, one wipe attempt per power cycle and then the fixed screen. Without a bound, the #106 fix turns a persistent SE fault into a wipe attempt on every boot.
- [ ] Move flag clearing to the dual-SE layer and clear it only when both legs report a verified wipe. Remove the erase from the SE050 leg. (The symptom is in the #106 comment; this is the structural change.)
- [ ] Add a check before the wizard: when the flag is clear and the wizard is about to run, probe the SE050 data objects for existence (three-state, as in #106) and read the OPTIGA sentinel. Any object present re-arms the flag and takes the resume path instead of the wizard. An unknown answer must not let the wizard run; whether it also re-arms the flag is a design choice, because a new unit with a flaky bus should not land in the wipe end state. Probe only the data and canary objects that the wipe itself checks (`secure/src/se050/mod.rs:2266`). Do not reuse the SE050 "is provisioned" test: it keys on the user ID object (`secure/src/se050/mod.rs:1793`), which survives every lockout wipe by design, so it would re-arm the wipe on every boot. The check reads object existence, not attempt counts, so the boot-time counter cross-check stays the two-input comparison that invariant 2 describes. On the OPTIGA side only the sentinel can be read without the PIN (the data objects need a PIN authentication to read, `secure/src/optiga/apdu.rs:1192` and `secure/src/optiga/apdu.rs:1194`), so this check cannot confirm the OPTIGA data objects are blank.
- [ ] Wipe screens: on a build where a wiped device cannot be set up again (#168), do not print "restore from seed".
- [ ] Tests assert over the log on the open bench board, which has no display panel, and over the USB status if the end state keeps USB up.

## What it needs

Firmware only. Confirming it on a device needs the open bench board (debug port, log output) and a way to make one SE unreachable during the wipe, for example holding its bus or its rail. A full lockout wipe on the locked profile ends the life of that unit's secure elements (#168), so use bench builds or a unit set aside for it.

## Limits

- This does not make a wiped device recoverable. On the locked profile ten wrong PINs still end the hardware's life (#168). Whether a locked-out device is meant to be single-use or must be recoverable is an owner decision that has not been recorded. If recovery is wanted, the research's acceptance rule for the secure-element lifecycle design is: every path that can reset or retire the attempt counter must destroy a secret the unlock needs, and every wipe must be able to reset or retire the counter. OPTIGA has four counter objects (`secure/src/optiga/apdu.rs:238`); the real PIN uses one and the duress feature another, which limits any "fresh object set per wipe" design to a few wipes per device. None of that is proposed here.
- A device parked in the end state reveals that one SE still holds its half of the seed entropy. With the XOR split one half alone says nothing about the seed, and each half stays behind its own SE attempt counter.
- Someone who cuts power during every boot can postpone the wipe for as long as they like. The device has no battery and does nothing while unpowered.
- The check before the wizard uses the same SE tunnels as the wipe. It does not detect an interposer that already holds the tunnel keys.
- Once #106 returns an error when the admin PIN cannot be derived (for example after loss of the hardware key it derives from), that device stays in the end state for good. That is honest, and terminal.
- Not measured: how long the wipe takes against the watchdog. Nothing here was run on silicon. The research review of this item had one reviewer, not two.

## Related

#106, #123, #168, #107, #129, #865, #853, #200, #75, #104, #120, #204, #712.

Public sources: Trezor's OPTIGA design note, which states the "resettable under all circumstances" goal, is `docs/core/misc/optiga.md` in https://github.com/trezor/trezor-firmware (read in a local clone). Ledger's "wipe verified at startup" note is https://donjon.ledger.com/lsb/003/ (cited by the research, not fetched again).

---
<sub>**Provenance.** Security frontier research, 2026-10-11 (report item M14, section 8). Report priority P1 is a research rating, not an owner decision. Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading and public sources; nothing was run on silicon. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>

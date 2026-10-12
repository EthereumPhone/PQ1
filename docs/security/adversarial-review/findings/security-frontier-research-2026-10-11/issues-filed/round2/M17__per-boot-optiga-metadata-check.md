TITLE: Add a read-only per-boot check of OPTIGA object metadata against a pinned table: it is compared only during provisioning, so a loose chip boots normally
LABELS: enhancement,priority:medium,surface:secure-element,surface:lockdown,source:frontier-research-2026-10
---
## Summary

The access conditions on the OPTIGA objects (who may read, change or execute each one, and whether the object is locked) are part of the wallet's security, but the firmware compares them with what it expects only inside the provisioning and locking paths. Nothing looks at them on an ordinary boot, so a chip whose conditions are looser than designed (a lock step that was skipped, an object frozen with the wrong conditions before first boot) boots and unlocks like any other. This issue asks for a read-only comparison at boot against a table pinned in the firmware, which may refuse to continue but never wipes and never rewrites anything. #87 tracks the same weakness at provisioning time; no issue tracks a per-boot check. Two dependencies are real and are listed as steps: the check is worth only as much as the channel it reads over, and the refusal policy is the security-versus-brick trade that #87 already holds for the owner. Scope is the OPTIGA and the device side only; the SE050 leg and chip identity are tracked elsewhere (see below).

## What the code does today

- Every metadata read in the OPTIGA driver sits in a provisioning, locking or duress-liveness path, for example `secure/src/optiga/mod.rs:898`, `secure/src/optiga/mod.rs:1087` and `secure/src/optiga/mod.rs:3174`. None of them compares metadata on an ordinary boot.
- The boot path goes from the first secure-element traffic (`secure/src/main.rs:1774`) to loading the pairing secret (`secure/src/main.rs:1793`) to the attempt-counter check (`secure/src/main.rs:1812`) with no metadata read in between.
- The existing comparator (`secure/src/optiga/apdu.rs:1544`) compares the Change, Read, Execute and data-type tags one by one. It leaves out the lifecycle state on purpose (`secure/src/optiga/apdu.rs:1535`), which is right for its caller (the check that runs just before the lock) and wrong for a boot check: reused as it is, it would accept an object that never reached the operational state.
- Provisioning writes a secret into an object (`secure/src/optiga/mod.rs:1265`) and, if that object is already operational, returns success without comparing its metadata (`secure/src/optiga/mod.rs:1280`). The lock step has the same skip (`secure/src/optiga/mod.rs:1088`). This is the defect #87 records.
- The encodings the firmware writes already have one source: the metadata builder functions in `secure/src/optiga/apdu.rs` (for example `secure/src/optiga/apdu.rs:1182` for the secret objects, `secure/src/optiga/apdu.rs:1358` for the PIN reference object and `secure/src/optiga/apdu.rs:1453` for the pairing secret). Host tests pin their exact bytes (for example `secure/src/optiga_under_test/pure_tests.rs:216` and `secure/src/optiga_under_test/pure_tests.rs:512`) and the comparator's behaviour (`secure/src/optiga_under_test/pure_tests.rs:410`).
- `secure/src/optiga/apdu.rs` is compiled into the host test suite (`secure/src/optiga_under_test/mod.rs:18`), so a table and comparator placed there can be tested without hardware.

## What is already tracked elsewhere

- #87: provisioning accepts an already operational object without proving its policy. It is owner-deferred as a security-versus-brick trade, and its "safe code-now slice" asks for host predicates that detect permissive final metadata per object class. The table proposed here is the natural home for those predicates. Build them once.
- #116: the secret objects are readable after a PIN verify without the tunnel. The table has to mirror what is provisioned today, including that, until #116 changes it.
- #117: a recorded OPTIGA session can be replayed. A metadata read over a replayed session proves nothing, so the liveness probe proposed there comes first. #121 and #126 cover reads made before the tunnel is up.
- #206, #61, #63, #444: the SE050 side (applet configuration pin, lock state, the get-version encoding defect). Not repeated here.
- #210, #244, #245, #249: chip identity and attestation. Not in scope here. One note for those issues: as written they specify verifying vendor certificate chains (ECDSA) on the device. The `make classical-crypto-boundary` gate, which enforces invariant 5, allows ECDSA code only in the host tool `dbgen`, so on-device verification would need an owner decision to change that gate. The research recommends verifying on the host instead.
- #6, #11, #14, #215: the factory-owned objects (trust-anchor pool, pairing-secret lifecycle state, the F1E1 sentinel). Their rows cannot be written until those close.

So this issue is only about the per-boot, read-only OPTIGA check and the table behind it.

## Proposed work

- [ ] A pinned table with one row per object the firmware provisions today: the pairing secret, the attempt counter, the PIN reference object, the four secret objects, and the duress twins under `duress-pin`. Derive each row from the existing builder function for that object, not from a second hand-written list, so that what is written and what is expected cannot drift apart. Each row lists the accepted encodings of the Change, Read and Execute conditions, the data type, and the lifecycle state where the profile expects one. Compare tag by tag and byte for byte against accepted encodings. Do not build a "looser than" ordering: OPTIGA access conditions are expressions, not bitmasks.
- [ ] A comparator that includes the lifecycle state, in code the host tests compile, with a negative control per row (one changed tag must fail).
- [ ] Generate the documentation table from the same source and diff it in `make invariant-gates`, so the document cannot drift from the firmware.
- [ ] Rows for the two states that are not "provisioned": a blank chip before the seed wizard, and a chip after a factory reset. Without them the check refuses every fresh unit. Which state applies must come from an authenticated source; the probe used today is a plaintext read (#121).
- [ ] Placement: after the pairing secret is loaded and the tunnel is up, after the liveness probe of #117, and before the PIN prompt. On `rdp2-self-lock` builds that is after the first-boot rotation. State which credentials the check uses when the rotation is part-way through its journal.
- [ ] **Owner decision, shared with #87:** whether a mismatch on a frozen object that cannot be repaired stops the boot. The funds stay recoverable from the 24 words, but the unit is lost. The table, the comparator, the tests and the generated document can land before this decision. The boot-time refusal cannot.
- [ ] On a mismatch: refuse with a readable code. Never wipe (one forged frame must not become a wipe trigger) and never rewrite metadata or move a lifecycle state from an ordinary boot.
- [ ] Measure the added boot time and flash. The research estimates 100 to 300 ms for about a dozen tunnelled reads and 3 to 8 KB. Both are estimates.
- [ ] Record that a firmware update carrying a wrong table would stop every unit that installs it, and rehearse that against the A/B rollback path before the refusal is switched on.
- [ ] Add the factory-owned rows only when the lifecycle work that defines them is done. The review warns that vendor default metadata for those objects may differ between batches. That was not checked. Survey parts before those rows can refuse.

## What it needs

Firmware only for the table, comparator, tests and generated document. The refusal needs the owner decision above. Timing needs a bench unit with a debug port and an OPTIGA. A refusal screen cannot be checked on the open bench board, which has no display panel.

## Limits

- Its value today is modest. The objects in the first rows are created by the firmware itself in the seed wizard and are compared before they are locked. The larger gain comes with the factory-owned rows.
- It runs on the boot after a secret was written. It does not stop the write into a loose object. That is #87.
- Malicious firmware on genuine chips passes. An interposer or emulator that holds the final tunnel credentials passes. An interposer can still force a refusal, which is a denial of service.
- The SE050 UserID policy cannot be read back at all: the production policy denies the attribute read.
- This is not a "genuine device" proof and must not be described as one.
- No vendor was found shipping a refuse-only per-boot check of this kind. By the research's reading of Trezor's sources, Trezor checks one of its secure elements at boot and rewrites the configuration to fix it, and has no boot-time OPTIGA metadata check.
- The research also proposed journaling the table version in flash page 127. The review dropped it: it had no consumer and that page belongs to the first-boot journal.

## Related

#87, #116, #117, #121, #126, #206, #61, #63, #444, #210, #244, #245, #249, #6, #11, #14, #215. Public source for the per-chip binding rule on the identity side: [Trezor, "Authenticity proofs not bounded to their secure element"](https://trezor.io/vulnerability/authenticity-proofs-not-bounded-to-their-secure-element) (cited by the research; I did not re-fetch it).

---
<sub>**Provenance.** Security frontier research, 2026-10-11 (report item M17, section 7; device-side part only). Report priority P2 is a research rating, not an owner decision. Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading and public sources; nothing was run on silicon. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>

COMMENT_ON: 123
---
**A correction to this issue's fix direction, from the 2026-10-11 security frontier research (report item M14). Line numbers are at master `c2fab970`.**

The body asks to "readback-verify every OID" and to write "secrets first, sentinel last". The first cannot be built as written, and that changes the argument for the second.

1. **The OPTIGA data objects cannot be read back on the wipe path.** Their read access condition requires a PIN authentication: `secure/src/optiga/apdu.rs:1192` (entropy half and master secret: PIN authentication AND the shielded connection) and `secure/src/optiga/apdu.rs:1194` (the two verifying keys: PIN authentication). After a lockout the firmware has no PIN, so it cannot read those four objects to see that they are blank. Of the objects the wipe writes, only the sentinel is readable: its read condition is "always" (`secure/src/optiga/apdu.rs:1245`).
2. **So the OPTIGA verdict can only be: the status of each blank-write, plus the sentinel.** The blank-writes already propagate their status (`secure/src/optiga/mod.rs:2841` to `secure/src/optiga/mod.rs:2844`). A second, idempotent pass of the same writes is a cheap extra check. A check before the setup wizard ({{M14}}) can confirm the sentinel and nothing else on this chip.
3. **That makes the write order matter more.** Today the sentinel is written first (`secure/src/optiga/mod.rs:2829`). A sentinel that reads "reset" then proves only that the first write landed. Written last, it is reached only when every blank-write before it returned success, so it becomes the one readable marker that the wipe ran to the end.
4. **The recorded reason for sentinel-first** (`secure/src/optiga/mod.rs:2822`: a crash in mid-wipe must still boot as unprovisioned) is the job of the page-125 flag, which is armed before any write (`secure/src/optiga/mod.rs:2781`). That holds only if the flag cannot be lost while objects survive, which is what #106 fixes. The two changes should land together, and reversing a rationale written in the code needs a decision.
5. The duress blank-writes are still unchecked (`secure/src/optiga/mod.rs:2863` to `secure/src/optiga/mod.rs:2867`), as the body says.

- [ ] Replace "readback-verify every OID" with: write status of every blank-write, an optional second pass, and the sentinel read.
- [ ] Decide sentinel-first or sentinel-last, with #106 in the same change.

Not checked: the access conditions are read from the metadata builders, not from a chip. Nothing was run on silicon.

<sub>**Provenance.** Security frontier research, 2026-10-11 (report item M14, section 8). Report priority P1 is a research rating, not an owner decision. Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading; nothing was run on silicon. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>

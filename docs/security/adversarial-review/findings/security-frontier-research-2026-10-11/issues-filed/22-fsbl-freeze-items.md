TITLE: FSBL freeze items with no issue: every FI delay is the constant 0x42, the slot tail beyond the declared lengths is never measured or checked blank, and the boot fingerprint covers the secure image only
LABELS: finding,priority:medium,surface:lockdown,surface:sca-fi,surface:fw-update,source:frontier-research-2026-10
---
Three properties of the first-stage bootloader that become permanent when its pages are write-protected and the device is locked at RDP-2 (invariant 10). None is a standalone bypass. Each must be decided, one way or the other, before the freeze, because none can be changed after it.

Line numbers at master `0feea78a` (2026-10-11). The research ran at `c75b0d9c`, an ancestor of master; the cited files were diffed against master before filing.

## 1. Every FI delay in the FSBL is the constant 0x42

- `fsbl/src/fi.rs:31-33`: `fn rng_byte() -> u8 { 0x42 }`. Every FSBL delay goes through it; there is no other entropy source in `fsbl/src`.
- The two evaluations inside the signature gate are therefore at a fixed separation and a fixed time from reset. The file header (`:5-16`) acknowledges this and names bringing up the TRNG in the FSBL as the future fix. That bring-up has no tracking issue.
- Severity: **medium**; an acknowledged weakening.
- [ ] Decide: TRNG bring-up in the FSBL (clock, size budget), or record the constant as an accepted residual in the freeze review.

## 2. The slot tail is never measured and never checked blank

- `fsbl/src/verify.rs:52-57` (capacity checks), `:62`, `:68`: the FSBL hashes exactly the manifest-declared lengths. `secure/src/fw_update/verify.rs:42-58` does the same at COMMIT.
- `fw-manifest/src/lib.rs:177`, `:180`, `:204`: the lengths are not in the signed preimage; they are bound only through the hashes.
- Bytes in the slot beyond those lengths are outside the hash, the manifest and the 8-word fingerprint. The erase at `FW_BEGIN` is not read back (see {{20}}).
- Reaching the tail needs a prior secure-world write or a faulted erase, plus a later control-flow fault. A full SWD flash diff at RDP-0 still catches it.
- Severity: **low-medium** / **low**.
- [ ] Add a blank (0xFF) scan of the tail, bounded by the geometry registry, at boot and at COMMIT. Factory flashing must then erase whole slots.

## 3. The boot fingerprint covers the secure image only

- `fsbl/src/verify.rs:109`, `fsbl/src/main.rs:220`, `:286`: the 8 words are derived from `secure_digest`. `secure/src/fw_update/mod.rs:133-139`.
- The non-secure hash is verified against the signed manifest at boot, but it is not in the words; nor is the firmware version. Two validly signed releases that differ only in the non-secure image render the same fingerprint.
- This may be intended (the non-secure world is untrusted by invariant 4). It is an owner call. The pixel UI's glyph atlas lives in the non-secure slot and is separately hash-pinned by the secure image, which already limits what a different non-secure image can change on screen.
- Severity: **low-medium** (merger), **low** (skeptic).
- [ ] Decide: derive the words from the manifest digest (covers both images and the version), or record the current scope in the user documentation of what the fingerprint proves.

Evidence level for all three: code read, re-checked independently at `c75b0d9c` (all confirmed). Silicon behaviour unmeasured.

Related: #540, #591, #541, #31, and {{02}}.

---
<sub>**Provenance.** Security frontier research, 2026-10-11 (report item M05 / M08, defect row C7, C10, C11).  The full report is `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`; it was not committed when this issue was filed, so this body is written to stand alone.</sub>

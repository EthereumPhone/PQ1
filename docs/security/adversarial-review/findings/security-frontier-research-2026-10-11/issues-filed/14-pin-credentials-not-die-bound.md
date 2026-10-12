TITLE: PIN credentials are not die-bound or salted (SE050 UserID is the raw PIN, OPTIGA F1D0 is one SHA-256 of it), while the threat model says single-chip extraction is defeated
LABELS: finding,priority:high,surface:secure-element,surface:docs,source:frontier-research-2026-10
---
## Summary

The seed is split across two secure elements so that neither chip alone reveals it. The PIN that gates both halves is presented to each chip in a form that is the same on every device and carries no secret from the microcontroller:

- SE050: the UserID credential is the raw 8-digit PIN.
- OPTIGA: the authorization secret is `SHA-256(domain || PIN || 0)`, with no salt.

If the stored credential can be read out of **either** chip, the PIN falls out (directly, or by trying at most 10^8 values offline). With the PIN and the device, the other chip opens on the first attempt. The split then protects against nothing that a single-chip extraction does not already give.

## Evidence

Line numbers at master `0feea78a` (2026-10-11). The research ran at `c75b0d9c`, an ancestor of master; the cited files were diffed against master before filing.

- `secure/src/se050/mod.rs:2023-2025`: the UserID object is written with `pin`. `:2776-2777`: verify presents `pin`. Builder at `secure/src/se050/apdu.rs:794-816`.
- `secure/src/optiga/mod.rs:916-918`: `crate::crypto::kdf(PIN_AUTH_DOMAIN, pin, 0)` (domain at `:70`). Ship call sites `:2144`, `:2164`, `:2502`, `:2561`.
- `domain/src/lib.rs:97-103`: `kdf` is a single SHA-256 over domain, input and index.
- `secure/src/dual_se.rs:455`: `xor_32(&half_o, &half_e)`. The join has no microcontroller-keyed input.
- No PIN-labelled derivation exists in `secure/src/hw/secret_keys.rs`; `saes-dhuk` and `bhk` do not touch the PIN path.

## Documentation that says otherwise

- `docs/security/threat-model.md:131-132`: "Offline brute force against persisted PIN material is structurally impossible because the PIN never leaves SE silicon."
- `:226`: "So even decapping both chips, the attacker still needs to *use* the chip with its silicon-enforced PIN gate."
- Also `:224-225`, `:252`, `:600`.

## What an attacker needs

A decap-class read of one EAL6+ secure element on a stolen device, then PIN entry on that device (or emulation of the destroyed chip). Alternatively a broken SCP03 session under the accepted Grover residual.

## Severity and evidence level

- Severity: **medium** for each credential; **medium-high** as a claim-versus-code defect.
- Evidence: code read; re-checked independently (confirmed). **Reasoned, not demonstrated.** The strongest doubt: it assumes the chip stores the credential in a recoverable form, which cannot be known from this repository.

## Fix directions

- [ ] Present `SAES-CMAC(DHUK, label_per_SE || salt || PIN)` to each chip instead. The comparison stays inside the secure element (invariant 2); only the value presented changes.
- [ ] Add a 32-byte per-provisioning salt, erased first in every wipe entry point.
- [ ] Mask each seed half with a PIN-keyed value derived under the device key, so the XOR join needs the microcontroller.
- [ ] Mint the credentials only after the device is at RDP-2, when the device key is final.
- [ ] Correct the threat-model sentences above until this lands.

## Related

#124, #104.

---
<sub>**Provenance.** Security frontier research, 2026-10-11 (report item M16, defect row A10 and E1). Re-checked before filing by an independent read at `c75b0d9c` (both confirmed; citations corrected to the shipping call sites). The full report is `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`; it was not committed when this issue was filed, so this body is written to stand alone.</sub>

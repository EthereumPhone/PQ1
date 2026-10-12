TITLE: Show two device-bound words part-way through PIN entry, so a swapped unit is noticed before the whole PIN is typed
LABELS: enhancement,priority:low,surface:trusted-ui,surface:lifecycle,source:frontier-research-2026-10
---
## Summary

After a device has been set up, nothing on its screen proves "this is my unit" before the user types the PIN. Someone who swaps the unit for a lookalike collects the PIN on the fake while holding the real one. Coldcard and Foundation Passport answer this by showing two words after the first part of the PIN, computed from a secret only that device has: wrong words, stop typing. The proposal is the same idea without any stored state. After the fourth PIN digit, show two BIP-39 words computed from the die's hardware unique key, the per-device salt that first boot already writes, and the four digits. It needs no secure-element change, no board change and no new flash state. #601 tracks the same threat through a stored, user-chosen artifact and is blocked on having no free flash page; this is a derived alternative that needs no storage, and no issue tracks it.

## What the code does today

- `secure/src/ui/pin_entry.rs:133`: a long press on the right button only advances to the next digit. There is no hook between digits.
- `secure/src/main.rs:4174`, `secure/src/main.rs:4622`, `secure/src/nsc/cmd_request_unlock.rs:54`: the three places that ask for the PIN (boot, idle re-unlock, USB unlock) all call the same `enter_pin`, so one hook reaches all of them.
- `secure/src/main.rs:1761`: the secure-world fingerprint screen is compiled out of production images. The remaining boot fingerprint is the bootloader's, which is computed from the firmware image and is therefore the same on every unit running that image, and which is dark on a cold-booted pq1 (#705).
- `secure/src/hw/saes_cmac.rs:44`: `cmac_dhuk` already exists (a MAC keyed by the hardware unique key, which secure code can use but cannot read).
- `secure/src/hw/secret_keys.rs:499`: a recorded rule forbids deriving anything a transit attacker must not predict from the hardware key and a fixed label alone. The final OPTIGA pairing secret mixes in a random salt for that reason. `secure/src/first_boot/mod.rs:83` returns that salt once first boot has completed.
- `secure/src/hw/secret_keys.rs:49`: at readout-protection level 0 the hardware key is a constant shared by all parts, so every bench board derives the same values.
- `secure/src/ui/pin_entry.rs:237`, `secure/src/ui/pin_entry.rs:243`, `secure/src/ui/seed_wizard.rs:285`: setting the PIN at setup calls `enter_pin` twice, and setting a duress PIN calls it at least twice more. Any limit on how often the words may be computed has to allow for that.
- `secure/src/ui/px/screens.rs:108` and `secure/src/ui/secret_text.rs:74`: the pixel UI and the legacy 16x4 UI each have a constant-time path for painting secret text.

## What is already tracked elsewhere

- #601 covers the same threat (a lookalike unit) with a stored artifact shown at boot. It is design-first and owner-gated because no flash page is free. It does not cover words derived from the PIN prefix. #601 requires that its artifact does not survive a wipe and does not reveal that a wallet exists. The words here do survive a wipe, on purpose: they depend only on the device and the digits typed, not on any wallet, so they look the same whether or not a wallet exists and for the real and the duress PIN alike.
- #705 covers the bootloader fingerprint being invisible on a cold-booted pq1.
- #249 and #206 cover factory attestation and secure-element variant checks. Those are checked by firmware or a companion, not by the user before the PIN.
- #772 (closed) is the three seed check words at setup, a different feature.

So this issue is only about the derived words shown during PIN entry.

## Proposed work

- [ ] Derivation: `CMAC(hardware key, DOMAIN || salt (32 bytes) || prefix length || prefix digits)`, top 22 bits mapped to two BIP-39 words with the word list already linked. The salt is the first-boot journal salt. If the salt is missing or first boot is not complete, label the screen "not device-unique"; never fall back silently to an unsalted form.
- [ ] Give `DOMAIN` a distinct prefix and add a test that it is neither a prefix of, nor prefixed by, any existing derivation label (`secure/src/hw/secret_keys.rs:304`, `secure/src/hw/secret_keys.rs:314`, `secure/src/hw/secret_keys.rs:324`, `secure/src/hw/secret_keys.rs:344`, `secure/src/hw/secret_keys.rs:353`, `secure/src/hw/secret_keys.rs:373`, `secure/src/hw/secret_keys.rs:409`, `secure/src/hw/secret_keys.rs:489`).
- [ ] One screen after digit four ("Your device words: W1 W2", continue or go back), on the legacy 16x4 path first because that is the UI in the release build. On the pixel UI it is a recorded deviation from the reference design (`tools/pq-ui/PORT_DEVIATIONS.toml`). Paint the words through the secret-text path and add a test that the frame is forced; #784 is a live bug of that class.
- [ ] Limit how often the words can be computed: count since the last successful unlock, reset on success, and do not count the PIN entries of the setup wizard. Keep the count in secure RAM, so no flash state is added; a power cycle therefore resets it. Past the limit show a plain "words unavailable" page, never skip silently, so that page is itself a warning sign.
- [ ] Drive the "not device-unique" label from the readout-protection level read at run time plus the first-boot journal state, not from a build feature. A bench board at level 1 already has a per-die key.
- [ ] Setup wizard: one page where the user first sees the pair, saying that the words belong to this device and not to the seed, and that they should be memorised or kept apart from the device.
- [ ] Compile the hook out of the test build that returns a fixed PIN (`secure/src/ui/pin_entry.rs:173`).
- [ ] Amend `docs/security/user-device-verification.md` with the scope and the limits below. Do not create a new document.
- [ ] Owner decisions: always on or switchable (a switch needs a stored bit, which is the #601 blocker); a fixed four-digit prefix or a user-chosen length as Coldcard does; the value of the limit.

## What it needs

Firmware only. Checking it on hardware needs a unit with a display panel running a non-test image (#700); the open bench board has no panel. Showing that two units give different words needs two units at readout-protection level 1 or higher. The first-boot flow that writes the salt is still a production-quarantined candidate (#268).

## Limits

- **Live relay.** The fake forwards the four digits to an accomplice who types them into the real unit and sends the words back. Coldcard accepts the same limit.
- **The words are a free lookup.** Anyone holding the real unit can go back after digit four and try another prefix. No PIN attempt is consumed, by design, so all 10,000 pairs can be read out through the two buttons in hours and loaded into a fake. The limit above slows this; it is not the main defence.
- **Filmed or noted words can be replayed** by a fake after any four digits. A written note of the pair, found together with the device, gives four of the eight PIN digits by enumeration.
- **No protection against malicious code on the user's own chip, or against a unit swapped before first setup.** In both cases the words are right, or the user learns the fake's words. `docs/security/user-device-verification.md:28` records why nothing computed inside the device can separate genuine from fake firmware on the same chip.
- **The words survive a wipe**, so a previous holder of the device knows its table.
- **The display bus still carries the words and the digits** to anyone tapping it.
- It is advisory. A user who ignores a wrong pair, or blames it on a mistyped digit, gets nothing from it.
- If the duress feature ships (#636), a user has two pairs unless both PINs share their first four digits.
- Not measured: whether the hardware key at protection level 1 equals the one at level 2 (#400). Not checked by me: the exact message framing of the existing key-derivation function, which the label test above depends on. Nothing was run on silicon.
- The research review lowered this from priority 2 to 3 and from small to medium cost: two UI paths, a wizard page, the salt wiring, and every validation step currently blocked.

## Related

#601, #705, #700, #784, #268, #636, #280, #249, #206, #400, #772.

Public sources: Coldcard PIN documentation https://coldcard.com/docs/pins/ and https://blog.coinkite.com/understanding-mk4-security-model/ ; Foundation Passport "Security Words" https://docs.foundation.xyz/passport/advanced (its mechanism was not checked in code). The research found nothing equivalent in a search of Trezor's source; Ledger was not checked in source.

---
<sub>**Provenance.** Security frontier research, 2026-10-11 (report item M13, section 8). Report priority P3 is a research rating, not an owner decision. Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading and public sources; nothing was run on silicon. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>

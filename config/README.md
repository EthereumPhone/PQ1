# Production release policy

`production-firmware-vendor-key.sha256` is the reviewed trust anchor for
firmware releases. It must contain exactly one lowercase, 64-character
SHA-256 fingerprint of the raw 32-byte SPHINCS+C10 vendor public key
(`pk_seed || pk_root`).

It intentionally contains `UNPROVISIONED` before the factory/HSM key ceremony.
Consequently every production FSBL, secure-world, and `make release` build
fails closed until the generated public-key fingerprint is reviewed and
committed. Never replace it with the public development-key fingerprint.

Key rotation is a new hardware cohort: the immutable FSBL cannot change this
root after WRP/RDP lockdown. Update this policy only as part of a reviewed
cohort provisioning ceremony.

`development-firmware-vendor-pubkey.hex` is the single, public source of truth
for the 32-byte bench/test update key. Production gates compare raw key bytes
against it and reject an exact match. The test tooling also derives its fixture
key and checks it against this file, so changing a duplicated seed cannot make a
new development key slip past the production ban.

`devunit-firmware-vendor-pubkey.bin` / `devunit-firmware-vendor-key.sha256`
are the public half and fingerprint of the separate DEV-UNIT update key
(`devunit-ab`, `tools/devunit/README.md`): pre-production DVTs handed to
testers accept releases signed by it and nothing else. It is not a production
key and grants no production authority — `mode-production` refuses
`devunit-ab` — and its private half is kept off the repository.

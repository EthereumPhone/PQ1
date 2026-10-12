COMMENT_ON: 370
---
**Status check (2026-10-12): this looks fixed in the tree. Not closing; please confirm.**

At master `0feea78a`, `provision_duress_wallet` in `secure/src/crypto.rs` no longer has the silent `if store.random(...).is_ok()` fall-through this issue describes. Both draws go through the strict helper and propagate failure:

- decoy entropy: `fill_strong_with_store(store, &mut decoy_entropy)?;`
- declined-duress random PIN: `if let Err(e) = fill_strong_with_store(store, &mut random_pin) { ... }`

Checked by reading the function only. `duress-pin` is not in the shipping feature set and no CI job compiles it (#636), so this has not been built or run by me.

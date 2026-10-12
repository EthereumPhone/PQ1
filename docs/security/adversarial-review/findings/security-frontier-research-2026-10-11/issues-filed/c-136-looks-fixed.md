COMMENT_ON: 136
---
**Status check (2026-10-12): the fix appears to be in the tree. Not closing; please confirm.**

At master `0feea78a`:

- `shared/src/apdu_framing.rs:140-190`: `ChainState::tick_timeout` implements an "X17-UC1 total-chain-lifetime timeout" and resets the chain when it expires.
- `nonsecure/src/usb/commands.rs:945-946`: the router calls `self.chain.tick_timeout(delta)` and releases on expiry.
- `shared/src/apdu_framing.rs:841-856`: host test `chain_tick_timeout_bounds_total_chain_lifetime`.

The implementation is a total-exchange deadline, not an idle timeout, and the code comments say so. I did not run it on hardware and did not check the companion-side "same-INS retransmit dup-appends" half of this issue.

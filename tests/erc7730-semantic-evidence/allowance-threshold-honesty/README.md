# Allowance threshold honesty

This package pins the source and fixed-block facts used to correct ERC-7730
allowance messages for WalletConnect WCT, FlyingTulip PositionsManager, and the
shared Ethereum/Polygon USDT descriptor.

- WCT inherits OpenZeppelin's allowance spending rule: only
  `type(uint256).max` is left unchanged. Values at or above `2^255` but below
  max are finite, so only exact max may trigger the unlimited message.
- FlyingTulip `approveEngine` is infinite only at exact max because
  `_consumeEngineDebitAllowance` returns only for that value.
  `approveBorrow` has no infinite sentinel: its consumption path decrements
  max like every other sufficient allowance, so it must not show Unlimited.
- Ethereum USDT treats exact max as non-decrementing at the pinned block, but
  Polygon USDT always subtracts the spent amount. The shared descriptor
  therefore cannot make one cross-deployment Unlimited claim. **UPDATE
  2026-10-19:** it now carries the exact-max threshold, and the narrowing-only
  `_pqsigner.thresholdOmissions` curation key compiles the Polygon deployment
  without it. Only the Ethereum IR says Unlimited, and only at exact max; on
  Polygon max stays an exact-value refusal. The Ethereum claim holds while the
  fixed-block `deprecated == false` receipt holds (see the residuals).
- The generic ERC-20 descriptor likewise carries no threshold because a token
  catalogue is not proof that every implementation has one infinite sentinel.

The four `.sol` files are deliberately small, normalized-LF, non-contiguous
source excerpts. They are not build inputs. `manifest.json` authenticates the
excerpts and records hashes of the complete explorer captures and complete
source files from which they were selected. `rpc/fixed-block-receipt.json`
records block, storage-slot, address, and runtime-digest facts without bloating
the repository with redundant runtime bytecode.

The evidence boundary is fixed-block and source-honest: it supports the
descriptor classifications at the recorded implementations, not a claim that
upgradeable deployments can never change.
